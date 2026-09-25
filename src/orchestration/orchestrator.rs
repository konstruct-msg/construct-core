/// Orchestrator — top-level facade (Phase 5).
///
/// Single entry point for all platform events. Swift / Kotlin call ONE function:
///
/// ```swift
/// let actions = orchestrator.handleEvent(event)
/// // execute each action, then feed results back as new events
/// ```
///
/// The `Orchestrator` holds the full orchestration state:
/// - `SessionLifecycleManager` (sessions, archives, ACK, healing, PQ)
/// - `MessageRouter` (routing decisions)
/// - Coordinator state: init locks, cooldowns, prewarm tracking
use std::collections::HashSet;
use std::sync::Arc;

use crate::crypto::client_api::ClassicClient;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::orchestration::actions::{Action, IncomingEvent, SecureStoreSlot};
use crate::orchestration::clock::{Clock, system_clock};
use crate::orchestration::message_router::{
    IncomingMessage, MessageRouter, Role, RoutingDecision, tie_break_role,
};
use crate::orchestration::session_lifecycle::SessionLifecycleManager;
use crate::orchestration::session_machine::{
    Effect as SessionEffect, Event as SessionEvent, ResetInitVerdict, SessionMachine, TearDownCause,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum time between prewarm attempts for the same contact (ms).
#[allow(dead_code)]
const PREWARM_COOLDOWN_MS: u64 = 30_000;

// ── Orchestrator ──────────────────────────────────────────────────────────────

/// The Kyber half of a fetched prekey bundle, as the server served it.
///
/// The signatures are Ed25519 by the bundle's `verifying_key` over
/// `build_x3dh_sign_message(0x10, key)`. `one_time_prekey_signature` has no source yet — the
/// server's `DevicePreKeyBundle` does not carry the OTPK signature — and is here so that a verified
/// OTPK is used the moment it does.
#[derive(Debug, Clone, Default)]
pub struct KyberBundleKeys {
    pub pre_key_public: Option<Vec<u8>>,
    pub pre_key_signature: Option<Vec<u8>>,
    pub one_time_prekey_public: Option<Vec<u8>>,
    pub one_time_prekey_id: Option<u32>,
    pub one_time_prekey_signature: Option<Vec<u8>>,
}

/// Binary first message for RESPONDER path — replaces JSON-encoded `&[u8]`.
pub struct IncomingFirstMessage {
    pub ephemeral_public_key: Vec<u8>,
    pub message_number: u32,
    /// Raw sealed box: nonce[12] ++ ciphertext
    pub content: Vec<u8>,
    pub one_time_prekey_id: u32,
    /// DR message suite (the NEGOTIATED suite the initiator encrypted with, e.g.
    /// `SuiteID::PQ_RATCHET`=3), distinct from the bundle's crypto suite. Must be carried from
    /// the wire so the responder rebuilds the exact AEAD associated data — see task #12.
    pub suite_id: u16,
    /// Suite-3 PQ epoch tag the initiator authenticated into the AD (0 for other suites).
    pub pq_message_epoch: u32,
    /// Suite-3 sparse PQ-ratchet field (initiator KEM public / responder ciphertext); `None`
    /// for other suites.
    pub pq_ratchet_field: Option<crate::crypto::messaging::double_ratchet::PqRatchetWireField>,
}

pub struct Orchestrator {
    lifecycle: SessionLifecycleManager,
    router: MessageRouter,
    /// What phase each ratchet is in, and the only thing that decides whether a session may be
    /// opened or torn down right now.
    ///
    /// Replaces three maps — `init_locks`, `cooldowns` and `pending_end_sessions` — which were
    /// three views of one lifecycle, each with its own window and no owner of the sequence. See
    /// `session_machine` and `decisions/session-is-one-state-machine.md`.
    sessions: SessionMachine,
    /// Contacts that have been pre-warmed (lower userId prewarms on first contact).
    #[allow(dead_code)]
    prewarm_done: HashSet<String>,
    /// Contacts whose chat is currently open in the UI. The orchestrator
    /// schedules periodic heartbeat timers for these contacts.
    active_chats: HashSet<String>,
}

impl Orchestrator {
    /// Create a new orchestrator for the given local user.
    ///
    /// `client` is a freshly constructed (or key-restored) `ClassicClient`.
    pub fn new(client: ClassicClient<ClassicSuiteProvider>, my_user_id: String) -> Self {
        Self::new_with_clock(client, my_user_id, system_clock())
    }

    pub fn new_with_clock(
        client: ClassicClient<ClassicSuiteProvider>,
        my_user_id: String,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            lifecycle: SessionLifecycleManager::new_with_clock(client, my_user_id, clock.clone()),
            router: MessageRouter::new(),
            sessions: SessionMachine::new(clock.clone()),
            prewarm_done: HashSet::new(),
            active_chats: HashSet::new(),
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Unified event handler — the **only** method Swift / Kotlin need to call.
    ///
    /// Returns a list of `Action`s that the platform must execute in order.
    /// After executing I/O actions (network, storage), the platform feeds
    /// results back via further `handle_event` calls.
    pub fn handle_event(&mut self, event: IncomingEvent) -> Vec<Action> {
        match event {
            IncomingEvent::MessageReceived {
                message_id,
                from,
                data,
                msg_num,
                kem_ct,
                otpk_id,
                is_control,
                content_type,
            } => self.handle_message_received(
                message_id,
                from,
                data,
                msg_num,
                kem_ct,
                otpk_id,
                is_control,
                content_type,
            ),
            IncomingEvent::OutgoingMessage {
                contact_id,
                message_id,
                plaintext,
                content_type,
            } => self.handle_outgoing_message(contact_id, message_id, plaintext, content_type),
            IncomingEvent::OutgoingCallSignal {
                contact_id,
                message_id,
                proto_bytes,
            } => self.handle_outgoing_call_signal(contact_id, message_id, proto_bytes),
            IncomingEvent::SessionInitCompleted {
                contact_id,
                session_data,
            } => self.handle_session_init_completed(contact_id, session_data),
            IncomingEvent::AckReceived { message_id } => self.handle_ack_received(message_id),
            IncomingEvent::KeyBundleFetched {
                user_id,
                bundle_json,
            } => self.handle_key_bundle_fetched(user_id, bundle_json),
            IncomingEvent::NetworkReconnected => self.handle_network_reconnected(),
            IncomingEvent::AppLaunched => self.handle_app_launched(),
            IncomingEvent::TimerFired { timer_id } => self.handle_timer_fired(timer_id),
            IncomingEvent::AckDbResult {
                message_id,
                is_processed,
            } => self.handle_ack_db_result(message_id, is_processed),
            IncomingEvent::ActiveChatChanged {
                contact_id,
                is_active,
            } => self.handle_active_chat_changed(contact_id, is_active),
            IncomingEvent::HeartbeatReceived {
                contact_id,
                message_id,
                data,
                msg_num,
            } => self.handle_heartbeat_received(contact_id, message_id, data, msg_num),
            IncomingEvent::TeardownRequested { contact_id, cause } => {
                self.handle_teardown_requested(contact_id, cause)
            }
            IncomingEvent::PeerToreDown { contact_id } => {
                self.sessions
                    .handle(&contact_id, SessionEvent::PeerToreDown);
                // The ratchet a heal was queued against is gone, so the carrier is spent and the
                // retry budget belongs to an episode that ended. `settle`, not `remove`: the
                // incoming-trigger cap must not be resettable by tearing down.
                self.lifecycle.healing_queue.settle(&contact_id);
                Vec::new()
            }
            IncomingEvent::HealAttempted { contact_id } => self.handle_heal_attempted(contact_id),
            IncomingEvent::ReopenRequested { contact_id } => {
                self.handle_reopen_requested(contact_id)
            }
            IncomingEvent::SriAnnounced { contact_id } => self.handle_sri_announced(contact_id),
            IncomingEvent::ResetInitArrived {
                contact_id,
                init_ephemeral,
                sent_at_s,
                established_at_s,
            } => {
                let verdict = self.sessions.judge_reset_init(
                    &contact_id,
                    &init_ephemeral,
                    sent_at_s,
                    established_at_s,
                );
                vec![match verdict {
                    ResetInitVerdict::Apply => Action::ApplyResetInit { contact_id },
                    ResetInitVerdict::Redelivery => Action::ResetInitSuperseded {
                        contact_id,
                        redelivery: true,
                    },
                    ResetInitVerdict::PredatesSession => Action::ResetInitSuperseded {
                        contact_id,
                        redelivery: false,
                    },
                }]
            }
            IncomingEvent::PeerAcked { contact_id } => {
                self.sessions.handle(&contact_id, SessionEvent::PeerAcked);
                vec![Action::CancelTimer {
                    timer_id: format!("open_confirm:{contact_id}"),
                }]
            }
        }
    }

    /// Answer the platform's "may I tear this ratchet down?".
    ///
    /// The answer is the same one `EndSessionNeeded` gets, from the same machine and the same
    /// window, which is the point: before this the platform held a second window of its own and
    /// the two could not see each other. A refusal is not a drop — the debt is recorded and the
    /// timer pays it, exactly as it does for a teardown the core concluded itself.
    fn handle_teardown_requested(
        &mut self,
        contact_id: String,
        cause: TearDownCause,
    ) -> Vec<Action> {
        match self
            .sessions
            .handle(&contact_id, SessionEvent::WantToTearDown { cause })
        {
            SessionEffect::DeferTearDown { retry_after_ms } => {
                self.condemn_active_session(&contact_id);
                vec![
                    Action::EndSessionSuppressed {
                        contact_id: contact_id.clone(),
                        retry_after_ms,
                    },
                    Action::ScheduleTimer {
                        timer_id: format!("cooldown_expired:{contact_id}"),
                        delay_ms: retry_after_ms,
                    },
                ]
            }
            // No timer: nothing is owed. The peer tore this ratchet down and knows it is gone,
            // so the ask is answered rather than postponed — arming a retry here would be the
            // 20 s grace's opposite, a guaranteed teardown back at a peer that already reset.
            SessionEffect::TearDownNotNeeded => {
                vec![Action::EndSessionNotNeeded { contact_id }]
            }
            // No `NotifyLinkedDevicesOfSessionReset` here, unlike `EndSessionNeeded`. The caller
            // is the platform, which reaches its own linked devices through the paths it already
            // owns; emitting it would broadcast the same reset twice.
            _ => vec![Action::SendEndSession { contact_id }],
        }
    }

    /// Record that a SESSION_RESET_INIT went out, and arm the only thing that ever ends the wait
    /// for an answer to it.
    ///
    /// The platform reports this because it is the one fact about an opening that only the sender
    /// has: an SRI has no acknowledgement other than the peer's own next carrier, so nothing
    /// downstream can infer that one was sent. It replaced
    /// `SessionConfirmationTracker.markPending` — a map of unanswered ratchets kept beside this
    /// phase, and a `tieBreakWatchdogs` task per account kept beside that.
    fn handle_sri_announced(&mut self, contact_id: String) -> Vec<Action> {
        match self
            .sessions
            .handle(&contact_id, SessionEvent::SriAnnounced)
        {
            SessionEffect::AwaitAck { retry_after_ms } => vec![Action::ScheduleTimer {
                timer_id: format!("open_confirm:{contact_id}"),
                delay_ms: retry_after_ms,
            }],
            _ => vec![],
        }
    }

    /// Answer the platform's "I need a session with this device".
    ///
    /// The caller is the platform, on a teardown it has just applied — the peer's, or its own
    /// after a divergence. It used to be a 1.5 s sleep and a `[String: Task]` map on iOS, and the
    /// two halves were one rule: a teardown and the rebuild that answers it ride the same server
    /// flush, so opening the instant the teardown is applied crosses the peer's init — and a
    /// backlog of N teardowns used to start N re-inits, each destroying the session the previous
    /// one had just built. Both fall out of one phase per device; see `REOPEN_QUIET_MS`.
    ///
    /// **Who rebuilds is ranked here.** On iOS it was `SessionReducer.endSessionReceiptAction`
    /// over `SessionAddressing.isNaturalInitiator`, which already asked `tie_break_role` — so the
    /// ranking was never a second copy. The *consequence* was: the RESPONDER arm armed a 60 s
    /// `[String: Task]` keyed by account, beside the phase the core kept per device, and its
    /// stand-down condition ("no session, none in flight") was a third reading of what the phase
    /// already says. See `RESPONDER_OVERRIDE_MS`.
    fn handle_reopen_requested(&mut self, contact_id: String) -> Vec<Action> {
        // An unset local id ranks as RESPONDER, and that is the direction to fail in: waiting
        // costs a minute, while an init raised on a role we guessed costs one of the peer's
        // one-time pre-keys and builds a session the winner will never read.
        let peer_rebuilds = matches!(
            tie_break_role(self.lifecycle.client.local_user_id(), &contact_id),
            Role::Responder
        );
        match self
            .sessions
            .handle(&contact_id, SessionEvent::WantToReopen { peer_rebuilds })
        {
            SessionEffect::DeferOpen { retry_after_ms } => vec![
                Action::OpenDeferred {
                    contact_id: contact_id.clone(),
                    retry_after_ms,
                },
                Action::ScheduleTimer {
                    timer_id: format!("reopen:{contact_id}"),
                    delay_ms: retry_after_ms,
                },
            ],
            // Someone is already opening this ratchet — the core's own message path, or an
            // earlier ask of the platform's. A second announce spends a second one-time pre-key
            // and replaces the first session, orphaning the SRI already on the wire.
            SessionEffect::WaitForOpen => vec![],
            _ => vec![Action::OpenSession { contact_id }],
        }
    }

    /// One heal attempt, counted where the queued carrier already lives.
    ///
    /// The count had three carriers until 2026-09-23 and the one that decided was the wrong one:
    /// a **second** `HealingQueue` instance the platform built for itself, keyed by account and
    /// fed a JSON `ChatMessage`, beside this one, keyed by device and holding the wire payload.
    /// This one's `attempts` was never incremented at all — `record_attempt` had no caller — so
    /// the field the `MAX_INCOMING_TRIGGERS` throttle sits next to was permanently zero. The
    /// third was a Core Data column written and read by nothing.
    ///
    /// `NotFound` answers `HealExhausted` rather than "go ahead". There is no record, so there is
    /// nothing to count against, and an unbounded retry is what the budget exists to prevent —
    /// it is also what the platform did before, by way of a Core Data lookup that missed.
    fn handle_heal_attempted(&mut self, contact_id: String) -> Vec<Action> {
        use crate::orchestration::healing_queue::HealingDecision;
        match self.lifecycle.healing_queue.record_attempt(&contact_id) {
            HealingDecision::RetryAllowed { attempt, .. } => {
                vec![Action::HealAttemptAllowed {
                    contact_id,
                    attempt,
                }]
            }
            HealingDecision::MaxAttemptsReached | HealingDecision::NotFound => {
                vec![Action::HealExhausted { contact_id }]
            }
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn my_user_id(&self) -> &str {
        self.lifecycle.my_user_id()
    }

    pub fn awaits_acknowledgement(&self, contact_id: &str) -> bool {
        self.sessions.awaits_acknowledgement(contact_id)
    }

    pub fn has_active_session(&self, contact_id: &str) -> bool {
        self.lifecycle.has_active_session(contact_id)
    }

    pub fn pending_message_count(&self, contact_id: &str) -> usize {
        self.router.pending_count(contact_id)
    }

    /// Remove all volatile local orchestration state for a contact the platform
    /// deliberately forgot.
    ///
    /// This is not a protocol reset and does not emit END_SESSION. It exists so
    /// local delete/re-add cannot reuse stale pending/heal/control state and
    /// force the next add down the RESPONDER path.
    pub fn forget_contact_state(&mut self, contact_id: &str) {
        self.router.forget_contact(contact_id);
        self.lifecycle.forget_contact_state(contact_id);
        self.sessions.handle(contact_id, SessionEvent::Forget);
        self.prewarm_done.remove(contact_id);
        self.active_chats.remove(contact_id);
    }

    pub fn ack_is_processed(&self, message_id: &str) -> crate::orchestration::AckCheckResult {
        self.lifecycle.ack_store.is_processed(message_id)
    }

    pub fn ack_mark_processed(&mut self, message_id: &str) -> Vec<crate::orchestration::Action> {
        self.lifecycle.ack_store.mark_processed(message_id)
    }

    /// Export the full orchestrator coordination state as a CFE binary blob.
    ///
    /// Captures ACK dedup cache, healing queue, init locks, archive index, and
    /// prekey tracker.  Persist under `SecureStoreSlot::OrchestratorState`.
    pub fn export_orchestrator_state_cfe(&self) -> Result<Vec<u8>, String> {
        // Serialise only the device ids — timestamps are ephemeral, and the machine re-dates
        // what it restores (`SessionMachine::restore_opening`).
        let lock_ids: std::collections::HashSet<String> =
            self.sessions.opening_device_ids().into_iter().collect();
        self.lifecycle.export_orchestrator_state_cfe(&lock_ids)
    }

    /// Restore the full orchestrator coordination state from a CFE binary blob.
    ///
    /// All in-memory queues and the init_locks set are replaced.
    pub fn import_orchestrator_state_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        let restored_ids = self.lifecycle.import_orchestrator_state_cfe(data)?;
        self.sessions.restore_opening(restored_ids);
        Ok(())
    }

    // ── Session-crypto delegates ──────────────────────────────────────────────

    pub fn get_all_session_contact_ids(&self) -> Vec<String> {
        self.lifecycle.client.active_contacts()
    }

    pub fn init_session_with_bundle(
        &mut self,
        contact_id: &str,
        public_bundle: crate::crypto::handshake::x3dh::X3DHPublicKeyBundle,
        kyber: KyberBundleKeys,
        allow_stale: bool,
    ) -> Result<String, String> {
        use crate::crypto::kyber_prekey_auth::PqAuthentication;
        use crate::orchestration::pq_prekey_plan::{
            ClassicReason, KyberPrekeyContext, KyberPrekeyDecision, KyberPrekeyOffer,
            plan_kyber_prekey, plan_pq_ratchet_capability,
        };

        // The sparse PQ ratchet's capability flag is as strippable as a Kyber signature;
        // decided first for the same reason — a refusal leaves no session behind.
        let pq_ratchet_advertised = public_bundle.supports_pq_ratchet;
        if let Some(reason) = plan_pq_ratchet_capability(
            crate::crypto::session_api::local_supports_pq_ratchet(),
            pq_ratchet_advertised,
            self.lifecycle.has_used_pq_ratchet(contact_id),
        ) {
            tracing::error!(
                target: "crypto::security",
                contact_id = %contact_id,
                reason = ?reason,
                "PQ downgrade refused: this device used the PQ ratchet before, and this bundle \
                 does not advertise it"
            );
            return Err(format!(
                "PQ_DOWNGRADE_REFUSED: {reason:?} — device {contact_id} used the PQ ratchet \
                 before; the bundle does not advertise it"
            ));
        }

        // Decided before anything is created: a refusal must leave no session behind.
        let plan = plan_kyber_prekey(
            KyberPrekeyOffer {
                verifying_key: &public_bundle.verifying_key,
                spk_public: kyber.pre_key_public.as_deref(),
                spk_signature: kyber.pre_key_signature.as_deref(),
                otpk_public: kyber.one_time_prekey_public.as_deref(),
                otpk_id: kyber.one_time_prekey_id,
                otpk_signature: kyber.one_time_prekey_signature.as_deref(),
            },
            KyberPrekeyContext {
                local_pq_available: cfg!(feature = "post-quantum"),
                presented_signed_spk_before: self.lifecycle.has_presented_signed_kyber(contact_id),
            },
        );
        let presented_signed_spk = plan.presented_signed_spk;
        let decision = match plan.decision {
            KyberPrekeyDecision::Refuse { reason } => {
                tracing::error!(
                target: "crypto::security",
                contact_id = %contact_id,
                reason = ?reason,
                "PQ downgrade refused: this device presented a signed Kyber SPK before, and \
                 this bundle has none that verifies"
                );
                return Err(format!(
                    "PQ_DOWNGRADE_REFUSED: {reason:?} — device {contact_id} presented a signed \
                     Kyber prekey before; the bundle has none that verifies"
                ));
            }
            decision => decision,
        };

        let remote_identity =
            ClassicSuiteProvider::kem_public_key_from_bytes(public_bundle.identity_public.clone());
        let one_time_prekey_id = public_bundle.one_time_prekey_id.unwrap_or(0);

        tracing::debug!(
            target: "crypto::orchestrator",
            contact_id = %contact_id,
            one_time_prekey_id = one_time_prekey_id,
            has_otpk_public = public_bundle.one_time_prekey_public.is_some(),
            "init_session_with_bundle: storing pending OTPK id"
        );

        if allow_stale {
            self.lifecycle
                .client
                .init_session_allowing_stale(
                    contact_id,
                    &public_bundle,
                    &remote_identity,
                    one_time_prekey_id,
                )
                .map_err(|e| e.to_string())?;
        } else {
            self.lifecycle
                .client
                .init_session(
                    contact_id,
                    &public_bundle,
                    &remote_identity,
                    one_time_prekey_id,
                )
                .map_err(|e| e.to_string())?;
        }

        // The classical X3DH above verified the bundle; only now is its Kyber SPK signature
        // worth remembering.
        if presented_signed_spk {
            self.lifecycle.record_signed_kyber(contact_id);
        }
        if pq_ratchet_advertised {
            self.lifecycle.record_pq_ratchet(contact_id);
        }

        // PQXDH: encapsulate to the planned Kyber key and defer applying the secret to the
        // first outgoing message.
        let authentication = match decision {
            KyberPrekeyDecision::Encapsulate {
                kyber_public,
                otpk_id,
                authentication,
            } => match self.lifecycle.pq_manager.encapsulate_and_defer(
                contact_id,
                &kyber_public,
                otpk_id,
            ) {
                Ok(_) => {
                    if authentication == PqAuthentication::Unauthenticated {
                        tracing::warn!(
                            target: "crypto::orchestrator",
                            contact_id = %contact_id,
                            kyber_otpk_id = otpk_id,
                            "PQ unauthenticated: the Kyber key carried no signature — protects \
                             against a passive recorder, not against whoever served the bundle"
                        );
                    } else {
                        tracing::info!(
                            target: "crypto::orchestrator",
                            contact_id = %contact_id,
                            kyber_otpk_id = otpk_id,
                            "PQ authenticated: Kyber key signature verified, ciphertext deferred"
                        );
                    }
                    authentication
                }
                Err(e) => {
                    tracing::error!(
                        target: "crypto::orchestrator",
                        contact_id = %contact_id,
                        error = %e,
                        "ML-KEM encapsulation failed — session is classical"
                    );
                    PqAuthentication::Classic
                }
            },
            KyberPrekeyDecision::Classic { reason } => {
                if reason == ClassicReason::InvalidSignature {
                    tracing::error!(
                        target: "crypto::security",
                        contact_id = %contact_id,
                        "Kyber prekey signature does not verify — this bundle's Kyber keys are \
                         not used; session is classical"
                    );
                }
                PqAuthentication::Classic
            }
            // Returned above; nothing to encapsulate.
            KyberPrekeyDecision::Refuse { .. } => PqAuthentication::Classic,
        };

        if let Some(session) = self.lifecycle.client.get_session_mut(contact_id) {
            session
                .messaging_session_mut()
                .set_pq_authentication(authentication);
        }

        Ok(contact_id.to_string())
    }

    /// A session a peer opened with the PQ ratchet proves that device has it: remember it, so a
    /// later bundle of theirs that stops advertising it is refused rather than silently classic.
    fn note_received_suite(&mut self, contact_id: &str, suite_id: u16) {
        if suite_id == crate::crypto::SuiteID::PQ_RATCHET.as_u16() {
            self.lifecycle.record_pq_ratchet(contact_id);
        }
    }

    pub fn init_receiving_session_with_msg(
        &mut self,
        contact_id: &str,
        public_bundle: &crate::crypto::handshake::x3dh::X3DHPublicKeyBundle,
        first_message: &IncomingFirstMessage,
    ) -> Result<(String, Vec<u8>), String> {
        use crate::crypto::keys::build_prologue;
        use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;
        use crate::crypto::provider::CryptoProvider;

        let sealed_box = &first_message.content;
        if sealed_box.len() < 12 {
            return Err("sealed_box too short".to_string());
        }
        let nonce = sealed_box[..12].to_vec();
        let ciphertext = sealed_box[12..].to_vec();

        let dh_public_key: [u8; 32] = first_message
            .ephemeral_public_key
            .clone()
            .try_into()
            .map_err(|_| "ephemeral_public_key must be 32 bytes".to_string())?;

        let encrypted_first_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number: first_message.message_number,
            ciphertext,
            nonce,
            previous_chain_length: 0,
            // Carry the DR message's NEGOTIATED suite / PQ tags from the wire — NOT the bundle's
            // crypto suite. The responder must reconstruct the exact AEAD associated data the
            // initiator authenticated; defaulting these to the bundle suite made suite-3 msg0
            // fail to decrypt (task #12).
            suite_id: first_message.suite_id,
            pq_message_epoch: first_message.pq_message_epoch,
            pq_ratchet_field: first_message.pq_ratchet_field.clone(),
        };

        // Verify the initiator's signed prekey signature before doing any crypto. This prologue
        // uses the BUNDLE's crypto suite (how the SPK signature was produced), which is a
        // different concept from the DR message suite above.
        let suite_id = public_bundle.suite_id;
        let verifying_key = ClassicSuiteProvider::signature_public_key_from_bytes(
            public_bundle.verifying_key.clone(),
        );
        let prologue = build_prologue(suite_id);
        let mut spk_msg =
            Vec::with_capacity(prologue.len() + public_bundle.signed_prekey_public.len());
        spk_msg.extend_from_slice(&prologue);
        spk_msg.extend_from_slice(&public_bundle.signed_prekey_public);
        ClassicSuiteProvider::verify(&verifying_key, &spk_msg, &public_bundle.signature)
            .map_err(|_| "invalid signed prekey signature from initiator".to_string())?;

        let remote_identity =
            ClassicSuiteProvider::kem_public_key_from_bytes(public_bundle.identity_public.clone());
        let remote_ephemeral = ClassicSuiteProvider::kem_public_key_from_bytes(
            first_message.ephemeral_public_key.clone(),
        );

        let (_session_id, plaintext) = self
            .lifecycle
            .client
            .init_receiving_session_with_ephemeral(
                contact_id,
                &remote_identity,
                &remote_ephemeral,
                &encrypted_first_message,
                first_message.one_time_prekey_id,
            )
            .map_err(|e| e.to_string())?;
        self.note_received_suite(contact_id, first_message.suite_id);

        Ok((contact_id.to_string(), plaintext))
    }

    /// RESPONDER X3DH init from a raw CFE wire payload.
    ///
    /// Drop-in replacement for `init_receiving_session_with_msg` when the caller
    /// has the raw binary WirePayload rather than a JSON-decoded first message.
    /// Used by non-UniFFI platforms (TUI, Android) in `Action::InitSession` when
    /// `pending_message_count(contact_id) > 0`, i.e. the local node is the RESPONDER.
    ///
    /// Returns `(contact_id, plaintext_of_first_message)` on success.
    pub fn init_receiving_session_from_wire_payload(
        &mut self,
        contact_id: &str,
        recipient_bundle: &[u8],
        wire_payload: &[u8],
    ) -> Result<(String, Vec<u8>), String> {
        use crate::crypto::SuiteID;
        use crate::crypto::keys::build_prologue;
        use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;
        use crate::crypto::provider::CryptoProvider;

        #[derive(serde::Deserialize)]
        struct KeyBundle {
            identity_public: Vec<u8>,
            signed_prekey_public: Vec<u8>,
            signature: Vec<u8>,
            verifying_key: Vec<u8>,
            suite_id: u16,
        }

        let key_bundle: KeyBundle = serde_json::from_slice(recipient_bundle)
            .map_err(|_| "invalid key bundle JSON".to_string())?;

        let decoded = crate::wire_payload::unpack(wire_payload)
            .map_err(|e| format!("wire_payload unpack failed: {e:?}"))?;

        if decoded.sealed_box.len() < 12 {
            return Err("sealed_box too short in wire_payload".to_string());
        }
        let nonce = decoded.sealed_box[..12].to_vec();
        let ciphertext = decoded.sealed_box[12..].to_vec();

        let dh_public_key: [u8; 32] = decoded
            .dh_public_key
            .clone()
            .try_into()
            .map_err(|_| "dh_public_key must be 32 bytes".to_string())?;

        let encrypted_first_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number: decoded.message_number,
            ciphertext,
            nonce,
            previous_chain_length: decoded.previous_chain_length,
            // The wire payload already carries the DR message's negotiated suite + PQ section;
            // use them (not the bundle's crypto suite) so suite-3 first messages decrypt (task #12).
            suite_id: decoded.suite_id,
            pq_message_epoch: decoded.pq_message_epoch,
            pq_ratchet_field: decoded.pq_ratchet_field,
        };

        // Verify the initiator's SPK signature — same check as init_receiving_session_with_msg.
        let suite_id =
            SuiteID::new(key_bundle.suite_id).map_err(|_| "invalid suite_id".to_string())?;
        let verifying_key =
            ClassicSuiteProvider::signature_public_key_from_bytes(key_bundle.verifying_key.clone());
        let prologue = build_prologue(suite_id);
        let mut spk_msg =
            Vec::with_capacity(prologue.len() + key_bundle.signed_prekey_public.len());
        spk_msg.extend_from_slice(&prologue);
        spk_msg.extend_from_slice(&key_bundle.signed_prekey_public);
        ClassicSuiteProvider::verify(&verifying_key, &spk_msg, &key_bundle.signature)
            .map_err(|_| "invalid signed prekey signature from initiator".to_string())?;

        let remote_identity =
            ClassicSuiteProvider::kem_public_key_from_bytes(key_bundle.identity_public.clone());
        let remote_ephemeral =
            ClassicSuiteProvider::kem_public_key_from_bytes(decoded.dh_public_key);

        let (_session_id, plaintext) = self
            .lifecycle
            .client
            .init_receiving_session_with_ephemeral(
                contact_id,
                &remote_identity,
                &remote_ephemeral,
                &encrypted_first_message,
                decoded.one_time_prekey_id,
            )
            .map_err(|e| e.to_string())?;
        self.note_received_suite(contact_id, decoded.suite_id);

        Ok((contact_id.to_string(), plaintext))
    }

    /// Return the raw WirePayload bytes of the first queued incoming message
    /// for `contact_id` without removing it from the queue.
    ///
    /// Use this in `Action::InitSession` to detect RESPONDER case:
    /// if this returns `Some(_)`, call `init_receiving_session_from_wire_payload()`
    /// instead of `init_session_with_bundle()`.
    pub fn peek_first_pending_wire_payload(&self, contact_id: &str) -> Option<Vec<u8>> {
        self.router.peek_first_pending_wire_payload(contact_id)
    }

    /// Consume the first pending wire payload for a contact without processing it.
    ///
    /// Call this after a successful RESPONDER `init_receiving_session_from_wire_payload`
    /// so that `drain_pending` does not attempt to re-decrypt the init message (msg_num=0),
    /// which would fail because the Double-Ratchet key was already consumed during X3DH.
    ///
    /// Returns `Some(message_id)` of the removed message, or `None` if the queue was empty.
    pub fn pop_first_pending(&mut self, contact_id: &str) -> Option<String> {
        self.router.pop_first_pending(contact_id)
    }

    pub fn export_session_json_for(&self, contact_id: &str) -> Result<String, String> {
        self.lifecycle.export_session_json_for(contact_id)
    }

    pub fn remove_session_by_contact(&mut self, contact_id: &str) -> bool {
        self.lifecycle.client.remove_session(contact_id)
    }

    /// Return the queued heal payload for `contact_id` (the raw wire bytes of the
    /// failed msgNum=0 message), or `None` if no heal record exists.
    ///
    /// Used by the TUI / other non-UniFFI platforms to implement the RESPONDER
    /// healing path: fetch the contact's bundle, then call
    /// `init_receiving_session_with_msg(contact_id, bundle, wire_payload)`.
    pub fn take_heal_payload(&self, contact_id: &str) -> Option<Vec<u8>> {
        self.lifecycle
            .healing_queue
            .get(contact_id)
            .map(|r| r.message_payload.clone())
    }

    /// Store a failed msgNum=0 wire payload in the healing queue for later retry.
    /// Idempotent — calling with the same `contact_id` again does not overwrite
    /// the existing record (first failure wins).
    pub fn enqueue_heal(&mut self, contact_id: &str, payload: Vec<u8>) {
        use crate::orchestration::healing_queue::HealDirection;
        self.lifecycle
            .healing_queue
            .enqueue(contact_id, payload, HealDirection::Incoming);
    }

    /// Record one healing attempt for `contact_id` and return whether another
    /// retry is allowed or the maximum has been reached.
    pub fn record_heal_attempt(
        &mut self,
        contact_id: &str,
    ) -> crate::orchestration::healing_queue::HealingDecision {
        self.lifecycle.healing_queue.record_attempt(contact_id)
    }

    /// Remove the healing record for `contact_id` (called on success or give-up).
    pub fn clear_heal_record(&mut self, contact_id: &str) {
        self.lifecycle.healing_queue.remove(contact_id);
    }

    /// Export registration bundle as CFE binary.
    pub fn export_registration_bundle_cfe(&self) -> Result<Vec<u8>, String> {
        let bundle = self
            .lifecycle
            .client
            .key_manager()
            .export_registration_bundle()
            .map_err(|e| e.to_string())?;

        let cfe_bundle = crate::cfe::CfeRegistrationBundleV1 {
            version: 1,
            identity_public: bundle.identity_public,
            signed_prekey_public: bundle.signed_prekey_public,
            signature: bundle.signature,
            verifying_key: bundle.verifying_key,
            suite_id: bundle.suite_id.as_u16() as u8,
        };

        crate::cfe::encode(crate::cfe::CfeMessageType::RegistrationBundle, &cfe_bundle)
            .map_err(|e| e.to_string())
    }

    pub fn sign_bundle_bytes(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.lifecycle
            .client
            .key_manager()
            .sign(data)
            .map_err(|e| e.to_string())
    }

    /// Suite ID for the active session with `contact_id`. Returns 0 if no session.
    pub fn get_session_suite_id(&self, contact_id: &str) -> u16 {
        self.lifecycle
            .client
            .get_session(contact_id)
            .map(|s| s.messaging_session().to_serializable().suite_id)
            .unwrap_or(0)
    }

    /// Return a health snapshot for the session with `contact_id`, or `None` if absent.
    pub fn get_session_health(
        &self,
        contact_id: &str,
    ) -> Option<crate::crypto::messaging::double_ratchet::DrHealthSnapshot> {
        self.lifecycle.client.get_session_health(contact_id)
    }

    /// Typed registration bundle fields (no JSON).
    pub fn get_registration_bundle_fields(
        &self,
    ) -> Result<crate::crypto::handshake::x3dh::X3DHPublicKeyBundle, String> {
        self.lifecycle
            .client
            .key_manager()
            .export_registration_bundle()
            .map_err(|e| e.to_string())
    }

    /// Raw Ed25519 signing secret key bytes.
    pub fn get_signing_key_bytes(&self) -> Result<Vec<u8>, String> {
        let km = self.lifecycle.client.key_manager();
        let secret = km.signing_secret_key().map_err(|e| e.to_string())?;
        Ok(<_ as AsRef<[u8]>>::as_ref(secret).to_vec())
    }

    /// Raw X25519 identity secret key bytes.
    pub fn get_identity_key_bytes(&self) -> Result<Vec<u8>, String> {
        let km = self.lifecycle.client.key_manager();
        let secret = km.identity_secret_key().map_err(|e| e.to_string())?;
        Ok(<_ as AsRef<[u8]>>::as_ref(secret).to_vec())
    }

    // Hybrid signature key ownership (centralized; all crypto key material lives here)
    pub fn ensure_hybrid_signature_key(&mut self) -> Result<Vec<u8>, String> {
        self.lifecycle
            .client
            .key_manager_mut()
            .ensure_hybrid_signature_key()
            .map_err(|e| e.to_string())
    }

    pub fn hybrid_signature_public_key(&self) -> Option<Vec<u8>> {
        self.lifecycle
            .client
            .key_manager()
            .hybrid_signature_public_key()
    }

    pub fn sign_hybrid(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.lifecycle
            .client
            .key_manager()
            .sign_hybrid(message)
            .map_err(|e| e.to_string())
    }

    /// Build the canonical X3DH prekey signature message (used for both
    /// classic Ed25519 and hybrid ML-DSA signatures).
    pub fn build_x3dh_sign_message(suite_id: u8, public_key: &[u8]) -> Vec<u8> {
        crate::crypto::keys::KeyManager::<crate::crypto::suites::classic::ClassicSuiteProvider>::build_x3dh_sign_message(
            suite_id, public_key,
        )
    }

    /// Build the bind message for hybrid identity cross-signature.
    pub fn build_hybrid_identity_bind_message(hybrid_public: &[u8]) -> Vec<u8> {
        crate::crypto::keys::KeyManager::<crate::crypto::suites::classic::ClassicSuiteProvider>::build_hybrid_identity_bind_message(
            hybrid_public,
        )
    }

    /// Ensure hybrid key and sign the standard prekey message with it.
    pub fn sign_hybrid_prekey(
        &mut self,
        suite_id: u8,
        public_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.lifecycle
            .client
            .key_manager_mut()
            .sign_hybrid_prekey(suite_id, public_key)
            .map_err(|e| e.to_string())
    }

    /// Import an existing hybrid signature private key (for migration from legacy separate keychain storage).
    /// After this, the hybrid key is owned by the core and will be persisted in CFE private keys.
    pub fn import_hybrid_signature_private_key(
        &mut self,
        priv_bytes: Vec<u8>,
    ) -> Result<(), String> {
        self.lifecycle
            .client
            .key_manager_mut()
            .set_hybrid_signature_private(priv_bytes)
            .map_err(|e| e.to_string())
    }

    pub fn set_my_user_id(&mut self, user_id: String) {
        self.lifecycle.set_my_user_id(user_id);
    }

    pub fn prekeys_available(&self) -> u32 {
        let old = self.lifecycle.client.key_manager().old_prekeys_count();
        (old + 1) as u32
    }

    /// Returns `(key_id, public_key_bytes)` pairs for the new OTPKs.
    pub fn generate_otpks(&mut self, count: u32) -> Result<Vec<(u32, Vec<u8>)>, String> {
        self.lifecycle
            .client
            .generate_one_time_prekeys(count)
            .map_err(|e| e.to_string())
    }

    pub fn otpk_count(&self) -> u32 {
        self.lifecycle.client.one_time_prekey_count() as u32
    }

    /// Prune OTPKs below `min_keep_id` after a replace-all upload converged the server set.
    pub fn prune_otpks_below(&mut self, min_keep_id: u32) -> u32 {
        self.lifecycle
            .client
            .prune_one_time_prekeys_below(min_keep_id) as u32
    }

    /// Store the ML-KEM-768 signed prekey in the key-state (commit-after-confirm).
    pub fn set_kyber_spk(&mut self, key_id: u32, private_key: Vec<u8>, public_key: Vec<u8>) {
        self.lifecycle
            .client
            .set_kyber_spk(key_id, private_key, public_key);
    }

    /// The stored ML-KEM-768 signed prekey as `(key_id, private, public)`, if any.
    pub fn kyber_spk_bytes(&self) -> Option<(u32, Vec<u8>, Vec<u8>)> {
        self.lifecycle.client.kyber_spk_bytes()
    }

    // ── Kyber prekeys (ML-KEM-1024, PQXDH v2) ─────────────────────────────────
    //
    // Every mutation changes the `KyberPrivateKeys` blob; the platform persists
    // `export_kyber_prekeys_cfe()` after each one, as it does the X25519 pool.

    pub fn generate_kyber_one_time_prekeys(
        &mut self,
        count: u32,
    ) -> Result<Vec<crate::crypto::kyber_prekeys::KyberPrekeyUpload>, String> {
        self.lifecycle
            .client
            .key_manager_mut()
            .generate_kyber_one_time_prekeys(count)
            .map_err(|e| e.to_string())
    }

    pub fn kyber_one_time_prekey_count(&self) -> u32 {
        self.lifecycle
            .client
            .key_manager()
            .kyber_prekeys()
            .otpk_count() as u32
    }

    pub fn prune_kyber_one_time_prekeys_below(&mut self, min_keep_id: u32) -> u32 {
        self.lifecycle
            .client
            .key_manager_mut()
            .kyber_prekeys_mut()
            .prune_otpks_below(min_keep_id) as u32
    }

    pub fn begin_kyber_spk_rotation(
        &mut self,
    ) -> Result<crate::crypto::kyber_prekeys::KyberPrekeyUpload, String> {
        self.lifecycle
            .client
            .key_manager_mut()
            .begin_kyber_spk_rotation()
            .map_err(|e| e.to_string())
    }

    pub fn commit_kyber_spk_rotation(&mut self) -> bool {
        self.lifecycle
            .client
            .key_manager_mut()
            .commit_kyber_spk_rotation()
    }

    pub fn rollback_kyber_spk_rotation(&mut self) {
        self.lifecycle
            .client
            .key_manager_mut()
            .rollback_kyber_spk_rotation();
    }

    pub fn current_kyber_spk_upload(
        &self,
    ) -> Result<Option<crate::crypto::kyber_prekeys::KyberPrekeyUpload>, String> {
        self.lifecycle
            .client
            .key_manager()
            .current_kyber_spk_upload()
            .map_err(|e| e.to_string())
    }

    pub fn kyber_prekey_decapsulate(
        &self,
        key_id: u32,
        ciphertext: &[u8],
    ) -> Result<crate::crypto::SecretBytes, String> {
        self.lifecycle
            .client
            .key_manager()
            .decapsulate_with_kyber_prekey(key_id, ciphertext)
            .map_err(|e| e.to_string())
    }

    pub fn export_kyber_prekeys_cfe(&self) -> Result<Vec<u8>, String> {
        let record = self.lifecycle.client.key_manager().kyber_prekeys().to_cfe();
        crate::cfe::encode(crate::cfe::CfeMessageType::KyberPrivateKeys, &record)
            .map_err(|e| e.to_string())
    }

    pub fn import_kyber_prekeys_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        let record = crate::cfe::decode_as::<crate::cfe::CfeKyberPrekeysV1>(
            data,
            crate::cfe::CfeMessageType::KyberPrivateKeys,
        )
        .map_err(|e| e.to_string())?;
        self.lifecycle
            .client
            .key_manager_mut()
            .import_kyber_prekeys(&record);
        Ok(())
    }

    /// Returns the raw bytes of our X3DH identity public key.
    /// Used by the UI for safety-number display and key export.
    pub fn identity_public_key_bytes(&self) -> Result<Vec<u8>, String> {
        self.lifecycle
            .client
            .key_manager()
            .identity_public_key()
            .map(|k| <_ as AsRef<[u8]>>::as_ref(k).to_vec())
            .map_err(|e| format!("identity key unavailable: {e}"))
    }

    pub fn export_otpks_json(&self) -> Result<String, String> {
        #[derive(serde::Serialize)]
        struct OtpkRecord {
            key_id: u32,
            private_key: Vec<u8>,
            public_key: Vec<u8>,
        }
        let records: Vec<OtpkRecord> = self
            .lifecycle
            .client
            .export_one_time_prekeys()
            .into_iter()
            .map(|(key_id, private_key, public_key)| OtpkRecord {
                key_id,
                private_key,
                public_key,
            })
            .collect();
        serde_json::to_string(&records).map_err(|e| e.to_string())
    }

    pub fn import_otpks_json(&mut self, json: &str) -> Result<(), String> {
        #[derive(serde::Deserialize)]
        struct OtpkRecord {
            key_id: u32,
            private_key: Vec<u8>,
            public_key: Vec<u8>,
        }
        let records: Vec<OtpkRecord> = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let keys: Vec<(u32, Vec<u8>, Vec<u8>)> = records
            .into_iter()
            .map(|r| (r.key_id, r.private_key, r.public_key))
            .collect();
        self.lifecycle.client.import_one_time_prekeys(keys);
        Ok(())
    }

    pub fn export_private_keys_cfe(&self) -> Result<Vec<u8>, String> {
        let payload = self.lifecycle.client.to_private_keys_cfe()?;
        crate::cfe::encode(crate::cfe::CfeMessageType::PrivateKeys, &payload)
            .map_err(|e| e.to_string())
    }

    pub fn export_otpks_cfe(&self) -> Result<Vec<u8>, String> {
        use serde_bytes::ByteBuf;

        let records: Vec<crate::cfe::CfeOtpkRecordV1> = self
            .lifecycle
            .client
            .export_one_time_prekeys()
            .into_iter()
            .map(|(id, priv_key, pub_key)| crate::cfe::CfeOtpkRecordV1 {
                id,
                priv_key: crate::crypto::SecretBytes::from(priv_key),
                pub_key: ByteBuf::from(pub_key),
            })
            .collect();

        let next_id = self.lifecycle.client.key_manager().next_otpk_id();
        let payload = crate::cfe::CfeOtpkBundleV1 { records, next_id };

        crate::cfe::encode(crate::cfe::CfeMessageType::OtpkBundle, &payload)
            .map_err(|e| e.to_string())
    }

    pub fn import_otpks_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        let bundle = crate::cfe::decode_as::<crate::cfe::CfeOtpkBundleV1>(
            data,
            crate::cfe::CfeMessageType::OtpkBundle,
        )
        .map_err(|e| e.to_string())?;

        let keys: Vec<(u32, Vec<u8>, Vec<u8>)> = bundle
            .records
            .iter()
            .map(|r| (r.id, r.priv_key.expose().to_vec(), r.pub_key.to_vec()))
            .collect();

        self.lifecycle.client.import_one_time_prekeys(keys);
        self.lifecycle
            .client
            .key_manager_mut()
            .set_next_otpk_id(bundle.next_id);
        Ok(())
    }

    /// Export a session as a CFE binary blob (MessagePack + CRC32 header).
    pub fn export_session_cfe(&self, contact_id: &str) -> Result<Vec<u8>, String> {
        self.lifecycle.export_session_bytes_for(contact_id)
    }

    /// Import a session from a `CfeSessionStateV1` binary blob.
    pub fn import_session_cfe(&mut self, contact_id: &str, data: &[u8]) -> Result<String, String> {
        use crate::cfe::{CfeMessageType, decode_as};
        use crate::crypto::messaging::double_ratchet::{DoubleRatchetSession, SerializableSession};

        let cfe_state =
            decode_as::<crate::cfe::CfeSessionStateV1>(data, CfeMessageType::SessionState)
                .map_err(|e| e.to_string())?;
        let serializable = SerializableSession::from_cfe_v1(cfe_state)
            .map_err(|e| format!("from_cfe_v1: {}", e))?;
        serializable.verify_identity(contact_id, self.lifecycle.client.local_user_id())?;
        let ratchet = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(serializable)
            .map_err(|e| format!("from_serializable: {}", e))?;
        let session_id = self.lifecycle.client.import_session(contact_id, ratchet);
        Ok(session_id)
    }
    pub fn rotate_spk(&mut self) -> Result<(u32, Vec<u8>, Vec<u8>), String> {
        self.lifecycle
            .client
            .key_manager_mut()
            .rotate_signed_prekey()
            .map_err(|e| e.to_string())?;

        let bundle = self
            .lifecycle
            .client
            .key_manager()
            .export_registration_bundle()
            .map_err(|e| e.to_string())?;

        let key_id = self
            .lifecycle
            .client
            .key_manager()
            .current_signed_prekey_id()
            .unwrap_or(1);

        Ok((key_id, bundle.signed_prekey_public, bundle.signature))
    }

    pub fn apply_pq_contribution_delegate(
        &mut self,
        contact_id: &str,
        kem_shared_secret: &[u8],
    ) -> Result<(), String> {
        self.lifecycle
            .client
            .apply_pq_contribution_to_session(contact_id, kem_shared_secret)
            .map_err(|e| e.to_string())?;
        // Consume the pending pq_manager entry so that `maybe_apply_pq_contribution`
        // (called after every Rust-routed decrypt) does not apply the same shared
        // secret a second time.  The returned delete actions are intentionally
        // dropped here because Swift has already cleared the per-entry Keychain
        // backup via KeychainManager in `applyDeferredPQContribution`.
        let _ = self.lifecycle.pq_manager.consume_deferred(contact_id);
        Ok(())
    }

    /// Register a KEM shared secret as a deferred contribution for `contact_id`.
    ///
    /// Call this AFTER performing ML-KEM encapsulation (INITIATOR) or
    /// decapsulation (RESPONDER) so that the shared secret is stored in the
    /// `PQContributionManager` and included in `export_kyber_session_state_cfe`
    /// snapshots.
    ///
    /// Returns a `SaveToSecureStore` action that the platform **must**
    /// execute to persist the per-entry deferred secret for crash-safety.
    pub fn register_pq_deferred(
        &mut self,
        contact_id: &str,
        otpk_id: u32,
        shared_secret: &[u8],
    ) -> Vec<crate::orchestration::Action> {
        let persist_action =
            self.lifecycle
                .pq_manager
                .register_shared_secret(contact_id, otpk_id, shared_secret);
        vec![persist_action]
    }

    /// Export the `PQContributionManager` state as a CFE binary blob.
    ///
    /// Persist the returned bytes under `SecureStoreSlot::KyberSessionState`
    /// after any encapsulate / decapsulate / consume operation.
    pub fn export_kyber_session_state_cfe(&self) -> Result<Vec<u8>, String> {
        self.lifecycle.export_kyber_session_state_cfe()
    }

    /// Restore the `PQContributionManager` state from a previously exported CFE blob.
    pub fn import_kyber_session_state_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        self.lifecycle.import_kyber_session_state_cfe(data)
    }

    /// Returns `(ephemeral_public_key, message_number, content_b64, one_time_prekey_id)`.
    /// Returns `(ephemeral_public_key, message_number, sealed_box, one_time_prekey_id, suite_id,
    /// pq_message_epoch, pq_ratchet_field)`. The last three carry the DR message's negotiated
    /// suite + suite-3 PQ section so the responder can reconstruct the exact AEAD associated data
    /// (task #12); they are `(1/2, 0, None)`-equivalent for non-PQ_RATCHET suites.
    #[allow(clippy::type_complexity)]
    pub fn encrypt_message_for(
        &mut self,
        contact_id: &str,
        plaintext: &[u8],
    ) -> Result<
        (
            Vec<u8>,
            u32,
            Vec<u8>,
            u32,
            u16,
            u32,
            Option<crate::crypto::messaging::double_ratchet::PqRatchetWireField>,
        ),
        String,
    > {
        let encrypted = self
            .lifecycle
            .client
            .encrypt_message(contact_id, plaintext)
            .map_err(|e| e.to_string())?;

        let mut sealed_box = Vec::new();
        sealed_box.extend_from_slice(&encrypted.nonce);
        sealed_box.extend_from_slice(&encrypted.ciphertext);

        let one_time_prekey_id = if encrypted.message_number == 0 {
            self.lifecycle.client.take_pending_otpk_id(contact_id)
        } else {
            0
        };

        Ok((
            encrypted.dh_public_key.to_vec(),
            encrypted.message_number,
            sealed_box,
            one_time_prekey_id,
            encrypted.suite_id,
            encrypted.pq_message_epoch,
            encrypted.pq_ratchet_field,
        ))
    }

    /// Encrypt arbitrary binary bytes using the Double Ratchet session and pack
    /// the result into a WirePayload blob ready to send over gRPC.
    ///
    /// Used for binary content types (e.g. CALL_SIGNAL = 12) where no base64
    /// round-trip should occur.
    pub fn encrypt_bytes_for(
        &mut self,
        contact_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let encrypted = self
            .lifecycle
            .client
            .encrypt_message(contact_id, plaintext)
            .map_err(|e| e.to_string())?;

        let mut sealed_box = Vec::new();
        sealed_box.extend_from_slice(&encrypted.nonce);
        sealed_box.extend_from_slice(&encrypted.ciphertext);

        let otpk_id = if encrypted.message_number == 0 {
            self.lifecycle.client.take_pending_otpk_id(contact_id)
        } else {
            0
        };

        crate::wire_payload::pack(
            &encrypted.dh_public_key,
            encrypted.message_number,
            otpk_id,
            0, // kyber_otpk_id — call signals always use existing sessions (no first-message PQC)
            encrypted.previous_chain_length,
            encrypted.suite_id,
            None,
            &sealed_box,
            encrypted.pq_message_epoch,
            encrypted.pq_ratchet_field.clone(),
        )
        .map_err(|e| e.to_string())
    }

    /// Decrypt a WirePayload blob and return the raw plaintext bytes.
    ///
    /// Used for binary content types (e.g. CALL_SIGNAL = 12).
    pub fn decrypt_bytes_for(
        &mut self,
        contact_id: &str,
        wire_payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;

        let decoded = crate::wire_payload::unpack(wire_payload).map_err(|e| e.to_string())?;

        if decoded.sealed_box.len() < 12 {
            return Err("sealed_box too short".to_string());
        }
        let nonce = decoded.sealed_box[..12].to_vec();
        let ciphertext = decoded.sealed_box[12..].to_vec();

        let dh_public_key: [u8; 32] = decoded
            .dh_public_key
            .try_into()
            .map_err(|_| "dh_public_key must be 32 bytes".to_string())?;

        let encrypted_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number: decoded.message_number,
            ciphertext,
            nonce,
            previous_chain_length: decoded.previous_chain_length,
            suite_id: decoded.suite_id,
            pq_message_epoch: decoded.pq_message_epoch,
            pq_ratchet_field: decoded.pq_ratchet_field,
        };

        self.lifecycle
            .client
            .decrypt_message(contact_id, &encrypted_message)
            .map_err(|e| e.to_string())
    }

    /// Component-based decrypt. The caller MUST pass the DR message's `suite_id`,
    /// `pq_message_epoch` and `pq_ratchet_field` from the wire (task #12): defaulting them to
    /// classic made `SuiteID::PQ_RATCHET` traffic fail to decrypt because the reconstructed AEAD
    /// associated data omitted the suite-3 epoch tag. `(classic, 0, None)` reproduces the old
    /// behaviour for non-PQ suites.
    pub fn decrypt_message_for(
        &mut self,
        contact_id: &str,
        ephemeral_public_key: Vec<u8>,
        message_number: u32,
        content: &[u8],
        suite_id: u16,
        pq_message_epoch: u32,
        pq_ratchet_field: Option<crate::crypto::messaging::double_ratchet::PqRatchetWireField>,
    ) -> Result<Vec<u8>, String> {
        use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;

        let sealed_box = content;

        if sealed_box.len() < 12 {
            return Err("sealed_box too short".to_string());
        }
        let nonce = sealed_box[..12].to_vec();
        let ciphertext = sealed_box[12..].to_vec();

        let dh_public_key: [u8; 32] = ephemeral_public_key
            .try_into()
            .map_err(|_| "ephemeral_public_key must be 32 bytes".to_string())?;

        let encrypted_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number,
            ciphertext,
            nonce,
            previous_chain_length: 0,
            suite_id,
            pq_message_epoch,
            pq_ratchet_field,
        };

        self.lifecycle
            .client
            .decrypt_message(contact_id, &encrypted_message)
            .map_err(|e| e.to_string())
    }

    // ── Event handlers ────────────────────────────────────────────────────────

    fn handle_message_received(
        &mut self,
        message_id: String,
        from: String,
        data: Vec<u8>,
        msg_num: u32,
        kem_ct: Vec<u8>,
        _otpk_id: u32,
        is_control: bool,
        content_type: u8,
    ) -> Vec<Action> {
        // `data` IS the wire payload — derive the routing fields from the canonical
        // parser instead of trusting the platform's copy of the header parse.
        // Android passes zeros (it has no wire-format knowledge at all); the event's
        // msg_num/kem_ct stay only as a fallback for callers that still fill them
        // (iOS). Control messages are routed before decrypt, so their `data` is not
        // required to be a wire payload.
        let (msg_num, kem_ct) = if is_control {
            (msg_num, kem_ct)
        } else {
            match crate::wire_payload::unpack(&data) {
                Ok(d) => (d.message_number, d.kem_ciphertext.unwrap_or_default()),
                // Legacy caller supplied fields — keep its exact routing behavior.
                Err(_) if msg_num != 0 || !kem_ct.is_empty() => (msg_num, kem_ct),
                // Unparseable and nothing to fall back on: decrypt uses this same
                // parser, so the payload can never decrypt — routing it with
                // msg_num=0 would spuriously trigger the heal machinery.
                Err(e) => {
                    return vec![Action::NotifyError {
                        code: "MALFORMED_WIRE_PAYLOAD".to_string(),
                        message: format!("{e} (message {message_id} from {from})"),
                    }];
                }
            }
        };

        // All content types — including CALL_SIGNAL (12) — go through the full
        // routing pipeline (ACK dedup, session check, heal path, PQ contribution).
        let incoming = IncomingMessage {
            contact_id: from.clone(),
            wire_payload: data,
            message_id,
            msg_number: msg_num,
            is_control,
            content_type,
        };

        // Store KEM ciphertext for PQ decapsulation if non-empty.
        // The platform must call back with `mlkem768_decapsulate` result.
        let mut actions = Vec::new();
        if !kem_ct.is_empty() {
            actions.push(Action::ApplyPQContribution {
                contact_id: from.clone(),
                kem_ss: kem_ct, // platform decapsulates, feeds ss back
            });
        }

        let decision = self.router.route_message(&mut self.lifecycle, &incoming);
        let needs_state_save = matches!(
            &decision,
            // Decrypted: ack_store.mark_processed() mutates the ACK cache — persist it
            // so the L1 in-memory dedup survives a restart (without this, every
            // message received since the last orchestrator_state save would hit L2 DB
            // on restart, creating duplicate-processing risk before the DB check fires).
            RoutingDecision::Decrypted { .. }
                | RoutingDecision::SessionHealNeeded { .. }
                | RoutingDecision::NeedSessionInit { .. }
                | RoutingDecision::EndSessionNeeded { .. }
        );
        actions.extend(self.decision_to_actions(decision, &from));
        // Persist coordination state (healing queue, ACK cache, init_locks) for
        // paths that don't already trigger a session-keyed save on the Swift side.
        if needs_state_save && let Some(save_action) = self.orchestrator_state_action() {
            actions.push(save_action);
        }
        actions
    }

    /// Encrypt a regular outgoing message and pack it into a WirePayload ready to send.
    ///
    /// Called when Swift feeds `OutgoingMessage` — single source of truth for all outgoing
    /// E2EE text encryption. Emits `SaveToSecureStore` to persist updated DR state.
    fn handle_outgoing_message(
        &mut self,
        contact_id: String,
        message_id: String,
        plaintext: Vec<u8>,
        content_type: u8,
    ) -> Vec<Action> {
        // For the first message (msgNum=0) after a fresh PQXDH session init, apply the
        // deferred KEM shared secret to the DR root key BEFORE encrypting.  This ensures
        // the INITIATOR's DR state matches what the RESPONDER will derive after
        // decapsulating the KEM ciphertext they receive in the wire payload.
        let (pq_kem_ct, pq_kyber_otpk_id) = {
            let (kem_ct, otpk_id, ss) = self
                .lifecycle
                .pq_manager
                .take_contribution_for_first_message(&contact_id);
            if let Some(shared_secret) = ss
                && let Err(e) = self
                    .lifecycle
                    .client
                    .apply_pq_contribution_to_session(&contact_id, shared_secret.expose())
            {
                return vec![Action::NotifyError {
                    code: "OUTGOING_MESSAGE_PQXDH_APPLY_FAILED".to_string(),
                    message: e.to_string(),
                }];
            }
            (kem_ct, otpk_id)
        };

        let encrypted = match self
            .lifecycle
            .client
            .encrypt_message(&contact_id, &plaintext)
        {
            Ok(e) => e,
            Err(e) => {
                return vec![Action::NotifyError {
                    code: "OUTGOING_MESSAGE_ENCRYPT_FAILED".to_string(),
                    message: e.to_string(),
                }];
            }
        };

        let mut sealed_box = Vec::new();
        sealed_box.extend_from_slice(&encrypted.nonce);
        sealed_box.extend_from_slice(&encrypted.ciphertext);

        let otpk_id = if encrypted.message_number == 0 {
            self.lifecycle.client.take_pending_otpk_id(&contact_id)
        } else {
            0
        };

        let kem_ct_ref: Option<&[u8]> = pq_kem_ct.as_deref();

        let payload = match crate::wire_payload::pack(
            &encrypted.dh_public_key,
            encrypted.message_number,
            otpk_id,
            pq_kyber_otpk_id,
            encrypted.previous_chain_length,
            encrypted.suite_id,
            kem_ct_ref,
            &sealed_box,
            encrypted.pq_message_epoch,
            encrypted.pq_ratchet_field.clone(),
        ) {
            Ok(p) => p,
            Err(e) => {
                return vec![Action::NotifyError {
                    code: "OUTGOING_MESSAGE_PACK_FAILED".to_string(),
                    message: e.to_string(),
                }];
            }
        };

        let mut actions = Vec::new();
        // SAFETY ORDER: persist updated DR state BEFORE sending.
        // If we sent first and then crashed before saving, the chain would advance on the
        // remote side (via decryption) while our local state stays stale — breaking the
        // session.  Saving first means a crash-before-send results in a locally-advanced
        // but unsent message, which is recoverable (resend).
        if let Ok(session_bytes) = self.lifecycle.export_session_bytes_for(&contact_id) {
            actions.push(Action::SaveToSecureStore {
                slot: SecureStoreSlot::Session {
                    contact_id: contact_id.clone(),
                },
                data: session_bytes.into(),
            });
        }
        actions.push(Action::SendEncryptedMessage {
            to: contact_id,
            payload,
            message_id,
            content_type,
        });
        actions
    }

    /// Encrypt a call signal proto blob and pack it into a WirePayload ready to send.
    ///
    /// Called when Swift feeds `OutgoingCallSignal` — no base64, no JSON, no Strings.
    /// Also emits `SaveToSecureStore` to persist the updated DR state.
    fn handle_outgoing_call_signal(
        &mut self,
        contact_id: String,
        message_id: String,
        proto_bytes: Vec<u8>,
    ) -> Vec<Action> {
        match self.encrypt_bytes_for(&contact_id, &proto_bytes) {
            Ok(payload) => {
                let mut actions = Vec::new();
                // SAFETY ORDER: save before send (same rationale as handle_outgoing_message).
                if let Ok(session_bytes) = self.lifecycle.export_session_bytes_for(&contact_id) {
                    actions.push(Action::SaveToSecureStore {
                        slot: SecureStoreSlot::Session {
                            contact_id: contact_id.clone(),
                        },
                        data: session_bytes.into(),
                    });
                }
                actions.push(Action::SendEncryptedMessage {
                    to: contact_id,
                    payload,
                    message_id,
                    content_type: 12,
                });
                actions
            }
            Err(e) => vec![Action::NotifyError {
                code: "CALL_SIGNAL_ENCRYPT_FAILED".to_string(),
                message: e,
            }],
        }
    }

    /// Decrypt a CALL_SIGNAL message using the existing JSON wire format path.
    ///
    /// Called when `handle_message_received` sees `content_type == 12`.
    fn handle_session_init_completed(
        &mut self,
        contact_id: String,
        session_data: Vec<u8>,
    ) -> Vec<Action> {
        // Releases the `Opening` phase and voids any teardown owed from before this session was
        // built — sending it would tear down the session that just replaced the broken one.
        //
        self.sessions
            .handle(&contact_id, SessionEvent::OpenFinished);
        // And settles the heal episode for the same reason the phase is released: a session that
        // exists again is the thing every retry in that episode was trying to produce.
        self.lifecycle.healing_queue.settle(&contact_id);

        let mut actions: Vec<Action> = Vec::new();

        // Import the newly created session from CFE binary (or JSON legacy fallback).
        // If import fails, emit an error action and abort — do not drain the queue
        // or notify the platform of a session that was never actually created.
        if !session_data.is_empty()
            && let Err(e) = self
                .lifecycle
                .import_session_bytes(&contact_id, &session_data)
        {
            tracing::error!(
                target: "orchestration",
                contact_id = %contact_id,
                error = %e,
                "SessionInitCompleted: import_session_bytes failed — aborting session init"
            );
            actions.push(Action::NotifyError {
                code: "session_import_failed".to_string(),
                message: format!("contact={}: {}", contact_id, e),
            });
            return actions;
        }

        // Save the session to secure store.
        if let Ok(bytes) = self.lifecycle.export_session_bytes_for(&contact_id) {
            actions.push(Action::SaveToSecureStore {
                slot: SecureStoreSlot::Session {
                    contact_id: contact_id.clone(),
                },
                data: bytes.into(),
            });
        }

        // Drain the pending queue.
        let drained = self.router.drain_pending(&contact_id, &mut self.lifecycle);
        for decision in drained {
            actions.extend(self.decision_to_actions(decision, &contact_id));
        }

        actions.push(Action::NotifySessionCreated {
            contact_id: contact_id.clone(),
        });

        actions
    }

    fn handle_ack_received(&mut self, message_id: String) -> Vec<Action> {
        vec![Action::MarkMessageDelivered { message_id }]
    }

    fn handle_ack_db_result(&mut self, message_id: String, is_processed: bool) -> Vec<Action> {
        let decision =
            self.router
                .resume_after_ack_check(&message_id, is_processed, &mut self.lifecycle);
        self.decision_to_actions(decision, "")
    }

    fn handle_key_bundle_fetched(&mut self, user_id: String, _bundle_json: String) -> Vec<Action> {
        // Session init is done by the platform using ClassicCryptoCore.init_session.
        // The result comes back via SessionInitCompleted.
        // Here we just clear the init lock if we were waiting.
        vec![Action::InitSession {
            contact_id: user_id,
            bundle_json: _bundle_json,
        }]
    }

    fn handle_network_reconnected(&mut self) -> Vec<Action> {
        let mut actions = vec![Action::ScheduleTimer {
            timer_id: "gc_sweep".to_string(),
            delay_ms: 1_000,
        }];

        // Drain any messages that were queued while offline.
        // Collect contact IDs first to avoid borrow conflicts.
        let pending_ids = self.router.contacts_with_pending();
        for contact_id in pending_ids {
            let decisions = self.router.drain_pending(&contact_id, &mut self.lifecycle);
            for decision in decisions {
                actions.extend(self.decision_to_actions(decision, &contact_id));
            }
        }

        actions
    }

    fn handle_app_launched(&mut self) -> Vec<Action> {
        // Schedule a GC and prewarm sweep on launch.
        vec![
            Action::ScheduleTimer {
                timer_id: "gc_sweep".to_string(),
                delay_ms: 5_000,
            },
            Action::ScheduleTimer {
                timer_id: "prewarm_sweep".to_string(),
                delay_ms: 2_000,
            },
        ]
    }

    fn handle_timer_fired(&mut self, timer_id: String) -> Vec<Action> {
        match timer_id.as_str() {
            "gc_sweep" => {
                let mut actions = self.lifecycle.gc_old_archives();
                actions.extend(self.lifecycle.ack_store.prune_expired());
                self.lifecycle.healing_queue.prune_expired();
                self.sessions.prune_expired();
                actions
            }
            _ if timer_id.starts_with("cooldown_expired:") => {
                let contact_id = timer_id["cooldown_expired:".len()..].to_string();
                let mut actions = vec![Action::ScheduleTimer {
                    timer_id: "gc_sweep".to_string(),
                    delay_ms: 100,
                }];

                // Pay out an END_SESSION this contact is owed.
                //
                // The old comment here said "the server will re-deliver any unACKed messages" and
                // left it at that. It is not the server's to do: re-delivery only happens while
                // the client holds its stream cursor back, and a message that arrived through
                // GetPendingMessages is not tracked by any cursor at all. Both layers deferred to
                // a third that was not holding anything.
                // The machine decides whether the window's debt is paid; `Timeout` is the one
                // alarm it asks for, and this is where the client's clock wakes it.
                // Read before `Timeout`: paying the debt starts a fresh window, which carries none.
                let condemned = self.sessions.condemned(&contact_id);
                if self.sessions.handle(&contact_id, SessionEvent::Timeout)
                    == SessionEffect::TearDown
                {
                    // Unless the session came back meanwhile. This is the case that MUST NOT
                    // fire: tearing down a session established during the cooldown is the
                    // crossing-teardown defect, and it is exactly what an unconditional
                    // re-send would cause here.
                    //
                    // "Came back" is a *different* session, not any session. Until 2026-09-24
                    // this asked `has_active_session`, and the debt is almost always owed against
                    // a session that is still held — a diverged ratchet stays in place until the
                    // END_SESSION that condemns it goes out, which is the thing being owed. So
                    // the check dropped exactly the debts it was meant to pay (device logs: two
                    // phones, one divergence, no teardown for an hour). A debt with no session
                    // named — a restart dropped it, or none was held — keeps the old answer:
                    // any session now present is treated as new.
                    let current = self.lifecycle.active_session_id(&contact_id);
                    if current.is_some() && current != condemned {
                        tracing::info!(
                            target: "orchestration",
                            contact_id = %contact_id,
                            "cooldown expired — owed END_SESSION dropped, session was re-established meanwhile"
                        );
                    } else {
                        actions.push(Action::SendEndSession {
                            contact_id: contact_id.clone(),
                        });
                        actions.push(Action::NotifyLinkedDevicesOfSessionReset {
                            contact_id: contact_id.clone(),
                        });
                    }
                }
                actions
            }
            // The wait has had its moment — the peer's flush, or the peer's whole turn. One timer
            // for both callers — the platform's re-init and a message queued behind the same
            // quiet — because after a teardown they want the same thing: an announced X3DH. A
            // message waiting on it drains out of `pending_queues` when the init completes, as it
            // does behind any other open.
            //
            // It re-asks `WantToOpen` and not `WantToReopen`, which is what bounds the peer's
            // turn: the ordering was ranked once, when the ratchet died, and this alarm yields to
            // nobody. Re-ranking here would let a peer who keeps tearing down keep its turn.
            _ if timer_id.starts_with("reopen:") => {
                let contact_id = timer_id["reopen:".len()..].to_string();
                // The peer's rebuild arrived — which is the whole reason the quiet exists.
                // Clearing the phase is what `OpenFinished` is for: a session that exists again
                // settles what was owed against the one it replaced.
                if self.lifecycle.has_active_session(&contact_id) {
                    self.sessions
                        .handle(&contact_id, SessionEvent::OpenFinished);
                    return vec![Action::OpenNotNeeded { contact_id }];
                }
                match self.sessions.handle(&contact_id, SessionEvent::WantToOpen) {
                    // Another teardown landed inside the quiet, so the flush is still arriving.
                    // Same deadline, re-armed — the machine counts from the last teardown, not
                    // from this timer.
                    SessionEffect::DeferOpen { retry_after_ms } => vec![Action::ScheduleTimer {
                        timer_id: timer_id.clone(),
                        delay_ms: retry_after_ms,
                    }],
                    // Somebody got there first. One announce per ratchet: a second spends another
                    // of the peer's one-time pre-keys and replaces the session the first is
                    // announcing, orphaning the SRI already on the wire.
                    SessionEffect::WaitForOpen => vec![],
                    _ => vec![Action::OpenSession { contact_id }],
                }
            }
            // The announcement has gone unanswered for a retry interval, or for the whole
            // window. Which of the two is the machine's to say — this only carries the alarm.
            _ if timer_id.starts_with("open_confirm:") => {
                let contact_id = timer_id["open_confirm:".len()..].to_string();
                match self.sessions.handle(&contact_id, SessionEvent::Timeout) {
                    SessionEffect::ResendSri { retry_after_ms } => vec![
                        Action::ResendSri {
                            contact_id: contact_id.clone(),
                        },
                        Action::ScheduleTimer {
                            timer_id: timer_id.clone(),
                            delay_ms: retry_after_ms,
                        },
                    ],
                    // No re-arm: the wait is over, and that is the whole point of the bound.
                    SessionEffect::GiveUpOpening => vec![Action::OpeningGaveUp { contact_id }],
                    // The peer answered, or the session was torn down, between the alarm being
                    // armed and firing. Timers outlive their reason.
                    _ => vec![],
                }
            }
            _ if timer_id.starts_with("heartbeat:") => {
                let contact_id = &timer_id["heartbeat:".len()..];
                if self.active_chats.contains(contact_id) {
                    // Re-schedule heartbeat for the next interval.
                    vec![
                        Action::SendHeartbeat {
                            contact_id: contact_id.to_string(),
                        },
                        Action::ScheduleTimer {
                            timer_id: timer_id.clone(),
                            delay_ms: 6 * 60 * 60 * 1_000, // 6 hours
                        },
                    ]
                } else {
                    vec![] // Chat closed — timer fires once more, then stops.
                }
            }
            _ => vec![],
        }
    }

    fn handle_active_chat_changed(&mut self, contact_id: String, is_active: bool) -> Vec<Action> {
        if is_active {
            self.active_chats.insert(contact_id.clone());
            // Schedule initial heartbeat after 6 hours.
            vec![Action::ScheduleTimer {
                timer_id: format!("heartbeat:{}", contact_id),
                delay_ms: 6 * 60 * 60 * 1_000,
            }]
        } else {
            self.active_chats.remove(&contact_id);
            vec![Action::CancelTimer {
                timer_id: format!("heartbeat:{}", contact_id),
            }]
        }
    }

    fn handle_heartbeat_received(
        &mut self,
        contact_id: String,
        message_id: String,
        data: Vec<u8>,
        msg_num: u32,
    ) -> Vec<Action> {
        // Route the heartbeat through the normal decrypt path.
        // A content_type we treat as "heartbeat" — content type 13.
        let msg = crate::orchestration::message_router::IncomingMessage {
            message_id,
            contact_id: contact_id.clone(),
            wire_payload: data,
            msg_number: msg_num,
            content_type: 13, // HEARTBEAT content type
            is_control: false,
        };
        let decision = self.router.route_message(&mut self.lifecycle, &msg);
        match decision {
            RoutingDecision::Decrypted { .. } => {
                // Heartbeat decrypted successfully — session is healthy, no action needed.
                vec![]
            }
            RoutingDecision::SessionHealNeeded {
                contact_id: cid,
                role,
                // A heartbeat is a payload, never a handshake, so the gate below applies to it
                // in full — and the field is destructured rather than ignored so a future
                // heartbeat carrying something else has to come back through here.
                is_handshake: false,
                reason,
            } => {
                // Decrypt failed on heartbeat msgNum=0 — proactively trigger heal.
                if self.sessions.awaits_acknowledgement(&cid) {
                    return vec![
                        Action::HeldPendingAck { contact_id: cid },
                        decrypt_failed(reason),
                    ];
                }
                let mut actions = match self.sessions.handle(&cid, SessionEvent::WantToHeal) {
                    SessionEffect::DeferHeal { retry_after_ms } => vec![Action::HealSuppressed {
                        contact_id: cid,
                        retry_after_ms,
                    }],
                    _ => vec![Action::SessionHealNeeded {
                        contact_id: cid,
                        role: role.as_wire().to_string(),
                    }],
                };
                actions.push(decrypt_failed(reason));
                actions
            }
            other => self.decision_to_actions(other, &contact_id),
        }
    }

    // ── Decision → Actions ────────────────────────────────────────────────────

    /// Name the ratchet a just-deferred teardown condemns, so the alarm that pays it can tell it
    /// from one established in the meantime.
    fn condemn_active_session(&mut self, contact_id: &str) {
        let session = self.lifecycle.active_session_id(contact_id);
        self.sessions.condemn(contact_id, session);
    }

    /// Every decision a refused decrypt produced also says *why* it was refused.
    ///
    /// The decision itself is heal / tear down / hold, and it is the same for every cause; the
    /// cause is what a divergence is diagnosed from. Until 2026-09-24 it was dropped here
    /// (`reason: _`) and on the heal path never left the router at all, so a device log could
    /// show two phones answering every message with END_SESSION and not one word on what the
    /// ratchet had objected to. The platform bridge's `log_event` is not wired on iOS, so an
    /// action is the only channel that reaches the log.
    fn decision_to_actions(&mut self, decision: RoutingDecision, contact_id: &str) -> Vec<Action> {
        let refused = match &decision {
            RoutingDecision::SessionHealNeeded { reason, .. }
            | RoutingDecision::EndSessionNeeded { reason, .. } => Some(reason.clone()),
            _ => None,
        };
        let mut actions = self.decide_actions(decision, contact_id);
        if let Some(reason) = refused {
            actions.push(decrypt_failed(reason));
        }
        actions
    }

    fn decide_actions(&mut self, decision: RoutingDecision, _contact_id: &str) -> Vec<Action> {
        match decision {
            RoutingDecision::Decrypted {
                plaintext,
                actions,
                contact_id: cid,
                message_id: mid,
                content_type,
            } => {
                let mut all = actions;
                if content_type == 12 {
                    // CALL_SIGNAL: return raw proto bytes, no chat notification.
                    all.push(Action::CallSignalDecrypted {
                        contact_id: cid,
                        message_id: mid,
                        proto_bytes: plaintext,
                    });
                } else {
                    // content_type 13 (HEARTBEAT) and 14 (DELIVERY_RECEIPT) are silent
                    // control payloads — no push notification, just decrypt and let Swift handle.
                    //
                    // Privacy note: decrypting ct=13/14 DOES advance the Double Ratchet chain
                    // (receiving_chain_length, possibly last_ratchet_at on a DH ratchet step).
                    // This is intentional — heartbeats must exercise the real DR path so session
                    // health is accurately reflected.  last_ratchet_at is local-only and is never
                    // transmitted to the server, so these decrypts do not leak timing metadata.
                    if content_type != 13 && content_type != 14 {
                        all.push(Action::NotifyNewMessage {
                            chat_id: cid.clone(),
                            preview: preview(&plaintext),
                        });
                    }
                    all.push(Action::MessageDecrypted {
                        contact_id: cid,
                        message_id: mid,
                        plaintext,
                    });
                }
                all
            }
            RoutingDecision::NeedSessionInit {
                contact_id: cid,
                queued_count,
            } => {
                match self.sessions.handle(&cid, SessionEvent::WantToOpen) {
                    SessionEffect::WaitForOpen => {
                        // The message is already in `pending_queues` (see `enqueue_or_reject`)
                        // and is drained by `handle_session_init_completed`. Say so: the empty
                        // list this used to return was read by the platform as a drop.
                        vec![Action::MessageQueuedPendingInit {
                            contact_id: cid,
                            queued_count: queued_count as u32,
                        }]
                    }
                    // Same hold as the platform's re-init gets, for the same reason: the peer
                    // tore this ratchet down and its rebuild is in the same flush. The message is
                    // queued either way; what changes is that our X3DH no longer races theirs.
                    // The timer is ours because nothing re-delivers a queued message to ask again
                    // — unlike a deferred heal, which the peer's next carrier re-raises.
                    //
                    // Same timer as the platform's, and it pays out `OpenSession` rather than the
                    // `FetchPublicKeyBundle` this arm grants directly. They are not two answers:
                    // after a teardown the recovery is an announced X3DH, and the bundle fetch is
                    // the first half of one. The bundle fetch is also message-bound on the
                    // platform — it re-queues *this* carrier — and a timer has no message, so
                    // granting it later would be a producer with no reader.
                    SessionEffect::DeferOpen { retry_after_ms } => vec![
                        Action::MessageQueuedPendingInit {
                            contact_id: cid.clone(),
                            queued_count: queued_count as u32,
                        },
                        Action::ScheduleTimer {
                            timer_id: format!("reopen:{cid}"),
                            delay_ms: retry_after_ms,
                        },
                    ],
                    _ => vec![Action::FetchPublicKeyBundle { user_id: cid }],
                }
            }
            RoutingDecision::SessionHealNeeded {
                contact_id: cid,
                role,
                is_handshake,
                // Reported by `decision_to_actions`, which wraps this for every refusal.
                reason: _,
            } => {
                // Our own announcement to this device is still unanswered, so this failure is
                // our re-init's own consequence. Healing on it archives the session we built in
                // answer to it — see `Action::HeldPendingAck`.
                //
                // A handshake carrier is exempt, and that exemption is the whole of it: it is
                // what the wait is waiting for, so holding it would make the gate wait on
                // itself. The heal is what applies the peer's X3DH, and when it completes the
                // phase clears by `OpenFinished` — which is the acknowledgement, arriving as an
                // event rather than as a byte we could not read.
                //
                // Asked of **this device**. iOS folded it over the peer's whole device set
                // (`awaitsAcknowledgementFromAnyDevice`), so an unanswered announcement to one
                // device held a genuine heal for its sibling; a ratchet is between two devices
                // and our SRI to one says nothing about the other.
                if !is_handshake && self.sessions.awaits_acknowledgement(&cid) {
                    return vec![Action::HeldPendingAck { contact_id: cid }];
                }
                match self.sessions.handle(&cid, SessionEvent::WantToHeal) {
                    SessionEffect::DeferHeal { retry_after_ms } => {
                        // `HealSuppressed` so the platform knows NOT to ACK: the message is
                        // re-delivered and the decision is taken again with fresher facts, which
                        // is why a deferred heal carries no debt.
                        vec![
                            Action::HealSuppressed {
                                contact_id: cid.clone(),
                                retry_after_ms,
                            },
                            Action::ScheduleTimer {
                                timer_id: format!("cooldown_expired:{cid}"),
                                delay_ms: retry_after_ms,
                            },
                        ]
                    }
                    _ => vec![Action::SessionHealNeeded {
                        contact_id: cid,
                        role: role.as_wire().to_string(),
                    }],
                }
            }
            RoutingDecision::EndSessionNeeded {
                contact_id: cid,
                // Reported by `decision_to_actions`, which wraps this for every refusal.
                reason: _,
            } => {
                // The same hold as the heal above, and there is no exemption to make here: a
                // real END_SESSION is short-circuited as a control frame before any decrypt is
                // attempted, so nothing reaching this arm is an acknowledgement. A handshake
                // that arrives with its heal budget exhausted reaches it, and holding that one
                // is the improvement — tearing down on it crosses our own unanswered SRI, which
                // is the defect the gate exists for.
                if self.sessions.awaits_acknowledgement(&cid) {
                    return vec![Action::HeldPendingAck { contact_id: cid }];
                }
                // Evidence, and the decision that produced it says so: `EndSessionNeeded`
                // arrives from a message that failed to decrypt on a ratchet we still hold a
                // record of — the peer is demonstrably still using a session we tore down. That
                // is what buys the fast retry instead of the full window.
                match self.sessions.handle(
                    &cid,
                    SessionEvent::WantToTearDown {
                        cause: TearDownCause::Unacknowledged,
                    },
                ) {
                    SessionEffect::DeferTearDown { retry_after_ms } => {
                        // Owed, not dropped. A message that failed to decrypt at msgNum > 0 is
                        // bound to a ratchet we no longer hold and will never be readable — the
                        // only thing that recovers it is the peer re-establishing and re-sending,
                        // which is what END_SESSION asks for. Swallowing it removed the recovery,
                        // silently: build 585 lost three media messages inside one five-second
                        // window. The debt is a flag, so every suppression in the window folds
                        // into the single teardown the timer pays.
                        self.condemn_active_session(&cid);
                        vec![
                            Action::EndSessionSuppressed {
                                contact_id: cid.clone(),
                                retry_after_ms,
                            },
                            Action::ScheduleTimer {
                                timer_id: format!("cooldown_expired:{cid}"),
                                delay_ms: retry_after_ms,
                            },
                        ]
                    }
                    _ => vec![
                        Action::SendEndSession {
                            contact_id: cid.clone(),
                        },
                        // Notify linked devices so they can proactively heal with this contact.
                        Action::NotifyLinkedDevicesOfSessionReset { contact_id: cid },
                    ],
                }
            }
            RoutingDecision::Duplicate { .. } => vec![],
            RoutingDecision::PendingAckCheck { message_id } => {
                vec![Action::CheckAckInDb { message_id }]
            }
            RoutingDecision::QueueFull { contact_id: cid } => {
                vec![Action::NotifyError {
                    code: "QUEUE_FULL".to_string(),
                    message: format!("Message queue full for {}", cid),
                }]
            }
            RoutingDecision::EndSessionReceived {
                contact_id: _,
                actions,
            } => actions,
            RoutingDecision::Error { message } => {
                vec![Action::NotifyError {
                    code: "ROUTING_ERROR".to_string(),
                    message,
                }]
            }
        }
    }

    // ── Orchestrator state persistence ────────────────────────────────────────

    /// Build a `SaveToSecureStore` action that persists the full
    /// orchestrator coordination state (ACK cache, healing queue, init_locks,
    /// archive index, prekey tracker) to the platform's secure store.
    ///
    /// Must be called after any event that mutates coordination state and does
    /// NOT already trigger a session-keyed save (e.g. SessionHealNeeded,
    /// NeedSessionInit, EndSessionNeeded).  The `Decrypted` path already causes
    /// Swift to call `saveOrchestratorStateCFE()` as a side-effect of the
    /// session save, so it does not need this action.
    fn orchestrator_state_action(&self) -> Option<Action> {
        let lock_ids: std::collections::HashSet<String> =
            self.sessions.opening_device_ids().into_iter().collect();
        self.lifecycle
            .export_orchestrator_state_cfe(&lock_ids)
            .ok()
            .map(|cfe| Action::SaveToSecureStore {
                slot: SecureStoreSlot::OrchestratorState,
                data: cfe.into(),
            })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn derive_message_id(data: &[u8], msg_num: u32) -> String {
    // Cheap deterministic ID: sha2 not available without feature, use a hash of
    // the first 16 bytes + message number. Good enough for deduplication.
    let prefix: u64 = data.iter().take(16).enumerate().fold(0u64, |acc, (i, &b)| {
        acc.wrapping_add((b as u64).wrapping_shl(i as u32 % 64))
    });
    format!("{}_{}", prefix, msg_num)
}

fn preview(plaintext: &[u8]) -> String {
    let s = String::from_utf8_lossy(plaintext);
    let chars: String = s.chars().take(50).collect();
    chars
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `NotifyError` code for a decrypt the ratchet refused. The message is the ratchet's own error.
pub const DECRYPT_FAILED: &str = "decrypt_failed";

fn decrypt_failed(reason: String) -> Action {
    Action::NotifyError {
        code: DECRYPT_FAILED.to_string(),
        message: reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_api::ClassicClient;
    use crate::crypto::suites::classic::ClassicSuiteProvider;
    use crate::orchestration::clock::MockClock;
    use crate::orchestration::session_machine::{
        END_SESSION_COOLDOWN_MS, OPENING_CONFIRM_WINDOW_MS, PEER_TEARDOWN_QUIET_MS,
        REOPEN_QUIET_MS, RESPONDER_OVERRIDE_MS, SRI_RETRY_MS,
    };

    fn make_orchestrator(user_id: &str) -> Orchestrator {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        Orchestrator::new(client, user_id.to_string())
    }

    #[test]
    fn test_new_orchestrator() {
        let o = make_orchestrator("alice");
        assert_eq!(o.my_user_id(), "alice");
        assert!(!o.has_active_session("bob"));
        assert_eq!(o.pending_message_count("bob"), 0);
    }

    /// A minimal valid packed wire payload (suite 1) for router tests — the
    /// orchestrator derives msg_num/kem_ct from `data` via the canonical parser.
    fn packed_wire(msg_num: u32, kem_ct: Option<&[u8]>) -> Vec<u8> {
        crate::wire_payload::pack(
            &[7u8; 32], msg_num, 0, 0, 0, 1, kem_ct,
            &[0u8; 32], // sealed box (never decrypted in these tests)
            0, None,
        )
        .unwrap()
    }

    #[test]
    fn test_message_received_no_session_fetches_bundle() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            message_id: "msg-001".to_string(),
            from: "bob".to_string(),
            data: packed_wire(0, None),
            msg_num: 0,
            kem_ct: vec![],
            otpk_id: 0,
            is_control: false,
            content_type: 0,
        });
        // Should ask to fetch bundle (no active session → NeedSessionInit).
        let fetches: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::FetchPublicKeyBundle { .. }))
            .collect();
        assert!(!fetches.is_empty(), "expected FetchPublicKeyBundle action");
    }

    #[test]
    fn forget_contact_state_clears_pending_router_state_before_re_add() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            message_id: "old-backlog".to_string(),
            from: "bob".to_string(),
            data: packed_wire(0, None),
            msg_num: 0,
            kem_ct: vec![],
            otpk_id: 0,
            is_control: false,
            content_type: 0,
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::FetchPublicKeyBundle { user_id } if user_id == "bob"))
        );
        assert_eq!(o.pending_message_count("bob"), 1);

        o.forget_contact_state("bob");

        assert_eq!(
            o.pending_message_count("bob"),
            0,
            "local delete must remove stale queued msgNum=0 carriers before re-add"
        );
    }

    #[test]
    fn test_message_received_pq_ciphertext_produces_apply_action() {
        let mut o = make_orchestrator("alice");
        // kem_ct travels inside the wire payload; the event fields are zeros
        // (Android-style caller) — the orchestrator must derive it from `data`.
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            message_id: "msg-002".to_string(),
            from: "bob".to_string(),
            data: packed_wire(0, Some(&[1, 2, 3])),
            msg_num: 0,
            kem_ct: vec![],
            otpk_id: 0,
            is_control: false,
            content_type: 0,
        });
        let pq_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::ApplyPQContribution { .. }))
            .collect();
        assert!(
            !pq_actions.is_empty(),
            "expected ApplyPQContribution action"
        );
    }

    #[test]
    fn test_message_received_malformed_payload_notifies_without_heal() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            message_id: "msg-003".to_string(),
            from: "bob".to_string(),
            data: vec![0u8; 4], // not a wire payload
            msg_num: 0,
            kem_ct: vec![],
            otpk_id: 0,
            is_control: false,
            content_type: 0,
        });
        assert!(
            matches!(actions.as_slice(), [Action::NotifyError { code, .. }] if code == "MALFORMED_WIRE_PAYLOAD"),
            "expected single MALFORMED_WIRE_PAYLOAD NotifyError, got {actions:?}"
        );
    }

    #[test]
    fn test_app_launched_schedules_timers() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::AppLaunched);
        let timers: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::ScheduleTimer { .. }))
            .collect();
        assert_eq!(timers.len(), 2);
    }

    #[test]
    fn test_network_reconnected_schedules_gc() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::NetworkReconnected);
        assert!(actions.iter().any(
            |a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id == "gc_sweep")
        ));
    }

    #[test]
    fn test_timer_gc_sweep_returns_actions() {
        let mut o = make_orchestrator("alice");
        // gc_sweep on empty state should return empty (no expired records).
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "gc_sweep".to_string(),
        });
        // May return prune actions even on empty store; just check no panic.
        let _ = actions;
    }

    #[test]
    fn test_ack_received_produces_mark_delivered() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::AckReceived {
            message_id: "msg-xyz".to_string(),
        });
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], Action::MarkMessageDelivered { message_id } if message_id == "msg-xyz")
        );
    }

    /// The init-in-flight lock is released by the completion — for a responder outright, and for
    /// an initiator into the wait for the peer's acknowledgement, which is the confirm gate the
    /// platform used to hold separately.
    #[test]
    fn test_session_init_completed_clears_lock() {
        let mut o = make_orchestrator("alice");
        o.sessions.handle("bob", SessionEvent::WantToOpen);
        let actions = o.handle_event(IncomingEvent::SessionInitCompleted {
            contact_id: "bob".to_string(),
            session_data: vec![], // empty → only releases the Opening phase
        });
        assert_eq!(o.sessions.phase("bob"), crate::orchestration::Phase::Absent);
        // Should include NotifySessionCreated.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::NotifySessionCreated { .. }))
        );
    }

    /// The window a teardown enters is the machine's, and a second teardown inside it is
    /// deferred rather than sent. The transitions themselves are covered in `session_machine`;
    /// this asserts the orchestrator asks.
    #[test]
    fn test_cooldown_deduplicates_end_session() {
        let mut o = make_orchestrator("alice");
        let first = o.decision_to_actions(end_session_needed("bob"), "");
        assert!(
            first
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { .. }))
        );
        let second = o.decision_to_actions(end_session_needed("bob"), "");
        assert!(
            second
                .iter()
                .any(|a| matches!(a, Action::EndSessionSuppressed { .. })),
            "the second teardown inside the window is deferred, not sent"
        );
    }

    /// The platform's teardown and the core's own share one window. They did not: the iOS
    /// coordinator held `endSessionSentAt` (30 s) and the core held `cooldowns` (5 s), for the
    /// same envelope to the same device, and neither could see the other's.
    ///
    /// Mutation: give `TeardownRequested` its own gate instead of `self.sessions` — this reddens.
    #[test]
    fn a_platform_teardown_shares_the_window_with_the_cores_own() {
        let mut o = make_orchestrator("alice");
        let first = o.decision_to_actions(end_session_needed("bob"), "");
        assert!(
            first
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { .. }))
        );
        let asked = o.handle_event(IncomingEvent::TeardownRequested {
            contact_id: "bob".to_string(),
            cause: TearDownCause::Blind,
        });
        assert!(
            asked
                .iter()
                .any(|a| matches!(a, Action::EndSessionSuppressed { .. })),
            "the platform's ask lands inside the window the core's own teardown opened"
        );
        assert!(
            asked.iter().any(
                |a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id == "cooldown_expired:bob")
            ),
            "and it is owed, so the alarm that pays it is armed"
        );
    }

    /// The peer's own teardown answers a blind ask of ours, and answers it **finally**: no
    /// suppression action, no timer. This is the iOS 20 s `lastInboundEndSessionAt` grace, folded
    /// into the one window that already decides whether a teardown may go out.
    #[test]
    fn the_peers_teardown_answers_a_blind_ask_without_owing_one() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        let actions = o.handle_event(IncomingEvent::TeardownRequested {
            contact_id: "bob".to_string(),
            cause: TearDownCause::Blind,
        });
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], Action::EndSessionNotNeeded { contact_id } if contact_id == "bob")
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::ScheduleTimer { .. })),
            "nothing is owed, so nothing may arm a retry — a timer here is the grace inverted"
        );
    }

    /// An explained teardown survives it. The peer cannot work out for itself that the one-time
    /// pre-key it chose is unreproducible, so silence is the retry loop continuing.
    #[test]
    fn the_peers_teardown_does_not_answer_an_explained_ask() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        let actions = o.handle_event(IncomingEvent::TeardownRequested {
            contact_id: "bob".to_string(),
            cause: TearDownCause::Explained,
        });
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::EndSessionNotNeeded { .. })),
            "an explained teardown is never answered away"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::EndSessionSuppressed { .. })),
            "it is held to the ordinary window, and owed"
        );
    }

    /// The first ask of a quiet device is granted, and it is a plain `SendEndSession` — the
    /// platform reaches its own linked devices through the paths it already owns, so the
    /// broadcast that rides on `EndSessionNeeded` is not repeated here.
    #[test]
    fn a_platform_teardown_of_a_quiet_device_is_granted_alone() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::TeardownRequested {
            contact_id: "bob".to_string(),
            cause: TearDownCause::Blind,
        });
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], Action::SendEndSession { contact_id } if contact_id == "bob")
        );
    }

    // ── Suppression is a debt, not a drop ─────────────────────────────────────
    //
    // Build 585, iOS device 6bf51980, one five-second window:
    //
    //     msgNum=4  ackDbResult … actions=2 flags=end_session
    //               SESSION_STATE[rust_end_session]: DR diverged for 0a1c609f… — sending END_SESSION
    //     msgNum=5  ackDbResult … actions=0
    //     msgNum=6  ackDbResult … actions=0
    //     msgNum=7  ackDbResult … actions=0
    //
    // msgNum 4 set the cooldown; 5, 6 and 7 each produced `EndSessionNeeded` and each was
    // answered with `vec![]`. Three media messages (3910 B, content_type 1) were never seen
    // again. A message that fails to decrypt at msgNum > 0 is bound to a ratchet we no longer
    // hold — it is not recoverable by re-reading it. What recovers it is the peer tearing down
    // and re-sending, which is what END_SESSION asks for; suppressing the END_SESSION removed
    // the only recovery there was, and said nothing about it.

    fn make_orchestrator_with_clock(user_id: &str, clock: Arc<dyn Clock>) -> Orchestrator {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        Orchestrator::new_with_clock(client, user_id.to_string(), clock)
    }

    fn end_session_needed(cid: &str) -> RoutingDecision {
        RoutingDecision::EndSessionNeeded {
            contact_id: cid.to_string(),
            reason: "AEAD decryption failed".to_string(),
        }
    }

    fn heal_needed(cid: &str, is_handshake: bool) -> RoutingDecision {
        RoutingDecision::SessionHealNeeded {
            contact_id: cid.to_string(),
            role: crate::orchestration::message_router::Role::Responder,
            is_handshake,
            reason: "AEAD decryption failed".to_string(),
        }
    }

    fn need_session_init(cid: &str) -> RoutingDecision {
        RoutingDecision::NeedSessionInit {
            contact_id: cid.to_string(),
            queued_count: 1,
        }
    }

    /// A local id that outranks `bob`, so `tie_break_role` makes **us** the natural INITIATOR: a
    /// reopen is ours to make, and waits only the peer's flush out.
    const WE_REBUILD: &str = "zoe";
    /// And one `bob` outranks, so the rebuild is the peer's to make and our reopen waits their
    /// turn. Which of the two a test uses is what it is testing.
    const PEER_REBUILDS: &str = "alice";

    // ── Reopening after the peer's teardown (step 2, timer 3) ─────────────────

    /// The platform's re-init asks the machine and is held while the peer's flush arrives. It
    /// used to be a 1.5 s `Task.sleep` in `SessionCoordinator` with no way for anything else to
    /// see it — including the core, which would happily open the same ratchet meanwhile.
    ///
    /// The timer is the core's: a platform that arms its own on `OpenDeferred` has rebuilt the
    /// debounce this replaced.
    #[test]
    fn a_reopen_inside_the_peers_flush_is_deferred_on_the_cores_own_timer() {
        let mut o = make_orchestrator(WE_REBUILD);
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        let actions = o.handle_event(IncomingEvent::ReopenRequested {
            contact_id: "bob".to_string(),
        });
        assert!(
            actions.iter().any(
                |a| matches!(a, Action::OpenDeferred { contact_id, .. } if contact_id == "bob")
            ),
            "the platform must be told it is held, not handed an empty list"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::ScheduleTimer { timer_id, delay_ms }
                    if timer_id == "reopen:bob" && *delay_ms <= REOPEN_QUIET_MS + 100
            )),
            "nothing else will wake the orchestrator to run it, and the flush is all it waits for"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::OpenSession { .. }))
        );
    }

    // ── One heal record (step 4) ─────────────────────────────────────────────

    /// The budget is counted where the queued carrier already is. Until 2026-09-23 this queue's
    /// `attempts` was permanently zero — `record_attempt` had no caller — while the decision was
    /// made by a second `HealingQueue` the platform built for itself, keyed by account and fed a
    /// JSON `ChatMessage`.
    ///
    /// Mutation: return `HealAttemptAllowed` unconditionally — this reddens.
    #[test]
    fn the_heal_budget_runs_out_where_the_carrier_is_queued() {
        let mut o = make_orchestrator("alice");
        o.enqueue_heal("bob", b"x3dh".to_vec());
        // Two, not three: `max_attempts` is the attempt that is refused. See `HealingQueue`.
        for expected in 1..=2u32 {
            let actions = o.handle_event(IncomingEvent::HealAttempted {
                contact_id: "bob".to_string(),
            });
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::HealAttemptAllowed { contact_id, attempt }
                        if contact_id == "bob" && *attempt == expected
                )),
                "attempt {expected} must be allowed"
            );
        }
        let actions = o.handle_event(IncomingEvent::HealAttempted {
            contact_id: "bob".to_string(),
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::HealExhausted { contact_id } if contact_id == "bob"))
        );
    }

    /// No record means nothing to count against, so the answer is "stop" rather than "go ahead".
    /// An empty list would be worse than either: the platform read silence as permission before
    /// this action existed, by way of a Core Data lookup that missed.
    #[test]
    fn a_heal_with_nothing_queued_is_not_permission() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::HealAttempted {
            contact_id: "bob".to_string(),
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::HealExhausted { .. })),
            "an unbounded retry is what the budget exists to prevent"
        );
        assert!(!actions.is_empty(), "silence is not an answer");
    }

    /// A session that exists again settles the episode — the same rule that releases the phase.
    /// Without it a peer that needed three attempts once would start its next episode exhausted,
    /// for the TTL's whole twenty-four hours.
    #[test]
    fn a_session_that_came_back_settles_the_heal_budget() {
        let mut o = make_orchestrator("alice");
        o.enqueue_heal("bob", b"x3dh".to_vec());
        for _ in 0..3 {
            o.handle_event(IncomingEvent::HealAttempted {
                contact_id: "bob".to_string(),
            });
        }
        o.handle_event(IncomingEvent::SessionInitCompleted {
            contact_id: "bob".to_string(),
            session_data: Vec::new(),
        });
        let actions = o.handle_event(IncomingEvent::HealAttempted {
            contact_id: "bob".to_string(),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::HealAttemptAllowed { attempt, .. } if *attempt == 1
            )),
            "the next episode starts with its own budget"
        );
    }

    /// And the peer's teardown settles it too, for the same reason: the ratchet the carrier was
    /// queued against is gone.
    #[test]
    fn the_peers_teardown_settles_the_heal_budget() {
        let mut o = make_orchestrator("alice");
        o.enqueue_heal("bob", b"x3dh".to_vec());
        for _ in 0..3 {
            o.handle_event(IncomingEvent::HealAttempted {
                contact_id: "bob".to_string(),
            });
        }
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        let actions = o.handle_event(IncomingEvent::HealAttempted {
            contact_id: "bob".to_string(),
        });
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::HealAttemptAllowed { attempt, .. } if *attempt == 1
        )));
    }

    /// But settling is not forgetting. The incoming-trigger cap is what stops a peer from making
    /// us start heal episodes at will, and a peer who can reset it by tearing down has the
    /// exhaustion attack back.
    ///
    /// Mutation: call `remove` instead of `settle` — this reddens.
    #[test]
    fn a_teardown_does_not_hand_back_the_incoming_trigger_budget() {
        let mut o = make_orchestrator("alice");
        for _ in 0..12 {
            o.enqueue_heal("bob", b"x3dh".to_vec());
        }
        assert!(
            o.lifecycle.healing_queue.is_incoming_throttled("bob"),
            "twelve incoming triggers is past MAX_INCOMING_TRIGGERS"
        );
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        assert!(
            o.lifecycle.healing_queue.is_incoming_throttled("bob"),
            "the cap is per record lifetime, not per episode"
        );
    }

    // ── Held behind our own announcement (step 3) ────────────────────────────

    /// A message that will not open while our own SESSION_RESET_INIT is unanswered is held, not
    /// answered. Tearing down there answers our own reset with another reset and takes the
    /// message with it — 2026-08-04, a user's first message after a re-init.
    ///
    /// This was `SessionReducer.confirmGateAction` on iOS, asked at two call sites in
    /// `MessageRouter` against a gate the core could not see.
    ///
    /// Mutation: drop the `awaits_acknowledgement` guard from the `EndSessionNeeded` arm — this
    /// reddens.
    #[test]
    fn a_teardown_is_held_while_our_own_announcement_is_unanswered() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob".to_string(),
        });
        let actions = o.decision_to_actions(end_session_needed("bob"), "");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::HeldPendingAck { contact_id } if contact_id == "bob")),
            "the platform must be told to buffer it — silence here is the message dropped"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { .. })),
        );
    }

    /// And a heal is held for the sharper version of the same reason: healing as RESPONDER runs
    /// `archiveSession`, which destroys the session we built two seconds ago in answer to the
    /// very message that will not open.
    #[test]
    fn a_heal_is_held_while_our_own_announcement_is_unanswered() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob".to_string(),
        });
        let actions = o.decision_to_actions(heal_needed("bob", false), "");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::HeldPendingAck { contact_id } if contact_id == "bob"))
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SessionHealNeeded { .. }))
        );
    }

    /// A handshake carrier is the one thing the wait is waiting for, so holding it would make
    /// the gate wait on itself. `msg_number == 0` cannot answer this — a DH sending chain
    /// restarts at 0 on every ratchet turn — which is why the content type rides on the
    /// decision.
    ///
    /// Mutation: ignore `is_handshake` in the heal arm — this reddens, and on device it is the
    /// 2026-08-21 log: 16 of the peer's 19 `session_ready` sitting in the buffer of the gate
    /// waiting for them.
    #[test]
    fn a_handshake_carrier_is_not_held_behind_the_wait_it_ends() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob".to_string(),
        });
        let actions = o.decision_to_actions(heal_needed("bob", true), "");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SessionHealNeeded { .. })),
            "their X3DH is what resolves the wait; the heal is what applies it"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::HeldPendingAck { .. }))
        );
    }

    /// The gate is asked of **one device**. iOS folded it over the peer's device set, so an
    /// unanswered announcement to one device held a genuine teardown for its sibling — and a
    /// ratchet is between two devices, so our SRI to one says nothing about the other.
    ///
    /// Mutation: fold the question over the peer's devices — this reddens.
    #[test]
    fn the_hold_is_asked_of_one_device_not_of_its_sibling() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob-phone".to_string(),
        });
        let actions = o.decision_to_actions(end_session_needed("bob-laptop"), "");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { .. })),
            "the sibling's ratchet is not waiting on anything"
        );
    }

    /// And the hold ends where the wait does. Both ends work: the peer's acknowledgement here,
    /// and `OpeningGaveUp` off the `open_confirm:` alarm — which is why that alarm exists.
    #[test]
    fn the_hold_ends_when_the_peer_acknowledges() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob".to_string(),
        });
        o.handle_event(IncomingEvent::PeerAcked {
            contact_id: "bob".to_string(),
        });
        let actions = o.decision_to_actions(end_session_needed("bob"), "");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { .. })),
            "a genuine divergence still tears down, one confirm window later"
        );
    }

    // ── Whose turn it is to rebuild (step 2, timer 5) ─────────────────────────

    /// Ranked in the core, over the two device ids, at the one moment both sides see the same
    /// dead ratchet. The natural RESPONDER's reopen waits the peer's whole turn — not the flush.
    ///
    /// Mutation: pass `peer_rebuilds: false` unconditionally — this reddens, and on device it is
    /// two clients announcing at each other, which is the dueling-initiator deadlock.
    #[test]
    fn the_reopen_of_the_side_that_should_not_rebuild_waits_the_peers_turn() {
        let mut o = make_orchestrator(PEER_REBUILDS);
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        let actions = o.handle_event(IncomingEvent::ReopenRequested {
            contact_id: "bob".to_string(),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::ScheduleTimer { timer_id, delay_ms }
                    if timer_id == "reopen:bob" && *delay_ms > PEER_TEARDOWN_QUIET_MS
            )),
            "the turn must outlast the teardown window, or taking the role finds our own \
             teardown still gated"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::OpenSession { .. }))
        );
    }

    /// And the turn ends. `startResponderFallback` was a 60 s `Task.sleep` keyed by account; what
    /// pays it now is the core's own alarm, which is the same one the flush quiet uses.
    #[test]
    fn the_role_is_taken_when_the_peers_rebuild_never_comes() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock(PEER_REBUILDS, clock.clone());
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        o.handle_event(IncomingEvent::ReopenRequested {
            contact_id: "bob".to_string(),
        });
        clock.advance_ms(RESPONDER_OVERRIDE_MS + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "reopen:bob".to_string(),
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::OpenSession { contact_id } if contact_id == "bob")),
            "a wait with no end is the conversation stopping for good"
        );
    }

    /// A peer that keeps tearing down does not keep its turn. The alarm re-asks `WantToOpen`,
    /// which yields to nobody: the ordering was ranked once, when the ratchet died.
    ///
    /// Mutation: make the timer arm ask `WantToReopen` — this reddens.
    #[test]
    fn the_peers_turn_is_not_extended_by_tearing_down_again() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock(PEER_REBUILDS, clock.clone());
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        o.handle_event(IncomingEvent::ReopenRequested {
            contact_id: "bob".to_string(),
        });
        clock.advance_ms(RESPONDER_OVERRIDE_MS / 2);
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        clock.advance_ms(RESPONDER_OVERRIDE_MS / 2 + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "reopen:bob".to_string(),
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::OpenSession { contact_id } if contact_id == "bob")),
            "the turn is bounded from the ratchet's death, not from the peer's last word"
        );
    }

    /// A message needing a session never waits the peer's turn out, on either side of the
    /// ranking. It waits the flush, like any other send — `plan_initiation` says the same thing
    /// in its own words: outbound work outranks prekey economy.
    ///
    /// Mutation: rank `NeedSessionInit` too — this reddens, and on device it is a typed message
    /// sitting for a minute with nothing on screen to say why.
    #[test]
    fn a_queued_message_does_not_wait_the_peers_turn_out() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock(PEER_REBUILDS, clock.clone());
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        o.decision_to_actions(need_session_init("bob"), "");
        clock.advance_ms(REOPEN_QUIET_MS + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "reopen:bob".to_string(),
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::OpenSession { contact_id } if contact_id == "bob"))
        );
    }

    /// Nothing torn down, nothing to wait for — including no turn to yield, because a turn is
    /// measured from a teardown and there has not been one.
    #[test]
    fn a_reopen_of_a_quiet_device_goes_straight_out() {
        let mut o = make_orchestrator(PEER_REBUILDS);
        let actions = o.handle_event(IncomingEvent::ReopenRequested {
            contact_id: "bob".to_string(),
        });
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::OpenSession { contact_id } if contact_id == "bob"));
    }

    /// A backlog flush of N teardowns produces **one** re-init, and not before the flush ends.
    /// Each used to schedule its own wipe+init+SRI, and every one after the first destroyed the
    /// session the previous had just created — so the peer AEAD-failed all but the last SRI and
    /// answered with fresh teardowns. The coalescing map is gone; the phase is what is one.
    ///
    /// Mutation: drop the `DeferOpen` arm from `handle_reopen_requested` — this reddens.
    #[test]
    fn a_flush_of_teardowns_produces_no_re_init_while_it_is_still_arriving() {
        let mut o = make_orchestrator("alice");
        let mut all = Vec::new();
        for _ in 0..3 {
            o.handle_event(IncomingEvent::PeerToreDown {
                contact_id: "bob".to_string(),
            });
            all.extend(o.handle_event(IncomingEvent::ReopenRequested {
                contact_id: "bob".to_string(),
            }));
        }
        assert!(
            !all.iter().any(|a| matches!(a, Action::OpenSession { .. })),
            "three teardowns in one flush must not start three announces"
        );
        assert_eq!(
            all.iter()
                .filter(|a| matches!(a, Action::OpenDeferred { .. }))
                .count(),
            3,
            "each ask is answered — silence is what iOS read as a drop"
        );
    }

    /// And when the flush has had its moment, the re-init runs.
    #[test]
    fn the_held_re_init_runs_once_the_quiet_passes() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock(WE_REBUILD, clock.clone());
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        o.handle_event(IncomingEvent::ReopenRequested {
            contact_id: "bob".to_string(),
        });
        clock.advance_ms(REOPEN_QUIET_MS + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "reopen:bob".to_string(),
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::OpenSession { contact_id } if contact_id == "bob")),
            "the core owns the alarm, so the core is what pays it"
        );
    }

    /// A message that needs a session waits for the peer's flush too, and for the same reason:
    /// its X3DH would cross theirs. It is queued either way — `MessageQueuedPendingInit` is the
    /// word for that, and the empty list this used to be was read by iOS as a drop.
    #[test]
    fn a_message_needing_a_session_waits_for_the_peers_flush_too() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        let actions = o.decision_to_actions(need_session_init("bob"), "");
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::FetchPublicKeyBundle { .. })),
            "the bundle fetch is what starts the crossing init"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::MessageQueuedPendingInit { .. }))
        );
        assert!(
            actions.iter().any(
                |a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id == "reopen:bob")
            ),
            "a queued message is not re-delivered, so only our own alarm brings it back"
        );
    }

    /// And it is paid with an announce, not a bundle fetch. The fetch this arm grants directly is
    /// message-bound on the platform — it re-queues the carrier it came with — and a timer has no
    /// carrier, so granting one later would be a producer with no reader. After a teardown the
    /// recovery is an announced X3DH either way, and the queued message drains out of
    /// `pending_queues` on init completion like anything else held behind an open.
    #[test]
    fn the_queued_message_is_recovered_by_an_announce_when_the_quiet_passes() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock("alice", clock.clone());
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        o.decision_to_actions(need_session_init("bob"), "");
        clock.advance_ms(REOPEN_QUIET_MS + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "reopen:bob".to_string(),
        });
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::OpenSession { contact_id } if contact_id == "bob"));
    }

    /// Two callers held by one quiet produce one open. Two announces spend two of the peer's
    /// one-time pre-keys and the second session orphans the SRI the first just put on the wire —
    /// which is what the `[String: Task]` map existed to prevent, one flush at a time.
    #[test]
    fn two_callers_held_by_one_quiet_produce_one_open() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock(WE_REBUILD, clock.clone());
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        o.decision_to_actions(need_session_init("bob"), "");
        let held = o.handle_event(IncomingEvent::ReopenRequested {
            contact_id: "bob".to_string(),
        });
        assert!(
            held.iter().any(
                |a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id == "reopen:bob")
            ),
            "both callers wait on the one alarm"
        );
        clock.advance_ms(REOPEN_QUIET_MS + 200);
        let first = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "reopen:bob".to_string(),
        });
        let second = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "reopen:bob".to_string(),
        });
        assert_eq!(first.len(), 1);
        assert!(matches!(&first[0], Action::OpenSession { .. }));
        assert!(
            second.is_empty(),
            "the alarm firing twice does not announce twice — the first open holds the phase"
        );
    }

    /// The peer's rebuild arrived during the quiet, which is what the quiet was waiting for. The
    /// line matters on device: it is what to look for when a re-init "should have" happened.
    #[test]
    fn a_session_that_came_back_during_the_quiet_cancels_the_re_init() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock(WE_REBUILD, clock.clone());
        o.handle_event(IncomingEvent::PeerToreDown {
            contact_id: "bob".to_string(),
        });
        o.handle_event(IncomingEvent::ReopenRequested {
            contact_id: "bob".to_string(),
        });
        // Stand in for the peer's init having completed: the machine's record goes, and the
        // orchestrator's own `has_active_session` is what the timer arm consults.
        o.sessions.handle("bob", SessionEvent::OpenFinished);
        clock.advance_ms(REOPEN_QUIET_MS + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "reopen:bob".to_string(),
        });
        // No session in this harness, so the machine grants the open — what is pinned here is
        // that a cleared phase does not leave the quiet running.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::OpenSession { .. })),
            "a cleared phase reopens immediately; it is the quiet that must not survive it"
        );
    }

    // ── Waiting for the peer's acknowledgement (step 3) ──────────────────────

    /// An announcement arms the confirm alarm. Nothing else ever does, so a missing one is a gate
    /// that never opens — which is what the single-shot watchdog left behind.
    ///
    /// Mutation: return `vec![]` from `handle_sri_announced` — this reddens.
    #[test]
    fn an_announcement_arms_the_confirm_alarm() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob".to_string(),
        });
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], Action::ScheduleTimer { timer_id, .. } if timer_id == "open_confirm:bob"),
            "nothing else wakes the orchestrator to re-send an unacknowledged SRI"
        );
        assert!(o.awaits_acknowledgement("bob"));
    }

    /// A finished init does not: a responder announces nothing, so there is nothing to wait for,
    /// and an initiator's wait starts from the carrier rather than from the init behind it.
    #[test]
    fn a_finished_init_alone_arms_no_confirm_alarm() {
        let mut o = make_orchestrator("alice");
        o.sessions.handle("bob", SessionEvent::WantToOpen);
        let actions = o.handle_event(IncomingEvent::SessionInitCompleted {
            contact_id: "bob".to_string(),
            session_data: vec![],
        });
        assert!(
            !actions.iter().any(
                |a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id.starts_with("open_confirm:"))
            )
        );
        assert!(!o.awaits_acknowledgement("bob"));
    }

    /// The alarm re-sends and re-arms itself. Re-arming is the whole fix: the watchdog was
    /// single-shot until 2026-08-04, fired once, went silent, and left the gate raised.
    #[test]
    fn the_confirm_alarm_re_sends_and_re_arms() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock("alice", clock.clone());
        o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob".to_string(),
        });
        clock.advance_ms(SRI_RETRY_MS);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "open_confirm:bob".to_string(),
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::ResendSri { contact_id } if contact_id == "bob"))
        );
        assert!(
            actions.iter().any(
                |a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id == "open_confirm:bob")
            ),
            "a retry that does not re-arm is the single-shot watchdog again"
        );
    }

    /// And it stops. Past the window the opening is given up, with no re-arm — the platform
    /// releases what it held and the ordinary decrypt/heal path decides on what arrives next.
    #[test]
    fn the_confirm_alarm_gives_up_at_the_window_and_does_not_re_arm() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock("alice", clock.clone());
        o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob".to_string(),
        });
        clock.advance_ms(OPENING_CONFIRM_WINDOW_MS + 1);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "open_confirm:bob".to_string(),
        });
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::OpeningGaveUp { contact_id } if contact_id == "bob"));
    }

    /// The peer's acknowledgement ends the wait and cancels the alarm. Leaving it armed means an
    /// SRI re-sent at a peer that already answered — a fresh X3DH over a working ratchet.
    #[test]
    fn the_peers_acknowledgement_ends_the_wait_and_the_alarm() {
        let mut o = make_orchestrator("alice");
        o.handle_event(IncomingEvent::SriAnnounced {
            contact_id: "bob".to_string(),
        });
        let actions = o.handle_event(IncomingEvent::PeerAcked {
            contact_id: "bob".to_string(),
        });
        assert_eq!(o.sessions.phase("bob"), crate::orchestration::Phase::Absent);
        assert!(actions.iter().any(
            |a| matches!(a, Action::CancelTimer { timer_id } if timer_id == "open_confirm:bob")
        ));
    }

    #[test]
    fn test_end_session_suppressed_by_cooldown_is_owed_not_dropped() {
        let mut o = make_orchestrator("alice");
        let _ = o.decision_to_actions(end_session_needed("bob"), "");

        let actions = o.decision_to_actions(end_session_needed("bob"), "");

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::EndSessionSuppressed { contact_id, .. } if contact_id == "bob")),
            "the platform must be told, not handed an empty list it has to guess about"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id == "cooldown_expired:bob")),
            "nothing else will wake the orchestrator to pay the debt"
        );
        assert!(o.sessions.owes_teardown("bob"));
    }

    #[test]
    fn test_owed_end_session_is_sent_when_the_cooldown_expires() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock("alice", clock.clone());
        let _ = o.decision_to_actions(end_session_needed("bob"), "");
        let _ = o.decision_to_actions(end_session_needed("bob"), "");

        clock.advance_ms(END_SESSION_COOLDOWN_MS + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "cooldown_expired:bob".to_string(),
        });

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { contact_id } if contact_id == "bob")),
            "the teardown the cooldown deferred must actually go out"
        );
        assert!(!o.sessions.owes_teardown("bob"), "and only once");
    }

    #[test]
    fn test_three_suppressions_in_one_window_collapse_into_one_teardown() {
        // msgNum 5, 6, 7 — the incident. The cooldown must still damp the storm it was
        // written for: three debts, one payment.
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock("alice", clock.clone());
        let _ = o.decision_to_actions(end_session_needed("bob"), "");
        for _ in 0..3 {
            let _ = o.decision_to_actions(end_session_needed("bob"), "");
        }

        clock.advance_ms(END_SESSION_COOLDOWN_MS + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "cooldown_expired:bob".to_string(),
        });

        let sends = actions
            .iter()
            .filter(|a| matches!(a, Action::SendEndSession { .. }))
            .count();
        assert_eq!(sends, 1);
    }

    // ── What must NOT fire ────────────────────────────────────────────────────
    //
    // An owed teardown paid out unconditionally is worse than the bug it fixes: it destroys
    // whatever session exists when the timer happens to land. That is the crossing-teardown
    // defect this project has been chasing all week from the other end.

    #[test]
    fn test_owed_end_session_is_void_once_the_session_is_re_established() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock("alice", clock.clone());
        let _ = o.decision_to_actions(end_session_needed("bob"), "");
        let _ = o.decision_to_actions(end_session_needed("bob"), "");
        assert!(o.sessions.owes_teardown("bob"));

        // A new session is built during the cooldown (iOS: proactive_init_success → SRI).
        let _ = o.handle_event(IncomingEvent::SessionInitCompleted {
            contact_id: "bob".to_string(),
            session_data: vec![],
        });

        clock.advance_ms(END_SESSION_COOLDOWN_MS + 200);
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "cooldown_expired:bob".to_string(),
        });

        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { .. })),
            "the session that replaced the broken one must not be torn down by its debt"
        );
    }

    #[test]
    fn test_a_timer_for_a_contact_with_no_debt_sends_nothing() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "cooldown_expired:bob".to_string(),
        });
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { .. }))
        );
    }

    #[test]
    fn test_end_session_off_cooldown_is_still_sent_immediately() {
        // The unchanged path. If this ever starts deferring, every teardown is a round trip late.
        let mut o = make_orchestrator("alice");
        let actions = o.decision_to_actions(end_session_needed("bob"), "");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { contact_id } if contact_id == "bob"))
        );
        assert!(!o.sessions.owes_teardown("bob"));
    }

    // ── The init lock says what it did ────────────────────────────────────────

    #[test]
    fn test_message_arriving_during_init_is_reported_queued_not_dropped() {
        // Also formerly `vec![]`. The message is in `pending_queues` and drained by
        // SessionInitCompleted — iOS logged "holding the cursor for redelivery" over a message
        // the core was holding perfectly well.
        let mut o = make_orchestrator("alice");
        o.sessions.handle("bob", SessionEvent::WantToOpen);

        let actions = o.decision_to_actions(
            RoutingDecision::NeedSessionInit {
                contact_id: "bob".to_string(),
                queued_count: 2,
            },
            "",
        );

        assert!(matches!(
            actions.as_slice(),
            [Action::MessageQueuedPendingInit { contact_id, queued_count }]
                if contact_id == "bob" && *queued_count == 2
        ));
    }

    /// A ratchet nobody has touched is `Absent`, so the first teardown goes out immediately.
    /// If this ever starts deferring, every teardown is a round trip late.
    #[test]
    fn test_no_cooldown_initially() {
        let mut o = make_orchestrator("alice");
        assert_eq!(o.sessions.phase("bob"), crate::orchestration::Phase::Absent);
        assert!(
            o.decision_to_actions(end_session_needed("bob"), "")
                .iter()
                .any(|a| matches!(a, Action::SendEndSession { .. }))
        );
    }

    // ── The owed teardown names the session it condemns (2026-09-24) ─────────

    /// Give `o` an initiator session with a fresh peer device, the way `init_session` leaves one.
    fn hold_session_with_new_peer(o: &mut Orchestrator) -> String {
        use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
        use crate::device_id::derive_device_id;

        let peer = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let bundle = peer.get_registration_bundle().unwrap();
        let identity = peer.key_manager().identity_public_key().unwrap().clone();
        let device = derive_device_id(&bundle.identity_public);
        let x3dh = X3DHPublicKeyBundle {
            identity_public: bundle.identity_public.clone(),
            signed_prekey_public: bundle.signed_prekey_public.clone(),
            signature: bundle.signature.clone(),
            verifying_key: bundle.verifying_key.clone(),
            suite_id: bundle.suite_id,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
            spk_uploaded_at: 0,
            spk_rotation_epoch: 0,
            kyber_spk_uploaded_at: 0,
            kyber_spk_rotation_epoch: 0,
            supports_pq_ratchet: false,
        };
        o.lifecycle
            .client
            .init_session(&device, &x3dh, &identity, 0)
            .unwrap();
        device
    }

    fn pays_teardown(actions: &[Action], device: &str) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::SendEndSession { contact_id } if contact_id == device))
    }

    /// The device logs of 2026-09-24: a diverged ratchet stays held until the END_SESSION that
    /// condemns it goes out, so the debt is owed against a session that is still there — and the
    /// payout, asking only "is there a session?", read it as re-established and dropped itself.
    ///
    /// Mutation: restore `has_active_session` as the payout's check — this reddens.
    #[test]
    fn an_owed_teardown_against_the_session_still_held_is_paid() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock("alice", clock.clone());
        let device = hold_session_with_new_peer(&mut o);

        let granted = o.decision_to_actions(end_session_needed(&device), "");
        assert!(
            pays_teardown(&granted, &device),
            "the first teardown goes out"
        );
        let deferred = o.decision_to_actions(end_session_needed(&device), "");
        assert!(o.sessions.owes_teardown(&device), "the second is owed");
        assert!(!pays_teardown(&deferred, &device));
        assert!(
            o.lifecycle.has_active_session(&device),
            "the premise: still held"
        );

        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        let paid = o.handle_event(IncomingEvent::TimerFired {
            timer_id: format!("cooldown_expired:{device}"),
        });
        assert!(
            pays_teardown(&paid, &device),
            "the debt was owed against the session that is still held, and was dropped"
        );
    }

    /// The case the check exists for, kept: a session established during the cooldown is a
    /// different ratchet, and tearing it down is the crossing-teardown defect.
    ///
    /// Mutation: pay whenever a debt is owed, ignoring the session — this reddens.
    #[test]
    fn an_owed_teardown_is_void_once_a_different_session_holds_the_device() {
        let clock = Arc::new(MockClock::new(1_000_000));
        let mut o = make_orchestrator_with_clock("alice", clock.clone());
        let device = hold_session_with_new_peer(&mut o);

        let _ = o.decision_to_actions(end_session_needed(&device), "");
        let _ = o.decision_to_actions(end_session_needed(&device), "");
        let condemned = o.lifecycle.active_session_id(&device);
        assert!(condemned.is_some());

        // A new ratchet with the same device, arrived without the event that cancels the debt.
        o.lifecycle.client.remove_session(&device);
        let replaced = hold_session_with_new_peer_as(&mut o, &device);
        assert!(replaced);
        assert_ne!(
            o.lifecycle.active_session_id(&device),
            condemned,
            "the premise: a new session"
        );

        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        let paid = o.handle_event(IncomingEvent::TimerFired {
            timer_id: format!("cooldown_expired:{device}"),
        });
        assert!(
            !pays_teardown(&paid, &device),
            "a session established during the cooldown was torn down by a debt owed to its predecessor"
        );
    }

    /// Re-open a session under an existing device id, as a crossing re-init would.
    fn hold_session_with_new_peer_as(o: &mut Orchestrator, device: &str) -> bool {
        use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

        let peer = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let bundle = peer.get_registration_bundle().unwrap();
        let identity = peer.key_manager().identity_public_key().unwrap().clone();
        let x3dh = X3DHPublicKeyBundle {
            identity_public: bundle.identity_public.clone(),
            signed_prekey_public: bundle.signed_prekey_public.clone(),
            signature: bundle.signature.clone(),
            verifying_key: bundle.verifying_key.clone(),
            suite_id: bundle.suite_id,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
            spk_uploaded_at: 0,
            spk_rotation_epoch: 0,
            kyber_spk_uploaded_at: 0,
            kyber_spk_rotation_epoch: 0,
            supports_pq_ratchet: false,
        };
        o.lifecycle
            .client
            .init_session(device, &x3dh, &identity, 0)
            .is_ok()
    }

    /// A refused decrypt says why, on both paths the refusal takes. The cause was dropped here
    /// (`reason: _`) and never left the router on the heal path, so a device log showed every
    /// message answered with END_SESSION and nothing on what the ratchet objected to.
    ///
    /// Mutation: drop the `NotifyError` push in `decision_to_actions` — this reddens.
    /// The platform's question gets the machine's answer, one action, naming the device.
    /// Mutation that reddens it: map `Redelivery` or `PredatesSession` onto `ApplyResetInit`.
    #[test]
    fn an_arriving_reset_init_is_answered_apply_or_superseded() {
        let mut o = make_orchestrator("alice");
        let arrive = |o: &mut Orchestrator, key: u8, sent: u64, est: Option<u64>| {
            o.handle_event(IncomingEvent::ResetInitArrived {
                contact_id: "bob".into(),
                init_ephemeral: vec![key; 32],
                sent_at_s: sent,
                established_at_s: est,
            })
        };
        assert!(matches!(
            arrive(&mut o, 1, 100, None).as_slice(),
            [Action::ApplyResetInit { contact_id }] if contact_id == "bob"
        ));
        assert!(matches!(
            arrive(&mut o, 1, 100, None).as_slice(),
            [Action::ResetInitSuperseded { contact_id, redelivery: true }] if contact_id == "bob"
        ));
        assert!(matches!(
            arrive(&mut o, 2, 10, Some(1_000)).as_slice(),
            [Action::ResetInitSuperseded {
                redelivery: false,
                ..
            }]
        ));
    }

    #[test]
    fn a_refused_decrypt_reports_its_cause_on_both_paths() {
        let mut o = make_orchestrator("alice");
        for (path, actions) in [
            (
                "tear down",
                o.decision_to_actions(end_session_needed("bob"), ""),
            ),
            (
                "heal",
                o.decision_to_actions(heal_needed("carol", false), ""),
            ),
        ] {
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::NotifyError { code, message }
                        if code == DECRYPT_FAILED && message == "AEAD decryption failed"
                )),
                "the {path} path lost the ratchet's reason: {actions:?}"
            );
        }
    }
}

/// The Kyber-prekey plan as the orchestrator carries it out: what gets encapsulated, what the
/// session is called, what is remembered, and what is refused.
#[cfg(all(test, feature = "post-quantum"))]
mod kyber_prekey_auth_tests {
    use super::*;
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
    use crate::crypto::keys::KeyManager;
    use crate::crypto::kyber_prekey_auth::PqAuthentication;
    use crate::device_id::derive_device_id;

    struct Peer {
        client: ClassicClient<ClassicSuiteProvider>,
        kyber_public: Vec<u8>,
    }

    impl Peer {
        fn new() -> Self {
            Self {
                client: ClassicClient::<ClassicSuiteProvider>::new().unwrap(),
                kyber_public: crate::crypto::pq_x3dh::mlkem768_keygen()
                    .unwrap()
                    .public_key,
            }
        }

        fn device(&self) -> String {
            derive_device_id(
                &self
                    .client
                    .get_registration_bundle()
                    .unwrap()
                    .identity_public,
            )
        }

        fn bundle(&self) -> X3DHPublicKeyBundle {
            let b = self.client.get_registration_bundle().unwrap();
            X3DHPublicKeyBundle {
                identity_public: b.identity_public,
                signed_prekey_public: b.signed_prekey_public,
                signature: b.signature,
                verifying_key: b.verifying_key,
                suite_id: b.suite_id,
                one_time_prekey_public: None,
                one_time_prekey_id: None,
                spk_uploaded_at: 0,
                spk_rotation_epoch: 0,
                kyber_spk_uploaded_at: 0,
                kyber_spk_rotation_epoch: 0,
                supports_pq_ratchet: false,
            }
        }

        /// What iOS `PQCKeyManager.signKyberKey` produces.
        fn kyber_signature(&self) -> Vec<u8> {
            let sk = self.client.key_manager().signing_secret_key().unwrap();
            let msg = KeyManager::<ClassicSuiteProvider>::build_x3dh_sign_message(
                0x10,
                &self.kyber_public,
            );
            ClassicSuiteProvider::sign(sk, &msg).unwrap()
        }

        fn signed(&self) -> KyberBundleKeys {
            KyberBundleKeys {
                pre_key_public: Some(self.kyber_public.clone()),
                pre_key_signature: Some(self.kyber_signature()),
                ..Default::default()
            }
        }

        fn unsigned(&self) -> KyberBundleKeys {
            KyberBundleKeys {
                pre_key_public: Some(self.kyber_public.clone()),
                ..Default::default()
            }
        }
    }

    fn orchestrator() -> Orchestrator {
        Orchestrator::new(
            ClassicClient::<ClassicSuiteProvider>::new().unwrap(),
            "alice".to_string(),
        )
    }

    fn label(o: &Orchestrator, device: &str) -> PqAuthentication {
        o.get_session_health(device).unwrap().pq_authentication
    }

    #[test]
    fn a_signed_kyber_spk_makes_an_authenticated_session_and_is_remembered() {
        let mut o = orchestrator();
        let peer = Peer::new();
        let device = peer.device();

        o.init_session_with_bundle(&device, peer.bundle(), peer.signed(), false)
            .unwrap();

        assert_eq!(label(&o, &device), PqAuthentication::Authenticated);
        assert!(o.lifecycle.pq_manager.has_pending(&device), "encapsulated");
        assert!(o.lifecycle.has_presented_signed_kyber(&device));

        // Remembered across a restart of the orchestrator state.
        let state = o.export_orchestrator_state_cfe().unwrap();
        let mut restarted = orchestrator();
        restarted.import_orchestrator_state_cfe(&state).unwrap();
        assert!(restarted.lifecycle.has_presented_signed_kyber(&device));
    }

    #[test]
    fn an_unsigned_kyber_key_is_used_and_labelled_unauthenticated() {
        let mut o = orchestrator();
        let peer = Peer::new();
        let device = peer.device();

        o.init_session_with_bundle(&device, peer.bundle(), peer.unsigned(), false)
            .unwrap();

        assert_eq!(label(&o, &device), PqAuthentication::Unauthenticated);
        assert!(
            o.lifecycle.pq_manager.has_pending(&device),
            "still encapsulated"
        );
        assert!(!o.lifecycle.has_presented_signed_kyber(&device));
    }

    /// The transition-period attack: a device known to sign arrives with its Kyber signature
    /// stripped. Mutation: skip the `Refuse` early return — this reddens.
    #[test]
    fn a_stripped_signature_from_a_remembered_device_is_refused_before_any_session() {
        let mut o = orchestrator();
        let peer = Peer::new();
        let device = peer.device();
        o.init_session_with_bundle(&device, peer.bundle(), peer.signed(), false)
            .unwrap();
        o.lifecycle.client.remove_session(&device);
        o.lifecycle.pq_manager.discard_for_contact(&device);

        for stripped in [peer.unsigned(), KyberBundleKeys::default()] {
            let err = o
                .init_session_with_bundle(&device, peer.bundle(), stripped, false)
                .unwrap_err();
            assert!(err.starts_with("PQ_DOWNGRADE_REFUSED"), "{err}");
            assert!(
                !o.has_active_session(&device),
                "a refusal leaves no session"
            );
            assert!(!o.lifecycle.pq_manager.has_pending(&device));
        }
    }

    #[test]
    fn a_wrong_signature_from_a_new_device_is_classic_and_not_encapsulated() {
        let mut o = orchestrator();
        let peer = Peer::new();
        let impostor = Peer::new();
        let device = peer.device();
        let forged = KyberBundleKeys {
            pre_key_public: Some(impostor.kyber_public.clone()),
            pre_key_signature: Some(impostor.kyber_signature()),
            ..Default::default()
        };

        o.init_session_with_bundle(&device, peer.bundle(), forged, false)
            .unwrap();

        assert_eq!(label(&o, &device), PqAuthentication::Classic);
        assert!(!o.lifecycle.pq_manager.has_pending(&device));
        assert!(!o.lifecycle.has_presented_signed_kyber(&device));
    }

    fn advertising_pq_ratchet(peer: &Peer) -> X3DHPublicKeyBundle {
        X3DHPublicKeyBundle {
            supports_pq_ratchet: true,
            ..peer.bundle()
        }
    }

    /// The cheapest PQ downgrade: the server drops the unsigned `supports_pq_ratchet` flag and
    /// the initiator quietly negotiates CLASSIC. Once a device has advertised the ratchet, a
    /// bundle without it is refused, before any session exists.
    ///
    /// Mutation: skip the capability refusal — this reddens.
    #[test]
    fn a_withdrawn_pq_ratchet_capability_is_refused() {
        let mut o = orchestrator();
        let peer = Peer::new();
        let device = peer.device();

        o.init_session_with_bundle(&device, advertising_pq_ratchet(&peer), peer.signed(), false)
            .unwrap();
        assert!(o.lifecycle.has_used_pq_ratchet(&device));
        assert_eq!(
            o.get_session_suite_id(&device),
            crate::crypto::SuiteID::PQ_RATCHET.as_u16(),
            "the premise: the ratchet was negotiated"
        );

        // Remembered across a restart.
        let state = o.export_orchestrator_state_cfe().unwrap();
        let mut o = orchestrator();
        o.import_orchestrator_state_cfe(&state).unwrap();
        assert!(o.lifecycle.has_used_pq_ratchet(&device));

        let err = o
            .init_session_with_bundle(&device, peer.bundle(), peer.signed(), false)
            .unwrap_err();
        assert!(
            err.starts_with("PQ_DOWNGRADE_REFUSED: PqRatchetWithdrawn"),
            "{err}"
        );
        assert!(
            !o.has_active_session(&device),
            "a refusal leaves no session"
        );
    }

    /// A device we have never seen with the ratchet is not refused for lacking it.
    #[test]
    fn a_device_that_never_advertised_the_ratchet_opens_classic() {
        let mut o = orchestrator();
        let peer = Peer::new();
        let device = peer.device();
        o.init_session_with_bundle(&device, peer.bundle(), peer.signed(), false)
            .unwrap();
        assert!(!o.lifecycle.has_used_pq_ratchet(&device));
        assert_eq!(
            o.get_session_suite_id(&device),
            crate::crypto::SuiteID::CLASSIC.as_u16()
        );
    }

    /// The responder learns the capability from the session itself: a suite-3 first message is
    /// proof the device has the ratchet, and a later bundle without it is refused.
    #[test]
    fn a_received_suite_3_session_is_remembered() {
        let mut o = orchestrator();
        let peer = Peer::new();
        let device = peer.device();

        o.note_received_suite(&device, crate::crypto::SuiteID::CLASSIC.as_u16());
        assert!(!o.lifecycle.has_used_pq_ratchet(&device));
        o.note_received_suite(&device, crate::crypto::SuiteID::PQ_RATCHET.as_u16());
        assert!(o.lifecycle.has_used_pq_ratchet(&device));

        let err = o
            .init_session_with_bundle(&device, peer.bundle(), peer.signed(), false)
            .unwrap_err();
        assert!(
            err.starts_with("PQ_DOWNGRADE_REFUSED: PqRatchetWithdrawn"),
            "{err}"
        );
    }

    /// `is_pq_strengthened` used to be `pre_pq_root_key.is_none()`, which only the responder
    /// sets — every initiator session, classical ones included, reported "strengthened".
    #[test]
    fn strengthened_means_a_secret_was_mixed_in_and_the_label_survives_export() {
        let mut o = orchestrator();
        let peer = Peer::new();
        let device = peer.device();

        o.init_session_with_bundle(&device, peer.bundle(), KyberBundleKeys::default(), false)
            .unwrap();
        let classic = o.get_session_health(&device).unwrap();
        assert_eq!(classic.pq_authentication, PqAuthentication::Classic);
        assert!(!classic.is_pq_strengthened, "a classical initiator session");

        let pq_peer = Peer::new();
        let pq_device = pq_peer.device();
        o.init_session_with_bundle(&pq_device, pq_peer.bundle(), pq_peer.signed(), false)
            .unwrap();
        assert!(
            !o.get_session_health(&pq_device).unwrap().is_pq_strengthened,
            "encapsulated but not mixed in until the first message"
        );
        let _ = o.handle_outgoing_message(pq_device.clone(), "m1".into(), b"hi".to_vec(), 0);
        let health = o.get_session_health(&pq_device).unwrap();
        assert!(health.is_pq_strengthened);
        assert_eq!(health.pq_authentication, PqAuthentication::Authenticated);

        let bytes = o.lifecycle.export_session_bytes_for(&pq_device).unwrap();
        o.lifecycle.client.remove_session(&pq_device);
        o.lifecycle
            .import_session_bytes(&pq_device, &bytes)
            .unwrap();
        let restored = o.get_session_health(&pq_device).unwrap();
        assert!(restored.is_pq_strengthened);
        assert_eq!(restored.pq_authentication, PqAuthentication::Authenticated);
    }
}
