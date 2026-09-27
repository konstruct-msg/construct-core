/// Message Router — Rust port of Swift `MessageRouter`.
///
/// The Decision Engine: receives a raw incoming message, runs it through
/// deduplication, session lookup, and decryption, and returns a
/// `RoutingDecision` describing what happened plus `Vec<Action>` for the
/// platform to execute.
///
/// No I/O is performed here. All side-effects are expressed as `Action` values
/// returned to the caller (Swift / Kotlin).
///
/// ## State machine per message
///
/// ```text
/// message arrives
///   │
///   ├─ is_duplicate? → Duplicate
///   │
///   ├─ is END_SESSION? → EndSessionReceived
///   │
///   ├─ no session, carries the handshake header?
///   │     └─ enqueue → NeedSessionInit (open from it)
///   │
///   └─ decrypt on the current state, then on each previous one
///         ├─ ok → Decrypted
///         ├─ key already used → Duplicate
///         └─ fail
///               ├─ carries the header → NeedSessionInit (a new state opens from it)
///               └─ carries none      → EndSessionNeeded
/// ```
use std::collections::{HashMap, VecDeque};

use crate::crypto::messaging::double_ratchet::MESSAGE_KEY_CONSUMED;
use crate::orchestration::actions::Action;
use crate::orchestration::session_lifecycle::SessionLifecycleManager;

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_PENDING_PER_USER: usize = 100;

/// Outcome of routing one message.
#[derive(Debug, Clone)]
pub enum RoutingDecision {
    /// Message decrypted successfully.
    Decrypted {
        contact_id: String,
        message_id: String,
        plaintext: Vec<u8>,
        content_type: u8,
        actions: Vec<Action>,
    },
    /// No active session; message queued — caller must fetch bundle and init session.
    NeedSessionInit {
        contact_id: String,
        queued_count: usize,
    },
    /// Nothing held decrypts it and it carries no handshake header — send END_SESSION.
    EndSessionNeeded { contact_id: String, reason: String },
    /// Message already processed — discard.
    Duplicate { message_id: String },
    /// ACK status unknown — buffered pending a DB check (platform feeds back `AckDbResult`).
    PendingAckCheck { message_id: String },
    /// Pending queue for this contact is full — apply backpressure.
    QueueFull { contact_id: String },
    /// END_SESSION control message received.
    EndSessionReceived {
        contact_id: String,
        actions: Vec<Action>,
    },
    /// Unrecoverable routing error.
    Error { message: String },
}

/// Whether `msg`'s header is a session opener — the classifier `open_receiving` uses, over
/// the header the core parses itself. An unparseable payload opens nothing.
pub(crate) fn opens_session(msg: &IncomingMessage) -> bool {
    use crate::orchestration::receiving_init_plan::{
        ReceivingInitCarrier, ReceivingInitKind, receiving_init_kind,
    };
    let Ok(header) = crate::wire_payload::unpack(&msg.wire_payload) else {
        return false;
    };
    receiving_init_kind(&ReceivingInitCarrier {
        message_number: header.message_number,
        one_time_prekey_id: header.one_time_prekey_id,
        kem_ciphertext_bytes: header.kem_ciphertext.as_ref().map_or(0, |k| k.len() as u32),
        pq_message_epoch: header.pq_message_epoch,
    }) == ReceivingInitKind::Handshake
}

/// A raw incoming message before decryption.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    pub contact_id: String,
    /// Binary WirePayload blob.
    pub wire_payload: Vec<u8>,
    pub message_id: String,
    pub msg_number: u32,
    /// When `true` this is a KEY_SYNC / END_SESSION control frame.
    pub is_control: bool,
    /// Original content_type from the wire envelope (e.g. 12 = CALL_SIGNAL).
    pub content_type: u8,
    /// The sender certificate this message was sealed with, unchecked. What lets it open a
    /// session: the key the session is opened with is the one it names. Checked where it is used,
    /// in `Orchestrator::open_receiving`, against the server keys held then — a message that
    /// arrived before the platform had a key is not spoiled by the order of events.
    pub sender_certificate: Option<crate::crypto::sealed_sender::SenderCertificate>,
}

// ── MessageRouter ─────────────────────────────────────────────────────────────

pub struct MessageRouter {
    /// Per-contact queues for messages that arrived before session init.
    pending_queues: HashMap<String, VecDeque<IncomingMessage>>,
    max_pending_per_user: usize,
    /// Messages awaiting a platform DB ACK-check response.
    /// Key = message_id, Value = the buffered IncomingMessage.
    pending_ack_checks: HashMap<String, IncomingMessage>,
    /// When each queued message arrived, by id — what `handshake_arrived_within` reads. Beside the
    /// queue rather than in `IncomingMessage`, which is built in a hundred places that have no
    /// clock; pruned to what is still queued whenever the queue shrinks.
    arrived_at: HashMap<String, u64>,
    clock: std::sync::Arc<dyn crate::orchestration::clock::Clock>,
}

/// How recently a queued handshake must have arrived to count as the peer opening a session *now*.
///
/// A queued handshake has no upper age — it waits until a session opens or the queue is dropped —
/// so "we hold a handshake" and "their init is in flight" are different statements. Once a bundle
/// is in hand a receiving init completes in hundredths of a second and the fetch in front of it
/// takes about one; twenty seconds bounds the case where the handshake cannot be opened at all.
/// That case deadlocked 2026-09-04 18:08, when an unopenable handshake answered "in flight"
/// forever and the initiation plan yielded to a peer that was not opening anything.
pub const PEER_INIT_FRESH_MS: u64 = 20_000;

impl MessageRouter {
    pub fn new() -> Self {
        Self::with_clock(crate::orchestration::clock::system_clock())
    }

    pub fn with_clock(clock: std::sync::Arc<dyn crate::orchestration::clock::Clock>) -> Self {
        Self {
            pending_queues: HashMap::new(),
            max_pending_per_user: MAX_PENDING_PER_USER,
            pending_ack_checks: HashMap::new(),
            arrived_at: HashMap::new(),
            clock,
        }
    }

    /// Forget arrival times of messages no longer queued.
    fn prune_arrivals(&mut self) {
        let queued: std::collections::HashSet<&str> = self
            .pending_queues
            .values()
            .flatten()
            .map(|m| m.message_id.as_str())
            .collect();
        self.arrived_at.retain(|id, _| queued.contains(id.as_str()));
    }

    /// Whether any of `devices` has a session-opening message queued that arrived within
    /// `window_ms` — the peer's own init reaching us right now. Asked by the initiation plan, which
    /// yields to it rather than crossing it with ours.
    pub fn handshake_arrived_within(&self, devices: &[String], window_ms: u64) -> bool {
        let now = self.clock.now_ms();
        devices.iter().any(|device| {
            self.pending_queues.get(device).is_some_and(|queue| {
                queue.iter().any(|m| {
                    opens_session(m)
                        && self
                            .arrived_at
                            .get(&m.message_id)
                            .is_some_and(|at| now.saturating_sub(*at) <= window_ms)
                })
            })
        })
    }

    // ── Primary entry point ───────────────────────────────────────────────────

    /// Route one incoming message through the full decision pipeline.
    ///
    /// Returns a `RoutingDecision` plus any `Action`s that need executing.
    pub fn route_message(
        &mut self,
        lifecycle: &mut SessionLifecycleManager,
        msg: &IncomingMessage,
    ) -> RoutingDecision {
        // Control messages (END_SESSION) bypass ACK deduplication entirely.
        // They are synthetic — generated with a unique-per-invocation ID — so
        // they will always be cache-miss in post_restart_mode, which would cause
        // `archive_session()` to never be called and leave the Rust in-memory
        // session alive, recreating a desync loop on the next incoming message.
        if msg.is_control {
            return self.route_after_ack_check(lifecycle, msg);
        }

        // ── 1. ACK deduplication ──────────────────────────────────────────────
        use crate::orchestration::ack_store::AckCheckResult;
        match lifecycle.ack_store.is_processed(&msg.message_id) {
            AckCheckResult::InCache => {
                return RoutingDecision::Duplicate {
                    message_id: msg.message_id.clone(),
                };
            }
            AckCheckResult::NeedDbCheck => {
                // L1 cache miss after restart — buffer and ask platform to check L2 (DB).
                self.pending_ack_checks
                    .insert(msg.message_id.clone(), msg.clone());
                return RoutingDecision::PendingAckCheck {
                    message_id: msg.message_id.clone(),
                };
            }
            AckCheckResult::NotProcessed => {}
        }

        // Steps 2-4 shared with `resume_after_ack_check`.
        self.route_after_ack_check(lifecycle, msg)
    }

    // ── Drain pending queue after session init ────────────────────────────────

    /// Process all queued messages for `contact_id` now that a session exists.
    ///
    /// Returns one `RoutingDecision` per queued message.
    /// Returns one `RoutingDecision` per queued message, stopping early on
    /// the first error decision (EndSessionNeeded) to
    /// avoid cascading 50+ failures from a single broken session.
    pub fn drain_pending(
        &mut self,
        contact_id: &str,
        lifecycle: &mut SessionLifecycleManager,
    ) -> Vec<RoutingDecision> {
        let queued: Vec<IncomingMessage> = self
            .pending_queues
            .remove(contact_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default();

        let mut results = Vec::with_capacity(queued.len());
        let mut remaining_start = queued.len(); // index after which messages should be re-queued
        for (i, msg) in queued.iter().enumerate() {
            let decision = self.route_message(lifecycle, msg);
            let is_error = matches!(&decision, RoutingDecision::EndSessionNeeded { .. });
            results.push(decision);
            if is_error {
                remaining_start = i + 1;
                break;
            }
        }
        // Re-queue any messages that were not processed due to early exit.
        if remaining_start < queued.len() {
            let queue = self
                .pending_queues
                .entry(contact_id.to_string())
                .or_default();
            for msg in queued.into_iter().skip(remaining_start) {
                queue.push_front(msg);
            }
        }
        self.prune_arrivals();
        results
    }

    /// Number of queued messages for `contact_id`.
    pub fn pending_count(&self, contact_id: &str) -> usize {
        self.pending_queues.get(contact_id).map_or(0, |q| q.len())
    }

    /// The messages waiting for a session with `contact_id`, oldest first.
    pub fn pending_messages(&self, contact_id: &str) -> Vec<IncomingMessage> {
        self.pending_queues
            .get(contact_id)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Take one message out of `contact_id`'s queue by id.
    pub fn remove_pending(&mut self, contact_id: &str, message_id: &str) {
        if let Some(queue) = self.pending_queues.get_mut(contact_id) {
            queue.retain(|m| m.message_id != message_id);
            if queue.is_empty() {
                self.pending_queues.remove(contact_id);
            }
        }
        self.prune_arrivals();
    }

    /// Take `contact_id`'s whole queue.
    pub fn take_pending(&mut self, contact_id: &str) -> Vec<IncomingMessage> {
        let taken = self
            .pending_queues
            .remove(contact_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default();
        self.prune_arrivals();
        taken
    }

    /// All contact IDs that currently have at least one queued message.
    pub fn contacts_with_pending(&self) -> Vec<String> {
        self.pending_queues
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Remove all volatile routing state for a locally forgotten contact.
    ///
    /// This is not a protocol END_SESSION. It is the local "delete/re-add"
    /// boundary: old queued deliveries for the contact must not force the next
    /// add to take the RESPONDER path.
    pub fn forget_contact(&mut self, contact_id: &str) {
        self.pending_queues.remove(contact_id);
        self.prune_arrivals();
        self.pending_ack_checks
            .retain(|_, msg| msg.contact_id != contact_id);
    }

    /// Handle the platform's response to `Action::CheckAckInDb`.
    ///
    /// - `is_processed = true`  → duplicate; returns `RoutingDecision::Duplicate`.
    /// - `is_processed = false` → re-routes the buffered message, skipping the ACK check.
    pub fn resume_after_ack_check(
        &mut self,
        message_id: &str,
        is_processed: bool,
        lifecycle: &mut SessionLifecycleManager,
    ) -> RoutingDecision {
        let Some(buffered_msg) = self.pending_ack_checks.remove(message_id) else {
            return RoutingDecision::Error {
                message: format!(
                    "No buffered message for AckDbResult message_id={}",
                    message_id
                ),
            };
        };

        if is_processed {
            return RoutingDecision::Duplicate {
                message_id: message_id.to_string(),
            };
        }

        // DB confirmed not a duplicate — route from step 2 (skip ACK check).
        self.route_after_ack_check(lifecycle, &buffered_msg)
    }

    /// Route steps 2-4 (post-ACK-check). Called by both `route_message` (for
    /// `NotProcessed` fast path) and `resume_after_ack_check` (after DB confirms absent).
    fn route_after_ack_check(
        &mut self,
        lifecycle: &mut SessionLifecycleManager,
        msg: &IncomingMessage,
    ) -> RoutingDecision {
        // ── 2. END_SESSION control message ────────────────────────────────────
        if msg.is_control {
            let actions = lifecycle.archive_session(&msg.contact_id);
            return RoutingDecision::EndSessionReceived {
                contact_id: msg.contact_id.clone(),
                actions,
            };
        }

        // ── 3. A handshake with nothing to open it on ────────────────────────
        let opener = opens_session(msg);
        if opener && !lifecycle.has_active_session(&msg.contact_id) {
            return self.enqueue_or_reject(lifecycle, msg);
        }
        if !lifecycle.has_active_session(&msg.contact_id)
            && lifecycle.has_archive(&msg.contact_id)
            && lifecycle.restore_latest_archive(&msg.contact_id).is_err()
        {
            tracing::warn!(
                target: "crypto::router",
                contact_id = %msg.contact_id,
                "archived session did not restore"
            );
        }

        // ── 4. Decrypt on any state held ──────────────────────────────────────
        match lifecycle.decrypt_wire_payload(&msg.contact_id, &msg.wire_payload) {
            Ok(result) => {
                let mut actions = lifecycle.ack_store.mark_processed(&msg.message_id);
                actions.extend(result.actions);
                RoutingDecision::Decrypted {
                    contact_id: msg.contact_id.clone(),
                    message_id: msg.message_id.clone(),
                    plaintext: result.plaintext,
                    content_type: msg.content_type,
                    actions,
                }
            }
            Err(e) if e.starts_with(MESSAGE_KEY_CONSUMED) => {
                // Already decrypted — by this path, or as the carrier a receiving open opened the
                // session from, which never passes the ACK store. A duplicate, not a desync.
                // Recorded in the in-memory ACK cache so the next copy stops at step 1.
                tracing::info!(
                    target: "crypto::router",
                    contact_id = %msg.contact_id,
                    message_id = %msg.message_id,
                    msg_number = msg.msg_number,
                    "decrypt found the key already consumed — duplicate, session kept"
                );
                let _ = lifecycle.ack_store.mark_processed(&msg.message_id);
                RoutingDecision::Duplicate {
                    message_id: msg.message_id.clone(),
                }
            }
            // No state we hold is the one it was written on, and it says how to build that one:
            // the peer opened a new session. It waits for the open like any first message, and
            // the state it opens becomes current, the old one previous.
            Err(_) if opener => self.enqueue_or_reject(lifecycle, msg),
            Err(e) => RoutingDecision::EndSessionNeeded {
                contact_id: msg.contact_id.clone(),
                reason: e,
            },
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn enqueue_or_reject(
        &mut self,
        _lifecycle: &mut SessionLifecycleManager,
        msg: &IncomingMessage,
    ) -> RoutingDecision {
        let queue = self
            .pending_queues
            .entry(msg.contact_id.clone())
            .or_default();

        // A queued message is not acknowledged, so the server redelivers it while it waits; each
        // copy must not become another carrier to try.
        if queue.iter().any(|q| q.message_id == msg.message_id) {
            return RoutingDecision::NeedSessionInit {
                contact_id: msg.contact_id.clone(),
                queued_count: queue.len(),
            };
        }

        if queue.len() >= self.max_pending_per_user {
            return RoutingDecision::QueueFull {
                contact_id: msg.contact_id.clone(),
            };
        }

        queue.push_back(msg.clone());
        let queued_count = queue.len();
        self.arrived_at
            .insert(msg.message_id.clone(), self.clock.now_ms());

        RoutingDecision::NeedSessionInit {
            contact_id: msg.contact_id.clone(),
            queued_count,
        }
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_api::ClassicClient;
    use crate::crypto::suites::classic::ClassicSuiteProvider;
    use crate::orchestration::session_lifecycle::SessionLifecycleManager;

    fn make_lifecycle(user_id: &str) -> SessionLifecycleManager {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        SessionLifecycleManager::new(client, user_id.to_string())
    }

    /// A message whose header carries the initiator's handshake (a KEM ciphertext) — one that can
    /// open a session. The body is noise: routing decides on the header alone.
    fn msg(contact_id: &str, msg_id: &str, msg_num: u32) -> IncomingMessage {
        let wire_payload = crate::wire_payload::pack(
            &[3; 32],
            msg_num,
            0,
            0,
            0,
            1,
            Some(&[7; 1568]),
            &[9; 40],
            0,
            None,
        )
        .unwrap();
        IncomingMessage {
            sender_certificate: None,
            contact_id: contact_id.to_string(),
            wire_payload,
            message_id: msg_id.to_string(),
            msg_number: msg_num,
            is_control: false,
            content_type: 0,
        }
    }

    #[test]
    fn test_no_session_queues_message() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");
        let m = msg("bob", "m1", 0);
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(matches!(
            decision,
            RoutingDecision::NeedSessionInit {
                queued_count: 1,
                ..
            }
        ));
        assert_eq!(router.pending_count("bob"), 1);
    }

    #[test]
    fn forget_contact_clears_pending_queue_for_that_contact_only() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        router.route_message(&mut lifecycle, &msg("bob", "bob-1", 0));
        router.route_message(&mut lifecycle, &msg("carol", "carol-1", 0));

        router.forget_contact("bob");

        assert_eq!(router.pending_count("bob"), 0);
        assert_eq!(router.pending_count("carol"), 1);
    }

    #[test]
    fn forget_contact_clears_pending_ack_checks_for_that_contact_only() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");
        lifecycle.ack_store.restore_cache(vec![]);

        router.route_message(&mut lifecycle, &msg("bob", "bob-ack", 0));
        router.route_message(&mut lifecycle, &msg("carol", "carol-ack", 0));

        router.forget_contact("bob");

        assert!(
            !router.pending_ack_checks.contains_key("bob-ack"),
            "forgotten contact must not leave a buffered DB-ack retry"
        );
        assert!(
            router.pending_ack_checks.contains_key("carol-ack"),
            "forgetting one contact must not drop another contact's buffered message"
        );
    }

    #[test]
    fn test_queue_full_backpressure() {
        let mut router = MessageRouter::new();
        router.max_pending_per_user = 2;
        let mut lifecycle = make_lifecycle("alice");

        router.route_message(&mut lifecycle, &msg("bob", "m1", 0));
        router.route_message(&mut lifecycle, &msg("bob", "m2", 1));
        let decision = router.route_message(&mut lifecycle, &msg("bob", "m3", 2));
        assert!(matches!(decision, RoutingDecision::QueueFull { .. }));
        assert_eq!(router.pending_count("bob"), 2); // still 2
    }

    #[test]
    fn test_duplicate_detection_via_cache() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        // Mark a message as already processed.
        lifecycle.ack_store.mark_processed("dup-msg");

        let m = IncomingMessage {
            sender_certificate: None,
            contact_id: "bob".to_string(),
            wire_payload: vec![],
            message_id: "dup-msg".to_string(),
            msg_number: 1,
            is_control: false,
            content_type: 0,
        };
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(matches!(decision, RoutingDecision::Duplicate { .. }));
    }

    #[test]
    fn test_duplicate_detection_survives_restart_via_durable_store() {
        // The orchestrator blob no longer snapshots the ACK cache, so after a
        // restart L1 is empty and `post_restart_mode` is on. A re-delivered
        // message must then be caught by the platform's durable ACK store rather
        // than silently re-processed. This is the path that makes dropping the
        // snapshot safe — assert the full round-trip, not just the store.
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        // Simulate a launch that restored a blob carrying no processed IDs.
        lifecycle.ack_store.restore_cache(vec![]);

        let m = IncomingMessage {
            sender_certificate: None,
            contact_id: "bob".to_string(),
            wire_payload: vec![],
            message_id: "dup-across-restart".to_string(),
            msg_number: 1,
            is_control: false,
            content_type: 0,
        };

        // L1 misses → the platform is asked instead of assuming "new".
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(
            matches!(decision, RoutingDecision::PendingAckCheck { .. }),
            "must defer to the durable ACK store, not treat the message as new"
        );

        // Platform reports it as already processed → duplicate, message dropped.
        let resumed = router.resume_after_ack_check("dup-across-restart", true, &mut lifecycle);
        assert!(matches!(resumed, RoutingDecision::Duplicate { .. }));
    }

    #[test]
    fn test_unseen_message_after_restart_is_routed_normally() {
        // Same path, negative case: the durable store says "not seen", so the
        // message must proceed to routing instead of being dropped.
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");
        lifecycle.ack_store.restore_cache(vec![]);

        let m = IncomingMessage {
            sender_certificate: None,
            contact_id: "bob".to_string(),
            wire_payload: vec![],
            message_id: "fresh-after-restart".to_string(),
            msg_number: 1,
            is_control: false,
            content_type: 0,
        };
        router.route_message(&mut lifecycle, &m);

        let resumed = router.resume_after_ack_check("fresh-after-restart", false, &mut lifecycle);
        assert!(
            !matches!(resumed, RoutingDecision::Duplicate { .. }),
            "a message the durable store has never seen must not be dropped"
        );
    }

    #[test]
    fn test_end_session_control_message() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        let m = IncomingMessage {
            sender_certificate: None,
            contact_id: "bob".to_string(),
            wire_payload: vec![],
            message_id: "ctrl-1".to_string(),
            msg_number: 0,
            is_control: true,
            content_type: 0,
        };
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(matches!(
            decision,
            RoutingDecision::EndSessionReceived { .. }
        ));
    }

    #[test]
    fn test_drain_pending_no_session_returns_decisions() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        // Queue a message without a session.
        router.route_message(&mut lifecycle, &msg("bob", "m1", 0));
        assert_eq!(router.pending_count("bob"), 1);

        // Drain without a session: route_message is called for each queued message.
        // Since there is still no session, the message is re-queued by route_message.
        let decisions = router.drain_pending("bob", &mut lifecycle);
        assert_eq!(decisions.len(), 1);
        // Message is re-enqueued because there is still no session.
        assert_eq!(router.pending_count("bob"), 1);
    }

    /// Nothing held and no header to open from: the message was written on a state we do not
    /// have, and only the peer can start a new one. Until 2026-09-27 this was queued to wait for
    /// an open that nothing in the queue could perform, and then dropped.
    ///
    /// Mutation: enqueue on "no session" regardless of the header — this reddens.
    #[test]
    fn a_message_without_a_header_and_no_state_asks_for_a_teardown() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");
        let m = IncomingMessage {
            sender_certificate: None,
            contact_id: "bob".to_string(),
            wire_payload: vec![],
            message_id: "bad-msg".to_string(),
            msg_number: 5,
            is_control: false,
            content_type: 0,
        };
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(matches!(decision, RoutingDecision::EndSessionNeeded { .. }));
        assert_eq!(router.pending_count("bob"), 0);
    }

    /// A header on message 5 opens, like one on message 0 — the first flight repeats it, and a
    /// lost first message must not cost the session.
    #[test]
    fn a_header_past_message_zero_waits_for_the_open() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");
        let decision = router.route_message(&mut lifecycle, &msg("bob", "m5", 5));
        assert!(matches!(decision, RoutingDecision::NeedSessionInit { .. }));
        assert_eq!(router.pending_count("bob"), 1);
    }
}
