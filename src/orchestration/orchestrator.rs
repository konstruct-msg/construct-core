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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::crypto::client_api::ClassicClient;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::orchestration::actions::{Action, IncomingEvent};
use crate::orchestration::clock::{Clock, system_clock};
use crate::orchestration::message_router::{IncomingMessage, MessageRouter, Role, RoutingDecision};
use crate::orchestration::session_lifecycle::SessionLifecycleManager;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum time between successive END_SESSION sends to the same contact (ms).
const END_SESSION_COOLDOWN_MS: u64 = 5_000;

/// Maximum time an init lock may be held before it is considered stale (ms).
/// Prevents a permanent deadlock if FetchPublicKeyBundle is never completed
/// (e.g. the network dropped mid-handshake).
const INIT_LOCK_TTL_MS: u64 = 30_000;

/// Minimum time between prewarm attempts for the same contact (ms).
#[allow(dead_code)]
const PREWARM_COOLDOWN_MS: u64 = 30_000;

// ── Orchestrator ──────────────────────────────────────────────────────────────

pub struct Orchestrator {
    lifecycle: SessionLifecycleManager,
    router: MessageRouter,
    /// Contacts whose session initialisation is currently in progress.
    /// Value is the Unix ms timestamp when the lock was acquired; locks older
    /// than INIT_LOCK_TTL_MS are treated as expired and may be re-acquired.
    init_locks: HashMap<String, u64>,
    /// contactId → Unix ms of last END_SESSION / prewarm (anti-loop cooldown).
    cooldowns: HashMap<String, u64>,
    /// Contacts that have been pre-warmed (lower userId prewarms on first contact).
    #[allow(dead_code)]
    prewarm_done: HashSet<String>,
    /// Contacts whose chat is currently open in the UI. The orchestrator
    /// schedules periodic heartbeat timers for these contacts.
    active_chats: HashSet<String>,
    clock: Arc<dyn Clock>,
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
            init_locks: HashMap::new(),
            cooldowns: HashMap::new(),
            prewarm_done: HashSet::new(),
            active_chats: HashSet::new(),
            clock,
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
            IncomingEvent::SessionLoaded { key, data } => self.handle_session_loaded(key, data),
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
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn my_user_id(&self) -> &str {
        self.lifecycle.my_user_id()
    }

    pub fn has_active_session(&self, contact_id: &str) -> bool {
        self.lifecycle.has_active_session(contact_id)
    }

    pub fn pending_message_count(&self, contact_id: &str) -> usize {
        self.router.pending_count(contact_id)
    }

    pub fn ack_is_processed(&self, message_id: &str) -> crate::orchestration::AckCheckResult {
        self.lifecycle.ack_store.is_processed(message_id)
    }

    pub fn ack_mark_processed(&mut self, message_id: &str) -> Vec<crate::orchestration::Action> {
        self.lifecycle.ack_store.mark_processed(message_id)
    }

    pub fn export_state_json(&self) -> Result<String, String> {
        self.lifecycle.export_state_json()
    }

    /// Export the full orchestrator coordination state as a CFE binary blob.
    ///
    /// Captures ACK dedup cache, healing queue, init locks, archive index, and
    /// prekey tracker.  Persist under `"orchestrator_state"` in Keychain.
    pub fn export_orchestrator_state_cfe(&self) -> Result<Vec<u8>, String> {
        // Serialise only the contact IDs (keys) — timestamps are ephemeral.
        let lock_ids: std::collections::HashSet<String> = self.init_locks.keys().cloned().collect();
        self.lifecycle.export_orchestrator_state_cfe(&lock_ids)
    }

    /// Restore the full orchestrator coordination state from a CFE binary blob.
    ///
    /// All in-memory queues and the init_locks set are replaced.
    pub fn import_orchestrator_state_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        let restored_ids = self.lifecycle.import_orchestrator_state_cfe(data)?;
        // Restored locks get a timestamp that puts them near expiry (5 s grace).
        // This prevents a crash-survivor lock from blocking init indefinitely.
        let near_expiry_ts = self.clock.now_ms().saturating_sub(INIT_LOCK_TTL_MS - 5_000);
        self.init_locks = restored_ids
            .into_iter()
            .map(|id| (id, near_expiry_ts))
            .collect();
        Ok(())
    }

    // ── Session-crypto delegates ──────────────────────────────────────────────

    pub fn get_all_session_contact_ids(&self) -> Vec<String> {
        self.lifecycle.client.active_contacts()
    }

    pub fn init_session_with_bundle(
        &mut self,
        contact_id: &str,
        recipient_bundle: &[u8],
    ) -> Result<String, String> {
        use crate::crypto::SuiteID;
        use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

        #[derive(serde::Deserialize)]
        struct KeyBundle {
            identity_public: Vec<u8>,
            signed_prekey_public: Vec<u8>,
            signature: Vec<u8>,
            verifying_key: Vec<u8>,
            suite_id: u16,
            #[serde(default)]
            one_time_prekey_public: Option<Vec<u8>>,
            #[serde(default)]
            one_time_prekey_id: Option<u32>,
            #[serde(default)]
            spk_uploaded_at: Option<u64>,
            #[serde(default)]
            spk_rotation_epoch: Option<u32>,
            #[serde(default)]
            kyber_spk_uploaded_at: Option<u64>,
            #[serde(default)]
            kyber_spk_rotation_epoch: Option<u32>,
            // PQXDH: recipient's ML-KEM-768 public keys
            #[serde(default)]
            kyber_pre_key_public: Option<Vec<u8>>,
            #[serde(default)]
            kyber_one_time_prekey_public: Option<Vec<u8>>,
            #[serde(default)]
            kyber_one_time_prekey_id: Option<u32>,
        }

        let key_bundle: KeyBundle = serde_json::from_slice(recipient_bundle)
            .map_err(|_| "invalid key bundle JSON".to_string())?;

        let public_bundle = X3DHPublicKeyBundle {
            identity_public: key_bundle.identity_public.clone(),
            signed_prekey_public: key_bundle.signed_prekey_public.clone(),
            signature: key_bundle.signature.clone(),
            verifying_key: key_bundle.verifying_key.clone(),
            suite_id: SuiteID::new(key_bundle.suite_id)
                .map_err(|_| "invalid suite_id".to_string())?,
            one_time_prekey_public: key_bundle.one_time_prekey_public.clone(),
            one_time_prekey_id: key_bundle.one_time_prekey_id,
            spk_uploaded_at: key_bundle.spk_uploaded_at.unwrap_or(0),
            spk_rotation_epoch: key_bundle.spk_rotation_epoch.unwrap_or(0),
            kyber_spk_uploaded_at: key_bundle.kyber_spk_uploaded_at.unwrap_or(0),
            kyber_spk_rotation_epoch: key_bundle.kyber_spk_rotation_epoch.unwrap_or(0),
        };

        let remote_identity =
            ClassicSuiteProvider::kem_public_key_from_bytes(key_bundle.identity_public.clone());
        let one_time_prekey_id = key_bundle.one_time_prekey_id.unwrap_or(0);

        tracing::debug!(
            target: "crypto::orchestrator",
            contact_id = %contact_id,
            one_time_prekey_id = one_time_prekey_id,
            has_otpk_public = key_bundle.one_time_prekey_public.is_some(),
            "init_session_with_bundle: storing pending OTPK id"
        );

        self.lifecycle
            .client
            .init_session(
                contact_id,
                &public_bundle,
                &remote_identity,
                one_time_prekey_id,
            )
            .map_err(|e| e.to_string())?;

        // PQXDH: encapsulate to recipient's Kyber public key and defer SS application.
        // Prefer one-time pre-key (consumed once) over the signed pre-key.
        // `recipient_otpk_id` is 0 when Kyber SPK is used (no OTPK available).
        let (kyber_public, recipient_otpk_id) =
            if let Some(pk) = key_bundle.kyber_one_time_prekey_public {
                (Some(pk), key_bundle.kyber_one_time_prekey_id.unwrap_or(0))
            } else {
                (key_bundle.kyber_pre_key_public, 0)
            };
        if let Some(kem_pk) = kyber_public {
            if let Ok((_result, _persist_actions)) = self
                .lifecycle
                .pq_manager
                .encapsulate_and_defer(contact_id, &kem_pk, recipient_otpk_id)
            {
                tracing::debug!(
                    target: "crypto::orchestrator",
                    contact_id = %contact_id,
                    kyber_otpk_id = _result.otpk_id,
                    "init_session_with_bundle: PQXDH encapsulated, ciphertext deferred"
                );
                // persist_actions (SaveSessionToSecureStore for pq_deferred_<id>) are
                // handled by the caller via saveOrchestratorStateCFE on the Swift side.
            }
        }

        Ok(contact_id.to_string())
    }

    pub fn init_receiving_session_with_msg(
        &mut self,
        contact_id: &str,
        recipient_bundle: &[u8],
        first_message: &[u8],
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

        #[derive(serde::Deserialize)]
        struct FirstMsg {
            ephemeral_public_key: Vec<u8>,
            message_number: u32,
            content: Vec<u8>, // raw sealed box bytes (JSON array of numbers)
            #[serde(default)]
            one_time_prekey_id: u32,
        }

        let key_bundle: KeyBundle = serde_json::from_slice(recipient_bundle)
            .map_err(|_| "invalid key bundle JSON".to_string())?;

        let first_msg: FirstMsg = serde_json::from_slice(first_message)
            .map_err(|_| "invalid first message JSON".to_string())?;

        let sealed_box = first_msg.content;

        if sealed_box.len() < 12 {
            return Err("sealed_box too short".to_string());
        }
        let nonce = sealed_box[..12].to_vec();
        let ciphertext = sealed_box[12..].to_vec();

        let dh_public_key: [u8; 32] = first_msg
            .ephemeral_public_key
            .clone()
            .try_into()
            .map_err(|_| "ephemeral_public_key must be 32 bytes".to_string())?;

        let encrypted_first_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number: first_msg.message_number,
            ciphertext,
            nonce,
            previous_chain_length: 0,
            suite_id: key_bundle.suite_id,
        };

        // Verify the initiator's signed prekey signature before doing any crypto.
        // This prevents a malicious or corrupted bundle from being used to establish
        // a session — the initiator must prove they hold the signing key that signed
        // their SPK.  We do this here rather than delegating to init_receiving_session()
        // because that function also checks contact_id == derive_device_id(identity_key),
        // which is only valid in the device-based test model; in production contact_id
        // is a user UUID and the check would always fail.
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
            ClassicSuiteProvider::kem_public_key_from_bytes(first_msg.ephemeral_public_key.clone());

        let (_session_id, plaintext) = self
            .lifecycle
            .client
            .init_receiving_session_with_ephemeral(
                contact_id,
                &remote_identity,
                &remote_ephemeral,
                &encrypted_first_message,
                first_msg.one_time_prekey_id,
            )
            .map_err(|e| e.to_string())?;

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
            suite_id: key_bundle.suite_id,
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

    pub fn export_session_json_for(&self, contact_id: &str) -> Result<String, String> {
        self.lifecycle.export_session_json_for(contact_id)
    }

    pub fn import_session_json(&mut self, contact_id: &str, json: &str) -> Result<String, String> {
        self.lifecycle.import_session_json(contact_id, json)
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

    pub fn export_private_keys_json_str(&self) -> Result<String, String> {
        use base64::Engine as _;
        let km = self.lifecycle.client.key_manager();
        let identity_secret = km.identity_secret_key().map_err(|e| e.to_string())?;
        let signing_secret = km.signing_secret_key().map_err(|e| e.to_string())?;
        let prekey = km.current_signed_prekey().map_err(|e| e.to_string())?;

        let identity_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(identity_secret).to_vec();
        let signing_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(signing_secret).to_vec();
        let prekey_secret_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(&prekey.key_pair.0).to_vec();

        use crate::crypto::provider::CryptoProvider as _;
        use crate::crypto::suites::classic::ClassicSuiteProvider;
        use base64::engine::general_purpose::STANDARD;

        // Re-derive public keys for integrity verification on next load.
        let identity_pub_check =
            ClassicSuiteProvider::from_private_key_to_public_key(&identity_bytes)
                .ok()
                .map(|b| STANDARD.encode(&b));
        let verifying_key_check =
            ClassicSuiteProvider::from_signature_private_to_public(&signing_bytes)
                .ok()
                .map(|b| STANDARD.encode(&b));
        let spk_pub_check =
            ClassicSuiteProvider::from_private_key_to_public_key(&prekey_secret_bytes)
                .ok()
                .map(|b| STANDARD.encode(&b));

        let mut json = serde_json::json!({
            "identity_secret": STANDARD.encode(&identity_bytes),
            "signing_secret": STANDARD.encode(&signing_bytes),
            "signed_prekey_secret": STANDARD.encode(&prekey_secret_bytes),
            "prekey_signature": STANDARD.encode(&prekey.signature),
            "suite_id": "1"
        });
        if let Some(v) = identity_pub_check {
            json["identity_public_check"] = serde_json::Value::String(v);
        }
        if let Some(v) = verifying_key_check {
            json["verifying_key_check"] = serde_json::Value::String(v);
        }
        if let Some(v) = spk_pub_check {
            json["signed_prekey_public_check"] = serde_json::Value::String(v);
        }
        serde_json::to_string(&json).map_err(|e| e.to_string())
    }

    pub fn export_registration_bundle_json_str(&self) -> Result<String, String> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        let bundle = self
            .lifecycle
            .client
            .key_manager()
            .export_registration_bundle()
            .map_err(|e| e.to_string())?;

        let json = serde_json::json!({
            "identity_public": STANDARD.encode(&bundle.identity_public),
            "signed_prekey_public": STANDARD.encode(&bundle.signed_prekey_public),
            "signature": STANDARD.encode(&bundle.signature),
            "verifying_key": STANDARD.encode(&bundle.verifying_key),
            "suite_id": bundle.suite_id.as_u16().to_string()
        });
        serde_json::to_string(&json).map_err(|e| e.to_string())
    }

    pub fn sign_bundle_bytes(&self, data: &[u8]) -> Result<String, String> {
        use base64::Engine as _;
        let signature = self
            .lifecycle
            .client
            .key_manager()
            .sign(data)
            .map_err(|e| e.to_string())?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&signature))
    }

    /// Suite ID for the active session with `contact_id`. Returns 0 if no session.
    pub fn get_session_suite_id(&self, contact_id: &str) -> u16 {
        self.lifecycle
            .client
            .get_session(contact_id)
            .map(|s| s.messaging_session().to_serializable().suite_id)
            .unwrap_or(0)
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
        use crate::crypto::provider::CryptoProvider as _;
        use crate::crypto::suites::classic::ClassicSuiteProvider;
        use serde_bytes::ByteBuf;

        let km = self.lifecycle.client.key_manager();
        let identity_secret = km.identity_secret_key().map_err(|e| e.to_string())?;
        let signing_secret = km.signing_secret_key().map_err(|e| e.to_string())?;
        let prekey = km.current_signed_prekey().map_err(|e| e.to_string())?;

        let ik_priv: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(identity_secret).to_vec();
        let sk_priv: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(signing_secret).to_vec();
        let spk_priv: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(&prekey.key_pair.0).to_vec();
        let spk_sig: Vec<u8> = prekey.signature.clone();

        let ik_pub = ClassicSuiteProvider::from_private_key_to_public_key(&ik_priv)
            .map_err(|e| e.to_string())?;
        let vk_pub = ClassicSuiteProvider::from_signature_private_to_public(&sk_priv)
            .map_err(|e| e.to_string())?;
        let spk_pub = ClassicSuiteProvider::from_private_key_to_public_key(&spk_priv)
            .map_err(|e| e.to_string())?;

        let spk_id = km.current_signed_prekey_id().unwrap_or(0);

        let payload = crate::cfe::CfePrivateKeysV1 {
            suite_id: 1,
            ik_priv: ByteBuf::from(ik_priv),
            sk_priv: ByteBuf::from(sk_priv),
            spk_priv: ByteBuf::from(spk_priv),
            spk_sig: ByteBuf::from(spk_sig),
            spk_id,
            ik_pub: ByteBuf::from(ik_pub),
            vk_pub: ByteBuf::from(vk_pub),
            spk_pub: ByteBuf::from(spk_pub),
        };

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
                priv_key: ByteBuf::from(priv_key),
                pub_key: ByteBuf::from(pub_key),
            })
            .collect();

        let next_id = self.lifecycle.client.key_manager().next_otpk_id();
        let payload = crate::cfe::CfeOtpkBundleV1 { records, next_id };

        crate::cfe::encode(crate::cfe::CfeMessageType::OtpkBundle, &payload)
            .map_err(|e| e.to_string())
    }

    pub fn import_otpks_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        let bundle = match crate::cfe::decode_as::<crate::cfe::CfeOtpkBundleV1>(
            data,
            crate::cfe::CfeMessageType::OtpkBundle,
        ) {
            Ok(b) => b,
            Err(crate::cfe::CfeError::LegacyJson) => {
                let s = std::str::from_utf8(data).map_err(|e| e.to_string())?;
                crate::cfe::migrate_otpk_bundle_json_str(s).map_err(|e| e.to_string())?
            }
            Err(e) => return Err(e.to_string()),
        };

        let keys: Vec<(u32, Vec<u8>, Vec<u8>)> = bundle
            .records
            .iter()
            .map(|r| (r.id, r.priv_key.to_vec(), r.pub_key.to_vec()))
            .collect();

        self.lifecycle.client.import_one_time_prekeys(keys);
        self.lifecycle
            .client
            .key_manager_mut()
            .set_next_otpk_id(bundle.next_id);
        Ok(())
    }

    /// Export a session as a CFE binary blob (MessagePack + CRC32 header).
    /// Falls back gracefully from JSON if needed by the caller.
    /// Export a session as a CFE binary blob (MessagePack, no JSON intermediate).
    pub fn export_session_cfe(&self, contact_id: &str) -> Result<Vec<u8>, String> {
        self.lifecycle.export_session_bytes_for(contact_id)
    }

    /// Import a session from a CFE binary blob.
    ///
    /// Tries formats in order:
    /// 1. `CfeSessionStateV1` — current binary format (new sessions)
    /// 2. `CfeSessionJsonWrapperV1` — old format (JSON inside CFE, pre-migration sessions)
    /// 3. Raw JSON bytes — legacy fallback (very old sessions)
    pub fn import_session_cfe(&mut self, contact_id: &str, data: &[u8]) -> Result<String, String> {
        use crate::cfe::{CfeError, CfeMessageType, decode_as};
        use crate::crypto::messaging::double_ratchet::{DoubleRatchetSession, SerializableSession};

        let serializable: SerializableSession =
            match decode_as::<crate::cfe::CfeSessionStateV1>(data, CfeMessageType::SessionState) {
                Ok(cfe_state) => SerializableSession::from_cfe_v1(cfe_state)
                    .map_err(|e| format!("from_cfe_v1: {}", e))?,
                Err(CfeError::DeserializeFailed(_)) => {
                    // Valid CFE but wrong schema — try old JSON-wrapper format.
                    match decode_as::<crate::cfe::CfeSessionJsonWrapperV1>(
                        data,
                        CfeMessageType::SessionState,
                    ) {
                        Ok(wrapper) => {
                            let json_str = std::str::from_utf8(&wrapper.json_bytes)
                                .map_err(|e| e.to_string())?;
                            serde_json::from_str(json_str)
                                .map_err(|e| format!("json wrapper fallback: {}", e))?
                        }
                        Err(CfeError::LegacyJson) => {
                            let s = std::str::from_utf8(data).map_err(|e| e.to_string())?;
                            serde_json::from_str(s)
                                .map_err(|e| format!("raw json fallback: {}", e))?
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
                Err(CfeError::LegacyJson) => {
                    let s = std::str::from_utf8(data).map_err(|e| e.to_string())?;
                    serde_json::from_str(s).map_err(|e| format!("raw json fallback: {}", e))?
                }
                Err(e) => return Err(e.to_string()),
            };

        let ratchet = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(serializable)
            .map_err(|e| format!("from_serializable: {}", e))?;
        let session_id = self.lifecycle.client.import_session(contact_id, ratchet);
        Ok(session_id)
    }
    pub fn rotate_spk(&mut self) -> Result<(u32, String, String), String> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
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

        Ok((
            key_id,
            STANDARD.encode(&bundle.signed_prekey_public),
            STANDARD.encode(&bundle.signature),
        ))
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
    /// Returns a `SaveSessionToSecureStore` action that the platform **must**
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
    /// Persist the returned bytes under `"kyber_session_state"` in the platform
    /// secure store after any encapsulate / decapsulate / consume operation.
    pub fn export_kyber_session_state_cfe(&self) -> Result<Vec<u8>, String> {
        self.lifecycle.export_kyber_session_state_cfe()
    }

    /// Restore the `PQContributionManager` state from a previously exported CFE blob.
    pub fn import_kyber_session_state_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        self.lifecycle.import_kyber_session_state_cfe(data)
    }

    /// Returns `(ephemeral_public_key, message_number, content_b64, one_time_prekey_id)`.
    pub fn encrypt_message_for(
        &mut self,
        contact_id: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, u32, Vec<u8>, u32), String> {
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
        };

        self.lifecycle
            .client
            .decrypt_message(contact_id, &encrypted_message)
            .map_err(|e| e.to_string())
    }

    pub fn decrypt_message_for(
        &mut self,
        contact_id: &str,
        ephemeral_public_key: Vec<u8>,
        message_number: u32,
        content: &[u8],
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
            suite_id: crate::config::Config::global().classic_suite_id,
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
            RoutingDecision::SessionHealNeeded { .. }
                | RoutingDecision::NeedSessionInit { .. }
                | RoutingDecision::EndSessionNeeded { .. }
        );
        actions.extend(self.decision_to_actions(decision, &from));
        // Persist coordination state (healing queue, ACK cache, init_locks) for
        // paths that don't already trigger a session-keyed save on the Swift side.
        if needs_state_save {
            if let Some(save_action) = self.orchestrator_state_action() {
                actions.push(save_action);
            }
        }
        actions
    }

    /// Encrypt a regular outgoing message and pack it into a WirePayload ready to send.
    ///
    /// Called when Swift feeds `OutgoingMessage` — single source of truth for all outgoing
    /// E2EE text encryption. Emits `SaveSessionToSecureStore` to persist updated DR state.
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
            if let Some(shared_secret) = ss {
                if let Err(e) = self
                    .lifecycle
                    .client
                    .apply_pq_contribution_to_session(&contact_id, &shared_secret)
                {
                    return vec![Action::NotifyError {
                        code: "OUTGOING_MESSAGE_PQXDH_APPLY_FAILED".to_string(),
                        message: e.to_string(),
                    }];
                }
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
        ) {
            Ok(p) => p,
            Err(e) => {
                return vec![Action::NotifyError {
                    code: "OUTGOING_MESSAGE_PACK_FAILED".to_string(),
                    message: e.to_string(),
                }];
            }
        };

        let mut actions = vec![Action::SendEncryptedMessage {
            to: contact_id.clone(),
            payload,
            message_id,
            content_type,
        }];
        if let Ok(session_json) = self.lifecycle.export_session_json_for(&contact_id) {
            actions.push(Action::SaveSessionToSecureStore {
                key: format!("session_{}", contact_id),
                data: session_json.into_bytes(),
            });
        }
        actions
    }

    /// Encrypt a call signal proto blob and pack it into a WirePayload ready to send.
    ///
    /// Called when Swift feeds `OutgoingCallSignal` — no base64, no JSON, no Strings.
    /// Also emits `SaveSessionToSecureStore` to persist the updated DR state.
    fn handle_outgoing_call_signal(
        &mut self,
        contact_id: String,
        message_id: String,
        proto_bytes: Vec<u8>,
    ) -> Vec<Action> {
        match self.encrypt_bytes_for(&contact_id, &proto_bytes) {
            Ok(payload) => {
                let mut actions = vec![Action::SendEncryptedMessage {
                    to: contact_id.clone(),
                    payload,
                    message_id,
                    content_type: 12,
                }];
                // Persist updated DR session state after encrypt.
                if let Ok(session_json) = self.lifecycle.export_session_json_for(&contact_id) {
                    actions.push(Action::SaveSessionToSecureStore {
                        key: format!("session_{}", contact_id),
                        data: session_json.into_bytes(),
                    });
                }
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
        self.init_locks.remove(&contact_id);

        // Import the newly created session from CFE binary (or JSON legacy fallback).
        if !session_data.is_empty() {
            // Try binary first, fall back to legacy JSON interpretation.
            if self
                .lifecycle
                .import_session_bytes(&contact_id, &session_data)
                .is_err()
            {
                // Treat bytes as UTF-8 JSON for backward compat.
                if let Ok(json) = std::str::from_utf8(&session_data) {
                    let _ = self.lifecycle.import_session_json(&contact_id, json);
                }
            }
        }

        // Save the session to secure store.
        let mut actions = vec![];
        if let Ok(bytes) = self.lifecycle.export_session_bytes_for(&contact_id) {
            actions.push(Action::SaveSessionToSecureStore {
                key: crate::orchestration::session_lifecycle::session_key(&contact_id),
                data: bytes,
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

    fn handle_session_loaded(&mut self, key: String, data: Option<Vec<u8>>) -> Vec<Action> {
        // key format: "session_<contact_id>" or "archive_<contact_id>"
        let contact_id = key
            .strip_prefix("session_")
            .or_else(|| key.strip_prefix("archive_"))
            .unwrap_or(&key)
            .to_string();

        if let Some(bytes) = data {
            if !bytes.is_empty() {
                self.lifecycle.load_archive_bytes(&contact_id, bytes);
            }
        }
        vec![]
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
                actions
            }
            _ if timer_id.starts_with("cooldown_expired:") => {
                // Cooldown expired — schedule a GC so stale locks/cooldowns are evicted.
                // The server will re-deliver any unACKed messages; this just ensures
                // the orchestrator is ready to process them.
                vec![Action::ScheduleTimer {
                    timer_id: "gc_sweep".to_string(),
                    delay_ms: 100,
                }]
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
            } => {
                // Decrypt failed on heartbeat msgNum=0 — proactively trigger heal.
                if self.on_cooldown(&cid) {
                    return vec![Action::HealSuppressed {
                        contact_id: cid,
                        retry_after_ms: 100,
                    }];
                }
                self.set_cooldown(cid.clone());
                let role_str = match role {
                    Role::Initiator => "Initiator",
                    Role::Responder => "Responder",
                };
                vec![Action::SessionHealNeeded {
                    contact_id: cid,
                    role: role_str.to_string(),
                }]
            }
            other => self.decision_to_actions(other, &contact_id),
        }
    }

    // ── Decision → Actions ────────────────────────────────────────────────────

    fn decision_to_actions(&mut self, decision: RoutingDecision, _contact_id: &str) -> Vec<Action> {
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
                    all.push(Action::NotifyNewMessage {
                        chat_id: cid.clone(),
                        preview: preview(&plaintext),
                    });
                    all.push(Action::MessageDecrypted {
                        contact_id: cid,
                        message_id: mid,
                        plaintext,
                    });
                }
                all
            }
            RoutingDecision::NeedSessionInit {
                contact_id: cid, ..
            } => {
                if self.is_init_locked(&cid) {
                    return vec![];
                }
                self.acquire_init_lock(cid.clone());
                vec![Action::FetchPublicKeyBundle { user_id: cid }]
            }
            RoutingDecision::SessionHealNeeded {
                contact_id: cid,
                role,
            } => {
                if self.on_cooldown(&cid) {
                    // Return HealSuppressed so the platform knows NOT to ACK.
                    // The server will re-deliver after the cooldown clears.
                    let now_ms = self.clock.now_ms();
                    let elapsed =
                        now_ms.saturating_sub(*self.cooldowns.get(&cid).unwrap_or(&now_ms));
                    let remaining = END_SESSION_COOLDOWN_MS.saturating_sub(elapsed) + 100;
                    return vec![
                        Action::HealSuppressed {
                            contact_id: cid.clone(),
                            retry_after_ms: remaining,
                        },
                        Action::ScheduleTimer {
                            timer_id: format!("cooldown_expired:{cid}"),
                            delay_ms: remaining,
                        },
                    ];
                }
                self.set_cooldown(cid.clone());
                let role_str = match role {
                    Role::Initiator => "Initiator",
                    Role::Responder => "Responder",
                };
                vec![Action::SessionHealNeeded {
                    contact_id: cid,
                    role: role_str.to_string(),
                }]
            }
            RoutingDecision::EndSessionNeeded {
                contact_id: cid,
                reason: _,
            } => {
                if self.on_cooldown(&cid) {
                    return vec![];
                }
                self.set_cooldown(cid.clone());
                vec![
                    Action::SendEndSession {
                        contact_id: cid.clone(),
                    },
                    // Notify linked devices so they can proactively heal with this contact.
                    Action::NotifyLinkedDevicesOfSessionReset { contact_id: cid },
                ]
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

    // ── Cooldown helpers ──────────────────────────────────────────────────────

    fn on_cooldown(&self, contact_id: &str) -> bool {
        self.cooldowns.get(contact_id).is_some_and(|&last_ms| {
            self.clock.now_ms().saturating_sub(last_ms) < END_SESSION_COOLDOWN_MS
        })
    }

    fn set_cooldown(&mut self, contact_id: String) {
        self.cooldowns.insert(contact_id, self.clock.now_ms());
    }

    // ── Init-lock helpers ─────────────────────────────────────────────────────

    /// Returns `true` if a live (non-expired) init lock exists for `contact_id`.
    fn is_init_locked(&self, contact_id: &str) -> bool {
        self.init_locks.get(contact_id).is_some_and(|&acquired_at| {
            self.clock.now_ms().saturating_sub(acquired_at) < INIT_LOCK_TTL_MS
        })
    }

    fn acquire_init_lock(&mut self, contact_id: String) {
        self.init_locks.insert(contact_id, self.clock.now_ms());
    }

    // ── Orchestrator state persistence ────────────────────────────────────────

    /// Build a `SaveSessionToSecureStore` action that persists the full
    /// orchestrator coordination state (ACK cache, healing queue, init_locks,
    /// archive index, prekey tracker) to the platform's secure store.
    ///
    /// Must be called after any event that mutates coordination state and does
    /// NOT already trigger a session-keyed save (e.g. SessionHealNeeded,
    /// NeedSessionInit, EndSessionNeeded).  The `Decrypted` path already causes
    /// Swift to call `saveOrchestratorStateCFE()` as a side-effect of the
    /// session save, so it does not need this action.
    fn orchestrator_state_action(&self) -> Option<Action> {
        let lock_ids: std::collections::HashSet<String> = self.init_locks.keys().cloned().collect();
        self.lifecycle
            .export_orchestrator_state_cfe(&lock_ids)
            .ok()
            .map(|cfe| Action::SaveSessionToSecureStore {
                key: "construct.orchestrator_state".to_string(),
                data: cfe,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_api::ClassicClient;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

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

    #[test]
    fn test_message_received_no_session_fetches_bundle() {
        let mut o = make_orchestrator("alice");
        let wire = r#"{"dh_public_key":[0],"message_number":0,"ciphertext":[],"nonce":[],"previous_chain_length":0,"suite_id":1}"#;
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            message_id: "msg-001".to_string(),
            from: "bob".to_string(),
            data: wire.as_bytes().to_vec(),
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
    fn test_message_received_pq_ciphertext_produces_apply_action() {
        let mut o = make_orchestrator("alice");
        let wire = r#"{"dh_public_key":[0],"message_number":0,"ciphertext":[],"nonce":[],"previous_chain_length":0,"suite_id":1}"#;
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            message_id: "msg-002".to_string(),
            from: "bob".to_string(),
            data: wire.as_bytes().to_vec(),
            msg_num: 0,
            kem_ct: vec![1, 2, 3],
            otpk_id: 42,
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

    #[test]
    fn test_session_init_completed_clears_lock() {
        let mut o = make_orchestrator("alice");
        o.acquire_init_lock("bob".to_string());
        let actions = o.handle_event(IncomingEvent::SessionInitCompleted {
            contact_id: "bob".to_string(),
            session_data: vec![], // empty → only clears init lock
        });
        assert!(!o.is_init_locked("bob"));
        // Should include NotifySessionCreated.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::NotifySessionCreated { .. }))
        );
    }

    #[test]
    fn test_cooldown_deduplicates_end_session() {
        let mut o = make_orchestrator("alice");
        o.set_cooldown("bob".to_string());
        assert!(o.on_cooldown("bob"));
    }

    #[test]
    fn test_no_cooldown_initially() {
        let o = make_orchestrator("alice");
        assert!(!o.on_cooldown("bob"));
    }
}
