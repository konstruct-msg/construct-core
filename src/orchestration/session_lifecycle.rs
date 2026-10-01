/// Session Lifecycle Manager — Rust port of Swift `CryptoManager`.
///
/// Owns the `ClassicClient` and orchestrates:
/// - Encrypt / Decrypt
/// - Retiring the current state when the peer could not read it (`retire_current`)
/// - Prekey change detection (reinstall)
/// - Previous session states, tried on decrypt (`decrypt_ratchet_message`)
/// - Integration of AckStore
///
/// All I/O is delegated via `Vec<Action>` returns; this struct is pure state.
use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::client_api::ClassicClient;
use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::orchestration::ack_store::AckStore;
use crate::orchestration::actions::{Action, SecureStoreSlot};
use crate::orchestration::clock::{Clock, system_clock};

// ── Constants ─────────────────────────────────────────────────────────────────

/// How many states a device's record keeps besides the current one.
///
/// A previous state exists for the messages the peer sent before it saw the state that replaced
/// it: both sides opening at once, or a reopen crossing the peer's traffic. That is one or two
/// states in practice; three leaves room for a reopen during a crossing. Signal keeps forty.
/// Each one kept is chain keys kept — see `PREVIOUS_STATE_TTL_SECONDS`.
pub const MAX_PREVIOUS_STATES: usize = 3;

/// How long a replaced state is kept, from the moment it was replaced.
///
/// Long enough for what the peer sent on it before it learned of the replacement to reach us —
/// including a peer that was offline when we reopened and comes back with an outbox — and no
/// longer: until it is dropped, a compromise of this device also exposes whatever is still in
/// flight on it. A week; Signal has no bound but the count.
pub const PREVIOUS_STATE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// The client's session type: one Double Ratchet state with one device.
type HeldSession = crate::crypto::session_api::ClassicSession<ClassicSuiteProvider>;

/// A state a newer one replaced with the same device, kept to decrypt what is still in flight on
/// it (`decisions/sessions-renew-by-sending.md`).
struct PreviousState {
    session: HeldSession,
    /// Unix seconds when it stopped being current.
    retired_at: u64,
    /// Retired because the peer could not read it (`retire_current`). It still decrypts what
    /// arrives on it, and is never made current again: our next message on it would fail the
    /// same way, so the next send opens a new state instead.
    held_back: bool,
}

/// Which state held with a device a ratchet key belongs to, as a sending key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetKeyOwner {
    /// The current state sends with it: what the peer could not read is what we send now.
    Current,
    /// A state already replaced — whatever the peer could not read, we no longer send on it.
    Previous,
    /// No state held. Nothing of ours to retire.
    Unknown,
}

// ── Result types ──────────────────────────────────────────────────────────────

/// Returned by `decrypt_wire_payload`.
#[derive(Debug, Clone)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    /// Actions the platform must execute after successful decryption.
    pub actions: Vec<Action>,
}

// ── SessionLifecycleManager ───────────────────────────────────────────────────

pub struct SessionLifecycleManager {
    pub(crate) client: ClassicClient<ClassicSuiteProvider>,
    pub ack_store: AckStore,
    /// Device → the states its current one replaced, newest first. Part of the device's session
    /// record: saved and loaded with the current state (`export_session_bytes_for`).
    previous: HashMap<String, Vec<PreviousState>>,
    /// contactId → last seen OTPK ID (used to detect reinstall).
    prekey_tracker: HashMap<String, u32>,
    /// Device → SHA-256 of the hybrid identity key it presented the first time a session to it
    /// was opened. The bundle binds that key to the device only by an Ed25519 cross-signature, so
    /// the pin is what a quantum adversary cannot get past — see `pq_prekey_plan`.
    hybrid_identity_pins: std::collections::BTreeMap<String, [u8; 32]>,
    /// Device → SHA-256 of the KEM identity key its first message named the first time it opened
    /// a session to us (decisions/responder-authenticates-initiator-by-kem.md). The responder's
    /// counterpart of `hybrid_identity_pins`: what a quantum adversary holding the device's X25519
    /// key and a forged server certificate still cannot present.
    kem_identity_pins: std::collections::BTreeMap<String, [u8; 32]>,
    my_user_id: String,
    clock: Arc<dyn Clock>,
    /// How late messages arrive, for this process (PQR-4). Diagnostics only.
    reorder_stats: super::ReorderStats,
}

/// The error prefix for a stored session made by a core older than the session envelope
/// (construct-core 0.26). The platform treats the session as absent.
pub const SESSION_PREDATES_ENVELOPE: &str = "SESSION_PREDATES_ENVELOPE";

impl SessionLifecycleManager {
    /// Create a manager from an existing `ClassicClient`.
    ///
    /// `my_user_id` is propagated to `client.local_user_id` so that every
    /// session created by this manager embeds the correct sender/receiver ID
    /// in its Associated Data.  Without this the AD byte layout diverges
    /// between the INITIATOR (encrypt) and RESPONDER (decrypt) sides, causing
    /// every AEAD verification to fail.
    pub fn new(client: ClassicClient<ClassicSuiteProvider>, my_user_id: String) -> Self {
        Self::new_with_clock(client, my_user_id, system_clock())
    }

    pub fn new_with_clock(
        mut client: ClassicClient<ClassicSuiteProvider>,
        my_user_id: String,
        clock: Arc<dyn Clock>,
    ) -> Self {
        client.set_local_user_id(my_user_id.clone());
        Self {
            client,
            ack_store: AckStore::new_with_clock(30 * 24 * 60 * 60, clock.clone()),
            previous: HashMap::new(),
            prekey_tracker: HashMap::new(),
            hybrid_identity_pins: std::collections::BTreeMap::new(),
            kem_identity_pins: std::collections::BTreeMap::new(),
            reorder_stats: super::ReorderStats::default(),
            my_user_id,
            clock,
        }
    }

    // ── Session queries ───────────────────────────────────────────────────────

    pub fn has_active_session(&self, contact_id: &str) -> bool {
        self.client.has_session(contact_id)
    }

    /// Which session is active for `contact_id` — `None` when there is none. Two answers that
    /// differ name two different ratchets, which `has_active_session` cannot tell apart.
    pub fn active_session_id(&self, contact_id: &str) -> Option<String> {
        self.client.get_session_id(contact_id)
    }

    pub fn my_user_id(&self) -> &str {
        &self.my_user_id
    }

    /// Remove all local session lifecycle state for a contact that the
    /// platform deliberately forgot.
    ///
    /// This is a local deletion boundary, not a protocol reset. It must not
    /// archive or send END_SESSION; it only prevents stale local state from
    /// steering the next add.
    pub fn forget_contact_state(&mut self, contact_id: &str) {
        self.client.remove_session(contact_id);
        self.previous.remove(contact_id);
        // The pairs stay, retired: the peer may still be writing on what we just forgot, and they
        // are how it is named and answered (`crypto::sealed_sender::book`).
        let now = self.clock.now_secs();
        let envelopes = self.client.envelopes_mut();
        envelopes.retire_device(contact_id, now);
        envelopes.prune(now);
        self.prekey_tracker.remove(contact_id);
        // Forgetting a contact is the person's decision to start over with it, and this is
        // local state about that contact like the rest.
        self.hybrid_identity_pins.remove(contact_id);
        self.kem_identity_pins.remove(contact_id);
    }

    /// Now, by the injected clock (unix seconds).
    pub fn now_secs(&self) -> u64 {
        self.clock.now_secs()
    }

    /// The hybrid identity key pinned for `device_id`, if a session to it was ever opened.
    pub fn pinned_hybrid_identity(&self, device_id: &str) -> Option<&[u8; 32]> {
        self.hybrid_identity_pins.get(device_id)
    }

    /// Pin on first sight; an existing pin is never replaced here (a change is refused upstream).
    pub fn pin_hybrid_identity(&mut self, device_id: &str, fingerprint: [u8; 32]) {
        self.hybrid_identity_pins
            .entry(device_id.to_string())
            .or_insert(fingerprint);
    }

    /// The KEM identity key pinned for `device_id`, if it ever opened a session to us.
    pub fn pinned_kem_identity(&self, device_id: &str) -> Option<&[u8; 32]> {
        self.kem_identity_pins.get(device_id)
    }

    /// Pin on first sight; an existing pin is never replaced here (a change is refused upstream).
    pub fn pin_kem_identity(&mut self, device_id: &str, fingerprint: [u8; 32]) {
        self.kem_identity_pins
            .entry(device_id.to_string())
            .or_insert(fingerprint);
    }

    /// Update the local user-id on both the lifecycle manager and the
    /// underlying `ClassicClient`.  Both fields must stay in sync so that
    /// newly created sessions bake in the correct sender/receiver ID.
    pub fn set_my_user_id(&mut self, user_id: String) {
        self.my_user_id = user_id.clone();
        self.client.set_local_user_id(user_id);
    }

    // ── Decrypt ───────────────────────────────────────────────────────────────

    /// Decrypt a wire payload (`wire_payload::pack`) and return the save the platform executes.
    /// The JSON path beside it (`encrypt` / `decrypt` over a `WireMessage`) was removed on
    /// 2026-09-28: a third carrier of the message, with no caller outside its own tests.
    pub fn decrypt_wire_payload(
        &mut self,
        contact_id: &str,
        payload: &[u8],
    ) -> Result<DecryptResult, String> {
        use crate::wire_payload;

        let decoded = wire_payload::unpack(payload).map_err(|e| e.to_string())?;

        let dh: [u8; 32] = decoded
            .dh_public_key
            .try_into()
            .map_err(|_| "dh_public_key must be 32 bytes".to_string())?;

        if decoded.sealed_box.len() < 12 {
            return Err("sealed_box too short (< 12 bytes)".to_string());
        }
        let nonce = decoded.sealed_box[..12].to_vec();
        let ciphertext = decoded.sealed_box[12..].to_vec();

        let msg = EncryptedRatchetMessage {
            dh_public_key: dh,
            message_number: decoded.message_number,
            ciphertext,
            nonce,
            previous_chain_length: decoded.previous_chain_length,
            suite_id: decoded.suite_id,
            pq_message_epoch: decoded.pq_message_epoch,
            pq_key_index: decoded.pq_key_index,
            pq_ratchet_field: decoded.pq_ratchet_field,
            identity_proof_ciphertext: decoded.identity_proof_ciphertext,
        };

        let plaintext = self.decrypt_ratchet_message(contact_id, &msg)?;

        let session_bytes = self.export_session_bytes_for(contact_id)?;
        let actions = vec![Action::SaveToSecureStore {
            slot: SecureStoreSlot::Session {
                contact_id: contact_id.to_string(),
            },
            data: session_bytes.into(),
        }];

        Ok(DecryptResult { plaintext, actions })
    }

    // ── Previous states ───────────────────────────────────────────────────────

    /// Decrypt `msg` on any state held with `contact_id`: the current one, then each previous
    /// one, newest first. A previous state that decrypts becomes current and the current one
    /// takes its place among the previous — the peer is talking on it, so it is the one to answer
    /// on. This is what makes two sides that opened at once converge: each holds both states, and
    /// the first message either reads picks one for both.
    ///
    /// A failed attempt changes nothing (`DoubleRatchetSession::decrypt` restores its snapshot on
    /// every failure path). A key already consumed in any state is a duplicate, reported as that
    /// state's `MESSAGE_KEY_CONSUMED` without trying further, and never promotes a state.
    ///
    /// The error, when nothing decrypts, is the current state's — the one a platform log is
    /// about — or "no active session" when there is none.
    pub fn decrypt_ratchet_message(
        &mut self,
        contact_id: &str,
        msg: &EncryptedRatchetMessage,
    ) -> Result<Vec<u8>, String> {
        use crate::crypto::messaging::double_ratchet::MESSAGE_KEY_CONSUMED;

        // The answer to our KEM identity key, when the message carries one: a responder's reply
        // until we have proved ourselves. The state it applies to — current or previous — decides
        // whether it is used (`IdentityProof::AwaitingAnswer`); decapsulating is cheap and never
        // fails on a foreign ciphertext, so it is done once, up front.
        let identity_secret = self.identity_answer_secret(msg)?;
        let identity_secret = identity_secret.as_ref().map(|s| s.expose());

        let mut current_error = None;
        let current_before = self.client.get_session_health(contact_id);
        if let Some(before) = &current_before {
            match self
                .client
                .decrypt_message_with_identity_secret(contact_id, msg, identity_secret)
            {
                Ok(plaintext) => {
                    if let Some(after) = self.client.get_session_health(contact_id) {
                        self.reorder_stats
                            .record_decrypted(before, &after, msg.pq_message_epoch);
                    }
                    self.close_first_flights(contact_id);
                    return Ok(plaintext);
                }
                Err(e) if e.starts_with(MESSAGE_KEY_CONSUMED) => return Err(e),
                Err(e) => current_error = Some(e),
            }
        }

        self.prune_previous(contact_id);
        let states = self.previous.get_mut(contact_id);
        let mut decrypted = None;
        if let Some(states) = states {
            for (index, state) in states.iter_mut().enumerate() {
                let before = state.session.health_snapshot();
                match state
                    .session
                    .decrypt_with_identity_secret(msg, identity_secret)
                {
                    Ok(plaintext) => {
                        self.reorder_stats.record_decrypted(
                            &before,
                            &state.session.health_snapshot(),
                            msg.pq_message_epoch,
                        );
                        decrypted = Some((index, plaintext));
                        break;
                    }
                    Err(e) if e.starts_with(MESSAGE_KEY_CONSUMED) => return Err(e),
                    Err(_) => {}
                }
            }
        }

        let Some((index, plaintext)) = decrypted else {
            self.reorder_stats
                .record_failed(current_before.as_ref(), msg.pq_message_epoch);
            return Err(
                current_error.unwrap_or_else(|| format!("No active session for {}", contact_id))
            );
        };
        if self.previous[contact_id][index].held_back {
            // Read, and left where it is: the peer said it cannot read this state.
            return Ok(plaintext);
        }
        let promoted = self
            .previous
            .get_mut(contact_id)
            .expect("the state that decrypted is held")
            .remove(index);
        tracing::info!(
            target: "crypto::lifecycle",
            contact_id = %contact_id,
            session_id = %promoted.session.session_id(),
            "a previous state decrypted — promoted to current"
        );
        self.install_current(contact_id, promoted.session);
        self.close_first_flights(contact_id);
        Ok(plaintext)
    }

    /// Drop the current session's first-flight key once no first flight can be written or arrive
    /// on it: the initiator has its answer (no header to attach), and the responder has the
    /// initiator's proof. Until then the initiator seals with it and the responder opens the later
    /// first flights with it (`crypto::sealed_sender::first_flight`).
    fn close_first_flights(&mut self, contact_id: &str) {
        use crate::crypto::kyber_prekey_auth::PqAuthentication;
        let Some(session) = self.client.get_session(contact_id) else {
            return;
        };
        let ratchet = session.messaging_session();
        if ratchet.prekey_header().is_some()
            || ratchet.pq_authentication() == PqAuthentication::Received
        {
            return;
        }
        let session_id = session.session_id().to_string();
        self.client.envelopes_mut().clear_first_flight(&session_id);
    }

    /// How late messages have arrived since the process started (PQR-4).
    pub fn reorder_stats(&self) -> super::ReorderStats {
        self.reorder_stats
    }

    #[cfg(feature = "post-quantum")]
    fn identity_answer_secret(
        &self,
        msg: &EncryptedRatchetMessage,
    ) -> Result<Option<crate::crypto::SecretBytes>, String> {
        msg.identity_proof_ciphertext
            .as_deref()
            .map(|ct| {
                self.client
                    .key_manager()
                    .kem_identity_decapsulate(ct)
                    .map_err(|e| e.to_string())
            })
            .transpose()
    }

    #[cfg(not(feature = "post-quantum"))]
    fn identity_answer_secret(
        &self,
        _msg: &EncryptedRatchetMessage,
    ) -> Result<Option<crate::crypto::SecretBytes>, String> {
        Ok(None)
    }

    /// Make `session` the current state with `contact_id`; the state it replaces, if any, becomes
    /// the newest previous one.
    ///
    /// Every replacement goes through here — a receiving open, a reopen, a promotion — so a state
    /// is never dropped by being replaced, only by `prune_previous`.
    pub(crate) fn install_current(&mut self, contact_id: &str, session: HeldSession) {
        if let Some(replaced) = self.client.take_session(contact_id) {
            self.retire(contact_id, replaced);
        }
        self.client.put_back_session(contact_id, session);
    }

    /// Keep `session` — taken out of the client, no longer current — as the newest previous state.
    pub(crate) fn retire(&mut self, contact_id: &str, session: HeldSession) {
        let retired_at = self.clock.now_secs();
        self.previous
            .entry(contact_id.to_string())
            .or_default()
            .insert(
                0,
                PreviousState {
                    session,
                    retired_at,
                    held_back: false,
                },
            );
        self.prune_previous(contact_id);
    }

    /// Retire the current state because the peer could not read it: it becomes the newest
    /// previous state, held back from promotion, and the device has no current state until the
    /// next send opens one. True when there was a current state to retire.
    ///
    /// Signal's `archiveCurrentState`, with the hold added: there a late message on the archived
    /// state promotes it back, and the next reply goes out on the state the peer just said it
    /// cannot read.
    pub fn retire_current(&mut self, contact_id: &str) -> bool {
        let Some(session) = self.client.take_session(contact_id) else {
            return false;
        };
        self.retire(contact_id, session);
        if let Some(newest) = self
            .previous
            .get_mut(contact_id)
            .and_then(|s| s.first_mut())
        {
            newest.held_back = true;
        }
        true
    }

    /// Whose sending key `key` is among the states held with `contact_id`.
    pub fn ratchet_key_owner(&self, contact_id: &str, key: &[u8]) -> RatchetKeyOwner {
        if let Some(current) = self.client.get_session(contact_id)
            && current.messaging_session().sending_ratchet_key() == key
        {
            return RatchetKeyOwner::Current;
        }
        let previous = self.previous.get(contact_id).is_some_and(|states| {
            states
                .iter()
                .any(|s| s.session.messaging_session().sending_ratchet_key() == key)
        });
        if previous {
            RatchetKeyOwner::Previous
        } else {
            RatchetKeyOwner::Unknown
        }
    }

    /// Whether anything at all is held with `contact_id` — a current state or a previous one.
    pub fn has_record(&self, contact_id: &str) -> bool {
        self.client.has_session(contact_id) || self.previous.contains_key(contact_id)
    }

    /// Drop the previous states past `PREVIOUS_STATE_TTL_SECONDS` or beyond `MAX_PREVIOUS_STATES`.
    fn prune_previous(&mut self, contact_id: &str) {
        let now = self.clock.now_secs();
        let Some(states) = self.previous.get_mut(contact_id) else {
            return;
        };
        states.retain(|s| now.saturating_sub(s.retired_at) < PREVIOUS_STATE_TTL_SECONDS);
        states.truncate(MAX_PREVIOUS_STATES);
        let mut held: Vec<String> = states
            .iter()
            .map(|s| s.session.session_id().to_string())
            .collect();
        if states.is_empty() {
            self.previous.remove(contact_id);
        }
        // A state pruned here takes its ratchet; its envelope pair is retired, not removed.
        if let Some(current) = self.client.get_session(contact_id) {
            held.push(current.session_id().to_string());
        }
        let envelopes = self.client.envelopes_mut();
        envelopes.retire_device_except(contact_id, &held, now);
        envelopes.prune(now);
    }

    /// How many previous states the record with `contact_id` holds.
    pub fn previous_state_count(&self, contact_id: &str) -> usize {
        self.previous.get(contact_id).map_or(0, Vec::len)
    }

    pub fn track_prekey(&mut self, contact_id: &str, otpk_id: u32) {
        self.prekey_tracker.insert(contact_id.to_string(), otpk_id);
    }

    /// `true` if `new_otpk_id` differs from the previously recorded value,
    /// indicating the contact has reinstalled.
    pub fn is_reinstall(&self, contact_id: &str, new_otpk_id: u32) -> bool {
        self.prekey_tracker
            .get(contact_id)
            .is_some_and(|&prev| prev != new_otpk_id)
    }

    // ── PQ contribution helpers ───────────────────────────────────────────────

    // ── State persistence ─────────────────────────────────────────────────────

    /// Export the full orchestrator coordination state (prekey tracker, pins) as a CFE binary blob — msg_type 0x05.
    ///
    /// `init_locks` is managed by `OrchestratorCore`; pass the current set here.
    /// The caller should persist the blob under `SecureStoreSlot::OrchestratorState`
    /// via `SaveToSecureStore` after every significant state change.
    ///
    /// **`processed_ids` is deliberately exported empty.** The ACK cache is an L1
    /// hot-path cache only; the durable owner of dedup state is the platform ACK
    /// store (iOS: Core Data `ProcessedMessage`, 30-day TTL matching the server
    /// re-delivery window). Snapshotting the cache bought nothing — `restore_cache`
    /// sets `post_restart_mode`, which is never cleared, so *every* cache miss
    /// already round-trips to the platform store via `Action::CheckAckInDb`
    /// regardless of what was restored. It only cost an unbounded blob: the state
    /// grew ~42 B per received message forever and is rewritten to the Keychain on
    /// every send and receive, and (since the fail-closed send-durability change)
    /// gates outgoing messages. Field devices were observed at 90 KB / ~2100 IDs.
    /// The field stays in the struct so the wire format is unchanged and older
    /// blobs still decode; `import` keeps reading it, so an existing device warms
    /// L1 once on the launch after the update and the next save shrinks the blob
    /// permanently.
    pub fn export_orchestrator_state_cfe(
        &self,
        init_locks: &std::collections::HashSet<String>,
    ) -> Result<Vec<u8>, String> {
        use crate::cfe::{CfeMessageType, CfeOrchestratorStateV1};

        let state = CfeOrchestratorStateV1 {
            ver: 1,
            my_user_id: self.my_user_id.clone(),
            processed_ids: Vec::new(),
            init_locks: init_locks.iter().cloned().collect(),
            prekey_tracker: self
                .prekey_tracker
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            hybrid_identity_pins: self
                .hybrid_identity_pins
                .iter()
                .map(|(device, fp)| crate::cfe::CfeHybridPinV1 {
                    device_id: device.clone(),
                    fingerprint: serde_bytes::ByteBuf::from(fp.to_vec()),
                })
                .collect(),
            kem_identity_pins: self
                .kem_identity_pins
                .iter()
                .map(|(device, fp)| crate::cfe::CfeHybridPinV1 {
                    device_id: device.clone(),
                    fingerprint: serde_bytes::ByteBuf::from(fp.to_vec()),
                })
                .collect(),
            envelope_book: self.client.envelopes().to_cfe(),
        };

        crate::cfe::encode(CfeMessageType::OrchestratorState, &state).map_err(|e| e.to_string())
    }

    /// Restore the orchestrator coordination state from a CFE binary blob.
    ///
    /// Returns the `init_locks` set so the caller (`OrchestratorCore`) can
    /// restore its own field.  All other fields are applied in-place.
    pub fn import_orchestrator_state_cfe(
        &mut self,
        data: &[u8],
    ) -> Result<std::collections::HashSet<String>, String> {
        use crate::cfe::{CfeMessageType, CfeOrchestratorStateV1};

        let state = crate::cfe::decode_as::<CfeOrchestratorStateV1>(
            data,
            CfeMessageType::OrchestratorState,
        )
        .map_err(|e| e.to_string())?;

        // Restore ACK cache.
        self.ack_store.restore_cache(
            state
                .processed_ids
                .into_iter()
                .map(|r| r.message_id)
                .collect(),
        );

        // Restore the prekey tracker.
        self.prekey_tracker = state.prekey_tracker.into_iter().collect();
        // A pin that is not 32 bytes cannot be compared with anything; dropping it re-pins on the
        // next session, which is where a device with no pin starts anyway.
        let pins = |pins: Vec<crate::cfe::CfeHybridPinV1>| {
            pins.into_iter()
                .filter_map(|p| {
                    <[u8; 32]>::try_from(p.fingerprint.as_slice())
                        .ok()
                        .map(|fp| (p.device_id, fp))
                })
                .collect()
        };
        self.hybrid_identity_pins = pins(state.hybrid_identity_pins);
        self.kem_identity_pins = pins(state.kem_identity_pins);
        let mut envelopes =
            crate::crypto::sealed_sender::book::EnvelopeBook::from_cfe(&state.envelope_book);
        envelopes.prune(self.clock.now_secs());
        *self.client.envelopes_mut() = envelopes;

        // Return init_locks for the caller to restore.
        Ok(state.init_locks.into_iter().collect())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    pub fn export_session_json_for(&self, contact_id: &str) -> Result<String, String> {
        let session = self
            .client
            .get_session(contact_id)
            .ok_or_else(|| format!("Session not found: {}", contact_id))?;
        let serializable = session.messaging_session().to_serializable();
        serde_json::to_string(&serializable).map_err(|e| format!("serialize session: {}", e))
    }

    /// Export the session as a CFE binary blob (MessagePack, no JSON intermediate).
    /// Prefer this over `export_session_json_for` wherever bytes are needed.
    pub fn export_session_bytes_for(&self, contact_id: &str) -> Result<Vec<u8>, String> {
        let previous: &[PreviousState] = self.previous.get(contact_id).map_or(&[], Vec::as_slice);
        // No current state: the newest previous one stands at the top of the record, marked
        // retired, so a record the peer's decryption error emptied survives a restart.
        let (mut cfe_state, rest) = match self.client.get_session(contact_id) {
            Some(session) => (
                session.messaging_session().to_serializable().to_cfe_v1()?,
                previous,
            ),
            None => {
                let (newest, rest) = previous
                    .split_first()
                    .ok_or_else(|| format!("Session not found: {}", contact_id))?;
                let mut top = newest
                    .session
                    .messaging_session()
                    .to_serializable()
                    .to_cfe_v1()?;
                top.retired = Some(crate::cfe::CfeRetiredMarkV1 {
                    retired_at: newest.retired_at,
                    held_back: newest.held_back,
                });
                (top, rest)
            }
        };
        for state in rest {
            cfe_state.previous.push(crate::cfe::CfePreviousStateV1 {
                retired_at: state.retired_at,
                state: state
                    .session
                    .messaging_session()
                    .to_serializable()
                    .to_cfe_v1()?,
                held_back: state.held_back,
            });
        }
        crate::cfe::encode(crate::cfe::CfeMessageType::SessionState, &cfe_state)
            .map_err(|e| e.to_string())
    }

    /// Import a session from CFE binary bytes.
    pub fn import_session_bytes(&mut self, contact_id: &str, data: &[u8]) -> Result<(), String> {
        use crate::cfe::{CfeError, CfeMessageType, decode_as};
        use crate::crypto::messaging::SecureMessaging;
        use crate::crypto::messaging::double_ratchet::{DoubleRatchetSession, SerializableSession};

        let (serializable, previous, retired) =
            match decode_as::<crate::cfe::CfeSessionStateV1>(data, CfeMessageType::SessionState) {
                Ok(mut cfe_state) => {
                    let previous = std::mem::take(&mut cfe_state.previous);
                    let retired = cfe_state.retired.take();
                    let current = SerializableSession::from_cfe_v1(cfe_state)
                        .map_err(|e| format!("from_cfe_v1: {}", e))?;
                    (current, previous, retired)
                }
                Err(CfeError::LegacyJson) => {
                    let s = std::str::from_utf8(data).map_err(|_| "not utf8".to_string())?;
                    let current =
                        serde_json::from_str(s).map_err(|e| format!("json fallback: {}", e))?;
                    (current, Vec::new(), None)
                }
                Err(e) => return Err(format!("decode_as: {}", e)),
            };

        // The record names its own contact and author; the argument is only what the caller
        // believed. Disagreement means the blob is being loaded under a name it was not saved
        // under, which does not fail here — it fails as a permanent AEAD error later. Asked of
        // every state in the record, previous ones included, before any of them is installed.
        serializable.verify_identity(contact_id, self.client.local_user_id())?;
        let mut states = Vec::with_capacity(previous.len());
        for entry in previous {
            // A previous state of the retired epoch-granular PQ ratchet reads nothing a peer on
            // this build still sends; it is dropped rather than failing the current state with it.
            if u16::from(entry.state.suite_id) == crate::crypto::SuiteID::RETIRED_PQ_RATCHET_V1 {
                tracing::info!(
                    target: "crypto::session",
                    "dropping a previous suite-3 state from the record (suite retired)"
                );
                continue;
            }
            let state = SerializableSession::from_cfe_v1(entry.state)
                .map_err(|e| format!("from_cfe_v1 (previous): {}", e))?;
            state.verify_identity(contact_id, self.client.local_user_id())?;
            let ratchet = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(state)
                .map_err(|e| format!("from_serializable (previous): {}", e))?;
            // Made by a core older than the envelope: nothing can be sealed on it, and what the
            // peer writes on it arrives as an envelope it cannot be found by. Dropped, as a
            // retired suite's states are.
            if !self.client.envelopes().has_session(ratchet.session_id()) {
                tracing::info!(
                    target: "crypto::session",
                    "dropping a previous state with no envelope keys (predates the envelope)"
                );
                continue;
            }
            states.push(PreviousState {
                session: HeldSession::from_messaging_session(contact_id.to_string(), ratchet),
                retired_at: entry.retired_at,
                held_back: entry.held_back,
            });
        }

        let ratchet = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(serializable)
            .map_err(|e| format!("from_serializable: {}", e))?;
        // A state made before the envelope has no keys in the book — they derive from the
        // handshake root, which is not kept — so nothing could be sealed on it. Refused like a
        // retired suite: the platform treats the session as absent, and the next send opens one.
        if !self.client.envelopes().has_session(ratchet.session_id()) {
            return Err(format!(
                "{SESSION_PREDATES_ENVELOPE}: session {} has no envelope keys",
                crate::crypto::messaging::double_ratchet::id_prefix(ratchet.session_id())
            ));
        }
        // A session still in its first flights needs their key — the initiator to seal them, the
        // responder to open the later ones. One made by core 0.26 has none: renewed like the above.
        let in_first_flights = ratchet.prekey_header().is_some()
            || ratchet.pq_authentication()
                == crate::crypto::kyber_prekey_auth::PqAuthentication::Received;
        if in_first_flights
            && self
                .client
                .envelopes()
                .first_flight_of_session(ratchet.session_id())
                .is_none()
        {
            return Err(format!(
                "{SESSION_PREDATES_ENVELOPE}: session {} is in its first flights and has no \
                 first-flight key",
                crate::crypto::messaging::double_ratchet::id_prefix(ratchet.session_id())
            ));
        }
        match retired {
            // The top of the record is a retired state, not a current one.
            Some(mark) => {
                let _ = self.client.take_session(contact_id);
                states.insert(
                    0,
                    PreviousState {
                        session: HeldSession::from_messaging_session(
                            contact_id.to_string(),
                            ratchet,
                        ),
                        retired_at: mark.retired_at,
                        held_back: mark.held_back,
                    },
                );
            }
            None => {
                self.client.import_session(contact_id, ratchet);
            }
        }
        if states.is_empty() {
            self.previous.remove(contact_id);
        } else {
            self.previous.insert(contact_id.to_string(), states);
            self.prune_previous(contact_id);
        }
        Ok(())
    }
}

// ── Key helpers ───────────────────────────────────────────────────────────────

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_api::ClassicClient;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    #[allow(dead_code)]
    fn make_pair() -> (SessionLifecycleManager, SessionLifecycleManager) {
        let alice_client = ClassicClient::<ClassicSuiteProvider>::new().expect("alice client");
        let bob_client = ClassicClient::<ClassicSuiteProvider>::new().expect("bob client");
        let alice = SessionLifecycleManager::new(alice_client, "alice".to_string());
        let bob = SessionLifecycleManager::new(bob_client, "bob".to_string());
        (alice, bob)
    }

    /// What the platform does before restoring any session: load the orchestrator state, which
    /// carries the envelope book. A session restored without it is refused
    /// (`SESSION_PREDATES_ENVELOPE`), as one made before the envelope is.
    fn carry_orchestrator_state(from: &SessionLifecycleManager, to: &mut SessionLifecycleManager) {
        let blob = from
            .export_orchestrator_state_cfe(&std::collections::HashSet::new())
            .unwrap();
        to.import_orchestrator_state_cfe(&blob).unwrap();
    }

    #[test]
    fn test_new_manager_has_no_sessions() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mgr = SessionLifecycleManager::new(client, "alice".to_string());
        assert!(!mgr.has_active_session("bob"));
        assert_eq!(mgr.my_user_id(), "alice");
    }

    #[test]
    fn test_prekey_tracking() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        assert!(!mgr.is_reinstall("bob", 42)); // no record yet → not a reinstall
        mgr.track_prekey("bob", 42);
        assert!(!mgr.is_reinstall("bob", 42)); // same key → not reinstall
        assert!(mgr.is_reinstall("bob", 99)); // different → reinstall
    }

    #[test]
    fn forget_contact_state_clears_prekey_and_pq_state() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        mgr.track_prekey("bob", 42);
        mgr.pin_hybrid_identity("bob", [7; 32]);

        mgr.forget_contact_state("bob");

        assert!(!mgr.is_reinstall("bob", 99));
        assert!(mgr.pinned_hybrid_identity("bob").is_none());
    }

    /// Establish a real X3DH session between two lifecycle managers.
    /// Returns (alice_mgr, bob_mgr, alice_device_id, bob_device_id).
    fn make_session_pair() -> (
        SessionLifecycleManager,
        SessionLifecycleManager,
        String,
        String,
    ) {
        use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
        use crate::device_id::derive_device_id;

        let alice_client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut alice = SessionLifecycleManager::new(alice_client, "alice".to_string());

        let bob_client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut bob = SessionLifecycleManager::new(bob_client, "bob".to_string());

        // Exchange registration bundles.
        let bob_bundle = bob.client.get_registration_bundle().unwrap();
        let bob_identity = bob
            .client
            .key_manager()
            .identity_public_key()
            .unwrap()
            .clone();
        let bob_device_id = derive_device_id(&bob_bundle.identity_public);

        let alice_bundle = alice.client.get_registration_bundle().unwrap();
        let alice_device_id = derive_device_id(&alice_bundle.identity_public);

        alice.client.set_local_user_id(alice_device_id.clone());
        bob.client.set_local_user_id(bob_device_id.clone());

        // Alice → Bob: X3DH init.
        let bob_x3dh = X3DHPublicKeyBundle {
            identity_public: bob_bundle.identity_public.clone(),
            signed_prekey_public: bob_bundle.signed_prekey_public.clone(),
            signature: bob_bundle.signature.clone(),
            verifying_key: bob_bundle.verifying_key.clone(),
            suite_id: bob_bundle.suite_id,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
            spk_uploaded_at: 0,
            spk_rotation_epoch: 0,
            kyber_spk_uploaded_at: 0,
            kyber_spk_rotation_epoch: 0,
        };
        alice
            .client
            .init_session(&bob_device_id, &bob_x3dh, &bob_identity, 0)
            .unwrap();

        // Alice encrypts first message.
        let first_msg = alice
            .client
            .encrypt_message(&bob_device_id, b"hello")
            .unwrap();

        // Bob initialises receiving session.
        bob.client
            .init_receiving_session(&alice_device_id, &alice_bundle, &first_msg)
            .unwrap();

        (alice, bob, alice_device_id, bob_device_id)
    }

    // ── Previous states (decisions/sessions-renew-by-sending.md) ─────────────
    //
    // A record keeps the states a newer one replaced, and a decrypt tries them all. Each test
    // below builds real ratchets: a state that "decrypts" only because nothing checked it is the
    // vacuous pass this file has been bitten by before.

    /// Alice opens a new state over the one she holds, and Bob opens it from her first message,
    /// each keeping the replaced state as a previous one — what the orchestrator does on a reopen
    /// and on a receiving open. The new state's first message is consumed by Bob's open.
    fn reopen(
        alice: &mut SessionLifecycleManager,
        bob: &mut SessionLifecycleManager,
        alice_id: &str,
        bob_id: &str,
    ) {
        use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

        let bob_bundle = bob.client.get_registration_bundle().unwrap();
        let bob_identity = bob
            .client
            .key_manager()
            .identity_public_key()
            .unwrap()
            .clone();
        let alice_bundle = alice.client.get_registration_bundle().unwrap();
        let old = alice.client.take_session(bob_id).unwrap();
        alice.retire(bob_id, old);
        alice
            .client
            .init_session(
                bob_id,
                &X3DHPublicKeyBundle {
                    identity_public: bob_bundle.identity_public.clone(),
                    signed_prekey_public: bob_bundle.signed_prekey_public.clone(),
                    signature: bob_bundle.signature.clone(),
                    verifying_key: bob_bundle.verifying_key.clone(),
                    suite_id: bob_bundle.suite_id,
                    one_time_prekey_public: None,
                    one_time_prekey_id: None,
                    spk_uploaded_at: 0,
                    spk_rotation_epoch: 0,
                    kyber_spk_uploaded_at: 0,
                    kyber_spk_rotation_epoch: 0,
                },
                &bob_identity,
                0,
            )
            .unwrap();
        let first = alice.client.encrypt_message(bob_id, b"new state").unwrap();
        let old = bob.client.take_session(alice_id).unwrap();
        bob.client
            .init_receiving_session(alice_id, &alice_bundle, &first)
            .unwrap();
        bob.retire(alice_id, old);
    }

    fn lifecycle_pair_with_clock(
        clock: Arc<crate::orchestration::clock::MockClock>,
    ) -> (
        SessionLifecycleManager,
        SessionLifecycleManager,
        String,
        String,
    ) {
        let (alice, bob, alice_id, bob_id) = make_session_pair();
        let mut alice = alice;
        let mut bob = bob;
        alice.clock = clock.clone();
        bob.clock = clock;
        (alice, bob, alice_id, bob_id)
    }

    /// A message the peer wrote on a state we replaced still decrypts, and the state it decrypted
    /// on becomes current: the peer is talking on it, so it is the one to answer on.
    ///
    /// Mutation: return the current state's error without trying the previous ones — this
    /// reddens. Mutation: decrypt on a previous state without promoting it — the last assertion
    /// reddens.
    #[test]
    fn a_message_on_a_replaced_state_decrypts_and_promotes_it() {
        let (mut alice, mut bob, alice_id, bob_id) = make_session_pair();
        let on_old = alice.client.encrypt_message(&bob_id, b"old").unwrap();
        let old_state = bob.active_session_id(&alice_id).unwrap();

        reopen(&mut alice, &mut bob, &alice_id, &bob_id);
        assert_ne!(bob.active_session_id(&alice_id).unwrap(), old_state);
        assert_eq!(bob.previous_state_count(&alice_id), 1);

        let plaintext = bob.decrypt_ratchet_message(&alice_id, &on_old).unwrap();
        assert_eq!(plaintext, b"old");
        assert_eq!(bob.active_session_id(&alice_id).unwrap(), old_state);
        assert_eq!(
            bob.previous_state_count(&alice_id),
            1,
            "the state it displaced is kept in turn"
        );
    }

    /// PQR-4's measurement on real ratchets: Alice writes and Bob answers until Bob has moved
    /// two epochs past the one Alice held two messages back on. The one followed by later
    /// messages of its epoch left a skipped key and opens late, counted as an older epoch; the
    /// last of its epoch left nothing and is counted as lost to eviction.
    ///
    /// Mutation: drop either `record_*` call in `decrypt_ratchet_message` — this reddens.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn reorder_stats_count_late_epochs_and_evictions() {
        let (mut alice, mut bob, alice_id, bob_id) = make_session_pair();
        let epoch_of = |m: &EncryptedRatchetMessage| m.pq_message_epoch;

        let mut mid_epoch = None; // (epoch, message) with later messages of its epoch delivered
        let mut last_of_epoch = None; // the last message Alice sent on its epoch
        let mut pending: Option<EncryptedRatchetMessage> = None;
        for round in 0..400 {
            let next = alice.client.encrypt_message(&bob_id, b"a").unwrap();
            if let Some(held) = pending.take() {
                let target = mid_epoch.as_ref().map(|(e, _)| *e);
                if mid_epoch.is_none() && epoch_of(&held) >= 1 && epoch_of(&next) == epoch_of(&held)
                {
                    mid_epoch = Some((epoch_of(&held), held));
                } else if last_of_epoch.is_none()
                    && target.is_some_and(|e| epoch_of(&held) == e)
                    && epoch_of(&next) > epoch_of(&held)
                {
                    last_of_epoch = Some(held);
                } else {
                    bob.decrypt_ratchet_message(&alice_id, &held).unwrap();
                }
            }
            pending = Some(next);

            let oldest = bob
                .client
                .get_session_health(&alice_id)
                .and_then(|s| s.pq_oldest_chain_epoch);
            let target = mid_epoch.as_ref().map(|(e, _)| *e);
            if last_of_epoch.is_some() && oldest.zip(target).is_some_and(|(o, e)| o > e) {
                break;
            }
            let reply = bob.client.encrypt_message(&alice_id, b"b").unwrap();
            alice.decrypt_ratchet_message(&bob_id, &reply).unwrap();
            assert!(round < 399, "Bob never moved two epochs past the held ones");
        }

        let before = bob.reorder_stats();
        let (_, late) = mid_epoch.expect("a mid-epoch message was held");
        assert_eq!(bob.decrypt_ratchet_message(&alice_id, &late).unwrap(), b"a");
        let after_late = bob.reorder_stats();
        assert_eq!(after_late.older_epoch, before.older_epoch + 1);
        assert!(after_late.max_epoch_lag >= 2);

        let lost = last_of_epoch.expect("the last message of the epoch was held");
        assert!(bob.decrypt_ratchet_message(&alice_id, &lost).is_err());
        assert_eq!(bob.reorder_stats().evicted_epoch_failures, 1);
    }

    /// A key already used in a previous state is a duplicate, and a duplicate promotes nothing —
    /// a replay must not be able to pull the record back onto an old state.
    ///
    /// Mutation: skip the `MESSAGE_KEY_CONSUMED` arm in the previous-state loop — this reddens.
    #[test]
    fn a_key_used_in_a_previous_state_is_a_duplicate_and_promotes_nothing() {
        let (mut alice, mut bob, alice_id, bob_id) = make_session_pair();
        let on_old = alice.client.encrypt_message(&bob_id, b"old").unwrap();
        bob.decrypt_ratchet_message(&alice_id, &on_old).unwrap();

        reopen(&mut alice, &mut bob, &alice_id, &bob_id);
        let current = bob.active_session_id(&alice_id).unwrap();

        let err = bob.decrypt_ratchet_message(&alice_id, &on_old).unwrap_err();
        assert!(
            err.starts_with(crate::crypto::messaging::double_ratchet::MESSAGE_KEY_CONSUMED),
            "{err}"
        );
        assert_eq!(bob.active_session_id(&alice_id).unwrap(), current);
    }

    /// Previous states are part of the record: saved with the current one and loaded with it.
    ///
    /// Mutation: drop the `previous` list in `export_session_bytes_for` — this reddens.
    #[test]
    fn previous_states_survive_a_save_and_load() {
        let (mut alice, mut bob, alice_id, bob_id) = make_session_pair();
        let on_old = alice.client.encrypt_message(&bob_id, b"old").unwrap();
        reopen(&mut alice, &mut bob, &alice_id, &bob_id);

        let saved = bob.export_session_bytes_for(&alice_id).unwrap();
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(client, bob_id.clone());
        carry_orchestrator_state(&bob, &mut restored);
        restored.import_session_bytes(&alice_id, &saved).unwrap();

        assert_eq!(restored.previous_state_count(&alice_id), 1);
        assert_eq!(
            restored
                .decrypt_ratchet_message(&alice_id, &on_old)
                .unwrap(),
            b"old"
        );
    }

    /// A replaced state is kept for `PREVIOUS_STATE_TTL_SECONDS` and no longer.
    ///
    /// Mutation: skip the age filter in `prune_previous` — this reddens.
    #[test]
    fn a_replaced_state_is_dropped_after_its_ttl() {
        let clock = Arc::new(crate::orchestration::clock::MockClock::new(1_000_000_000));
        let (mut alice, mut bob, alice_id, bob_id) = lifecycle_pair_with_clock(clock.clone());
        let late = alice.client.encrypt_message(&bob_id, b"late").unwrap();
        reopen(&mut alice, &mut bob, &alice_id, &bob_id);

        clock.advance_ms(PREVIOUS_STATE_TTL_SECONDS * 1000 + 1000);
        assert!(bob.decrypt_ratchet_message(&alice_id, &late).is_err());
        assert_eq!(bob.previous_state_count(&alice_id), 0);
    }

    /// No more than `MAX_PREVIOUS_STATES` are kept; the oldest go first.
    ///
    /// Mutation: skip the `truncate` in `prune_previous` — this reddens.
    #[test]
    fn no_more_than_the_cap_of_previous_states_is_kept() {
        let (mut alice, mut bob, alice_id, bob_id) = make_session_pair();
        let on_first = alice.client.encrypt_message(&bob_id, b"first").unwrap();
        for _ in 0..=MAX_PREVIOUS_STATES {
            reopen(&mut alice, &mut bob, &alice_id, &bob_id);
        }
        assert_eq!(bob.previous_state_count(&alice_id), MAX_PREVIOUS_STATES);
        assert!(
            bob.decrypt_ratchet_message(&alice_id, &on_first).is_err(),
            "the oldest state went first"
        );
    }

    // ── Retiring on the peer's decryption error (variant B) ──────────────────

    fn sending_key(mgr: &SessionLifecycleManager, peer: &str) -> Vec<u8> {
        mgr.client
            .get_session(peer)
            .unwrap()
            .messaging_session()
            .sending_ratchet_key()
            .to_vec()
    }

    /// A decryption error is acted on only when its key is the current state's. Mutation: answer
    /// `Current` for a previous state's key — this reddens.
    #[test]
    fn a_ratchet_key_names_the_state_that_sends_with_it() {
        let (mut alice, _bob, _alice_id, bob_id) = make_session_pair();
        let key = sending_key(&alice, &bob_id);
        assert_eq!(
            alice.ratchet_key_owner(&bob_id, &key),
            RatchetKeyOwner::Current
        );
        assert_eq!(
            alice.ratchet_key_owner(&bob_id, &[1; 32]),
            RatchetKeyOwner::Unknown
        );

        assert!(alice.retire_current(&bob_id));
        assert_eq!(
            alice.ratchet_key_owner(&bob_id, &key),
            RatchetKeyOwner::Previous
        );
        assert!(
            !alice.retire_current(&bob_id),
            "nothing current is left to retire"
        );
    }

    /// The peer said it cannot read the retired state; a late message on it still reads, and the
    /// state stays retired, so the next send opens a new one. Mutation: drop the `held_back`
    /// check in `decrypt_ratchet_message` — this reddens.
    #[test]
    fn a_retired_state_reads_but_is_not_made_current_again() {
        let (mut alice, mut bob, alice_id, bob_id) = make_session_pair();
        let late = bob.client.encrypt_message(&alice_id, b"late").unwrap();
        alice.retire_current(&bob_id);

        assert_eq!(
            alice.decrypt_ratchet_message(&bob_id, &late).unwrap(),
            b"late"
        );
        assert!(!alice.has_active_session(&bob_id));
        assert!(alice.has_record(&bob_id));
    }

    /// Until the next send opens a state, the record is only previous states, and it must survive
    /// a restart that way. Mutation: export the retired state as current — this reddens.
    #[test]
    fn a_record_with_no_current_state_survives_save_and_load() {
        let (mut alice, mut bob, alice_id, bob_id) = make_session_pair();
        let late = bob.client.encrypt_message(&alice_id, b"late").unwrap();
        alice.retire_current(&bob_id);

        let saved = alice.export_session_bytes_for(&bob_id).unwrap();
        alice.previous.remove(&bob_id);
        alice.import_session_bytes(&bob_id, &saved).unwrap();

        assert!(!alice.has_active_session(&bob_id));
        assert_eq!(alice.previous_state_count(&bob_id), 1);
        assert_eq!(
            alice.decrypt_ratchet_message(&bob_id, &late).unwrap(),
            b"late"
        );
        assert!(
            !alice.has_active_session(&bob_id),
            "still held back after the reload"
        );
    }

    #[test]
    fn test_export_session_bytes_for_produces_valid_cfe() {
        let (alice, _bob, _alice_id, bob_device_id) = make_session_pair();
        let bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();
        // Must start with CFE magic.
        assert_eq!(&bytes[..2], b"CF");
        // Must be decodable back to CfeSessionStateV1.
        let state = crate::cfe::decode_as::<crate::cfe::CfeSessionStateV1>(
            &bytes,
            crate::cfe::CfeMessageType::SessionState,
        )
        .unwrap();
        assert_eq!(state.ver, 1);
        assert!(!state.contact_id.is_empty());
    }

    #[test]
    fn test_export_bytes_import_bytes_round_trip() {
        // The restoring manager must be the same identity that exported. Until 2026-08-26 this
        // test restored into a manager whose local id was the literal `"alice"` rather than
        // Alice's device id, and passed: it asserted the session was *present*, and presence is
        // not usability — the restored session would have built its AD with the wrong name and
        // failed every decrypt. `verify_identity` is what turns that into a visible failure.
        let (alice, _bob, alice_id, bob_device_id) = make_session_pair();
        let bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();

        let alice_client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(alice_client, alice_id);
        carry_orchestrator_state(&alice, &mut restored);
        restored
            .import_session_bytes(&bob_device_id, &bytes)
            .unwrap();
        assert!(restored.has_active_session(&bob_device_id));
    }

    /// A session whose envelope keys are not in the book — made by a core older than the
    /// envelope, or restored without the orchestrator state — is refused: nothing can be sealed
    /// on it, and the platform treats it as absent so the next send opens one.
    ///
    /// Mutation: drop the `has_session` check on the current state in `import_session_bytes`.
    #[test]
    fn a_session_with_no_envelope_keys_is_refused() {
        let (alice, _bob, alice_id, bob_device_id) = make_session_pair();
        let bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(client, alice_id);
        let err = restored
            .import_session_bytes(&bob_device_id, &bytes)
            .unwrap_err();
        assert!(err.starts_with(SESSION_PREDATES_ENVELOPE), "{err}");
        assert!(!restored.has_active_session(&bob_device_id));
    }

    // ── Import verifies the record's own identity ────────────────────────────
    //
    // A session record carries `contact_id` and `local_uid` inside it, and every import path
    // also takes a `contact_id` argument. Until 2026-08-26 the argument simply won: a blob
    // loaded under the wrong name was imported without complaint and failed later, as a
    // permanent AEAD error on a session that looked healthy. Each test below names the
    // mutation of `SerializableSession::verify_identity` that must redden it.

    /// Mutation: drop the `contact_id` comparison — this reddens.
    #[test]
    fn test_import_rejects_a_record_saved_for_another_contact() {
        let (alice, _bob, alice_id, bob_device_id) = make_session_pair();
        let bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();

        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(client, alice_id);
        let stranger = "0".repeat(32);

        let err = restored
            .import_session_bytes(&stranger, &bytes)
            .expect_err("a record for Bob must not import as a session with someone else");
        assert!(err.contains("identity mismatch"), "unexpected error: {err}");
        assert!(
            !restored.has_active_session(&stranger),
            "a rejected import must leave no session behind"
        );
    }

    /// Mutation: drop the `local_user_id` comparison — this reddens.
    ///
    /// This is the half that catches the addressing drift: the record was written while we were
    /// one identity and is being loaded while we are another, so the AD it will build no longer
    /// mirrors what the peer builds.
    #[test]
    fn test_import_rejects_a_record_made_by_another_local_identity() {
        let (alice, _bob, _alice_id, bob_device_id) = make_session_pair();
        let bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();

        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(client, "1".repeat(32));

        let err = restored
            .import_session_bytes(&bob_device_id, &bytes)
            .expect_err("a record made by another identity must not import");
        assert!(err.contains("identity mismatch"), "unexpected error: {err}");
        assert!(!restored.has_active_session(&bob_device_id));
    }

    /// Diagnostics name the mismatch without writing either identifier out in full — the
    /// mismatch is exactly the case where both would otherwise reach a log.
    ///
    /// Mutation: format the whole id instead of `id_prefix` — this reddens.
    #[test]
    fn test_the_mismatch_error_does_not_carry_a_whole_identifier() {
        let (alice, _bob, alice_id, bob_device_id) = make_session_pair();
        let bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();

        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(client, alice_id.clone());
        let err = restored
            .import_session_bytes(&"0".repeat(32), &bytes)
            .unwrap_err();

        assert!(
            !err.contains(&bob_device_id),
            "leaked the record's contact id: {err}"
        );
        assert!(
            err.contains(&bob_device_id[..8]),
            "should still say which contact: {err}"
        );
    }

    /// Mutation: reject instead of skipping when a side is empty — this reddens.
    ///
    /// The core's own id is empty until `set_local_user_id` runs, and startup imports sessions.
    /// Refusing them would discard live ratchet state to enforce a comparison that cannot
    /// conclude anything.
    #[test]
    fn test_import_skips_the_local_id_check_before_the_identity_is_set() {
        let (alice, _bob, _alice_id, bob_device_id) = make_session_pair();
        let bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();

        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(client, String::new());
        carry_orchestrator_state(&alice, &mut restored);

        restored
            .import_session_bytes(&bob_device_id, &bytes)
            .expect("an unset local identity cannot disprove the record");
        assert!(restored.has_active_session(&bob_device_id));
    }

    /// A legacy JSON blob predates `local_user_id` (the field carries `#[serde(default)]`).
    /// Empty on the record's side means "this predates the field", not "this belongs to
    /// someone else".
    ///
    /// Mutation: reject a record with an empty `local_user_id` — this reddens.
    #[test]
    fn test_import_accepts_a_legacy_record_with_no_local_user_id() {
        let (alice, _bob, alice_id, bob_device_id) = make_session_pair();
        let json = alice.export_session_json_for(&bob_device_id).unwrap();

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("local_user_id")
            .expect("the exported JSON should carry the field this test removes");
        let legacy = serde_json::to_vec(&value).unwrap();

        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(client, alice_id);
        carry_orchestrator_state(&alice, &mut restored);
        restored
            .import_session_bytes(&bob_device_id, &legacy)
            .expect("a pre-field record must still load");
        assert!(restored.has_active_session(&bob_device_id));
    }

    #[test]
    fn test_export_bytes_no_json_intermediate() {
        // Verify the exported bytes are NOT a JSON string wrapped in CFE
        // (i.e., the old CfeSessionJsonWrapperV1 path is no longer used).
        let (alice, _bob, _alice_id, bob_device_id) = make_session_pair();
        let bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();
        // Successfully decode as CfeSessionStateV1 (new format).
        assert!(
            crate::cfe::decode_as::<crate::cfe::CfeSessionStateV1>(
                &bytes,
                crate::cfe::CfeMessageType::SessionState,
            )
            .is_ok()
        );
        // Must NOT decode as CfeSessionJsonWrapperV1 (old format with JSON inside).
        assert!(
            crate::cfe::decode_as::<crate::cfe::CfeSessionJsonWrapperV1>(
                &bytes,
                crate::cfe::CfeMessageType::SessionState,
            )
            .is_err()
        );
    }

    #[test]
    fn test_import_session_bytes_handles_old_json_wrapper_format() {
        // Simulate data produced by the old export_session_cfe (JSON inside CFE wrapper).
        let (alice, _bob, _alice_id, bob_device_id) = make_session_pair();
        let json = alice.export_session_json_for(&bob_device_id).unwrap();
        let wrapper = crate::cfe::CfeSessionJsonWrapperV1 {
            contact_id: bob_device_id.clone(),
            json_bytes: crate::crypto::SecretBytes::from(json.into_bytes()),
        };
        let old_bytes =
            crate::cfe::encode(crate::cfe::CfeMessageType::SessionState, &wrapper).unwrap();

        // import_session_bytes handles CfeSessionStateV1 and LegacyJson only.
        // CfeSessionJsonWrapperV1 (old orchestrator format) is handled by import_session_cfe.
        let alice_client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restored = SessionLifecycleManager::new(alice_client, "alice".to_string());
        let result = restored.import_session_bytes(&bob_device_id, &old_bytes);
        assert!(
            result.is_err(),
            "import_session_bytes does not handle CfeSessionJsonWrapperV1 — use import_session_cfe"
        );
    }

    // ── ACK cache is not snapshotted (orchestrator blob stays bounded) ────────
    //
    // Field devices were observed carrying a 90 KB orchestrator blob that grew
    // ~42 B per received message and is rewritten to the Keychain on every send
    // and receive. The cause was snapshotting the L1 ACK cache, which bought
    // nothing: `restore_cache` sets `post_restart_mode` (never cleared), so every
    // miss already round-trips to the durable platform store.

    fn decode_orchestrator_state(bytes: &[u8]) -> crate::cfe::CfeOrchestratorStateV1 {
        crate::cfe::decode_as::<crate::cfe::CfeOrchestratorStateV1>(
            bytes,
            crate::cfe::CfeMessageType::OrchestratorState,
        )
        .expect("orchestrator state decodes")
    }

    #[test]
    fn test_orchestrator_state_export_omits_processed_ids() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        let locks = std::collections::HashSet::new();

        for i in 0..100 {
            mgr.ack_store.mark_processed(&format!("msg-{i:04}"));
        }
        assert_eq!(mgr.ack_store.cache_len(), 100, "L1 cache still tracks them");

        let state = decode_orchestrator_state(&mgr.export_orchestrator_state_cfe(&locks).unwrap());
        assert!(
            state.processed_ids.is_empty(),
            "ACK cache must never be snapshotted — it is what made the blob unbounded"
        );
    }

    #[test]
    fn test_orchestrator_state_blob_does_not_grow_with_acks() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        let locks = std::collections::HashSet::new();

        let baseline = mgr.export_orchestrator_state_cfe(&locks).unwrap().len();
        for i in 0..1_000 {
            mgr.ack_store
                .mark_processed(&format!("11111111-2222-3333-4444-{i:012}"));
        }
        let after = mgr.export_orchestrator_state_cfe(&locks).unwrap().len();

        assert_eq!(
            baseline, after,
            "1000 processed messages must not add a single byte to the persisted blob \
             (was ~42 B each, forever)"
        );
    }

    #[test]
    fn test_orchestrator_state_import_still_reads_legacy_processed_ids() {
        // A blob written before the change carries a populated list. It must still
        // decode and warm L1 once, so the launch right after the update does not
        // lose dedup state it already had in memory.
        use crate::cfe::{CfeAckRecordV1, CfeMessageType, CfeOrchestratorStateV1};
        let legacy = CfeOrchestratorStateV1 {
            ver: 1,
            my_user_id: "alice".to_string(),
            processed_ids: vec![
                CfeAckRecordV1 {
                    message_id: "old-msg-1".to_string(),
                },
                CfeAckRecordV1 {
                    message_id: "old-msg-2".to_string(),
                },
            ],
            init_locks: vec![],
            prekey_tracker: vec![],
            hybrid_identity_pins: vec![],
            kem_identity_pins: vec![],
            envelope_book: vec![],
        };
        let bytes = crate::cfe::encode(CfeMessageType::OrchestratorState, &legacy).unwrap();

        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        mgr.import_orchestrator_state_cfe(&bytes).unwrap();

        assert_eq!(
            mgr.ack_store.is_processed("old-msg-1"),
            crate::orchestration::AckCheckResult::InCache
        );

        // …and the very next save drops them permanently — the blob shrinks itself.
        let locks = std::collections::HashSet::new();
        let re_exported =
            decode_orchestrator_state(&mgr.export_orchestrator_state_cfe(&locks).unwrap());
        assert!(re_exported.processed_ids.is_empty());
    }

    #[test]
    fn test_ack_miss_after_restart_defers_to_durable_store() {
        // With nothing restored, a miss must NOT be answered `NotProcessed` from
        // memory — it has to ask the platform's durable ACK store, which is what
        // makes dropping the snapshot safe.
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        let locks = std::collections::HashSet::new();

        mgr.ack_store.mark_processed("msg-seen-before-restart");
        let bytes = mgr.export_orchestrator_state_cfe(&locks).unwrap();

        let fresh_client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut restarted = SessionLifecycleManager::new(fresh_client, "alice".to_string());
        restarted.import_orchestrator_state_cfe(&bytes).unwrap();

        assert_eq!(
            restarted.ack_store.is_processed("msg-seen-before-restart"),
            crate::orchestration::AckCheckResult::NeedDbCheck,
            "must defer to the durable store, not silently re-process"
        );
        assert_eq!(restarted.ack_store.cache_len(), 0);
    }

    #[test]
    fn print_session_payload_sizes() {
        let (alice, _bob, _alice_id, bob_device_id) = make_session_pair();
        let cfe_bytes = alice.export_session_bytes_for(&bob_device_id).unwrap();
        let json_str = alice.export_session_json_for(&bob_device_id).unwrap();
        eprintln!("CFE bytes: {} bytes", cfe_bytes.len());
        eprintln!("JSON bytes: {} bytes", json_str.len());
        eprintln!(
            "JSON/CFE ratio: {:.1}x",
            json_str.len() as f64 / cfe_bytes.len() as f64
        );
    }
}
