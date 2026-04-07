/// Session Lifecycle Manager — Rust port of Swift `CryptoManager`.
///
/// Owns the `ClassicClient` and orchestrates:
/// - Encrypt / Decrypt with automatic session restore from archive
/// - Session archiving (retire → store JSON → GC)
/// - Prekey change detection (reinstall)
/// - Integration of AckStore, HealingQueue, PQContributionManager
///
/// All I/O is delegated via `Vec<Action>` returns; this struct is pure state.
use std::collections::HashMap;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::client_api::ClassicClient;
use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::orchestration::ack_store::AckStore;
use crate::orchestration::actions::Action;
use crate::orchestration::clock::{Clock, system_clock};
use crate::orchestration::healing_queue::HealingQueue;
use crate::orchestration::pq_contribution::PQContributionManager;

type HmacSha256 = Hmac<Sha256>;

// ── Constants ─────────────────────────────────────────────────────────────────

const ARCHIVE_GC_AGE_SECONDS: u64 = 24 * 60 * 60; // 24 h

// ── Result types ──────────────────────────────────────────────────────────────

/// Returned by `encrypt`.
#[derive(Debug, Clone)]
pub struct EncryptResult {
    /// JSON-encoded `EncryptedRatchetMessage` ready for wire transmission.
    pub ciphertext_json: String,
    /// Actions the platform must execute (e.g. save updated session state).
    pub actions: Vec<Action>,
}

/// Returned by `decrypt`.
#[derive(Debug, Clone)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    /// Actions the platform must execute after successful decryption.
    pub actions: Vec<Action>,
}

// ── Serializable wire message ─────────────────────────────────────────────────

/// JSON-serializable form of `EncryptedRatchetMessage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    pub dh_public_key: Vec<u8>,
    pub message_number: u32,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub previous_chain_length: u32,
    pub suite_id: u16,
}

impl From<EncryptedRatchetMessage> for WireMessage {
    fn from(m: EncryptedRatchetMessage) -> Self {
        Self {
            dh_public_key: m.dh_public_key.to_vec(),
            message_number: m.message_number,
            ciphertext: m.ciphertext,
            nonce: m.nonce,
            previous_chain_length: m.previous_chain_length,
            suite_id: m.suite_id,
        }
    }
}

impl TryFrom<WireMessage> for EncryptedRatchetMessage {
    type Error = String;
    fn try_from(w: WireMessage) -> Result<Self, String> {
        let dh: [u8; 32] = w
            .dh_public_key
            .try_into()
            .map_err(|_| "dh_public_key must be 32 bytes".to_string())?;
        Ok(EncryptedRatchetMessage {
            dh_public_key: dh,
            message_number: w.message_number,
            ciphertext: w.ciphertext,
            nonce: w.nonce,
            previous_chain_length: w.previous_chain_length,
            suite_id: w.suite_id,
        })
    }
}

// ── Serializable state (export / import) ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LifecycleState {
    my_user_id: String,
    archives: HashMap<String, String>,
    archive_timestamps: HashMap<String, u64>,
    prekey_tracker: HashMap<String, u32>,
}

// ── SessionLifecycleManager ───────────────────────────────────────────────────

pub struct SessionLifecycleManager {
    pub(crate) client: ClassicClient<ClassicSuiteProvider>,
    pub ack_store: AckStore,
    pub healing_queue: HealingQueue,
    pub pq_manager: PQContributionManager,
    /// contactId → archived session JSON (latest archive only).
    archives: HashMap<String, String>,
    /// contactId → Unix timestamp of the archive (for GC).
    archive_timestamps: HashMap<String, u64>,
    /// contactId → last seen OTPK ID (used to detect reinstall).
    prekey_tracker: HashMap<String, u32>,
    my_user_id: String,
    clock: Arc<dyn Clock>,
}

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
            healing_queue: HealingQueue::new_with_clock(3, 24 * 60 * 60, clock.clone()),
            pq_manager: PQContributionManager::new(),
            archives: HashMap::new(),
            archive_timestamps: HashMap::new(),
            prekey_tracker: HashMap::new(),
            my_user_id,
            clock,
        }
    }

    // ── Archive integrity (HMAC-SHA256) ─────────────────────────────────────
    //
    // Archives are session-state blobs stored in Keychain. Bit-rot, partial
    // writes during a crash, or Keychain corruption can silently produce a
    // malformed JSON that confuses the Double-Ratchet importer and sends the
    // session into an endless heal loop. We protect against this by wrapping
    // the JSON in an HMAC envelope using the device identity key.
    //
    // Envelope format:  "<hex(hmac32)>:<json>"
    // The colon is safe as a separator because JSON never starts with `:`.

    fn identity_key_bytes(&self) -> Vec<u8> {
        let km = self.client.key_manager();
        if let Ok(secret) = km.identity_secret_key() {
            <_ as AsRef<[u8]>>::as_ref(secret).to_vec()
        } else {
            // Fallback: derive a stable key from the user-id (never empty).
            self.my_user_id.as_bytes().to_vec()
        }
    }

    fn hmac_sign(&self, data: &[u8]) -> [u8; 32] {
        let key = self.identity_key_bytes();
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    fn wrap_archive(&self, json: &str) -> String {
        let mac = self.hmac_sign(json.as_bytes());
        format!("{}:{}", hex::encode(mac), json)
    }

    /// Verify envelope integrity and return the inner JSON.
    /// Returns `Err` if the envelope is malformed or the HMAC does not match.
    fn unwrap_archive<'a>(&self, envelope: &'a str) -> Result<&'a str, String> {
        // Legacy archives (created before this check was added) have no `:`
        // prefix with a 64-char hex tag. Accept them as-is to avoid breaking
        // existing users on upgrade; they will be re-written with a valid MAC
        // on the next `archive_session` call.
        let Some(colon_pos) = envelope.find(':') else {
            return Ok(envelope); // legacy — no MAC prefix
        };
        let maybe_hex = &envelope[..colon_pos];
        if maybe_hex.len() != 64 || !maybe_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(envelope); // legacy JSON that happens to contain a colon
        }
        let json = &envelope[colon_pos + 1..];
        let expected = self.hmac_sign(json.as_bytes());
        let actual =
            hex::decode(maybe_hex).map_err(|e| format!("archive MAC decode error: {e}"))?;
        if actual != expected.as_ref() {
            return Err(
                "archive integrity check failed — possible Keychain corruption".to_string(),
            );
        }
        Ok(json)
    }

    // ── Session queries ───────────────────────────────────────────────────────

    pub fn has_active_session(&self, contact_id: &str) -> bool {
        self.client.has_session(contact_id)
    }

    pub fn has_archive(&self, contact_id: &str) -> bool {
        self.archives.contains_key(contact_id)
    }

    pub fn my_user_id(&self) -> &str {
        &self.my_user_id
    }

    /// Update the local user-id on both the lifecycle manager and the
    /// underlying `ClassicClient`.  Both fields must stay in sync so that
    /// newly created sessions bake in the correct sender/receiver ID.
    pub fn set_my_user_id(&mut self, user_id: String) {
        self.my_user_id = user_id.clone();
        self.client.set_local_user_id(user_id);
    }

    // ── Encrypt ───────────────────────────────────────────────────────────────

    /// Encrypt `plaintext` for `contact_id`.
    ///
    /// If no active session exists but an archive is available, it is restored
    /// in-memory (the caller must have pre-loaded the archive JSON via
    /// `restore_latest_archive`).
    ///
    /// Returns `EncryptResult` with ciphertext JSON and follow-up `Action`s
    /// (always includes `SaveSessionToSecureStore` to persist the updated session).
    pub fn encrypt(&mut self, contact_id: &str, plaintext: &[u8]) -> Result<EncryptResult, String> {
        // Ensure session is loaded.
        if !self.client.has_session(contact_id) {
            return Err(format!(
                "No active session for {}: call restore_latest_archive first",
                contact_id
            ));
        }

        let encrypted = self.client.encrypt_message(contact_id, plaintext)?;
        let wire: WireMessage = encrypted.into();
        let ciphertext_json =
            serde_json::to_string(&wire).map_err(|e| format!("serialize: {}", e))?;

        // Always save updated session state after encrypt.
        let session_json = self.export_session_json_for(contact_id)?;
        let actions = vec![Action::SaveSessionToSecureStore {
            key: session_key(contact_id),
            data: session_json.into_bytes(),
        }];

        Ok(EncryptResult {
            ciphertext_json,
            actions,
        })
    }

    // ── Decrypt ───────────────────────────────────────────────────────────────

    /// Decrypt a wire-format message for `contact_id`.
    ///
    /// `wire_json` is a JSON-encoded `WireMessage`.
    ///
    /// On success, returns `DecryptResult` with plaintext and follow-up actions
    /// (save updated session). On failure, returns `Err` so the caller (Phase 4
    /// `MessageRouter`) can decide on healing or END_SESSION.
    pub fn decrypt(&mut self, contact_id: &str, wire_json: &str) -> Result<DecryptResult, String> {
        let wire: WireMessage =
            serde_json::from_str(wire_json).map_err(|e| format!("parse wire: {}", e))?;
        let msg = EncryptedRatchetMessage::try_from(wire)?;

        if !self.client.has_session(contact_id) {
            return Err(format!("No active session for {}", contact_id));
        }

        let plaintext = self.client.decrypt_message(contact_id, &msg)?;

        // Persist updated session state.
        let session_json = self.export_session_json_for(contact_id)?;
        let actions = vec![Action::SaveSessionToSecureStore {
            key: session_key(contact_id),
            data: session_json.into_bytes(),
        }];

        Ok(DecryptResult { plaintext, actions })
    }

    /// Decrypt using a binary WirePayload blob (no JSON round-trip).
    ///
    /// Functionally equivalent to `decrypt` but bypasses JSON serialization.
    /// The payload is the raw wire format produced by `wire_payload::pack`.
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
        };

        if !self.client.has_session(contact_id) {
            return Err(format!("No active session for {}", contact_id));
        }

        let plaintext = self.client.decrypt_message(contact_id, &msg)?;

        let session_json = self.export_session_json_for(contact_id)?;
        let actions = vec![Action::SaveSessionToSecureStore {
            key: session_key(contact_id),
            data: session_json.into_bytes(),
        }];

        Ok(DecryptResult { plaintext, actions })
    }

    // ── Archive lifecycle ─────────────────────────────────────────────────────

    /// Serialize the active session for `contact_id` into the in-memory archive
    /// and remove it from the active session map.
    ///
    /// Returns `Action`s to persist the archive and delete the hot session.
    pub fn archive_session(&mut self, contact_id: &str) -> Vec<Action> {
        let json = match self.export_session_json_for(contact_id) {
            Ok(j) => j,
            Err(_) => return vec![],
        };

        // Wrap with HMAC to detect Keychain corruption on restore.
        let envelope = self.wrap_archive(&json);

        self.archives
            .insert(contact_id.to_string(), envelope.clone());
        self.archive_timestamps
            .insert(contact_id.to_string(), self.clock.now_secs());
        self.client.remove_session(contact_id);

        vec![
            // Persist archive under a separate key.
            Action::SaveSessionToSecureStore {
                key: archive_key(contact_id),
                data: envelope.into_bytes(),
            },
            // Delete the hot session from secure store.
            Action::SaveSessionToSecureStore {
                key: session_key(contact_id),
                data: vec![], // empty = delete sentinel
            },
        ]
    }

    /// Restore the latest archive for `contact_id` into the active session map.
    ///
    /// The archive JSON must already be in memory (either via a previous
    /// `archive_session` call or loaded from the platform store via
    /// `load_archive_json`).
    pub fn restore_latest_archive(&mut self, contact_id: &str) -> Result<(), String> {
        let envelope = self
            .archives
            .get(contact_id)
            .cloned()
            .ok_or_else(|| format!("No archive for {}", contact_id))?;
        let json = self.unwrap_archive(&envelope)?;
        self.import_session_json(contact_id, json)?;
        Ok(())
    }

    /// Feed an archive JSON/envelope loaded from the platform secure store into memory.
    pub fn load_archive_json(&mut self, contact_id: &str, envelope: String) {
        // Verify integrity before importing the session; if the envelope is
        // corrupted we still store it (so restore_latest_archive can return a
        // meaningful error) but we don't import a broken session into memory.
        match self.unwrap_archive(&envelope) {
            Ok(json) => {
                let _ = self.import_session_json(contact_id, json);
            }
            Err(e) => {
                // Log via debug; will surface as Err from restore_latest_archive.
                let _ = e; // suppress unused warning; platform will handle via restore error
            }
        }
        self.archives.insert(contact_id.to_string(), envelope);
    }

    /// Feed an archive from CFE binary bytes into memory (preferred over `load_archive_json`).
    pub fn load_archive_bytes(&mut self, contact_id: &str, data: Vec<u8>) {
        // Decode CFE binary → import session (has LegacyJson fallback inside import_session).
        if let Ok(json_str) = self.import_session_bytes(contact_id, &data) {
            // Mirror into the JSON archive map so restore_latest_archive still works.
            self.archives.insert(contact_id.to_string(), json_str);
        }
    }

    /// Garbage-collect archives older than 24 h.
    ///
    /// Returns `Action`s requesting the platform to delete the stale records.
    pub fn gc_old_archives(&mut self) -> Vec<Action> {
        let cutoff = self.clock.now_secs().saturating_sub(ARCHIVE_GC_AGE_SECONDS);
        let expired: Vec<String> = self
            .archive_timestamps
            .iter()
            .filter(|&(_, &ts)| ts < cutoff)
            .map(|(k, _)| k.clone())
            .collect();

        let mut actions = Vec::new();
        for contact_id in &expired {
            self.archives.remove(contact_id);
            self.archive_timestamps.remove(contact_id);
            actions.push(Action::SaveSessionToSecureStore {
                key: archive_key(contact_id),
                data: vec![], // empty = delete sentinel
            });
        }
        actions
    }

    // ── Prekey tracking ───────────────────────────────────────────────────────

    /// Record the OTPK ID used to initiate a session with `contact_id`.
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

    /// Apply a deferred PQ contribution for `contact_id` (if one exists).
    ///
    /// Returns `Vec<Action>` — empty if no contribution was pending.
    pub fn maybe_apply_pq_contribution(&mut self, contact_id: &str) -> Vec<Action> {
        let (contribution, delete_actions) = self.pq_manager.consume_deferred(contact_id);
        let contribution = match contribution {
            Some(c) => c,
            None => return vec![],
        };
        if let Err(e) = self
            .client
            .apply_pq_contribution_to_session(contact_id, &contribution.shared_secret)
        {
            return vec![Action::NotifyError {
                code: "PQ_CONTRIBUTION_FAILED".to_string(),
                message: e,
            }];
        }
        // Save updated session state and delete the now-consumed deferred entry.
        match self.export_session_json_for(contact_id) {
            Ok(json) => {
                let mut actions = delete_actions;
                actions.push(Action::SaveSessionToSecureStore {
                    key: session_key(contact_id),
                    data: json.into_bytes(),
                });
                actions
            }
            Err(e) => vec![Action::NotifyError {
                code: "SESSION_EXPORT_FAILED".to_string(),
                message: e,
            }],
        }
    }

    // ── State persistence ─────────────────────────────────────────────────────

    /// Export non-crypto orchestration state to JSON.
    ///
    /// This does NOT include session keys (those are persisted separately via
    /// `Action::SaveSessionToSecureStore`). Use this to snapshot coordinator
    /// metadata (archives index, prekey tracker, user ID).
    pub fn export_state_json(&self) -> Result<String, String> {
        let state = LifecycleState {
            my_user_id: self.my_user_id.clone(),
            archives: self.archives.clone(),
            archive_timestamps: self.archive_timestamps.clone(),
            prekey_tracker: self.prekey_tracker.clone(),
        };
        serde_json::to_string(&state).map_err(|e| format!("export_state_json: {}", e))
    }

    /// Restore orchestration metadata from a previously exported JSON snapshot.
    pub fn import_state_json(&mut self, json: &str) -> Result<(), String> {
        let state: LifecycleState =
            serde_json::from_str(json).map_err(|e| format!("import_state_json: {}", e))?;
        self.my_user_id = state.my_user_id;
        self.archives = state.archives;
        self.archive_timestamps = state.archive_timestamps;
        self.prekey_tracker = state.prekey_tracker;
        Ok(())
    }

    /// Export the Kyber `PQContributionManager` state as a CFE binary blob.
    ///
    /// The caller should persist the returned bytes under the well-known key
    /// `"kyber_session_state"` via `SaveSessionToSecureStore`.
    pub fn export_kyber_session_state_cfe(&self) -> Result<Vec<u8>, String> {
        self.pq_manager.export_cfe()
    }

    /// Restore the Kyber `PQContributionManager` state from a CFE binary blob.
    ///
    /// Any previously-loaded state (including in-progress SPK rotations) is
    /// replaced.  Returns an error if the blob is malformed.
    pub fn import_kyber_session_state_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        self.pq_manager.import_cfe(data)
    }

    /// Export the full orchestrator coordination state (ACK cache, healing queue,
    /// archive index, prekey tracker) as a CFE binary blob — msg_type 0x05.
    ///
    /// `init_locks` is managed by `OrchestratorCore`; pass the current set here.
    /// The caller should persist the blob under `"orchestrator_state"` via
    /// `SaveSessionToSecureStore` after every significant state change.
    pub fn export_orchestrator_state_cfe(
        &self,
        init_locks: &std::collections::HashSet<String>,
    ) -> Result<Vec<u8>, String> {
        use crate::cfe::{
            CfeAckRecordV1, CfeHealingRecordV1, CfeMessageType, CfeOrchestratorStateV1,
        };
        use base64::Engine as _;

        let state = CfeOrchestratorStateV1 {
            ver: 1,
            my_user_id: self.my_user_id.clone(),
            processed_ids: self
                .ack_store
                .snapshot_cache()
                .into_iter()
                .map(|id| CfeAckRecordV1 { message_id: id })
                .collect(),
            healing_records: self
                .healing_queue
                .snapshot_records()
                .into_iter()
                .map(|r| CfeHealingRecordV1 {
                    contact_id: r.contact_id.clone(),
                    message_b64: base64::engine::general_purpose::STANDARD
                        .encode(&r.message_payload),
                    attempts: r.attempts,
                    created_at: r.created_at,
                })
                .collect(),
            init_locks: init_locks.iter().cloned().collect(),
            archives: self
                .archives
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            archive_timestamps: self
                .archive_timestamps
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            prekey_tracker: self
                .prekey_tracker
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
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
        use crate::orchestration::healing_queue::HealingRecord;
        use base64::Engine as _;

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

        // Restore healing queue.
        self.healing_queue.restore_records(
            state
                .healing_records
                .into_iter()
                .map(|r| HealingRecord {
                    contact_id: r.contact_id,
                    message_payload: base64::engine::general_purpose::STANDARD
                        .decode(&r.message_b64)
                        .unwrap_or_default(),
                    attempts: r.attempts,
                    created_at: r.created_at,
                })
                .collect(),
        );

        // Restore archive index and prekey tracker.
        self.archives = state.archives.into_iter().collect();
        self.archive_timestamps = state.archive_timestamps.into_iter().collect();
        self.prekey_tracker = state.prekey_tracker.into_iter().collect();

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

    pub fn import_session_json(&mut self, contact_id: &str, json: &str) -> Result<String, String> {
        use crate::crypto::messaging::double_ratchet::{DoubleRatchetSession, SerializableSession};

        let serializable: SerializableSession =
            serde_json::from_str(json).map_err(|e| format!("deserialize session: {}", e))?;
        let ratchet =
            DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(serializable)?;
        let session_id = self.client.import_session(contact_id, ratchet);
        Ok(session_id)
    }

    /// Import a session from CFE binary bytes (preferred over `import_session_json`).
    /// Returns the JSON-serialised session string for archive mirroring.
    pub fn import_session_bytes(
        &mut self,
        contact_id: &str,
        data: &[u8],
    ) -> Result<String, String> {
        use crate::cfe::{CfeError, CfeMessageType, decode_as};
        use crate::crypto::messaging::double_ratchet::{DoubleRatchetSession, SerializableSession};

        let serializable =
            match decode_as::<crate::cfe::CfeSessionStateV1>(data, CfeMessageType::SessionState) {
                Ok(cfe_state) => SerializableSession::from_cfe_v1(cfe_state)
                    .map_err(|e| format!("from_cfe_v1: {}", e))?,
                Err(CfeError::LegacyJson) => {
                    let s = std::str::from_utf8(data).map_err(|_| "not utf8".to_string())?;
                    serde_json::from_str(s).map_err(|e| format!("json fallback: {}", e))?
                }
                Err(e) => return Err(format!("decode_as: {}", e)),
            };

        // Mirror into JSON archive map for restore_latest_archive compat.
        let json =
            serde_json::to_string(&serializable).map_err(|e| format!("re-serialize: {}", e))?;
        let ratchet = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(serializable)
            .map_err(|e| format!("from_serializable: {}", e))?;
        self.client.import_session(contact_id, ratchet);
        Ok(json)
    }
}

// ── Key helpers ───────────────────────────────────────────────────────────────

pub fn session_key(contact_id: &str) -> String {
    format!("session_{}", contact_id)
}

pub fn archive_key(contact_id: &str) -> String {
    format!("archive_{}", contact_id)
}

#[cfg(test)]
fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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

    #[test]
    fn test_new_manager_has_no_sessions() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mgr = SessionLifecycleManager::new(client, "alice".to_string());
        assert!(!mgr.has_active_session("bob"));
        assert!(!mgr.has_archive("bob"));
        assert_eq!(mgr.my_user_id(), "alice");
    }

    #[test]
    fn test_encrypt_without_session_returns_error() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        let result = mgr.encrypt("bob", b"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No active session"));
    }

    #[test]
    fn test_decrypt_without_session_returns_error() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        let result = mgr.decrypt("bob", r#"{"msg":"fake"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_restore_archive_without_archive_returns_error() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        assert!(mgr.restore_latest_archive("bob").is_err());
    }

    #[test]
    fn test_gc_empty_archives_is_noop() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        let actions = mgr.gc_old_archives();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_gc_removes_old_archives() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        // Inject an archive with a stale timestamp.
        mgr.archives.insert("bob".to_string(), "{}".to_string());
        mgr.archive_timestamps.insert("bob".to_string(), 0);

        let actions = mgr.gc_old_archives();
        assert!(!actions.is_empty());
        assert!(!mgr.has_archive("bob"));
    }

    #[test]
    fn test_gc_keeps_fresh_archives() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        mgr.archives.insert("bob".to_string(), "{}".to_string());
        mgr.archive_timestamps.insert("bob".to_string(), unix_now());

        mgr.gc_old_archives();
        assert!(mgr.has_archive("bob"));
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
    fn test_export_import_state_json() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        mgr.track_prekey("bob", 5);
        mgr.archives.insert("carol".to_string(), "{}".to_string());

        let json = mgr.export_state_json().unwrap();
        assert!(json.contains("alice"));
        assert!(json.contains("carol"));

        let client2 = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr2 = SessionLifecycleManager::new(client2, "initial".to_string());
        mgr2.import_state_json(&json).unwrap();
        assert_eq!(mgr2.my_user_id(), "alice");
        assert!(mgr2.has_archive("carol"));
        assert!(!mgr2.is_reinstall("bob", 5)); // prekey tracker restored
        assert!(mgr2.is_reinstall("bob", 99));
    }

    #[test]
    fn test_session_and_archive_keys() {
        assert_eq!(session_key("alice"), "session_alice");
        assert_eq!(archive_key("alice"), "archive_alice");
    }

    #[test]
    fn test_maybe_apply_pq_contribution_no_pending() {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        let mut mgr = SessionLifecycleManager::new(client, "alice".to_string());
        let actions = mgr.maybe_apply_pq_contribution("bob");
        assert!(actions.is_empty());
    }

    #[test]
    fn test_wire_message_roundtrip() {
        let original = EncryptedRatchetMessage {
            dh_public_key: [42u8; 32],
            message_number: 7,
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            previous_chain_length: 0,
            suite_id: 1,
        };
        let wire: WireMessage = original.clone().into();
        let json = serde_json::to_string(&wire).unwrap();
        let wire2: WireMessage = serde_json::from_str(&json).unwrap();
        let restored = EncryptedRatchetMessage::try_from(wire2).unwrap();
        assert_eq!(restored.dh_public_key, original.dh_public_key);
        assert_eq!(restored.message_number, original.message_number);
        assert_eq!(restored.ciphertext, original.ciphertext);
    }
}
