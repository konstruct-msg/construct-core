/// PQ Contribution Manager — Rust port of Swift `PQCKeyManager` +
/// the PQ-specific parts of `SessionInitializationService`.
///
/// Manages the two-phase ML-KEM-768 (Kyber) contribution to Double Ratchet sessions:
///
/// **Sender (INITIATOR) flow:**
/// 1. `encapsulate_and_defer(contact_id, kem_public, recipient_otpk_id)` — encapsulate to the
///    recipient's Kyber OTPK, store shared secret + ciphertext locally.
/// 2. After the session's first message is confirmed received, call
///    `consume_deferred(contact_id)` to retrieve the contribution for
///    `apply_pq_contribution`.
///
/// **Receiver (RESPONDER) flow:**
/// 1. `decapsulate_and_store(contact_id, kem_ciphertext, otpk_id)` — decapsulate
///    the received KEM ciphertext using the private OTPK. Stores the shared
///    secret for subsequent `apply_pq_contribution`.
/// 2. Call `consume_deferred(contact_id)` to retrieve the shared secret.
///
/// **SPK rotation:**
/// `begin_spk_rotation` → upload new SPK to server → `commit_spk_rotation`.
/// If the upload fails, call `rollback_spk_rotation`.
use std::collections::HashMap;

use crate::orchestration::actions::Action;

// ── Public types ──────────────────────────────────────────────────────────────

/// Contains the KEM ciphertext to include in the first message and the shared
/// secret deferred for `apply_pq_contribution`.
#[derive(Debug, Clone)]
pub struct EncapsulationResult {
    /// ML-KEM-768 ciphertext (1 088 bytes) — embed in PreKeySignalMessage.
    pub ciphertext: Vec<u8>,
    /// The associated Kyber OTPK ID used.
    pub otpk_id: u32,
}

/// The deferred contribution retrieved by `consume_deferred`.
#[derive(Debug, Clone)]
pub struct DeferredContribution {
    pub shared_secret: Vec<u8>,
    pub otpk_id: u32,
}

/// New SPK data returned by `begin_spk_rotation` — upload to key server.
#[derive(Debug, Clone)]
pub struct SPKRotationPending {
    pub new_public: Vec<u8>,
    pub new_secret: Vec<u8>,
    pub new_id: u32,
}

// ── Internal record ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PendingContribution {
    shared_secret: Vec<u8>,
    otpk_id: u32,
}

// ── PQContributionManager ─────────────────────────────────────────────────────

pub struct PQContributionManager {
    /// Per-contact deferred shared secrets (set by encapsulate or decapsulate).
    pending: HashMap<String, PendingContribution>,
    /// KEM ciphertexts waiting to be sent (sender side).
    pending_ciphertexts: HashMap<String, Vec<u8>>,
    /// In-progress SPK rotation, if any.
    spk_rotation: Option<SPKRotationPending>,
    /// Next OTPK ID to allocate (monotonically increasing).
    next_otpk_id: u32,
}

impl PQContributionManager {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            pending_ciphertexts: HashMap::new(),
            spk_rotation: None,
            next_otpk_id: 1,
        }
    }

    // ── Sender flow ───────────────────────────────────────────────────────────

    /// Encapsulate to `kem_public` and defer the shared secret for later application.
    ///
    /// `recipient_otpk_id` is the Kyber OTPK ID from the recipient's key bundle;
    /// it is stored and returned by `take_pending_ciphertext` so that the wire
    /// payload carries the correct key reference for the recipient to look up.
    ///
    /// The returned `EncapsulationResult` contains the ciphertext that must be
    /// included in the initial message. The shared secret is stored internally
    /// and retrieved via `consume_deferred` once the session is initialised.
    ///
    /// The returned `Vec<Action>` contains a `SaveSessionToSecureStore` action
    /// that the platform **must** execute to persist the deferred contribution
    /// across process restarts.  Key format: `"pq_deferred_<contact_id>"`,
    /// data: `otpk_id (4 bytes LE) || shared_secret`.
    ///
    /// Calls the actual ML-KEM-768 primitive from `crate::crypto::pq_x3dh`
    /// when the `post-quantum` feature is enabled; otherwise returns an error.
    pub fn encapsulate_and_defer(
        &mut self,
        contact_id: &str,
        kem_public: &[u8],
        recipient_otpk_id: u32,
    ) -> Result<(EncapsulationResult, Vec<Action>), String> {
        let (ciphertext, shared_secret) = pq_encapsulate(kem_public)?;

        let persist_action =
            serialize_pending_action(contact_id, recipient_otpk_id, &shared_secret);

        self.pending.insert(
            contact_id.to_string(),
            PendingContribution {
                shared_secret,
                otpk_id: recipient_otpk_id,
            },
        );
        self.pending_ciphertexts
            .insert(contact_id.to_string(), ciphertext.clone());

        Ok((
            EncapsulationResult {
                ciphertext,
                otpk_id: recipient_otpk_id,
            },
            vec![persist_action],
        ))
    }

    // ── Receiver flow ─────────────────────────────────────────────────────────

    /// Decapsulate the received `kem_ciphertext` using the responder's secret key.
    ///
    /// `kem_secret` is the ML-KEM-768 secret key loaded from the platform
    /// secure store by the caller. The shared secret is stored and returned
    /// via `consume_deferred`.
    ///
    /// The returned `Vec<Action>` contains a `SaveSessionToSecureStore` action
    /// that the platform **must** execute to persist the deferred contribution
    /// across process restarts.  Key format: `"pq_deferred_<contact_id>"`.
    pub fn decapsulate_and_store(
        &mut self,
        contact_id: &str,
        kem_ciphertext: &[u8],
        kem_secret: &[u8],
        otpk_id: u32,
    ) -> Result<Vec<Action>, String> {
        let shared_secret = pq_decapsulate(kem_secret, kem_ciphertext)?;
        let persist_action = serialize_pending_action(contact_id, otpk_id, &shared_secret);
        self.pending.insert(
            contact_id.to_string(),
            PendingContribution {
                shared_secret,
                otpk_id,
            },
        );
        Ok(vec![persist_action])
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    /// Register an already-computed KEM shared secret as a deferred contribution.
    ///
    /// Use this when the KEM operation was performed externally (e.g. by a
    /// platform ML-KEM call) and the result needs to be stored in the manager
    /// so that it is included in CFE snapshots and consumed by
    /// `consume_deferred`.
    ///
    /// Returns a `SaveSessionToSecureStore` persist action with the same wire
    /// format as `encapsulate_and_defer` and `decapsulate_and_store`.
    pub fn register_shared_secret(
        &mut self,
        contact_id: &str,
        otpk_id: u32,
        shared_secret: &[u8],
    ) -> Action {
        let persist_action = serialize_pending_action(contact_id, otpk_id, shared_secret);
        self.pending.insert(
            contact_id.to_string(),
            PendingContribution {
                shared_secret: shared_secret.to_vec(),
                otpk_id,
            },
        );
        persist_action
    }

    /// Peek at the deferred contribution for `contact_id` without removing it.
    ///
    /// Returns `None` if no contribution is pending.  The caller should
    /// apply the contribution and persist the result, then call
    /// `finalize_consumed` to atomically clear the in-memory entry and
    /// obtain the delete + CFE export actions.
    ///
    /// This two-phase design prevents data loss on a crash between applying
    /// the PQ shared secret to the Double Ratchet state and persisting it:
    /// if the process dies before the platform executes the returned
    /// `SaveSessionToSecureStore` actions, the contribution survives in the
    /// `kyber_session_state` CFE snapshot and can be replayed on next launch.
    pub fn peek_deferred(&self, contact_id: &str) -> Option<DeferredContribution> {
        self.pending.get(contact_id).map(|c| DeferredContribution {
            shared_secret: c.shared_secret.clone(),
            otpk_id: c.otpk_id,
        })
    }

    /// Remove the deferred contribution after the caller has successfully
    /// applied and persisted the updated session state.
    ///
    /// Returns the `SaveSessionToSecureStore` delete sentinel (empty `data`)
    /// for the individual `pq_deferred_{contact_id}` Keychain / Keystore entry.
    /// The caller **must** also export a fresh `kyber_session_state` CFE
    /// (via `export_cfe`) and include it in the same persist batch so that
    /// a subsequent restart does not replay the already-applied contribution.
    ///
    /// No-op (returns empty Vec) if no pending contribution exists.
    pub fn finalize_consumed(&mut self, contact_id: &str) -> Vec<Action> {
        self.pending_ciphertexts.remove(contact_id);
        match self.pending.remove(contact_id) {
            None => vec![],
            Some(_) => vec![Action::SaveSessionToSecureStore {
                key: format!("pq_deferred_{}", contact_id),
                data: vec![],
            }],
        }
    }

    /// Retrieve and remove the deferred contribution for `contact_id`.
    ///
    /// **Prefer using `peek_deferred` + `finalize_consumed`** when you need
    /// crash-safe transactional semantics (apply, persist, then finalize).
    /// Use this method only when the caller already holds a separate
    /// guarantee that the contribution was handled (e.g. Swift-side Keychain
    /// cleanup has already run before this call).
    ///
    /// Returns `(None, [])` if no deferred contribution exists (caller should
    /// skip `apply_pq_contribution`).
    pub fn consume_deferred(
        &mut self,
        contact_id: &str,
    ) -> (Option<DeferredContribution>, Vec<Action>) {
        let contribution = self.peek_deferred(contact_id);
        let delete_actions = self.finalize_consumed(contact_id);
        (contribution, delete_actions)
    }

    /// Consume the pending PQXDH contribution for sending the first message (msgNum=0).
    ///
    /// Returns `(kem_ciphertext, kyber_otpk_id, shared_secret)`.  The caller MUST:
    /// 1. Apply `shared_secret` to the DR session (via `apply_pq_contribution_to_session`)
    ///    **before** calling `encrypt_message` so the PQ SS is mixed into the root key.
    /// 2. Include `kem_ciphertext` in the wire payload so the RESPONDER can decapsulate.
    ///
    /// All three values are `None`/0/empty when no pending contribution exists.
    pub fn take_contribution_for_first_message(
        &mut self,
        contact_id: &str,
    ) -> (Option<Vec<u8>>, u32, Option<Vec<u8>>) {
        let ct = self.pending_ciphertexts.remove(contact_id);
        match self.pending.remove(contact_id) {
            None => (ct, 0, None),
            Some(c) => (ct, c.otpk_id, Some(c.shared_secret)),
        }
    }

    /// Consume only the pending KEM ciphertext for `contact_id`, leaving the
    /// shared secret (`pending`) intact for later application via `consume_deferred`.
    ///
    /// This is called when packing the first outgoing message (msgNum=0): the
    /// ciphertext must be included in the wire payload, but the SS must not be
    /// applied until `maybe_apply_pq_contribution` processes the sent message.
    ///
    /// Returns `(ciphertext, kyber_otpk_id)`. Both fields are `None`/0 when no
    /// pending ciphertext exists for this contact.
    pub fn take_pending_ciphertext(&mut self, contact_id: &str) -> (Option<Vec<u8>>, u32) {
        let ct = self.pending_ciphertexts.remove(contact_id);
        let otpk_id = self.pending.get(contact_id).map(|c| c.otpk_id).unwrap_or(0);
        (ct, otpk_id)
    }

    /// `true` if there is a pending contribution for `contact_id`.
    pub fn has_pending(&self, contact_id: &str) -> bool {
        self.pending.contains_key(contact_id)
    }

    // ── SPK rotation ──────────────────────────────────────────────────────────

    /// Prepare a new Signed Pre-Key rotation.
    ///
    /// Generates a new ML-KEM-768 keypair and stores the pending rotation.
    /// The caller must upload `SPKRotationPending.new_public` to the server
    /// before calling `commit_spk_rotation`.
    ///
    /// Returns an error if a rotation is already in progress.
    pub fn begin_spk_rotation(&mut self) -> Result<SPKRotationPending, String> {
        if self.spk_rotation.is_some() {
            return Err("SPK rotation already in progress".to_string());
        }
        let (public, secret) = pq_keygen()?;
        let pending = SPKRotationPending {
            new_public: public,
            new_secret: secret,
            new_id: self.allocate_otpk_id(),
        };
        self.spk_rotation = Some(pending.clone());
        Ok(pending)
    }

    /// Commit the pending SPK rotation after successful server upload.
    ///
    /// Returns `Action`s requesting the platform to persist the new secret key.
    pub fn commit_spk_rotation(&mut self) -> Vec<Action> {
        match self.spk_rotation.take() {
            None => vec![],
            Some(pending) => vec![Action::SaveSessionToSecureStore {
                key: format!("kyber_spk_{}", pending.new_id),
                data: pending.new_secret,
            }],
        }
    }

    /// Abort the pending SPK rotation (e.g. server upload failed).
    pub fn rollback_spk_rotation(&mut self) {
        self.spk_rotation = None;
    }

    /// `true` if an SPK rotation is currently in progress.
    pub fn is_rotation_pending(&self) -> bool {
        self.spk_rotation.is_some()
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn allocate_otpk_id(&mut self) -> u32 {
        let id = self.next_otpk_id;
        self.next_otpk_id += 1;
        id
    }

    // ── CFE serialization ─────────────────────────────────────────────────────

    /// Serialize the complete manager state to a CFE binary blob
    /// (`KyberSessionState` / msg_type 0x21).
    ///
    /// The caller should persist the returned bytes via
    /// `SaveSessionToSecureStore { key: "kyber_session_state", data: ... }`
    /// after any state change.
    pub fn export_cfe(&self) -> Result<Vec<u8>, String> {
        use crate::cfe::{CfeKyberDeferredEntryV1, CfeKyberSessionStateV1, CfeMessageType};
        use serde_bytes::ByteBuf;

        let entries: Vec<CfeKyberDeferredEntryV1> = self
            .pending
            .iter()
            .map(|(contact_id, c)| CfeKyberDeferredEntryV1 {
                contact_id: contact_id.clone(),
                otpk_id: c.otpk_id,
                shared_secret: ByteBuf::from(c.shared_secret.clone()),
            })
            .collect();

        let payload = CfeKyberSessionStateV1 {
            ver: 1,
            entries,
            next_otpk_id: self.next_otpk_id,
        };

        crate::cfe::encode(CfeMessageType::KyberSessionState, &payload).map_err(|e| e.to_string())
    }

    /// Restore manager state from a CFE binary blob produced by `export_cfe`.
    ///
    /// Replaces all in-memory state. The in-progress SPK rotation (if any) is
    /// discarded because it is never written to the CFE snapshot — a rotation
    /// that was in progress when the app was killed must be restarted.
    pub fn import_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        use crate::cfe::{CfeKyberSessionStateV1, CfeMessageType};

        let snapshot = crate::cfe::decode_as::<CfeKyberSessionStateV1>(
            data,
            CfeMessageType::KyberSessionState,
        )
        .map_err(|e| e.to_string())?;

        self.pending.clear();
        self.pending_ciphertexts.clear();
        self.spk_rotation = None;

        for entry in snapshot.entries {
            self.pending.insert(
                entry.contact_id,
                PendingContribution {
                    shared_secret: entry.shared_secret.into_vec(),
                    otpk_id: entry.otpk_id,
                },
            );
        }
        self.next_otpk_id = snapshot.next_otpk_id;
        Ok(())
    }
}

impl Default for PQContributionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Serialize a pending contribution to `Action::SaveSessionToSecureStore`.
/// Wire format: `otpk_id (4 bytes LE) || shared_secret`.
fn serialize_pending_action(contact_id: &str, otpk_id: u32, shared_secret: &[u8]) -> Action {
    let mut data = Vec::with_capacity(4 + shared_secret.len());
    data.extend_from_slice(&otpk_id.to_le_bytes());
    data.extend_from_slice(shared_secret);
    Action::SaveSessionToSecureStore {
        key: format!("pq_deferred_{}", contact_id),
        data,
    }
}

// ── Crypto primitives (feature-gated) ─────────────────────────────────────────

/// Encapsulate to `public_key`. Returns `(ciphertext, shared_secret)`.
fn pq_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    #[cfg(feature = "post-quantum")]
    {
        crate::crypto::pq_x3dh::mlkem768_encapsulate(public_key)
            .map(|enc| (enc.ciphertext, enc.shared_secret))
    }
    #[cfg(not(feature = "post-quantum"))]
    {
        // Stub for builds without the post-quantum feature.
        let _ = public_key;
        Err("post-quantum feature not enabled".to_string())
    }
}

/// Decapsulate `ciphertext` using `secret_key`. Returns shared secret.
fn pq_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(feature = "post-quantum")]
    {
        crate::crypto::pq_x3dh::mlkem768_decapsulate(secret_key, ciphertext)
    }
    #[cfg(not(feature = "post-quantum"))]
    {
        let _ = (secret_key, ciphertext);
        Err("post-quantum feature not enabled".to_string())
    }
}

/// Generate a fresh ML-KEM-768 keypair. Returns `(public_key, secret_key)`.
fn pq_keygen() -> Result<(Vec<u8>, Vec<u8>), String> {
    #[cfg(feature = "post-quantum")]
    {
        crate::crypto::pq_x3dh::mlkem768_keygen().map(|kp| (kp.public_key, kp.secret_key))
    }
    #[cfg(not(feature = "post-quantum"))]
    {
        Err("post-quantum feature not enabled".to_string())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SPK rotation tests (feature-independent) ──────────────────────────────

    #[test]
    fn test_no_pending_contribution_initially() {
        let mgr = PQContributionManager::new();
        assert!(!mgr.has_pending("alice"));
    }

    #[test]
    fn test_consume_deferred_returns_none_when_absent() {
        let mut mgr = PQContributionManager::new();
        let (result, actions) = mgr.consume_deferred("nobody");
        assert!(result.is_none());
        assert!(actions.is_empty());
    }

    #[test]
    fn test_commit_rotation_without_begin_returns_empty() {
        let mut mgr = PQContributionManager::new();
        assert!(mgr.commit_spk_rotation().is_empty());
    }

    #[test]
    fn test_rollback_clears_pending_rotation() {
        let mut mgr = PQContributionManager::new();
        // Inject fake rotation without calling begin_spk_rotation
        // (avoids needing post-quantum feature in unit tests).
        mgr.spk_rotation = Some(SPKRotationPending {
            new_public: vec![0u8; 32],
            new_secret: vec![1u8; 32],
            new_id: 1,
        });
        assert!(mgr.is_rotation_pending());
        mgr.rollback_spk_rotation();
        assert!(!mgr.is_rotation_pending());
    }

    #[test]
    fn test_commit_rotation_returns_save_action() {
        let mut mgr = PQContributionManager::new();
        mgr.spk_rotation = Some(SPKRotationPending {
            new_public: vec![0u8; 32],
            new_secret: vec![2u8; 32],
            new_id: 7,
        });
        let actions = mgr.commit_spk_rotation();
        assert_eq!(actions.len(), 1);
        matches!(
            &actions[0],
            Action::SaveSessionToSecureStore { key, .. } if key == "kyber_spk_7"
        );
        assert!(!mgr.is_rotation_pending());
    }

    #[test]
    fn test_begin_rotation_error_when_already_pending() {
        let mut mgr = PQContributionManager::new();
        mgr.spk_rotation = Some(SPKRotationPending {
            new_public: vec![],
            new_secret: vec![],
            new_id: 1,
        });
        let result = mgr.begin_spk_rotation();
        assert!(result.is_err());
    }

    #[test]
    fn test_otpk_id_is_monotonically_increasing() {
        let mut mgr = PQContributionManager::new();
        assert_eq!(mgr.allocate_otpk_id(), 1);
        assert_eq!(mgr.allocate_otpk_id(), 2);
        assert_eq!(mgr.allocate_otpk_id(), 3);
    }

    // ── Post-quantum encapsulate/decapsulate round-trip ───────────────────────
    #[cfg(feature = "post-quantum")]
    #[test]
    fn test_encapsulate_and_consume_roundtrip() {
        let kp = crate::crypto::pq_x3dh::mlkem768_keygen().unwrap();
        let mut mgr = PQContributionManager::new();
        let (result, persist_actions) = mgr
            .encapsulate_and_defer("bob", &kp.public_key, 42)
            .unwrap();
        assert!(!result.ciphertext.is_empty());
        assert_eq!(result.otpk_id, 42);
        assert_eq!(persist_actions.len(), 1);
        assert!(
            matches!(&persist_actions[0], Action::SaveSessionToSecureStore { key, data }
                if key == "pq_deferred_bob" && !data.is_empty()),
            "persist action must save deferred entry"
        );
        assert!(mgr.has_pending("bob"));

        let (deferred, delete_actions) = mgr.consume_deferred("bob");
        let deferred = deferred.unwrap();
        assert!(!deferred.shared_secret.is_empty());
        assert!(!mgr.has_pending("bob"));
        assert_eq!(delete_actions.len(), 1);
        assert!(
            matches!(&delete_actions[0], Action::SaveSessionToSecureStore { key, data }
                if key == "pq_deferred_bob" && data.is_empty()),
            "delete action must be empty-data sentinel"
        );

        // Verify decapsulate produces the same shared secret.
        let ss2 = pq_decapsulate(&kp.secret_key, &result.ciphertext).unwrap();
        assert_eq!(deferred.shared_secret, ss2);
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn test_decapsulate_and_store_returns_persist_action() {
        let kp = crate::crypto::pq_x3dh::mlkem768_keygen().unwrap();
        let mut mgr = PQContributionManager::new();

        // Build a ciphertext using the public key
        let enc = crate::crypto::pq_x3dh::mlkem768_encapsulate(&kp.public_key).unwrap();
        let actions = mgr
            .decapsulate_and_store("alice", &enc.ciphertext, &kp.secret_key, 42)
            .unwrap();
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], Action::SaveSessionToSecureStore { key, data }
                if key == "pq_deferred_alice" && !data.is_empty()),
            "decapsulate must return persist action"
        );
        assert!(mgr.has_pending("alice"));

        // Consume should return delete action
        let (deferred, delete_actions) = mgr.consume_deferred("alice");
        assert!(deferred.is_some());
        assert_eq!(delete_actions.len(), 1);
        assert!(
            matches!(&delete_actions[0], Action::SaveSessionToSecureStore { key, data }
                if key == "pq_deferred_alice" && data.is_empty()),
        );
    }

    // ── CFE roundtrip (feature-independent) ───────────────────────────────────

    #[test]
    fn test_export_import_cfe_empty() {
        let mgr = PQContributionManager::new();
        let blob = mgr.export_cfe().expect("export should succeed");
        let mut mgr2 = PQContributionManager::new();
        mgr2.import_cfe(&blob).expect("import should succeed");
        assert_eq!(mgr2.next_otpk_id, mgr.next_otpk_id);
        assert!(mgr2.pending.is_empty());
    }

    #[test]
    fn test_export_import_cfe_with_pending() {
        let mut mgr = PQContributionManager::new();
        // Inject a fake deferred contribution without needing the post-quantum feature.
        mgr.pending.insert(
            "test-contact".to_string(),
            PendingContribution {
                shared_secret: vec![0xAB; 32],
                otpk_id: 42,
            },
        );
        mgr.next_otpk_id = 100;

        let blob = mgr.export_cfe().expect("export should succeed");
        let mut mgr2 = PQContributionManager::new();
        mgr2.import_cfe(&blob).expect("import should succeed");

        assert_eq!(mgr2.next_otpk_id, 100);
        assert!(mgr2.has_pending("test-contact"));
        let (deferred, _) = mgr2.consume_deferred("test-contact");
        let d = deferred.unwrap();
        assert_eq!(d.otpk_id, 42);
        assert_eq!(d.shared_secret, vec![0xAB; 32]);
    }

    #[test]
    fn test_import_cfe_resets_spk_rotation() {
        let mut mgr = PQContributionManager::new();
        // Simulate a rotation in progress.
        mgr.spk_rotation = Some(SPKRotationPending {
            new_public: vec![1u8; 32],
            new_secret: vec![2u8; 32],
            new_id: 5,
        });
        let blob = mgr.export_cfe().unwrap();

        let mut mgr2 = PQContributionManager::new();
        mgr2.spk_rotation = Some(SPKRotationPending {
            new_public: vec![],
            new_secret: vec![],
            new_id: 99,
        });
        mgr2.import_cfe(&blob).unwrap();
        // Import must clear any in-progress SPK rotation.
        assert!(!mgr2.is_rotation_pending());
    }
}
