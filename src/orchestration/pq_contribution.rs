/// PQ Contribution Manager — Rust port of Swift `PQCKeyManager` +
/// the PQ-specific parts of `SessionInitializationService`.
///
/// Manages the two-phase ML-KEM-768 (Kyber) contribution to Double Ratchet sessions:
///
/// **Sender (INITIATOR) flow:**
/// 1. `encapsulate_and_defer(contact_id, kem_public)` — encapsulate to the
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
    /// The returned `EncapsulationResult` contains the ciphertext that must be
    /// included in the initial message. The shared secret is stored internally
    /// and retrieved via `consume_deferred` once the session is initialised.
    ///
    /// Calls the actual ML-KEM-768 primitive from `crate::crypto::pq_x3dh`
    /// when the `post-quantum` feature is enabled; otherwise returns an error.
    pub fn encapsulate_and_defer(
        &mut self,
        contact_id: &str,
        kem_public: &[u8],
    ) -> Result<EncapsulationResult, String> {
        let (ciphertext, shared_secret) = pq_encapsulate(kem_public)?;
        let otpk_id = self.allocate_otpk_id();

        self.pending.insert(
            contact_id.to_string(),
            PendingContribution { shared_secret, otpk_id },
        );
        self.pending_ciphertexts
            .insert(contact_id.to_string(), ciphertext.clone());

        Ok(EncapsulationResult { ciphertext, otpk_id })
    }

    // ── Receiver flow ─────────────────────────────────────────────────────────

    /// Decapsulate the received `kem_ciphertext` using the responder's secret key.
    ///
    /// `kem_secret` is the ML-KEM-768 secret key loaded from the platform
    /// secure store by the caller. The shared secret is stored and returned
    /// via `consume_deferred`.
    pub fn decapsulate_and_store(
        &mut self,
        contact_id: &str,
        kem_ciphertext: &[u8],
        kem_secret: &[u8],
        otpk_id: u32,
    ) -> Result<(), String> {
        let shared_secret = pq_decapsulate(kem_secret, kem_ciphertext)?;
        self.pending.insert(
            contact_id.to_string(),
            PendingContribution { shared_secret, otpk_id },
        );
        Ok(())
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    /// Retrieve and remove the deferred contribution for `contact_id`.
    ///
    /// Returns `None` if no deferred contribution exists (caller should skip
    /// `apply_pq_contribution`).
    pub fn consume_deferred(&mut self, contact_id: &str) -> Option<DeferredContribution> {
        self.pending_ciphertexts.remove(contact_id);
        self.pending.remove(contact_id).map(|c| DeferredContribution {
            shared_secret: c.shared_secret,
            otpk_id: c.otpk_id,
        })
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
}

impl Default for PQContributionManager {
    fn default() -> Self {
        Self::new()
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
        crate::crypto::pq_x3dh::mlkem768_keygen()
            .map(|kp| (kp.public_key, kp.secret_key))
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
        assert!(mgr.consume_deferred("nobody").is_none());
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
        let result = mgr.encapsulate_and_defer("bob", &kp.public_key).unwrap();
        assert!(!result.ciphertext.is_empty());
        assert!(mgr.has_pending("bob"));

        let deferred = mgr.consume_deferred("bob").unwrap();
        assert!(!deferred.shared_secret.is_empty());
        assert!(!mgr.has_pending("bob"));

        // Verify decapsulate produces the same shared secret.
        let ss2 = pq_decapsulate(&kp.secret_key, &result.ciphertext).unwrap();
        assert_eq!(deferred.shared_secret, ss2);
    }
}
