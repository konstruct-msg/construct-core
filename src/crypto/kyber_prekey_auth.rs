//! Is this Kyber prekey the peer's, and what may a session built on it be called.
//!
//! Every Kyber prekey a device uploads is signed by it over
//! `"KonstruktX3DH-v1" ‖ 0x00 0x11 ‖ created_at (u64 BE) ‖ kyber_public` — Ed25519 by its identity
//! key and hybrid (Ed25519 + ML-DSA-65) by its hybrid identity key. Two clients must reach the same
//! verdict on the same bytes, so the checks live here; `orchestration::pq_prekey_plan` decides
//! from them whether a session may be opened (PQXDH v2 makes PQ mandatory: an unsigned or
//! unverifiable key is a refusal, not a classic session).
//!
//! The v1 message (`0x10`, a 768-bit key, no time) and its check are gone with the cutover
//! (construct-docs `decisions/pqxdh-v2-mandatory-pq-cutover.md`). Before 2026-09-24 nobody on the
//! receiving side checked a Kyber signature at all; a substituted key got the ML-KEM secret of
//! every session opened to that device while every indicator said "PQ".

use crate::crypto::keys::KeyManager;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;

/// The signature on one Kyber prekey, as the bundle presented it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyberPrekeySignature {
    /// Verifies under the bundle's identity signing key.
    Valid,
    /// Not in the bundle (absent, or empty — proto3's default for a bytes field).
    Missing,
    /// Present and does not verify. An honest server never serves this: it rejects such an
    /// upload. This is tampering, not a transition.
    Invalid,
}

// ── v2: ML-KEM-1024 prekeys, freshness under the signature ──────────────────────

/// Suite byte of the v2 Kyber prekey signature message.
///
/// A new byte, not a new meaning for `0x10`: a v1 signature (768-bit key, no timestamp) must not
/// verify as a v2 one, or an old key could be served as a new one.
pub const KYBER_PREKEY_SIGN_SUITE_V2: u8 = 0x11;

/// The oldest a Kyber SPK may be, by its **signed** `created_at`, for an initiator to encapsulate
/// to it. Not subject to `allow_stale`: that override exists because the classic SPK's upload
/// time is the server's unsigned word; here, skipping the check is the replay attack itself.
pub const KYBER_SPK_MAX_AGE_SECS: u64 = 30 * 24 * 3600;

/// `"KonstruktX3DH-v1" ‖ 0x00 0x11 ‖ created_at (u64 BE) ‖ kyber_public` — what the device's
/// identity key (Ed25519, and the hybrid key) signs for every v2 Kyber prekey, SPK and OTPK
/// alike. `created_at` sits under the signature so a server cannot pass off a long-rotated key
/// as current: the bundle's `kyber_spk_uploaded_at` is the server's own, unsigned claim.
pub fn kyber_prekey_sign_message_v2(created_at: u64, kyber_public: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + kyber_public.len());
    payload.extend_from_slice(&created_at.to_be_bytes());
    payload.extend_from_slice(kyber_public);
    KeyManager::<ClassicSuiteProvider>::build_x3dh_sign_message(
        KYBER_PREKEY_SIGN_SUITE_V2,
        &payload,
    )
}

/// Check a v2 Kyber prekey's Ed25519 signature against the bundle's `verifying_key`.
pub fn check_kyber_prekey_signature_v2(
    verifying_key: &[u8],
    kyber_public: &[u8],
    created_at: u64,
    signature: Option<&[u8]>,
) -> KyberPrekeySignature {
    let Some(signature) = signature.filter(|s| !s.is_empty()) else {
        return KyberPrekeySignature::Missing;
    };
    let message = kyber_prekey_sign_message_v2(created_at, kyber_public);
    let key = ClassicSuiteProvider::signature_public_key_from_bytes(verifying_key.to_vec());
    match ClassicSuiteProvider::verify(&key, &message, signature) {
        Ok(()) => KyberPrekeySignature::Valid,
        Err(_) => KyberPrekeySignature::Invalid,
    }
}

/// Check a v2 Kyber prekey's hybrid (Ed25519 + ML-DSA-65) signature against the device's hybrid
/// identity key — the half of the prekey's authenticity that a quantum adversary cannot forge.
///
/// What this does **not** establish on its own: that `hybrid_identity_key` is the device's. The
/// bundle binds it to the device only by an Ed25519 cross-signature (key-service field 21), which
/// is exactly what such an adversary could forge. The caller pins the hybrid key per device.
#[cfg(feature = "post-quantum")]
pub fn check_kyber_prekey_hybrid_signature(
    hybrid_identity_key: &[u8],
    kyber_public: &[u8],
    created_at: u64,
    signature: Option<&[u8]>,
) -> KyberPrekeySignature {
    use crate::crypto::suites::hybrid::{HYBRID_SIG_PUBLIC_KEY_SIZE, HybridSuiteProvider};
    let Some(signature) = signature.filter(|s| !s.is_empty()) else {
        return KyberPrekeySignature::Missing;
    };
    if hybrid_identity_key.len() != HYBRID_SIG_PUBLIC_KEY_SIZE {
        return KyberPrekeySignature::Invalid;
    }
    let message = kyber_prekey_sign_message_v2(created_at, kyber_public);
    let key = HybridSuiteProvider::signature_public_key_from_bytes(hybrid_identity_key.to_vec());
    match HybridSuiteProvider::verify(&key, &message, signature) {
        Ok(()) => KyberPrekeySignature::Valid,
        Err(_) => KyberPrekeySignature::Invalid,
    }
}

/// What a session's post-quantum layer is, as far as this device can know.
///
/// Persisted with the session (`pqa` in the CFE session record) and reported by
/// `get_session_health`. Anything a person sees about "PQ" should read this, not
/// `is_pq_strengthened` alone: that one says whether a KEM secret was mixed in, this one says
/// whose key it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PqAuthentication {
    /// Recorded before this field existed. Nothing is claimed.
    #[default]
    Unknown,
    /// No Kyber contribution: classical X3DH + Double Ratchet only.
    Classic,
    /// We encapsulated to a Kyber key whose signature by the peer's identity key verified.
    Authenticated,
    /// We encapsulated to a Kyber key that carried no signature. Protects against a passive
    /// recorder; not against whoever served the bundle.
    Unauthenticated,
    /// We are the responder: the peer encapsulated to our own key. Whether *they* verified it is
    /// decided on their side.
    Received,
}

impl PqAuthentication {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Classic => 1,
            Self::Authenticated => 2,
            Self::Unauthenticated => 3,
            Self::Received => 4,
        }
    }

    /// Unrecognised values read as `Unknown`: a newer build's label claims nothing here.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Classic,
            2 => Self::Authenticated,
            3 => Self::Unauthenticated,
            4 => Self::Received,
            _ => Self::Unknown,
        }
    }
}

/// How a session's post-quantum layer started — `SessionHealthReport.pq_handshake`.
///
/// Together with [`PqAuthentication`] (whose key), this is everything a person may be told about
/// "PQ" for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PqHandshake {
    /// No ML-KEM at session start.
    #[default]
    None,
    /// Established before PQXDH v2: the ML-KEM secret was mixed in after the first ratchet
    /// step, so the initiator's first sending chain was X25519-only. Only sessions older than
    /// the cutover have it.
    DeferredV1,
    /// PQXDH v2: the ML-KEM-1024 secret is in the initial key; every message is covered.
    InitialV2,
}

impl PqHandshake {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::DeferredV1 => 1,
            Self::InitialV2 => 2,
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::DeferredV1,
            2 => Self::InitialV2,
            _ => Self::None,
        }
    }

    /// For a session recorded before this field existed: the old deferred contribution was the
    /// only kind, so an applied one is `DeferredV1` and anything else claims nothing.
    pub const fn legacy(pq_applied: Option<bool>) -> Self {
        match pq_applied {
            Some(true) => Self::DeferredV1,
            _ => Self::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact v2 bytes: `"KonstruktX3DH-v1" || 0x00 0x11 || created_at (BE) || pk`. The server
    /// verifies uploads against the same bytes; a change here is a protocol change.
    #[test]
    fn the_v2_signed_message_is_suite_0x11_time_then_key() {
        let msg = kyber_prekey_sign_message_v2(0x0102_0304_0506_0708, &[0xAA, 0xBB]);
        let mut expected = b"KonstruktX3DH-v1".to_vec();
        expected.extend_from_slice(&[0x00, 0x11]);
        expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        expected.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(msg, expected);
    }

    #[test]
    fn a_v2_signature_binds_the_time_and_is_not_a_v1_one() {
        let pk = vec![7_u8; 1568];
        let (sk, vk) = ClassicSuiteProvider::generate_signature_keys().unwrap();
        let sig =
            ClassicSuiteProvider::sign(&sk, &kyber_prekey_sign_message_v2(1000, &pk)).unwrap();
        assert_eq!(
            check_kyber_prekey_signature_v2(&vk, &pk, 1000, Some(&sig)),
            KyberPrekeySignature::Valid
        );
        assert_eq!(
            check_kyber_prekey_signature_v2(&vk, &pk, 1001, Some(&sig)),
            KyberPrekeySignature::Invalid,
            "a server that rewrites created_at breaks the signature"
        );
        assert_eq!(
            check_kyber_prekey_signature_v2(&vk, &pk, 1000, None),
            KyberPrekeySignature::Missing
        );

        // A v1 (0x10) signature over the same key is not a v2 one.
        let v1 = ClassicSuiteProvider::sign(
            &sk,
            &KeyManager::<ClassicSuiteProvider>::build_x3dh_sign_message(0x10, &pk),
        )
        .unwrap();
        assert_eq!(
            check_kyber_prekey_signature_v2(&vk, &pk, 1000, Some(&v1)),
            KyberPrekeySignature::Invalid
        );
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn the_hybrid_signature_verifies_over_the_same_v2_message() {
        use crate::crypto::suites::hybrid::HybridSuiteProvider;
        let pk = vec![9_u8; 1568];
        let (hsk, hpk) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let sig = HybridSuiteProvider::sign(&hsk, &kyber_prekey_sign_message_v2(42, &pk)).unwrap();
        assert_eq!(
            check_kyber_prekey_hybrid_signature(&hpk, &pk, 42, Some(&sig)),
            KyberPrekeySignature::Valid
        );
        assert_eq!(
            check_kyber_prekey_hybrid_signature(&hpk, &pk, 43, Some(&sig)),
            KyberPrekeySignature::Invalid
        );
        let (_, other) = HybridSuiteProvider::generate_signature_keys().unwrap();
        assert_eq!(
            check_kyber_prekey_hybrid_signature(&other, &pk, 42, Some(&sig)),
            KyberPrekeySignature::Invalid,
            "another hybrid key"
        );
        assert_eq!(
            check_kyber_prekey_hybrid_signature(&hpk[..32], &pk, 42, Some(&sig)),
            KyberPrekeySignature::Invalid,
            "a truncated key is refused, not a panic"
        );
    }

    #[test]
    fn labels_round_trip_and_unknown_values_claim_nothing() {
        for label in [
            PqAuthentication::Unknown,
            PqAuthentication::Classic,
            PqAuthentication::Authenticated,
            PqAuthentication::Unauthenticated,
            PqAuthentication::Received,
        ] {
            assert_eq!(PqAuthentication::from_u8(label.as_u8()), label);
        }
        assert_eq!(PqAuthentication::from_u8(200), PqAuthentication::Unknown);
    }
}
