//! Is this Kyber prekey the peer's, and what may a session built on it be called.
//!
//! # Why the core checks this
//!
//! Every Kyber SPK a device uploads carries an Ed25519 signature by that device's identity
//! signing key over `"KonstruktX3DH-v1" || 0x00 0x10 || kyber_public` — the classic SPK message
//! with suite byte `0x10` (iOS `PQCKeyManager.signKyberKey`; the server rejects an upload whose
//! signature does not verify, key-service `core.rs:960`). Until 2026-09-24 nobody on the
//! receiving side checked it: iOS read the field and dropped it, and `init_session` had no
//! parameter for it. A server that substituted the Kyber key got the ML-KEM secret of every
//! session opened to that device, and every indicator still said "PQ".
//!
//! Two clients must reach the same verdict on the same bytes, so the verdict is computed here.
//!
//! # What an unverified key is still worth
//!
//! The KEM secret is mixed into a root key the classical X3DH already produced
//! (`HKDF(rk, kem_ss, "construct-pqxdh-v1")`), and the classical half stays authenticated by the
//! SPK signature this crate does check. A substituted Kyber key therefore gives its substitute
//! `kem_ss` and nothing else: classical protection is intact, and against a passive recorder that
//! does not control the server the unverified key still protects. So an unsigned key is used —
//! but the session it builds is labelled [`PqAuthentication::Unauthenticated`], never "PQ".

use crate::crypto::keys::KeyManager;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;

/// Suite byte of the Kyber prekey signature message (the classic SPK uses `0x01`).
pub const KYBER_PREKEY_SIGN_SUITE: u8 = 0x10;

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

/// Check `signature` over `kyber_public` against the bundle's Ed25519 `verifying_key`.
pub fn check_kyber_prekey_signature(
    verifying_key: &[u8],
    kyber_public: &[u8],
    signature: Option<&[u8]>,
) -> KyberPrekeySignature {
    let Some(signature) = signature.filter(|s| !s.is_empty()) else {
        return KyberPrekeySignature::Missing;
    };
    let message = KeyManager::<ClassicSuiteProvider>::build_x3dh_sign_message(
        KYBER_PREKEY_SIGN_SUITE,
        kyber_public,
    );
    let key = ClassicSuiteProvider::signature_public_key_from_bytes(verifying_key.to_vec());
    match ClassicSuiteProvider::verify(&key, &message, signature) {
        Ok(()) => KyberPrekeySignature::Valid,
        Err(_) => KyberPrekeySignature::Invalid,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(kyber_public: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (sk, vk) = ClassicSuiteProvider::generate_signature_keys().unwrap();
        let msg = KeyManager::<ClassicSuiteProvider>::build_x3dh_sign_message(0x10, kyber_public);
        (vk, ClassicSuiteProvider::sign(&sk, &msg).unwrap())
    }

    /// The exact bytes iOS signs: `"KonstruktX3DH-v1" || 0x00 0x10 || pk`.
    #[test]
    fn the_signed_message_is_the_one_ios_signs() {
        let pk = [0xAA_u8; 4];
        let msg = KeyManager::<ClassicSuiteProvider>::build_x3dh_sign_message(
            KYBER_PREKEY_SIGN_SUITE,
            &pk,
        );
        let mut expected = b"KonstruktX3DH-v1".to_vec();
        expected.extend_from_slice(&[0x00, 0x10]);
        expected.extend_from_slice(&pk);
        assert_eq!(msg, expected);
    }

    #[test]
    fn a_valid_signature_verifies() {
        let pk = vec![7_u8; 1184];
        let (vk, sig) = signed(&pk);
        assert_eq!(
            check_kyber_prekey_signature(&vk, &pk, Some(&sig)),
            KyberPrekeySignature::Valid
        );
    }

    #[test]
    fn absent_and_empty_are_missing() {
        let pk = vec![7_u8; 1184];
        let (vk, _) = signed(&pk);
        assert_eq!(
            check_kyber_prekey_signature(&vk, &pk, None),
            KyberPrekeySignature::Missing
        );
        assert_eq!(
            check_kyber_prekey_signature(&vk, &pk, Some(&[])),
            KyberPrekeySignature::Missing
        );
    }

    #[test]
    fn a_substituted_key_or_a_classic_spk_signature_is_invalid() {
        let pk = vec![7_u8; 1184];
        let (vk, sig) = signed(&pk);
        let mut other = pk.clone();
        other[0] ^= 1;
        assert_eq!(
            check_kyber_prekey_signature(&vk, &other, Some(&sig)),
            KyberPrekeySignature::Invalid,
            "a signature over another key"
        );

        // The classic SPK signature (suite byte 0x01) over the same bytes must not pass for a
        // Kyber one: the suite byte is what keeps the two from being interchangeable.
        let (sk, vk) = ClassicSuiteProvider::generate_signature_keys().unwrap();
        let classic = KeyManager::<ClassicSuiteProvider>::build_x3dh_sign_message(0x01, &pk);
        let sig = ClassicSuiteProvider::sign(&sk, &classic).unwrap();
        assert_eq!(
            check_kyber_prekey_signature(&vk, &pk, Some(&sig)),
            KyberPrekeySignature::Invalid
        );
    }

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
