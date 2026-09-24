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
