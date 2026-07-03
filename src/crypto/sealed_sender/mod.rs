/// ConstructSEALED — sealed sender box + sender-certificate verification
/// (stealth-sealed-sender-v2 Phase 5: one implementation for both platforms).
///
/// Send:   seal(cert_bytes, recipient_identity_pub)  → box
/// Recv:   unseal(box, our_identity_priv)            → cert_bytes
/// Verify: Ed25519(bundle key from well-known) over the variant-0 payload
///
/// Box wire format (bit-compatible with the iOS CryptoKit implementation in
/// `ConstructMessenger/Security/StealthSenderService.swift`):
///
///   ephemeral_pub(32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)
///
///   key  = HKDF-SHA256(ikm = X25519(ephemeral, identity),
///                      salt = "ConstructSEALED-v1", info = "") → 32 bytes
///   AEAD = ChaCha20-Poly1305, random 12-byte nonce
///
/// Certificate sign payload (variant 0, Phase 3.4 — must match
/// identity-service::build_sender_cert_sign_payload and iOS
/// StealthSenderService.buildCertPayload exactly): direct concatenation, no
/// separators, issued_at/expires_at as big-endian i64:
///
///   user_id ‖ domain ‖ identity_key ‖ device_id ‖ BE64(issued_at) ‖ BE64(expires_at)
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CryptoError;

const SEALED_SALT: &[u8] = b"ConstructSEALED-v1";
const EPH_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Derive the ChaChaPoly key from an X25519 shared secret.
fn derive_key(shared: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SEALED_SALT), shared);
    let mut key = [0u8; 32];
    hk.expand(&[], &mut key)
        .expect("HKDF-SHA256 with 32-byte output always succeeds");
    key
}

fn as_key32(bytes: &[u8], what: &str) -> Result<[u8; 32], CryptoError> {
    bytes.try_into().map_err(|_| {
        CryptoError::InvalidInputError(format!("{what} must be 32 bytes, got {}", bytes.len()))
    })
}

/// Seal `cert_bytes` (serialized SenderCertificate proto — opaque here) to the
/// recipient's X25519 identity public key.
pub fn seal_sender_cert(
    cert_bytes: &[u8],
    recipient_identity_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let recipient_pub =
        PublicKey::from(as_key32(recipient_identity_key, "recipient identity key")?);

    let mut eph_seed = [0u8; 32];
    OsRng.fill_bytes(&mut eph_seed);
    let ephemeral = StaticSecret::from(eph_seed);
    let ephemeral_pub = PublicKey::from(&ephemeral);

    let shared = ephemeral.diffie_hellman(&recipient_pub);
    let key = derive_key(shared.as_bytes());

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct_and_tag = cipher
        .encrypt(Nonce::from_slice(&nonce), cert_bytes)
        .map_err(|_| CryptoError::AeadEncryptionError("sealed sender seal failed".into()))?;

    let mut boxed = Vec::with_capacity(EPH_LEN + NONCE_LEN + ct_and_tag.len());
    boxed.extend_from_slice(ephemeral_pub.as_bytes());
    boxed.extend_from_slice(&nonce);
    boxed.extend_from_slice(&ct_and_tag);
    Ok(boxed)
}

/// Open a sealed box with our X25519 identity private key. Returns the
/// serialized SenderCertificate bytes (caller parses the proto).
pub fn unseal_sender_cert(
    sealed_box: &[u8],
    our_identity_priv: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed_box.len() < EPH_LEN + NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidInputError(format!(
            "sealed box too short: {} bytes",
            sealed_box.len()
        )));
    }

    let ephemeral_pub = PublicKey::from(as_key32(&sealed_box[..EPH_LEN], "ephemeral key")?);
    let nonce = &sealed_box[EPH_LEN..EPH_LEN + NONCE_LEN];
    let ct_and_tag = &sealed_box[EPH_LEN + NONCE_LEN..];

    let our_priv = StaticSecret::from(as_key32(our_identity_priv, "identity private key")?);
    let shared = our_priv.diffie_hellman(&ephemeral_pub);
    let key = derive_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct_and_tag)
        .map_err(|_| CryptoError::AeadDecryptionError("sealed sender unseal failed".into()))
}

/// Variant-0 certificate sign payload (Phase 3.4 canonical format).
pub fn build_cert_sign_payload(
    user_id: &str,
    domain: &str,
    identity_key: &[u8],
    device_id: &str,
    issued_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        user_id.len() + domain.len() + identity_key.len() + device_id.len() + 16,
    );
    payload.extend_from_slice(user_id.as_bytes());
    payload.extend_from_slice(domain.as_bytes());
    payload.extend_from_slice(identity_key);
    payload.extend_from_slice(device_id.as_bytes());
    payload.extend_from_slice(&issued_at.to_be_bytes());
    payload.extend_from_slice(&expires_at.to_be_bytes());
    payload
}

/// Verify the server's Ed25519 signature over a SenderCertificate's fields.
/// `server_verifying_key` is the 32-byte bundle verification key from
/// `/.well-known/construct-server`. Returns false on any malformed input —
/// verification failures are not actionable errors for callers.
#[allow(clippy::too_many_arguments)]
pub fn verify_sender_cert(
    user_id: &str,
    domain: &str,
    identity_key: &[u8],
    device_id: &str,
    issued_at: i64,
    expires_at: i64,
    signature: &[u8],
    server_verifying_key: &[u8],
) -> bool {
    let Ok(vk_bytes): Result<[u8; 32], _> = server_verifying_key.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);

    let payload = build_cert_sign_payload(
        user_id,
        domain,
        identity_key,
        device_id,
        issued_at,
        expires_at,
    );
    vk.verify(&payload, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> ([u8; 32], PublicKey) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        (seed, public)
    }

    #[test]
    fn seal_unseal_round_trip() {
        let (recipient_priv, recipient_pub) = keypair();
        let cert = b"serialized sender certificate stand-in";

        let boxed = seal_sender_cert(cert, recipient_pub.as_bytes()).unwrap();
        assert_eq!(&boxed[..], &boxed[..]); // structural sanity
        assert!(boxed.len() >= EPH_LEN + NONCE_LEN + TAG_LEN);

        let opened = unseal_sender_cert(&boxed, &recipient_priv).unwrap();
        assert_eq!(opened, cert);
    }

    #[test]
    fn unseal_rejects_wrong_recipient() {
        let (_, recipient_pub) = keypair();
        let (other_priv, _) = keypair();

        let boxed = seal_sender_cert(b"cert", recipient_pub.as_bytes()).unwrap();
        assert!(unseal_sender_cert(&boxed, &other_priv).is_err());
    }

    #[test]
    fn unseal_rejects_tampered_box() {
        let (recipient_priv, recipient_pub) = keypair();
        let mut boxed = seal_sender_cert(b"cert", recipient_pub.as_bytes()).unwrap();
        let last = boxed.len() - 1;
        boxed[last] ^= 0x01;
        assert!(unseal_sender_cert(&boxed, &recipient_priv).is_err());
    }

    #[test]
    fn unseal_rejects_truncated_box() {
        let (recipient_priv, _) = keypair();
        assert!(
            unseal_sender_cert(&[0u8; EPH_LEN + NONCE_LEN + TAG_LEN - 1], &recipient_priv).is_err()
        );
    }

    /// Cross-implementation vector generated by an independent Python
    /// (`cryptography`) implementation of the same construction — mirrors the
    /// iOS CryptoKit seal byte-for-byte (X25519 → HKDF-SHA256(salt
    /// "ConstructSEALED-v1") → ChaChaPoly, eph_pub‖nonce‖ct‖tag).
    #[test]
    fn unseal_cross_implementation_vector() {
        let recipient_priv: [u8; 32] = (1..=32).collect::<Vec<u8>>().try_into().unwrap();
        let boxed = hex_to_vec(
            "5714769d116bf76436ae74bc793d2c30ad1903c59ac5273805c7e2698b410c36\
             000102030405060708090a0b\
             4fc2d403950d2573faee2d79e64c820578b8997c99e555a130c6ad01bc7e0d37\
             292a6cd859f41f36598cd0a54dba6a4166e338d42a0f8718a37a6d85f199c5de\
             72b3475d1a9738db80c8772dd5ad864f",
        );

        let opened = unseal_sender_cert(&boxed, &recipient_priv).unwrap();
        assert_eq!(
            opened,
            b"ConstructSEALED cross-impl test vector: serialized cert stand-in"
        );
    }

    /// Mirrors identity-service's
    /// `build_sender_cert_sign_payload_is_direct_concat_no_separators_be_times`.
    #[test]
    fn cert_payload_is_direct_concat_no_separators_be_times() {
        let payload = build_cert_sign_payload(
            "user-123",
            "construct.example",
            &[0xAB; 32],
            "device-1",
            1_000,
            2_000,
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(b"user-123");
        expected.extend_from_slice(b"construct.example");
        expected.extend_from_slice(&[0xAB; 32]);
        expected.extend_from_slice(b"device-1");
        expected.extend_from_slice(&1_000i64.to_be_bytes());
        expected.extend_from_slice(&2_000i64.to_be_bytes());

        assert_eq!(payload, expected);
        assert!(!payload.contains(&b':'));
    }

    #[test]
    fn verify_cert_round_trip_and_rejections() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();

        let ik = [0xCD; 32];
        let payload = build_cert_sign_payload("user-1", "example.org", &ik, "dev-1", 100, 200);
        let sig = sk.sign(&payload);

        assert!(verify_sender_cert(
            "user-1",
            "example.org",
            &ik,
            "dev-1",
            100,
            200,
            &sig.to_bytes(),
            vk.as_bytes()
        ));
        // Any field change breaks the signature.
        assert!(!verify_sender_cert(
            "user-2",
            "example.org",
            &ik,
            "dev-1",
            100,
            200,
            &sig.to_bytes(),
            vk.as_bytes()
        ));
        assert!(!verify_sender_cert(
            "user-1",
            "example.org",
            &ik,
            "dev-1",
            100,
            201,
            &sig.to_bytes(),
            vk.as_bytes()
        ));
        // Malformed inputs are false, not panics.
        assert!(!verify_sender_cert(
            "user-1",
            "example.org",
            &ik,
            "dev-1",
            100,
            200,
            &[0u8; 63],
            vk.as_bytes()
        ));
        assert!(!verify_sender_cert(
            "user-1",
            "example.org",
            &ik,
            "dev-1",
            100,
            200,
            &sig.to_bytes(),
            &[0u8; 31]
        ));
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
