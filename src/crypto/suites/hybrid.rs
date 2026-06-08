//! Hybrid Post-Quantum Crypto Suite (Suite ID = 2)
//!
//! Combines classical and post-quantum cryptography:
//! - **KEM**: X25519 (classical — PQ KEM is handled separately via `pq_contribution`)
//! - **Signatures**: Ed25519 + ML-DSA-65 (hybrid — both must verify)
//! - **AEAD**: ChaCha20-Poly1305
//! - **KDF**: HKDF-SHA256
//!
//! ## Key sizes
//!
//! | Component | Ed25519 | ML-DSA-65 | Hybrid |
//! |-----------|---------|-----------|--------|
//! | Public key | 32 | 1952 | **1984** |
//! | Private key | 32 (seed) | 4032+1952 (expanded + embedded pk) | **6016** |
//! | Signature | 64 | 3309 (detached) | **3373** |
//!
//! ## Wire format
//!
//! ### Public key: `[ed25519_pk (32)] [mldsa65_pk (1952)]` = 1984 bytes
//!
//! ### Private key: `[ed25519_seed (32)] [mldsa65_sk (4032)] [mldsa65_pk (1952)]` = 6016 bytes
//!
//! The ML-DSA-65 expanded secret key (4032 bytes, PQClean format) does **not**
//! contain enough information to derive the public key. We embed the public key
//! at the end of the private key blob so that `from_signature_private_to_public`
//! can extract it without regenerating the keypair.
//!
//! For signing, only bytes `0..4064` (ed25519_seed + mldsa65_sk) are needed.
//!
//! ### Signature: `[ed25519_sig (64)] [mldsa65_sig (3309)]` = 3373 bytes
//!
//! ## Security
//!
//! Signature security = MIN(Ed25519, ML-DSA-65).
//! An attacker must break BOTH algorithms to forge a signature.

use crate::crypto::provider::CryptoProvider;
use crate::error::CryptoError;
use chacha20poly1305::{
    ChaCha20Poly1305, Key as AeadKeyChacha, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use pqcrypto_mldsa::mldsa65::{
    DetachedSignature, PublicKey as MlDsaPublicKey, SecretKey as MlDsaSecretKey, detached_sign,
    keypair, verify_detached_signature,
};
use pqcrypto_traits::sign::{
    DetachedSignature as MlDsaDetachedSignatureTrait, PublicKey as MlDsaPublicKeyTrait,
    SecretKey as MlDsaSecretKeyTrait,
};
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as KemPublicKeyDalek, StaticSecret};

// ── ML-DSA-65 sizes (PQClean via pqcrypto-mldsa) ─────────────────────────────

/// ML-DSA-65 public key size in bytes (NIST FIPS 204)
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
/// ML-DSA-65 secret key size in bytes (expanded form, PQClean)
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4032;
/// ML-DSA-65 detached signature size in bytes
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

// ── Ed25519 sizes ─────────────────────────────────────────────────────────────

/// Ed25519 public key size
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 secret key seed size
pub const ED25519_SECRET_KEY_SIZE: usize = 32;
/// Ed25519 signature size
pub const ED25519_SIGNATURE_SIZE: usize = 64;

// ── Hybrid sizes ──────────────────────────────────────────────────────────────

/// Hybrid signature public key = Ed25519 (32) + ML-DSA-65 (1952)
pub const HYBRID_SIG_PUBLIC_KEY_SIZE: usize = ED25519_PUBLIC_KEY_SIZE + ML_DSA_65_PUBLIC_KEY_SIZE; // 1984
/// Hybrid signature private key = Ed25519 seed (32) + ML-DSA-65 sk (4032) + ML-DSA-65 pk (1952)
/// The embedded ML-DSA pk is needed because PQClean's expanded secret key format
/// does not allow public key derivation.
pub const HYBRID_SIG_SECRET_KEY_SIZE: usize =
    ED25519_SECRET_KEY_SIZE + ML_DSA_65_SECRET_KEY_SIZE + ML_DSA_65_PUBLIC_KEY_SIZE; // 6016
/// Bytes 0..4064 of the hybrid private key are the actual signing material
pub const HYBRID_SIG_SIGNING_MATERIAL_SIZE: usize =
    ED25519_SECRET_KEY_SIZE + ML_DSA_65_SECRET_KEY_SIZE; // 4064
/// Hybrid signature = Ed25519 sig (64) + ML-DSA-65 detached sig (3309)
pub const HYBRID_SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + ML_DSA_65_SIGNATURE_SIZE; // 3373

// ── Helpers: split hybrid private key ─────────────────────────────────────────

// ── Helpers: split hybrid private key ─────────────────────────────────────────

/// Decomposed parts of a hybrid private key.
struct HybridKeyParts<'a> {
    ed25519_seed: &'a [u8; ED25519_SECRET_KEY_SIZE],
    mldsa_sk: &'a [u8; ML_DSA_65_SECRET_KEY_SIZE],
    mldsa_pk: &'a [u8; ML_DSA_65_PUBLIC_KEY_SIZE],
}

/// Split hybrid private key into its constituent parts.
fn split_hybrid_private_key(hybrid_sk: &[u8]) -> Result<HybridKeyParts<'_>, CryptoError> {
    if hybrid_sk.len() != HYBRID_SIG_SECRET_KEY_SIZE {
        return Err(CryptoError::InvalidInputError(format!(
            "Hybrid private key size mismatch: expected {HYBRID_SIG_SECRET_KEY_SIZE}, got {}",
            hybrid_sk.len()
        )));
    }
    let ed25519_seed: &[u8; ED25519_SECRET_KEY_SIZE] = hybrid_sk[..ED25519_SECRET_KEY_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InvalidInputError("Failed to extract Ed25519 seed".into()))?;
    let mldsa_sk: &[u8; ML_DSA_65_SECRET_KEY_SIZE] = hybrid_sk
        [ED25519_SECRET_KEY_SIZE..ED25519_SECRET_KEY_SIZE + ML_DSA_65_SECRET_KEY_SIZE]
        .try_into()
        .map_err(|_| {
            CryptoError::InvalidInputError("Failed to extract ML-DSA secret key".into())
        })?;
    let mldsa_pk: &[u8; ML_DSA_65_PUBLIC_KEY_SIZE] = hybrid_sk
        [ED25519_SECRET_KEY_SIZE + ML_DSA_65_SECRET_KEY_SIZE..]
        .try_into()
        .map_err(|_| {
            CryptoError::InvalidInputError("Failed to extract ML-DSA public key".into())
        })?;
    Ok(HybridKeyParts {
        ed25519_seed,
        mldsa_sk,
        mldsa_pk,
    })
}
// ── Helpers: split hybrid public key ──────────────────────────────────────────

fn split_hybrid_public_key(
    hybrid_pk: &[u8],
) -> Result<
    (
        &[u8; ED25519_PUBLIC_KEY_SIZE],
        &[u8; ML_DSA_65_PUBLIC_KEY_SIZE],
    ),
    CryptoError,
> {
    if hybrid_pk.len() != HYBRID_SIG_PUBLIC_KEY_SIZE {
        return Err(CryptoError::InvalidInputError(format!(
            "Hybrid public key size mismatch: expected {HYBRID_SIG_PUBLIC_KEY_SIZE}, got {}",
            hybrid_pk.len()
        )));
    }
    let ed25519_pk: &[u8; ED25519_PUBLIC_KEY_SIZE] = hybrid_pk[..ED25519_PUBLIC_KEY_SIZE]
        .try_into()
        .map_err(|_| {
            CryptoError::InvalidInputError("Failed to extract Ed25519 public key".into())
        })?;
    let mldsa_pk: &[u8; ML_DSA_65_PUBLIC_KEY_SIZE] = hybrid_pk[ED25519_PUBLIC_KEY_SIZE..]
        .try_into()
        .map_err(|_| {
            CryptoError::InvalidInputError("Failed to extract ML-DSA public key".into())
        })?;
    Ok((ed25519_pk, mldsa_pk))
}

// ── Helpers: split hybrid signature ───────────────────────────────────────────

fn split_hybrid_signature(
    hybrid_sig: &[u8],
) -> Result<
    (
        &[u8; ED25519_SIGNATURE_SIZE],
        &[u8; ML_DSA_65_SIGNATURE_SIZE],
    ),
    CryptoError,
> {
    if hybrid_sig.len() != HYBRID_SIGNATURE_SIZE {
        return Err(CryptoError::InvalidInputError(format!(
            "Hybrid signature size mismatch: expected {HYBRID_SIGNATURE_SIZE}, got {}",
            hybrid_sig.len()
        )));
    }
    let ed25519_sig: &[u8; ED25519_SIGNATURE_SIZE] = hybrid_sig[..ED25519_SIGNATURE_SIZE]
        .try_into()
        .map_err(|_| {
            CryptoError::InvalidInputError("Failed to extract Ed25519 signature".into())
        })?;
    let mldsa_sig: &[u8; ML_DSA_65_SIGNATURE_SIZE] = hybrid_sig[ED25519_SIGNATURE_SIZE..]
        .try_into()
        .map_err(|_| CryptoError::InvalidInputError("Failed to extract ML-DSA signature".into()))?;
    Ok((ed25519_sig, mldsa_sig))
}

/// Concrete implementation of `CryptoProvider` for the PQ Hybrid suite.
///
/// Suite ID: 2
/// KEM: X25519 (same as Classic — PQ KEM handled via pq_contribution layer)
/// Signatures: Ed25519 + ML-DSA-65
/// AEAD: ChaCha20-Poly1305
/// KDF: HKDF-SHA256
pub struct HybridSuiteProvider;

impl CryptoProvider for HybridSuiteProvider {
    type KemPublicKey = Vec<u8>;
    type KemPrivateKey = Vec<u8>;
    type SignaturePublicKey = Vec<u8>;
    type SignaturePrivateKey = Vec<u8>;
    type AeadKey = Vec<u8>;

    // ── KEM: X25519 (identical to ClassicSuiteProvider) ───────────────────────

    fn generate_kem_keys() -> Result<(Self::KemPrivateKey, Self::KemPublicKey), CryptoError> {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = KemPublicKeyDalek::from(&private_key);
        Ok((
            private_key.to_bytes().to_vec(),
            public_key.to_bytes().to_vec(),
        ))
    }

    fn from_private_key_to_public_key(
        private_key: &Self::KemPrivateKey,
    ) -> Result<Self::KemPublicKey, CryptoError> {
        let bytes: &[u8; 32] = private_key.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid KEM private key length".to_string())
        })?;
        let static_secret = StaticSecret::from(*bytes);
        Ok(KemPublicKeyDalek::from(&static_secret).to_bytes().to_vec())
    }

    fn kem_public_key_from_bytes(bytes: Vec<u8>) -> Self::KemPublicKey {
        bytes
    }

    fn kem_private_key_from_bytes(bytes: Vec<u8>) -> Self::KemPrivateKey {
        bytes
    }

    fn aead_key_from_bytes(bytes: Vec<u8>) -> Self::AeadKey {
        bytes
    }

    // ── Signature key helpers ─────────────────────────────────────────────────

    fn signature_public_key_from_bytes(bytes: Vec<u8>) -> Self::SignaturePublicKey {
        bytes
    }

    fn signature_private_key_from_bytes(bytes: Vec<u8>) -> Self::SignaturePrivateKey {
        bytes
    }

    fn generate_signature_keys()
    -> Result<(Self::SignaturePrivateKey, Self::SignaturePublicKey), CryptoError> {
        // Ed25519
        let ed25519_sk = SigningKey::generate(&mut OsRng);
        let ed25519_pk = ed25519_sk.verifying_key();

        // ML-DSA-65
        let (mldsa_pk, mldsa_sk) = keypair();

        // Private key: [ed25519_seed (32)] [mldsa65_sk (4032)] [mldsa65_pk (1952)]
        let mut hybrid_sk = Vec::with_capacity(HYBRID_SIG_SECRET_KEY_SIZE);
        hybrid_sk.extend_from_slice(&ed25519_sk.to_bytes());
        hybrid_sk.extend_from_slice(mldsa_sk.as_bytes());
        hybrid_sk.extend_from_slice(mldsa_pk.as_bytes());

        // Public key: [ed25519_pk (32)] [mldsa65_pk (1952)]
        let mut hybrid_pk = Vec::with_capacity(HYBRID_SIG_PUBLIC_KEY_SIZE);
        hybrid_pk.extend_from_slice(&ed25519_pk.to_bytes());
        hybrid_pk.extend_from_slice(mldsa_pk.as_bytes());

        Ok((hybrid_sk, hybrid_pk))
    }

    fn from_signature_private_to_public(
        private_key: &Self::SignaturePrivateKey,
    ) -> Result<Self::SignaturePublicKey, CryptoError> {
        let parts = split_hybrid_private_key(private_key.as_ref())?;

        let ed25519_signing_key = SigningKey::from_bytes(parts.ed25519_seed);
        let ed25519_pk = ed25519_signing_key.verifying_key();

        let mut hybrid_pk = Vec::with_capacity(HYBRID_SIG_PUBLIC_KEY_SIZE);
        hybrid_pk.extend_from_slice(&ed25519_pk.to_bytes());
        hybrid_pk.extend_from_slice(parts.mldsa_pk);
        Ok(hybrid_pk)
    }

    fn sign(
        private_key: &Self::SignaturePrivateKey,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if private_key.len() != HYBRID_SIG_SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidInputError(format!(
                "Hybrid private key size mismatch: expected {HYBRID_SIG_SECRET_KEY_SIZE}, got {}",
                private_key.len()
            )));
        }

        let parts = split_hybrid_private_key(private_key.as_ref())?;

        // Ed25519 signature
        let ed25519_signing_key = SigningKey::from_bytes(parts.ed25519_seed);
        let ed25519_sig = ed25519_signing_key.sign(message);

        // ML-DSA-65 detached signature
        let mldsa_sk = MlDsaSecretKey::from_bytes(parts.mldsa_sk).map_err(|e| {
            CryptoError::SigningError(format!("ML-DSA-65 secret key parse error: {e:?}"))
        })?;
        let mldsa_sig = detached_sign(message, &mldsa_sk);

        // Concatenate: [ed25519_sig (64)] [mldsa65_sig (3309)]
        let mut hybrid_sig = Vec::with_capacity(HYBRID_SIGNATURE_SIZE);
        hybrid_sig.extend_from_slice(&ed25519_sig.to_bytes());
        hybrid_sig.extend_from_slice(mldsa_sig.as_bytes());

        Ok(hybrid_sig)
    }

    fn verify(
        public_key: &Self::SignaturePublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let (ed25519_pk_bytes, mldsa_pk_bytes) = split_hybrid_public_key(public_key.as_ref())?;
        let (ed25519_sig_bytes, mldsa_sig_bytes) = split_hybrid_signature(signature)?;

        // Verify Ed25519
        let ed25519_vk = VerifyingKey::from_bytes(ed25519_pk_bytes).map_err(|e| {
            CryptoError::InvalidInputError(format!("Invalid Ed25519 verifying key: {e}"))
        })?;
        let ed25519_sig = Signature::from_bytes(ed25519_sig_bytes);
        ed25519_vk.verify(message, &ed25519_sig).map_err(|e| {
            CryptoError::SignatureVerificationError(format!("Ed25519 verification failed: {e}"))
        })?;

        // Verify ML-DSA-65
        let mldsa_pk = MlDsaPublicKey::from_bytes(mldsa_pk_bytes).map_err(|e| {
            CryptoError::InvalidInputError(format!("Invalid ML-DSA-65 public key: {e:?}"))
        })?;
        let mldsa_sig = DetachedSignature::from_bytes(mldsa_sig_bytes).map_err(|e| {
            CryptoError::InvalidInputError(format!("Invalid ML-DSA-65 signature: {e:?}"))
        })?;
        verify_detached_signature(&mldsa_sig, message, &mldsa_pk).map_err(|e| {
            CryptoError::SignatureVerificationError(format!("ML-DSA-65 verification failed: {e:?}"))
        })?;

        Ok(())
    }

    // ── KEM encapsulation/decapsulation: X25519 (identical to Classic) ────────

    fn kem_encapsulate(public_key: &Self::KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let pk_bytes: &[u8; 32] = public_key.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid KEM public key length".to_string())
        })?;
        let recipient_pk = KemPublicKeyDalek::from(*pk_bytes);

        let ephemeral_pk = KemPublicKeyDalek::from(&ephemeral_secret);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

        Ok((
            ephemeral_pk.to_bytes().to_vec(),
            shared_secret.to_bytes().to_vec(),
        ))
    }

    fn kem_decapsulate(
        private_key: &Self::KemPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let sk_bytes: &[u8; 32] = private_key.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid KEM private key length".to_string())
        })?;
        let static_secret = StaticSecret::from(*sk_bytes);

        let ct_bytes: &[u8; 32] = ciphertext.try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid KEM ciphertext length".to_string())
        })?;
        let ephemeral_pk = KemPublicKeyDalek::from(*ct_bytes);

        Ok(static_secret
            .diffie_hellman(&ephemeral_pk)
            .to_bytes()
            .to_vec())
    }

    // ── AEAD: ChaCha20-Poly1305 (identical to Classic) ────────────────────────

    fn aead_encrypt(
        key: &Self::AeadKey,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(AeadKeyChacha::from_slice(key));
        let nonce_ref = Nonce::from_slice(nonce);
        let payload = if let Some(aad) = associated_data {
            Payload {
                msg: plaintext,
                aad,
            }
        } else {
            Payload {
                msg: plaintext,
                aad: b"",
            }
        };
        cipher
            .encrypt(nonce_ref, payload)
            .map_err(|e| CryptoError::AeadEncryptionError(e.to_string()))
    }

    fn aead_decrypt(
        key: &Self::AeadKey,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(AeadKeyChacha::from_slice(key));
        let nonce_ref = Nonce::from_slice(nonce);
        let payload = if let Some(aad) = associated_data {
            Payload {
                msg: ciphertext,
                aad,
            }
        } else {
            Payload {
                msg: ciphertext,
                aad: b"",
            }
        };
        cipher
            .decrypt(nonce_ref, payload)
            .map_err(|e| CryptoError::AeadDecryptionError(e.to_string()))
    }

    // ── KDF: HKDF-SHA256 (identical to Classic) ───────────────────────────────

    fn hkdf_derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm = vec![0u8; len];
        hkdf.expand(info, &mut okm)
            .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
        Ok(okm)
    }

    fn kdf_rk(
        root_key: &Self::AeadKey,
        dh_output: &[u8],
    ) -> Result<(Self::AeadKey, Self::AeadKey), CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key.as_ref()), dh_output);
        let mut output = vec![0u8; 64];
        hkdf.expand(b"Double-Ratchet-Root-Key-Expansion", &mut output)
            .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
        Ok((output[..32].to_vec(), output[32..].to_vec()))
    }

    fn kdf_ck(chain_key: &Self::AeadKey) -> Result<(Self::AeadKey, Self::AeadKey), CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(chain_key.as_ref()), b"");
        let mut output = vec![0u8; 64];
        hkdf.expand(b"Double-Ratchet-Chain-Key-Expansion", &mut output)
            .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
        Ok((output[..32].to_vec(), output[32..].to_vec()))
    }

    fn generate_nonce(len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut nonce_bytes);
        Ok(nonce_bytes)
    }

    fn suite_id() -> u16 {
        2
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_signature_keypair_generation() {
        let (sk, pk) = HybridSuiteProvider::generate_signature_keys().unwrap();
        assert_eq!(
            sk.len(),
            HYBRID_SIG_SECRET_KEY_SIZE,
            "Hybrid secret key size mismatch"
        );
        assert_eq!(
            pk.len(),
            HYBRID_SIG_PUBLIC_KEY_SIZE,
            "Hybrid public key size mismatch"
        );
    }

    #[test]
    fn test_hybrid_sign_and_verify_roundtrip() {
        let (sk, pk) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let message = b"Hello, post-quantum world!";

        let sig = HybridSuiteProvider::sign(&sk, message).unwrap();
        assert_eq!(
            sig.len(),
            HYBRID_SIGNATURE_SIZE,
            "Hybrid signature size mismatch"
        );

        HybridSuiteProvider::verify(&pk, message, &sig)
            .expect("Hybrid signature verification should succeed");
    }

    #[test]
    fn test_hybrid_verify_rejects_tampered_message() {
        let (sk, pk) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let message = b"Original message";
        let tampered = b"Tampered message!";

        let sig = HybridSuiteProvider::sign(&sk, message).unwrap();
        assert!(
            HybridSuiteProvider::verify(&pk, tampered, &sig).is_err(),
            "Verification should fail for tampered message"
        );
    }

    #[test]
    fn test_hybrid_verify_rejects_tampered_ed25519_portion() {
        let (sk, pk) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let message = b"Test message";
        let mut sig = HybridSuiteProvider::sign(&sk, message).unwrap();
        sig[0] ^= 0xFF; // Tamper with Ed25519 signature byte

        assert!(
            HybridSuiteProvider::verify(&pk, message, &sig).is_err(),
            "Verification should fail for tampered Ed25519 signature"
        );
    }

    #[test]
    fn test_hybrid_verify_rejects_tampered_mldsa_portion() {
        let (sk, pk) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let message = b"Test message";
        let mut sig = HybridSuiteProvider::sign(&sk, message).unwrap();
        sig[ED25519_SIGNATURE_SIZE] ^= 0xFF; // Tamper with ML-DSA signature byte

        assert!(
            HybridSuiteProvider::verify(&pk, message, &sig).is_err(),
            "Verification should fail for tampered ML-DSA signature"
        );
    }

    #[test]
    fn test_hybrid_verify_rejects_wrong_key() {
        let (sk_a, _) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let (_, pk_b) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let message = b"Test message";

        let sig = HybridSuiteProvider::sign(&sk_a, message).unwrap();
        assert!(
            HybridSuiteProvider::verify(&pk_b, message, &sig).is_err(),
            "Verification should fail with wrong public key"
        );
    }

    #[test]
    fn test_from_private_to_public() {
        let (sk, expected_pk) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let derived_pk = HybridSuiteProvider::from_signature_private_to_public(&sk).unwrap();
        assert_eq!(derived_pk, expected_pk, "Derived public key should match");
    }

    #[test]
    fn test_derived_pk_signs_and_verifies() {
        let (sk, _original_pk) = HybridSuiteProvider::generate_signature_keys().unwrap();
        let derived_pk = HybridSuiteProvider::from_signature_private_to_public(&sk).unwrap();
        let message = b"Sign with sk, verify with derived pk";
        let sig = HybridSuiteProvider::sign(&sk, message).unwrap();
        HybridSuiteProvider::verify(&derived_pk, message, &sig)
            .expect("Verification with derived pk should succeed");
    }

    #[test]
    fn test_hybrid_key_sizes_match_constants() {
        assert_eq!(ML_DSA_65_PUBLIC_KEY_SIZE, 1952);
        assert_eq!(ML_DSA_65_SECRET_KEY_SIZE, 4032);
        assert_eq!(ML_DSA_65_SIGNATURE_SIZE, 3309);
        assert_eq!(HYBRID_SIG_PUBLIC_KEY_SIZE, 1984);
        assert_eq!(HYBRID_SIG_SECRET_KEY_SIZE, 6016);
        assert_eq!(HYBRID_SIGNATURE_SIZE, 3373);
    }

    #[test]
    fn test_hybrid_suite_id() {
        assert_eq!(HybridSuiteProvider::suite_id(), 2);
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let (sk, pk) = HybridSuiteProvider::generate_kem_keys().unwrap();
        let (ciphertext, shared_secret_a) = HybridSuiteProvider::kem_encapsulate(&pk).unwrap();
        let shared_secret_b = HybridSuiteProvider::kem_decapsulate(&sk, &ciphertext).unwrap();
        assert_eq!(
            shared_secret_a, shared_secret_b,
            "KEM shared secrets must match"
        );
    }

    #[test]
    fn test_hybrid_aead_roundtrip() {
        let key = HybridSuiteProvider::aead_key_from_bytes(vec![0x42u8; 32]);
        let nonce = HybridSuiteProvider::generate_nonce(12).unwrap();
        let plaintext = b"Secret PQ message";
        let ct = HybridSuiteProvider::aead_encrypt(&key, &nonce, plaintext, None).unwrap();
        let pt = HybridSuiteProvider::aead_decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_hybrid_kdf_rk() {
        let root_key = HybridSuiteProvider::aead_key_from_bytes(vec![0x11u8; 32]);
        let dh_output = vec![0x22u8; 32];
        let (new_rk, ck) = HybridSuiteProvider::kdf_rk(&root_key, &dh_output).unwrap();
        assert_eq!(new_rk.len(), 32);
        assert_eq!(ck.len(), 32);
        assert_ne!(new_rk, root_key);
    }

    #[test]
    fn test_hybrid_kdf_ck() {
        let ck = HybridSuiteProvider::aead_key_from_bytes(vec![0x33u8; 32]);
        let (mk, next_ck) = HybridSuiteProvider::kdf_ck(&ck).unwrap();
        assert_eq!(mk.len(), 32);
        assert_eq!(next_ck.len(), 32);
        assert_ne!(mk, ck);
        assert_ne!(next_ck, ck);
    }
}
