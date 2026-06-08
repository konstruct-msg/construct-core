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
//! | Private key | 32 (seed) | 32 (seed) + 1952 (embedded pk) | **2016** |
//! | Signature | 64 | 3309 (detached) | **3373** |
//!
//! ## Implementation
//!
//! ML-DSA-65 uses RustCrypto `ml-dsa` (FIPS 204), seed-based secret-key storage —
//! the SAME implementation as construct-server, so signatures cross-verify byte-for-byte
//! between client and server. (Replaced the archived PQClean `pqcrypto-mldsa`.)
//!
//! ## Wire format
//!
//! ### Public key: `[ed25519_pk (32)] [mldsa65_pk (1952)]` = 1984 bytes
//!
//! ### Private key: `[ed25519_seed (32)] [mldsa65_seed (32)] [mldsa65_pk (1952)]` = 2016 bytes
//!
//! The ML-DSA-65 expanded signing key (4032 bytes) is re-derived from its 32-byte
//! seed at sign time. The public key (1952) is embedded at the end of the private
//! key blob so that `from_signature_private_to_public` can extract it without
//! re-deriving the keypair.
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
use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
// Trait methods only — aliased `as _` so they don't clash with the
// ed25519-dalek Signer/Verifier names imported above.
use ml_dsa::{Keypair as _, Signer as _, Verifier as _};
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as KemPublicKeyDalek, StaticSecret};

// ── ML-DSA-65 sizes (RustCrypto ml-dsa, FIPS 204) ────────────────────────────

/// ML-DSA-65 public key size in bytes (NIST FIPS 204)
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
/// ML-DSA-65 stored secret size — the 32-byte signing seed (the expanded
/// 4032-byte key is re-derived on demand at sign time).
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 32;
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
/// Hybrid signature private key = Ed25519 seed (32) + ML-DSA-65 seed (32) + ML-DSA-65 pk (1952)
/// The embedded ML-DSA pk lets `from_signature_private_to_public` extract the public
/// key without re-deriving the keypair from the seed.
pub const HYBRID_SIG_SECRET_KEY_SIZE: usize =
    ED25519_SECRET_KEY_SIZE + ML_DSA_65_SECRET_KEY_SIZE + ML_DSA_65_PUBLIC_KEY_SIZE; // 2016
/// Hybrid signature = Ed25519 sig (64) + ML-DSA-65 detached sig (3309)
pub const HYBRID_SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + ML_DSA_65_SIGNATURE_SIZE; // 3373

// ── Helpers: split hybrid private key ─────────────────────────────────────────

// ── Helpers: split hybrid private key ─────────────────────────────────────────

/// Decomposed parts of a hybrid private key.
struct HybridKeyParts<'a> {
    ed25519_seed: &'a [u8; ED25519_SECRET_KEY_SIZE],
    mldsa_seed: &'a [u8; ML_DSA_65_SECRET_KEY_SIZE],
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
    let mldsa_seed: &[u8; ML_DSA_65_SECRET_KEY_SIZE] = hybrid_sk
        [ED25519_SECRET_KEY_SIZE..ED25519_SECRET_KEY_SIZE + ML_DSA_65_SECRET_KEY_SIZE]
        .try_into()
        .map_err(|_| {
            CryptoError::InvalidInputError("Failed to extract ML-DSA signing seed".into())
        })?;
    let mldsa_pk: &[u8; ML_DSA_65_PUBLIC_KEY_SIZE] = hybrid_sk
        [ED25519_SECRET_KEY_SIZE + ML_DSA_65_SECRET_KEY_SIZE..]
        .try_into()
        .map_err(|_| {
            CryptoError::InvalidInputError("Failed to extract ML-DSA public key".into())
        })?;
    Ok(HybridKeyParts {
        ed25519_seed,
        mldsa_seed,
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

        // ML-DSA-65 — store the 32-byte signing seed; the expanded 4032-byte key is
        // re-derived on demand at sign time. The public key (1952) is embedded for
        // convenience. pk and signature wire formats are FIPS 204 standard.
        let mut rng = OsRng;
        let mut mldsa_seed = [0u8; ML_DSA_65_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut mldsa_seed);
        let mldsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(mldsa_seed));
        let mldsa_pk_enc = mldsa_sk.verifying_key().encode(); // 1952 bytes

        // Private key: [ed25519_seed (32)] [mldsa65_seed (32)] [mldsa65_pk (1952)]
        let mut hybrid_sk = Vec::with_capacity(HYBRID_SIG_SECRET_KEY_SIZE);
        hybrid_sk.extend_from_slice(&ed25519_sk.to_bytes());
        hybrid_sk.extend_from_slice(&mldsa_seed);
        hybrid_sk.extend_from_slice(mldsa_pk_enc.as_slice());

        // Public key: [ed25519_pk (32)] [mldsa65_pk (1952)]
        let mut hybrid_pk = Vec::with_capacity(HYBRID_SIG_PUBLIC_KEY_SIZE);
        hybrid_pk.extend_from_slice(&ed25519_pk.to_bytes());
        hybrid_pk.extend_from_slice(mldsa_pk_enc.as_slice());

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

        // ML-DSA-65 detached signature — re-derive the signing key from its 32-byte seed.
        let mldsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(*parts.mldsa_seed));
        let mldsa_sig = mldsa_sk
            .try_sign(message)
            .map_err(|e| CryptoError::SigningError(format!("ML-DSA-65 signing failed: {e}")))?;

        // Concatenate: [ed25519_sig (64)] [mldsa65_sig (3309)]
        let mut hybrid_sig = Vec::with_capacity(HYBRID_SIGNATURE_SIZE);
        hybrid_sig.extend_from_slice(&ed25519_sig.to_bytes());
        hybrid_sig.extend_from_slice(mldsa_sig.encode().as_slice());

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
        let mldsa_pk_enc =
            EncodedVerifyingKey::<MlDsa65>::try_from(&mldsa_pk_bytes[..]).map_err(|_| {
                CryptoError::InvalidInputError("Invalid ML-DSA-65 public key size".into())
            })?;
        let mldsa_pk = MlDsaVerifyingKey::<MlDsa65>::decode(&mldsa_pk_enc);
        let mldsa_sig_enc =
            EncodedSignature::<MlDsa65>::try_from(&mldsa_sig_bytes[..]).map_err(|_| {
                CryptoError::InvalidInputError("Invalid ML-DSA-65 signature size".into())
            })?;
        let mldsa_sig = MlDsaSignature::<MlDsa65>::decode(&mldsa_sig_enc).ok_or_else(|| {
            CryptoError::InvalidInputError("Invalid ML-DSA-65 signature encoding".into())
        })?;
        mldsa_pk.verify(message, &mldsa_sig).map_err(|e| {
            CryptoError::SignatureVerificationError(format!("ML-DSA-65 verification failed: {e}"))
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

    /// Cross-implementation interop pin: a hybrid (pk, message, signature) vector
    /// produced by construct-server's `construct-crypto` (RustCrypto ml-dsa, seed-based)
    /// MUST verify here. Both sides now use the same ml-dsa 0.1.1; this guards against
    /// the two cores drifting apart (e.g. an ml-dsa bump that changes the FIPS 204
    /// encoding on only one side). Regenerate with `emit_cross_impl_vector` on the server.
    #[test]
    fn test_cross_impl_server_vector_verifies() {
        let pk = hex::decode(SERVER_VEC_PK).unwrap();
        let sig = hex::decode(SERVER_VEC_SIG).unwrap();
        let message = b"construct cross-impl hybrid vector v1";
        assert_eq!(pk.len(), HYBRID_SIG_PUBLIC_KEY_SIZE);
        assert_eq!(sig.len(), HYBRID_SIGNATURE_SIZE);
        HybridSuiteProvider::verify(&pk, message, &sig)
            .expect("server-produced hybrid signature must verify on the client");
    }

    // Vector emitted by construct-server `construct-crypto::pqc::hybrid::emit_cross_impl_vector`.
    const SERVER_VEC_PK: &str = "d1c03d40e54576887ce4b4e4f90e2768663e6ffb6d310e07622c91be28bb33573b675c0b97049e1877490ffb01baa6b4318e753fdde3b7e3ab000bd167efee138f8f90ee5e305b484808f0f8123753b1da81a7907d97a476c1ea36785bdfdcd68fd9a78fda7e0ed2ec14490b70884906ceb842e924ed045f9773069b20e7341e6ec6f64b4599dd160b577614d3c610cbbe9e7d0ccf58d617f007f2376cf20e1d7d76ff0e92d77cd209f04c1ac6084c219c7ea977d193909d5ef2b1df5df0bb1505418b46ac686f8d70594a3029395901a4ab7f7a2fdc3519b05cbf1cb060d83225e040ec04400ccad4a05daf34b7f53569a824ba268a9480d1e019cc0597e77ed27e3ec7dd14d4367f4878e93fe3c5f6e04c909bf942c8f260755cbceecefa4663b211433e4db05d84ab1290de7489322e5b9404c648d4cd764c16c28810d62e19189471dd2bc497962870ebf72f5753e4016a39154a88e538fd651a9b5c90d66cf73d7e10cbf797da2dae8a11501c10ea07dcafbbdfe2a4e6443975ef1f37f8f4df091c9aa0f95fbe8ccafd79a89df27460d801778f61b1f1775652250b8c6d2e102395e16fcdcbb6d9767cdb2f3c74a601a973721f119375b8715c5d41818ea618d93ae21b11732c9dd8bd1034d9e57efbac6dd36b5f0cba61238e69ee7b3430a23ffb8e81d9c84506d964d7e80cc24a42932ade1dcb28a398ca551684f0b04aa13449de01e9337a5f86fb04c351a6b6c8ee3643b22703094fa0a6557d2f6e399c59e3889c107bc66e2367f40fe27cc48cf93ba10bc46e90ab221272261783bbd0a90ecd65bcdc956101404515a90c894c6ebda1aa427645b2a4fcc73124d5b0aca152bf2560268dda0e3164ebd76b44ae48059b6dbd4b53bf37b4bc96f135669d82be83f2b25f9e7c066a30f9f031417f5e9c62c17f8ae641ddbf60348ba54cb4d17c742873071941fc11f6ca9734be9beb2528d19030e4c833ce79973a94c32ff9643f8bfa975038c9071b06b5e4e22cf93e51c5de3a0ae566f08b0796c1f5669e688220c735a534567b71fb96d134fafc182417f3dd1ca46503411bfbbd68e63b6aae6e6e0d4a44065998e17f3ff993b2c627f588ae7254eb6a30d0cc7fe6309e32f3beb451a8d9345257661696d87dfe973eeca018ee2e3b0937d5c5975a5ef5a9f9c04989394ba5fea2d59cceeafc8bdf352a2a2313888cdc901eb2a5d490f71191e2a7a3d6e5600d638e9a1372daaef15ba24faff6a79694c7eaeecf27aa8d91790d4de6a6d2c0dfb0b60cf50a88b227ac19d08470753e58661d46c279437fdd24aa8085f161c8df2696fef6e80eaa573fd31b014a0397f84e68fab93de5f6f6417a3f38a2878aaf3a46cefef83013ea46395a27acd14350f23b90129260f352cc17b872b7708f97cf9bf4d75100fef7d34a0308a7346c813799e8bf8d6182979f494c91b3aed93409fc691d60328ff339aae8ad20aaef317330e81c9bda29cb7c88941ed1278139d1f4b9b3da0f50e5bf236ad4d5a68ef28ecffe23762bc2c6eb6170412d951f9013c985f6b7c54fced9220633c742147e58f422776ba1b5479c35c2708d4ad377271ba4a9e1c5dfbe5b733d36a6e61bc44123ba5c1c090117beca29b15b8f27b0530d5816c23278c657de6e7c126bd9cfde825b6818652263b90b56b54b7c20882c31648b26b7f433ede89d27651ac9adcd1f50b2d09b5d2c179b6a5ec7f9fd8a0a4a29d6dcc279efd7ee50f5bf66d76809791aca0628a5b8e7ad87e05f9d2dd696e0caaa761d8de590c32b98056b89901c6864738a8dbfbcc8ff082859ef0d05609e19886a72828e02fa48eb0e756bd03badacb979095e749e873f79514370cbf4b0301dfbe2287f67fe325e0a1804c6ee0ca67ec71db21cd85feb6948a9d228fc9c77adcd7fd309e5ed1899dba9b45a567792aee8b946bd6374884185c01385a5b4eddc07cb6800851aa3aef9af3e8e25d0daa3bb3a83d98b4a9c43204f804c5aaa5727ebca0fca4f85f6b95c4af5133c2cc4d2ea15c61912046b6372dfc32386c4931bdce42b8ee1745fa095f4caf420481e001bac08bacdad2ccf1916d5853593db1eefbcc9224639a0d8826e95eb7185f531694913d86c0826a58a24bbdc08d387f2197833cc7bbcc36001002a6764f3fca628cd193e3b6a1a4c6a19199d1c92420417ee4d3220d331482088e1710f6e87b86566d621263dd60745fe7c1040003a75737d15795e083576c2332cd76df00ab3b621496b19164a95dbd75e29b832600c04240005faf65654a90bcaea1ac67d6f6564b2c0a40eaf842b294020a90ba37eda6a8717afe8845cfe9ed5d355b457e5a0d536e4d3b15e50f376b23d616ca0c34c2fe4271f9733540039975407c751aaf7d49c4a4cc998bcf18c4979e1ccdd29a0b6dfca502c4d74557b0c96b20a16f74e5996464d318a2576928d1b838c2ecd01fa94e4ce7df96124d3a0d341eb8baa017cf52d381400c95edb46a2b93fe237ef07b60d375b3951be5144b90974e1f8300c097ffd9f7dc6199e6190088a4faba2a0683fc62024ed34e80e6c760d5e3e60959c573077906d2b22f197bed063c25a882a4237b307b986e9e79a43c8af746032b5fd6d27caa069b3c4cc254d81cdec64d8479d4e7a38104b09a87cce2bd6e6878bc23a6cb05efc3c6991d97c93ccf82dd4056d5add589a77b019b7ddaa0286954818187206b53a4d25674357c1e27709520c79e981c9c4fedb965bcc0cac8a7254f6c1165a167345a14c7198af8b3c0328394b56ca6d09ebbae3ea2c5cd5";
    const SERVER_VEC_SIG: &str = "beacfb9e77a211ea535a2398e0974ec18e47e714bf01ee0c9592dc7ae3dea03bff4aa18083220ea66b8506f39a321e7fa7bd0b4eccff2c01942a7dee53d6e801507786532b5b51e8873f4224c15b44995753571f4ddd0c413f024b1b88a28cda3309807306406bbc821940a231fea764e1daea0c2d528c82a37459016349dea787f17d0ef534d94e39951668216ca6cf872553834efff7279eda4032721735659e88bea1c16de45483b6f964d0cdec245ec980b18772e838e00975eecc0c7dee3fd22b040eba59d64ccb5dd72254d7fdb352da7d84dd34ec99631d025a5dd026392e43b323bc6e1489ecf0b8e37a40525b7a5e9138946c4116cb40faf052b20de89151dae5da3a4872d70fa74ecd2f9fe301aef79d5446c42f5b65bdf99cf38039eba06eb875d28253ef0b825b5dca1d5ef899e7b25b23813fc8aace47d8b65a85c89dffc5ac98ea3baf36a915006c6c2e1acb6ab287545c897fb16e7707d4b3d7a9a091fe8202f360120d7024381c1eff299365a062183ed19d7852ecfa546d822820bdfee6263f70c162e608c21286134b5f696ace2d0f8f899265ff5fefd8a0af95fc5e833fef9088cbd673b633c757d7d9ff55a3aaffa2c89cd1bde0ee9791e1bc4b0aea1dca7e409d04df2d2648704cf9980f981d930f38ac6684203b33dc67d6ad6723a34e936c5a5287c365984b4fb5a43725be4ee42ce108db06848c79c40855df6c73ab107dec57469bf746b6ed65c17cfcd7a3fdb506af778e3ed177b5d9cffae30c7befbd394d4172e5f31a5292f25d81537e88c05e24c07dcd2895d899a4b424ab21f37b8b9425459cdc29c23c4181b5b2bb349b832ddb0e61ae7cd9e73c88691f534cf1fdf562fbd9580c187edc2fbea597c70b3e288cb76a9df41f9e1fe7256a09df6b5af20255535536cc10e718aceac6f39d2c2c320a06ff986d58f0051c616af351b64f8dace1ffcc0fd99f3e0cc4cfd713d6cb731da30df546be79739f087b6e98658299b3ba83c997133106b558d3a6b4048cb9415ca56c0fa416ac84ddab86d6ab1f925678736b6f295daf8fe72d947ca7f9cebb7e48002caa1aafd78bf9b0982f6ef3781bbe01a64ad1de3c069e7e80e6547f69bbdb2b250523cbdca528c14dacac53041c1f7cb330acbce84c396d7a267fdd882e433b9b4636363b93602423f41ca478e8938d45e76d428c1d48a171bc4780660c5b308c0185bd48f395dea424e5c827c53e2a54cb987905b32cd06ab1682d89c7b67dbc30a619b496b035df2b23970c24994f05ec21d82d61f2df0ce16deb3a774afaa77e3176dd4ff20fcb59eefc42558ae0e59b0dc6b6e9442ce1826d0b8129a9c594d370c378b93fc4e58a0d58a2584f8191f152aacb5645a897c5a91d9462e9918bed5580dcfa68c51ba355a0eefe43b6c73ce198cd006c277477a8c3e258b8fd03919c0d020d96e71b91a8fd97e70717aa8e55a6c6f45383e2ae46fde7b39a0a4f64fc1360d4e82432b2105771d6760b9e04f097178b5dcd65985fa5c439845d90854967484833e21103c9245441b499fccd5f0e4554bb17b240672912bc4b223159609ebdf51ba2e83c14cea0c43d9101c0497e6416966605e0ccab632ebabab3e44e57215f0692968b167813ed95cadfcadd1871271f6f3c3fb916683a0bc4972a5ddd44a67614c5d2e9284b5998446327a3a96c3d032c0c6d506b7a6962370996037099fd3598a0e4ef79b002886ec81c996f79bf80d1b69112266172fad145eff64522a83ee4ce3bab2c56423b4746272ff4bf403946eddfd8ea9716c4a6c090171e41a9a50a06d742f7812be7d39c98429e48800d32d466f491e79b515fbdb81db6094b7c37dbaeb24adbd13dffc90c825abcd70220833d1c323d187c66d4efaa1820bc9ae73f46af17b15bec9c5babee117e6c81233ff850c7301faf20f7f8f910b1b46e8a1d84d25597f308d38fdd1076697a6ef6f52b597cbf4c982530fccfef06706102dbf13624ddbdd90026da0605bd3a7f72845e44cd27103a2f8bc589bb1c8daf0c641beb856d1cfc023e796bb4258696bc085c400e8af1e609e2eb86a9cb365aee9db3cfec22533d36495034a8b9c1aad22c67974a681d1184988e175294b01b6cddad7364d4253c115ecd44154e829f54bc75080a6c7f7c93668574276a81b9889ccce49810dc9963236948cc46e4f4005a5bb03271fe90b3ceaceb0217d64f726bc51c09f6ae772fb33c0184932b1ad564d2c6563b41e7988c995d2e5da0a2b7d1cbef3df2771361176342ab143e055c97a7351c13b8fa8dba4baf30e21b36049a7fde6e2ae0f4c01421ce9c3d301934b795cac0c4e314f9dad004eb042abc92a65fc23a51851ad44cd8096e3dc0d4e68023a9228a0825e6fa064ccf1d8c8880f1d237c2097fe8bc3584baa7fd9682c9797900289dbf0e70c793b4b796c7f923e0f4a5bca412346ec02b9e9a2ef3bc8f2fbeb7a5f32597cfacded8ce1390364311296e299d87812ccc3785d501bfc7b52a62d78f311d1f6c4522e7ba8b9299e0a25c8852b3d59e22abf5679712804defc854189aed51497e48a0cc29739148aea651b53726693f0e9c91180ad88ba0b11e6f87bfee85f824f41272665ff65b3dc6160a0906b4ad315a66595845179fa9467850226ec403286377081b6717f1a0508f242e9552fed5bd655e747fde5039dafdf0d60d3c52b6da7342e7d9acc8e3b017495bb291b5fec9da1facc103d3b08fe64cea1e13ababddcef5b8072334815757bfe937454583f94452c9376bfca308c697f9ce50b0869c21793e47cf49131ed20937452e3455547989a3976e0295d83e7146b3f3452781310a33c6c856bfc43bf3e6c87da692369985bac579dd3b466c48fcc47928fe0c85124d9a68861e3f1370f9d1b8f8542febd5672479e8ba72d32c8bdf7eb809227471df25fcbd263322df12d5a72da159a74af53d548a8b3f6cee018831e3da330a5aa4b791ed4f39946ccebf3c17860d9218c427695c66ae0415dee4e09be19ff8d663900eb460b9443befb8a1fc6380700830065b58c8ba27a0b0c54c66566c5fc0312bae3f06faab6fdadea4e1da691567d16f7acbd4c388e5b191538c31d24067071230b5587c5a2de90fdff05b4731972054e354e1c7cfe8c16cf21bcd1a3cfe4f1d6643b6d50a3624d29ee318ee0d3b40ab83877bff4e1e2f849393ed5d606a97dd3e8733f6645b22473fb8312529f30570001409b6430bc8297a75d4cc4ed444f29f19b388cfee459859422e98c735a448e03b45f2ca59ecf6e234fcf3244ce0a4f65beb89346395e656c3ac1784cd74cee5a35f41161277af0bc59ecd23b713e054f5f690acf952237521bfc6a2e05e6b5806c64a7c30a439eb55820bcead06eaa963050e0bfc67ddb51c51f8c1ba125c554afc31227cfc041969f972cf230cd98d8a3385bb13a639ac3b74e5693d9b04bb99b6fc995888f6ff1fc28d7b92e2ea9c36ab08b77f5058fd2e3c2be3d44fa0d1304343265e4ca63e0d4e10707a395501165666991da22576bf4a10977455f98b412e1c1ab6205cac936df7638eddcf9638d2c030ccfa32c0fe35e5a74b8a4c546980ee45b9f927a0e4e9c2ebcc1a914f91d89a60b5031f5b13de02c4e4b401a9f43d5acfbcad7d23858cbab9515639a48bda76ed7f628c5965fad595a42131f37232628ea10fdea11afc5de613df511efaed42bb420788aa185f225288a247f2ba72e53a4a7402de5a75b22bc51495d04e288b9f72863f2e25f08ad9e1d3439fc31a9c544cd45d543eb2fbf114f985e72538ad6d4e09e900fd0b37a8a58f2a894693cc3ccb09f8e69040797c33fa9f385ae6b432745dcb3d85c5d7b178d17b5d1fd2c8142ee519fe6bdcdb103cfdbc19ef5bda96ede674cfe4d31329dfce0fa9b0c3eca39df438ed681eac5bae96ce0beef4e408e5c3270a7624b458e0f08157d740681484e82a366bd5acbff6a86b5f6aa2ff14f1bed40d212e23935e997eb3821a40117d1d7c674339701ea2a338e1f592af9cc299ff96e51c41a323c855ebfb664fd6761afb1904f0a23514964d8b6b53a55d6e17be5ea92750c745f838f428e6b158ba58368b0785c95de7dd2a1a5c4c76f02c52c3b315482bb3949d3b373ceef15c53e748b51585247ab8f4d3aa90717c08d7949b72b78fe2b4ec5666805781c01ba763a209ea5bd6a5f67e8ccfb5584c1f26798020d3a3b6dbf8a6710cf481dc2bf1d9ad8b4542ae430ccacc211c9de339991d1009006d9c844aa09125e3d135cb1258d407b8711ae5b2a6b7b41c69f6542b9dcce9f85fb3cbdc22f9d11691e42c23398b57d0b01cc3b75fdb3d6b1306646e09f133bf2c97ebbd5597787055eba405fe0b1faf281c27e2719de7eae529b464e71fea1e15341ca5ba96b63bb92eab201bde3cad9f734b6747e8854c16e1d081502eab9f2d53b3b939a26f79554554791281f50fc29b047dfcfa7a09953cf6a416e372bf5b8be4da4a4b01034cbd0fe04a19e13f01779677e1b2aedf24362c97ce564d647ffb16180d2a8ed3f77f31046eb7648cb875d99f83ec34486dac95681f1662318d33a5797341d7c2ac818e4c3eec5da1176eba317fe45c3f6204bc6563cb75a3d6bd903a26e2a306f5cecdbd5af15341749ff3c8ab9fcfccba2f241fcfb201bf223093c803082594ee3e6399bccad7db0a30fc021b227eab25518d91c5dee000000000000000000000000000000000000000000000000004091013181f";

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
        assert_eq!(ML_DSA_65_SECRET_KEY_SIZE, 32);
        assert_eq!(ML_DSA_65_SIGNATURE_SIZE, 3309);
        assert_eq!(HYBRID_SIG_PUBLIC_KEY_SIZE, 1984);
        assert_eq!(HYBRID_SIG_SECRET_KEY_SIZE, 2016);
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
