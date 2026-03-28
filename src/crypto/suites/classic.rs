use crate::crypto::provider::CryptoProvider;
use crate::error::CryptoError;
use chacha20poly1305::{
    ChaCha20Poly1305, Key as AeadKeyChacha, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as KemPublicKeyDalek, StaticSecret};

/// Concrete implementation of `CryptoProvider` for the classic suite.
pub struct ClassicSuiteProvider;

impl CryptoProvider for ClassicSuiteProvider {
    type KemPublicKey = Vec<u8>;
    type KemPrivateKey = Vec<u8>;
    type SignaturePublicKey = Vec<u8>;
    type SignaturePrivateKey = Vec<u8>;
    type AeadKey = Vec<u8>;

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
        let bytes_slice: &[u8] = private_key.as_ref();
        let bytes: &[u8; 32] = bytes_slice.try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid KEM private key length".to_string())
        })?;
        let static_secret = StaticSecret::from(*bytes);
        let public_key = KemPublicKeyDalek::from(&static_secret);
        Ok(public_key.to_bytes().to_vec())
    }

    fn kem_public_key_from_bytes(bytes: Vec<u8>) -> Self::KemPublicKey {
        // For ClassicSuiteProvider, KemPublicKey is Vec<u8>, so just return it
        bytes
    }

    fn kem_private_key_from_bytes(bytes: Vec<u8>) -> Self::KemPrivateKey {
        // For ClassicSuiteProvider, KemPrivateKey is Vec<u8>, so just return it
        bytes
    }

    fn aead_key_from_bytes(bytes: Vec<u8>) -> Self::AeadKey {
        // For ClassicSuiteProvider, AeadKey is Vec<u8>, so just return it
        bytes
    }

    fn signature_public_key_from_bytes(bytes: Vec<u8>) -> Self::SignaturePublicKey {
        // For ClassicSuiteProvider, SignaturePublicKey is Vec<u8>, so just return it
        bytes
    }

    fn signature_private_key_from_bytes(bytes: Vec<u8>) -> Self::SignaturePrivateKey {
        // For ClassicSuiteProvider, SignaturePrivateKey is Vec<u8>, so just return it
        bytes
    }

    fn generate_signature_keys()
    -> Result<(Self::SignaturePrivateKey, Self::SignaturePublicKey), CryptoError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok((
            signing_key.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
        ))
    }

    fn from_signature_private_to_public(
        private_key: &Self::SignaturePrivateKey,
    ) -> Result<Self::SignaturePublicKey, CryptoError> {
        let bytes_slice: &[u8] = private_key.as_ref();
        let bytes: &[u8; 32] = bytes_slice.try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid signing key length".to_string())
        })?;
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(verifying_key.to_bytes().to_vec())
    }

    fn sign(
        private_key: &Self::SignaturePrivateKey,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let bytes_slice: &[u8] = private_key.as_ref();
        let bytes: &[u8; 32] = bytes_slice.try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid signing key length".to_string())
        })?;
        let signing_key = SigningKey::from_bytes(bytes);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::SignaturePublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let vk_slice: &[u8] = public_key.as_ref();
        let vk_bytes: &[u8; 32] = vk_slice.try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid verifying key length".to_string())
        })?;
        let verifying_key = VerifyingKey::from_bytes(vk_bytes)
            .map_err(|e| CryptoError::InvalidInputError(format!("Invalid verifying key: {}", e)))?;

        let sig_bytes: &[u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidInputError("Invalid signature length".to_string()))?;
        let signature_obj = Signature::from_bytes(sig_bytes);

        verifying_key
            .verify(message, &signature_obj)
            .map_err(|e| CryptoError::SignatureVerificationError(e.to_string()))
    }

    fn kem_encapsulate(public_key: &Self::KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let pk_slice: &[u8] = public_key.as_ref();
        let pk_bytes: &[u8; 32] = pk_slice.try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid KEM public key length".to_string())
        })?;
        let recipient_public_key = KemPublicKeyDalek::from(*pk_bytes);

        // Get ephemeral public key before consuming ephemeral_secret
        let ephemeral_public_key = KemPublicKeyDalek::from(&ephemeral_secret);

        // Now consume ephemeral_secret in DH
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);

        Ok((
            ephemeral_public_key.to_bytes().to_vec(),
            shared_secret.to_bytes().to_vec(),
        ))
    }

    fn kem_decapsulate(
        private_key: &Self::KemPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let pk_slice: &[u8] = private_key.as_ref();
        let bytes: &[u8; 32] = pk_slice.try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid KEM private key length".to_string())
        })?;
        let static_secret = StaticSecret::from(*bytes);

        let ct_bytes: &[u8; 32] = ciphertext.try_into().map_err(|_| {
            CryptoError::InvalidInputError("Invalid KEM ciphertext length".to_string())
        })?;
        let ephemeral_public_key = KemPublicKeyDalek::from(*ct_bytes);

        let shared_secret = static_secret.diffie_hellman(&ephemeral_public_key);
        Ok(shared_secret.to_bytes().to_vec())
    }

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

        let ciphertext_with_tag = cipher
            .encrypt(nonce_ref, payload)
            .map_err(|e| CryptoError::AeadEncryptionError(e.to_string()))?;
        Ok(ciphertext_with_tag)
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

        let plaintext = cipher
            .decrypt(nonce_ref, payload)
            .map_err(|e| CryptoError::AeadDecryptionError(e.to_string()))?;
        Ok(plaintext)
    }

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

        let new_root_key = output[..32].to_vec();
        let chain_key = output[32..].to_vec();

        Ok((new_root_key, chain_key))
    }

    fn kdf_ck(chain_key: &Self::AeadKey) -> Result<(Self::AeadKey, Self::AeadKey), CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(chain_key.as_ref()), b"");
        let mut output = vec![0u8; 64];
        hkdf.expand(b"Double-Ratchet-Chain-Key-Expansion", &mut output)
            .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

        let message_key = output[..32].to_vec();
        let next_chain = output[32..].to_vec();

        Ok((message_key, next_chain))
    }

    fn generate_nonce(len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut nonce_bytes);
        Ok(nonce_bytes)
    }

    fn suite_id() -> u16 {
        crate::config::Config::global().classic_suite_id
    }
}
