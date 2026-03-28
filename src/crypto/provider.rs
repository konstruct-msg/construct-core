//! Defines the CryptoProvider trait for crypto-agility.

use crate::error::CryptoError;
use core::fmt::Debug;
use zeroize::Zeroize;

/// Trait that formalizes all cryptographic operations for a specific cipher suite.
/// This enables crypto-agility by allowing different implementations (e.g., classic, PQ-hybrid).
pub trait CryptoProvider: Send + Sync + 'static {
    // Associated types for key representation (using Vec<u8> for flexibility)
    type KemPublicKey: AsRef<[u8]> + Debug + Clone + 'static;
    type KemPrivateKey: AsRef<[u8]> + Debug + Clone + Zeroize + 'static;
    type SignaturePublicKey: AsRef<[u8]> + Debug + Clone + 'static;
    type SignaturePrivateKey: AsRef<[u8]> + Debug + Clone + 'static;
    type AeadKey: AsRef<[u8]> + Debug + Clone + Default + 'static; // Added Default bound

    /// Generates a new KEM key pair.
    fn generate_kem_keys() -> Result<(Self::KemPrivateKey, Self::KemPublicKey), CryptoError>;

    /// Derives a KEM public key from a KEM private key.
    fn from_private_key_to_public_key(
        private_key: &Self::KemPrivateKey,
    ) -> Result<Self::KemPublicKey, CryptoError>;

    /// Creates a KEM public key from raw bytes
    fn kem_public_key_from_bytes(bytes: Vec<u8>) -> Self::KemPublicKey;

    /// Creates a KEM private key from raw bytes
    fn kem_private_key_from_bytes(bytes: Vec<u8>) -> Self::KemPrivateKey;

    /// Creates an AEAD key from raw bytes
    fn aead_key_from_bytes(bytes: Vec<u8>) -> Self::AeadKey;

    /// Creates a Signature public key from raw bytes
    fn signature_public_key_from_bytes(bytes: Vec<u8>) -> Self::SignaturePublicKey;

    /// Creates a Signature private key from raw bytes
    fn signature_private_key_from_bytes(bytes: Vec<u8>) -> Self::SignaturePrivateKey;

    /// Generates a new Signature key pair.
    fn generate_signature_keys()
    -> Result<(Self::SignaturePrivateKey, Self::SignaturePublicKey), CryptoError>;

    /// Derives a Signature public key from a Signature private key.
    fn from_signature_private_to_public(
        private_key: &Self::SignaturePrivateKey,
    ) -> Result<Self::SignaturePublicKey, CryptoError>;

    /// Signs a message with the given private key.
    fn sign(
        private_key: &Self::SignaturePrivateKey,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Verifies a signature with the given public key.
    fn verify(
        public_key: &Self::SignaturePublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    /// Encapsulates a shared secret using the recipient's KEM public key.
    /// Returns the encapsulated ciphertext and the shared secret.
    fn kem_encapsulate(public_key: &Self::KemPublicKey) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Decapsulates a shared secret using the recipient's KEM private key and the encapsulated ciphertext.
    fn kem_decapsulate(
        private_key: &Self::KemPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Performs AEAD encryption.
    /// `key`: The symmetric encryption key.
    /// `nonce`: The unique nonce for this encryption.
    /// `plaintext`: The data to encrypt.
    /// `associated_data`: Optional associated data (authenticated but not encrypted).
    fn aead_encrypt(
        key: &Self::AeadKey,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Performs AEAD decryption.
    /// `key`: The symmetric encryption key.
    /// `nonce`: The unique nonce used for encryption.
    /// `ciphertext`: The encrypted data.
    /// `associated_data`: Optional associated data.
    fn aead_decrypt(
        // Corrected typo: aead_decryp to aead_decrypt
        key: &Self::AeadKey,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Derives a key from input key material using HKDF.
    fn hkdf_derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Derives a root key and a chain key from the current root key and DH output.
    fn kdf_rk(
        root_key: &Self::AeadKey,
        dh_output: &[u8],
    ) -> Result<(Self::AeadKey, Self::AeadKey), CryptoError>;

    /// Derives a message key and the next chain key from the current chain key.
    fn kdf_ck(chain_key: &Self::AeadKey) -> Result<(Self::AeadKey, Self::AeadKey), CryptoError>;

    /// Generates a cryptographically secure random nonce of a specified length.
    fn generate_nonce(len: usize) -> Result<Vec<u8>, CryptoError>;

    /// Returns the SuiteID associated with this CryptoProvider.
    fn suite_id() -> u16;
}
