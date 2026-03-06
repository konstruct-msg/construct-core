//! Account recovery: BIP39 mnemonics + SLIP-0010 Ed25519 HD key derivation.
//!
//! # API (matches ACCOUNT_RECOVERY_CLIENT_SPEC.md v1.1)
//!
//! ```text
//! generate_mnemonic(word_count)          → mnemonic string
//! validate_mnemonic(mnemonic)            → bool
//! mnemonic_to_seed(mnemonic)             → [u8; 64]
//! derive_recovery_keypair(seed)          → RecoveryKeypair
//! sign_recovery_challenge(key, message)  → [u8; 64]
//! verify_recovery_signature(key, msg, sig) → bool
//! ```
//!
//! # Derivation path
//! Spec says `m/44'/0'/0'/0/0` (BIP44). For Ed25519, SLIP-0010 requires
//! ALL indices to be hardened (non-hardened child derivation is undefined).
//! We use `m/44'/0'/0'/0'/0'` and the server must match this convention.

use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::utils::error::{ConstructError, Result};

// ── Public types ──────────────────────────────────────────────────────────────

/// Ed25519 keypair derived from a recovery seed.
#[derive(Clone)]
pub struct RecoveryKeypair {
    /// 32-byte Ed25519 private key — keep in memory only, never persist.
    pub private_key: [u8; 32],
    /// 32-byte Ed25519 public key — sent to server in SetRecoveryKey.
    pub public_key: [u8; 32],
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a BIP39 mnemonic with the given word count (12 or 24).
pub fn generate_mnemonic(word_count: u8) -> Result<String> {
    let mnemonic = Mnemonic::generate(word_count as usize)
        .map_err(|e| ConstructError::InternalError(format!("BIP39 generate failed: {e}")))?;
    Ok(mnemonic.to_string())
}

/// Validate BIP39 checksum and word membership.
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    mnemonic.parse::<Mnemonic>().is_ok()
}

/// Convert a BIP39 mnemonic to a 64-byte seed via PBKDF2-HMAC-SHA512
/// (2048 rounds, no passphrase). This is the BIP39 standard derivation.
pub fn mnemonic_to_seed(mnemonic: &str) -> Result<[u8; 64]> {
    let m: Mnemonic = mnemonic
        .parse()
        .map_err(|e| ConstructError::InternalError(format!("Invalid mnemonic: {e}")))?;
    Ok(m.to_seed(""))
}

/// Derive an Ed25519 recovery keypair from a 64-byte BIP39 seed.
///
/// Derivation: SLIP-0010, path m/44'/0'/0'/0'/0' (all hardened — required for Ed25519).
pub fn derive_recovery_keypair(seed: &[u8]) -> Result<RecoveryKeypair> {
    if seed.len() < 16 {
        return Err(ConstructError::InternalError(format!(
            "Seed too short: {} bytes (need ≥ 16)",
            seed.len()
        )));
    }

    // SLIP-0010 master key from seed
    let (mut key, mut chain) = slip10_master_key(seed);

    // m/44'/0'/0'/0'/0' — all five components hardened
    for index in [44u32, 0, 0, 0, 0] {
        let (k, c) = slip10_hardened_child(&key, &chain, index);
        key = k;
        chain = c;
    }

    let signing_key = SigningKey::from_bytes(&key);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    Ok(RecoveryKeypair {
        private_key: key,
        public_key: verifying_key.to_bytes(),
    })
}

/// Sign a message string with a 32-byte Ed25519 private key.
/// Returns a 64-byte detached signature.
pub fn sign_recovery_challenge(private_key: &[u8; 32], message: &str) -> Result<[u8; 64]> {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature: Signature = signing_key.sign(message.as_bytes());
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature over a message using a 32-byte public key.
pub fn verify_recovery_signature(
    public_key: &[u8; 32],
    message: &str,
    signature: &[u8; 64],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(message.as_bytes(), &sig).is_ok()
}

/// Compute a short fingerprint of a public key for UI display.
/// Format: first 8 bytes of SHA-256(pubkey) as "A1B2 C3D4 E5F6 G7H8".
pub fn compute_key_fingerprint(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    hash[..8]
        .chunks(2)
        .map(|pair| format!("{:02X}{:02X}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── SLIP-0010 internals ───────────────────────────────────────────────────────

/// SLIP-0010 master key: HMAC-SHA512(Key="ed25519 seed", Data=seed)
/// Returns (master_key[32], chain_code[32]).
fn slip10_master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let result = hmac_sha512(b"ed25519 seed", seed);
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain.copy_from_slice(&result[32..]);
    (key, chain)
}

/// SLIP-0010 hardened child: HMAC-SHA512(Key=chain, Data=0x00||parent_key||ser32(index|0x80000000))
/// Returns (child_key[32], child_chain[32]).
fn slip10_hardened_child(
    parent_key: &[u8; 32],
    parent_chain: &[u8; 32],
    index: u32,
) -> ([u8; 32], [u8; 32]) {
    let hardened = index | 0x8000_0000;
    let mut data = [0u8; 37]; // 1 + 32 + 4
    data[0] = 0x00;
    data[1..33].copy_from_slice(parent_key);
    data[33..37].copy_from_slice(&hardened.to_be_bytes());

    let result = hmac_sha512(parent_chain, &data);
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain.copy_from_slice(&result[32..]);
    (key, chain)
}

fn hmac_sha512(secret: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac =
        <Hmac<Sha512>>::new_from_slice(secret).expect("HMAC-SHA512 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_generate_12_words() {
        let m = generate_mnemonic(12).unwrap();
        assert_eq!(m.split_whitespace().count(), 12);
        assert!(validate_mnemonic(&m));
    }

    #[test]
    fn test_generate_24_words() {
        let m = generate_mnemonic(24).unwrap();
        assert_eq!(m.split_whitespace().count(), 24);
    }

    #[test]
    fn test_validate_rejects_garbage() {
        assert!(!validate_mnemonic("not valid words at all hey there"));
        assert!(!validate_mnemonic(""));
    }

    #[test]
    fn test_mnemonic_to_seed_length() {
        let seed = mnemonic_to_seed(TEST_PHRASE).unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_derivation_deterministic() {
        let seed = mnemonic_to_seed(TEST_PHRASE).unwrap();
        let kp1 = derive_recovery_keypair(&seed).unwrap();
        let kp2 = derive_recovery_keypair(&seed).unwrap();
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.private_key, kp2.private_key);
    }

    #[test]
    fn test_different_mnemonics_different_keys() {
        let s1 = mnemonic_to_seed(TEST_PHRASE).unwrap();
        let s2 = mnemonic_to_seed(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        )
        .unwrap();
        let kp1 = derive_recovery_keypair(&s1).unwrap();
        let kp2 = derive_recovery_keypair(&s2).unwrap();
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = mnemonic_to_seed(TEST_PHRASE).unwrap();
        let kp = derive_recovery_keypair(&seed).unwrap();
        let challenge = "CONSTRUCT_RECOVERY_SETUP:user123:1741200000";
        let sig = sign_recovery_challenge(&kp.private_key, challenge).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify_recovery_signature(&kp.public_key, challenge, &sig));
        // Wrong message → invalid
        assert!(!verify_recovery_signature(&kp.public_key, "wrong_message", &sig));
    }

    #[test]
    fn test_fingerprint_format() {
        let seed = mnemonic_to_seed(TEST_PHRASE).unwrap();
        let kp = derive_recovery_keypair(&seed).unwrap();
        let fp = compute_key_fingerprint(&kp.public_key);
        // Format: "XXXX XXXX XXXX XXXX" = 4 groups of 4 hex chars separated by spaces
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.chars().filter(|c| *c == ' ').count(), 3);
    }
}
