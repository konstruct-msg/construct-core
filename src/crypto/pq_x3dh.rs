//! Post-quantum extensions for X3DH: ML-KEM (CRYSTALS-Kyber) operations.
//!
//! Two parameter sets, for two jobs (construct-docs `cryptocore/PQXDH_V2_DESIGN.md`):
//! - **ML-KEM-1024** for Kyber prekeys and the first message's encapsulation. A prekey is
//!   long-lived and guards the start of every session, so it gets the margin — the split Signal
//!   (PQXDH on Kyber-1024) and Apple PQ3 (1024 to establish) make too. Secrets are held as the
//!   FIPS 203 64-byte seed `d ‖ z`, not the 3168-byte expanded key.
//! - **ML-KEM-768** for the legacy deferred contribution and the suite-3 sparse ratchet, whose
//!   keys are fresh and frequent.
//!
//! Provides standalone KEM primitives used by the PQXDH protocol:
//! - Key generation for registration/upload
//! - Encapsulation (sender side of handshake)
//! - Decapsulation (receiver side of handshake)
//!
//! These are exposed via UniFFI to Swift. Swift orchestrates the PQXDH handshake
//! and calls `ClassicCryptoCore::apply_pq_contribution` to mix the KEM shared
//! secret into the existing Double Ratchet session root key.

/// ML-KEM-768 public key size in bytes (NIST FIPS 203)
pub const MLKEM768_PK_SIZE: usize = 1184;
/// ML-KEM-768 secret key size in bytes
pub const MLKEM768_SK_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext size in bytes
pub const MLKEM768_CT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size in bytes
pub const MLKEM768_SS_SIZE: usize = 32;

/// A generated ML-KEM-768 keypair.
#[derive(Debug, Clone)]
pub struct MLKEMKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: crate::crypto::SecretBytes,
}

/// Result of ML-KEM encapsulation: ciphertext sent to receiver, shared secret kept locally.
#[derive(Debug, Clone)]
pub struct MLKEMEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: crate::crypto::SecretBytes,
}

/// Generate an ML-KEM-768 keypair.
///
/// Returns `(public_key, secret_key)` as raw bytes.
#[cfg(feature = "post-quantum")]
pub fn mlkem768_keygen() -> Result<MLKEMKeyPair, String> {
    use getrandom_pq::SysRng;
    use getrandom_pq::rand_core::UnwrapErr;
    #[allow(deprecated)]
    use ml_kem::{
        DecapsulationKey, EncapsulationKey, ExpandedKeyEncoding, Generate, KeyExport, MlKem768,
    };
    let mut rng = UnwrapErr(SysRng);
    let dk = DecapsulationKey::<MlKem768>::generate_from_rng(&mut rng);
    let ek: &EncapsulationKey<MlKem768> = dk.encapsulation_key();
    let pk_bytes: Vec<u8> = ek.to_bytes().to_vec();
    #[allow(deprecated)]
    let sk_bytes = crate::crypto::SecretBytes::from_slice(&dk.to_expanded_bytes());
    Ok(MLKEMKeyPair {
        public_key: pk_bytes,
        secret_key: sk_bytes,
    })
}

#[cfg(not(feature = "post-quantum"))]
pub fn mlkem768_keygen() -> Result<MLKEMKeyPair, String> {
    Err("post-quantum feature not enabled".to_string())
}

/// Encapsulate to a recipient's ML-KEM-768 public key.
///
/// Returns `(ciphertext, shared_secret)`. The ciphertext is sent to the recipient;
/// the shared secret is mixed into the session root key.
#[cfg(feature = "post-quantum")]
pub fn mlkem768_encapsulate(pk_bytes: &[u8]) -> Result<MLKEMEncapsulation, String> {
    use ml_kem::{Encapsulate, EncapsulationKey, MlKem768};
    if pk_bytes.len() != MLKEM768_PK_SIZE {
        return Err(format!(
            "Invalid ML-KEM-768 public key size: expected {}, got {}",
            MLKEM768_PK_SIZE,
            pk_bytes.len()
        ));
    }
    let pk_arr: &ml_kem::array::Array<u8, _> = pk_bytes
        .try_into()
        .map_err(|_| "Failed to convert pk slice".to_string())?;
    let ek = EncapsulationKey::<MlKem768>::new(pk_arr)
        .map_err(|_| "Invalid ML-KEM-768 public key".to_string())?;
    use getrandom_pq::SysRng;
    use getrandom_pq::rand_core::UnwrapErr;
    let mut rng = UnwrapErr(SysRng);
    let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
    Ok(MLKEMEncapsulation {
        ciphertext: ct.to_vec(),
        shared_secret: crate::crypto::SecretBytes::from_slice(&ss),
    })
}

#[cfg(not(feature = "post-quantum"))]
pub fn mlkem768_encapsulate(_pk_bytes: &[u8]) -> Result<MLKEMEncapsulation, String> {
    Err("post-quantum feature not enabled".to_string())
}

/// Decapsulate from a received ML-KEM-768 ciphertext using our secret key.
///
/// Returns the shared secret, which must match the sender's shared secret.
#[cfg(feature = "post-quantum")]
#[allow(deprecated)] // ExpandedKeyEncoding: key format uses expanded bytes for backward compat
pub fn mlkem768_decapsulate(
    sk_bytes: &[u8],
    ct_bytes: &[u8],
) -> Result<crate::crypto::SecretBytes, String> {
    use ml_kem::{Decapsulate, DecapsulationKey, ExpandedKeyEncoding, MlKem768};
    if sk_bytes.len() != MLKEM768_SK_SIZE {
        return Err(format!(
            "Invalid ML-KEM-768 secret key size: expected {}, got {}",
            MLKEM768_SK_SIZE,
            sk_bytes.len()
        ));
    }
    if ct_bytes.len() != MLKEM768_CT_SIZE {
        return Err(format!(
            "Invalid ML-KEM-768 ciphertext size: expected {}, got {}",
            MLKEM768_CT_SIZE,
            ct_bytes.len()
        ));
    }
    let sk_arr: &ml_kem::array::Array<u8, _> = sk_bytes
        .try_into()
        .map_err(|_| "Failed to convert sk slice".to_string())?;
    let dk = DecapsulationKey::<MlKem768>::from_expanded_bytes(sk_arr)
        .map_err(|_| "Invalid ML-KEM-768 secret key".to_string())?;
    let ss = dk
        .decapsulate_slice(ct_bytes)
        .map_err(|_| "ML-KEM-768 decapsulation failed (bad ciphertext size)".to_string())?;
    Ok(crate::crypto::SecretBytes::from_slice(&ss))
}

#[cfg(not(feature = "post-quantum"))]
pub fn mlkem768_decapsulate(
    _sk_bytes: &[u8],
    _ct_bytes: &[u8],
) -> Result<crate::crypto::SecretBytes, String> {
    Err("post-quantum feature not enabled".to_string())
}

// ── ML-KEM-1024: Kyber prekeys (PQXDH v2) ──────────────────────────────────────

/// ML-KEM-1024 public (encapsulation) key size in bytes (NIST FIPS 203)
pub const MLKEM1024_PK_SIZE: usize = 1568;
/// ML-KEM-1024 ciphertext size in bytes
pub const MLKEM1024_CT_SIZE: usize = 1568;
/// ML-KEM decapsulation-key seed `d ‖ z` (FIPS 203), the form a Kyber prekey secret is kept in
pub const MLKEM_SEED_SIZE: usize = 64;

/// Generate a fresh ML-KEM-1024 key; returns `(seed, public_key)`.
#[cfg(feature = "post-quantum")]
pub fn mlkem1024_generate() -> Result<(crate::crypto::SecretBytes, Vec<u8>), String> {
    use getrandom_pq::SysRng;
    use getrandom_pq::rand_core::UnwrapErr;
    use ml_kem::{DecapsulationKey, Generate, KeyExport, MlKem1024};
    let mut rng = UnwrapErr(SysRng);
    let dk = DecapsulationKey::<MlKem1024>::generate_from_rng(&mut rng);
    let seed = dk
        .to_seed()
        .ok_or_else(|| "ML-KEM-1024 key generated without a seed".to_string())?;
    let public = dk.encapsulation_key().to_bytes().to_vec();
    Ok((crate::crypto::SecretBytes::from_slice(&seed), public))
}

#[cfg(not(feature = "post-quantum"))]
pub fn mlkem1024_generate() -> Result<(crate::crypto::SecretBytes, Vec<u8>), String> {
    Err("post-quantum feature not enabled".to_string())
}

#[cfg(feature = "post-quantum")]
fn mlkem1024_key_from_seed(
    seed: &[u8],
) -> Result<ml_kem::DecapsulationKey<ml_kem::MlKem1024>, String> {
    if seed.len() != MLKEM_SEED_SIZE {
        return Err(format!(
            "Invalid ML-KEM seed size: expected {MLKEM_SEED_SIZE}, got {}",
            seed.len()
        ));
    }
    let seed: ml_kem::Seed = seed
        .try_into()
        .map_err(|_| "Failed to convert seed slice".to_string())?;
    Ok(ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(
        seed,
    ))
}

/// The ML-KEM-1024 public key a seed expands to.
#[cfg(feature = "post-quantum")]
pub fn mlkem1024_public_from_seed(seed: &[u8]) -> Result<Vec<u8>, String> {
    use ml_kem::KeyExport;
    Ok(mlkem1024_key_from_seed(seed)?
        .encapsulation_key()
        .to_bytes()
        .to_vec())
}

#[cfg(not(feature = "post-quantum"))]
pub fn mlkem1024_public_from_seed(_seed: &[u8]) -> Result<Vec<u8>, String> {
    Err("post-quantum feature not enabled".to_string())
}

/// Encapsulate to an ML-KEM-1024 public key.
#[cfg(feature = "post-quantum")]
pub fn mlkem1024_encapsulate(pk_bytes: &[u8]) -> Result<MLKEMEncapsulation, String> {
    use getrandom_pq::SysRng;
    use getrandom_pq::rand_core::UnwrapErr;
    use ml_kem::{Encapsulate, EncapsulationKey, MlKem1024};
    if pk_bytes.len() != MLKEM1024_PK_SIZE {
        return Err(format!(
            "Invalid ML-KEM-1024 public key size: expected {MLKEM1024_PK_SIZE}, got {}",
            pk_bytes.len()
        ));
    }
    let pk_arr: &ml_kem::array::Array<u8, _> = pk_bytes
        .try_into()
        .map_err(|_| "Failed to convert pk slice".to_string())?;
    let ek = EncapsulationKey::<MlKem1024>::new(pk_arr)
        .map_err(|_| "Invalid ML-KEM-1024 public key".to_string())?;
    let mut rng = UnwrapErr(SysRng);
    let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
    Ok(MLKEMEncapsulation {
        ciphertext: ct.to_vec(),
        shared_secret: crate::crypto::SecretBytes::from_slice(&ss),
    })
}

#[cfg(not(feature = "post-quantum"))]
pub fn mlkem1024_encapsulate(_pk_bytes: &[u8]) -> Result<MLKEMEncapsulation, String> {
    Err("post-quantum feature not enabled".to_string())
}

/// Decapsulate an ML-KEM-1024 ciphertext with the key a seed expands to.
///
/// A ciphertext for another key does **not** fail: ML-KEM's implicit rejection returns a
/// pseudorandom secret, so a wrong key surfaces later, as an AEAD failure, never here.
#[cfg(feature = "post-quantum")]
pub fn mlkem1024_decapsulate(
    seed: &[u8],
    ct_bytes: &[u8],
) -> Result<crate::crypto::SecretBytes, String> {
    use ml_kem::Decapsulate;
    if ct_bytes.len() != MLKEM1024_CT_SIZE {
        return Err(format!(
            "Invalid ML-KEM-1024 ciphertext size: expected {MLKEM1024_CT_SIZE}, got {}",
            ct_bytes.len()
        ));
    }
    let ss = mlkem1024_key_from_seed(seed)?
        .decapsulate_slice(ct_bytes)
        .map_err(|_| "ML-KEM-1024 decapsulation failed (bad ciphertext size)".to_string())?;
    Ok(crate::crypto::SecretBytes::from_slice(&ss))
}

#[cfg(not(feature = "post-quantum"))]
pub fn mlkem1024_decapsulate(
    _seed: &[u8],
    _ct_bytes: &[u8],
) -> Result<crate::crypto::SecretBytes, String> {
    Err("post-quantum feature not enabled".to_string())
}

#[cfg(all(test, feature = "post-quantum"))]
mod mlkem1024_tests {
    use super::*;

    #[test]
    fn sizes_are_ml_kem_1024() {
        let (seed, public) = mlkem1024_generate().unwrap();
        assert_eq!(seed.len(), MLKEM_SEED_SIZE);
        assert_eq!(public.len(), MLKEM1024_PK_SIZE);
        let enc = mlkem1024_encapsulate(&public).unwrap();
        assert_eq!(enc.ciphertext.len(), MLKEM1024_CT_SIZE);
        assert_eq!(enc.shared_secret.len(), 32);
    }

    #[test]
    fn a_seed_is_the_whole_secret() {
        let (seed, public) = mlkem1024_generate().unwrap();
        assert_eq!(mlkem1024_public_from_seed(seed.expose()).unwrap(), public);
        let enc = mlkem1024_encapsulate(&public).unwrap();
        let ss = mlkem1024_decapsulate(seed.expose(), &enc.ciphertext).unwrap();
        assert_eq!(ss.expose(), enc.shared_secret.expose());
    }

    /// Implicit rejection: another key's ciphertext yields a different secret, not an error.
    #[test]
    fn a_wrong_key_decapsulates_to_a_different_secret() {
        let (_, public) = mlkem1024_generate().unwrap();
        let (other_seed, _) = mlkem1024_generate().unwrap();
        let enc = mlkem1024_encapsulate(&public).unwrap();
        let ss = mlkem1024_decapsulate(other_seed.expose(), &enc.ciphertext).unwrap();
        assert_ne!(ss.expose(), enc.shared_secret.expose());
    }

    #[test]
    fn a_768_key_is_refused() {
        let kp = mlkem768_keygen().unwrap();
        assert!(mlkem1024_encapsulate(&kp.public_key).is_err());
    }
}
