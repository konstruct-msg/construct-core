//! Post-quantum extensions for X3DH: ML-KEM-768 (CRYSTALS-Kyber) operations.
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
    pub secret_key: Vec<u8>,
}

/// Result of ML-KEM encapsulation: ciphertext sent to receiver, shared secret kept locally.
#[derive(Debug, Clone)]
pub struct MLKEMEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
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
    let sk_bytes: Vec<u8> = dk.to_expanded_bytes().to_vec();
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
        shared_secret: ss.to_vec(),
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
pub fn mlkem768_decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, String> {
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
    Ok(ss.to_vec())
}

#[cfg(not(feature = "post-quantum"))]
pub fn mlkem768_decapsulate(_sk_bytes: &[u8], _ct_bytes: &[u8]) -> Result<Vec<u8>, String> {
    Err("post-quantum feature not enabled".to_string())
}
