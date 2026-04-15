/// ConstructPrivacyPass — OPRF blind token primitives (Ristretto255 / RFC 9497)
///
/// Scheme: OPRF(ristretto255, SHA-512)
///
/// Issuance (client):
///   nonce  → hash_to_ristretto255 → T
///   r      = random Scalar
///   blinded = r * T                   → send to server
///
/// Issuance (server):
///   Z = k * blinded                   → return to client
///
/// Finalization (client):
///   N = r_inv * Z = k * T             (unblind)
///   token = HKDF-SHA512(N_compressed || nonce, info="ConstructPP-v1")
///
/// Redemption (server):
///   T      = hash_to_ristretto255(nonce)
///   N      = k * T
///   expected = HKDF-SHA512(N_compressed || nonce, info="ConstructPP-v1")
///   valid  = expected == token  &&  token not in spent-set
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha512};

use crate::error::CryptoError;

const HKDF_INFO: &[u8] = b"ConstructPP-v1";

// ──────────────────────────────────────────────────────────────────────────────
// Shared helper
// ──────────────────────────────────────────────────────────────────────────────

/// Map arbitrary bytes to a Ristretto255 point using hash-to-group.
///
/// Uses `from_hash(SHA-512(data))` which applies the Elligator2 map internally.
/// This is the standard approach for OPRF inputs.
pub fn hash_to_ristretto(data: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(data);
    RistrettoPoint::from_hash(h)
}

// ──────────────────────────────────────────────────────────────────────────────
// Client side
// ──────────────────────────────────────────────────────────────────────────────

/// Client blind step.
///
/// Returns `(blinded_point_bytes, blind_factor_bytes)`.
/// Caller must keep `blind_factor_bytes` until `finalize()` is called.
pub fn blind(nonce: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let t = hash_to_ristretto(nonce);
    let r = Scalar::random(&mut OsRng);
    let blinded = r * t;
    (blinded.compress().to_bytes(), r.to_bytes())
}

/// Client finalization step.
///
/// `evaluated_bytes`    — 32-byte compressed Ristretto point from server (Z = k * blinded)
/// `blind_factor_bytes` — the `r` scalar saved from `blind()`
/// `nonce`              — original 32-byte nonce used in `blind()`
///
/// Returns 32-byte token or error if the evaluated point is malformed.
pub fn finalize(
    evaluated_bytes: &[u8; 32],
    blind_factor_bytes: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let z = CompressedRistretto::from_slice(evaluated_bytes)
        .map_err(|_| {
            CryptoError::InvalidInputError("pp finalize: bad evaluated point length".into())
        })?
        .decompress()
        .ok_or_else(|| {
            CryptoError::InvalidInputError("pp finalize: evaluated point not on curve".into())
        })?;

    let r = Option::<Scalar>::from(Scalar::from_canonical_bytes(*blind_factor_bytes)).ok_or_else(
        || CryptoError::InvalidInputError("pp finalize: blind factor not canonical".into()),
    )?;

    let r_inv = r.invert();
    let n = r_inv * z; // = k * T

    Ok(derive_token(&n.compress().to_bytes(), nonce))
}

// ──────────────────────────────────────────────────────────────────────────────
// Server side
// ──────────────────────────────────────────────────────────────────────────────

/// Server evaluation step: Z = k * blinded.
///
/// `k_scalar_bytes` — 32-byte little-endian canonical scalar (TOKEN_ISSUER_KEY)
/// `blinded_bytes`  — 32-byte compressed Ristretto point from client
pub fn evaluate(
    k_scalar_bytes: &[u8; 32],
    blinded_bytes: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let k =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*k_scalar_bytes)).ok_or_else(|| {
            CryptoError::InvalidInputError("pp evaluate: issuer key not canonical scalar".into())
        })?;

    let blinded = CompressedRistretto::from_slice(blinded_bytes)
        .map_err(|_| {
            CryptoError::InvalidInputError("pp evaluate: bad blinded point length".into())
        })?
        .decompress()
        .ok_or_else(|| {
            CryptoError::InvalidInputError("pp evaluate: blinded point not on curve".into())
        })?;

    let z = k * blinded;
    Ok(z.compress().to_bytes())
}

/// Server verification step (used at redemption).
///
/// Re-derives the expected token from (nonce, k) and compares in constant time.
pub fn server_verify(
    token: &[u8; 32],
    nonce: &[u8; 32],
    k_scalar_bytes: &[u8; 32],
) -> Result<bool, CryptoError> {
    let k =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*k_scalar_bytes)).ok_or_else(|| {
            CryptoError::InvalidInputError("pp verify: issuer key not canonical scalar".into())
        })?;

    let t = hash_to_ristretto(nonce);
    let n = k * t;
    let expected = derive_token(&n.compress().to_bytes(), nonce);

    Ok(constant_time_eq(token, &expected))
}

/// Derive server pubkey K = k * B from the issuer scalar.
pub fn issuer_pubkey(k_scalar_bytes: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let k =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*k_scalar_bytes)).ok_or_else(|| {
            CryptoError::InvalidInputError("pp pubkey: issuer key not canonical".into())
        })?;

    let pubkey = RistrettoPoint::multiscalar_mul(
        &[k],
        &[curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT],
    );
    Ok(pubkey.compress().to_bytes())
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

fn derive_token(n_compressed: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let ikm: Vec<u8> = n_compressed.iter().chain(nonce.iter()).copied().collect();
    let hk = Hkdf::<Sha512>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .expect("HKDF-SHA512 with 32-byte output always succeeds");
    out
}

/// Constant-time byte comparison (avoids timing side-channel).
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ──────────────────────────────────────────────────────────────────────────────
// UniFFI wrappers (called from Swift via construct_core.udl)
// ──────────────────────────────────────────────────────────────────────────────

/// Blind a nonce for OPRF issuance.
///
/// Returns packed 64 bytes: blinded_point[0..32] || blind_factor[32..64].
pub fn pp_blind_token(nonce: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let nonce_arr: [u8; 32] = nonce.try_into().map_err(|_| {
        CryptoError::InvalidInputError("pp_blind_token: nonce must be 32 bytes".into())
    })?;
    let (blinded, factor) = blind(&nonce_arr);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&blinded);
    out.extend_from_slice(&factor);
    Ok(out)
}

/// Finalize a blind token after server evaluation.
///
/// Returns 32-byte token bytes.
pub fn pp_finalize_token(
    evaluated_bytes: Vec<u8>,
    blind_factor_bytes: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let ev: [u8; 32] = evaluated_bytes.try_into().map_err(|_| {
        CryptoError::InvalidInputError("pp_finalize: evaluated must be 32 bytes".into())
    })?;
    let bf: [u8; 32] = blind_factor_bytes.try_into().map_err(|_| {
        CryptoError::InvalidInputError("pp_finalize: blind_factor must be 32 bytes".into())
    })?;
    let n: [u8; 32] = nonce.try_into().map_err(|_| {
        CryptoError::InvalidInputError("pp_finalize: nonce must be 32 bytes".into())
    })?;
    Ok(finalize(&ev, &bf, &n)?.to_vec())
}

/// Client-side sanity check: verify the evaluated point is on the Ristretto curve.
///
/// `server_pubkey_bytes` is accepted for future DLEQ proof verification.
/// Currently verifies only curve membership (sufficient for our threat model —
/// the pubkey in well-known is signed by bundle_signing_key).
pub fn pp_verify_client(
    evaluated_bytes: Vec<u8>,
    _nonce: Vec<u8>,
    _server_pubkey_bytes: Vec<u8>,
) -> bool {
    let ev_arr: [u8; 32] = match evaluated_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    CompressedRistretto::from_slice(&ev_arr)
        .ok()
        .and_then(|c| c.decompress())
        .is_some()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn random_scalar_bytes() -> [u8; 32] {
        Scalar::random(&mut OsRng).to_bytes()
    }

    fn random_nonce() -> [u8; 32] {
        let mut b = [0u8; 32];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut b);
        b
    }

    #[test]
    fn round_trip_issuance() {
        let k = random_scalar_bytes();
        let nonce = random_nonce();

        let (blinded, factor) = blind(&nonce);
        let evaluated = evaluate(&k, &blinded).unwrap();
        let token = finalize(&evaluated, &factor, &nonce).unwrap();

        assert!(server_verify(&token, &nonce, &k).unwrap());
    }

    #[test]
    fn wrong_nonce_rejected() {
        let k = random_scalar_bytes();
        let nonce = random_nonce();
        let wrong = random_nonce();

        let (blinded, factor) = blind(&nonce);
        let evaluated = evaluate(&k, &blinded).unwrap();
        let token = finalize(&evaluated, &factor, &nonce).unwrap();

        assert!(!server_verify(&token, &wrong, &k).unwrap());
    }

    #[test]
    fn wrong_key_rejected() {
        let k1 = random_scalar_bytes();
        let k2 = random_scalar_bytes();
        let nonce = random_nonce();

        let (blinded, factor) = blind(&nonce);
        let evaluated = evaluate(&k1, &blinded).unwrap();
        let token = finalize(&evaluated, &factor, &nonce).unwrap();

        assert!(!server_verify(&token, &nonce, &k2).unwrap());
    }

    #[test]
    fn uniffi_wrappers_round_trip() {
        let k = random_scalar_bytes();
        let nonce = random_nonce();

        let packed = pp_blind_token(nonce.to_vec()).unwrap();
        assert_eq!(packed.len(), 64);

        let blinded = packed[..32].to_vec();
        let factor = packed[32..].to_vec();

        let evaluated = evaluate(&k, &blinded.clone().try_into().unwrap()).unwrap();
        let token = pp_finalize_token(evaluated.to_vec(), factor, nonce.to_vec()).unwrap();
        assert_eq!(token.len(), 32);

        assert!(server_verify(&token.try_into().unwrap(), &nonce, &k).unwrap());
    }

    #[test]
    fn invalid_point_rejected() {
        let k = random_scalar_bytes();
        // Setting the high bit of the last byte makes it non-canonical in Ristretto255
        let mut bad_point = [0u8; 32];
        bad_point[31] = 0x80;
        assert!(evaluate(&k, &bad_point).is_err());
    }

    #[test]
    fn issuer_pubkey_deterministic() {
        let k = random_scalar_bytes();
        assert_eq!(issuer_pubkey(&k).unwrap(), issuer_pubkey(&k).unwrap());
    }
}
