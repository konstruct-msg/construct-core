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
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul},
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha512};

use crate::error::CryptoError;

const HKDF_INFO: &[u8] = b"ConstructPP-v1";
const TOKEN_SEAL_INFO: &[u8] = b"construct-token-seal-v1";

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
// Batched DLEQ proof verification (Phase C — verifiable VOPRF)
//
// Ported byte-for-byte from construct-server `construct-crypto::privacy_pass`
// (`verify_dleq_proof` / `compute_composites` / `dleq_hash_to_scalar`). MUST stay
// byte-identical or issuance proofs will not verify — see construct-docs
// `cryptocore/privacy-pass-dleq-v1.md`. Client pins `issuer_public` (K) and verifies the
// proof from `IssueTokensResponse.dleq_proof` against the pin, closing malicious-issuer
// key-tagging (a per-user `k_u` where `K = k·G` but `Z = k_u·B` is rejected).
// ──────────────────────────────────────────────────────────────────────────────

const DLEQ_DOMAIN: &[u8] = b"ConstructPP-DLEQ-v1";

/// Hash to a Ristretto scalar via SHA-512 + `Scalar::from_hash` (sha2 0.10, matching the
/// server's `sha2_dalek_compat` alias). Callers prepend `DLEQ_DOMAIN` + a 1-byte tag.
fn dleq_hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    Scalar::from_hash(h)
}

fn decompress_nonidentity(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    let p = CompressedRistretto::from_slice(bytes).ok()?.decompress()?;
    if p.is_identity() {
        return None;
    }
    Some(p)
}

/// Deterministic random-linear-combination of the `(B_i, Z_i)` batch — identical on prover
/// and verifier. `None` if empty, length-mismatched, or any point fails to decompress / is
/// the identity. `k_pub` (`K`) is bound into the seed so a proof can't be replayed under a
/// different commitment.
fn compute_composites(
    k_pub: &[u8; 32],
    blinded: &[[u8; 32]],
    evaluated: &[[u8; 32]],
) -> Option<(RistrettoPoint, RistrettoPoint)> {
    if blinded.is_empty() || blinded.len() != evaluated.len() {
        return None;
    }

    let mut b_pts = Vec::with_capacity(blinded.len());
    let mut z_pts = Vec::with_capacity(evaluated.len());
    for (b, z) in blinded.iter().zip(evaluated.iter()) {
        b_pts.push(decompress_nonidentity(b)?);
        z_pts.push(decompress_nonidentity(z)?);
    }

    // seed = SHA512(DOMAIN ‖ 0x00 ‖ K ‖ Σ_i (B_i ‖ Z_i))
    let mut sh = Sha512::new();
    sh.update(DLEQ_DOMAIN);
    sh.update([0x00u8]);
    sh.update(k_pub);
    for (b, z) in blinded.iter().zip(evaluated.iter()) {
        sh.update(b);
        sh.update(z);
    }
    let seed = sh.finalize();

    // M = Σ d_i·B_i, Zc = Σ d_i·Z_i, d_i = H(DOMAIN ‖ 0x01 ‖ seed ‖ u32_be(i) ‖ B_i ‖ Z_i)
    let mut m = RistrettoPoint::identity();
    let mut zc = RistrettoPoint::identity();
    for (i, (b, z)) in blinded.iter().zip(evaluated.iter()).enumerate() {
        let idx = (i as u32).to_be_bytes();
        let d = dleq_hash_to_scalar(&[DLEQ_DOMAIN, &[0x01], &seed[..], &idx[..], &b[..], &z[..]]);
        m += d * b_pts[i];
        zc += d * z_pts[i];
    }
    Some((m, zc))
}

/// Verify a batched DLEQ proof against the pinned public commitment `issuer_public` (`K`).
/// Returns `true` iff the same `k` links `K = k·G` and every `evaluated[i] = k·blinded[i]`.
///
/// UniFFI-facing: each point/proof is a `Vec<u8>` (32 / 32 / 64 bytes). Any malformed input
/// (wrong length, non-canonical scalar, bad point) returns `false` — never panics.
pub fn pp_verify_dleq(
    blinded: Vec<Vec<u8>>,
    evaluated: Vec<Vec<u8>>,
    proof: Vec<u8>,
    issuer_public: Vec<u8>,
) -> bool {
    // Convert the batch to fixed-size arrays; bail on any wrong-length input.
    fn to_arrays(v: &[Vec<u8>]) -> Option<Vec<[u8; 32]>> {
        v.iter()
            .map(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .collect()
    }
    let blinded_arr = match to_arrays(&blinded) {
        Some(v) => v,
        None => return false,
    };
    let evaluated_arr = match to_arrays(&evaluated) {
        Some(v) => v,
        None => return false,
    };
    let issuer_public: [u8; 32] = match issuer_public.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let proof: [u8; 64] = match proof.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let c_bytes: [u8; 32] = proof[..32].try_into().expect("32-byte slice");
    let s_bytes: [u8; 32] = proof[32..].try_into().expect("32-byte slice");
    let c = Option::<Scalar>::from(Scalar::from_canonical_bytes(c_bytes));
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes));
    let (c, s) = match (c, s) {
        (Some(c), Some(s)) => (c, s),
        _ => return false, // non-canonical scalar encoding
    };

    let k_point = match CompressedRistretto::from_slice(&issuer_public)
        .ok()
        .and_then(|cp| cp.decompress())
    {
        Some(p) => p,
        None => return false,
    };

    let (m, zc) = match compute_composites(&issuer_public, &blinded_arr, &evaluated_arr) {
        Some(v) => v,
        None => return false,
    };
    let m_c = m.compress().to_bytes();
    let zc_c = zc.compress().to_bytes();

    // A1' = s·G − c·K, A2' = s·M − c·Zc; accept iff H(...A1'‖A2') == c.
    let a1p = s * RISTRETTO_BASEPOINT_POINT - c * k_point;
    let a2p = s * m - c * zc;
    let c_prime = dleq_hash_to_scalar(&[
        DLEQ_DOMAIN,
        &[0x03],
        &issuer_public[..],
        &m_c[..],
        &zc_c[..],
        &a1p.compress().to_bytes()[..],
        &a2p.compress().to_bytes()[..],
    ]);

    c_prime == c
}

/// Seal a finalized token to the server's X25519 token-encryption public key
/// (`token_encryption_key` from `/.well-known/construct-server`) so relay
/// operators cannot read spent tokens in transit.
///
/// Format: `ephemeral_pub(32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`.
/// Key: `HKDF-SHA256(ikm = X25519(eph, server), salt = ∅,
/// info = "construct-token-seal-v1")` — matches iOS `ServerKeyManager.sealBox`
/// and construct-server's `privacy_pass::open_sealed_token_bytes`.
pub fn pp_seal_token_bytes(
    token: Vec<u8>,
    server_encryption_key: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
    use rand_core::RngCore;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    let server_pub_arr: [u8; 32] = server_encryption_key.try_into().map_err(|_| {
        CryptoError::InvalidInputError("pp_seal_token_bytes: server key must be 32 bytes".into())
    })?;
    let server_pub = PublicKey::from(server_pub_arr);

    let mut eph_seed = [0u8; 32];
    OsRng.fill_bytes(&mut eph_seed);
    let ephemeral = StaticSecret::from(eph_seed);
    let ephemeral_pub = PublicKey::from(&ephemeral);

    let shared = ephemeral.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(TOKEN_SEAL_INFO, &mut key)
        .expect("HKDF-SHA256 with 32-byte output always succeeds");

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct_and_tag = cipher
        .encrypt(Nonce::from_slice(&nonce), token.as_slice())
        .map_err(|_| CryptoError::AeadEncryptionError("token seal failed".into()))?;

    let mut out = Vec::with_capacity(32 + 12 + ct_and_tag.len());
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct_and_tag);
    Ok(out)
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

    /// Round trip against a reimplementation of construct-server's
    /// `open_sealed_token_bytes` (same derivation: HKDF-SHA256 no salt,
    /// info "construct-token-seal-v1").
    #[test]
    fn seal_token_bytes_server_open_round_trip() {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
        use hkdf::Hkdf;
        use rand_core::RngCore;
        use sha2::Sha256;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut server_seed = [0u8; 32];
        OsRng.fill_bytes(&mut server_seed);
        let server_secret = StaticSecret::from(server_seed);
        let server_pub = PublicKey::from(&server_secret);

        let token = [0x42u8; 32];
        let sealed = pp_seal_token_bytes(token.to_vec(), server_pub.as_bytes().to_vec()).unwrap();
        assert!(sealed.len() >= 32 + 12 + 16);

        // Server-side open
        let eph_pub_arr: [u8; 32] = sealed[..32].try_into().unwrap();
        let eph_pub = PublicKey::from(eph_pub_arr);
        let shared = server_secret.diffie_hellman(&eph_pub);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(TOKEN_SEAL_INFO, &mut key).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let opened = cipher
            .decrypt(Nonce::from_slice(&sealed[32..44]), &sealed[44..])
            .unwrap();

        assert_eq!(opened, token);
    }

    #[test]
    fn seal_token_bytes_rejects_bad_key_length() {
        assert!(pp_seal_token_bytes(vec![0u8; 32], vec![0u8; 31]).is_err());
    }
}

#[cfg(test)]
mod dleq_tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Cross-impl golden vector: the exact `(k, batch, proof)` pinned in construct-server
    /// `construct-crypto::privacy_pass::dleq_kat_vector`. The client verifier MUST accept the
    /// server-generated proof byte-for-byte, or issuance breaks. This locks the
    /// privacy-pass-dleq-v1.md client-parity contract.
    #[test]
    fn pp_verify_dleq_accepts_server_kat_and_rejects_tampering() {
        let k = Scalar::from_bytes_mod_order([7u8; 32]);
        let mk = |label: &[u8]| -> [u8; 32] {
            let t = hash_to_ristretto(label);
            let r = Scalar::from_bytes_mod_order([3u8; 32]);
            (r * t).compress().to_bytes()
        };
        let blinded_arr = [mk(b"kat-0"), mk(b"kat-1")];
        let evaluated_arr: Vec<[u8; 32]> = blinded_arr
            .iter()
            .map(|b| {
                let p = CompressedRistretto::from_slice(b)
                    .unwrap()
                    .decompress()
                    .unwrap();
                (k * p).compress().to_bytes()
            })
            .collect();
        let k_pub = (RISTRETTO_BASEPOINT_POINT * k).compress().to_bytes();

        // Golden proof from construct-server (privacy-pass-dleq-v1.md).
        const KAT_PROOF_HEX: &str = "a5fc43539f4acf319af0035bc73a19006588f75a5d425fc3039e906597c08d06bfa8b0cd50bb08d6d7bcb90dae2222fd2384e8404de57260fd412f729d29ab08";
        let proof = from_hex(KAT_PROOF_HEX);

        let blinded: Vec<Vec<u8>> = blinded_arr.iter().map(|b| b.to_vec()).collect();
        let evaluated: Vec<Vec<u8>> = evaluated_arr.iter().map(|z| z.to_vec()).collect();

        // (1) Accepts the real server proof under the correct pinned K.
        assert!(
            pp_verify_dleq(
                blinded.clone(),
                evaluated.clone(),
                proof.clone(),
                k_pub.to_vec()
            ),
            "client DLEQ verify must accept the server KAT proof (byte-compat broke)"
        );

        // (2) Rejects a mismatched issuer key — the per-user key-tag threat Phase C closes.
        let wrong_k = (RISTRETTO_BASEPOINT_POINT * Scalar::from_bytes_mod_order([8u8; 32]))
            .compress()
            .to_bytes();
        assert!(
            !pp_verify_dleq(
                blinded.clone(),
                evaluated.clone(),
                proof.clone(),
                wrong_k.to_vec()
            ),
            "verify must reject a mismatched issuer key"
        );

        // (3) Rejects a tampered proof.
        let mut bad = proof.clone();
        bad[0] ^= 0x01;
        assert!(!pp_verify_dleq(
            blinded.clone(),
            evaluated.clone(),
            bad,
            k_pub.to_vec()
        ));

        // (4) Malformed inputs never panic → false.
        assert!(!pp_verify_dleq(
            vec![vec![0u8; 31]],
            evaluated,
            proof,
            k_pub.to_vec()
        ));
    }
}
