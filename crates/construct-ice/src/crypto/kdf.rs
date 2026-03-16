//! Key derivation for obfs4 session keys.
//!
//! After the ntor handshake derives KEY_SEED, HKDF-SHA256 expands it
//! into 144 bytes of session key material per the obfs4 spec §4.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Error, Result};

/// ntor KDF salt for HKDF extract.
const NTOR_KDF_SALT: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
/// ntor KDF info for HKDF expand.
const NTOR_KDF_INFO: &[u8] = b"ntor-curve25519-sha256-1:key_expand";

/// All session keys derived from the ntor KEY_SEED.
///
/// Layout per obfs4 spec §4 (144 bytes total):
/// ```text
/// Bytes 000:031 — Server→Client NaCl secretbox key (32)
/// Bytes 032:047 — Server→Client nonce prefix (16)
/// Bytes 048:063 — Server→Client SipHash-2-4 key (16)
/// Bytes 064:071 — Server→Client SipHash-2-4 OFB IV (8)
/// Bytes 072:103 — Client→Server NaCl secretbox key (32)
/// Bytes 104:119 — Client→Server nonce prefix (16)
/// Bytes 120:135 — Client→Server SipHash-2-4 key (16)
/// Bytes 136:143 — Client→Server SipHash-2-4 OFB IV (8)
/// ```
pub struct SessionKeys {
    /// Server→Client secretbox key (32 bytes).
    pub s2c_key: [u8; 32],
    /// Server→Client nonce prefix (16 bytes).
    pub s2c_nonce_prefix: [u8; 16],
    /// Server→Client SipHash key (16 bytes).
    pub s2c_siphash_key: [u8; 16],
    /// Server→Client SipHash OFB IV (8 bytes).
    pub s2c_siphash_iv: [u8; 8],

    /// Client→Server secretbox key (32 bytes).
    pub c2s_key: [u8; 32],
    /// Client→Server nonce prefix (16 bytes).
    pub c2s_nonce_prefix: [u8; 16],
    /// Client→Server SipHash key (16 bytes).
    pub c2s_siphash_key: [u8; 16],
    /// Client→Server SipHash OFB IV (8 bytes).
    pub c2s_siphash_iv: [u8; 8],
}

impl SessionKeys {
    /// Derive all session keys from the ntor KEY_SEED.
    ///
    /// Uses HKDF-SHA256 with info = `ntor-curve25519-sha256-1:key_expand`.
    pub fn derive(key_seed: &[u8; 32]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(NTOR_KDF_SALT), key_seed);

        let mut okm = [0u8; 144];
        hk.expand(NTOR_KDF_INFO, &mut okm)
            .map_err(|_| Error::KdfError)?;

        Ok(SessionKeys {
            s2c_key: okm[0..32].try_into().unwrap(),
            s2c_nonce_prefix: okm[32..48].try_into().unwrap(),
            s2c_siphash_key: okm[48..64].try_into().unwrap(),
            s2c_siphash_iv: okm[64..72].try_into().unwrap(),

            c2s_key: okm[72..104].try_into().unwrap(),
            c2s_nonce_prefix: okm[104..120].try_into().unwrap(),
            c2s_siphash_key: okm[120..136].try_into().unwrap(),
            c2s_siphash_iv: okm[136..144].try_into().unwrap(),
        })
    }
}

/// Build the HMAC key for handshake mark/MAC computation.
///
/// Key = `B || NODEID` (52 bytes), where B is the server's static public key
/// and NODEID is the 20-byte server identifier.
pub fn handshake_hmac_key(server_pubkey: &[u8; 32], node_id: &[u8; 20]) -> [u8; 52] {
    let mut key = [0u8; 52];
    key[..32].copy_from_slice(server_pubkey);
    key[32..].copy_from_slice(node_id);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_produces_different_directions() {
        let seed = [0xab_u8; 32];
        let keys = SessionKeys::derive(&seed).unwrap();
        assert_ne!(keys.s2c_key, keys.c2s_key);
        assert_ne!(keys.s2c_nonce_prefix, keys.c2s_nonce_prefix);
    }

    #[test]
    fn derive_is_deterministic() {
        let seed = [0x42_u8; 32];
        let k1 = SessionKeys::derive(&seed).unwrap();
        let k2 = SessionKeys::derive(&seed).unwrap();
        assert_eq!(k1.s2c_key, k2.s2c_key);
        assert_eq!(k1.c2s_key, k2.c2s_key);
    }

    /// Cross-reference with Go HKDF output for the ntor key_seed from go_reference_ntor_vectors.
    #[test]
    fn go_reference_kdf() {
        fn h(s: &str) -> [u8; 32] {
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }

        let key_seed = h("86ff4ea92c7c913fd2fa3df39c4153175ea8060e94df06fd6fa0fff66de6376e");
        let keys = SessionKeys::derive(&key_seed).unwrap();

        // Go: session_keys = ba1486f5a74835b1047cd2bcc36e5b37ef5bf5235f6dc08e274d6e5adaa71bfc
        //   99740014a3c3943a89716ba70b08ae11330dedf7b9b179fac5912e8aef1549a4e
        //   73cb62b5e1ef536c71c50d1ce01dc8c6187786f46cdb4d520b87600354eb05e2e
        //   28d8f6cbc46db496f3534f1d12a42da8a7e75e1684a21c187d25b17d7c046f24a
        //   b5e835a51d2bcb31c4a90b45e0b64
        // (Parsed from the Go HKDF output, 144 bytes)
        assert_eq!(
            hex::encode(keys.s2c_key),
            "ba1486f5a74835b1047cd2bcc36e5b37ef5bf5235f6dc08e274d6e5adaa71bfc",
            "s2c_key mismatch"
        );
        assert_eq!(
            hex::encode(keys.s2c_nonce_prefix),
            "99740014a3c3943a89716ba70b08ae11",
            "s2c_nonce_prefix mismatch"
        );
    }
}
