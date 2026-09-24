//! What a log line may say about a secret: that two of them are equal, and nothing else.
//!
//! The handshake and ratchet logs exist to answer one question — did both sides derive the same
//! value? — and until 2026-09-24 they answered it by printing the value's first bytes: 8 of the
//! root key, 4 of each DH output, 4 of the *private* identity and signed prekeys, at `info`. Those
//! lines land in os_log / Logcat and in whatever collects them, and a prefix of a key is part of
//! the key.
//!
//! A fingerprint answers the same question. Equal secrets give equal fingerprints on both
//! devices; the fingerprint is a truncated domain-separated SHA-256, so it reveals nothing that
//! helps recover a 256-bit input. `label` keeps fingerprints of different values from being
//! comparable with each other (the DH1 of one handshake never "matches" the root key of another).
//!
//! Private keys are not fingerprinted at all: which key was used is identified by its *public*
//! half, which is what the peer can compare against.

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"construct-log-fingerprint-v1";

/// 8 hex chars identifying `secret` under `label`. Safe to log; see the module doc.
pub fn secret_fingerprint(label: &str, secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update((label.len() as u32).to_be_bytes());
    h.update(label.as_bytes());
    h.update(secret);
    hex::encode(&h.finalize()[..4])
}

/// First 4 bytes of a *public* value, hex. Public keys identify themselves; no hashing needed.
pub fn public_prefix(public: &[u8]) -> String {
    hex::encode(&public[..4.min(public.len())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_secrets_match_and_the_bytes_do_not_appear() {
        let secret = [0xAB_u8; 32];
        let fp = secret_fingerprint("root_key", &secret);
        assert_eq!(fp, secret_fingerprint("root_key", &secret));
        assert_eq!(fp.len(), 8);
        assert_ne!(
            fp,
            hex::encode(&secret[..4]),
            "the fingerprint must not be a prefix of the secret"
        );
    }

    #[test]
    fn the_label_separates_values() {
        let secret = [7_u8; 32];
        assert_ne!(
            secret_fingerprint("dh1", &secret),
            secret_fingerprint("dh2", &secret)
        );
    }
}
