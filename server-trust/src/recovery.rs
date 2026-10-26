//! The bytes an account's recovery key signs — one format for the clients that sign and the server
//! that checks.
//!
//! The recovery key is derived from the account's twelve words. Its Ed25519 half is the key
//! accounts have always had, and the account's address; since 0.59.0 an ML-DSA-65 half rides
//! beside it, and the pair signs as one hybrid key (both halves must verify).
//!
//! ```text
//! setup = "konstruct/v1/recovery-setup" ‖ lp(account_id) ‖ BE64(timestamp) ‖ public_key(1984)
//! claim = "konstruct/v1/recovery-claim" ‖ public_key(1984) ‖ BE64(timestamp)
//!         ‖ lp(device_id) ‖ lp(verifying_key) ‖ lp(identity_public)
//! ```
//!
//! A claim names the device it hands the account to. The claim it replaces signed a bare
//! timestamp the server never checked, so one recovery request, seen once, recovered the account
//! again a week later for whoever replayed it with their own device keys.
//!
//! Decision: `construct-docs/todo/222-recovery-key-hybrid-pq.md`.

use crate::{HYBRID_PUBLIC_KEY_LEN, Malformed, put_lp};

const SETUP_LABEL: &[u8] = b"konstruct/v1/recovery-setup";
const CLAIM_LABEL: &[u8] = b"konstruct/v1/recovery-claim";

/// How far a setup's or a claim's timestamp may stand from the server's clock.
pub const MAX_SKEW_SECS: i64 = 600;

/// Whether `timestamp` is close enough to `now` to be accepted.
pub fn fresh(timestamp: i64, now: i64) -> bool {
    timestamp.abs_diff(now) <= MAX_SKEW_SECS as u64
}

/// What a recovery key signs to be set on `account_id`, or to upgrade the Ed25519 key stored
/// there: the Ed25519 half of the signature proves the stored key, the ML-DSA half the new one.
pub fn setup_signable(
    account_id: &str,
    timestamp: i64,
    public_key: &[u8],
) -> Result<Vec<u8>, Malformed> {
    if public_key.len() != HYBRID_PUBLIC_KEY_LEN {
        return Err(Malformed);
    }
    let mut m = Vec::with_capacity(SETUP_LABEL.len() + 2 + account_id.len() + 8 + public_key.len());
    m.extend_from_slice(SETUP_LABEL);
    put_lp(&mut m, account_id.as_bytes())?;
    m.extend_from_slice(&timestamp.to_be_bytes());
    m.extend_from_slice(public_key);
    Ok(m)
}

/// What a recovery key signs to hand its account to the device these keys name.
pub fn claim_signable(
    public_key: &[u8],
    timestamp: i64,
    device_id: &str,
    verifying_key: &[u8],
    identity_public: &[u8],
) -> Result<Vec<u8>, Malformed> {
    if public_key.len() != HYBRID_PUBLIC_KEY_LEN {
        return Err(Malformed);
    }
    let mut m = Vec::with_capacity(
        CLAIM_LABEL.len()
            + public_key.len()
            + 8
            + 6
            + device_id.len()
            + verifying_key.len()
            + identity_public.len(),
    );
    m.extend_from_slice(CLAIM_LABEL);
    m.extend_from_slice(public_key);
    m.extend_from_slice(&timestamp.to_be_bytes());
    put_lp(&mut m, device_id.as_bytes())?;
    put_lp(&mut m, verifying_key)?;
    put_lp(&mut m, identity_public)?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn key() -> Vec<u8> {
        (0..HYBRID_PUBLIC_KEY_LEN).map(|i| i as u8).collect()
    }

    /// The bytes are pinned: a server and a client built from different revisions must agree, and a
    /// change here is a wire change.
    #[test]
    fn the_signed_bytes_are_pinned() {
        let setup = setup_signable(
            "14f28d31-0000-4000-8000-000000000001",
            1_800_000_000,
            &key(),
        )
        .unwrap();
        let claim = claim_signable(&key(), 1_800_000_000, "6f5e37ac", &[1; 32], &[2; 32]).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&setup)),
            "35fd8426675aa355a5e2bb7cdd7e31894bec550d4aa6e7a6e29a91c6d1f2ca94"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&claim)),
            "2325ef6230d4fccdb0bfad81b2e3124bdaa6a059dd8be4a8c004ebbea5caa8f0"
        );
    }

    #[test]
    fn the_two_messages_cannot_be_taken_for_each_other() {
        let setup = setup_signable("a", 1, &key()).unwrap();
        let claim = claim_signable(&key(), 1, "a", &[], &[]).unwrap();
        assert!(setup.starts_with(SETUP_LABEL) && !setup.starts_with(CLAIM_LABEL));
        assert!(claim.starts_with(CLAIM_LABEL) && !claim.starts_with(SETUP_LABEL));
    }

    /// Without the length prefixes `("ab", "c")` and `("a", "bc")` would sign the same bytes, and a
    /// claim for one device would be a claim for another.
    #[test]
    fn the_device_fields_do_not_run_into_each_other() {
        let a = claim_signable(&key(), 1, "ab", b"c", b"").unwrap();
        let b = claim_signable(&key(), 1, "a", b"bc", b"").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_key_of_another_length_is_refused() {
        assert_eq!(setup_signable("a", 1, &[0; 32]), Err(Malformed));
        assert_eq!(claim_signable(&[0; 32], 1, "a", &[], &[]), Err(Malformed));
    }

    #[test]
    fn freshness_is_ten_minutes_either_way() {
        assert!(fresh(1_000, 1_000 + MAX_SKEW_SECS));
        assert!(fresh(1_000 + MAX_SKEW_SECS, 1_000));
        assert!(!fresh(1_000, 1_001 + MAX_SKEW_SECS));
        assert!(!fresh(1_001 + MAX_SKEW_SECS, 1_000));
        assert!(!fresh(i64::MIN, 0));
    }
}
