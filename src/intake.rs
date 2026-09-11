//! Intake credentials — what an envelope carries instead of a Privacy Pass token.
//!
//! Measured 2026-09-11 on two devices in one ordinary conversation: delivery receipts were 36–38%
//! of all token spend, and the batcher was not at fault — in a live conversation there is nothing
//! to batch. The cost is the model. A token per sealed envelope charges the same price for a
//! stranger's first contact and for the four-hundredth message between two people who have been
//! talking for a year, and the receipt is spent by the person who was *written to*.
//!
//! The server cannot be told which envelopes to exempt: `content_type` lives inside the seal on
//! purpose (`construct-docs/decisions/sealed-content-type-inside-the-plaintext-frame.md`), so
//! waiving a token for a receipt would put message kind back on the outer envelope. The question
//! is therefore not *which envelopes are exempt* but *what an envelope carries instead*, and the
//! answer is a credential the recipient issued:
//! `construct-docs/decisions/contact-traffic-is-vouched-not-purchased.md`.
//!
//! ```text
//! intake_key : 32 random bytes, one per account, shared with every vouched contact
//! epoch      : floor(unix_seconds / 86400)
//! intake_tag : HMAC-SHA256(intake_key, "knst-intake-v1" ‖ 0x00 ‖ account ‖ 0x00 ‖ epoch)[0..16]
//! ```
//!
//! **Per recipient, never per pair.** The tag is identical for every sender who holds the key,
//! which is the whole property: the server checks membership and learns nothing that separates one
//! contact from another. A pair-wise value — the shape `reach_proof` takes — would be a stable
//! pseudonymous handle for the sender inside each epoch, which is precisely the linkability sealed
//! sender exists to destroy.
//!
//! The recipient computes the tag for its *own* account id to publish it; a sender computes the
//! tag for the *recipient's* account id to attach it. Same function, same inputs, and that
//! symmetry is why there is only one implementation and it is here.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Length of `intake_key`, in bytes.
pub const INTAKE_KEY_LEN: usize = 32;

/// Length of `intake_tag`, in bytes. Truncated from HMAC-SHA256's 32.
///
/// 16 bytes is a forgery probability of 2^-128 per guess against a server that answers only
/// accept/reject, and the field rides in every sealed envelope, where 16 bytes of padding budget
/// is not free. The same truncation and the same reasoning as `derive_device_id`.
pub const INTAKE_TAG_LEN: usize = 16;

/// Seconds per intake epoch: one UTC day.
///
/// The epoch is what makes a leaked *tag* self-healing — every contact recomputes tomorrow's from
/// the key it already holds, so rotation costs no distribution. A leaked *key* is a different
/// event and is answered by generating a new one and re-sharing it.
pub const INTAKE_EPOCH_SECONDS: u64 = 86_400;

/// Domain-separation label. Bump the version suffix if the derivation ever changes shape: two
/// clients on different labels produce different tags, and the symptom is a silently charged
/// token rather than an error.
const INTAKE_LABEL: &[u8] = b"knst-intake-v1";

/// Field separator inside the HMAC message.
///
/// **Today it prevents nothing**, and saying otherwise would be the more comfortable lie. The
/// label is a fixed-length prefix and the epoch a fixed-width suffix, so the only variable field
/// is the account in the middle and no two (account, epoch) pairs can concatenate to the same
/// bytes. A first draft of this file claimed the separator stopped a sliding collision and shipped
/// a test for it; the test passed against a build with the separators removed, because the
/// collision it described cannot occur either way.
///
/// It is here so that the next field added to this message cannot introduce one — the moment
/// anything variable-width joins the account, ambiguity becomes possible and the separator is
/// already in place instead of being remembered. `construct-server`'s `unit_key` separates
/// `spend_id` from `recipient_user_id` with `b"|"` for the same reason. `0x00` because an account
/// id is text and cannot contain it.
///
/// The byte layout, separators included, is pinned by `known_answer_vector` and by nothing else.
const FIELD_SEP: u8 = 0x00;

/// Errors from intake derivation.
#[derive(Debug, PartialEq, Eq)]
pub enum IntakeError {
    /// `intake_key` was not [`INTAKE_KEY_LEN`] bytes.
    InvalidKeyLength { got: usize },
    /// The account id was empty, or became empty once normalised.
    EmptyAccountId,
}

/// A fresh `intake_key`.
///
/// One per account, not per device: every device of the account derives the same tags, and a
/// device linked later receives this key over the account's own sync channel rather than
/// generating its own — two keys for one account would mean half the contacts hold a credential
/// the server does not recognise.
pub fn generate_intake_key() -> Vec<u8> {
    let mut key = vec![0u8; INTAKE_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// The epoch containing `unix_seconds`.
pub fn intake_epoch(unix_seconds: u64) -> u64 {
    unix_seconds / INTAKE_EPOCH_SECONDS
}

/// The intake tag for one account and one epoch.
///
/// `recipient_account_id` is a `ServerUserId` — the one identity this crate otherwise refuses to
/// speak. It is taken here as an opaque binding input, never stored, never routed on, and never
/// interpreted: the crate does not learn the account space, it hashes a string the caller names.
///
/// What *is* decided here, and the reason this cannot be left to callers, is **normalisation**.
/// Two clients that disagree about case or surrounding whitespace produce different tags, the
/// envelope is charged a token, and nothing anywhere reports a mismatch. This project has already
/// paid that exact bill once: account recovery hashed the raw identifier while registration stored
/// `hash(trim().lowercase())`, so a username typed with a capital letter was simply NOT_FOUND. The
/// normalisation belongs next to the derivation or it will drift away from it.
pub fn intake_tag(
    intake_key: &[u8],
    recipient_account_id: &str,
    epoch: u64,
) -> Result<Vec<u8>, IntakeError> {
    if intake_key.len() != INTAKE_KEY_LEN {
        return Err(IntakeError::InvalidKeyLength {
            got: intake_key.len(),
        });
    }
    let account = recipient_account_id.trim().to_ascii_lowercase();
    if account.is_empty() {
        return Err(IntakeError::EmptyAccountId);
    }

    // `new_from_slice` rejects nothing for HMAC — any length is a valid key — so the length check
    // above is the only thing standing between a truncated key and a tag that looks fine.
    let mut mac = HmacSha256::new_from_slice(intake_key).expect("HMAC accepts any key length");
    mac.update(INTAKE_LABEL);
    mac.update(&[FIELD_SEP]);
    mac.update(account.as_bytes());
    mac.update(&[FIELD_SEP]);
    // Big-endian and fixed width, so the epoch cannot be confused with the bytes before it and the
    // encoding does not depend on the platform.
    mac.update(&epoch.to_be_bytes());

    Ok(mac.finalize().into_bytes()[..INTAKE_TAG_LEN].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; INTAKE_KEY_LEN] = [7u8; INTAKE_KEY_LEN];
    const ACCOUNT: &str = "ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8";

    fn tag(key: &[u8], account: &str, epoch: u64) -> Vec<u8> {
        intake_tag(key, account, epoch).expect("valid inputs")
    }

    // MARK: the property the whole design rests on

    #[test]
    fn every_holder_of_the_key_computes_the_same_tag() {
        // The sender derives for the recipient's account; the recipient derives for its own. If
        // these ever differed the credential would be per-pair, which is the shape the ADR
        // rejects: a stable pseudonymous handle for the sender inside each epoch.
        let sender_side = tag(&KEY, ACCOUNT, 20_342);
        let recipient_side = tag(&KEY, ACCOUNT, 20_342);
        assert_eq!(sender_side, recipient_side);
    }

    #[test]
    fn a_different_key_cannot_produce_the_tag() {
        let mut other = KEY;
        other[0] ^= 1;
        assert_ne!(tag(&KEY, ACCOUNT, 20_342), tag(&other, ACCOUNT, 20_342));
    }

    #[test]
    fn the_tag_changes_every_epoch() {
        // A leaked tag must die on its own, or the epoch buys nothing.
        assert_ne!(tag(&KEY, ACCOUNT, 20_342), tag(&KEY, ACCOUNT, 20_343));
    }

    #[test]
    fn one_key_gives_different_tags_to_different_recipients() {
        // The account id is bound in for the same reason the server binds its spend unit to
        // `recipient_user_id`: without it a credential for one account would be a credential for
        // every account.
        let other = "9a921fe2-2f50-44cf-ba68-ed10422de0bc";
        assert_ne!(tag(&KEY, ACCOUNT, 20_342), tag(&KEY, other, 20_342));
    }

    // MARK: normalisation — the failure that reports nothing

    #[test]
    fn case_and_whitespace_do_not_change_the_tag() {
        // Registration vs recovery, 2026-07-22: one side hashed the raw identifier and the other
        // hashed `trim().lowercase()`, so a capital letter meant NOT_FOUND. Here the same drift
        // would mean a silently charged token.
        let canonical = tag(&KEY, ACCOUNT, 20_342);
        assert_eq!(tag(&KEY, &ACCOUNT.to_uppercase(), 20_342), canonical);
        assert_eq!(tag(&KEY, &format!("  {ACCOUNT}\n"), 20_342), canonical);
        assert_eq!(
            tag(&KEY, &format!("\t{}  ", ACCOUNT.to_uppercase()), 20_342),
            canonical
        );
    }

    // MARK: shape and rejection

    #[test]
    fn a_tag_is_sixteen_bytes() {
        assert_eq!(tag(&KEY, ACCOUNT, 0).len(), INTAKE_TAG_LEN);
    }

    #[test]
    fn a_generated_key_is_thirty_two_bytes_and_not_constant() {
        let a = generate_intake_key();
        let b = generate_intake_key();
        assert_eq!(a.len(), INTAKE_KEY_LEN);
        assert_eq!(b.len(), INTAKE_KEY_LEN);
        assert_ne!(a, b, "two calls returned the same key");
        assert_ne!(a, vec![0u8; INTAKE_KEY_LEN], "key is all zeros");
    }

    #[test]
    fn a_wrong_length_key_is_refused_not_accepted_quietly() {
        // HMAC takes a key of any length, so nothing below this crate would complain about a
        // truncated one — it would simply produce a tag the recipient's devices never match.
        assert_eq!(
            intake_tag(&[0u8; 31], ACCOUNT, 1),
            Err(IntakeError::InvalidKeyLength { got: 31 })
        );
        assert_eq!(
            intake_tag(&[0u8; 33], ACCOUNT, 1),
            Err(IntakeError::InvalidKeyLength { got: 33 })
        );
        assert_eq!(
            intake_tag(&[], ACCOUNT, 1),
            Err(IntakeError::InvalidKeyLength { got: 0 })
        );
    }

    #[test]
    fn an_empty_account_id_is_refused() {
        // Whitespace-only is the interesting case: it survives a non-empty check and dies in
        // normalisation, so the check has to come after the trim.
        assert_eq!(intake_tag(&KEY, "", 1), Err(IntakeError::EmptyAccountId));
        assert_eq!(
            intake_tag(&KEY, "   \t\n", 1),
            Err(IntakeError::EmptyAccountId)
        );
    }

    // MARK: epoch arithmetic

    #[test]
    fn an_epoch_is_a_utc_day() {
        assert_eq!(intake_epoch(0), 0);
        assert_eq!(intake_epoch(INTAKE_EPOCH_SECONDS - 1), 0);
        assert_eq!(intake_epoch(INTAKE_EPOCH_SECONDS), 1);
        // 2026-09-11T00:00:00Z
        assert_eq!(intake_epoch(1_789_084_800), 20_707);
        // …and the last second of that day is still the same epoch.
        assert_eq!(
            intake_epoch(1_789_084_800 + INTAKE_EPOCH_SECONDS - 1),
            20_707
        );
    }

    // MARK: the vector the other implementations must match

    #[test]
    fn known_answer_vector() {
        // Android and construct-tui must reproduce this exactly. A tag that differs by one byte is
        // not an error anywhere — the envelope is charged a token and the saving silently does not
        // happen — so this is the only place the wire shape is pinned.
        //
        // "Only" is literal, and it is the whole weight this test carries: the label, both field
        // separators, the normalisation, the big-endian width of the epoch and the truncation to
        // 16 bytes are pinned *here* and by no other test. Verified by mutation 2026-09-11 —
        // deleting the separators leaves every other test in this file green.
        let t = tag(&KEY, ACCOUNT, 20_707);
        assert_eq!(
            hex::encode(&t),
            KNOWN_TAG,
            "the derivation changed; every other implementation must be updated with it"
        );
    }

    /// Pinned 2026-09-11. Changing it is a protocol change.
    ///
    /// Computed independently of this code before it was pinned, so it asserts the documented
    /// derivation and not merely that the implementation reproduces itself:
    ///
    /// ```python
    /// hmac.new(bytes([7]*32),
    ///          b"knst-intake-v1" + b"\x00"
    ///          + b"ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8" + b"\x00"
    ///          + (20707).to_bytes(8, "big"),
    ///          hashlib.sha256).digest()[:16].hex()
    /// ```
    const KNOWN_TAG: &str = "bb7672311345ed228f7b5b584072a13a";
}
