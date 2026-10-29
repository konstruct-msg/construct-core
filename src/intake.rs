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
    /// `intake_mint` was asked for the generation after `u32::MAX`.
    GenerationExhausted,
}

/// The account's intake key and its generation
/// (`construct-docs/decisions/intake-key-is-the-accounts-not-the-devices.md`).
///
/// The generation is the key's address (rule 3 of the project): a card, a sync between our own
/// devices and a publish each name it, so every holder tells the current key from a stale one by
/// comparing two numbers, with no clock and no tie-break. Generation 0 is a key from before the
/// account had one — each device minted its own — and is older than every generation minted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakeKeyState {
    pub generation: u32,
    pub key: Vec<u8>,
}

/// What to do with an offered key: one from a contact's card (their account's key) or one from a
/// card our own device sent (our account's key). One rule for both, because both are the same
/// statement — "the key this account accepts, at generation g".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeOffer {
    /// Hold the offered key from now on.
    Adopt,
    /// Keep what is held.
    Keep,
}

/// A new key one generation above `above_generation`.
///
/// Called in exactly three cases, each named by state: the account's first device
/// (`above_generation` 0), a rotation (the held generation), and an account with no live key
/// anywhere (the generation the server reports). Never because a key is late to arrive.
pub fn intake_mint(above_generation: u32) -> Result<IntakeKeyState, IntakeError> {
    let generation = above_generation
        .checked_add(1)
        .ok_or(IntakeError::GenerationExhausted)?;
    Ok(IntakeKeyState {
        generation,
        key: generate_intake_key(),
    })
}

/// Whether to replace `held` with `offered`.
///
/// Only a higher generation replaces. An equal generation with a different key is kept as held:
/// that is two of our devices rotating at once, both keys are published and valid, and the next
/// rotation brings everyone back to one — choosing a winner would be a tie-break, and there is
/// nothing to win, because either key works. A held key of the wrong length is no key at all.
///
/// An offered key of the wrong length is refused rather than kept: a card that carries one is
/// malformed, and saying so is the only way the sender's bug is ever seen.
pub fn intake_offer(
    held: Option<&IntakeKeyState>,
    offered: &IntakeKeyState,
) -> Result<IntakeOffer, IntakeError> {
    if offered.key.len() != INTAKE_KEY_LEN {
        return Err(IntakeError::InvalidKeyLength {
            got: offered.key.len(),
        });
    }
    match held {
        Some(held) if held.key.len() == INTAKE_KEY_LEN && held.generation >= offered.generation => {
            Ok(IntakeOffer::Keep)
        }
        _ => Ok(IntakeOffer::Adopt),
    }
}

/// A fresh `intake_key`. A platform mints through [`intake_mint`], which names the generation.
///
/// One per account, not per device: every device of the account derives the same tags, and a
/// device linked later receives this key over the account's own sync channel rather than
/// generating its own — two keys for one account would mean half the contacts hold a credential
/// the server does not recognise. Until 2026-10-29 the platforms did generate one per device, and
/// that is how ~30% of tags in production came to be unrecognised.
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

    // MARK: the generation — which key is current

    fn state(generation: u32, byte: u8) -> IntakeKeyState {
        IntakeKeyState {
            generation,
            key: vec![byte; INTAKE_KEY_LEN],
        }
    }

    #[test]
    fn nothing_held_adopts() {
        assert_eq!(intake_offer(None, &state(1, 1)), Ok(IntakeOffer::Adopt));
        // A card from before generations (0) still beats having no key at all.
        assert_eq!(intake_offer(None, &state(0, 1)), Ok(IntakeOffer::Adopt));
    }

    #[test]
    fn a_higher_generation_adopts() {
        assert_eq!(
            intake_offer(Some(&state(1, 1)), &state(2, 2)),
            Ok(IntakeOffer::Adopt)
        );
        // The migration: a per-device key (0) gives way to the account's first generation.
        assert_eq!(
            intake_offer(Some(&state(0, 1)), &state(1, 2)),
            Ok(IntakeOffer::Adopt)
        );
    }

    #[test]
    fn a_lower_generation_is_kept_out() {
        // An old card arriving late, or an old build still sending its per-device key.
        assert_eq!(
            intake_offer(Some(&state(2, 2)), &state(1, 1)),
            Ok(IntakeOffer::Keep)
        );
        assert_eq!(
            intake_offer(Some(&state(1, 2)), &state(0, 1)),
            Ok(IntakeOffer::Keep)
        );
    }

    /// Two of our devices rotated at once: both keys are valid, nobody picks a winner.
    /// Mutation: `>=` → `>` — the different-key case adopts and this reddens.
    #[test]
    fn an_equal_generation_keeps_what_is_held() {
        assert_eq!(
            intake_offer(Some(&state(3, 1)), &state(3, 1)),
            Ok(IntakeOffer::Keep)
        );
        assert_eq!(
            intake_offer(Some(&state(3, 1)), &state(3, 2)),
            Ok(IntakeOffer::Keep)
        );
    }

    #[test]
    fn a_damaged_held_key_is_no_key() {
        let damaged = IntakeKeyState {
            generation: 9,
            key: vec![1; 16],
        };
        assert_eq!(
            intake_offer(Some(&damaged), &state(1, 2)),
            Ok(IntakeOffer::Adopt)
        );
    }

    #[test]
    fn a_wrong_length_offer_is_refused() {
        let short = IntakeKeyState {
            generation: 5,
            key: vec![1; 31],
        };
        assert_eq!(
            intake_offer(None, &short),
            Err(IntakeError::InvalidKeyLength { got: 31 })
        );
    }

    #[test]
    fn mint_is_one_generation_above_with_a_fresh_key() {
        let first = intake_mint(0).expect("room above 0");
        assert_eq!(first.generation, 1);
        assert_eq!(first.key.len(), INTAKE_KEY_LEN);
        let next = intake_mint(first.generation).expect("room above 1");
        assert_eq!(next.generation, 2);
        assert_ne!(next.key, first.key);
        // What it minted replaces what it was minted above.
        assert_eq!(intake_offer(Some(&first), &next), Ok(IntakeOffer::Adopt));
    }

    #[test]
    fn mint_refuses_to_wrap() {
        assert_eq!(intake_mint(u32::MAX), Err(IntakeError::GenerationExhausted));
    }
}
