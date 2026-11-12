//! Decisions about the account's intake key (construct-docs
//! `decisions/intake-key-is-the-accounts-not-the-devices.md`): when to publish its tags, whether
//! the server holds them, what to do with our own key, how a rotation mints, who gets the new card
//! and when, and what a send's verdict does. Minting, tags and "which of two keys to keep" are the
//! core's cryptography (`construct_core::intake`); what is here has no secret in it.
//!
//! Moved here from three copies — iOS `IntakeCredentialService.swift` (`IntakePublishing`,
//! `IntakeOwnKey`, `IntakeRotation`, `IntakeVerdictReaction`, `IntakeKeyRecord`), Android
//! `IntakeCredentials.kt`, construct-client `intake.rs`. Where they differed the stricter one is
//! kept (owner, 2026-11-12): a publish marker names the account and the key as well as the epoch
//! (Android), and a stale publish is re-minted once and only above what was minted.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Epochs a publish covers from today: a device silent for a week must not break its own incoming
/// traffic, since the tags its contacts present are the ones it published. The server caps one
/// call at 14.
pub const WINDOW_EPOCHS: u64 = 7;

/// How often a running process asks [`should_publish`] again. The RPC runs only when it says so.
pub const RECHECK_MS: u64 = 3_600_000;

/// The hour in which a rotation's cards to the remaining contacts are spread.
pub const SWEEP_SPREAD_MS: u64 = 3_600_000;

/// The epochs a publish covers, from `current` (included: a fresh install's first incoming message
/// is due today).
pub fn window(current: u64) -> Vec<u64> {
    (0..WINDOW_EPOCHS).map(|i| current + i).collect()
}

/// What a publish covered: the account, the epoch and the key. A marker naming only the epoch
/// outlived a re-minted key, and the new key's tags waited for the next epoch (Android, before it
/// was the rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Published {
    pub account_id: String,
    pub epoch: u64,
    pub key_id: String,
}

/// Names a key without storing it twice: the first 8 bytes of its SHA-256, hex.
pub fn key_id(key: &[u8]) -> String {
    Sha256::digest(key)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Once per epoch per account and key: a new key, or another account, publishes at once. A clock
/// that went backwards is no reason to skip — publishing is cheap where being wrong is not.
pub fn should_publish(last: Option<&Published>, due: &Published) -> bool {
    last.is_none_or(|last| {
        last.epoch != due.epoch
            || last.key_id != due.key_id
            || !last.account_id.eq_ignore_ascii_case(&due.account_id)
    })
}

/// The last publish the server took was this key's, for this account, and its window still
/// covers `current`. A card names only a key the server holds: one it does not gets NOT_ACCEPTED.
/// A marker from the future (a clock set back) is not trusted.
pub fn server_holds(
    last: Option<&Published>,
    account_id: &str,
    key_id: &str,
    current: u64,
) -> bool {
    last.is_some_and(|last| {
        last.key_id == key_id
            && last.account_id.eq_ignore_ascii_case(account_id)
            && current >= last.epoch
            && current - last.epoch < WINDOW_EPOCHS
    })
}

/// The server refused a publish as stale: the account is at `current`, above `ours`.
pub fn refused_as_stale(current: u32, ours: u32) -> bool {
    current > ours
}

/// What to do about our own key, from what this device holds and what the server says of the
/// account (`GetIntakeState`). Named by state, never by a key being late.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnKey {
    /// The held key, as it is.
    Use,
    /// Our per-device key from before generations becomes the account's generation 1: the contacts
    /// that hold it stay valid. Only while the account has no generation yet.
    Promote,
    /// No live key anywhere on the account: a new one above `above`.
    Mint { above: u32 },
    /// The account has a live key this device does not hold: it is due from one of our devices.
    /// Nothing is published meanwhile.
    Wait,
}

/// `held_generation`: the generation of the key this device holds, `None` when it holds none.
pub fn own_key(
    held_generation: Option<u32>,
    server_generation: u32,
    server_has_live_tags: bool,
) -> OwnKey {
    if held_generation.is_some_and(|g| g > 0) {
        return OwnKey::Use;
    }
    let account_is_live = server_generation > 0 && server_has_live_tags;
    match held_generation {
        Some(_) if server_generation == 0 => OwnKey::Promote,
        _ if account_is_live => OwnKey::Wait,
        _ => OwnKey::Mint {
            above: server_generation,
        },
    }
}

/// A rotation mints above both what we hold and what the server has, so a sibling's rotation not
/// heard of yet is not undercut. A server that could not be asked counts as 0: the rotation still
/// happens, because the old key must not stay ours.
pub fn mint_above(held: Option<u32>, server: Option<u32>) -> u32 {
    held.unwrap_or(0).max(server.unwrap_or(0))
}

/// The publish of `minted` was refused as stale, the account being at `current`: mint once more,
/// above it. Once — that generation is an address, not a retry budget — and only when it is above
/// what was minted.
pub fn re_mint_above(minted: u32, current: u32, already_re_minted: bool) -> Option<u32> {
    (!already_re_minted && current > minted).then_some(current)
}

/// When each remaining contact is handed the new key after a rotation: one envelope each, at its
/// own moment within [`SWEEP_SPREAD_MS`] — a batch right after a block would tell the server the
/// moment and the size of the contact list. The dropped contact, the blocked and our own account
/// get none; a contact listed twice (in any case) once. Each delay is drawn from `seed` (random
/// bytes the platform supplies) and the contact, so a schedule can be checked.
pub fn card_schedule(
    contacts: &[String],
    dropped: &str,
    blocked: &[String],
    own_account: &str,
    seed: &[u8],
) -> Vec<(String, u64)> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for contact in contacts {
        let lower = contact.to_lowercase();
        if lower == dropped.to_lowercase()
            || lower == own_account.to_lowercase()
            || blocked.iter().any(|b| b.eq_ignore_ascii_case(contact))
            || seen.contains(&lower)
        {
            continue;
        }
        let digest = Sha256::new()
            .chain_update(seed)
            .chain_update(lower.as_bytes())
            .finalize();
        let draw = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"));
        out.push((contact.clone(), draw % SWEEP_SPREAD_MS));
        seen.push(lower);
    }
    out
}

/// What a send's verdict on the tag it presented does: only NOT_ACCEPTED (3) suspends the key, until
/// the epoch rolls. UNCHECKED (4) is the server failing to look; acting on it would throw away
/// working keys during an outage.
pub fn verdict_suspends_key(verdict: i32) -> bool {
    verdict == 3
}

/// A key as a client keeps it: the generation big-endian, then the 32-byte key. A bare 32-byte
/// key is one written before 2026-10-29, with no generation: it reads as generation 0, so nothing
/// migrates. Anything else is damaged.
pub fn encode_key_record(generation: u32, key: &[u8]) -> Vec<u8> {
    let mut out = generation.to_be_bytes().to_vec();
    out.extend_from_slice(key);
    out
}

pub fn decode_key_record(bytes: &[u8]) -> Option<(u32, Vec<u8>)> {
    match bytes.len() {
        32 => Some((0, bytes.to_vec())),
        36 => Some((
            u32::from_be_bytes(bytes[..4].try_into().ok()?),
            bytes[4..].to_vec(),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(account: &str, epoch: u64, key: &str) -> Published {
        Published {
            account_id: account.into(),
            epoch,
            key_id: key.into(),
        }
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Mutation: leave out today.
    #[test]
    fn the_window_is_seven_epochs_from_today() {
        assert_eq!(window(100), (100..107).collect::<Vec<_>>());
    }

    /// Mutation: compare only the epoch (iOS and construct-client before this rule).
    #[test]
    fn a_new_key_or_account_publishes_in_the_same_epoch() {
        let last = marker("Me", 10, "k1");
        assert!(!should_publish(Some(&last), &marker("me", 10, "k1")));
        assert!(should_publish(Some(&last), &marker("me", 10, "k2")));
        assert!(should_publish(Some(&last), &marker("other", 10, "k1")));
        assert!(
            should_publish(Some(&last), &marker("me", 9, "k1")),
            "a clock set back"
        );
        assert!(should_publish(None, &marker("me", 10, "k1")));
    }

    /// Mutation: ignore the key id, or accept a marker from the future.
    #[test]
    fn the_server_holds_only_this_keys_window() {
        let last = marker("me", 10, "k1");
        assert!(server_holds(Some(&last), "ME", "k1", 10));
        assert!(server_holds(Some(&last), "me", "k1", 16));
        assert!(!server_holds(Some(&last), "me", "k1", 17), "a week on");
        assert!(!server_holds(Some(&last), "me", "k2", 10), "another key");
        assert!(!server_holds(Some(&last), "other", "k1", 10));
        assert!(!server_holds(Some(&last), "me", "k1", 9), "from the future");
        assert!(!server_holds(None, "me", "k1", 10));
    }

    #[test]
    fn a_key_is_named_by_its_hash() {
        assert_eq!(key_id(&[0u8; 32]).len(), 16);
        assert_ne!(key_id(&[0u8; 32]), key_id(&[1u8; 32]));
    }

    /// Each case of `IntakeOwnKey.next` / `OwnKey.next` / `intake::next`.
    /// Mutation: wait when the account is not live, or promote when the server has a generation.
    #[test]
    fn what_to_do_with_our_key() {
        assert_eq!(own_key(Some(3), 5, true), OwnKey::Use);
        assert_eq!(own_key(Some(0), 0, false), OwnKey::Promote);
        assert_eq!(own_key(Some(0), 2, true), OwnKey::Wait);
        assert_eq!(own_key(Some(0), 2, false), OwnKey::Mint { above: 2 });
        assert_eq!(own_key(None, 2, true), OwnKey::Wait);
        assert_eq!(own_key(None, 0, true), OwnKey::Mint { above: 0 });
        assert_eq!(own_key(None, 4, false), OwnKey::Mint { above: 4 });
    }

    #[test]
    fn a_rotation_mints_above_everything_known() {
        assert_eq!(mint_above(Some(3), Some(5)), 5);
        assert_eq!(mint_above(Some(7), None), 7);
        assert_eq!(mint_above(None, None), 0);
        assert!(refused_as_stale(4, 3));
        assert!(!refused_as_stale(3, 3));
    }

    /// Mutation: drop either condition.
    #[test]
    fn a_stale_publish_re_mints_once_and_only_upward() {
        assert_eq!(re_mint_above(3, 5, false), Some(5));
        assert_eq!(re_mint_above(3, 5, true), None, "once");
        assert_eq!(
            re_mint_above(5, 5, false),
            None,
            "not above what was minted"
        );
    }

    /// Mutation: keep the dropped, the blocked, ourselves or a repeat.
    #[test]
    fn the_cards_go_to_everyone_else_once() {
        let schedule = card_schedule(
            &ids(&["ann", "Bob", "carl", "ANN", "me", "dan"]),
            "bob",
            &ids(&["Carl"]),
            "ME",
            b"seed",
        );
        let who: Vec<&str> = schedule.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(who, vec!["ann", "dan"]);
        assert!(schedule.iter().all(|(_, d)| *d < SWEEP_SPREAD_MS));
    }

    /// The delays are drawn from the seed and differ between contacts. Mutation: one delay for all.
    #[test]
    fn each_card_has_its_own_moment() {
        let contacts = ids(&["a", "b", "c", "d"]);
        let one = card_schedule(&contacts, "x", &[], "me", b"seed-1");
        let again = card_schedule(&contacts, "x", &[], "me", b"seed-1");
        let other = card_schedule(&contacts, "x", &[], "me", b"seed-2");
        assert_eq!(one, again);
        assert_ne!(one, other);
        let mut delays: Vec<u64> = one.iter().map(|(_, d)| *d).collect();
        delays.dedup();
        assert_eq!(delays.len(), 4);
    }

    /// Mutation: suspend on UNCHECKED too.
    #[test]
    fn only_not_accepted_suspends_the_key() {
        assert!(verdict_suspends_key(3));
        for v in [0, 1, 2, 4] {
            assert!(!verdict_suspends_key(v));
        }
    }

    /// Mutation: read 32 bytes as damaged, or the generation little-endian.
    #[test]
    fn a_key_record_reads_back_and_an_old_one_is_generation_zero() {
        let key = vec![7u8; 32];
        let kept = encode_key_record(0x0102_0304, &key);
        assert_eq!(kept.len(), 36);
        assert_eq!(&kept[..4], &[1, 2, 3, 4]);
        assert_eq!(decode_key_record(&kept), Some((0x0102_0304, key.clone())));
        assert_eq!(decode_key_record(&key), Some((0, key)));
        assert_eq!(decode_key_record(&[0u8; 33]), None);
    }
}
