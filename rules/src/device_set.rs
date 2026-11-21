//! What the answer to a send says about the recipient's devices, and when it is worth asking.
//!
//! The answer to `SendSealedMessage` names the recipient's active devices
//! (`SendMessageResponse.recipient_active_devices`, construct-docs
//! `decisions/the-send-answer-names-the-device-set.md`). A send makes one call per device copy, so
//! one message brings several answers: the last one that names anything is the newest statement,
//! and an empty one means nothing (an older server, a read that failed, a recipient elsewhere).
//!
//! The set is a reason to ask the key server, never an answer: a device joins the plan only from
//! its bundle. **The set is the address, not a timer.** A device the key server names and the
//! client refused, or one with no bundle, stays out of the plan, so the named set and the plan keep
//! differing; asking on every difference would ask on every message and spend the bundle budget a
//! session setup needs (`BUNDLE_RATE_LIMIT_PER_MIN`). The same named set is asked about once, and a
//! changed one again. iOS decided so (`DeviceSetAnswer`, todo 263); Android asked the key server
//! before every send instead (todo 321). One rule now.

use std::collections::BTreeSet;

/// The set the answers to one message's copies name, the last that names any winning; empty when
/// none did. Each answer is the list one copy's response carried, as it came.
pub fn named<'a, I, A>(answers: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = A>,
    A: IntoIterator<Item = &'a String>,
{
    answers
        .into_iter()
        .map(|answer| answer.into_iter().cloned().collect::<BTreeSet<_>>())
        .filter(|set| !set.is_empty())
        .last()
        .unwrap_or_default()
}

/// Whether to ask the key server about `named`: it names something, and not the set already asked
/// about for this recipient (`None`: never asked).
pub fn should_ask(named: &BTreeSet<String>, already_asked: Option<&BTreeSet<String>>) -> bool {
    !named.is_empty() && Some(named) != already_asked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn answer(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    /// Mutations that redden it: take the first answer; let an empty answer win; keep duplicates or order.
    #[test]
    fn the_last_answer_that_names_devices_wins() {
        let answers = [answer(&["a"]), answer(&["b", "a"]), answer(&[])];
        assert_eq!(named(&answers), set(&["a", "b"]));
        assert_eq!(named(&[answer(&["c", "c"])]), set(&["c"]));
        assert!(named(&[answer(&[]), answer(&[])]).is_empty());
        assert!(named(&Vec::<Vec<String>>::new()).is_empty());
    }

    /// Mutations that redden it: ask on an empty set; ask again about the same set; never ask about a changed one.
    #[test]
    fn the_same_set_is_asked_about_once() {
        let ab = set(&["a", "b"]);
        assert!(should_ask(&ab, None));
        assert!(!should_ask(&ab, Some(&set(&["b", "a"]))));
        assert!(should_ask(&ab, Some(&set(&["a"]))));
        assert!(!should_ask(&BTreeSet::new(), None));
        assert!(!should_ask(&BTreeSet::new(), Some(&ab)));
    }
}
