//! When a signed offer may name a front this device knows with another key.
//!
//! A front is learned from coordinates signed by the relay-config key, and pinned to its
//! certificate's key. A signature alone never moves a front to another key: the server could
//! otherwise re-point any of them. A front whose operator changed its key was then lost for good
//! to whoever learned it before (2026-11-23). So the pin is *disputed* when a dial to the front
//! meets another key, and only for a disputed front does a signed offer with a new key count
//! (construct-docs `decisions/a-front-that-does-not-answer-is-left.md`).
//!
//! A disputed front is not deleted: whoever can answer for a front's address with a certificate of
//! their own would otherwise delete every front a device has. It is dialled last, and not counted
//! as a usable one, so its coordinates are asked for again. A platform keeps the dispute for the
//! life of the process and no longer: whether a network forges certificates is the network's doing
//! (`no-client-side-network-learning.md`), and the next dial finds out again.
//!
//! The signature itself is the platform's to check; here it is one of the facts.

/// The pin this device holds for a front it learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldPin<'a> {
    pub spki: &'a str,
    /// A dial to it met another key, and none since met this one.
    pub disputed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinVerdict {
    /// The pin we have. Nothing to write; a dispute stays until a dial meets this key.
    Same,
    /// A front not known here: pin it.
    Learn,
    /// A known, disputed front under a new key: pin the new one, no longer disputed.
    Repin,
    /// Not a pin at all.
    Malformed,
    /// A public anchor (the signed manifest, the binary) has this address under another key.
    /// No offer moves it.
    DiffersFromAnchor,
    /// Known here under another key, which no dial has disputed.
    DiffersFromHeld,
    /// New coordinates, with no live signature over them.
    Unsigned,
}

/// What an offered pin means. `signed`: the coordinates carry the relay-config key's signature and
/// have not expired. `anchor`: the pin a public anchor has for this address.
pub fn judge_pin(
    anchor: Option<&str>,
    held: Option<HeldPin<'_>>,
    offered: &str,
    signed: bool,
) -> PinVerdict {
    let Some(offered) = normal_pin(offered) else {
        return PinVerdict::Malformed;
    };
    let same = |pin: &str| normal_pin(pin).is_some_and(|p| p == offered);
    if let Some(anchor) = anchor {
        return if same(anchor) {
            PinVerdict::Same
        } else {
            PinVerdict::DiffersFromAnchor
        };
    }
    match held {
        Some(held) if same(held.spki) => PinVerdict::Same,
        Some(held) if !held.disputed => PinVerdict::DiffersFromHeld,
        _ if !signed => PinVerdict::Unsigned,
        Some(_) => PinVerdict::Repin,
        None => PinVerdict::Learn,
    }
}

/// A pin as it is compared: 64 lowercase hex digits (SHA-256 of the SubjectPublicKeyInfo).
fn normal_pin(pin: &str) -> Option<String> {
    let pin = pin.trim().to_ascii_lowercase();
    (pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit())).then_some(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn held(spki: &str, disputed: bool) -> Option<HeldPin<'_>> {
        Some(HeldPin { spki, disputed })
    }

    #[test]
    fn an_unknown_front_is_learned_only_signed() {
        assert_eq!(judge_pin(None, None, &pin('a'), true), PinVerdict::Learn);
        assert_eq!(
            judge_pin(None, None, &pin('a'), false),
            PinVerdict::Unsigned
        );
    }

    #[test]
    fn a_known_front_keeps_its_key_whatever_signs_another() {
        let a = pin('a');
        assert_eq!(
            judge_pin(None, held(&a, false), &pin('b'), true),
            PinVerdict::DiffersFromHeld
        );
        for signed in [true, false] {
            assert_eq!(
                judge_pin(None, held(&a, false), &a, signed),
                PinVerdict::Same
            );
        }
    }

    #[test]
    fn a_disputed_front_takes_a_new_key_only_signed() {
        let a = pin('a');
        assert_eq!(
            judge_pin(None, held(&a, true), &pin('b'), true),
            PinVerdict::Repin
        );
        assert_eq!(
            judge_pin(None, held(&a, true), &pin('b'), false),
            PinVerdict::Unsigned
        );
        assert_eq!(judge_pin(None, held(&a, true), &a, true), PinVerdict::Same);
    }

    #[test]
    fn a_public_anchor_is_moved_by_nothing() {
        let a = pin('a');
        assert_eq!(
            judge_pin(Some(&a), held(&a, true), &pin('b'), true),
            PinVerdict::DiffersFromAnchor
        );
        assert_eq!(
            judge_pin(Some(&a), held(&pin('c'), false), &a, false),
            PinVerdict::Same
        );
    }

    #[test]
    fn what_is_not_a_pin_is_refused_and_case_is_not_a_difference() {
        let a = pin('a');
        for bad in ["", "ab", &pin('g'), &pin('а')] {
            assert_eq!(
                judge_pin(None, held(&a, true), bad, true),
                PinVerdict::Malformed
            );
        }
        assert_eq!(
            judge_pin(None, held(&a, false), &format!(" {} ", pin('A')), true),
            PinVerdict::Same
        );
    }

    /// A stored pin that is not one is not "the same" as anything.
    #[test]
    fn a_malformed_anchor_matches_nothing() {
        assert_eq!(
            judge_pin(Some(""), None, &pin('a'), true),
            PinVerdict::DiffersFromAnchor
        );
    }
}
