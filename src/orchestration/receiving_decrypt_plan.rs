//! Which of a peer's device sessions an incoming message is tried against.

//!
//! # Why this is here and not in a client
//!
//! "Which sessions does this operation touch" is a plan, and a plan is protocol. On receive the
//! iOS client answered it with a single lookup — `SessionAddressing.contactId(forPeer:)`, one
//! device per account — and then handed that one session every message the account sent. A peer
//! with two devices has two ratchets; messages from the second were decrypted against the first
//! and failed AEAD on keys that were entirely valid, which is indistinguishable from a broken
//! session and was treated as one, with a teardown of the healthy session that followed.
//!
//! Attempting is safe, and that is not an assumption: `DoubleRatchetSession::decrypt` snapshots
//! every mutable field before it touches any of them and restores the snapshot on each failure
//! path. A wrong guess costs HKDF work and changes nothing. If that ever stops being true, this
//! function's contract goes with it — the same caveat `plan_receiving_init` carries.
//!
//! The client keeps what this crate cannot have: it maps the account to its devices, because
//! `ServerUserId` does not exist here. What it hands over is the device ids it holds sessions
//! with; what it gets back is the order to try them in.
//!
//! See `construct-docs/decisions/a-peer-is-a-set-of-devices.md`.

/// Every device session worth trying, in the order to try them.
///
/// * `session_device_ids` — the peer's devices we hold a session with. Not "the peer's devices":
///   a device we have never talked to has no ratchet to try, and asking for one would be a
///   session init, which is a different operation with a different cost.
/// * `preferred_device_id` — the device that last decrypted for this peer, or empty when there is
///   none. Tried first: a conversation is with one device at a time far more often than not, so
///   this is the difference between one attempt per message and N in the ordinary case. It is a
///   hint and never a filter — a preferred id absent from the set simply does not reorder
///   anything, because the alternative is refusing to try sessions we hold on the strength of a
///   cache.
///
/// Caller order otherwise, which is the client's stable order. A plan that reshuffles makes a
/// failure reproduce on one launch and not the next.
///
/// A device id appears at most once, and empty ids are dropped — an empty id names nobody, and it
/// is what an unresolved translation produces on the client side.
///
/// **Deliberately unbounded**, like `plan_receiving_init` and for the same reason: a cap could
/// only drop a session that might be the right one, and the caller could not tell a cap from an
/// exhausted search. An account has units of devices. If that stops being true the answer is §D —
/// have the message name its sending device — not to search less and hope.
pub fn plan_receiving_decrypt(
    session_device_ids: &[String],
    preferred_device_id: &str,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if !preferred_device_id.is_empty()
        && session_device_ids
            .iter()
            .any(|id| id == preferred_device_id)
    {
        out.push(preferred_device_id.to_string());
    }

    for id in session_device_ids {
        if id.is_empty() || out.iter().any(|s| s == id) {
            continue;
        }
        out.push(id.clone());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The ordinary case: the device we last heard from is tried first, and the rest stay in the
    /// caller's order behind it.
    #[test]
    fn the_last_device_to_decrypt_is_tried_first() {
        assert_eq!(
            plan_receiving_decrypt(&ids(&["a", "b", "c"]), "b"),
            ids(&["b", "a", "c"])
        );
    }

    /// **The defect, stated as a test.** Two devices, no preference yet: both are tried. The
    /// implementation this replaces produced exactly one — whichever `contactId(forPeer:)` named —
    /// so every message from the other device failed AEAD against valid keys.
    #[test]
    fn every_session_we_hold_is_tried() {
        assert_eq!(
            plan_receiving_decrypt(&ids(&["a", "b"]), ""),
            ids(&["a", "b"])
        );
    }

    /// The preference is a hint, not a filter. A stale id — the device was revoked, or the cache
    /// outlived the session — must not remove the sessions we actually hold from the plan.
    #[test]
    fn an_unknown_preference_does_not_narrow_the_plan() {
        assert_eq!(
            plan_receiving_decrypt(&ids(&["a", "b"]), "gone"),
            ids(&["a", "b"])
        );
    }

    /// The preferred device appears once, not twice. Trying the same ratchet again wastes the
    /// work the preference exists to save.
    #[test]
    fn the_preferred_device_is_not_tried_twice() {
        let plan = plan_receiving_decrypt(&ids(&["a", "b"]), "a");
        assert_eq!(plan, ids(&["a", "b"]));
        assert_eq!(plan.iter().filter(|id| *id == "a").count(), 1);
    }

    /// A repeated id in the caller's set collapses to one attempt.
    #[test]
    fn duplicates_in_the_input_collapse() {
        assert_eq!(
            plan_receiving_decrypt(&ids(&["a", "b", "a"]), ""),
            ids(&["a", "b"])
        );
    }

    /// Empty ids name nobody and must not become attempts.
    #[test]
    fn empty_ids_are_dropped() {
        assert_eq!(
            plan_receiving_decrypt(&ids(&["", "a", ""]), ""),
            ids(&["a"])
        );
    }

    /// An empty preference is "no preference", not "prefer nothing" — the distinction matters
    /// because an unresolved lookup on the client produces exactly that empty string, and reading
    /// it as a device id would put a nameless entry at the head of the plan.
    #[test]
    fn an_empty_preference_reorders_nothing() {
        assert_eq!(
            plan_receiving_decrypt(&ids(&["a", "b"]), ""),
            ids(&["a", "b"])
        );
    }

    /// No sessions is an empty plan, not an error. It is the state before the first handshake with
    /// an account, where the right operation is an init and not a decrypt.
    #[test]
    fn no_sessions_is_an_empty_plan() {
        assert!(plan_receiving_decrypt(&[], "a").is_empty());
    }

    /// The single-device case is the overwhelmingly common one and must stay exactly one attempt —
    /// this change must not cost a single-device peer anything.
    #[test]
    fn one_session_is_one_attempt() {
        assert_eq!(plan_receiving_decrypt(&ids(&["a"]), "a"), ids(&["a"]));
        assert_eq!(plan_receiving_decrypt(&ids(&["a"]), ""), ids(&["a"]));
    }
}
