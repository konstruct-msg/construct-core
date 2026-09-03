//! Which of a peer's devices a session teardown actually goes to, and what to do with each.
//!
//! # Why this is here and not in a client
//!
//! A teardown is a plan: "which sessions does this operation touch". That is protocol, and every
//! client that builds it will build it differently — silently, because a teardown that reaches the
//! wrong device produces no error, only a peer that keeps using a session nobody can read.
//!
//! The iOS client built it, and both halves were wrong in mirror image (measured 2026-08-30, one
//! peer, one run): an account id in the recipient field reached **every** device of the account, so
//! a Double Ratchet divergence with one device tore down its siblings' healthy sessions — 10 sends,
//! 21 local archives; and a device id in the same field, which is an account-space field on the
//! wire, reached nobody at all — 12 sends, delivered nowhere.
//!
//! The client keeps the half this crate cannot have: `ServerUserId` does not exist here, so
//! translating an account into a set of devices is the caller's job. What the caller hands over is
//! the **set**; what it gets back is the decision over it.
//!
//! See `construct-docs/decisions/a-peer-is-a-set-of-devices.md`.

/// What to do about one device of the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownAction {
    /// We hold a session with this device. Send the teardown, then archive ours — the peer is
    /// being told to stop using a session we are about to stop being able to read.
    SendAndArchive,
    /// No session of ours to condemn, but the peer is demonstrably still on one: a message arrived
    /// that we could not read. Sending is the whole point here — this is the device that needs to
    /// restart, and it is exactly the case a "only devices we have sessions with" filter would
    /// drop.
    SendOnly,
    /// Nothing to condemn and no evidence anyone is on a dead session. A teardown here is an
    /// envelope that says nothing, and under sealed sender it costs a Privacy Pass token to say it.
    Skip,
}

/// One device and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeardownDecision {
    pub device_id: String,
    pub action: TeardownAction,
}

/// Decide the teardown for each candidate device.
///
/// `candidates` is the peer's device set, translated by the caller from whatever id space it
/// speaks. `active_contacts` is the set of devices we hold sessions with — the caller passes what
/// this crate already knows, so the function stays pure and testable without a live core.
///
/// `peer_on_dead_session` is evidence, not a preference: it means a message arrived on a session we
/// no longer have. Only the caller can know that, because only the caller saw the message fail.
///
/// Duplicates in `candidates` collapse — a device appears at most once in the result, so a caller
/// that concatenated two sources cannot send the same device two teardowns.
///
/// Order is the caller's order, first occurrence wins. Stable on purpose: a plan whose order
/// differs between runs makes a failure reproduce on one launch and not the next.
pub fn plan_teardown(
    candidates: &[String],
    active_contacts: &[String],
    peer_on_dead_session: bool,
) -> Vec<TeardownDecision> {
    let mut seen: Vec<&str> = Vec::with_capacity(candidates.len());
    let mut out = Vec::with_capacity(candidates.len());

    for device_id in candidates {
        if device_id.is_empty() || seen.contains(&device_id.as_str()) {
            continue;
        }
        seen.push(device_id.as_str());

        let has_session = active_contacts.iter().any(|c| c == device_id);
        let action = if has_session {
            TeardownAction::SendAndArchive
        } else if peer_on_dead_session {
            TeardownAction::SendOnly
        } else {
            TeardownAction::Skip
        };
        out.push(TeardownDecision {
            device_id: device_id.clone(),
            action,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn actions(d: &[TeardownDecision]) -> Vec<TeardownAction> {
        d.iter().map(|x| x.action).collect()
    }

    /// The defect this function exists for: a peer with two devices, a session with one of them.
    /// The device we hold a session with is condemned; the other is not swept up in it.
    #[test]
    fn only_the_device_we_have_a_session_with_is_condemned() {
        let plan = plan_teardown(&ids(&["aa", "bb"]), &ids(&["aa"]), false);
        assert_eq!(
            actions(&plan),
            vec![TeardownAction::SendAndArchive, TeardownAction::Skip]
        );
    }

    /// Evidence turns a sessionless device from noise into the one that must be told. A filter on
    /// "we have a session" would drop exactly this device — the one whose message we could not
    /// read, which is why we are here at all.
    #[test]
    fn evidence_makes_a_sessionless_device_worth_telling() {
        let plan = plan_teardown(&ids(&["aa", "bb"]), &ids(&["aa"]), true);
        assert_eq!(
            actions(&plan),
            vec![TeardownAction::SendAndArchive, TeardownAction::SendOnly]
        );
    }

    /// Without evidence and without a session there is nothing to say. Under sealed sender saying
    /// it costs a token, so silence is the correct answer rather than a missed opportunity.
    #[test]
    fn nothing_to_condemn_and_no_evidence_is_silence() {
        let plan = plan_teardown(&ids(&["aa"]), &[], false);
        assert_eq!(actions(&plan), vec![TeardownAction::Skip]);
    }

    /// A caller that concatenated two sources must not send one device two teardowns. Asserted on
    /// the decision list rather than a count, so an implementation that dedups by dropping the
    /// wrong one still fails.
    #[test]
    fn duplicates_collapse_to_the_first_occurrence() {
        let plan = plan_teardown(&ids(&["aa", "bb", "aa"]), &ids(&["aa"]), false);
        assert_eq!(
            plan,
            vec![
                TeardownDecision {
                    device_id: "aa".into(),
                    action: TeardownAction::SendAndArchive
                },
                TeardownDecision {
                    device_id: "bb".into(),
                    action: TeardownAction::Skip
                },
            ]
        );
    }

    /// The caller's order survives. A plan whose order depends on iteration of a set makes a
    /// failure reproduce on one launch and not the next.
    #[test]
    fn caller_order_is_preserved() {
        let plan = plan_teardown(&ids(&["cc", "aa", "bb"]), &ids(&["aa", "bb", "cc"]), false);
        assert_eq!(
            plan.iter()
                .map(|d| d.device_id.as_str())
                .collect::<Vec<_>>(),
            vec!["cc", "aa", "bb"]
        );
    }

    /// An empty id names nobody and must not become a target — the empty string is what an
    /// unresolved translation produces on the client side, and it addressed the whole account
    /// before this function existed.
    #[test]
    fn empty_ids_are_not_targets() {
        let plan = plan_teardown(&ids(&["", "aa"]), &ids(&["aa"]), true);
        assert_eq!(
            plan.iter()
                .map(|d| d.device_id.as_str())
                .collect::<Vec<_>>(),
            vec!["aa"]
        );
    }

    /// No candidates, no plan — including when there is evidence. Evidence says someone is on a
    /// dead session; it does not name them, and this function never invents a target.
    #[test]
    fn no_candidates_is_an_empty_plan_even_with_evidence() {
        assert!(plan_teardown(&[], &ids(&["aa"]), true).is_empty());
    }
}
