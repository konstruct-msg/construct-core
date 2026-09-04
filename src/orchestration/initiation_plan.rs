//! Whether to open a session with a device right now, and as which side.
//!
//! # Why this is here and not in a client
//!
//! "May I initiate?" is the same class of question as "which sessions does this operation touch":
//! two clients must answer it compatibly or the session does not form. `tie_break_role` already
//! settles a collision that has happened. This settles whether to walk into one — and a client
//! that decides it locally decides it differently, silently, because the symptom is not an error.
//! It is a conversation that stops for as long as the recovery takes.
//!
//! # The run this is written from
//!
//! Devices 2026-09-04, one account and one device on each side, after A deleted the chat:
//!
//! ```text
//! 12:28:13  A  deletes the chat → END_SESSION → archives its own session
//! 12:28:19  B  receives END_SESSION → archives → "re-init as natural INITIATOR"
//! 12:29:24  B  relaunches
//! 12:30:11  B  no session after restart → proactive init → INITIATOR session created
//! 12:30:44  A  its user types           → proactive init
//! 12:30:59  A  init succeeds — two INITIATOR sessions now exist, different root keys
//! 12:30:59  B  DR diverged
//! 12:31:15  A  DR diverged
//! 12:31:16  A  RESPONDER fallback opens a receiving session
//! 12:31:32  A  four messages appear at once
//! ```
//!
//! Thirty-two seconds of silence, four messages batched, seven one-time prekeys spent between the
//! two devices. `tie_break_role` could not help: each side was **alone** when it decided, so there
//! was no pair to rank. By the time there was, both had already spent a prekey on a session the
//! other could not read.
//!
//! # The rule
//!
//! A session is opened when there is something to put in it. B's initiation at 12:30:11 carried
//! nothing — it was "no session after a restart", and that is the initiation that should not have
//! happened. Waiting costs nothing there: whatever B eventually wants to send *is* the reason to
//! open, and it opens then.
//!
//! This does not replace the tie-break; it reduces how often the tie-break is needed. Two peers
//! who both have something to send still collide, and that collision is still ranked.
//!
//! See `construct-docs/decisions/a-peer-is-a-set-of-devices.md` for why plans live here at all.

use crate::orchestration::message_router::{Role, tie_break_role};

/// What to do about opening a session with one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiationDecision {
    /// Open a fresh session as INITIATOR now.
    Initiate,
    /// One of ours is already in flight. Join it — do not start a second.
    ///
    /// A second init is not a retry: it derives a new root key, spends another one-time prekey,
    /// and leaves the first one's `SESSION_RESET_INIT` in the air addressing a session that no
    /// longer exists. The peer then answers the one we discarded.
    JoinInFlight,
    /// The peer's init is arriving and outranks ours. Take the responder side.
    YieldToPeer,
    /// Nothing to send and no init in the air. Opening here spends a prekey on a session that
    /// carries nothing, and doubles the chance of colliding with the peer's next one.
    Wait,
}

impl InitiationDecision {
    /// Stable wire spelling, so a client can log and compare it without re-deriving the names.
    pub fn as_wire(&self) -> &'static str {
        match self {
            InitiationDecision::Initiate => "Initiate",
            InitiationDecision::JoinInFlight => "JoinInFlight",
            InitiationDecision::YieldToPeer => "YieldToPeer",
            InitiationDecision::Wait => "Wait",
        }
    }
}

/// What the caller knows at the moment it wants a session.
///
/// Every field is something only the caller can see — the network, the outbox, the UI. The
/// decision over them is made here so that two clients make the same one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiationContext {
    /// Our device id, in the space the session is addressed by. Ranked against `peer_device_id`;
    /// anything else ranks a different pair (see `tie_break_role`).
    pub my_device_id: String,
    /// The device we want a session with.
    pub peer_device_id: String,
    /// We sent a `SESSION_RESET_INIT` to this device and it is neither acknowledged nor expired.
    pub our_init_in_flight: bool,
    /// We have the peer's init in hand — received, not yet completed.
    pub peer_init_in_flight: bool,
    /// Something is waiting to be sent to this device: a typed message, a queued one, a receipt
    /// the user can see the absence of. Not "the app would like a warm session".
    pub have_outbound_work: bool,
}

/// Decide whether to open a session with `peer_device_id` right now.
///
/// The order of the arms is the content. Each one is a case the 2026-09-04 run produced or would
/// have produced:
///
/// 1. **Ours is in flight** — join it. Spending a second prekey here is how a recovery becomes a
///    second divergence.
/// 2. **Theirs is in flight** — rank the pair. The loser takes the responder side instead of
///    building a session the winner will never read. This is `tie_break_role`, applied at the one
///    moment both sides can see the same two ids.
/// 3. **We have something to send** — initiate. A waiting user outranks prekey economy, and the
///    peer, seeing our init, reaches case 2.
/// 4. **Otherwise** — wait. This is B at 12:30:11.
///
/// An empty `peer_device_id` cannot be ranked and cannot be addressed; the answer is `Wait`,
/// which is also what an unknown device deserves.
pub fn plan_initiation(ctx: &InitiationContext) -> InitiationDecision {
    if ctx.peer_device_id.is_empty() || ctx.my_device_id.is_empty() {
        return InitiationDecision::Wait;
    }
    if ctx.our_init_in_flight {
        return InitiationDecision::JoinInFlight;
    }
    if ctx.peer_init_in_flight {
        return match tie_break_role(&ctx.my_device_id, &ctx.peer_device_id) {
            Role::Initiator => InitiationDecision::Initiate,
            Role::Responder => InitiationDecision::YieldToPeer,
        };
    }
    if ctx.have_outbound_work {
        return InitiationDecision::Initiate;
    }
    InitiationDecision::Wait
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two ids that rank deterministically: `high` wins the tie-break against `low`.
    const HIGH: &str = "ff00000000000000000000000000000f";
    const LOW: &str = "0011111111111111111111111111111f";

    fn ctx(my: &str, peer: &str) -> InitiationContext {
        InitiationContext {
            my_device_id: my.to_string(),
            peer_device_id: peer.to_string(),
            our_init_in_flight: false,
            peer_init_in_flight: false,
            have_outbound_work: false,
        }
    }

    // ── The initiation that caused the outage ────────────────────────────────

    /// **B at 12:30:11.** No session after a restart, nothing to send, no init in the air. The
    /// old behaviour opened one anyway and collided with A thirty-three seconds later.
    #[test]
    fn a_restart_with_nothing_to_say_does_not_open_a_session() {
        assert_eq!(plan_initiation(&ctx(LOW, HIGH)), InitiationDecision::Wait);
        assert_eq!(plan_initiation(&ctx(HIGH, LOW)), InitiationDecision::Wait);
    }

    /// **A at 12:30:44.** Its user typed. Waiting here would be the opposite defect — a message
    /// the user believes they sent, sitting behind a session nobody opened.
    #[test]
    fn something_to_send_opens_a_session() {
        let mut c = ctx(LOW, HIGH);
        c.have_outbound_work = true;
        assert_eq!(plan_initiation(&c), InitiationDecision::Initiate);
    }

    // ── Our own init already in flight ───────────────────────────────────────

    /// The plan's first item, stated: a second init spends a second prekey and orphans the first
    /// `SESSION_RESET_INIT`. Outbound work does not override it — the work goes into the session
    /// that is already opening.
    #[test]
    fn a_second_init_is_never_started_while_ours_is_in_flight() {
        let mut c = ctx(HIGH, LOW);
        c.our_init_in_flight = true;
        assert_eq!(plan_initiation(&c), InitiationDecision::JoinInFlight);

        c.have_outbound_work = true;
        assert_eq!(plan_initiation(&c), InitiationDecision::JoinInFlight);

        // Even against an inbound init: ours went first, and the peer will rank the pair too.
        c.peer_init_in_flight = true;
        assert_eq!(plan_initiation(&c), InitiationDecision::JoinInFlight);
    }

    // ── Both at once: the tie-break, applied before the divergence ───────────

    /// The two sides must reach opposite answers over the same pair, or the collision survives.
    #[test]
    fn a_visible_collision_is_ranked_and_one_side_yields() {
        let mut mine = ctx(HIGH, LOW);
        mine.peer_init_in_flight = true;
        let mut theirs = ctx(LOW, HIGH);
        theirs.peer_init_in_flight = true;

        assert_eq!(plan_initiation(&mine), InitiationDecision::Initiate);
        assert_eq!(plan_initiation(&theirs), InitiationDecision::YieldToPeer);
    }

    /// Yielding does not depend on having nothing to send: the loser's messages go into the
    /// session the winner opens. Deciding otherwise would make both sides initiate whenever both
    /// had traffic, which is the case that hurts most.
    #[test]
    fn the_lower_id_yields_even_with_something_to_send() {
        let mut c = ctx(LOW, HIGH);
        c.peer_init_in_flight = true;
        c.have_outbound_work = true;
        assert_eq!(plan_initiation(&c), InitiationDecision::YieldToPeer);
    }

    /// The ranking is `tie_break_role`'s, not a second copy of it. If that function's order ever
    /// changes, this test changes with it rather than silently disagreeing — which is the exact
    /// failure the comment on `tie_break_role` describes.
    #[test]
    fn the_ranking_is_the_one_tie_break_role_makes() {
        for (my, peer) in [(HIGH, LOW), (LOW, HIGH)] {
            let mut c = ctx(my, peer);
            c.peer_init_in_flight = true;
            let expected = match tie_break_role(my, peer) {
                Role::Initiator => InitiationDecision::Initiate,
                Role::Responder => InitiationDecision::YieldToPeer,
            };
            assert_eq!(plan_initiation(&c), expected);
        }
    }

    // ── Degenerate input ─────────────────────────────────────────────────────

    /// A device we cannot name cannot be ranked or addressed. `Wait` rather than `Initiate`: an
    /// unaddressable init is a spent prekey and an envelope delivered nowhere.
    #[test]
    fn an_unnameable_device_is_waited_on_not_initiated_with() {
        let mut c = ctx(HIGH, "");
        c.have_outbound_work = true;
        assert_eq!(plan_initiation(&c), InitiationDecision::Wait);

        let mut c = ctx("", HIGH);
        c.have_outbound_work = true;
        assert_eq!(plan_initiation(&c), InitiationDecision::Wait);
    }

    /// A device ranked against itself is not a pair. It cannot happen through the seam, but the
    /// answer must not be "initiate a session with ourselves".
    #[test]
    fn a_device_is_not_its_own_peer() {
        let mut c = ctx(HIGH, HIGH);
        c.peer_init_in_flight = true;
        // `tie_break_role` gives Responder for equal ids, so this yields rather than initiating.
        assert_eq!(plan_initiation(&c), InitiationDecision::YieldToPeer);
    }

    /// The wire spellings are compared across clients and printed into logs; pin them.
    #[test]
    fn the_wire_spellings_are_stable() {
        assert_eq!(InitiationDecision::Initiate.as_wire(), "Initiate");
        assert_eq!(InitiationDecision::JoinInFlight.as_wire(), "JoinInFlight");
        assert_eq!(InitiationDecision::YieldToPeer.as_wire(), "YieldToPeer");
        assert_eq!(InitiationDecision::Wait.as_wire(), "Wait");
    }
}
