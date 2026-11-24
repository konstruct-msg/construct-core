//! A new device's wait to be let into an account, when the new device shows the QR (Flow B).
//!
//! The device submits a join request, shows its code, and asks the server until a device of the
//! account has let it in; then it signs in with the key it asked to join with
//! (construct-docs `decisions/a-joining-device-signs-in-with-its-own-key.md`). What to do next and
//! how the wait ends is decided here; a platform makes the two calls and shows the end.
//!
//! The server keeps an approval for two minutes and a request for ten. So an approval is remembered
//! here, and a sign-in that did not get through is tried again without asking. And **the server's
//! "expired" does not say that nobody let us in**: it answers that too once it forgot the approval,
//! and then this device is on the account's list while its screen says the code ran out. Only the
//! sign-in knows — a device nobody let in is refused — so it is tried before giving up.
//!
//! Three copies before this one (construct-docs todo 338), and they ended differently: let in but
//! unable to sign in, construct-client said so, Android called it an expired code, iOS said
//! nothing.

use crate::send_failure::SendError;

/// Between two questions, or two sign-ins that did not get through.
pub const POLL_MS: i64 = 3_000;
/// How long the server holds a join request; and how long a device let in tries to sign in.
pub const TTL_MS: i64 = 10 * 60_000;

/// What to do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Nothing for this long; then ask again. Never more than [`POLL_MS`].
    Wait(i64),
    /// `CheckJoinRequestStatus`; then [`Join::on_status`] or [`Join::on_status_failed`].
    Ask,
    /// `AuthenticateDevice`; then [`Join::on_sign_in_failed`], or the device is in.
    SignIn,
    /// Over.
    Ended(End),
}

/// How the wait ended without the device signed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// A device of the account turned the request down.
    Rejected,
    /// Nobody let this device in before the request ran out: show a new code.
    Expired,
    /// Let in, then refused in a way that would repeat: a clock out by minutes, a wrong key.
    SignInRefused,
    /// Let in, and the server could not be reached to sign in. The device is on the account's list.
    LetInUnreachable,
}

/// `CheckJoinRequestStatusResponse.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pending,
    Approved,
    Rejected,
    Expired,
}

impl Status {
    /// An unknown value is no answer yet.
    fn from_wire(value: i32) -> Self {
        match value {
            1 => Self::Approved,
            2 => Self::Rejected,
            3 => Self::Expired,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nobody has let us in yet.
    Asking,
    /// The server no longer knows the request, or must have dropped it: a sign-in tells an expired
    /// one from an approval it forgot, or one we slept through.
    Forgotten,
    /// Let in, not signed in.
    LetIn,
    Ended(End),
}

/// gRPC codes that refuse the sign-in itself: the same answer would come again.
const INVALID_ARGUMENT: u32 = 3;
const PERMISSION_DENIED: u32 = 7;
const UNAUTHENTICATED: u32 = 16;

fn refuses(failure: SendError) -> bool {
    matches!(
        failure,
        SendError::Status(INVALID_ARGUMENT | PERMISSION_DENIED | UNAUTHENTICATED)
    )
}

/// One join request's wait. Not kept: a restarted client shows a new code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    phase: Phase,
    next_at_ms: i64,
    deadline_ms: i64,
}

impl Join {
    /// The request was submitted and its code is on the screen.
    pub fn new(now_ms: i64) -> Self {
        Self {
            phase: Phase::Asking,
            next_at_ms: now_ms.saturating_add(POLL_MS),
            deadline_ms: now_ms.saturating_add(TTL_MS),
        }
    }

    /// What to do now. Asked again after every step.
    pub fn next(&mut self, now_ms: i64) -> Step {
        if self.phase == Phase::Asking && now_ms >= self.deadline_ms {
            self.phase = Phase::Forgotten;
            self.next_at_ms = now_ms;
        }
        // A clock set back meanwhile must not stop the asking until it catches up.
        self.next_at_ms = self.next_at_ms.min(now_ms.saturating_add(POLL_MS));
        let wait = self.next_at_ms.saturating_sub(now_ms);
        match self.phase {
            Phase::Ended(end) => Step::Ended(end),
            _ if wait > 0 => Step::Wait(wait),
            Phase::Asking => Step::Ask,
            Phase::Forgotten | Phase::LetIn => Step::SignIn,
        }
    }

    /// The server's answer, by its number.
    pub fn on_status(&mut self, status: i32, now_ms: i64) {
        if self.phase != Phase::Asking {
            return;
        }
        match Status::from_wire(status) {
            Status::Pending => self.later(now_ms),
            Status::Approved => {
                self.phase = Phase::LetIn;
                self.deadline_ms = now_ms.saturating_add(TTL_MS);
            }
            Status::Rejected => self.phase = Phase::Ended(End::Rejected),
            Status::Expired => self.phase = Phase::Forgotten,
        }
    }

    /// No answer about the request; asked again later.
    pub fn on_status_failed(&mut self, now_ms: i64) {
        self.later(now_ms);
    }

    /// The sign-in did not give tokens. The time is up only after a sign-in: whoever slept past the
    /// deadline still gets one.
    pub fn on_sign_in_failed(&mut self, failure: SendError, now_ms: i64) {
        let refused = refuses(failure);
        let over = now_ms >= self.deadline_ms;
        let end = match self.phase {
            Phase::LetIn if refused => End::SignInRefused,
            Phase::LetIn if over => End::LetInUnreachable,
            // Refused: nobody let us in. No answer in time: nothing says that anyone did.
            Phase::Forgotten if refused || over => End::Expired,
            Phase::LetIn | Phase::Forgotten => return self.later(now_ms),
            Phase::Asking | Phase::Ended(_) => return,
        };
        self.phase = Phase::Ended(end);
    }

    fn later(&mut self, now_ms: i64) {
        self.next_at_ms = now_ms.saturating_add(POLL_MS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PENDING: i32 = 0;
    const APPROVED: i32 = 1;
    const REJECTED: i32 = 2;
    const EXPIRED: i32 = 3;
    const T0: i64 = 1_000_000;

    /// A join asked for the first time, at `T0 + POLL_MS`.
    fn asking() -> (Join, i64) {
        let mut join = Join::new(T0);
        let now = T0 + POLL_MS;
        assert_eq!(join.next(now), Step::Ask);
        (join, now)
    }

    fn after_status(status: i32) -> (Join, i64) {
        let (mut join, now) = asking();
        join.on_status(status, now);
        (join, now)
    }

    /// Mutations that redden it: sign in while pending; ask without a pause; sign in only at the
    /// next poll.
    #[test]
    fn it_asks_until_let_in_and_then_signs_in_at_once() {
        let mut join = Join::new(T0);
        assert_eq!(join.next(T0), Step::Wait(POLL_MS));
        assert_eq!(join.next(T0 + 1_000), Step::Wait(POLL_MS - 1_000));
        let now = T0 + POLL_MS;
        assert_eq!(join.next(now), Step::Ask);
        join.on_status(PENDING, now);
        assert_eq!(join.next(now), Step::Wait(POLL_MS));
        assert_eq!(join.next(now + POLL_MS), Step::Ask);
        join.on_status(APPROVED, now + POLL_MS);
        assert_eq!(join.next(now + POLL_MS), Step::SignIn);
    }

    /// construct-server keeps a join request for ten minutes (`store_join_request`).
    #[test]
    fn it_waits_as_long_as_the_server_holds_the_request() {
        assert_eq!((POLL_MS, TTL_MS), (3_000, 600_000));
    }

    /// An unknown value, and no answer at all, are not an end.
    #[test]
    fn no_answer_is_asked_again() {
        let (mut join, now) = after_status(99);
        assert_eq!(join.next(now), Step::Wait(POLL_MS));
        join.on_status_failed(now + POLL_MS);
        assert_eq!(join.next(now + POLL_MS), Step::Wait(POLL_MS));
        assert_eq!(join.next(now + 2 * POLL_MS), Step::Ask);
    }

    /// Mutation that reddens it: go back to asking after a sign-in that did not get through — the
    /// server has forgotten the approval by then.
    #[test]
    fn a_sign_in_that_did_not_get_through_is_tried_again_without_asking() {
        let (mut join, now) = after_status(APPROVED);
        for failure in [
            SendError::NoAnswer,
            SendError::Status(14),
            SendError::Status(13),
        ] {
            assert_eq!(join.next(now), Step::SignIn);
            join.on_sign_in_failed(failure, now - POLL_MS);
            assert_eq!(join.next(now - POLL_MS), Step::Wait(POLL_MS));
        }
    }

    /// Mutations that redden it: drop any of the three codes; treat every status as a refusal.
    #[test]
    fn a_refused_sign_in_ends_it() {
        for code in [3, 7, 16] {
            let (mut join, now) = after_status(APPROVED);
            join.on_sign_in_failed(SendError::Status(code), now);
            assert_eq!(
                join.next(now),
                Step::Ended(End::SignInRefused),
                "code {code}"
            );
        }
    }

    #[test]
    fn a_rejected_request_ends_it() {
        let (mut join, now) = after_status(REJECTED);
        assert_eq!(join.next(now), Step::Ended(End::Rejected));
        join.on_status(APPROVED, now);
        assert_eq!(join.next(now), Step::Ended(End::Rejected), "an end stays");
    }

    /// The server forgot the approval (it keeps one for two minutes) and says "expired" of a device
    /// it let in. Mutation that reddens it: end on `Expired`.
    #[test]
    fn expired_is_asked_of_the_sign_in_before_giving_up() {
        let (mut join, now) = after_status(EXPIRED);
        assert_eq!(join.next(now), Step::SignIn);
        join.on_sign_in_failed(SendError::NoAnswer, now);
        assert_eq!(join.next(now), Step::Wait(POLL_MS));
        assert_eq!(join.next(now + POLL_MS), Step::SignIn);
        join.on_sign_in_failed(SendError::Status(16), now + POLL_MS);
        assert_eq!(join.next(now + POLL_MS), Step::Ended(End::Expired));
    }

    /// Nobody let us in: the request ran out on the server, or here first. Mutations that redden
    /// it: end before the sign-in; keep trying past the deadline.
    #[test]
    fn a_request_that_ran_out_ends_after_one_sign_in() {
        for failure in [SendError::NoAnswer, SendError::Status(16)] {
            let mut join = Join::new(T0);
            assert_eq!(join.next(T0 + TTL_MS - 1), Step::Ask);
            join.on_status_failed(T0 + TTL_MS - 1);
            assert_eq!(join.next(T0 + TTL_MS), Step::SignIn);
            join.on_sign_in_failed(failure, T0 + TTL_MS);
            assert_eq!(join.next(T0 + TTL_MS), Step::Ended(End::Expired));
        }
    }

    /// Let in, and no answer for as long as it tries — ten minutes from the approval, not from the
    /// code. Mutations that redden it: "expired" said of a device the account now lists; the
    /// deadline of the code kept.
    #[test]
    fn a_device_let_in_and_never_signed_in_is_not_expired() {
        let mut join = Join::new(T0);
        let now = T0 + TTL_MS - 1;
        assert_eq!(join.next(now), Step::Ask);
        join.on_status(APPROVED, now);
        join.on_sign_in_failed(SendError::NoAnswer, now + TTL_MS - 1);
        assert_eq!(
            join.next(now + TTL_MS + POLL_MS),
            Step::SignIn,
            "asleep past the deadline: one more"
        );
        join.on_sign_in_failed(SendError::NoAnswer, now + TTL_MS);
        assert_eq!(join.next(now + TTL_MS), Step::Ended(End::LetInUnreachable));
    }

    /// Mutations that redden it: the wait without its bound; a bound that is not kept — every wait
    /// short, and no question for an hour.
    #[test]
    fn a_clock_set_back_does_not_stop_the_asking() {
        let mut join = Join::new(T0);
        let back = T0 - 3_600_000;
        assert_eq!(join.next(back), Step::Wait(POLL_MS));
        assert_eq!(join.next(back + POLL_MS), Step::Ask);
    }

    /// A sign-in nobody asked for, or an answer that comes late, changes nothing.
    #[test]
    fn a_report_out_of_turn_changes_nothing() {
        let (mut join, now) = asking();
        let before = join.clone();
        join.on_sign_in_failed(SendError::Status(16), now);
        assert_eq!(join, before);

        let (mut join, now) = after_status(APPROVED);
        let before = join.clone();
        join.on_status(EXPIRED, now);
        assert_eq!(join, before);
    }
}
