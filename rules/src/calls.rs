//! A 1:1 call: which of the other person's devices each signal goes to, how it ended, and what the
//! call history says about it.
//!
//! Three copies of this lived apart until now: iOS (`CallDeviceRouting`, `CallManager.endActiveCall`,
//! `CallPhase.outcome`), Android (`CallDeviceRouting.kt`, `CallHistoryRules`, `CallRules` — "Canon:
//! iOS, rule for rule") and the Linux and Windows client (`calls::Manager`), which had drifted: it
//! released only a late answer and never the devices still ringing, ended the whole call on one busy
//! device, kept its own outgoing call on glare, and wrote "failed" where iOS writes "missed". The iOS
//! rules are the canon here (construct-docs `decisions/a-call-rings-every-device.md`,
//! todo 295).
//!
//! No proto: a platform maps `WebRTCSignal` and `SignalErrorCode` to these types at its boundary
//! (`HangupReason::from_wire`, `SignalError::from_wire`). Device ids are `CryptoDeviceId`s, and a
//! device is the one whose session opened the signal — never the `sender_device_id` its sender wrote.

/// Which side of the call we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}

/// `HangupReason` of `signaling/webrtc.proto`, by value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HangupReason {
    /// 0, and any value this build does not know.
    Unspecified,
    Normal,
    Busy,
    Declined,
    /// Nobody answered.
    Timeout,
    ConnectionFailed,
    /// Another device of the callee took the call.
    AcceptedElsewhere,
}

impl HangupReason {
    /// The reason a received `CallHangup.reason` names. A value from a later build reads as
    /// `Unspecified`, which every decision here treats as a normal hangup.
    pub fn from_wire(value: i32) -> Self {
        match value {
            1 => Self::Normal,
            2 => Self::Busy,
            3 => Self::Declined,
            4 => Self::Timeout,
            5 => Self::ConnectionFailed,
            6 => Self::AcceptedElsewhere,
            _ => Self::Unspecified,
        }
    }

    /// The value to write into `CallHangup.reason`.
    pub fn wire(self) -> i32 {
        match self {
            Self::Unspecified => 0,
            Self::Normal => 1,
            Self::Busy => 2,
            Self::Declined => 3,
            Self::Timeout => 4,
            Self::ConnectionFailed => 5,
            Self::AcceptedElsewhere => 6,
        }
    }
}

/// `SignalErrorCode` of `services/signaling_service.proto`: the signaling server refused or ended
/// the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    /// 0, and any value this build does not know.
    Unspecified,
    CalleeOffline,
    CalleeBusy,
    RateLimited,
    Unauthorized,
    CallExpired,
}

impl SignalError {
    pub fn from_wire(value: i32) -> Self {
        match value {
            1 => Self::CalleeOffline,
            2 => Self::CalleeBusy,
            3 => Self::RateLimited,
            4 => Self::Unauthorized,
            5 => Self::CallExpired,
            _ => Self::Unspecified,
        }
    }
}

/// Why a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// A hangup: ours, or one the peer's device sent.
    Hangup(HangupReason),
    /// The signaling server's error.
    Error(SignalError),
    /// Our own setup or path failed (media, ICE, a send). A person ending the call is a hangup.
    Local,
}

// ── Devices ───────────────────────────────────────────────────────────────────
//
// The offer rings every device of the peer we hold a session with; until someone answers,
// everything we send goes to all of them; the first answer picks the device, from then on we talk
// to it alone, and the others are told the call was taken elsewhere.

/// Who a call signal is sealed for. `chosen`: the device this call talks to — the one that sent the
/// offer (callee side) or answered first (caller side). `offered`: the devices our offer went to.
/// `pinned`: the device the peer's pinned key names, for a call that knows neither (a busy refusal
/// to a call we never took).
pub fn targets(chosen: Option<&str>, offered: &[String], pinned: Option<&str>) -> Vec<String> {
    if let Some(chosen) = chosen {
        return vec![chosen.to_owned()];
    }
    if !offered.is_empty() {
        return offered.to_vec();
    }
    pinned.map(|p| vec![p.to_owned()]).unwrap_or_default()
}

/// The devices an offer goes to: those the core planned a send to (`plan_send`) that we hold a
/// session with, in the plan's order, each once. A device without a session would get nothing it
/// can open; the pinned device is the fallback when none has one (the caller then waits for its
/// session).
pub fn offer_devices(
    planned: &[String],
    with_session: &[String],
    pinned: Option<&str>,
) -> Vec<String> {
    let mut usable: Vec<String> = Vec::new();
    for device in planned {
        if with_session.contains(device) && !usable.contains(device) {
            usable.push(device.clone());
        }
    }
    if !usable.is_empty() {
        return usable;
    }
    pinned.map(|p| vec![p.to_owned()]).unwrap_or_default()
}

/// Whether a signal from `device` belongs to this call. Before a device is chosen any of the peer's
/// devices may speak (an answer, a decline); after, only the chosen one.
pub fn admits(device: &str, chosen: Option<&str>) -> bool {
    chosen.is_none_or(|c| c == device)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerDisposition {
    /// Take this answer: `device` becomes the call's device, and `release` are told the call was
    /// taken elsewhere.
    Accept {
        device: String,
        release: Vec<String>,
    },
    /// Another device answered first: tell this one the call was taken elsewhere.
    ReleaseLate { device: String },
}

/// An answer from `from` to our outgoing call.
pub fn on_answer(from: &str, chosen: Option<&str>, offered: &[String]) -> AnswerDisposition {
    match chosen {
        Some(chosen) if chosen != from => AnswerDisposition::ReleaseLate {
            device: from.to_owned(),
        },
        _ => AnswerDisposition::Accept {
            device: from.to_owned(),
            release: offered.iter().filter(|d| *d != from).cloned().collect(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HangupDisposition {
    /// End the call, and tell `release` (the other offered devices) it was taken elsewhere.
    End { release: Vec<String> },
    /// Another device of ours took the call: stop ringing, tell nobody — not the server, which
    /// would end the call for the device that took it — and write no history.
    EndTakenElsewhere,
    /// Only this device is out (it is busy); the call keeps ringing on `remaining`.
    DropDevice { remaining: Vec<String> },
    /// Not from this call's device: ignore.
    Ignore,
}

/// A hangup (or busy) from one of the peer's devices. Declining anywhere ends the call for every
/// device; busy on one only takes that one out until all are busy.
pub fn on_hangup(
    from: &str,
    reason: HangupReason,
    chosen: Option<&str>,
    offered: &[String],
) -> HangupDisposition {
    if !admits(from, chosen) {
        return HangupDisposition::Ignore;
    }
    if reason == HangupReason::AcceptedElsewhere {
        return HangupDisposition::EndTakenElsewhere;
    }
    let others: Vec<String> = offered.iter().filter(|d| *d != from).cloned().collect();
    if chosen.is_none() && reason == HangupReason::Busy && !others.is_empty() {
        return HangupDisposition::DropDevice { remaining: others };
    }
    HangupDisposition::End {
        release: if chosen.is_none() { others } else { Vec::new() },
    }
}

/// The reason our own hangup carries: declining an incoming call that is still ringing, otherwise
/// a normal hangup.
pub fn local_hangup_reason(direction: Direction, still_ringing: bool) -> HangupReason {
    if direction == Direction::Incoming && still_ringing {
        HangupReason::Declined
    } else {
        HangupReason::Normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glare {
    /// Keep our outgoing call and ignore their offer.
    KeepOurs,
    /// Drop our outgoing call and take theirs.
    Yield,
}

/// Both sides dialled each other at once, each with its own call id. The greater account id, by
/// its bytes, keeps its outgoing call; the other yields. Both sides must decide the same, or both
/// keep (no call) or both yield (no call). An empty `my_user_id` (not signed in) yields.
pub fn glare(my_user_id: &str, peer_user_id: &str) -> Glare {
    if my_user_id.as_bytes() > peer_user_id.as_bytes() {
        Glare::KeepOurs
    } else {
        Glare::Yield
    }
}

// ── How it ended ──────────────────────────────────────────────────────────────

/// How an ended call reads on its screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Ended normally; `connected_seconds` is how long the two were connected, `None` if never.
    Ended {
        connected_seconds: Option<u32>,
    },
    Declined,
    Busy,
    /// The other side never answered.
    NoAnswer,
    /// Setup, ICE or signalling failed.
    Failed,
}

impl Outcome {
    /// An outcome the person may want to act on (call back, look at the network); a normal end
    /// needs no answer, so its screen closes by itself.
    pub fn wants_attention(self) -> bool {
        !matches!(self, Self::Ended { .. })
    }
}

/// The outcome of a call that ended for `reason`.
pub fn outcome(reason: EndReason, connected_seconds: Option<u32>) -> Outcome {
    match reason {
        EndReason::Hangup(HangupReason::Declined) => Outcome::Declined,
        EndReason::Hangup(HangupReason::Busy) => Outcome::Busy,
        EndReason::Hangup(HangupReason::Timeout) => Outcome::NoAnswer,
        EndReason::Hangup(HangupReason::ConnectionFailed) => Outcome::Failed,
        EndReason::Hangup(_) => Outcome::Ended { connected_seconds },
        EndReason::Error(SignalError::CalleeBusy) => Outcome::Busy,
        EndReason::Error(SignalError::CallExpired) => Outcome::NoAnswer,
        EndReason::Error(_) => Outcome::Failed,
        EndReason::Local => Outcome::Failed,
    }
}

/// A call history row's status. The codes are the wire's (`history_snapshot.proto`,
/// `CallRecord.status`) and the store's column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryStatus {
    /// Answered, then ended.
    Completed,
    /// Never answered — ours or theirs.
    Missed,
    /// An incoming call we declined.
    Declined,
    /// An error or a local failure before anyone answered.
    Failed,
}

impl HistoryStatus {
    pub fn code(self) -> u8 {
        match self {
            Self::Completed => 0,
            Self::Missed => 1,
            Self::Declined => 2,
            Self::Failed => 3,
        }
    }
}

/// The history row a call that ended for `reason` leaves; `None` for one taken on another of our
/// devices — that device records it, and here it was neither missed nor declined. A decline is
/// ours on an incoming call and a miss on an outgoing one, busy is a miss, and otherwise whether
/// anyone answered decides.
pub fn history_status(
    direction: Direction,
    reason: EndReason,
    answered: bool,
) -> Option<HistoryStatus> {
    let status = match reason {
        EndReason::Hangup(HangupReason::AcceptedElsewhere) => return None,
        EndReason::Hangup(HangupReason::Declined) => match direction {
            Direction::Incoming => HistoryStatus::Declined,
            Direction::Outgoing => HistoryStatus::Missed,
        },
        EndReason::Hangup(HangupReason::Busy) => HistoryStatus::Missed,
        EndReason::Hangup(_) if answered => HistoryStatus::Completed,
        EndReason::Hangup(_) => HistoryStatus::Missed,
        EndReason::Error(_) | EndReason::Local if answered => HistoryStatus::Completed,
        EndReason::Error(_) | EndReason::Local => HistoryStatus::Failed,
    };
    Some(status)
}

/// Whole seconds from the answer to the end; 0 for a call nobody answered.
pub fn duration_seconds(answered_at_ms: Option<i64>, ended_at_ms: i64) -> u32 {
    answered_at_ms
        .map(|since| (ended_at_ms.saturating_sub(since) / 1000).clamp(0, u32::MAX as i64) as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Mutations that redden it: return `offered` while a device is chosen; skip `offered` for
    /// `pinned`; drop the pinned fallback.
    #[test]
    fn a_signal_goes_to_the_chosen_device_then_the_offered_ones_then_the_pinned_one() {
        let offered = ids(&["d1", "d2"]);
        assert_eq!(targets(Some("d2"), &offered, Some("p")), ids(&["d2"]));
        assert_eq!(targets(None, &offered, Some("p")), offered);
        assert_eq!(targets(None, &[], Some("p")), ids(&["p"]));
        assert!(targets(None, &[], None).is_empty());
    }

    /// Mutations that redden it: keep a device without a session; keep a duplicate; lose the
    /// plan's order; fall back to pinned while a planned device has a session.
    #[test]
    fn the_offer_rings_each_planned_device_with_a_session_once_in_order() {
        let planned = ids(&["d3", "d1", "d2", "d1"]);
        let with_session = ids(&["d1", "d3"]);
        assert_eq!(
            offer_devices(&planned, &with_session, Some("p")),
            ids(&["d3", "d1"])
        );
        assert_eq!(offer_devices(&planned, &[], Some("p")), ids(&["p"]));
        assert!(offer_devices(&planned, &[], None).is_empty());
    }

    /// Mutation that reddens it: admit any device once one is chosen, or refuse before.
    #[test]
    fn once_a_device_is_chosen_only_it_speaks() {
        assert!(admits("d1", None));
        assert!(admits("d1", Some("d1")));
        assert!(!admits("d2", Some("d1")));
    }

    /// Mutations that redden it: release nobody on the first answer; release the answering device
    /// itself; accept a later answer.
    #[test]
    fn the_first_answer_wins_and_releases_every_other_ringing_device() {
        let offered = ids(&["d1", "d2", "d3"]);
        assert_eq!(
            on_answer("d2", None, &offered),
            AnswerDisposition::Accept {
                device: "d2".into(),
                release: ids(&["d1", "d3"])
            }
        );
        assert_eq!(
            on_answer("d3", Some("d2"), &offered),
            AnswerDisposition::ReleaseLate {
                device: "d3".into()
            }
        );
        // The chosen device answering again (a renegotiation) is still its answer.
        assert_eq!(
            on_answer("d2", Some("d2"), &[]),
            AnswerDisposition::Accept {
                device: "d2".into(),
                release: vec![]
            }
        );
    }

    /// Mutations that redden it: end the call on the first busy device; keep ringing on the last
    /// one's busy; drop a device after a device was chosen; release devices after one was chosen.
    #[test]
    fn busy_on_one_device_drops_only_it_while_others_ring() {
        let offered = ids(&["d1", "d2"]);
        assert_eq!(
            on_hangup("d1", HangupReason::Busy, None, &offered),
            HangupDisposition::DropDevice {
                remaining: ids(&["d2"])
            }
        );
        assert_eq!(
            on_hangup("d2", HangupReason::Busy, None, &ids(&["d2"])),
            HangupDisposition::End { release: vec![] }
        );
        assert_eq!(
            on_hangup("d1", HangupReason::Busy, Some("d1"), &offered),
            HangupDisposition::End { release: vec![] }
        );
    }

    /// Mutations that redden it: keep ringing the other devices after a decline; listen to a device
    /// that is not the chosen one; treat taken-elsewhere as an ordinary end.
    #[test]
    fn a_decline_anywhere_ends_the_call_and_releases_the_rest() {
        let offered = ids(&["d1", "d2", "d3"]);
        assert_eq!(
            on_hangup("d2", HangupReason::Declined, None, &offered),
            HangupDisposition::End {
                release: ids(&["d1", "d3"])
            }
        );
        assert_eq!(
            on_hangup("d3", HangupReason::Normal, Some("d1"), &offered),
            HangupDisposition::Ignore
        );
        assert_eq!(
            on_hangup("c", HangupReason::AcceptedElsewhere, Some("c"), &[]),
            HangupDisposition::EndTakenElsewhere
        );
        assert_eq!(
            on_hangup("x", HangupReason::AcceptedElsewhere, Some("c"), &[]),
            HangupDisposition::Ignore
        );
    }

    /// Mutations that redden it: decline an answered incoming call; decline an outgoing one.
    #[test]
    fn ending_a_ringing_incoming_call_declines_it() {
        assert_eq!(
            local_hangup_reason(Direction::Incoming, true),
            HangupReason::Declined
        );
        assert_eq!(
            local_hangup_reason(Direction::Incoming, false),
            HangupReason::Normal
        );
        assert_eq!(
            local_hangup_reason(Direction::Outgoing, true),
            HangupReason::Normal
        );
    }

    /// Mutations that redden it: compare the other way; keep on equal ids. Exactly one side keeps.
    #[test]
    fn on_glare_exactly_one_side_keeps_its_call() {
        let a = "3f0c1d2e-0000-4000-8000-000000000001";
        let b = "3f0c1d2e-0000-4000-8000-000000000002";
        assert_eq!(glare(b, a), Glare::KeepOurs);
        assert_eq!(glare(a, b), Glare::Yield);
        assert_eq!(glare(a, a), Glare::Yield);
        assert_eq!(glare("", a), Glare::Yield);
    }

    /// Mutations that redden it: swap two arms of `from_wire`/`wire`, or read an unknown value as
    /// anything but `Unspecified`.
    #[test]
    fn hangup_reasons_and_errors_keep_their_wire_values() {
        for v in 0..=6 {
            assert_eq!(HangupReason::from_wire(v).wire(), v);
        }
        assert_eq!(HangupReason::from_wire(7), HangupReason::Unspecified);
        assert_eq!(HangupReason::from_wire(-1), HangupReason::Unspecified);
        assert_eq!(HangupReason::from_wire(6), HangupReason::AcceptedElsewhere);
        let errors = [
            (1, SignalError::CalleeOffline),
            (2, SignalError::CalleeBusy),
            (3, SignalError::RateLimited),
            (4, SignalError::Unauthorized),
            (5, SignalError::CallExpired),
            (9, SignalError::Unspecified),
        ];
        for (v, e) in errors {
            assert_eq!(SignalError::from_wire(v), e, "{v}");
        }
    }

    /// iOS `CallPhase.outcome`, case for case. Mutations that redden it: any arm changed.
    #[test]
    fn the_outcome_reads_as_ios_shows_it() {
        let h = |r| outcome(EndReason::Hangup(r), Some(12));
        assert_eq!(h(HangupReason::Declined), Outcome::Declined);
        assert_eq!(h(HangupReason::Busy), Outcome::Busy);
        assert_eq!(h(HangupReason::Timeout), Outcome::NoAnswer);
        assert_eq!(h(HangupReason::ConnectionFailed), Outcome::Failed);
        for r in [
            HangupReason::Normal,
            HangupReason::Unspecified,
            HangupReason::AcceptedElsewhere,
        ] {
            assert_eq!(
                h(r),
                Outcome::Ended {
                    connected_seconds: Some(12)
                }
            );
        }
        let e = |c| outcome(EndReason::Error(c), None);
        assert_eq!(e(SignalError::CalleeBusy), Outcome::Busy);
        assert_eq!(e(SignalError::CallExpired), Outcome::NoAnswer);
        assert_eq!(e(SignalError::CalleeOffline), Outcome::Failed);
        assert_eq!(outcome(EndReason::Local, Some(3)), Outcome::Failed);
        assert!(
            !Outcome::Ended {
                connected_seconds: None
            }
            .wants_attention()
        );
        assert!(Outcome::NoAnswer.wants_attention());
    }

    /// iOS `CallManager.endActiveCall`, case for case. Mutations that redden it: record a call
    /// taken elsewhere; make an outgoing decline "declined"; make busy depend on the answer; make a
    /// local failure of an answered call "failed".
    #[test]
    fn the_history_status_follows_ios() {
        use Direction::{Incoming, Outgoing};
        use HistoryStatus::*;
        let hang = EndReason::Hangup;
        assert_eq!(
            history_status(Incoming, hang(HangupReason::AcceptedElsewhere), false),
            None
        );
        assert_eq!(
            history_status(Incoming, hang(HangupReason::Declined), false),
            Some(Declined)
        );
        assert_eq!(
            history_status(Outgoing, hang(HangupReason::Declined), false),
            Some(Missed)
        );
        assert_eq!(
            history_status(Outgoing, hang(HangupReason::Busy), true),
            Some(Missed)
        );
        assert_eq!(
            history_status(Outgoing, hang(HangupReason::Normal), true),
            Some(Completed)
        );
        assert_eq!(
            history_status(Incoming, hang(HangupReason::ConnectionFailed), false),
            Some(Missed)
        );
        assert_eq!(
            history_status(Outgoing, EndReason::Local, true),
            Some(Completed)
        );
        assert_eq!(
            history_status(Outgoing, EndReason::Local, false),
            Some(Failed)
        );
        assert_eq!(
            history_status(Incoming, EndReason::Error(SignalError::CalleeBusy), false),
            Some(Failed)
        );
        let codes: Vec<u8> = [Completed, Missed, Declined, Failed]
            .iter()
            .map(|s| s.code())
            .collect();
        assert_eq!(codes, vec![0, 1, 2, 3]);
    }

    /// Mutations that redden it: count in ms; let a clock step back go negative; count an
    /// unanswered call.
    #[test]
    fn the_duration_counts_whole_seconds_from_the_answer() {
        assert_eq!(duration_seconds(Some(1_000), 63_999), 62);
        assert_eq!(duration_seconds(Some(5_000), 1_000), 0);
        assert_eq!(duration_seconds(None, 63_999), 0);
    }
}
