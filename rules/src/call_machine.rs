//! One 1:1 call from its first signal to its end: the phase, the facts every decision about it
//! reads, and when it must give up.
//!
//! The decisions themselves are `calls` (which device, how it ended, an arriving offer, a closed
//! stream, where a hangup goes). What iOS and Android still kept apart, each in its own
//! `ActiveCall`, is the state those decisions read and the moments it changes: the phase, the
//! chosen and offered devices, whether an offer is held or awaited, whether media is up, the stream
//! and ICE-restart budgets, the ended call ids, and the three timers (an unanswered call, an
//! answer waiting for its offer, the ICE-restart grace). Android ported iOS "rule for rule"; this
//! is that state once, with the timings both had to keep equal by hand (todo 295, step 5).
//!
//! Prior art: Signal RingRTC keeps the whole call in Rust for Android, iOS and Desktop
//! (`src/rust/src/core/call_fsm.rs`, `call_manager.rs`, read 2026-11-14 at `1c386d7`) and drives
//! the platform through callbacks. Ours is sans-IO like every rule here: each method takes an event
//! and the time, changes the state and returns what it decided; the platform does the sending,
//! WebRTC, CallKit and the history row. Timers are deadlines: the platform keeps one timer at
//! [`Calls::next_deadline`] and calls [`Calls::tick`] when it fires.
//!
//! Not here, because they are media or a platform's own carrier: ICE candidates and their
//! buffering, SDP, the camera, the VoIP push's CallKit report, the ended screen's auto-clear.

use crate::calls::{
    self, AnswerDisposition, Direction, EndReason, HangupDisposition, HangupReason, HangupRoute,
    HangupSide, HeldCall, HistoryStatus, OfferAction, Outcome, SignalError, StreamClosedAction,
};

/// The call timings. Before this they were constants in two places that had to agree: iOS
/// `NetworkTiming.Calls` and Android `CallTiming` ("the same value here, so both platforms give up
/// on one schedule").
pub mod timing {
    /// An incoming call nobody answers ends with `TIMEOUT`. Nothing else ends it: the callee opens
    /// its stream only on answer, so the server's reaper never reaches it, and a caller that
    /// crashed sends no hangup.
    pub const UNANSWERED_MS: i64 = 90_000;
    /// An answered call waits this long for an offer that has not arrived. Generous: the offer
    /// rides the ordinary message stream and queues behind whatever else is on it (2026-08-05: 30 s).
    pub const OFFER_WAIT_MS: i64 = 45_000;
    /// A disconnected ICE path gets this long to come back before the caller restarts it.
    pub const ICE_RESTART_GRACE_MS: i64 = 2_000;
    /// ICE restarts per call, counted again from zero each time media connects.
    pub const MAX_ICE_RESTARTS: u32 = 3;
    /// Signalling stream reopenings before media is up.
    pub const MAX_STREAM_RETRIES: u32 = 3;
    /// Signalling stream reopenings once media is up.
    pub const MAX_POST_MEDIA_RECONNECTS: u32 = 5;
    /// An ended call id is remembered only to outlive its own signals still in flight.
    pub const ENDED_MEMORY_MS: i64 = 120_000;
}

/// Where a call is. An ended call is not a phase: it leaves [`Calls`] as an [`Ended`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Ringing on us, unanswered.
    Incoming,
    /// Ours, before any of their devices rang.
    Dialing,
    /// Ours, ringing on their side.
    Ringing,
    /// The person answered their call; the offer is being applied or awaited.
    Connecting,
    /// Answered on both sides.
    Active,
}

/// The call this device is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub call_id: String,
    pub peer_user_id: String,
    pub direction: Direction,
    pub phase: Phase,
    /// The peer's device this call talks to: the one that sent the offer (incoming), or the one
    /// whose answer came first (outgoing). Known from the session the core opened its signal
    /// under, never from the `sender_device_id` the sender wrote.
    pub chosen: Option<String>,
    /// The peer's devices our offer went to (outgoing, until one answers).
    pub offered: Vec<String>,
    pub started_at_ms: i64,
    /// When the call was first answered; what its duration counts from. Not moved by a
    /// renegotiation: restamping it on an ICE restart reported a two-minute call as ten seconds.
    pub answered_at_ms: Option<i64>,
    /// An offer is held for the answer to apply (incoming, before the person answered).
    pub holds_offer: bool,
    /// The person answered before the offer arrived; the offer, when it comes, finishes the
    /// answer (2026-08-05: it came 30 s later and nothing consumed it).
    pub awaiting_offer_after_answer: bool,
    /// Media connected at least once. From then on a closed stream does not end the call.
    pub media_connected: bool,
    /// ICE reports the path disconnected.
    pub reconnecting: bool,
    stream_retries: u32,
    post_media_reconnects: u32,
    ice_restart_in_flight: bool,
    ice_restart_attempts: u32,
    unanswered_due_ms: Option<i64>,
    offer_wait_due_ms: Option<i64>,
    ice_restart_due_ms: Option<i64>,
}

impl Call {
    fn new(
        call_id: String,
        peer_user_id: String,
        direction: Direction,
        phase: Phase,
        now_ms: i64,
    ) -> Self {
        Self {
            call_id,
            peer_user_id,
            direction,
            phase,
            chosen: None,
            offered: Vec::new(),
            started_at_ms: now_ms,
            answered_at_ms: None,
            holds_offer: false,
            awaiting_offer_after_answer: false,
            media_connected: false,
            reconnecting: false,
            stream_retries: 0,
            post_media_reconnects: 0,
            ice_restart_in_flight: false,
            ice_restart_attempts: 0,
            unanswered_due_ms: None,
            offer_wait_due_ms: None,
            ice_restart_due_ms: None,
        }
    }

    fn incoming(call_id: String, peer_user_id: String, now_ms: i64) -> Self {
        let mut call = Self::new(
            call_id,
            peer_user_id,
            Direction::Incoming,
            Phase::Incoming,
            now_ms,
        );
        call.unanswered_due_ms = Some(now_ms + timing::UNANSWERED_MS);
        call
    }

    fn held(&self, call_id: &str, offerer: &str) -> HeldCall {
        HeldCall {
            same_call: self.call_id == call_id,
            direction: self.direction,
            with_offerer: self.peer_user_id == offerer,
            answered: self.answered_at_ms.is_some(),
            awaiting_offer_after_answer: self.awaiting_offer_after_answer,
        }
    }

    /// Who a signal of ours goes to now: the chosen device, else every device our offer went to.
    /// Empty when neither is known; the platform falls back to the pinned device.
    pub fn targets(&self) -> Vec<String> {
        calls::targets(self.chosen.as_deref(), &self.offered, None)
    }
}

/// A call that ended: what its screen and its history row say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    pub call_id: String,
    pub peer_user_id: String,
    pub direction: Direction,
    pub reason: EndReason,
    pub outcome: Outcome,
    /// `None`: no row (taken on another of our devices, which records it).
    pub history: Option<HistoryStatus>,
    pub started_at_ms: i64,
    pub duration_seconds: u32,
}

/// What a request to call someone does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialAction {
    /// The call is ours now, dialing.
    Start,
    /// They are ringing us: answer that instead of starting a call that would cross it.
    AnswerInstead,
    /// Another call is up; this one does not start.
    Busy,
}

/// What a VoIP push (iOS) means: "there is a call", with its id and no SDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushAction {
    /// Ring: the call is held now, incoming, waiting for its offer.
    Begin,
    /// The offer got here first; the push adds nothing.
    AlreadyTracking,
    /// Our call to the same person is up and they dialled us too: end only the CallKit report
    /// the push forced. The offer decides which call survives (glare), so this one is neither
    /// refused nor remembered as ended.
    DeferToGlare,
    /// Another call is up: refuse this one as busy. Its id is remembered as ended, so its offer,
    /// arriving later, is not taken for a new call.
    DeclineBusy,
}

/// What an arriving offer did. `calls::OfferAction`, plus the two ways an offer without a usable
/// SDP ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferStep {
    /// A call that ended a moment ago, or a new call whose offer carries no SDP: nothing to ring.
    /// An unusable offer rings for a call that cannot be negotiated, and the caller learns nothing
    /// until a human hangs up.
    Ignore,
    /// A new call: ring. The offer is held for the answer.
    Ring,
    /// Glare, theirs wins: our outgoing call `replaced` gave way and theirs rings now.
    ReplaceOutgoing { replaced: String },
    /// Glare, ours wins: ignore their offer.
    KeepOurs,
    /// Another call is up: answer busy to the offering device. The id is remembered as ended.
    Busy,
    /// Ringing and unanswered: the offer is held; consent starts negotiation.
    Hold,
    /// The person answered before the offer came: apply it and finish the answer.
    ResumeAnswer,
    /// The call is under way and the peer renegotiates (an ICE restart): apply it.
    Renegotiate,
    /// The offer for the call in progress carries no SDP: the call ends rather than wait on it.
    Fail(Ended),
}

/// What the person answering an incoming call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptStep {
    /// The offer is here: apply it and send the answer.
    ApplyOffer,
    /// The offer has not arrived: wait for it (at most `timing::OFFER_WAIT_MS`), with the stream
    /// open and the backlog pulled — the offer is on the server more often than not.
    WaitForOffer,
    /// No incoming call to answer.
    Ignore,
}

/// A hangup we send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hangup {
    pub reason: HangupReason,
    /// The devices it is sealed for; empty when none is known (the platform's pinned device).
    pub targets: Vec<String>,
    pub route: HangupRoute,
    pub ended: Ended,
}

/// What a hangup or a busy from one of the peer's devices did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteHangupStep {
    /// Not from this call's device.
    Ignore,
    /// Only that device is out (busy); the call keeps ringing on `remaining`.
    DropDevice { remaining: Vec<String> },
    /// The call ended. `release`: the other offered devices, told it was taken elsewhere.
    /// `route`: where the received hangup is repeated — to the stream, so the server frees us;
    /// nowhere for "accepted elsewhere".
    End {
        release: Vec<String>,
        reason: HangupReason,
        route: HangupRoute,
        ended: Ended,
    },
}

/// What the signalling stream closing did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamStep {
    /// Open it again; the call is unaffected.
    Reconnect,
    /// No more reconnects, but media or the offer wait bounds the call.
    KeepOnMessagePath,
    /// Nothing else could end the call: it ended.
    End(Ended),
}

/// What ICE reporting the path disconnected does. `Schedule` puts the grace deadline in
/// [`Calls::next_deadline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceStep {
    Schedule,
    /// The callee waits for the caller's restart: two restarts would cross.
    CalleeWaits,
    /// Before media, already pending, or out of attempts.
    Skip,
}

/// A deadline that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Due {
    /// Nobody answered: our hangup `TIMEOUT` goes out and the call ended.
    Unanswered(Hangup),
    /// The answered call never got its offer: it ended.
    NoOffer(Ended),
    /// ICE did not come back within the grace: restart it now (the caller's offer with fresh
    /// credentials). Call [`Calls::ice_restart_sent`] when it went out, or failed to.
    RestartIce,
}

/// The call this device is in, if any, and the ids of those that ended a moment ago.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Calls {
    active: Option<Call>,
    ended: Vec<(String, i64)>,
}

impl Calls {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active(&self) -> Option<&Call> {
        self.active.as_ref()
    }

    /// The call `call_id` ended on this device within `timing::ENDED_MEMORY_MS`.
    pub fn recently_ended(&self, call_id: &str, now_ms: i64) -> bool {
        self.ended
            .iter()
            .any(|(id, at)| id == call_id && now_ms - at < timing::ENDED_MEMORY_MS)
    }

    fn remember_ended(&mut self, call_id: &str, now_ms: i64) {
        self.ended
            .retain(|(id, at)| id != call_id && now_ms - at < timing::ENDED_MEMORY_MS);
        self.ended.push((call_id.to_owned(), now_ms));
    }

    fn is_this(&self, call_id: &str) -> bool {
        self.active.as_ref().is_some_and(|c| c.call_id == call_id)
    }

    /// End the call in progress for `reason`.
    fn end(&mut self, reason: EndReason, now_ms: i64) -> Option<Ended> {
        let call = self.active.take()?;
        self.remember_ended(&call.call_id, now_ms);
        let duration_seconds = calls::duration_seconds(call.answered_at_ms, now_ms);
        let connected = call.answered_at_ms.map(|_| duration_seconds);
        Some(Ended {
            outcome: calls::outcome(reason, connected),
            history: calls::history_status(call.direction, reason, call.answered_at_ms.is_some()),
            call_id: call.call_id,
            peer_user_id: call.peer_user_id,
            direction: call.direction,
            reason,
            started_at_ms: call.started_at_ms,
            duration_seconds,
        })
    }

    // ── Starting ────────────────────────────────────────────────────────────

    /// The person asked to call `peer_user_id`.
    pub fn dial(&mut self, call_id: &str, peer_user_id: &str, now_ms: i64) -> DialAction {
        if let Some(call) = &self.active {
            return if call.direction == Direction::Incoming && call.peer_user_id == peer_user_id {
                DialAction::AnswerInstead
            } else {
                DialAction::Busy
            };
        }
        self.active = Some(Call::new(
            call_id.to_owned(),
            peer_user_id.to_owned(),
            Direction::Outgoing,
            Phase::Dialing,
            now_ms,
        ));
        DialAction::Start
    }

    /// Our offer went to `devices` (outgoing, before an answer).
    pub fn offer_sent(&mut self, devices: Vec<String>) {
        if let Some(call) = &mut self.active
            && call.direction == Direction::Outgoing
            && call.chosen.is_none()
        {
            call.offered = devices;
        }
    }

    /// A VoIP push for `call_id` from `peer_user_id` (iOS). The push and the offer are two
    /// carriers of one fact, and the offer carries strictly more; until 2026-08-22 a push that came
    /// second replaced the call and lost the offer and its candidates (build 630).
    pub fn push(&mut self, call_id: &str, peer_user_id: &str, now_ms: i64) -> PushAction {
        match &self.active {
            None => {
                self.active = Some(Call::incoming(
                    call_id.to_owned(),
                    peer_user_id.to_owned(),
                    now_ms,
                ));
                PushAction::Begin
            }
            Some(call) if call.call_id == call_id => PushAction::AlreadyTracking,
            Some(call)
                if call.direction == Direction::Outgoing && call.peer_user_id == peer_user_id =>
            {
                PushAction::DeferToGlare
            }
            Some(_) => {
                self.remember_ended(call_id, now_ms);
                PushAction::DeclineBusy
            }
        }
    }

    /// An offer for `call_id` arrived from `device` of `peer_user_id`, out of the Double Ratchet.
    /// `usable`: it carries an SDP (`offer_sdp_is_usable`); `my_user_id` decides glare.
    pub fn offer(
        &mut self,
        call_id: &str,
        peer_user_id: &str,
        device: &str,
        usable: bool,
        my_user_id: &str,
        now_ms: i64,
    ) -> OfferStep {
        let held = self.active.as_ref().map(|c| c.held(call_id, peer_user_id));
        let action = calls::on_offer(
            self.recently_ended(call_id, now_ms),
            held,
            my_user_id,
            peer_user_id,
        );
        let ring = |calls: &mut Self| {
            let mut call = Call::incoming(call_id.to_owned(), peer_user_id.to_owned(), now_ms);
            call.chosen = Some(device.to_owned());
            call.holds_offer = true;
            calls.active = Some(call);
        };
        match action {
            OfferAction::IgnoreEnded => OfferStep::Ignore,
            OfferAction::KeepOurs => OfferStep::KeepOurs,
            OfferAction::Busy => {
                self.remember_ended(call_id, now_ms);
                OfferStep::Busy
            }
            OfferAction::Ring | OfferAction::ReplaceOutgoing if !usable => OfferStep::Ignore,
            OfferAction::Ring => {
                ring(self);
                OfferStep::Ring
            }
            OfferAction::ReplaceOutgoing => {
                let replaced = self.active.take().map(|c| c.call_id).unwrap_or_default();
                self.remember_ended(&replaced, now_ms);
                ring(self);
                OfferStep::ReplaceOutgoing { replaced }
            }
            OfferAction::HoldUntilAnswered
            | OfferAction::ResumeAnswer
            | OfferAction::Renegotiate
                if !usable =>
            {
                self.end(EndReason::Local, now_ms)
                    .map_or(OfferStep::Ignore, OfferStep::Fail)
            }
            OfferAction::HoldUntilAnswered
            | OfferAction::ResumeAnswer
            | OfferAction::Renegotiate => {
                let call = self.active.as_mut().expect("the rule held this call");
                if call.chosen.is_none() {
                    call.chosen = Some(device.to_owned());
                }
                match action {
                    OfferAction::Renegotiate => OfferStep::Renegotiate,
                    OfferAction::ResumeAnswer => {
                        call.holds_offer = true;
                        OfferStep::ResumeAnswer
                    }
                    _ => {
                        call.holds_offer = true;
                        OfferStep::Hold
                    }
                }
            }
        }
    }

    // ── Answering ───────────────────────────────────────────────────────────

    /// The person answered the incoming call.
    pub fn accept(&mut self, now_ms: i64) -> AcceptStep {
        let Some(call) = &mut self.active else {
            return AcceptStep::Ignore;
        };
        if call.direction != Direction::Incoming || call.phase != Phase::Incoming {
            return AcceptStep::Ignore;
        }
        call.phase = Phase::Connecting;
        call.unanswered_due_ms = None;
        if call.holds_offer {
            return AcceptStep::ApplyOffer;
        }
        call.awaiting_offer_after_answer = true;
        call.offer_wait_due_ms = Some(now_ms + timing::OFFER_WAIT_MS);
        AcceptStep::WaitForOffer
    }

    /// Our answer went out: the held offer was applied and answered (callee), or a renegotiation
    /// was. The call is answered from the first of these on.
    pub fn answered(&mut self, now_ms: i64) {
        if let Some(call) = &mut self.active {
            call.phase = Phase::Active;
            call.answered_at_ms.get_or_insert(now_ms);
            call.holds_offer = false;
            call.awaiting_offer_after_answer = false;
            call.offer_wait_due_ms = None;
            call.unanswered_due_ms = None;
        }
    }

    /// One of their devices rang (outgoing).
    pub fn ringing(&mut self) -> bool {
        match &mut self.active {
            Some(call) if call.phase == Phase::Dialing => {
                call.phase = Phase::Ringing;
                true
            }
            _ => false,
        }
    }

    /// An answer to our outgoing call from `device`. `Accept` chose the device; apply its SDP and
    /// then call [`Calls::answered`].
    pub fn answer_from(&mut self, call_id: &str, device: &str) -> Option<AnswerDisposition> {
        if !self.is_this(call_id) {
            return None;
        }
        let call = self.active.as_mut()?;
        if call.direction != Direction::Outgoing {
            return None;
        }
        let disposition = calls::on_answer(device, call.chosen.as_deref(), &call.offered);
        if let AnswerDisposition::Accept { device, .. } = &disposition {
            call.chosen = Some(device.clone());
            call.offered.clear();
        }
        Some(disposition)
    }

    // ── Ending ──────────────────────────────────────────────────────────────

    /// The person (or this app) ended the call: declined if it is incoming and still ringing, a
    /// normal hangup otherwise.
    pub fn hang_up(&mut self, now_ms: i64) -> Option<Hangup> {
        let call = self.active.as_ref()?;
        let reason = calls::local_hangup_reason(call.direction, call.phase == Phase::Incoming);
        self.hang_up_for(reason, now_ms)
    }

    fn hang_up_for(&mut self, reason: HangupReason, now_ms: i64) -> Option<Hangup> {
        let targets = self.active.as_ref()?.targets();
        let ended = self.end(EndReason::Hangup(reason), now_ms)?;
        Some(Hangup {
            reason,
            targets,
            route: calls::hangup_route(HangupSide::Local, reason),
            ended,
        })
    }

    /// A hangup (or a busy, `reason` `Busy`) for `call_id` from `device` of the peer, end to end.
    pub fn hangup_from(
        &mut self,
        call_id: &str,
        device: &str,
        reason: HangupReason,
        now_ms: i64,
    ) -> RemoteHangupStep {
        let Some(call) = self.active.as_mut().filter(|c| c.call_id == call_id) else {
            return RemoteHangupStep::Ignore;
        };
        match calls::on_hangup(device, reason, call.chosen.as_deref(), &call.offered) {
            HangupDisposition::Ignore => RemoteHangupStep::Ignore,
            HangupDisposition::DropDevice { remaining } => {
                call.offered = remaining.clone();
                RemoteHangupStep::DropDevice { remaining }
            }
            HangupDisposition::EndTakenElsewhere => self.remote_end(Vec::new(), reason, now_ms),
            HangupDisposition::End { release } => self.remote_end(release, reason, now_ms),
        }
    }

    fn remote_end(
        &mut self,
        release: Vec<String>,
        reason: HangupReason,
        now_ms: i64,
    ) -> RemoteHangupStep {
        match self.end(EndReason::Hangup(reason), now_ms) {
            Some(ended) => RemoteHangupStep::End {
                release,
                reason,
                route: calls::hangup_route(HangupSide::Remote, reason),
                ended,
            },
            None => RemoteHangupStep::Ignore,
        }
    }

    /// The server ended the call over the stream (its hangup or busy, relayed or its own): it
    /// knows, so nothing is sent back.
    pub fn ended_by_server(&mut self, reason: HangupReason, now_ms: i64) -> Option<Ended> {
        self.end(EndReason::Hangup(reason), now_ms)
    }

    /// A signalling error from the server. `RateLimited` drops one ICE signal and nothing else —
    /// the call goes on; every other error ends it.
    pub fn server_error(&mut self, error: SignalError, now_ms: i64) -> Option<Ended> {
        if error == SignalError::RateLimited {
            return None;
        }
        self.end(EndReason::Error(error), now_ms)
    }

    /// Our own setup or path failed (ICE failed, a send, an offer or answer that would not apply).
    pub fn fail(&mut self, now_ms: i64) -> Option<Ended> {
        self.end(EndReason::Local, now_ms)
    }

    // ── Media and the stream ────────────────────────────────────────────────

    /// Media connected (again). The ICE-restart budget starts over.
    pub fn media_connected(&mut self) {
        if let Some(call) = &mut self.active {
            call.media_connected = true;
            call.reconnecting = false;
            call.ice_restart_due_ms = None;
            call.ice_restart_in_flight = false;
            call.ice_restart_attempts = 0;
        }
    }

    /// ICE reports the path `reconnecting` (disconnected) or back. Only the caller restarts, once
    /// media has been up, at most `timing::MAX_ICE_RESTARTS` times; the callee waits for the
    /// caller's offer, since two restarts would cross.
    pub fn media_quality(&mut self, reconnecting: bool, now_ms: i64) -> IceStep {
        let Some(call) = &mut self.active else {
            return IceStep::Skip;
        };
        call.reconnecting = reconnecting;
        if !reconnecting {
            call.ice_restart_due_ms = None;
            return IceStep::Skip;
        }
        if !call.media_connected {
            return IceStep::Skip;
        }
        if call.direction != Direction::Outgoing {
            return IceStep::CalleeWaits;
        }
        if call.ice_restart_in_flight
            || call.ice_restart_due_ms.is_some()
            || call.ice_restart_attempts >= timing::MAX_ICE_RESTARTS
        {
            return IceStep::Skip;
        }
        call.ice_restart_due_ms = Some(now_ms + timing::ICE_RESTART_GRACE_MS);
        IceStep::Schedule
    }

    /// The restart offer went out, or failed to; another may be scheduled.
    pub fn ice_restart_sent(&mut self) {
        if let Some(call) = &mut self.active {
            call.ice_restart_in_flight = false;
        }
    }

    /// The signalling stream's receive loop ended.
    pub fn stream_closed(&mut self, now_ms: i64) -> Option<StreamStep> {
        let call = self.active.as_mut()?;
        let can_reconnect = if call.media_connected {
            call.post_media_reconnects < timing::MAX_POST_MEDIA_RECONNECTS
        } else {
            call.stream_retries < timing::MAX_STREAM_RETRIES
        };
        match calls::on_stream_closed(
            can_reconnect,
            call.media_connected,
            call.awaiting_offer_after_answer,
        ) {
            StreamClosedAction::Reconnect => {
                if call.media_connected {
                    call.post_media_reconnects += 1;
                } else {
                    call.stream_retries += 1;
                }
                Some(StreamStep::Reconnect)
            }
            StreamClosedAction::KeepOnMessagePath => Some(StreamStep::KeepOnMessagePath),
            StreamClosedAction::EndCall => self.fail(now_ms).map(StreamStep::End),
        }
    }

    // ── Time ────────────────────────────────────────────────────────────────

    /// The earliest moment [`Calls::tick`] has something to do; `None` with nothing pending.
    pub fn next_deadline(&self) -> Option<i64> {
        let call = self.active.as_ref()?;
        [
            call.unanswered_due_ms,
            call.offer_wait_due_ms,
            call.ice_restart_due_ms,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// What the deadlines that passed by `now_ms` decided. At most one ends the call.
    pub fn tick(&mut self, now_ms: i64) -> Option<Due> {
        let call = self.active.as_mut()?;
        let passed = |due: Option<i64>| due.is_some_and(|at| at <= now_ms);
        if passed(call.unanswered_due_ms) {
            call.unanswered_due_ms = None;
            if call.phase == Phase::Incoming {
                return self
                    .hang_up_for(HangupReason::Timeout, now_ms)
                    .map(Due::Unanswered);
            }
        }
        let call = self.active.as_mut()?;
        if passed(call.offer_wait_due_ms) {
            call.offer_wait_due_ms = None;
            if call.awaiting_offer_after_answer {
                return self.fail(now_ms).map(Due::NoOffer);
            }
        }
        let call = self.active.as_mut()?;
        // The grace deadline is set only when a restart may run (`media_quality`), and cleared when
        // the path comes back or media connects: still set, it is due.
        if passed(call.ice_restart_due_ms) {
            call.ice_restart_due_ms = None;
            call.ice_restart_in_flight = true;
            call.ice_restart_attempts += 1;
            return Some(Due::RestartIce);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_000_000;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Our call to `peer`, offered to `devices`.
    fn dialled(devices: &[&str]) -> Calls {
        let mut calls = Calls::new();
        assert_eq!(calls.dial("c1", "peer", T0), DialAction::Start);
        calls.offer_sent(ids(devices));
        calls
    }

    /// Their call, rung by its offer from `d1`.
    fn rung() -> Calls {
        let mut calls = Calls::new();
        assert_eq!(
            calls.offer("c1", "peer", "d1", true, "me", T0),
            OfferStep::Ring
        );
        calls
    }

    fn phase(calls: &Calls) -> Option<Phase> {
        calls.active().map(|c| c.phase)
    }

    // ── Starting ────────────────────────────────────────────────────────────

    /// Mutations: dial over a call in progress; answer-instead for someone else's call.
    #[test]
    fn dialling_starts_only_with_nothing_in_progress_and_answers_a_crossing_call() {
        let mut calls = rung();
        assert_eq!(calls.dial("c2", "peer", T0), DialAction::AnswerInstead);
        assert_eq!(calls.dial("c2", "other", T0), DialAction::Busy);
        assert_eq!(calls.active().unwrap().call_id, "c1");

        let mut calls = dialled(&["d1"]);
        assert_eq!(calls.dial("c2", "peer", T0), DialAction::Busy);
        assert_eq!(phase(&calls), Some(Phase::Dialing));
    }

    /// The offer list is the outgoing call's until a device is chosen.
    #[test]
    fn the_offer_list_is_kept_only_before_a_device_is_chosen() {
        let mut calls = dialled(&["d1", "d2"]);
        assert_eq!(calls.active().unwrap().offered, ids(&["d1", "d2"]));
        calls.answer_from("c1", "d1");
        calls.offer_sent(ids(&["d3"]));
        assert!(calls.active().unwrap().offered.is_empty());
        assert_eq!(calls.active().unwrap().targets(), ids(&["d1"]));
    }

    // ── A push and an offer, in either order (iOS 2026-08-22, build 630) ─────

    /// Mutations: a push for the tracked call begins it again; a busy push not remembered.
    #[test]
    fn a_push_rings_once_defers_to_glare_and_refuses_a_second_call() {
        let mut calls = Calls::new();
        assert_eq!(calls.push("c1", "peer", T0), PushAction::Begin);
        assert_eq!(phase(&calls), Some(Phase::Incoming));
        assert!(!calls.active().unwrap().holds_offer);
        assert_eq!(calls.push("c1", "peer", T0), PushAction::AlreadyTracking);

        // The offer that follows the push is held for the answer.
        assert_eq!(
            calls.offer("c1", "peer", "d1", true, "me", T0),
            OfferStep::Hold
        );
        assert_eq!(calls.active().unwrap().chosen.as_deref(), Some("d1"));

        assert_eq!(calls.push("c2", "other", T0), PushAction::DeclineBusy);
        assert!(calls.recently_ended("c2", T0));
        // The refused call's offer, later, rings nothing.
        assert_eq!(
            calls.offer("c2", "other", "o1", true, "me", T0 + 1),
            OfferStep::Ignore
        );

        let mut calls = dialled(&["d1"]);
        assert_eq!(calls.push("c9", "peer", T0), PushAction::DeferToGlare);
        assert!(!calls.recently_ended("c9", T0));
        // Glare is our call to them: a second call from the person ringing us, or a push while
        // we call someone else, is busy.
        let mut calls = rung();
        assert_eq!(calls.push("c9", "peer", T0), PushAction::DeclineBusy);
        let mut calls = dialled(&["d1"]);
        assert_eq!(calls.push("c9", "other", T0), PushAction::DeclineBusy);
    }

    /// Every refused or ended id is remembered for its own two minutes, not only the last one.
    ///
    /// Mutations: remembering one id forgets the others.
    #[test]
    fn each_ended_id_is_remembered_apart() {
        let mut calls = rung();
        calls.offer("c2", "other", "o1", true, "me", T0 + 1_000);
        calls.offer("c3", "third", "t1", true, "me", T0 + 2_000);
        calls.hang_up(T0 + 3_000);
        for id in ["c1", "c2", "c3"] {
            assert!(calls.recently_ended(id, T0 + 4_000), "{id}");
        }
        assert!(!calls.recently_ended("c2", T0 + 1_000 + timing::ENDED_MEMORY_MS));
        assert!(calls.recently_ended("c1", T0 + 1_000 + timing::ENDED_MEMORY_MS));
    }

    // ── Offers ──────────────────────────────────────────────────────────────

    /// A new call rings with its offer held and its device chosen; one without an SDP rings
    /// nothing (build 613).
    ///
    /// Mutations: ring an unusable offer; forget the device; forget the held offer.
    #[test]
    fn a_new_call_rings_from_a_usable_offer_only() {
        let calls = rung();
        let call = calls.active().unwrap();
        assert_eq!(call.phase, Phase::Incoming);
        assert_eq!(call.direction, Direction::Incoming);
        assert_eq!(call.chosen.as_deref(), Some("d1"));
        assert!(call.holds_offer);

        let mut calls = Calls::new();
        assert_eq!(
            calls.offer("c1", "peer", "d1", false, "me", T0),
            OfferStep::Ignore
        );
        assert!(calls.active().is_none());
    }

    /// The offer of a call that ended a moment ago rings nothing (2026-08-05): it outlived its call.
    ///
    /// Mutation: end without remembering the id.
    #[test]
    fn an_offer_after_the_end_rings_nothing() {
        let mut calls = rung();
        calls.hang_up(T0 + 1_000).unwrap();
        assert_eq!(
            calls.offer("c1", "peer", "d1", true, "me", T0 + 9_000),
            OfferStep::Ignore
        );
        assert!(calls.active().is_none());
        // Past the memory, the id is a new call again.
        assert_eq!(
            calls.offer(
                "c1",
                "peer",
                "d1",
                true,
                "me",
                T0 + 1_000 + timing::ENDED_MEMORY_MS
            ),
            OfferStep::Ring
        );
    }

    /// A second caller is refused and the call in progress is untouched (2026-10-01).
    ///
    /// Mutation: busy without remembering the refused id.
    #[test]
    fn a_second_callers_offer_is_busy_and_leaves_the_call_alone() {
        let mut calls = rung();
        assert_eq!(
            calls.offer("c2", "other", "o1", true, "me", T0),
            OfferStep::Busy
        );
        assert_eq!(calls.active().unwrap().call_id, "c1");
        assert!(calls.recently_ended("c2", T0));
    }

    /// Glare: the greater account id keeps its call; the other gives its own up and rings for
    /// theirs, and the dropped call's late signals are not taken for anything.
    ///
    /// Mutations: keep the replaced call; replace without remembering it.
    #[test]
    fn glare_keeps_one_call_of_the_two() {
        let mut calls = Calls::new();
        calls.dial("mine", "a", T0);
        assert_eq!(
            calls.offer("theirs", "a", "d1", true, "b", T0),
            OfferStep::KeepOurs
        );
        assert_eq!(calls.active().unwrap().call_id, "mine");

        let mut calls = Calls::new();
        calls.dial("mine", "b", T0);
        assert_eq!(
            calls.offer("theirs", "b", "d1", true, "a", T0),
            OfferStep::ReplaceOutgoing {
                replaced: "mine".into()
            }
        );
        let call = calls.active().unwrap();
        assert_eq!(call.call_id, "theirs");
        assert_eq!(call.direction, Direction::Incoming);
        assert!(calls.recently_ended("mine", T0));
    }

    /// An offer after the answer finishes it; one under way renegotiates; one without an SDP for
    /// the call in progress ends it rather than wait on it.
    ///
    /// Mutations: resume without holding the offer; fail without ending.
    #[test]
    fn an_offer_for_the_call_in_progress_holds_resumes_or_renegotiates() {
        let mut calls = Calls::new();
        calls.push("c1", "peer", T0);
        assert_eq!(calls.accept(T0 + 2_000), AcceptStep::WaitForOffer);
        assert_eq!(
            calls.offer("c1", "peer", "d1", true, "me", T0 + 30_000),
            OfferStep::ResumeAnswer
        );
        assert!(calls.active().unwrap().holds_offer);
        calls.answered(T0 + 31_000);
        assert_eq!(
            calls.offer("c1", "peer", "d1", true, "me", T0 + 60_000),
            OfferStep::Renegotiate
        );

        let OfferStep::Fail(ended) = calls.offer("c1", "peer", "d1", false, "me", T0 + 61_000)
        else {
            panic!("an unusable offer for the call in progress ends it");
        };
        assert_eq!(ended.reason, EndReason::Local);
        assert_eq!(ended.history, Some(HistoryStatus::Completed));
        assert!(calls.active().is_none());
    }

    // ── Answering ───────────────────────────────────────────────────────────

    /// Answering with the offer here applies it; without it, waits for it, bounded (2026-08-05).
    ///
    /// Mutations: wait while an offer is held; no offer-wait deadline; the ring timer kept.
    #[test]
    fn answering_applies_the_held_offer_or_waits_for_it() {
        let mut calls = rung();
        assert_eq!(calls.accept(T0 + 1_000), AcceptStep::ApplyOffer);
        assert_eq!(phase(&calls), Some(Phase::Connecting));
        assert_eq!(calls.next_deadline(), None);
        assert_eq!(calls.accept(T0 + 1_000), AcceptStep::Ignore);

        let mut calls = Calls::new();
        calls.push("c1", "peer", T0);
        assert_eq!(calls.accept(T0 + 1_000), AcceptStep::WaitForOffer);
        assert!(calls.active().unwrap().awaiting_offer_after_answer);
        assert_eq!(
            calls.next_deadline(),
            Some(T0 + 1_000 + timing::OFFER_WAIT_MS)
        );

        assert_eq!(dialled(&["d1"]).accept(T0), AcceptStep::Ignore);
    }

    /// The answer stamps the start of the call once; a renegotiation does not move it.
    ///
    /// Mutation: `answered` overwrites `answered_at_ms`.
    #[test]
    fn a_call_is_answered_once() {
        let mut calls = rung();
        calls.accept(T0 + 1_000);
        calls.answered(T0 + 2_000);
        let call = calls.active().unwrap();
        assert_eq!(call.phase, Phase::Active);
        assert_eq!(call.answered_at_ms, Some(T0 + 2_000));
        assert!(!call.holds_offer);
        calls.answered(T0 + 120_000);
        assert_eq!(calls.active().unwrap().answered_at_ms, Some(T0 + 2_000));
        let ended = calls.hang_up(T0 + 122_000).unwrap().ended;
        assert_eq!(ended.duration_seconds, 120);
    }

    /// The first answer picks the device and releases the rest; a later one is released.
    ///
    /// Mutations: keep the offer list after the answer; choose the late device.
    #[test]
    fn the_first_answer_picks_the_device() {
        let mut calls = dialled(&["d1", "d2", "d3"]);
        assert!(calls.ringing());
        assert_eq!(phase(&calls), Some(Phase::Ringing));
        assert!(!calls.ringing());
        assert_eq!(
            calls.answer_from("c1", "d2"),
            Some(AnswerDisposition::Accept {
                device: "d2".into(),
                release: ids(&["d1", "d3"])
            })
        );
        assert_eq!(
            calls.answer_from("c1", "d3"),
            Some(AnswerDisposition::ReleaseLate {
                device: "d3".into()
            })
        );
        assert_eq!(calls.active().unwrap().chosen.as_deref(), Some("d2"));
        assert_eq!(calls.answer_from("other", "d2"), None);
        assert_eq!(rung().answer_from("c1", "d1"), None);
    }

    // ── Ending ──────────────────────────────────────────────────────────────

    /// Ours: declined while ringing, normal after; to the call's devices, both ways.
    ///
    /// Mutations: decline after the answer; route it as received.
    #[test]
    fn our_hangup_declines_a_ringing_call_and_goes_both_ways() {
        let mut calls = rung();
        let hangup = calls.hang_up(T0 + 5_000).unwrap();
        assert_eq!(hangup.reason, HangupReason::Declined);
        assert_eq!(hangup.targets, ids(&["d1"]));
        assert_eq!(
            hangup.route,
            HangupRoute {
                e2ee: true,
                stream: true
            }
        );
        assert_eq!(hangup.ended.history, Some(HistoryStatus::Declined));
        assert_eq!(hangup.ended.outcome, Outcome::Declined);
        assert!(calls.active().is_none());
        assert!(calls.hang_up(T0 + 6_000).is_none());

        let mut calls = dialled(&["d1", "d2"]);
        let hangup = calls.hang_up(T0 + 5_000).unwrap();
        assert_eq!(hangup.reason, HangupReason::Normal);
        assert_eq!(hangup.targets, ids(&["d1", "d2"]));
        assert_eq!(hangup.ended.history, Some(HistoryStatus::Missed));
    }

    /// Theirs: a decline ends it and releases the others, repeated to the stream only (AC92380B);
    /// busy on one device takes only that one out; taken elsewhere ends it and goes nowhere.
    ///
    /// Mutations: drop the busy device's list update; route the received hangup end to end.
    #[test]
    fn a_hangup_from_their_device_ends_or_drops_as_the_rule_says() {
        let mut calls = dialled(&["d1", "d2"]);
        assert_eq!(
            calls.hangup_from("c1", "d1", HangupReason::Busy, T0),
            RemoteHangupStep::DropDevice {
                remaining: ids(&["d2"])
            }
        );
        assert_eq!(calls.active().unwrap().offered, ids(&["d2"]));
        let RemoteHangupStep::End {
            release,
            reason,
            route,
            ended,
        } = calls.hangup_from("c1", "d2", HangupReason::Declined, T0 + 1_000)
        else {
            panic!("a decline ends the call");
        };
        assert!(release.is_empty());
        assert_eq!(reason, HangupReason::Declined);
        assert_eq!(
            route,
            HangupRoute {
                e2ee: false,
                stream: true
            }
        );
        assert_eq!(ended.outcome, Outcome::Declined);

        let mut calls = rung();
        let RemoteHangupStep::End { route, ended, .. } =
            calls.hangup_from("c1", "d1", HangupReason::AcceptedElsewhere, T0)
        else {
            panic!("taken elsewhere ends the call");
        };
        assert_eq!(
            route,
            HangupRoute {
                e2ee: false,
                stream: false
            }
        );
        assert_eq!(ended.history, None);
    }

    /// A hangup for another call, or from a device the call does not talk to, changes nothing.
    #[test]
    fn a_hangup_not_for_this_call_is_ignored() {
        let mut calls = rung();
        assert_eq!(
            calls.hangup_from("c2", "d1", HangupReason::Normal, T0),
            RemoteHangupStep::Ignore
        );
        assert_eq!(
            calls.hangup_from("c1", "d9", HangupReason::Normal, T0),
            RemoteHangupStep::Ignore
        );
        assert!(calls.active().is_some());
    }

    /// A rate limit drops one signal; any other server error ends the call.
    ///
    /// Mutation: end on a rate limit.
    #[test]
    fn a_rate_limit_does_not_end_the_call() {
        let mut calls = dialled(&["d1"]);
        assert_eq!(calls.server_error(SignalError::RateLimited, T0), None);
        assert!(calls.active().is_some());
        let ended = calls.server_error(SignalError::CalleeBusy, T0).unwrap();
        assert_eq!(ended.outcome, Outcome::Busy);
        assert_eq!(ended.history, Some(HistoryStatus::Failed));

        let mut calls = dialled(&["d1"]);
        let ended = calls.ended_by_server(HangupReason::Timeout, T0).unwrap();
        assert_eq!(ended.outcome, Outcome::NoAnswer);
        assert!(calls.recently_ended("c1", T0));
    }

    // ── Time ────────────────────────────────────────────────────────────────

    /// An incoming call nobody answers ends at 90 s with our TIMEOUT; an answered one does not.
    ///
    /// Mutations: no ring deadline; fire it before it is due; fire it after the answer.
    #[test]
    fn an_unanswered_call_times_out() {
        let mut calls = rung();
        let due = T0 + timing::UNANSWERED_MS;
        assert_eq!(calls.next_deadline(), Some(due));
        assert_eq!(calls.tick(due - 1), None);
        let Some(Due::Unanswered(hangup)) = calls.tick(due) else {
            panic!("the ring deadline ends the call");
        };
        assert_eq!(hangup.reason, HangupReason::Timeout);
        assert_eq!(hangup.targets, ids(&["d1"]));
        assert_eq!(hangup.ended.outcome, Outcome::NoAnswer);
        assert_eq!(hangup.ended.history, Some(HistoryStatus::Missed));
        assert!(calls.active().is_none());

        let mut calls = rung();
        calls.accept(T0 + 1_000);
        assert_eq!(calls.tick(due), None);
        assert!(calls.active().is_some());
    }

    /// An answer that never gets its offer fails at 45 s; the offer arriving first stops it.
    ///
    /// Mutations: no offer deadline; keep it after the offer is applied.
    #[test]
    fn an_answer_waits_for_its_offer_45_seconds() {
        let mut calls = Calls::new();
        calls.push("c1", "peer", T0);
        calls.accept(T0);
        let due = T0 + timing::OFFER_WAIT_MS;
        assert_eq!(calls.tick(due - 1), None);
        let Some(Due::NoOffer(ended)) = calls.tick(due) else {
            panic!("the offer wait ends the call");
        };
        assert_eq!(ended.reason, EndReason::Local);
        assert_eq!(ended.history, Some(HistoryStatus::Failed));

        let mut calls = Calls::new();
        calls.push("c1", "peer", T0);
        calls.accept(T0);
        calls.offer("c1", "peer", "d1", true, "me", T0 + 10_000);
        calls.answered(T0 + 11_000);
        assert_eq!(calls.next_deadline(), None);
        assert_eq!(calls.tick(due), None);
    }

    /// The caller restarts ICE after the grace, at most three times, and the budget starts over
    /// when media comes back; the callee waits; nothing before media.
    ///
    /// Mutations: restart on the callee; skip the grace; no cap; no reset on reconnect.
    #[test]
    fn the_caller_restarts_ice_after_the_grace_three_times() {
        let mut calls = dialled(&["d1"]);
        assert_eq!(calls.media_quality(true, T0), IceStep::Skip);
        calls.answer_from("c1", "d1");
        calls.answered(T0);
        calls.media_connected();
        let mut now = T0;
        for _ in 0..timing::MAX_ICE_RESTARTS {
            assert_eq!(calls.media_quality(true, now), IceStep::Schedule);
            assert_eq!(calls.media_quality(true, now), IceStep::Skip);
            assert_eq!(calls.tick(now + timing::ICE_RESTART_GRACE_MS - 1), None);
            now += timing::ICE_RESTART_GRACE_MS;
            assert_eq!(calls.tick(now), Some(Due::RestartIce));
            assert_eq!(calls.media_quality(true, now), IceStep::Skip);
            calls.ice_restart_sent();
        }
        assert_eq!(calls.media_quality(true, now), IceStep::Skip);
        calls.media_connected();
        assert_eq!(calls.media_quality(true, now), IceStep::Schedule);

        // Back before the grace: nothing to restart.
        calls.media_quality(false, now + 1);
        assert_eq!(calls.tick(now + timing::ICE_RESTART_GRACE_MS), None);

        let mut calls = rung();
        calls.accept(T0);
        calls.answered(T0);
        calls.media_connected();
        assert_eq!(calls.media_quality(true, T0), IceStep::CalleeWaits);
        assert_eq!(calls.next_deadline(), None);
    }

    /// The stream reopens three times before media and five after; past that a call bounded by
    /// media or an offer wait goes on, and one bounded by nothing ends (3C86C064).
    ///
    /// Mutations: count retries on the wrong budget; end a call media bounds.
    #[test]
    fn a_closed_stream_reopens_within_its_budget_then_ends_only_an_unbounded_call() {
        let mut calls = dialled(&["d1"]);
        for _ in 0..timing::MAX_STREAM_RETRIES {
            assert_eq!(calls.stream_closed(T0), Some(StreamStep::Reconnect));
        }
        let Some(StreamStep::End(ended)) = calls.stream_closed(T0) else {
            panic!("nothing bounds a call before media without its stream");
        };
        assert_eq!(ended.reason, EndReason::Local);

        let mut calls = dialled(&["d1"]);
        calls.stream_closed(T0);
        calls.answer_from("c1", "d1");
        calls.answered(T0);
        calls.media_connected();
        for _ in 0..timing::MAX_POST_MEDIA_RECONNECTS {
            assert_eq!(calls.stream_closed(T0), Some(StreamStep::Reconnect));
        }
        assert_eq!(calls.stream_closed(T0), Some(StreamStep::KeepOnMessagePath));
        assert!(calls.active().is_some());

        let mut calls = Calls::new();
        calls.push("c1", "peer", T0);
        calls.accept(T0);
        for _ in 0..timing::MAX_STREAM_RETRIES {
            calls.stream_closed(T0);
        }
        assert_eq!(calls.stream_closed(T0), Some(StreamStep::KeepOnMessagePath));
        assert_eq!(Calls::new().stream_closed(T0), None);
    }

    /// A failure after the answer is a completed call; before it, a failed one.
    #[test]
    fn a_failure_is_completed_after_the_answer_and_failed_before() {
        let mut calls = dialled(&["d1"]);
        assert_eq!(calls.fail(T0).unwrap().history, Some(HistoryStatus::Failed));
        let mut calls = dialled(&["d1"]);
        calls.answer_from("c1", "d1");
        calls.answered(T0);
        let ended = calls.fail(T0 + 3_000).unwrap();
        assert_eq!(ended.history, Some(HistoryStatus::Completed));
        assert_eq!(ended.duration_seconds, 3);
        assert_eq!(Calls::new().fail(T0), None);
    }
}
