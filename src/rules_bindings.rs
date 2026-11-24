//! `construct-rules` over UniFFI, in this library's one component (as `local_store_bindings`).
//! Field-for-field conversions only; the rule decides everything (`rule_state`,
//! `construct-docs/decisions/client-rules-shared-in-rust.md`).

use std::sync::Mutex;

use crate::device_link_qr;
use crate::rule_state::{
    self, call_machine, calls, device_join, device_refusal, device_set, fanout_retry, intake,
    mailbox_gap, names, read_sync, send_failure, stream_cursor, transport_route, veil_fronts,
};
use crate::uniffi_bindings::CryptoError;

/// What the notice says: messages sent from `from_ms` to `until_ms` (Unix ms) may not have
/// arrived; `until_ms` is `None` when the mailbox held nothing to resume from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxGapInterval {
    pub from_ms: i64,
    pub until_ms: Option<i64>,
}

/// The state of the "messages may not have arrived" notice (`construct_rules::mailbox_gap`).
pub struct MailboxGapState {
    notice: Mutex<mailbox_gap::Notice>,
}

impl Default for MailboxGapState {
    fn default() -> Self {
        Self::new()
    }
}

impl MailboxGapState {
    pub fn new() -> Self {
        Self {
            notice: Mutex::new(mailbox_gap::Notice::default()),
        }
    }

    pub fn from_bytes(kept: Vec<u8>) -> Self {
        Self {
            notice: Mutex::new(rule_state::decode_mailbox_gap(&kept)),
        }
    }

    fn notice(&self) -> std::sync::MutexGuard<'_, mailbox_gap::Notice> {
        self.notice.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn record(&self, after_cursor: String, resumes_at: String) -> bool {
        self.notice().record(mailbox_gap::Report {
            after_cursor,
            resumes_at,
        })
    }

    pub fn dismiss(&self) {
        self.notice().close();
    }

    pub fn interval(&self) -> Option<MailboxGapInterval> {
        self.notice().interval().map(|i| MailboxGapInterval {
            from_ms: i.from_ms,
            until_ms: i.until_ms,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        rule_state::encode_mailbox_gap(&self.notice()).map_err(|e| {
            CryptoError::SerializationFailed {
                detail: format!("mailbox-gap notice: {e:?}"),
            }
        })
    }
}

// ── Names ─────────────────────────────────────────────────────────────────────

pub fn generated_name(user_id: String) -> String {
    names::generated(&user_id)
}

pub fn is_generated_name(name: String, user_id: String) -> bool {
    names::is_generated(&name, &user_id)
}

pub fn shown_name(
    alias: Option<String>,
    display_name: String,
    username: String,
    user_id: String,
) -> String {
    names::shown(alias.as_deref(), &display_name, &username, &user_id)
}

// ── Device refusal ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRefusalKind {
    Unspecified,
    Removed,
    NotFound,
}

impl From<device_refusal::Refusal> for DeviceRefusalKind {
    fn from(r: device_refusal::Refusal) -> Self {
        match r {
            device_refusal::Refusal::Unspecified => Self::Unspecified,
            device_refusal::Refusal::Removed => Self::Removed,
            device_refusal::Refusal::NotFound => Self::NotFound,
        }
    }
}

impl From<DeviceRefusalKind> for device_refusal::Refusal {
    fn from(r: DeviceRefusalKind) -> Self {
        match r {
            DeviceRefusalKind::Unspecified => Self::Unspecified,
            DeviceRefusalKind::Removed => Self::Removed,
            DeviceRefusalKind::NotFound => Self::NotFound,
        }
    }
}

pub fn device_refusal_of(status_code: u32, trailer: Option<String>) -> DeviceRefusalKind {
    device_refusal::refusal(status_code, trailer.as_deref()).into()
}

pub fn refusal_erases_device(refusal: DeviceRefusalKind, over_direct_tls: bool) -> bool {
    device_refusal::erases_device(refusal.into(), over_direct_tls)
}

// ── Device set ────────────────────────────────────────────────────────────────

pub fn device_set_named(answers: Vec<Vec<String>>) -> Vec<String> {
    device_set::named(&answers).into_iter().collect()
}

pub fn device_set_should_ask(named: Vec<String>, already_asked: Option<Vec<String>>) -> bool {
    let named = named.into_iter().collect();
    let asked = already_asked.map(|a| a.into_iter().collect());
    device_set::should_ask(&named, asked.as_ref())
}

// ── Send failure ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailureKind {
    NoAnswer,
    Status { code: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageAfterSendFailure {
    Queued,
    Failed,
}

impl From<SendFailureKind> for send_failure::SendError {
    fn from(failure: SendFailureKind) -> Self {
        match failure {
            SendFailureKind::NoAnswer => Self::NoAnswer,
            SendFailureKind::Status { code } => Self::Status(code),
        }
    }
}

pub fn after_send_failure(failure: SendFailureKind) -> MessageAfterSendFailure {
    match send_failure::after(failure.into()) {
        send_failure::AfterSend::Queued => MessageAfterSendFailure::Queued,
        send_failure::AfterSend::Failed => MessageAfterSendFailure::Failed,
    }
}

// ── Stream cursor ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCursorOutcome {
    Durable,
    Deferred,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCursorHold {
    Pending,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCursorBlocker {
    pub message_id: String,
    pub hold: StreamCursorHold,
    pub tracked_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCursorSkip {
    pub cursor: String,
    pub held: u32,
    pub head: Option<StreamCursorBlocker>,
}

impl From<stream_cursor::Blocker> for StreamCursorBlocker {
    fn from(b: stream_cursor::Blocker) -> Self {
        Self {
            message_id: b.message_id,
            hold: match b.hold {
                stream_cursor::Hold::Pending => StreamCursorHold::Pending,
                stream_cursor::Hold::Deferred => StreamCursorHold::Deferred,
            },
            tracked_at_ms: b.tracked_at_ms,
        }
    }
}

/// The stream resume cursor of one connection (`construct_rules::stream_cursor`). Not kept: the
/// cursor it returns is what a client stores.
pub struct StreamCursorState {
    tracker: Mutex<stream_cursor::Tracker>,
}

impl Default for StreamCursorState {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCursorState {
    pub fn new() -> Self {
        Self {
            tracker: Mutex::new(stream_cursor::Tracker::new()),
        }
    }

    fn tracker(&self) -> std::sync::MutexGuard<'_, stream_cursor::Tracker> {
        self.tracker.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn reset(&self) {
        self.tracker().reset();
    }

    pub fn track(&self, message_id: String, cursor: String, now_ms: i64) {
        self.tracker().track(&message_id, &cursor, now_ms);
    }

    pub fn track_resolved(&self, cursor: String, now_ms: i64) -> Option<String> {
        self.tracker().track_resolved(&cursor, now_ms)
    }

    pub fn report(&self, message_id: String, outcome: StreamCursorOutcome) -> Option<String> {
        let outcome = match outcome {
            StreamCursorOutcome::Durable => stream_cursor::Outcome::Durable,
            StreamCursorOutcome::Deferred => stream_cursor::Outcome::Deferred,
            StreamCursorOutcome::Skip => stream_cursor::Outcome::Skip,
        };
        self.tracker().report(&message_id, outcome)
    }

    pub fn resolve(&self, message_id: String) -> Option<String> {
        self.tracker().resolve(&message_id)
    }

    pub fn skip_held_backlog(&self) -> Option<StreamCursorSkip> {
        self.tracker()
            .skip_held_backlog()
            .map(|s| StreamCursorSkip {
                cursor: s.cursor,
                held: s.held,
                head: s.head.map(Into::into),
            })
    }

    pub fn head_blocker(&self) -> Option<StreamCursorBlocker> {
        self.tracker().head_blocker().map(Into::into)
    }

    pub fn in_flight(&self) -> u32 {
        u32::try_from(self.tracker().in_flight()).unwrap_or(u32::MAX)
    }
}

fn rule_bytes<E: std::fmt::Debug>(
    what: &str,
    r: Result<Vec<u8>, E>,
) -> Result<Vec<u8>, CryptoError> {
    r.map_err(|e| CryptoError::SerializationFailed {
        detail: format!("{what}: {e:?}"),
    })
}

// ── Fan-out retry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedCopy {
    pub key: String,
    pub base_message_id: String,
    pub recipient_user_id: String,
    pub sender_user_id: String,
    pub owed_device_ids: Vec<String>,
    pub attempts: u32,
    pub next_attempt_at_ms: i64,
    pub created_at_ms: i64,
}

impl From<fanout_retry::Entry> for OwedCopy {
    fn from(e: fanout_retry::Entry) -> Self {
        Self {
            key: e.key(),
            base_message_id: e.base_message_id,
            recipient_user_id: e.recipient_user_id,
            sender_user_id: e.sender_user_id,
            owed_device_ids: e.owed_device_ids,
            attempts: e.attempts,
            next_attempt_at_ms: e.next_attempt_at_ms,
            created_at_ms: e.created_at_ms,
        }
    }
}

pub fn fanout_retry_max_attempts() -> u32 {
    fanout_retry::MAX_ATTEMPTS
}

pub fn fanout_retry_base_backoff_ms() -> i64 {
    fanout_retry::BASE_BACKOFF_MS
}

/// The owed copies (`construct_rules::fanout_retry`).
pub struct FanoutRetryState {
    queue: Mutex<fanout_retry::Queue>,
}

impl Default for FanoutRetryState {
    fn default() -> Self {
        Self::new()
    }
}

impl FanoutRetryState {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(fanout_retry::Queue::default()),
        }
    }

    pub fn from_bytes(kept: Vec<u8>) -> Self {
        Self {
            queue: Mutex::new(rule_state::decode_fanout_retry(&kept)),
        }
    }

    /// `key` is derived, not read: an entry is named by its message and recipient.
    pub fn restore(entries: Vec<OwedCopy>) -> Self {
        let entries = entries
            .into_iter()
            .map(|c| fanout_retry::Entry {
                base_message_id: c.base_message_id,
                recipient_user_id: c.recipient_user_id,
                sender_user_id: c.sender_user_id,
                owed_device_ids: c.owed_device_ids,
                attempts: c.attempts,
                next_attempt_at_ms: c.next_attempt_at_ms,
                created_at_ms: c.created_at_ms,
            })
            .collect();
        Self {
            queue: Mutex::new(fanout_retry::Queue { entries }),
        }
    }

    fn queue(&self) -> std::sync::MutexGuard<'_, fanout_retry::Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn enqueue(
        &self,
        base_message_id: String,
        recipient_user_id: String,
        sender_user_id: String,
        owed: Vec<String>,
        now_ms: i64,
    ) {
        self.queue().enqueue(
            &base_message_id,
            &recipient_user_id,
            &sender_user_id,
            owed,
            now_ms,
        );
    }

    pub fn record_attempt(&self, key: String, now_ms: i64) -> Option<OwedCopy> {
        self.queue().record_attempt(&key, now_ms).map(Into::into)
    }

    pub fn replace_owed(&self, key: String, owed: Vec<String>) {
        self.queue().replace_owed(&key, owed);
    }

    pub fn remove(&self, key: String) {
        self.queue().remove(&key);
    }

    pub fn remove_all(&self) {
        self.queue().remove_all();
    }

    pub fn due(&self, now_ms: i64) -> Vec<OwedCopy> {
        self.queue()
            .due(now_ms)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    pub fn next_due(&self, now_ms: i64) -> Option<i64> {
        self.queue().next_due(now_ms)
    }

    pub fn all(&self) -> Vec<OwedCopy> {
        self.queue()
            .entries
            .clone()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        rule_bytes(
            "fan-out retry queue",
            rule_state::encode_fanout_retry(&self.queue()),
        )
    }
}

// ── Read sync ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadBoundary {
    pub sent_at_ms: u64,
    pub message_id: String,
}

impl From<ReadBoundary> for read_sync::Boundary {
    fn from(b: ReadBoundary) -> Self {
        read_sync::Boundary::new(b.sent_at_ms, &b.message_id)
    }
}

impl From<read_sync::Boundary> for ReadBoundary {
    fn from(b: read_sync::Boundary) -> Self {
        Self {
            sent_at_ms: b.sent_at_ms,
            message_id: b.message_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadIncoming {
    pub message_id: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerBoundary {
    pub partner: String,
    pub boundary: ReadBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMarkerOutcome {
    Apply,
    Ignore,
    Drop,
}

impl From<read_sync::Outcome> for ReadMarkerOutcome {
    fn from(o: read_sync::Outcome) -> Self {
        match o {
            read_sync::Outcome::Apply => Self::Apply,
            read_sync::Outcome::Ignore => Self::Ignore,
            read_sync::Outcome::Drop => Self::Drop,
        }
    }
}

pub fn read_boundary_is_later(a: ReadBoundary, b: ReadBoundary) -> bool {
    read_sync::is_later(&a.into(), &b.into())
}

pub fn read_boundary_covers(boundary: ReadBoundary, message: ReadBoundary) -> bool {
    read_sync::covers(&boundary.into(), &message.into())
}

pub fn read_unread_left(unread: u32, incoming: Vec<ReadIncoming>, boundary: ReadBoundary) -> u32 {
    let incoming: Vec<read_sync::Incoming> = incoming
        .into_iter()
        .map(|m| read_sync::Incoming {
            message_id: m.message_id,
            at_ms: m.at_ms,
        })
        .collect();
    read_sync::unread_left(unread, &incoming, &boundary.into())
}

/// Read sync's kept state (`construct_rules::read_sync::State`).
pub struct ReadMarkerState {
    state: Mutex<read_sync::State>,
}

impl Default for ReadMarkerState {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadMarkerState {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(read_sync::State::default()),
        }
    }

    pub fn from_bytes(kept: Vec<u8>) -> Self {
        Self {
            state: Mutex::new(rule_state::decode_read_sync(&kept)),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, read_sync::State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn boundary(&self, partner: String) -> Option<ReadBoundary> {
        self.state().boundary(&partner).cloned().map(Into::into)
    }

    pub fn advance(&self, partner: String, to: ReadBoundary) -> bool {
        self.state().advance(&partner, to.into())
    }

    pub fn covers(&self, partner: String, message: ReadBoundary) -> bool {
        self.state().covers(&partner, &message.into())
    }

    pub fn note_incoming(&self, partner: String, message: ReadBoundary) {
        self.state().note_incoming(&partner, message.into());
    }

    pub fn newest_incoming(&self, partner: String) -> Option<ReadBoundary> {
        self.state()
            .newest_incoming(&partner)
            .cloned()
            .map(Into::into)
    }

    pub fn note_read(&self, partner: String, boundary: ReadBoundary) -> bool {
        self.state().note_read(&partner, boundary.into())
    }

    pub fn apply_marker(
        &self,
        partner: String,
        marker: ReadBoundary,
        from_own_account: bool,
        own_account: String,
    ) -> ReadMarkerOutcome {
        self.state()
            .apply_marker(&partner, marker.into(), from_own_account, &own_account)
            .into()
    }

    pub fn take_pending(&self) -> Vec<PartnerBoundary> {
        self.state()
            .take_pending()
            .into_iter()
            .map(|(partner, b)| PartnerBoundary {
                partner,
                boundary: b.into(),
            })
            .collect()
    }

    pub fn return_pending(&self, unsent: Vec<PartnerBoundary>) {
        self.state().return_pending(
            unsent
                .into_iter()
                .map(|p| (p.partner.to_lowercase(), p.boundary.into()))
                .collect(),
        );
    }

    pub fn has_pending(&self) -> bool {
        !self.state().pending.is_empty()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        rule_bytes("read sync", rule_state::encode_read_sync(&self.state()))
    }
}

// ── Intake ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakePublished {
    pub account_id: String,
    pub epoch: u64,
    pub key_id: String,
}

impl From<IntakePublished> for intake::Published {
    fn from(p: IntakePublished) -> Self {
        Self {
            account_id: p.account_id,
            epoch: p.epoch,
            key_id: p.key_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeOwnKeyNext {
    Use,
    Promote,
    Mint { above: u32 },
    Wait,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakeCard {
    pub contact: String,
    pub delay_ms: u64,
}

pub fn intake_window(current: u64) -> Vec<u64> {
    intake::window(current)
}

pub fn intake_recheck_ms() -> u64 {
    intake::RECHECK_MS
}

pub fn intake_key_id(key: Vec<u8>) -> String {
    intake::key_id(&key)
}

pub fn intake_should_publish(last: Option<IntakePublished>, due: IntakePublished) -> bool {
    intake::should_publish(last.map(Into::into).as_ref(), &due.into())
}

pub fn intake_server_holds(
    last: Option<IntakePublished>,
    account_id: String,
    key_id: String,
    current: u64,
) -> bool {
    intake::server_holds(last.map(Into::into).as_ref(), &account_id, &key_id, current)
}

pub fn intake_published_to_bytes(published: IntakePublished) -> Result<Vec<u8>, CryptoError> {
    rule_bytes(
        "intake publish marker",
        rule_state::encode_intake_published(&published.into()),
    )
}

pub fn intake_published_from_bytes(kept: Vec<u8>) -> Option<IntakePublished> {
    rule_state::decode_intake_published(&kept).map(|p| IntakePublished {
        account_id: p.account_id,
        epoch: p.epoch,
        key_id: p.key_id,
    })
}

pub fn intake_refused_as_stale(current: u32, ours: u32) -> bool {
    intake::refused_as_stale(current, ours)
}

pub fn intake_own_key(
    held_generation: Option<u32>,
    server_generation: u32,
    server_has_live_tags: bool,
) -> IntakeOwnKeyNext {
    match intake::own_key(held_generation, server_generation, server_has_live_tags) {
        intake::OwnKey::Use => IntakeOwnKeyNext::Use,
        intake::OwnKey::Promote => IntakeOwnKeyNext::Promote,
        intake::OwnKey::Mint { above } => IntakeOwnKeyNext::Mint { above },
        intake::OwnKey::Wait => IntakeOwnKeyNext::Wait,
    }
}

pub fn intake_mint_above(held: Option<u32>, server: Option<u32>) -> u32 {
    intake::mint_above(held, server)
}

pub fn intake_re_mint_above(minted: u32, current: u32, already_re_minted: bool) -> Option<u32> {
    intake::re_mint_above(minted, current, already_re_minted)
}

pub fn intake_card_schedule(
    contacts: Vec<String>,
    dropped: String,
    blocked: Vec<String>,
    own_account: String,
    seed: Vec<u8>,
) -> Vec<IntakeCard> {
    intake::card_schedule(&contacts, &dropped, &blocked, &own_account, &seed)
        .into_iter()
        .map(|(contact, delay_ms)| IntakeCard { contact, delay_ms })
        .collect()
}

pub fn intake_verdict_suspends_key(verdict: i32) -> bool {
    intake::verdict_suspends_key(verdict)
}

pub fn intake_key_record_encode(state: crate::intake::IntakeKeyState) -> Vec<u8> {
    intake::encode_key_record(state.generation, &state.key)
}

pub fn intake_key_record_decode(kept: Vec<u8>) -> Option<crate::intake::IntakeKeyState> {
    intake::decode_key_record(&kept)
        .map(|(generation, key)| crate::intake::IntakeKeyState { generation, key })
}

// ── Calls ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDirection {
    Incoming,
    Outgoing,
}

impl From<CallDirection> for calls::Direction {
    fn from(d: CallDirection) -> Self {
        match d {
            CallDirection::Incoming => Self::Incoming,
            CallDirection::Outgoing => Self::Outgoing,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallHangupReason {
    Unspecified,
    Normal,
    Busy,
    Declined,
    Timeout,
    ConnectionFailed,
    AcceptedElsewhere,
}

impl From<CallHangupReason> for calls::HangupReason {
    fn from(r: CallHangupReason) -> Self {
        match r {
            CallHangupReason::Unspecified => Self::Unspecified,
            CallHangupReason::Normal => Self::Normal,
            CallHangupReason::Busy => Self::Busy,
            CallHangupReason::Declined => Self::Declined,
            CallHangupReason::Timeout => Self::Timeout,
            CallHangupReason::ConnectionFailed => Self::ConnectionFailed,
            CallHangupReason::AcceptedElsewhere => Self::AcceptedElsewhere,
        }
    }
}

impl From<calls::HangupReason> for CallHangupReason {
    fn from(r: calls::HangupReason) -> Self {
        match r {
            calls::HangupReason::Unspecified => Self::Unspecified,
            calls::HangupReason::Normal => Self::Normal,
            calls::HangupReason::Busy => Self::Busy,
            calls::HangupReason::Declined => Self::Declined,
            calls::HangupReason::Timeout => Self::Timeout,
            calls::HangupReason::ConnectionFailed => Self::ConnectionFailed,
            calls::HangupReason::AcceptedElsewhere => Self::AcceptedElsewhere,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSignalError {
    Unspecified,
    CalleeOffline,
    CalleeBusy,
    RateLimited,
    Unauthorized,
    CallExpired,
}

impl From<CallSignalError> for calls::SignalError {
    fn from(e: CallSignalError) -> Self {
        match e {
            CallSignalError::Unspecified => Self::Unspecified,
            CallSignalError::CalleeOffline => Self::CalleeOffline,
            CallSignalError::CalleeBusy => Self::CalleeBusy,
            CallSignalError::RateLimited => Self::RateLimited,
            CallSignalError::Unauthorized => Self::Unauthorized,
            CallSignalError::CallExpired => Self::CallExpired,
        }
    }
}

impl From<calls::SignalError> for CallSignalError {
    fn from(e: calls::SignalError) -> Self {
        match e {
            calls::SignalError::Unspecified => Self::Unspecified,
            calls::SignalError::CalleeOffline => Self::CalleeOffline,
            calls::SignalError::CalleeBusy => Self::CalleeBusy,
            calls::SignalError::RateLimited => Self::RateLimited,
            calls::SignalError::Unauthorized => Self::Unauthorized,
            calls::SignalError::CallExpired => Self::CallExpired,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEndCause {
    Hangup { reason: CallHangupReason },
    ServerError { error: CallSignalError },
    Local,
}

impl From<CallEndCause> for calls::EndReason {
    fn from(c: CallEndCause) -> Self {
        match c {
            CallEndCause::Hangup { reason } => Self::Hangup(reason.into()),
            CallEndCause::ServerError { error } => Self::Error(error.into()),
            CallEndCause::Local => Self::Local,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEndOutcome {
    Ended { connected_seconds: Option<u32> },
    Declined,
    Busy,
    NoAnswer,
    Failed,
}

impl From<calls::Outcome> for CallEndOutcome {
    fn from(o: calls::Outcome) -> Self {
        match o {
            calls::Outcome::Ended { connected_seconds } => Self::Ended { connected_seconds },
            calls::Outcome::Declined => Self::Declined,
            calls::Outcome::Busy => Self::Busy,
            calls::Outcome::NoAnswer => Self::NoAnswer,
            calls::Outcome::Failed => Self::Failed,
        }
    }
}

impl From<CallEndOutcome> for calls::Outcome {
    fn from(o: CallEndOutcome) -> Self {
        match o {
            CallEndOutcome::Ended { connected_seconds } => Self::Ended { connected_seconds },
            CallEndOutcome::Declined => Self::Declined,
            CallEndOutcome::Busy => Self::Busy,
            CallEndOutcome::NoAnswer => Self::NoAnswer,
            CallEndOutcome::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallHistoryStatus {
    Completed,
    Missed,
    Declined,
    Failed,
}

impl From<calls::HistoryStatus> for CallHistoryStatus {
    fn from(s: calls::HistoryStatus) -> Self {
        match s {
            calls::HistoryStatus::Completed => Self::Completed,
            calls::HistoryStatus::Missed => Self::Missed,
            calls::HistoryStatus::Declined => Self::Declined,
            calls::HistoryStatus::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallAnswerDisposition {
    Accept {
        device: String,
        release: Vec<String>,
    },
    ReleaseLate {
        device: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallHangupDisposition {
    End { release: Vec<String> },
    EndTakenElsewhere,
    DropDevice { remaining: Vec<String> },
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallGlare {
    KeepOurs,
    Yield,
}

pub fn call_hangup_reason_from_wire(value: i32) -> CallHangupReason {
    calls::HangupReason::from_wire(value).into()
}

pub fn call_hangup_reason_wire(reason: CallHangupReason) -> i32 {
    calls::HangupReason::from(reason).wire()
}

pub fn call_signal_error_from_wire(value: i32) -> CallSignalError {
    calls::SignalError::from_wire(value).into()
}

pub fn call_signal_targets(
    chosen: Option<String>,
    offered: Vec<String>,
    pinned: Option<String>,
) -> Vec<String> {
    calls::targets(chosen.as_deref(), &offered, pinned.as_deref())
}

pub fn call_offer_devices(
    planned: Vec<String>,
    with_session: Vec<String>,
    pinned: Option<String>,
) -> Vec<String> {
    calls::offer_devices(&planned, &with_session, pinned.as_deref())
}

pub fn call_admits(device: String, chosen: Option<String>) -> bool {
    calls::admits(&device, chosen.as_deref())
}

pub fn call_on_answer(
    device: String,
    chosen: Option<String>,
    offered: Vec<String>,
) -> CallAnswerDisposition {
    match calls::on_answer(&device, chosen.as_deref(), &offered) {
        calls::AnswerDisposition::Accept { device, release } => {
            CallAnswerDisposition::Accept { device, release }
        }
        calls::AnswerDisposition::ReleaseLate { device } => {
            CallAnswerDisposition::ReleaseLate { device }
        }
    }
}

pub fn call_on_hangup(
    device: String,
    reason: CallHangupReason,
    chosen: Option<String>,
    offered: Vec<String>,
) -> CallHangupDisposition {
    match calls::on_hangup(&device, reason.into(), chosen.as_deref(), &offered) {
        calls::HangupDisposition::End { release } => CallHangupDisposition::End { release },
        calls::HangupDisposition::EndTakenElsewhere => CallHangupDisposition::EndTakenElsewhere,
        calls::HangupDisposition::DropDevice { remaining } => {
            CallHangupDisposition::DropDevice { remaining }
        }
        calls::HangupDisposition::Ignore => CallHangupDisposition::Ignore,
    }
}

pub fn call_local_hangup_reason(direction: CallDirection, still_ringing: bool) -> CallHangupReason {
    calls::local_hangup_reason(direction.into(), still_ringing).into()
}

pub fn call_glare(my_user_id: String, peer_user_id: String) -> CallGlare {
    match calls::glare(&my_user_id, &peer_user_id) {
        calls::Glare::KeepOurs => CallGlare::KeepOurs,
        calls::Glare::Yield => CallGlare::Yield,
    }
}

pub fn call_end_outcome(cause: CallEndCause, connected_seconds: Option<u32>) -> CallEndOutcome {
    calls::outcome(cause.into(), connected_seconds).into()
}

pub fn call_outcome_wants_attention(outcome: CallEndOutcome) -> bool {
    calls::Outcome::from(outcome).wants_attention()
}

pub fn call_history_status(
    direction: CallDirection,
    cause: CallEndCause,
    answered: bool,
) -> Option<CallHistoryStatus> {
    calls::history_status(direction.into(), cause.into(), answered).map(Into::into)
}

pub fn call_duration_seconds(answered_at_ms: Option<i64>, ended_at_ms: i64) -> u32 {
    calls::duration_seconds(answered_at_ms, ended_at_ms)
}

/// The call this device holds when an offer arrives (`calls::HeldCall`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallHeldCall {
    pub same_call: bool,
    pub direction: CallDirection,
    pub with_offerer: bool,
    pub answered: bool,
    pub awaiting_offer_after_answer: bool,
}

impl From<CallHeldCall> for calls::HeldCall {
    fn from(h: CallHeldCall) -> Self {
        Self {
            same_call: h.same_call,
            direction: h.direction.into(),
            with_offerer: h.with_offerer,
            answered: h.answered,
            awaiting_offer_after_answer: h.awaiting_offer_after_answer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOfferAction {
    IgnoreEnded,
    ResumeAnswer,
    HoldUntilAnswered,
    Renegotiate,
    Ring,
    KeepOurs,
    ReplaceOutgoing,
    Busy,
}

impl From<calls::OfferAction> for CallOfferAction {
    fn from(a: calls::OfferAction) -> Self {
        match a {
            calls::OfferAction::IgnoreEnded => Self::IgnoreEnded,
            calls::OfferAction::ResumeAnswer => Self::ResumeAnswer,
            calls::OfferAction::HoldUntilAnswered => Self::HoldUntilAnswered,
            calls::OfferAction::Renegotiate => Self::Renegotiate,
            calls::OfferAction::Ring => Self::Ring,
            calls::OfferAction::KeepOurs => Self::KeepOurs,
            calls::OfferAction::ReplaceOutgoing => Self::ReplaceOutgoing,
            calls::OfferAction::Busy => Self::Busy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallStreamClosedAction {
    Reconnect,
    KeepOnMessagePath,
    EndCall,
}

impl From<calls::StreamClosedAction> for CallStreamClosedAction {
    fn from(a: calls::StreamClosedAction) -> Self {
        match a {
            calls::StreamClosedAction::Reconnect => Self::Reconnect,
            calls::StreamClosedAction::KeepOnMessagePath => Self::KeepOnMessagePath,
            calls::StreamClosedAction::EndCall => Self::EndCall,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallHangupSide {
    Local,
    Remote,
}

impl From<CallHangupSide> for calls::HangupSide {
    fn from(s: CallHangupSide) -> Self {
        match s {
            CallHangupSide::Local => Self::Local,
            CallHangupSide::Remote => Self::Remote,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallHangupRoute {
    pub e2ee: bool,
    pub stream: bool,
}

pub fn call_on_offer(
    recently_ended: bool,
    held: Option<CallHeldCall>,
    my_user_id: String,
    offerer_user_id: String,
) -> CallOfferAction {
    calls::on_offer(
        recently_ended,
        held.map(Into::into),
        &my_user_id,
        &offerer_user_id,
    )
    .into()
}

pub fn call_on_stream_closed(
    can_reconnect: bool,
    media_connected: bool,
    awaiting_offer_after_answer: bool,
) -> CallStreamClosedAction {
    calls::on_stream_closed(can_reconnect, media_connected, awaiting_offer_after_answer).into()
}

pub fn call_hangup_route(side: CallHangupSide, reason: CallHangupReason) -> CallHangupRoute {
    let route = calls::hangup_route(side.into(), reason.into());
    CallHangupRoute {
        e2ee: route.e2ee,
        stream: route.stream,
    }
}

// ── The call machine ──────────────────────────────────────────────────────────

impl From<calls::Direction> for CallDirection {
    fn from(d: calls::Direction) -> Self {
        match d {
            calls::Direction::Incoming => Self::Incoming,
            calls::Direction::Outgoing => Self::Outgoing,
        }
    }
}

impl From<calls::EndReason> for CallEndCause {
    fn from(r: calls::EndReason) -> Self {
        match r {
            calls::EndReason::Hangup(reason) => Self::Hangup {
                reason: reason.into(),
            },
            calls::EndReason::Error(error) => Self::ServerError {
                error: error.into(),
            },
            calls::EndReason::Local => Self::Local,
        }
    }
}

impl From<calls::HangupRoute> for CallHangupRoute {
    fn from(r: calls::HangupRoute) -> Self {
        Self {
            e2ee: r.e2ee,
            stream: r.stream,
        }
    }
}

/// The timings the call machine keeps (`call_machine::timing`), for a platform's logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallTimings {
    pub unanswered_ms: i64,
    pub offer_wait_ms: i64,
    pub ice_restart_grace_ms: i64,
    pub max_ice_restarts: u32,
    pub max_stream_retries: u32,
    pub max_post_media_reconnects: u32,
    pub ended_memory_ms: i64,
}

/// The TURN urls a call relays through; None: the call is not placed (`calls::relay_urls`).
pub fn call_relay_urls(turn_urls: Vec<String>, veil_on: bool) -> Option<Vec<String>> {
    calls::relay_urls(&turn_urls, veil_on)
}

pub fn call_timings() -> CallTimings {
    use call_machine::timing as t;
    CallTimings {
        unanswered_ms: t::UNANSWERED_MS,
        offer_wait_ms: t::OFFER_WAIT_MS,
        ice_restart_grace_ms: t::ICE_RESTART_GRACE_MS,
        max_ice_restarts: t::MAX_ICE_RESTARTS,
        max_stream_retries: t::MAX_STREAM_RETRIES,
        max_post_media_reconnects: t::MAX_POST_MEDIA_RECONNECTS,
        ended_memory_ms: t::ENDED_MEMORY_MS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMachinePhase {
    Incoming,
    Dialing,
    Ringing,
    Connecting,
    Active,
}

impl From<call_machine::Phase> for CallMachinePhase {
    fn from(p: call_machine::Phase) -> Self {
        match p {
            call_machine::Phase::Incoming => Self::Incoming,
            call_machine::Phase::Dialing => Self::Dialing,
            call_machine::Phase::Ringing => Self::Ringing,
            call_machine::Phase::Connecting => Self::Connecting,
            call_machine::Phase::Active => Self::Active,
        }
    }
}

/// The call in progress, as the machine holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSnapshot {
    pub call_id: String,
    pub peer_user_id: String,
    pub direction: CallDirection,
    pub phase: CallMachinePhase,
    pub chosen: Option<String>,
    pub offered: Vec<String>,
    /// Who a signal of ours goes to now (`Call::targets`); empty: the pinned device.
    pub targets: Vec<String>,
    pub started_at_ms: i64,
    pub answered_at_ms: Option<i64>,
    pub holds_offer: bool,
    pub awaiting_offer_after_answer: bool,
    pub media_connected: bool,
    pub reconnecting: bool,
}

impl From<&call_machine::Call> for CallSnapshot {
    fn from(c: &call_machine::Call) -> Self {
        Self {
            call_id: c.call_id.clone(),
            peer_user_id: c.peer_user_id.clone(),
            direction: c.direction.into(),
            phase: c.phase.into(),
            chosen: c.chosen.clone(),
            offered: c.offered.clone(),
            targets: c.targets(),
            started_at_ms: c.started_at_ms,
            answered_at_ms: c.answered_at_ms,
            holds_offer: c.holds_offer,
            awaiting_offer_after_answer: c.awaiting_offer_after_answer,
            media_connected: c.media_connected,
            reconnecting: c.reconnecting,
        }
    }
}

/// A call that ended: its screen and its history row (`call_machine::Ended`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEnded {
    pub call_id: String,
    pub peer_user_id: String,
    pub direction: CallDirection,
    pub cause: CallEndCause,
    pub outcome: CallEndOutcome,
    /// None: no row (taken on another of our devices).
    pub history: Option<CallHistoryStatus>,
    pub started_at_ms: i64,
    pub duration_seconds: u32,
}

impl From<call_machine::Ended> for CallEnded {
    fn from(e: call_machine::Ended) -> Self {
        Self {
            call_id: e.call_id,
            peer_user_id: e.peer_user_id,
            direction: e.direction.into(),
            cause: e.reason.into(),
            outcome: e.outcome.into(),
            history: e.history.map(Into::into),
            started_at_ms: e.started_at_ms,
            duration_seconds: e.duration_seconds,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDialAction {
    Start,
    AnswerInstead,
    Busy,
}

impl From<call_machine::DialAction> for CallDialAction {
    fn from(a: call_machine::DialAction) -> Self {
        match a {
            call_machine::DialAction::Start => Self::Start,
            call_machine::DialAction::AnswerInstead => Self::AnswerInstead,
            call_machine::DialAction::Busy => Self::Busy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPushAction {
    Begin,
    AlreadyTracking,
    DeferToGlare,
    DeclineBusy,
}

impl From<call_machine::PushAction> for CallPushAction {
    fn from(a: call_machine::PushAction) -> Self {
        match a {
            call_machine::PushAction::Begin => Self::Begin,
            call_machine::PushAction::AlreadyTracking => Self::AlreadyTracking,
            call_machine::PushAction::DeferToGlare => Self::DeferToGlare,
            call_machine::PushAction::DeclineBusy => Self::DeclineBusy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallOfferStep {
    Ignore,
    Ring,
    ReplaceOutgoing { replaced: String },
    KeepOurs,
    Busy,
    Hold,
    ResumeAnswer,
    Renegotiate,
    Fail { failure: CallFailure },
}

impl From<call_machine::OfferStep> for CallOfferStep {
    fn from(s: call_machine::OfferStep) -> Self {
        use call_machine::OfferStep as S;
        match s {
            S::Ignore => Self::Ignore,
            S::Ring => Self::Ring,
            S::ReplaceOutgoing { replaced } => Self::ReplaceOutgoing { replaced },
            S::KeepOurs => Self::KeepOurs,
            S::Busy => Self::Busy,
            S::Hold => Self::Hold,
            S::ResumeAnswer => Self::ResumeAnswer,
            S::Renegotiate => Self::Renegotiate,
            S::Fail(failure) => Self::Fail {
                failure: failure.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallAcceptStep {
    ApplyOffer,
    WaitForOffer,
    Ignore,
}

impl From<call_machine::AcceptStep> for CallAcceptStep {
    fn from(s: call_machine::AcceptStep) -> Self {
        match s {
            call_machine::AcceptStep::ApplyOffer => Self::ApplyOffer,
            call_machine::AcceptStep::WaitForOffer => Self::WaitForOffer,
            call_machine::AcceptStep::Ignore => Self::Ignore,
        }
    }
}

/// A hangup of ours (`call_machine::Hangup`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallLocalHangup {
    pub reason: CallHangupReason,
    pub targets: Vec<String>,
    pub route: CallHangupRoute,
    pub ended: CallEnded,
}

impl From<call_machine::Hangup> for CallLocalHangup {
    fn from(h: call_machine::Hangup) -> Self {
        Self {
            reason: h.reason.into(),
            targets: h.targets,
            route: h.route.into(),
            ended: h.ended.into(),
        }
    }
}

/// A failure of ours (`call_machine::Failure`): the end, and the hangup that tells the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFailure {
    pub ended: CallEnded,
    /// None: nothing goes out (their call, still ringing here).
    pub hangup: Option<CallFailureHangup>,
}

/// The hangup a failure sends (`call_machine::FailureHangup`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFailureHangup {
    pub reason: CallHangupReason,
    pub targets: Vec<String>,
    pub route: CallHangupRoute,
}

impl From<call_machine::Failure> for CallFailure {
    fn from(f: call_machine::Failure) -> Self {
        Self {
            ended: f.ended.into(),
            hangup: f.hangup.map(|h| CallFailureHangup {
                reason: h.reason.into(),
                targets: h.targets,
                route: h.route.into(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallRemoteHangupStep {
    Ignore,
    DropDevice {
        remaining: Vec<String>,
    },
    End {
        release: Vec<String>,
        reason: CallHangupReason,
        route: CallHangupRoute,
        ended: CallEnded,
    },
}

impl From<call_machine::RemoteHangupStep> for CallRemoteHangupStep {
    fn from(s: call_machine::RemoteHangupStep) -> Self {
        use call_machine::RemoteHangupStep as S;
        match s {
            S::Ignore => Self::Ignore,
            S::DropDevice { remaining } => Self::DropDevice { remaining },
            S::End {
                release,
                reason,
                route,
                ended,
            } => Self::End {
                release,
                reason: reason.into(),
                route: route.into(),
                ended: ended.into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallStreamStep {
    Reconnect,
    KeepOnMessagePath,
    End { failure: CallFailure },
}

impl From<call_machine::StreamStep> for CallStreamStep {
    fn from(s: call_machine::StreamStep) -> Self {
        match s {
            call_machine::StreamStep::Reconnect => Self::Reconnect,
            call_machine::StreamStep::KeepOnMessagePath => Self::KeepOnMessagePath,
            call_machine::StreamStep::End(failure) => Self::End {
                failure: failure.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallIceStep {
    Schedule,
    CalleeWaits,
    Skip,
}

impl From<call_machine::IceStep> for CallIceStep {
    fn from(s: call_machine::IceStep) -> Self {
        match s {
            call_machine::IceStep::Schedule => Self::Schedule,
            call_machine::IceStep::CalleeWaits => Self::CalleeWaits,
            call_machine::IceStep::Skip => Self::Skip,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallDue {
    Unanswered { hangup: CallLocalHangup },
    NoOffer { failure: CallFailure },
    RestartIce,
}

impl From<call_machine::Due> for CallDue {
    fn from(d: call_machine::Due) -> Self {
        match d {
            call_machine::Due::Unanswered(hangup) => Self::Unanswered {
                hangup: hangup.into(),
            },
            call_machine::Due::NoOffer(failure) => Self::NoOffer {
                failure: failure.into(),
            },
            call_machine::Due::RestartIce => Self::RestartIce,
        }
    }
}

/// The call this device is in (`construct_rules::call_machine`). One per app; it is not kept:
/// a call does not outlive the process.
pub struct CallMachine {
    calls: Mutex<call_machine::Calls>,
}

impl Default for CallMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl CallMachine {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(call_machine::Calls::new()),
        }
    }

    fn calls(&self) -> std::sync::MutexGuard<'_, call_machine::Calls> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn active(&self) -> Option<CallSnapshot> {
        self.calls().active().map(Into::into)
    }

    pub fn recently_ended(&self, call_id: String, now_ms: i64) -> bool {
        self.calls().recently_ended(&call_id, now_ms)
    }

    pub fn dial(&self, call_id: String, peer_user_id: String, now_ms: i64) -> CallDialAction {
        self.calls().dial(&call_id, &peer_user_id, now_ms).into()
    }

    pub fn offer_sent(&self, devices: Vec<String>) {
        self.calls().offer_sent(devices)
    }

    pub fn push(&self, call_id: String, peer_user_id: String, now_ms: i64) -> CallPushAction {
        self.calls().push(&call_id, &peer_user_id, now_ms).into()
    }

    pub fn offer(
        &self,
        call_id: String,
        peer_user_id: String,
        device: String,
        usable: bool,
        my_user_id: String,
        now_ms: i64,
    ) -> CallOfferStep {
        self.calls()
            .offer(
                &call_id,
                &peer_user_id,
                &device,
                usable,
                &my_user_id,
                now_ms,
            )
            .into()
    }

    pub fn accept(&self, now_ms: i64) -> CallAcceptStep {
        self.calls().accept(now_ms).into()
    }

    pub fn answered(&self, now_ms: i64) {
        self.calls().answered(now_ms)
    }

    pub fn ringing(&self) -> bool {
        self.calls().ringing()
    }

    pub fn answer_from(&self, call_id: String, device: String) -> Option<CallAnswerDisposition> {
        self.calls()
            .answer_from(&call_id, &device)
            .map(|d| match d {
                calls::AnswerDisposition::Accept { device, release } => {
                    CallAnswerDisposition::Accept { device, release }
                }
                calls::AnswerDisposition::ReleaseLate { device } => {
                    CallAnswerDisposition::ReleaseLate { device }
                }
            })
    }

    pub fn hang_up(&self, now_ms: i64) -> Option<CallLocalHangup> {
        self.calls().hang_up(now_ms).map(Into::into)
    }

    pub fn hangup_from(
        &self,
        call_id: String,
        device: String,
        reason: CallHangupReason,
        now_ms: i64,
    ) -> CallRemoteHangupStep {
        self.calls()
            .hangup_from(&call_id, &device, reason.into(), now_ms)
            .into()
    }

    pub fn ended_by_server(&self, reason: CallHangupReason, now_ms: i64) -> Option<CallEnded> {
        self.calls()
            .ended_by_server(reason.into(), now_ms)
            .map(Into::into)
    }

    pub fn server_error(&self, error: CallSignalError, now_ms: i64) -> Option<CallEnded> {
        self.calls()
            .server_error(error.into(), now_ms)
            .map(Into::into)
    }

    pub fn fail(&self, now_ms: i64) -> Option<CallFailure> {
        self.calls().fail(now_ms).map(Into::into)
    }

    pub fn media_connected(&self) {
        self.calls().media_connected()
    }

    pub fn media_quality(&self, reconnecting: bool, now_ms: i64) -> CallIceStep {
        self.calls().media_quality(reconnecting, now_ms).into()
    }

    pub fn ice_restart_sent(&self) {
        self.calls().ice_restart_sent()
    }

    pub fn stream_closed(&self, now_ms: i64) -> Option<CallStreamStep> {
        self.calls().stream_closed(now_ms).map(Into::into)
    }

    pub fn next_deadline(&self) -> Option<i64> {
        self.calls().next_deadline()
    }

    pub fn tick(&self, now_ms: i64) -> Option<CallDue> {
        self.calls().tick(now_ms).map(Into::into)
    }
}

// ── Linking a device ──────────────────────────────────────────────────────────

pub fn device_sign_in_message(device_id: String, timestamp: i64) -> Vec<u8> {
    crate::device_id::sign_in_message(&device_id, timestamp)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTokenClaims {
    pub user_id: Option<String>,
    pub issued_at: Option<i64>,
}

pub fn session_token_claims(token: String) -> Option<SessionTokenClaims> {
    let claims = crate::session_token::claims(&token)?;
    Some(SessionTokenClaims {
        user_id: claims.user_id,
        issued_at: claims.issued_at,
    })
}

pub fn device_link_start_cursor(access_token: String) -> Option<String> {
    crate::session_token::start_cursor(&access_token)
}

/// No `Debug`, as `device_link_qr::LinkQr`.
#[derive(Clone, PartialEq, Eq)]
pub enum DeviceLinkQr {
    Offer {
        token: String,
        fingerprint: Option<Vec<u8>>,
        secret: Option<Vec<u8>>,
    },
    JoinRequest {
        device_id: String,
        identity_public: Vec<u8>,
        fingerprint: Option<Vec<u8>>,
        name: String,
        platform: String,
    },
}

fn key32(bytes: &[u8]) -> Result<&[u8; 32], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidKeyData)
}

pub fn device_link_offer_qr(
    token: String,
    fingerprint: Option<Vec<u8>>,
    secret: Vec<u8>,
) -> Result<String, CryptoError> {
    let fingerprint = fingerprint.as_deref().map(key32).transpose()?;
    Ok(device_link_qr::offer(&token, fingerprint, key32(&secret)?))
}

pub fn device_join_request_qr(
    identity_public: Vec<u8>,
    hybrid_public: Vec<u8>,
    name: String,
    platform: String,
) -> Result<String, CryptoError> {
    let identity_public = key32(&identity_public)?;
    Ok(device_link_qr::join_request(
        identity_public,
        &hybrid_public,
        &name,
        &platform,
    ))
}

pub fn read_device_link_qr(text: String) -> Option<DeviceLinkQr> {
    Some(match device_link_qr::read(&text)? {
        device_link_qr::LinkQr::Offer {
            token,
            fingerprint,
            secret,
        } => DeviceLinkQr::Offer {
            token,
            fingerprint: fingerprint.map(Into::into),
            secret: secret.map(Into::into),
        },
        device_link_qr::LinkQr::JoinRequest {
            device_id,
            identity_public,
            fingerprint,
            name,
            platform,
        } => DeviceLinkQr::JoinRequest {
            device_id,
            identity_public: identity_public.into(),
            fingerprint: fingerprint.map(Into::into),
            name,
            platform,
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceJoinEnd {
    Rejected,
    Expired,
    SignInRefused,
    LetInUnreachable,
}

impl From<device_join::End> for DeviceJoinEnd {
    fn from(end: device_join::End) -> Self {
        match end {
            device_join::End::Rejected => Self::Rejected,
            device_join::End::Expired => Self::Expired,
            device_join::End::SignInRefused => Self::SignInRefused,
            device_join::End::LetInUnreachable => Self::LetInUnreachable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceJoinStep {
    Wait { ms: i64 },
    Ask,
    SignIn,
    Ended { end: DeviceJoinEnd },
}

impl From<device_join::Step> for DeviceJoinStep {
    fn from(step: device_join::Step) -> Self {
        match step {
            device_join::Step::Wait(ms) => Self::Wait { ms },
            device_join::Step::Ask => Self::Ask,
            device_join::Step::SignIn => Self::SignIn,
            device_join::Step::Ended(end) => Self::Ended { end: end.into() },
        }
    }
}

/// The new device's wait in Flow B (`construct_rules::device_join`).
pub struct DeviceJoinWait {
    join: Mutex<device_join::Join>,
}

impl DeviceJoinWait {
    pub fn new(now_ms: i64) -> Self {
        Self {
            join: Mutex::new(device_join::Join::new(now_ms)),
        }
    }

    fn join(&self) -> std::sync::MutexGuard<'_, device_join::Join> {
        self.join.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn next(&self, now_ms: i64) -> DeviceJoinStep {
        self.join().next(now_ms).into()
    }

    pub fn on_status(&self, status: i32, now_ms: i64) {
        self.join().on_status(status, now_ms);
    }

    pub fn on_status_failed(&self, now_ms: i64) {
        self.join().on_status_failed(now_ms);
    }

    pub fn on_sign_in_failed(&self, failure: SendFailureKind, now_ms: i64) {
        self.join().on_sign_in_failed(failure.into(), now_ms);
    }
}

// ── Transport route ───────────────────────────────────────────────────────────

// The rule's plain enums and records cross as they are. UniFFI 0.30 takes no remote enum with
// fields, so those three are mirrored.
pub use crate::rule_state::transport_route::{
    Config as RouteConfig, Lane as RouteLane, Mode as RouteMode, RpcFailure as RouteRpcFailure,
    SoftFails as RouteSoftFails, StreamFailure as RouteStreamFailure, Via as RouteVia,
};
pub use crate::rule_state::veil_fronts::PinVerdict as FrontPinVerdict;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteState {
    Offline,
    Direct {
        fails: u32,
    },
    VeilProbing,
    VeilActive {
        relay: String,
        port: u16,
        since_ms: i64,
        soft_fails: RouteSoftFails,
        front_fails: u32,
    },
    VeilCooldown {
        until_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteEvent {
    RpcSucceeded {
        via: RouteVia,
        lane: RouteLane,
    },
    RpcFailed {
        failure: RouteRpcFailure,
        via: RouteVia,
        foreground: bool,
        lane: RouteLane,
    },
    StreamOpened {
        via: RouteVia,
    },
    StreamFailed {
        failure: RouteStreamFailure,
        via: RouteVia,
    },
    NetworkPathChanged {
        reachable: bool,
    },
    VeilModeChanged,
    VeilConfigChanged,
    BackgroundWake,
    ProxyStarted {
        relay: String,
        port: u16,
        restarted: bool,
    },
    ProxyStartFailed,
    FrontDialed {
        relay: String,
    },
    FrontDialFailed {
        relay: String,
    },
    CooldownElapsed,
    ManualReset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteEffect {
    InvalidateGrpcClient,
    SetVeilPort { port: Option<u16> },
    RequestProxyStart,
    RequestProxyStop,
    DemoteRelay { relay: String },
    ScheduleCooldownEnd { at_ms: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOutcome {
    pub state: RouteState,
    pub effects: Vec<RouteEffect>,
}

impl From<transport_route::State> for RouteState {
    fn from(state: transport_route::State) -> Self {
        use transport_route::State as S;
        match state {
            S::Offline => Self::Offline,
            S::Direct { fails } => Self::Direct { fails },
            S::VeilProbing => Self::VeilProbing,
            S::VeilActive {
                relay,
                port,
                since_ms,
                soft_fails,
                front_fails,
            } => Self::VeilActive {
                relay,
                port,
                since_ms,
                soft_fails,
                front_fails,
            },
            S::VeilCooldown { until_ms } => Self::VeilCooldown { until_ms },
        }
    }
}

impl From<RouteState> for transport_route::State {
    fn from(state: RouteState) -> Self {
        use RouteState as S;
        match state {
            S::Offline => Self::Offline,
            S::Direct { fails } => Self::Direct { fails },
            S::VeilProbing => Self::VeilProbing,
            S::VeilActive {
                relay,
                port,
                since_ms,
                soft_fails,
                front_fails,
            } => Self::VeilActive {
                relay,
                port,
                since_ms,
                soft_fails,
                front_fails,
            },
            S::VeilCooldown { until_ms } => Self::VeilCooldown { until_ms },
        }
    }
}

impl From<RouteEvent> for transport_route::Event {
    fn from(event: RouteEvent) -> Self {
        use RouteEvent as E;
        match event {
            E::RpcSucceeded { via, lane } => Self::RpcSucceeded { via, lane },
            E::RpcFailed {
                failure,
                via,
                foreground,
                lane,
            } => Self::RpcFailed {
                failure,
                via,
                foreground,
                lane,
            },
            E::StreamOpened { via } => Self::StreamOpened { via },
            E::StreamFailed { failure, via } => Self::StreamFailed { failure, via },
            E::NetworkPathChanged { reachable } => Self::NetworkPathChanged { reachable },
            E::VeilModeChanged => Self::VeilModeChanged,
            E::VeilConfigChanged => Self::VeilConfigChanged,
            E::BackgroundWake => Self::BackgroundWake,
            E::ProxyStarted {
                relay,
                port,
                restarted,
            } => Self::ProxyStarted {
                relay,
                port,
                restarted,
            },
            E::ProxyStartFailed => Self::ProxyStartFailed,
            E::FrontDialed { relay } => Self::FrontDialed { relay },
            E::FrontDialFailed { relay } => Self::FrontDialFailed { relay },
            E::CooldownElapsed => Self::CooldownElapsed,
            E::ManualReset => Self::ManualReset,
        }
    }
}

impl From<transport_route::Effect> for RouteEffect {
    fn from(effect: transport_route::Effect) -> Self {
        use transport_route::Effect as E;
        match effect {
            E::InvalidateGrpcClient => Self::InvalidateGrpcClient,
            E::SetVeilPort { port } => Self::SetVeilPort { port },
            E::RequestProxyStart => Self::RequestProxyStart,
            E::RequestProxyStop => Self::RequestProxyStop,
            E::DemoteRelay { relay } => Self::DemoteRelay { relay },
            E::ScheduleCooldownEnd { at_ms } => Self::ScheduleCooldownEnd { at_ms },
        }
    }
}

pub fn route_default_config() -> RouteConfig {
    RouteConfig::default()
}

pub fn route_initial(mode: RouteMode, reachable: bool) -> RouteState {
    transport_route::initial(mode, reachable).into()
}

pub fn route_step(
    state: RouteState,
    event: RouteEvent,
    mode: RouteMode,
    config: RouteConfig,
    now_ms: i64,
) -> RouteOutcome {
    let out = transport_route::reduce(&state.into(), &event.into(), mode, config, now_ms);
    RouteOutcome {
        state: out.state.into(),
        effects: out.effects.into_iter().map(RouteEffect::from).collect(),
    }
}

// ── VEIL fronts ───────────────────────────────────────────────────────────────

/// The pin kept for a front this device learned (`construct_rules::veil_fronts`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontHeldPin {
    pub spki: String,
    pub disputed: bool,
}

impl FrontHeldPin {
    fn rule(&self) -> veil_fronts::HeldPin<'_> {
        veil_fronts::HeldPin {
            spki: &self.spki,
            disputed: self.disputed,
        }
    }
}

pub fn judge_front_pin(
    anchor: Option<String>,
    held: Option<FrontHeldPin>,
    offered: String,
    vouched: bool,
) -> FrontPinVerdict {
    veil_fronts::judge_pin(
        anchor.as_deref(),
        held.as_ref().map(FrontHeldPin::rule),
        &offered,
        vouched,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The link exports carry every field through. Mutations that redden it: swap two fields or
    /// two arms of a conversion; accept a short key.
    #[test]
    fn linking_crosses_the_bridge() {
        let (identity, print, secret) = (vec![5u8; 32], vec![6u8; 32], vec![7u8; 32]);
        let offer = device_link_offer_qr(s("t"), Some(print.clone()), secret.clone()).unwrap();
        assert!(
            read_device_link_qr(offer)
                == Some(DeviceLinkQr::Offer {
                    token: s("t"),
                    fingerprint: Some(print.clone()),
                    secret: Some(secret.clone()),
                })
        );
        let hybrid = vec![8u8; 64];
        let request =
            device_join_request_qr(identity.clone(), hybrid.clone(), s("n"), s("p")).unwrap();
        assert!(
            read_device_link_qr(request)
                == Some(DeviceLinkQr::JoinRequest {
                    device_id: crate::device_id::derive_device_id(&identity),
                    identity_public: identity.clone(),
                    fingerprint: Some(
                        crate::history::discovery::qr_fingerprint(&identity, &hybrid).into()
                    ),
                    name: s("n"),
                    platform: s("p"),
                })
        );
        assert!(read_device_link_qr(s("konstruct://add?invite=x")).is_none());
        for short in [31, 33] {
            let short = vec![1u8; short];
            assert!(device_link_offer_qr(s("t"), None, short.clone()).is_err());
            assert!(device_link_offer_qr(s("t"), Some(short.clone()), secret.clone()).is_err());
            assert!(device_join_request_qr(short, hybrid.clone(), s("n"), s("p")).is_err());
        }
        assert_eq!(device_sign_in_message(s("id"), 12), b"id12".to_vec());

        // nonce (32) ‖ claims ‖ signature (64), as `session_token` reads it.
        let payload = [&[1u8; 32][..], br#"{"sub":"u","iat":3}"#, &[2u8; 64]].concat();
        let token = format!(
            "v4.public.{}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
        );
        assert_eq!(
            session_token_claims(token.clone()),
            Some(SessionTokenClaims {
                user_id: Some(s("u")),
                issued_at: Some(3)
            })
        );
        assert_eq!(device_link_start_cursor(token), Some(s("3000-0")));
        assert_eq!(session_token_claims(s("t")), None);
        assert_eq!(device_link_start_cursor(s("t")), None);
    }

    /// Every step and end crosses. Mutations that redden it: swap two arms; a report dropped.
    #[test]
    fn a_join_crosses_the_bridge() {
        use DeviceJoinEnd as E;
        use DeviceJoinStep as S;
        let due = 3_000;
        let wait = || DeviceJoinWait::new(0);

        let join = wait();
        assert_eq!(join.next(1_000), S::Wait { ms: 2_000 });
        assert_eq!(join.next(due), S::Ask);
        join.on_status_failed(due);
        assert_eq!(join.next(due), S::Wait { ms: 3_000 });
        let due = 2 * due;
        assert_eq!(join.next(due), S::Ask);
        join.on_status(1, due);
        assert_eq!(join.next(due), S::SignIn);
        join.on_sign_in_failed(SendFailureKind::NoAnswer, due);
        assert_eq!(join.next(due), S::Wait { ms: 3_000 });
        join.on_sign_in_failed(SendFailureKind::Status { code: 16 }, due);
        assert_eq!(
            join.next(due),
            S::Ended {
                end: E::SignInRefused
            }
        );

        let join = wait();
        join.on_status(2, due);
        assert_eq!(join.next(due), S::Ended { end: E::Rejected });

        let join = wait();
        join.on_status(3, due);
        join.on_sign_in_failed(SendFailureKind::Status { code: 16 }, due);
        assert_eq!(join.next(due), S::Ended { end: E::Expired });

        let join = wait();
        join.on_status(1, due);
        join.on_sign_in_failed(SendFailureKind::NoAnswer, due + 600_000);
        assert_eq!(
            join.next(due),
            S::Ended {
                end: E::LetInUnreachable
            }
        );
    }

    fn s(v: &str) -> String {
        v.to_owned()
    }

    /// Mutations that redden it: `None`; `Some(vec![])`; the arguments ignored.
    #[test]
    fn the_relay_urls_cross_the_bridge() {
        let urls = vec![
            "turn:t.example:3478".to_owned(),
            "turns:t.example:5349".to_owned(),
        ];
        assert_eq!(call_relay_urls(Vec::new(), false), None);
        assert_eq!(call_relay_urls(urls.clone(), false), Some(urls.clone()));
        assert_eq!(
            call_relay_urls(urls, true),
            Some(vec!["turns:t.example:5349".to_owned()])
        );
    }

    /// The call machine's exports carry its state and every step through. Mutations that redden
    /// it: swap two arms of any `call_machine` conversion, a snapshot field, an `Ended` field, a
    /// timing.
    #[test]
    fn the_call_machine_crosses_the_bridge_whole() {
        let t = call_timings();
        assert_eq!(
            (
                t.unanswered_ms,
                t.offer_wait_ms,
                t.ice_restart_grace_ms,
                t.ended_memory_ms
            ),
            (90_000, 45_000, 2_000, 120_000)
        );
        assert_eq!(
            (
                t.max_ice_restarts,
                t.max_stream_retries,
                t.max_post_media_reconnects
            ),
            (3, 3, 5)
        );

        // Ours: dial, offer, ring, answer, media, ICE, stream, hang up.
        let m = CallMachine::new();
        assert_eq!(m.dial(s("c1"), s("b"), 1_000), CallDialAction::Start);
        assert_eq!(m.dial(s("c2"), s("x"), 1_000), CallDialAction::Busy);
        m.offer_sent(vec![s("d1"), s("d2")]);
        let snap = m.active().unwrap();
        assert_eq!(
            (snap.call_id.as_str(), snap.peer_user_id.as_str()),
            ("c1", "b")
        );
        assert_eq!(snap.direction, CallDirection::Outgoing);
        assert_eq!(snap.phase, CallMachinePhase::Dialing);
        assert_eq!(snap.offered, vec![s("d1"), s("d2")]);
        assert_eq!(snap.targets, vec![s("d1"), s("d2")]);
        assert_eq!(snap.started_at_ms, 1_000);
        assert!(m.ringing());
        assert_eq!(m.active().unwrap().phase, CallMachinePhase::Ringing);
        assert_eq!(
            m.answer_from(s("c1"), s("d2")),
            Some(CallAnswerDisposition::Accept {
                device: s("d2"),
                release: vec![s("d1")]
            })
        );
        assert_eq!(
            m.answer_from(s("c1"), s("d1")),
            Some(CallAnswerDisposition::ReleaseLate { device: s("d1") })
        );
        m.answered(2_000);
        m.media_connected();
        let snap = m.active().unwrap();
        assert_eq!(snap.phase, CallMachinePhase::Active);
        assert_eq!(snap.chosen, Some(s("d2")));
        assert_eq!(snap.answered_at_ms, Some(2_000));
        assert!(snap.media_connected && !snap.holds_offer && !snap.awaiting_offer_after_answer);
        assert_eq!(m.media_quality(true, 3_000), CallIceStep::Schedule);
        assert!(m.active().unwrap().reconnecting);
        assert_eq!(m.media_quality(true, 3_000), CallIceStep::Skip);
        assert_eq!(m.next_deadline(), Some(5_000));
        assert_eq!(m.tick(5_000), Some(CallDue::RestartIce));
        assert_eq!(m.media_quality(true, 5_000), CallIceStep::Skip);
        m.ice_restart_sent();
        assert_eq!(m.media_quality(true, 5_000), CallIceStep::Schedule);
        assert_eq!(m.stream_closed(5_000), Some(CallStreamStep::Reconnect));
        assert_eq!(m.server_error(CallSignalError::RateLimited, 5_000), None);
        let hangup = m.hang_up(9_000).unwrap();
        assert_eq!(hangup.reason, CallHangupReason::Normal);
        assert_eq!(hangup.targets, vec![s("d2")]);
        assert_eq!(
            hangup.route,
            CallHangupRoute {
                e2ee: true,
                stream: true
            }
        );
        let ended = hangup.ended;
        assert_eq!(
            (ended.call_id.as_str(), ended.peer_user_id.as_str()),
            ("c1", "b")
        );
        assert_eq!(ended.direction, CallDirection::Outgoing);
        assert_eq!(
            ended.cause,
            CallEndCause::Hangup {
                reason: CallHangupReason::Normal
            }
        );
        assert_eq!(
            ended.outcome,
            CallEndOutcome::Ended {
                connected_seconds: Some(7)
            }
        );
        assert_eq!(ended.history, Some(CallHistoryStatus::Completed));
        assert_eq!((ended.started_at_ms, ended.duration_seconds), (1_000, 7));
        assert!(m.recently_ended(s("c1"), 9_000));
        assert!(!m.recently_ended(s("c9"), 9_000));
        assert!(m.active().is_none());

        // Theirs, by push: wait for the offer, then it resumes the answer.
        let m = CallMachine::new();
        assert_eq!(m.push(s("c1"), s("a"), 0), CallPushAction::Begin);
        assert_eq!(m.push(s("c1"), s("a"), 0), CallPushAction::AlreadyTracking);
        assert_eq!(m.push(s("c2"), s("x"), 0), CallPushAction::DeclineBusy);
        assert_eq!(m.dial(s("c3"), s("a"), 0), CallDialAction::AnswerInstead);
        assert_eq!(m.accept(0), CallAcceptStep::WaitForOffer);
        assert!(m.active().unwrap().awaiting_offer_after_answer);
        assert_eq!(m.accept(0), CallAcceptStep::Ignore);
        assert_eq!(
            m.offer(s("c1"), s("a"), s("d1"), true, s("b"), 1),
            CallOfferStep::ResumeAnswer
        );
        assert!(m.active().unwrap().holds_offer);
        m.answered(2);
        assert_eq!(
            m.offer(s("c1"), s("a"), s("d1"), true, s("b"), 3),
            CallOfferStep::Renegotiate
        );
        assert_eq!(
            m.offer(s("c4"), s("x"), s("x1"), true, s("b"), 3),
            CallOfferStep::Busy
        );
        assert_eq!(m.media_quality(true, 3), CallIceStep::Skip);
        m.media_connected();
        assert_eq!(m.media_quality(true, 3), CallIceStep::CalleeWaits);
        let CallOfferStep::Fail { failure } = m.offer(s("c1"), s("a"), s("d1"), false, s("b"), 4)
        else {
            panic!("an unusable offer for the call in progress ends it");
        };
        assert_eq!(failure.ended.cause, CallEndCause::Local);
        assert_eq!(failure.ended.direction, CallDirection::Incoming);
        let hangup = failure.hangup.expect("answered: the caller is told");
        assert_eq!(hangup.reason, CallHangupReason::ConnectionFailed);
        assert_eq!(hangup.targets, vec![s("d1")]);

        // Theirs, by offer: held, then glare and the ways it ends.
        let m = CallMachine::new();
        assert_eq!(
            m.offer(s("c1"), s("a"), s("d1"), false, s("b"), 0),
            CallOfferStep::Ignore
        );
        assert_eq!(
            m.offer(s("c1"), s("a"), s("d1"), true, s("b"), 0),
            CallOfferStep::Ring
        );
        assert_eq!(m.active().unwrap().phase, CallMachinePhase::Incoming);
        assert_eq!(
            m.hangup_from(s("c1"), s("d9"), CallHangupReason::Normal, 0),
            CallRemoteHangupStep::Ignore
        );
        assert_eq!(m.accept(0), CallAcceptStep::ApplyOffer);
        assert_eq!(m.active().unwrap().phase, CallMachinePhase::Connecting);
        let CallRemoteHangupStep::End {
            release,
            reason,
            route,
            ended,
        } = m.hangup_from(s("c1"), s("d1"), CallHangupReason::Declined, 5)
        else {
            panic!("their decline ends the call");
        };
        assert!(release.is_empty());
        assert_eq!(reason, CallHangupReason::Declined);
        assert_eq!(
            route,
            CallHangupRoute {
                e2ee: false,
                stream: true
            }
        );
        assert_eq!(ended.history, Some(CallHistoryStatus::Declined));

        let m = CallMachine::new();
        m.dial(s("mine"), s("a"), 0);
        assert_eq!(
            m.offer(s("theirs"), s("a"), s("d1"), true, s("b"), 0),
            CallOfferStep::KeepOurs
        );
        let m = CallMachine::new();
        m.dial(s("mine"), s("b"), 0);
        m.offer_sent(vec![s("d1"), s("d2")]);
        assert_eq!(
            m.hangup_from(s("mine"), s("d1"), CallHangupReason::Busy, 0),
            CallRemoteHangupStep::DropDevice {
                remaining: vec![s("d2")]
            }
        );
        assert_eq!(
            m.offer(s("theirs"), s("b"), s("d1"), true, s("a"), 0),
            CallOfferStep::ReplaceOutgoing {
                replaced: s("mine")
            }
        );
        let CallDue::Unanswered { hangup } = m.tick(90_000).unwrap() else {
            panic!("nobody answered");
        };
        assert_eq!(hangup.reason, CallHangupReason::Timeout);
        assert_eq!(hangup.ended.outcome, CallEndOutcome::NoAnswer);
        assert_eq!(hangup.ended.history, Some(CallHistoryStatus::Missed));

        let m = CallMachine::new();
        m.push(s("c1"), s("a"), 0);
        m.accept(0);
        let CallDue::NoOffer { failure } = m.tick(45_000).unwrap() else {
            panic!("the offer never came");
        };
        assert_eq!(failure.ended.history, Some(CallHistoryStatus::Failed));

        let m = CallMachine::new();
        m.dial(s("c1"), s("b"), 0);
        let ended = m.server_error(CallSignalError::CallExpired, 0).unwrap();
        assert_eq!(
            ended.cause,
            CallEndCause::ServerError {
                error: CallSignalError::CallExpired
            }
        );
        assert_eq!(ended.outcome, CallEndOutcome::NoAnswer);
        m.dial(s("c2"), s("b"), 0);
        let ended = m.ended_by_server(CallHangupReason::Busy, 0).unwrap();
        assert_eq!(ended.outcome, CallEndOutcome::Busy);
        m.dial(s("c3"), s("b"), 0);
        for _ in 0..3 {
            m.stream_closed(0);
        }
        let Some(CallStreamStep::End { failure }) = m.stream_closed(0) else {
            panic!("nothing bounds the call");
        };
        assert_eq!(failure.ended.outcome, CallEndOutcome::Failed);
        m.dial(s("c4"), s("b"), 0);
        m.answer_from(s("c4"), s("d1"));
        m.answered(0);
        m.media_connected();
        for _ in 0..5 {
            m.stream_closed(0);
        }
        assert_eq!(m.stream_closed(0), Some(CallStreamStep::KeepOnMessagePath));
        assert_eq!(
            m.fail(0).unwrap().ended.history,
            Some(CallHistoryStatus::Completed)
        );
        assert_eq!(m.fail(0), None);
        assert_eq!(m.next_deadline(), None);
    }

    /// The call exports carry every variant through, both ways. Mutation that reddens it: swap two
    /// arms of any call `From`, or of `call_on_hangup` / `call_on_answer` / `call_glare`.
    #[test]
    fn the_call_exports_carry_every_variant() {
        use CallHangupReason as R;
        let reasons = [
            R::Unspecified,
            R::Normal,
            R::Busy,
            R::Declined,
            R::Timeout,
            R::ConnectionFailed,
            R::AcceptedElsewhere,
        ];
        for (wire, reason) in reasons.into_iter().enumerate() {
            assert_eq!(call_hangup_reason_from_wire(wire as i32), reason);
            assert_eq!(call_hangup_reason_wire(reason), wire as i32);
        }
        use CallSignalError as E;
        let errors = [
            E::Unspecified,
            E::CalleeOffline,
            E::CalleeBusy,
            E::RateLimited,
            E::Unauthorized,
            E::CallExpired,
        ];
        for (wire, error) in errors.into_iter().enumerate() {
            assert_eq!(call_signal_error_from_wire(wire as i32), error);
        }
        // Each error reaches the rule as itself: busy and expired read apart from the rest.
        let outcomes: Vec<CallEndOutcome> = errors
            .into_iter()
            .map(|error| call_end_outcome(CallEndCause::ServerError { error }, None))
            .collect();
        use CallEndOutcome as O;
        assert_eq!(
            outcomes,
            vec![
                O::Failed,
                O::Failed,
                O::Busy,
                O::Failed,
                O::Failed,
                O::NoAnswer
            ]
        );
        let hangups: Vec<CallEndOutcome> = reasons
            .into_iter()
            .map(|reason| call_end_outcome(CallEndCause::Hangup { reason }, Some(4)))
            .collect();
        let ended = O::Ended {
            connected_seconds: Some(4),
        };
        assert_eq!(
            hangups,
            vec![
                ended,
                ended,
                O::Busy,
                O::Declined,
                O::NoAnswer,
                O::Failed,
                ended
            ]
        );
        assert_eq!(call_end_outcome(CallEndCause::Local, None), O::Failed);
        assert!(!call_outcome_wants_attention(ended));
        for o in [O::Declined, O::Busy, O::NoAnswer, O::Failed] {
            assert!(call_outcome_wants_attention(o), "{o:?}");
        }

        use CallDirection::{Incoming, Outgoing};
        use CallHistoryStatus as H;
        let declined = CallEndCause::Hangup {
            reason: R::Declined,
        };
        assert_eq!(
            call_history_status(Incoming, declined, false),
            Some(H::Declined)
        );
        assert_eq!(
            call_history_status(Outgoing, declined, false),
            Some(H::Missed)
        );
        assert_eq!(
            call_history_status(Outgoing, CallEndCause::Local, true),
            Some(H::Completed)
        );
        assert_eq!(
            call_history_status(Outgoing, CallEndCause::Local, false),
            Some(H::Failed)
        );
        assert_eq!(
            call_history_status(
                Incoming,
                CallEndCause::Hangup {
                    reason: R::AcceptedElsewhere
                },
                false
            ),
            None
        );
        assert_eq!(call_local_hangup_reason(Incoming, true), R::Declined);
        assert_eq!(call_local_hangup_reason(Outgoing, true), R::Normal);
        assert_eq!(call_duration_seconds(Some(0), 2_500), 2);

        let offered = vec!["d1".to_string(), "d2".to_string()];
        assert_eq!(
            call_signal_targets(None, offered.clone(), None),
            offered.clone()
        );
        assert_eq!(
            call_offer_devices(offered.clone(), vec!["d2".into()], None),
            vec!["d2".to_string()]
        );
        assert!(!call_admits("d2".into(), Some("d1".into())));
        assert!(call_admits("d1".into(), Some("d1".into())));
        assert_eq!(
            call_on_answer("d1".into(), None, offered.clone()),
            CallAnswerDisposition::Accept {
                device: "d1".into(),
                release: vec!["d2".into()]
            }
        );
        assert_eq!(
            call_on_answer("d2".into(), Some("d1".into()), offered.clone()),
            CallAnswerDisposition::ReleaseLate {
                device: "d2".into()
            }
        );
        assert_eq!(
            call_on_hangup("d1".into(), R::Busy, None, offered.clone()),
            CallHangupDisposition::DropDevice {
                remaining: vec!["d2".into()]
            }
        );
        assert_eq!(
            call_on_hangup("d1".into(), R::Declined, None, offered.clone()),
            CallHangupDisposition::End {
                release: vec!["d2".into()]
            }
        );
        assert_eq!(
            call_on_hangup("d1".into(), R::AcceptedElsewhere, Some("d1".into()), vec![]),
            CallHangupDisposition::EndTakenElsewhere
        );
        assert_eq!(
            call_on_hangup("d2".into(), R::Normal, Some("d1".into()), vec![]),
            CallHangupDisposition::Ignore
        );
        assert_eq!(call_glare("b".into(), "a".into()), CallGlare::KeepOurs);
        assert_eq!(call_glare("a".into(), "b".into()), CallGlare::Yield);
    }

    /// A set is a set across the boundary: an answer in another order is the same set, and the
    /// named one comes back sorted. Mutation that reddens it: compare the lists as they came.
    #[test]
    fn a_device_set_is_compared_as_a_set() {
        let ba = vec!["b".to_string(), "a".to_string()];
        assert_eq!(
            device_set_named(vec![vec![], ba.clone(), vec![]]),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(!device_set_should_ask(
            vec!["a".into(), "b".into()],
            Some(ba.clone())
        ));
        assert!(device_set_should_ask(ba, None));
    }

    /// The wrappers carry each variant through, both ways. Mutation that reddens it: swap two
    /// arms of a `From` or of `after_send_failure`.
    #[test]
    fn the_exports_carry_every_variant() {
        assert_eq!(
            device_refusal_of(16, Some("1".into())),
            DeviceRefusalKind::Removed
        );
        assert_eq!(
            device_refusal_of(16, Some("2".into())),
            DeviceRefusalKind::NotFound
        );
        assert_eq!(device_refusal_of(16, None), DeviceRefusalKind::Unspecified);
        assert!(refusal_erases_device(DeviceRefusalKind::Removed, true));
        assert!(!refusal_erases_device(DeviceRefusalKind::NotFound, true));
        assert!(!refusal_erases_device(DeviceRefusalKind::Unspecified, true));
        assert_eq!(
            after_send_failure(SendFailureKind::NoAnswer),
            MessageAfterSendFailure::Queued
        );
        assert_eq!(
            after_send_failure(SendFailureKind::Status { code: 7 }),
            MessageAfterSendFailure::Failed
        );
        assert_eq!(generated_name("test".into()), "ancient sphinx");
        assert_eq!(
            shown_name(None, "Анна".into(), "anna_k".into(), "test".into()),
            "Анна"
        );
    }

    /// The batch-4 objects and functions carry their values through. Mutation that reddens it:
    /// swap two arms of `intake_own_key` or `ReadMarkerOutcome`, or drop `restore`'s fields.
    #[test]
    fn the_batch_4_exports_carry_their_values() {
        let q = FanoutRetryState::new();
        q.enqueue(
            "m1".into(),
            "bob".into(),
            "me".into(),
            vec!["d2".into(), "d1".into()],
            1_000,
        );
        // An attempt first, so `restore` has more than defaults to carry.
        assert!(q.record_attempt("m1|bob".into(), 1_500).is_some());
        let all = q.all();
        assert_eq!(all[0].key, "m1|bob");
        assert_eq!(all[0].attempts, 1);
        assert_eq!(
            all[0].owed_device_ids,
            vec!["d1".to_string(), "d2".to_string()]
        );
        let restored = FanoutRetryState::restore(all.clone());
        assert_eq!(restored.all(), all);
        let back = FanoutRetryState::from_bytes(q.to_bytes().unwrap());
        assert_eq!(back.all(), all);
        assert_eq!(
            q.record_attempt("m1|bob".into(), 2_000).unwrap().attempts,
            2
        );
        assert_eq!(q.next_due(2_000), Some(122_000));

        let r = ReadMarkerState::new();
        let at = |ms, id: &str| ReadBoundary {
            sent_at_ms: ms,
            message_id: id.into(),
        };
        assert!(r.note_read("Bob".into(), at(10, "M")));
        assert_eq!(r.boundary("bob".into()), Some(at(10, "m")));
        assert_eq!(
            r.apply_marker("bob".into(), at(20, "n"), false, "me".into()),
            ReadMarkerOutcome::Drop
        );
        assert_eq!(
            r.apply_marker("bob".into(), at(20, "n"), true, "me".into()),
            ReadMarkerOutcome::Apply
        );
        assert_eq!(
            r.apply_marker("bob".into(), at(5, "n"), true, "me".into()),
            ReadMarkerOutcome::Ignore
        );
        let pending = r.take_pending();
        assert_eq!(pending.len(), 1);
        assert!(!r.has_pending());
        r.return_pending(pending);
        assert!(r.has_pending());
        let back = ReadMarkerState::from_bytes(r.to_bytes().unwrap());
        assert_eq!(back.boundary("bob".into()), Some(at(20, "n")));
        assert_eq!(
            read_unread_left(
                2,
                vec![
                    ReadIncoming {
                        message_id: "a".into(),
                        at_ms: 1
                    },
                    ReadIncoming {
                        message_id: "b".into(),
                        at_ms: 2
                    }
                ],
                at(9, "a")
            ),
            1
        );

        assert_eq!(intake_own_key(Some(2), 3, true), IntakeOwnKeyNext::Use);
        assert_eq!(intake_own_key(Some(0), 0, false), IntakeOwnKeyNext::Promote);
        assert_eq!(
            intake_own_key(None, 4, false),
            IntakeOwnKeyNext::Mint { above: 4 }
        );
        assert_eq!(intake_own_key(None, 4, true), IntakeOwnKeyNext::Wait);
        let published = IntakePublished {
            account_id: "me".into(),
            epoch: 10,
            key_id: "k".into(),
        };
        let kept = intake_published_to_bytes(published.clone()).unwrap();
        assert_eq!(intake_published_from_bytes(kept), Some(published.clone()));
        assert!(intake_server_holds(
            Some(published.clone()),
            "me".into(),
            "k".into(),
            12
        ));
        assert!(!intake_should_publish(Some(published.clone()), published));
        let state = crate::intake::IntakeKeyState {
            generation: 9,
            key: vec![1; 32],
        };
        assert_eq!(
            intake_key_record_decode(intake_key_record_encode(state.clone())),
            Some(state)
        );
        assert_eq!(
            intake_card_schedule(
                vec!["a".into(), "b".into()],
                "b".into(),
                vec![],
                "me".into(),
                vec![1]
            )
            .len(),
            1
        );
    }

    /// The cursor object carries each outcome and hold through. Mutation that reddens it: map
    /// `Deferred` to `Durable` in `report`, or swap the two holds.
    #[test]
    fn the_stream_cursor_carries_outcomes_and_holds() {
        let cursor = StreamCursorState::new();
        cursor.track("a".into(), "1-0".into(), 10);
        cursor.track("b".into(), "2-0".into(), 11);
        assert_eq!(
            cursor.report("a".into(), StreamCursorOutcome::Deferred),
            None
        );
        assert_eq!(
            cursor.report("b".into(), StreamCursorOutcome::Durable),
            None
        );
        assert_eq!(
            cursor.head_blocker(),
            Some(StreamCursorBlocker {
                message_id: "a".into(),
                hold: StreamCursorHold::Deferred,
                tracked_at_ms: 10,
            })
        );
        assert_eq!(cursor.report("a".into(), StreamCursorOutcome::Skip), None);
        assert_eq!(cursor.resolve("a".into()).as_deref(), Some("2-0"));
        cursor.track("c".into(), "3-0".into(), 12);
        assert_eq!(
            cursor.head_blocker().map(|b| b.hold),
            Some(StreamCursorHold::Pending)
        );
        let skipped = cursor.skip_held_backlog().unwrap();
        assert_eq!((skipped.cursor.as_str(), skipped.held), ("3-0", 1));
        assert_eq!(
            cursor.track_resolved("4-0".into(), 13).as_deref(),
            Some("4-0")
        );
        assert_eq!(cursor.in_flight(), 0);
    }

    /// The offer, stream and hangup-route exports carry every case through. Mutations that redden
    /// it: swap two arms of `CallOfferAction`, `CallStreamClosedAction` or `CallHangupSide`; drop a
    /// field of `CallHeldCall`; swap `e2ee` and `stream`.
    #[test]
    fn the_offer_stream_and_route_exports_carry_every_case() {
        let held = |same_call, direction, answered, awaiting| CallHeldCall {
            same_call,
            direction,
            with_offerer: true,
            answered,
            awaiting_offer_after_answer: awaiting,
        };
        use CallDirection::{Incoming, Outgoing};
        use CallOfferAction as A;
        let offer = |ended, h: Option<CallHeldCall>, me: &str| {
            call_on_offer(ended, h, me.into(), "m".into())
        };
        assert_eq!(offer(true, None, "a"), A::IgnoreEnded);
        assert_eq!(offer(false, None, "a"), A::Ring);
        assert_eq!(
            offer(false, Some(held(true, Incoming, true, true)), "a"),
            A::ResumeAnswer
        );
        assert_eq!(
            offer(false, Some(held(true, Incoming, false, false)), "a"),
            A::HoldUntilAnswered
        );
        assert_eq!(
            offer(false, Some(held(true, Incoming, true, false)), "a"),
            A::Renegotiate
        );
        assert_eq!(
            offer(false, Some(held(false, Outgoing, false, false)), "z"),
            A::KeepOurs
        );
        assert_eq!(
            offer(false, Some(held(false, Outgoing, false, false)), "a"),
            A::ReplaceOutgoing
        );
        let other = CallHeldCall {
            with_offerer: false,
            ..held(false, Outgoing, false, false)
        };
        assert_eq!(offer(false, Some(other), "a"), A::Busy);

        use CallStreamClosedAction as S;
        assert_eq!(call_on_stream_closed(true, false, false), S::Reconnect);
        assert_eq!(
            call_on_stream_closed(false, true, false),
            S::KeepOnMessagePath
        );
        assert_eq!(
            call_on_stream_closed(false, false, true),
            S::KeepOnMessagePath
        );
        assert_eq!(call_on_stream_closed(false, false, false), S::EndCall);

        let route = |side, reason| call_hangup_route(side, reason);
        assert_eq!(
            route(CallHangupSide::Local, CallHangupReason::Normal),
            CallHangupRoute {
                e2ee: true,
                stream: true
            }
        );
        assert_eq!(
            route(CallHangupSide::Remote, CallHangupReason::Normal),
            CallHangupRoute {
                e2ee: false,
                stream: true
            }
        );
        assert_eq!(
            route(CallHangupSide::Local, CallHangupReason::AcceptedElsewhere),
            CallHangupRoute {
                e2ee: true,
                stream: false
            }
        );
    }

    /// Every case crosses to the same case with the same fields: the two print alike, and a state
    /// goes there and back. Mutation: swap two arms or two fields of a conversion.
    #[test]
    fn every_route_case_crosses_as_itself() {
        let r = || "front:443".to_string();
        let states = [
            RouteState::Offline,
            RouteState::Direct { fails: 1 },
            RouteState::VeilProbing,
            RouteState::VeilActive {
                relay: r(),
                port: 7,
                since_ms: 8,
                soft_fails: RouteSoftFails { auth: 1, sealed: 2 },
                front_fails: 3,
            },
            RouteState::VeilCooldown { until_ms: 9 },
        ];
        for state in states {
            let there = transport_route::State::from(state.clone());
            assert_eq!(format!("{there:?}"), format!("{state:?}"));
            assert_eq!(RouteState::from(there), state);
        }
        let (via, lane) = (RouteVia::Veil, RouteLane::Sealed);
        let events = [
            RouteEvent::RpcSucceeded { via, lane },
            RouteEvent::RpcFailed {
                failure: RouteRpcFailure::ServerNotReady,
                via,
                foreground: true,
                lane,
            },
            RouteEvent::StreamOpened { via },
            RouteEvent::StreamFailed {
                failure: RouteStreamFailure::WriteFailed,
                via,
            },
            RouteEvent::NetworkPathChanged { reachable: true },
            RouteEvent::VeilModeChanged,
            RouteEvent::VeilConfigChanged,
            RouteEvent::BackgroundWake,
            RouteEvent::ProxyStarted {
                relay: r(),
                port: 7,
                restarted: true,
            },
            RouteEvent::ProxyStartFailed,
            RouteEvent::FrontDialed { relay: r() },
            RouteEvent::FrontDialFailed { relay: r() },
            RouteEvent::CooldownElapsed,
            RouteEvent::ManualReset,
        ];
        for event in events {
            let there = transport_route::Event::from(event.clone());
            assert_eq!(format!("{there:?}"), format!("{event:?}"));
        }
        use transport_route::Effect as E;
        let effects = [
            E::InvalidateGrpcClient,
            E::SetVeilPort { port: Some(7) },
            E::RequestProxyStart,
            E::RequestProxyStop,
            E::DemoteRelay { relay: r() },
            E::ScheduleCooldownEnd { at_ms: 9 },
        ];
        for effect in effects {
            let here = RouteEffect::from(effect.clone());
            assert_eq!(format!("{here:?}"), format!("{effect:?}"));
        }
    }

    /// The route and the pin rule answer across the bridge: an event moves the state given, under
    /// the mode, config and time given, and every argument reaches the rule.
    #[test]
    fn the_route_crosses_the_bridge() {
        let front = "front:443".to_string();
        let up = route_step(
            route_initial(RouteMode::On, true),
            RouteEvent::ProxyStarted {
                relay: front.clone(),
                port: 7,
                restarted: false,
            },
            RouteMode::On,
            route_default_config(),
            42,
        );
        assert_eq!(
            up.state,
            RouteState::VeilActive {
                relay: front.clone(),
                port: 7,
                since_ms: 42,
                soft_fails: RouteSoftFails::default(),
                front_fails: 0,
            }
        );
        let failed = RouteEvent::FrontDialFailed { relay: front };
        let once = RouteConfig {
            front_dial_fail_threshold: 1,
            ..route_default_config()
        };
        let left = route_step(up.state, failed, RouteMode::On, once, 43);
        assert_eq!(left.state, RouteState::VeilProbing);
        assert_eq!(
            left.effects[0],
            RouteEffect::DemoteRelay {
                relay: "front:443".into()
            }
        );
        assert_eq!(left.effects.len(), 5);
        let cooled = |mode| {
            route_step(
                RouteState::VeilCooldown { until_ms: 1 },
                RouteEvent::CooldownElapsed,
                mode,
                route_default_config(),
                2,
            )
            .state
        };
        assert_eq!(cooled(RouteMode::On), RouteState::VeilProbing);
        assert_eq!(cooled(RouteMode::Auto), RouteState::Direct { fails: 0 });
        assert_eq!(route_initial(RouteMode::On, false), RouteState::Offline);
        assert_eq!(
            route_initial(RouteMode::Auto, true),
            RouteState::Direct { fails: 0 }
        );
    }

    #[test]
    fn a_front_pin_crosses_the_bridge() {
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let held = |disputed| {
            Some(FrontHeldPin {
                spki: a.clone(),
                disputed,
            })
        };
        use FrontPinVerdict as V;
        let judge = |anchor, held, signed| judge_front_pin(anchor, held, b.clone(), signed);
        assert_eq!(judge(None, held(true), true), V::Repin);
        assert_eq!(judge_front_pin(None, held(true), a.clone(), true), V::Same);
        assert_eq!(judge(None, held(true), false), V::Unsigned);
        assert_eq!(judge(None, held(false), true), V::DiffersFromHeld);
        assert_eq!(
            judge(Some(a.clone()), held(true), true),
            V::DiffersFromAnchor
        );
    }
}
