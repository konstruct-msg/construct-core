//! `construct-rules` over UniFFI, in this library's one component (as `local_store_bindings`).
//! Field-for-field conversions only; the rule decides everything (`rule_state`,
//! `construct-docs/decisions/client-rules-shared-in-rust.md`).

use std::sync::Mutex;

use crate::rule_state::{
    self, device_refusal, fanout_retry, intake, mailbox_gap, names, read_sync, send_failure,
    stream_cursor,
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

pub fn after_send_failure(failure: SendFailureKind) -> MessageAfterSendFailure {
    let failure = match failure {
        SendFailureKind::NoAnswer => send_failure::SendError::NoAnswer,
        SendFailureKind::Status { code } => send_failure::SendError::Status(code),
    };
    match send_failure::after(failure) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
