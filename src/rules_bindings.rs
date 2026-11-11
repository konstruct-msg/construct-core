//! `construct-rules` over UniFFI, in this library's one component (as `local_store_bindings`).
//! Field-for-field conversions only; the rule decides everything (`rule_state`,
//! `construct-docs/decisions/client-rules-shared-in-rust.md`).

use std::sync::Mutex;

use crate::rule_state::{self, device_refusal, mailbox_gap, names, send_failure, stream_cursor};
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
