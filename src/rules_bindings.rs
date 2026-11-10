//! `construct-rules` over UniFFI, in this library's one component (as `local_store_bindings`).
//! Field-for-field conversions only; the rule decides everything (`rule_state`,
//! `construct-docs/decisions/client-rules-shared-in-rust.md`).

use std::sync::Mutex;

use crate::rule_state::{self, device_refusal, mailbox_gap, names, send_failure};
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
}
