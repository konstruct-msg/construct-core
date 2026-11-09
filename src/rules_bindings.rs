//! `construct-rules` over UniFFI, in this library's one component (as `local_store_bindings`).
//! Field-for-field conversions only; the rule decides everything (`rule_state`,
//! `construct-docs/decisions/client-rules-shared-in-rust.md`).

use std::sync::Mutex;

use crate::rule_state::{self, mailbox_gap};
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

    pub fn close(&self) {
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
