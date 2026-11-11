//! The client rules (`construct-rules`) and the bytes their state is kept as.
//!
//! A rule owns its state and transitions; the format is the core's, the one every persisted state
//! has: a CFE envelope with the rule's own message type (rule 6 of
//! `decisions/rules-from-the-first-year.md`). iOS and Android reach this through
//! `rules_bindings`; a Rust client (construct-client) calls it directly.
//!
//! What a client does with a kept blob that does not read is a rule too, so it is decided here:
//! the state starts empty and the reason goes to the log. A notice nobody can read is a notice
//! nobody can show; refusing to start over it would only keep the person from seeing the next one.

pub use construct_rules::{device_refusal, mailbox_gap, names, send_failure, stream_cursor};

use crate::cfe::{self, CfeError, CfeMessageType};

/// The notice as bytes to keep.
pub fn encode_mailbox_gap(notice: &mailbox_gap::Notice) -> Result<Vec<u8>, CfeError> {
    cfe::encode(CfeMessageType::MailboxGapNotice, notice)
}

/// The notice that was kept, or an empty one when the bytes are not a notice.
pub fn decode_mailbox_gap(kept: &[u8]) -> mailbox_gap::Notice {
    cfe::decode_as(kept, CfeMessageType::MailboxGapNotice).unwrap_or_else(|e| {
        tracing::warn!(target: "rules", "kept mailbox-gap notice does not read, starting empty: {e}");
        mailbox_gap::Notice::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailbox_gap::{Notice, Report};

    fn report(after: &str, resumes: &str) -> Report {
        Report {
            after_cursor: after.into(),
            resumes_at: resumes.into(),
        }
    }

    /// What was kept reads back the same, open and closed reports both.
    #[test]
    fn a_notice_reads_back_as_it_was_kept() {
        let mut notice = Notice::default();
        notice.record(report("100-0", "300-0"));
        notice.close();
        notice.record(report("200-0", ""));
        let kept = encode_mailbox_gap(&notice).unwrap();
        assert_eq!(decode_mailbox_gap(&kept), notice);
    }

    /// The bytes are a CFE envelope of this rule's type, not JSON and not another type.
    #[test]
    fn the_notice_is_kept_as_its_own_cfe_type() {
        let kept = encode_mailbox_gap(&Notice::default()).unwrap();
        assert_eq!(
            cfe::decode(&kept).unwrap().msg_type,
            CfeMessageType::MailboxGapNotice
        );
    }

    /// A blob that is not this notice — JSON from an older build, another CFE type, garbage —
    /// starts the notice empty instead of failing.
    #[test]
    fn what_does_not_read_starts_empty() {
        assert_eq!(
            decode_mailbox_gap(br#"{"open":[{"after_cursor":"1-0","resumes_at":""}],"closed":[]}"#),
            Notice::default()
        );
        let other = cfe::encode(CfeMessageType::ClientBlockWishes, &Notice::default()).unwrap();
        assert_eq!(decode_mailbox_gap(&other), Notice::default());
        assert_eq!(decode_mailbox_gap(b"garbage"), Notice::default());
    }
}
