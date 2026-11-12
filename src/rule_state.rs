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

pub use construct_rules::{
    device_refusal, fanout_retry, intake, mailbox_gap, names, read_sync, send_failure,
    stream_cursor,
};

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

/// The owed copies as bytes to keep.
pub fn encode_fanout_retry(queue: &fanout_retry::Queue) -> Result<Vec<u8>, CfeError> {
    cfe::encode(CfeMessageType::FanoutRetryQueue, queue)
}

/// The owed copies that were kept, or none when the bytes are not that queue. A copy lost so is
/// one device without a message the others have — the same as before the queue existed.
pub fn decode_fanout_retry(kept: &[u8]) -> fanout_retry::Queue {
    cfe::decode_as(kept, CfeMessageType::FanoutRetryQueue).unwrap_or_else(|e| {
        tracing::warn!(target: "rules", "kept fan-out retry queue does not read, starting empty: {e}");
        fanout_retry::Queue::default()
    })
}

/// Read sync as bytes to keep.
pub fn encode_read_sync(state: &read_sync::State) -> Result<Vec<u8>, CfeError> {
    cfe::encode(CfeMessageType::ReadSyncState, state)
}

/// The read state that was kept, or an empty one: unread counts stay this device's own until the
/// next marker.
pub fn decode_read_sync(kept: &[u8]) -> read_sync::State {
    cfe::decode_as(kept, CfeMessageType::ReadSyncState).unwrap_or_else(|e| {
        tracing::warn!(target: "rules", "kept read sync does not read, starting empty: {e}");
        read_sync::State::default()
    })
}

/// The last intake publish as bytes to keep.
pub fn encode_intake_published(published: &intake::Published) -> Result<Vec<u8>, CfeError> {
    cfe::encode(CfeMessageType::IntakePublished, published)
}

/// The last intake publish, or `None` when the bytes are not one — the next check publishes again,
/// which is cheap.
pub fn decode_intake_published(kept: &[u8]) -> Option<intake::Published> {
    cfe::decode_as(kept, CfeMessageType::IntakePublished)
        .map_err(
            |e| tracing::info!(target: "rules", "kept intake publish marker does not read: {e}"),
        )
        .ok()
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

    /// Each state reads back as it was kept, under its own type; anything else starts empty.
    /// Mutation: write one state under another's type.
    #[test]
    fn the_batch_4_states_read_back_under_their_types() {
        let mut queue = fanout_retry::Queue::default();
        queue.enqueue("m1", "bob", "me", vec!["d1".into()], 1_000);
        let kept = encode_fanout_retry(&queue).unwrap();
        assert_eq!(
            cfe::decode(&kept).unwrap().msg_type,
            CfeMessageType::FanoutRetryQueue
        );
        assert_eq!(decode_fanout_retry(&kept), queue);

        let mut read = read_sync::State::default();
        read.note_read("bob", read_sync::Boundary::new(10, "m"));
        read.note_incoming("bob", read_sync::Boundary::new(12, "n"));
        let kept = encode_read_sync(&read).unwrap();
        assert_eq!(
            cfe::decode(&kept).unwrap().msg_type,
            CfeMessageType::ReadSyncState
        );
        assert_eq!(decode_read_sync(&kept), read);

        let published = intake::Published {
            account_id: "me".into(),
            epoch: 10,
            key_id: "k".into(),
        };
        let kept = encode_intake_published(&published).unwrap();
        assert_eq!(
            cfe::decode(&kept).unwrap().msg_type,
            CfeMessageType::IntakePublished
        );
        assert_eq!(decode_intake_published(&kept), Some(published));

        assert_eq!(decode_fanout_retry(b"[]"), fanout_retry::Queue::default());
        assert_eq!(decode_read_sync(&kept), read_sync::State::default());
        assert_eq!(decode_intake_published(b"7"), None);
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
