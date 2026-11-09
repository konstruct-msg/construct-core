//! Messages the server's queue trimmed before this device collected them.
//!
//! The queue keeps a device's mailbox for a limited time and count; what it trims after the
//! cursor this device reads from is gone. The server says so on the stream and on a fetch
//! (`MailboxGap { after_cursor, resumes_at }`), and the person is told with one notice above the
//! chat list until they close it (construct-docs `decisions/mailbox-gap-is-reported.md`). Whose
//! messages they were nobody knows: the server knows only the interval. Nothing is refetched.
//!
//! The notice keeps the reports it was made of, not just their dates. The server reports again on
//! every stream it opens until the cursor moves, and the cursor does not move while the mailbox
//! holds nothing to deliver. A report the person already closed is the same loss, named by the
//! same cursors, and does not raise the notice again. Kept only as dates, a closed notice came
//! back on every connection (iOS and Android until 2026-11-09, todo 290).
//!
//! Moved here from construct-client (`mailbox_gap.rs`), where it was right first.

use serde::{Deserialize, Serialize};

/// One report as the server made it: the cursor this device read from, and the oldest position
/// still held (empty when nothing is).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub after_cursor: String,
    pub resumes_at: String,
}

/// What the notice says: messages sent from `from_ms` to `until_ms` (Unix ms) may not have
/// arrived; `until_ms` is `None` when the mailbox held nothing to resume from ("since …").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    pub from_ms: i64,
    pub until_ms: Option<i64>,
}

/// The notice as a client keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// Reported and not yet closed.
    #[serde(default)]
    pub open: Vec<Report>,
    /// Closed by the person: these again are not a new loss.
    #[serde(default)]
    pub closed: Vec<Report>,
}

impl Notice {
    /// Take a report in. Whether the notice changed: a report already open or already closed,
    /// or one whose cursor names no moment, changes nothing.
    pub fn record(&mut self, report: Report) -> bool {
        if moment(&report.after_cursor).is_none()
            || self.open.contains(&report)
            || self.closed.contains(&report)
        {
            return false;
        }
        self.open.push(report);
        true
    }

    /// The person closed the notice. Only the reports it showed are remembered as seen: the
    /// cursor never goes back, so older closed ones cannot be reported again.
    pub fn close(&mut self) {
        self.closed = std::mem::take(&mut self.open);
    }

    /// What is shown: one interval as wide as every open report, open-ended if any of them is.
    pub fn interval(&self) -> Option<Interval> {
        let from_ms = self
            .open
            .iter()
            .filter_map(|r| moment(&r.after_cursor))
            .min()?;
        let mut until_ms = Some(i64::MIN);
        for report in &self.open {
            until_ms = match (until_ms, moment(&report.resumes_at)) {
                (Some(until), Some(resumes)) => Some(until.max(resumes)),
                _ => None,
            };
        }
        Some(Interval { from_ms, until_ms })
    }
}

/// A stream cursor `ms-seq` (or bare `ms`) as the moment it names, Unix ms; `None` otherwise.
pub fn moment(cursor: &str) -> Option<i64> {
    let ms = cursor.split_once('-').map_or(cursor, |(ms, _)| ms);
    ms.parse::<u64>().ok().and_then(|ms| i64::try_from(ms).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(after: &str, resumes: &str) -> Report {
        Report {
            after_cursor: after.into(),
            resumes_at: resumes.into(),
        }
    }

    #[test]
    fn a_cursor_names_its_moment() {
        assert_eq!(moment("1700000000000-3"), Some(1_700_000_000_000));
        assert_eq!(moment("1700000000500"), Some(1_700_000_000_500));
        assert_eq!(moment("not-a-cursor"), None);
        assert_eq!(moment(""), None);
        assert_eq!(moment("-1-0"), None);
    }

    #[test]
    fn nothing_held_is_an_open_interval() {
        let mut notice = Notice::default();
        assert!(notice.record(report("1700000000000-0", "")));
        assert_eq!(
            notice.interval(),
            Some(Interval {
                from_ms: 1_700_000_000_000,
                until_ms: None
            })
        );
    }

    #[test]
    fn a_report_without_a_start_is_no_notice() {
        let mut notice = Notice::default();
        assert!(!notice.record(report("garbage", "1700000000000-0")));
        assert_eq!(notice.interval(), None);
    }

    /// Several reports (two reconnects, a fetch and the stream) are one notice, as wide as all
    /// of them.
    #[test]
    fn reports_widen_the_one_notice() {
        let mut notice = Notice::default();
        notice.record(report("200-0", "300-0"));
        notice.record(report("100-0", "250-0"));
        assert_eq!(
            notice.interval(),
            Some(Interval {
                from_ms: 100,
                until_ms: Some(300)
            })
        );
        notice.record(report("150-0", ""));
        assert_eq!(
            notice.interval().unwrap().until_ms,
            None,
            "an open report keeps the notice open"
        );
    }

    #[test]
    fn the_same_report_again_changes_nothing() {
        let mut notice = Notice::default();
        assert!(notice.record(report("100-0", "")));
        assert!(!notice.record(report("100-0", "")));
        assert_eq!(notice.open.len(), 1);
    }

    /// The server reports on every stream until the cursor moves, and with nothing held it does
    /// not move: a closed notice stays closed for the same report, and opens for a new one.
    #[test]
    fn a_closed_report_does_not_come_back_but_a_new_one_does() {
        let mut notice = Notice::default();
        notice.record(report("100-0", ""));
        notice.close();
        assert_eq!(notice.interval(), None);
        assert!(!notice.record(report("100-0", "")), "the same loss, seen");
        assert_eq!(notice.interval(), None);
        assert!(
            notice.record(report("100-0", "400-0")),
            "a different report is shown: an over-report at worst"
        );
        assert!(notice.record(report("500-0", "")), "a later cursor");
        assert_eq!(
            notice.interval(),
            Some(Interval {
                from_ms: 100,
                until_ms: None
            })
        );
    }

    /// Closing twice remembers only what the second close showed: the cursor never goes back.
    #[test]
    fn a_second_close_keeps_what_it_closed() {
        let mut notice = Notice::default();
        notice.record(report("100-0", ""));
        notice.close();
        notice.record(report("500-0", ""));
        notice.close();
        assert_eq!(notice.closed, vec![report("500-0", "")]);
        assert!(notice.open.is_empty());
    }
}
