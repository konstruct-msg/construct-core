//! The position this device resumes its message stream from.
//!
//! A client sends it as `since_cursor` when it subscribes or fetches, and the server trims its
//! offline queue up to it: whatever is at or before the cursor is deleted. So **the cursor never
//! moves past a message that has not reached a durable end** — kept, a control fully handled, or
//! given up for good. A message that is only waiting (behind a session the core is opening, or a
//! retry) holds it; if the cursor passed it and the app died, the message would be gone from both
//! sides with no error anywhere.
//!
//! Entries are kept in the order they arrived. The cursor moves over the longest run of resolved
//! entries at the front, never over a pending or deferred one. A missed resolution is a stall —
//! the server delivers again from the cursor, the client drops what it already has — never a loss.
//! The stall clears on the next connection, which starts tracking afresh.
//!
//! Moved here from three copies (construct-docs `decisions/client-rules-shared-in-rust.md`): iOS
//! (`StreamCursorTracker.swift`, the canon since 2026-06-16), Android (its port), and
//! construct-client, whose copy kept a map from message to cursor and committed the cursor of
//! whichever message finished last — past one still waiting for its session.

use std::collections::VecDeque;

/// How the pipeline ended with a tracked message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Durably handled: kept, a control applied, or given up for good.
    Durable,
    /// Waiting (behind a session the core is opening, or a retry): holds the cursor until it is
    /// resolved.
    Deferred,
    /// Not this caller's to decide (a copy already in flight elsewhere): leaves the entry as it is.
    Skip,
}

/// Why the entry at the front is holding the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    /// Arrived, nothing reported yet.
    Pending,
    /// Reported waiting.
    Deferred,
}

/// The entry holding the cursor back — for the log line that names a stall, so a stuck head is
/// seen rather than inferred from a redelivery count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocker {
    pub message_id: String,
    pub hold: Hold,
    pub tracked_at_ms: i64,
}

/// What [`Tracker::skip_held_backlog`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The cursor now committed: the furthest one delivered on this connection.
    pub cursor: String,
    /// How many entries were abandoned.
    pub held: u32,
    /// The entry that was holding them.
    pub head: Option<Blocker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Deferred,
    Resolved,
}

#[derive(Debug, Clone)]
struct Entry {
    message_id: String,
    cursor: String,
    state: State,
    tracked_at_ms: i64,
}

/// The entries of one connection and the last cursor committed on it. Not kept: the committed
/// cursor is what a client stores, and a new connection starts here empty.
#[derive(Debug, Clone, Default)]
pub struct Tracker {
    entries: VecDeque<Entry>,
    committed: Option<String>,
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// A new connection. The stored cursor is where it resumes; whatever had not moved it is
    /// delivered again and tracked again.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.committed = None;
    }

    /// A stream entry, in the order it arrived and before it is handled. The same message again
    /// keeps its first place and cursor; an empty id or cursor is not an entry.
    pub fn track(&mut self, message_id: &str, cursor: &str, now_ms: i64) {
        if message_id.is_empty() || cursor.is_empty() {
            return;
        }
        if self.entries.iter().any(|e| e.message_id == message_id) {
            return;
        }
        self.entries.push_back(Entry {
            message_id: message_id.to_string(),
            cursor: cursor.to_string(),
            state: State::Pending,
            tracked_at_ms: now_ms,
        });
    }

    /// A frame with nothing to keep (a receipt, an envelope dropped on arrival) still takes its
    /// place in line, so its cursor cannot move past an earlier message that is still held. The
    /// cursor stands as its id. Returns the cursor to store, if it moved.
    pub fn track_resolved(&mut self, cursor: &str, now_ms: i64) -> Option<String> {
        self.track(cursor, cursor, now_ms);
        self.resolve(cursor)
    }

    /// How a tracked message ended. Returns the cursor to store when it moved; `None` for an
    /// untracked id (a fetched message carries no stream cursor) or when it did not move.
    pub fn report(&mut self, message_id: &str, outcome: Outcome) -> Option<String> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.message_id == message_id)?;
        match outcome {
            Outcome::Durable => entry.state = State::Resolved,
            Outcome::Deferred => {
                if entry.state == State::Pending {
                    entry.state = State::Deferred;
                }
            }
            Outcome::Skip => {}
        }
        self.advance()
    }

    /// A message finished — a waiting one drained and kept, or given up. `report(Durable)`.
    pub fn resolve(&mut self, message_id: &str) -> Option<String> {
        self.report(message_id, Outcome::Durable)
    }

    fn advance(&mut self) -> Option<String> {
        let mut moved = None;
        while self
            .entries
            .front()
            .is_some_and(|e| e.state == State::Resolved)
        {
            moved = self.entries.pop_front().map(|e| e.cursor);
        }
        let cursor = moved?;
        if self.committed.as_deref() == Some(cursor.as_str()) {
            return None;
        }
        self.committed = Some(cursor.clone());
        Some(cursor)
    }

    /// Abandon everything held and commit the furthest cursor delivered on this connection.
    ///
    /// **This breaks the rule above, and it is the only thing here that does**: whatever was held
    /// is trimmed on the server without having been kept. So nothing calls it on its own — no
    /// timer, no heuristic. It is a person's explicit action, worded as what it is, for the head
    /// nothing will ever resolve: on 2026-08-20 an iOS device resumed from 31 July for three weeks
    /// behind a message from a deleted account, and the only other way out was reinstalling,
    /// which loses the identity too.
    pub fn skip_held_backlog(&mut self) -> Option<Skipped> {
        let cursor = self.entries.back()?.cursor.clone();
        let head = self.head_blocker();
        let held = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        self.entries.clear();
        self.committed = Some(cursor.clone());
        Some(Skipped { cursor, held, head })
    }

    /// The entry holding the cursor back, if any.
    pub fn head_blocker(&self) -> Option<Blocker> {
        let head = self.entries.front()?;
        let hold = match head.state {
            State::Pending => Hold::Pending,
            State::Deferred => Hold::Deferred,
            State::Resolved => return None,
        };
        Some(Blocker {
            message_id: head.message_id.clone(),
            hold,
            tracked_at_ms: head.tracked_at_ms,
        })
    }

    /// Entries still held: pending, deferred, or resolved behind one that is not.
    pub fn in_flight(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    //! Each case below was a test on iOS (`StreamCursorTrackerTests`, `StreamCursorSkipTests`) or
    //! Android (`StreamCursorTrackerTest`); the mutation that reddens it is named.
    use super::*;

    /// Tracks `ids` with cursors `1-0`, `2-0`, … in that order.
    fn tracking(ids: &[&str]) -> Tracker {
        let mut t = Tracker::new();
        for (i, id) in ids.iter().enumerate() {
            t.track(id, &format!("{}-0", i + 1), 100 + i as i64);
        }
        t
    }

    #[test]
    fn resolved_in_order_the_cursor_moves_each_time() {
        let mut t = tracking(&["a", "b", "c"]);
        assert_eq!(t.resolve("a").as_deref(), Some("1-0"));
        assert_eq!(t.resolve("b").as_deref(), Some("2-0"));
        assert_eq!(t.resolve("c").as_deref(), Some("3-0"));
        assert_eq!(t.in_flight(), 0);
    }

    /// Only the run at the front moves it.
    #[test]
    fn a_later_entry_resolved_first_waits_for_the_front() {
        let mut t = tracking(&["a", "b", "c"]);
        assert_eq!(t.resolve("c"), None);
        assert_eq!(t.resolve("b"), None);
        assert_eq!(
            t.resolve("a").as_deref(),
            Some("3-0"),
            "the whole run at once"
        );
        assert_eq!(t.in_flight(), 0);
    }

    /// The loss this exists for: a message waiting for its session, then a later one kept. The
    /// cursor stays behind the waiting one. Mutation: treat `Deferred` as `Durable`.
    #[test]
    fn a_deferred_message_holds_the_cursor() {
        let mut t = tracking(&["a", "b"]);
        assert_eq!(t.report("a", Outcome::Deferred), None);
        assert_eq!(t.report("b", Outcome::Durable), None);
        assert_eq!(t.head_blocker().map(|b| b.hold), Some(Hold::Deferred));
        assert_eq!(t.resolve("a").as_deref(), Some("2-0"));
    }

    /// A receipt (nothing to keep) after a waiting message does not move the cursor past it.
    /// Mutation: `track_resolved` commits its cursor directly — construct-client's
    /// `commit_direct` before this rule.
    #[test]
    fn a_receipt_does_not_jump_a_waiting_message() {
        let mut t = Tracker::new();
        t.track("msgA", "10-0", 1);
        t.report("msgA", Outcome::Deferred);
        assert_eq!(t.track_resolved("11-0", 2), None);
        assert_eq!(t.resolve("msgA").as_deref(), Some("11-0"));
    }

    /// With nothing held, a receipt moves the cursor itself.
    #[test]
    fn a_receipt_alone_moves_the_cursor() {
        let mut t = Tracker::new();
        assert_eq!(t.track_resolved("7-0", 1).as_deref(), Some("7-0"));
        assert_eq!(t.in_flight(), 0);
    }

    /// Mutation: `Skip` resolves the entry.
    #[test]
    fn skip_leaves_the_entry_where_it_is() {
        let mut t = tracking(&["a"]);
        assert_eq!(t.report("a", Outcome::Skip), None);
        assert_eq!(t.in_flight(), 1);
        assert_eq!(t.head_blocker().map(|b| b.hold), Some(Hold::Pending));
        assert_eq!(t.resolve("a").as_deref(), Some("1-0"));
    }

    /// A `Deferred` report after the entry was resolved does not take it back.
    /// Mutation: set `Deferred` whatever the state.
    #[test]
    fn deferred_does_not_undo_a_resolution() {
        let mut t = tracking(&["a", "b"]);
        t.resolve("b");
        t.report("b", Outcome::Deferred);
        assert_eq!(t.resolve("a").as_deref(), Some("2-0"));
    }

    #[test]
    fn an_untracked_id_changes_nothing() {
        let mut t = Tracker::new();
        assert_eq!(t.report("ghost", Outcome::Durable), None);
        assert_eq!(t.resolve("ghost"), None);
        assert_eq!(t.in_flight(), 0);
    }

    /// Mutation: drop the duplicate check — the second cursor replaces or follows the first.
    #[test]
    fn the_same_message_again_keeps_its_first_place() {
        let mut t = Tracker::new();
        t.track("a", "1-0", 1);
        t.track("a", "9-0", 2);
        assert_eq!(t.in_flight(), 1);
        assert_eq!(t.resolve("a").as_deref(), Some("1-0"));
    }

    /// Mutation: drop the empty check.
    #[test]
    fn an_empty_id_or_cursor_is_not_an_entry() {
        let mut t = Tracker::new();
        t.track("", "1-0", 1);
        t.track("a", "", 1);
        assert_eq!(t.in_flight(), 0);
    }

    #[test]
    fn reset_drops_what_was_held() {
        let mut t = tracking(&["a"]);
        t.reset();
        assert_eq!(t.in_flight(), 0);
        assert_eq!(
            t.resolve("a"),
            None,
            "the next connection delivers it again"
        );
    }

    /// Mutation: drop the "same as committed" check — the cursor is stored twice.
    #[test]
    fn the_same_cursor_is_not_stored_twice() {
        let mut t = Tracker::new();
        assert_eq!(t.track_resolved("5-0", 1).as_deref(), Some("5-0"));
        assert_eq!(t.track_resolved("5-0", 2), None);
    }

    /// The head names itself, with when it arrived.
    #[test]
    fn the_head_names_itself() {
        let mut t = tracking(&["stuck", "b"]);
        t.resolve("b");
        assert_eq!(
            t.head_blocker(),
            Some(Blocker {
                message_id: "stuck".into(),
                hold: Hold::Pending,
                tracked_at_ms: 100,
            })
        );
    }

    /// Mutation: commit the front entry's cursor instead of the furthest delivered.
    #[test]
    fn skipping_commits_the_furthest_delivered_cursor() {
        let mut t = tracking(&["stuck", "b", "c"]);
        t.report("stuck", Outcome::Deferred);
        let skipped = t.skip_held_backlog().unwrap();
        assert_eq!(skipped.cursor, "3-0");
        assert_eq!(skipped.held, 3);
        assert_eq!(skipped.head.map(|b| b.hold), Some(Hold::Deferred));
        assert_eq!(t.in_flight(), 0);
    }

    #[test]
    fn skipping_with_nothing_held_does_nothing() {
        let mut t = Tracker::new();
        assert_eq!(t.skip_held_backlog(), None);
    }

    /// Resolved entries at the front were committed already; the skip goes forward from there.
    #[test]
    fn skipping_never_moves_the_cursor_back() {
        let mut t = tracking(&["a", "stuck", "c"]);
        assert_eq!(t.resolve("a").as_deref(), Some("1-0"));
        assert_eq!(t.skip_held_backlog().unwrap().cursor, "3-0");
    }

    /// After a skip the tracker works as before, so the next stall can be seen.
    #[test]
    fn after_a_skip_it_tracks_as_before() {
        let mut t = tracking(&["stuck"]);
        t.skip_held_backlog();
        t.track("fresh", "8-0", 5);
        assert_eq!(t.resolve("fresh").as_deref(), Some("8-0"));
        assert_eq!(t.head_blocker(), None);
    }
}
