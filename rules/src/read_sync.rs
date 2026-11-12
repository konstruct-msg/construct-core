//! How far this account has read each chat, kept in step across its own devices
//! (construct-docs `decisions/read-state-syncs-between-own-devices.md`).
//!
//! Only between our own devices: a contact gets the delivery receipt, never this. A boundary is
//! the last read incoming message, named by what every device of ours holds alike — its id from
//! inside the ciphertext and its sender's time — never a server position, which each device's
//! mailbox numbers differently. The comparison is pinned by construct-protos
//! `conformance/knst_read_markers.json`.
//!
//! Moved here from iOS (`ReadSync.swift`, `ReadBoundaries`, `ReadSyncOutbox`) and Android
//! (`readsync/`). The count of what a marker leaves unread is Android's (owner, 2026-11-12): by the
//! position of the boundary's message when the chat holds it, by time when it does not.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A point in a chat: the sender's time, then the message id (lowercased) as bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boundary {
    pub sent_at_ms: u64,
    pub message_id: String,
}

impl Boundary {
    /// Ids are compared lowercased, as every device stores them.
    pub fn new(sent_at_ms: u64, message_id: &str) -> Self {
        Self {
            sent_at_ms,
            message_id: message_id.to_lowercase(),
        }
    }
}

/// What a received marker does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Apply,
    /// Not later than what is held.
    Ignore,
    /// Not from our own account: a contact must not be able to clear an unread count.
    Drop,
}

/// `a` strictly after `b`: a later time, or the same time and a greater id by its UTF-8 bytes.
pub fn is_later(a: &Boundary, b: &Boundary) -> bool {
    if a.sent_at_ms != b.sent_at_ms {
        return a.sent_at_ms > b.sent_at_ms;
    }
    a.message_id.as_bytes() > b.message_id.as_bytes()
}

/// An incoming message is read when it is at or before the boundary.
pub fn covers(boundary: &Boundary, message: &Boundary) -> bool {
    !is_later(message, boundary)
}

pub fn outcome(marker: &Boundary, held: Option<&Boundary>, from_own_account: bool) -> Outcome {
    if !from_own_account {
        return Outcome::Drop;
    }
    match held {
        Some(held) if !is_later(marker, held) => Outcome::Ignore,
        _ => Outcome::Apply,
    }
}

/// An incoming message as the count reads it: its id and the time this device keeps for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub message_id: String,
    pub at_ms: u64,
}

/// Of the `unread` newest of `incoming` (oldest first, as the chat orders them), how many are past
/// `boundary`. Only ever lower than `unread`.
///
/// By position when the boundary's message is here: what comes after it in the chat's order is
/// unread. When it is not (not arrived yet), by time — a device that keeps the time it received a
/// message, never earlier than its envelope's, errs toward unread rather than hiding one.
pub fn unread_left(unread: u32, incoming: &[Incoming], boundary: &Boundary) -> u32 {
    if unread == 0 {
        return 0;
    }
    let counted_from = incoming.len().saturating_sub(unread as usize);
    let at = incoming
        .iter()
        .position(|m| m.message_id.eq_ignore_ascii_case(&boundary.message_id));
    let past = match at {
        Some(at) => (counted_from..incoming.len()).filter(|&i| i > at).count(),
        None => incoming[counted_from..]
            .iter()
            .filter(|m| m.at_ms > boundary.sent_at_ms)
            .count(),
    };
    unread.min(u32::try_from(past).unwrap_or(u32::MAX))
}

/// What a client keeps of read sync: per partner (`ServerUserId`, lowercased) how far this account
/// has read the chat and the newest incoming message seen there, and the boundaries moved by
/// reading here that our other devices have not been sent yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub read: BTreeMap<String, Boundary>,
    #[serde(default)]
    pub newest_incoming: BTreeMap<String, Boundary>,
    /// Waiting to go to our other devices. Kept, so a restart before the send does not lose them.
    #[serde(default)]
    pub pending: BTreeMap<String, Boundary>,
}

impl State {
    pub fn boundary(&self, partner: &str) -> Option<&Boundary> {
        self.read.get(&partner.to_lowercase())
    }

    /// Move the boundary if `to` is later; whether it moved.
    pub fn advance(&mut self, partner: &str, to: Boundary) -> bool {
        let partner = partner.to_lowercase();
        if let Some(held) = self.read.get(&partner)
            && !is_later(&to, held)
        {
            return false;
        }
        self.read.insert(partner, to);
        true
    }

    /// Whether an incoming message from `partner` is already read on one of our devices.
    pub fn covers(&self, partner: &str, message: &Boundary) -> bool {
        self.boundary(partner).is_some_and(|b| covers(b, message))
    }

    /// An incoming message from `partner` arrived; the newest is what reading the chat reads.
    pub fn note_incoming(&mut self, partner: &str, message: Boundary) {
        let partner = partner.to_lowercase();
        if self
            .newest_incoming
            .get(&partner)
            .is_none_or(|held| is_later(&message, held))
        {
            self.newest_incoming.insert(partner, message);
        }
    }

    pub fn newest_incoming(&self, partner: &str) -> Option<&Boundary> {
        self.newest_incoming.get(&partner.to_lowercase())
    }

    /// The person read the chat with `partner` up to `boundary` here: it moves, and goes to our
    /// other devices. Whether it moved.
    pub fn note_read(&mut self, partner: &str, boundary: Boundary) -> bool {
        if !self.advance(partner, boundary.clone()) {
            return false;
        }
        self.pending.insert(partner.to_lowercase(), boundary);
        true
    }

    /// A marker from another device: applied when it is from our own account and later than what
    /// is held. The marker for our own account (a chat with ourselves) changes nothing.
    pub fn apply_marker(
        &mut self,
        partner: &str,
        marker: Boundary,
        from_own_account: bool,
        own_account: &str,
    ) -> Outcome {
        if from_own_account && partner.eq_ignore_ascii_case(own_account) {
            return Outcome::Ignore;
        }
        let result = outcome(&marker, self.boundary(partner), from_own_account);
        if result == Outcome::Apply {
            self.advance(partner, marker);
        }
        result
    }

    /// What is to be sent now; the pending set is emptied.
    pub fn take_pending(&mut self) -> BTreeMap<String, Boundary> {
        std::mem::take(&mut self.pending)
    }

    /// A send that did not go through: back into pending, unless reading moved a boundary further
    /// meanwhile.
    pub fn return_pending(&mut self, unsent: BTreeMap<String, Boundary>) {
        for (partner, boundary) in unsent {
            match self.pending.get(&partner) {
                Some(newer) if is_later(newer, &boundary) => {}
                _ => {
                    self.pending.insert(partner, boundary);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(ms: u64, id: &str) -> Boundary {
        Boundary::new(ms, id)
    }

    fn incoming(list: &[(&str, u64)]) -> Vec<Incoming> {
        list.iter()
            .map(|(id, ms)| Incoming {
                message_id: id.to_string(),
                at_ms: *ms,
            })
            .collect()
    }

    /// The vectors' rule: time first, then the id's bytes. Mutation: compare ids before times.
    #[test]
    fn later_is_time_then_id() {
        assert!(is_later(&b(2, "a"), &b(1, "z")));
        assert!(is_later(&b(1, "b"), &b(1, "a")));
        assert!(!is_later(&b(1, "a"), &b(1, "a")), "strictly");
        assert!(covers(&b(1, "a"), &b(1, "a")));
        assert_eq!(Boundary::new(1, "AbC").message_id, "abc");
    }

    /// Mutation: apply a marker from a contact.
    #[test]
    fn a_marker_from_anyone_else_is_dropped() {
        assert_eq!(outcome(&b(9, "x"), None, false), Outcome::Drop);
        assert_eq!(outcome(&b(9, "x"), None, true), Outcome::Apply);
        assert_eq!(outcome(&b(1, "x"), Some(&b(2, "y")), true), Outcome::Ignore);
    }

    /// Mutation: count by time when the boundary's message is in the chat.
    #[test]
    fn unread_left_by_position_when_the_message_is_here() {
        // The boundary's time is later than both after it — by position they are still unread.
        let rows = incoming(&[("m1", 10), ("m2", 20), ("m3", 15), ("m4", 16)]);
        assert_eq!(unread_left(3, &rows, &b(30, "m2")), 2);
    }

    /// Mutation: count by position (or nothing) when the message is not here.
    #[test]
    fn unread_left_by_time_when_it_is_not() {
        let rows = incoming(&[("m1", 10), ("m2", 20), ("m3", 30)]);
        assert_eq!(unread_left(3, &rows, &b(20, "gone")), 1);
        assert_eq!(unread_left(3, &rows, &b(5, "gone")), 3);
    }

    /// Only the `unread` newest count, and the result never rises. Mutation: count all rows.
    #[test]
    fn unread_left_only_lowers() {
        let rows = incoming(&[("m1", 10), ("m2", 20), ("m3", 30)]);
        assert_eq!(unread_left(1, &rows, &b(0, "gone")), 1);
        assert_eq!(unread_left(0, &rows, &b(0, "gone")), 0);
        // An older row past the boundary is not among the unread newest and does not count.
        let late_old = incoming(&[("m1", 30), ("m2", 10), ("m3", 10)]);
        assert_eq!(unread_left(2, &late_old, &b(20, "gone")), 0);
        assert_eq!(
            unread_left(2, &rows, &b(0, "M1")),
            2,
            "ids match in any case"
        );
    }

    /// Mutation: let `advance` move backwards.
    #[test]
    fn a_boundary_only_moves_forward() {
        let mut s = State::default();
        assert!(s.advance("Bob", b(10, "m")));
        assert!(!s.advance("bob", b(5, "m")));
        assert_eq!(s.boundary("BOB"), Some(&b(10, "m")));
        assert!(s.covers("bob", &b(10, "m")));
        assert!(!s.covers("bob", &b(11, "m")));
    }

    /// Mutation: queue a read that did not move the boundary.
    #[test]
    fn reading_here_goes_out_once_it_moves() {
        let mut s = State::default();
        assert!(s.note_read("bob", b(10, "m")));
        assert!(!s.note_read("bob", b(10, "m")));
        let sent = s.take_pending();
        assert_eq!(sent.len(), 1);
        assert!(s.pending.is_empty());
    }

    /// Mutation: put back over a newer pending boundary.
    #[test]
    fn an_unsent_marker_comes_back_unless_reading_moved_on() {
        let mut s = State::default();
        s.note_read("bob", b(10, "m"));
        s.note_read("ann", b(10, "m"));
        let unsent = s.take_pending();
        s.note_read("bob", b(20, "n"));
        s.return_pending(unsent);
        assert_eq!(s.pending.get("bob"), Some(&b(20, "n")));
        assert_eq!(s.pending.get("ann"), Some(&b(10, "m")));
    }

    /// Mutation: skip the own-account check.
    #[test]
    fn markers_apply_from_our_account_only_and_not_for_ourselves() {
        let mut s = State::default();
        assert_eq!(
            s.apply_marker("bob", b(10, "m"), false, "me"),
            Outcome::Drop
        );
        assert_eq!(s.boundary("bob"), None);
        assert_eq!(
            s.apply_marker("ME", b(10, "m"), true, "me"),
            Outcome::Ignore
        );
        assert_eq!(
            s.apply_marker("bob", b(10, "m"), true, "me"),
            Outcome::Apply
        );
        assert_eq!(s.boundary("bob"), Some(&b(10, "m")));
        assert_eq!(
            s.apply_marker("bob", b(9, "m"), true, "me"),
            Outcome::Ignore
        );
    }

    /// Mutation: keep the first incoming instead of the newest.
    #[test]
    fn the_newest_incoming_is_kept() {
        let mut s = State::default();
        s.note_incoming("bob", b(10, "a"));
        s.note_incoming("bob", b(5, "z"));
        s.note_incoming("bob", b(12, "b"));
        assert_eq!(s.newest_incoming("Bob"), Some(&b(12, "b")));
    }
}
