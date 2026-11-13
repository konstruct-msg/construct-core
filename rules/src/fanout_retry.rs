//! Devices of a recipient still owed their copy of a message the sender already calls sent.
//!
//! A message goes to each device of the recipient as its own copy; when some take it and some do
//! not, the row says "sent" and a receipt from any device says "delivered", while the others never
//! see the message. This queue keeps those devices and when to try them again.
//!
//! **Identifiers only, never a payload**: the retry rebuilds the copy from the message's row, as a
//! resend after a decryption error does. Storing bodies would put messages at rest in plain.
//!
//! **The owed set.** Empty means *plan again*: the bundle fetch that would have named the devices
//! is what failed, nothing was sent, so the whole fan-out runs again. Non-empty is the opposite —
//! the plan named devices and some of them did not take their copy — and only those are retried:
//! a second copy to a device that has the message puts two ciphertexts of it through one ratchet
//! and shows it twice. Android never queues an empty set (its send that reached no device is
//! "not sent" and the person retries it), so for it the set is never empty.
//!
//! Five attempts, the first wait 30 s, doubling to an hour; an entry lives a day from when it was
//! first queued, and failing again does not extend it. The cap exists because a device gone for
//! good is indistinguishable here from one briefly offline, and each attempt to a device without a
//! session spends one of its one-time prekeys.
//!
//! The queue is written to disappear once a message names its sending device on the wire (§D of
//! the multi-device plan): every copy is then retried by the machinery that retries the first.
//! Moved here from iOS (`FanoutRetryQueue.swift`, the canon) and Android (`FanoutRetryQueue.kt`).

use serde::{Deserialize, Serialize};

pub const MAX_ATTEMPTS: u32 = 5;
pub const BASE_BACKOFF_MS: i64 = 30_000;
pub const MAX_BACKOFF_MS: i64 = 3_600_000;
pub const ENTRY_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// One message to one recipient, and the devices of theirs still owed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub base_message_id: String,
    pub recipient_user_id: String,
    pub sender_user_id: String,
    /// Sorted, without repeats. Empty: plan again.
    pub owed_device_ids: Vec<String>,
    pub attempts: u32,
    pub next_attempt_at_ms: i64,
    pub created_at_ms: i64,
}

impl Entry {
    /// What the entry is found by: the message and its recipient.
    pub fn key(&self) -> String {
        key(&self.base_message_id, &self.recipient_user_id)
    }

    fn live(&self, now_ms: i64) -> bool {
        now_ms.saturating_sub(self.created_at_ms) < ENTRY_TTL_MS
    }
}

pub fn key(base_message_id: &str, recipient_user_id: &str) -> String {
    format!("{base_message_id}|{recipient_user_id}")
}

fn sorted_unique(ids: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut ids: Vec<String> = ids.into_iter().collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The owed copies a client keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queue {
    #[serde(default)]
    pub entries: Vec<Entry>,
}

impl Queue {
    /// `owed` devices of `recipient` still need their copy of `base_message_id`.
    ///
    /// A second enqueue of the same message merges: two chunks of one message can fail apart, and
    /// the second must not erase what the first recorded. The age and attempts stay, so a message
    /// cannot extend its own life by failing again. An empty `owed` on an entry that already names
    /// devices does not widen it back to "plan again": the named set is the more precise one.
    pub fn enqueue(
        &mut self,
        base_message_id: &str,
        recipient_user_id: &str,
        sender_user_id: &str,
        owed: Vec<String>,
        now_ms: i64,
    ) {
        if base_message_id.is_empty() || recipient_user_id.is_empty() {
            return;
        }
        let key = key(base_message_id, recipient_user_id);
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key() == key) {
            if !owed.is_empty() {
                let merged = entry.owed_device_ids.drain(..).chain(owed);
                entry.owed_device_ids = sorted_unique(merged);
            }
            return;
        }
        self.entries.push(Entry {
            base_message_id: base_message_id.to_string(),
            recipient_user_id: recipient_user_id.to_string(),
            sender_user_id: sender_user_id.to_string(),
            owed_device_ids: sorted_unique(owed),
            attempts: 0,
            next_attempt_at_ms: now_ms.saturating_add(BASE_BACKOFF_MS),
            created_at_ms: now_ms,
        });
    }

    /// One attempt spent, before it is made — a pass cut short must not leave the count where it
    /// was. The entry afterwards, or `None` once it is exhausted and removed, so a give-up is
    /// counted once. The wait after the n-th attempt is 30 s · 2ⁿ, at most an hour.
    pub fn record_attempt(&mut self, key: &str, now_ms: i64) -> Option<Entry> {
        let index = self.entries.iter().position(|e| e.key() == key)?;
        let attempts = self.entries[index].attempts + 1;
        if attempts >= MAX_ATTEMPTS {
            self.entries.remove(index);
            return None;
        }
        let backoff = BASE_BACKOFF_MS
            .checked_shl(attempts)
            .unwrap_or(MAX_BACKOFF_MS)
            .min(MAX_BACKOFF_MS);
        let entry = &mut self.entries[index];
        entry.attempts = attempts;
        entry.next_attempt_at_ms = now_ms.saturating_add(backoff);
        Some(entry.clone())
    }

    /// Narrow an entry to exactly the devices a retry just lost — not a union, which would leave a
    /// "plan again" entry empty and send a second copy to the device that took the first. Nothing
    /// left removes the entry: empty here would mean "plan again".
    pub fn replace_owed(&mut self, key: &str, owed: Vec<String>) {
        if owed.is_empty() {
            self.remove(key);
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key() == key) {
            entry.owed_device_ids = sorted_unique(owed);
        }
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|e| e.key() != key);
    }

    /// Every owed copy dropped: the queue was an account's that no longer signs in here.
    pub fn remove_all(&mut self) {
        self.entries.clear();
    }

    /// Entries whose wait is over, oldest first. Expired ones are dropped on the way, so a queue
    /// nobody drains cannot grow without bound.
    pub fn due(&mut self, now_ms: i64) -> Vec<Entry> {
        self.entries.retain(|e| e.live(now_ms));
        let mut due: Vec<Entry> = self
            .entries
            .iter()
            .filter(|e| e.next_attempt_at_ms <= now_ms)
            .cloned()
            .collect();
        due.sort_by_key(|e| e.created_at_ms);
        due
    }

    /// When the next live entry comes due; `None` when nothing is owed. What a drain is
    /// scheduled by.
    pub fn next_due(&self, now_ms: i64) -> Option<i64> {
        self.entries
            .iter()
            .filter(|e| e.live(now_ms))
            .map(|e| e.next_attempt_at_ms)
            .min()
    }
}

#[cfg(test)]
mod tests {
    //! The cases of iOS `FanoutRetryQueueTests` and Android `FanoutRetryQueueTest`; each names the
    //! mutation that reddens it.
    use super::*;

    const T: i64 = 1_000_000;

    fn devices(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn queue_with(owed: &[&str]) -> Queue {
        let mut q = Queue::default();
        q.enqueue("m1", "bob", "me", devices(owed), T);
        q
    }

    /// Mutation: start the first wait at 0 — the entry is due at once.
    #[test]
    fn a_new_entry_waits_thirty_seconds() {
        let mut q = queue_with(&["d1"]);
        assert!(q.due(T + BASE_BACKOFF_MS - 1).is_empty());
        assert_eq!(q.due(T + BASE_BACKOFF_MS).len(), 1);
        assert_eq!(q.next_due(T), Some(T + BASE_BACKOFF_MS));
    }

    /// Mutation: replace the set instead of merging — the first chunk's device is lost.
    #[test]
    fn a_second_enqueue_merges_and_keeps_the_age() {
        let mut q = queue_with(&["d2"]);
        q.record_attempt("m1|bob", T);
        q.enqueue("m1", "bob", "me", devices(&["d1"]), T + 500);
        let e = &q.entries[0];
        assert_eq!(e.owed_device_ids, devices(&["d1", "d2"]));
        assert_eq!((e.created_at_ms, e.attempts), (T, 1));
    }

    /// Mutation: let an empty set overwrite a named one — the next pass plans again and sends a
    /// second copy to devices that have it.
    #[test]
    fn an_empty_set_does_not_widen_a_named_one() {
        let mut q = queue_with(&["d1"]);
        q.enqueue("m1", "bob", "me", Vec::new(), T);
        assert_eq!(q.entries[0].owed_device_ids, devices(&["d1"]));
    }

    #[test]
    fn an_empty_set_is_kept_as_plan_again() {
        let q = queue_with(&[]);
        assert!(q.entries[0].owed_device_ids.is_empty());
    }

    #[test]
    fn no_id_or_no_recipient_is_not_an_entry() {
        let mut q = Queue::default();
        q.enqueue("", "bob", "me", devices(&["d1"]), T);
        q.enqueue("m1", "", "me", devices(&["d1"]), T);
        assert!(q.entries.is_empty());
    }

    /// The waits after attempts 1–4: 30 s · 2ⁿ. With five attempts the hour cap is never reached;
    /// it is there for a larger count. Mutation: no doubling.
    #[test]
    fn the_wait_doubles() {
        let mut q = queue_with(&["d1"]);
        let waits: Vec<i64> = (0..4)
            .map(|_| q.record_attempt("m1|bob", T).unwrap().next_attempt_at_ms - T)
            .collect();
        assert_eq!(waits, vec![60_000, 120_000, 240_000, 480_000]);
    }

    /// Mutation: give up one attempt later — a device gone for good spends another prekey.
    #[test]
    fn the_fifth_attempt_removes_the_entry() {
        let mut q = queue_with(&["d1"]);
        for _ in 0..MAX_ATTEMPTS - 1 {
            assert!(q.record_attempt("m1|bob", T).is_some());
        }
        assert!(q.record_attempt("m1|bob", T).is_none());
        assert!(q.entries.is_empty());
    }

    /// Mutation: union in `replace_owed` — the device that took its copy gets another.
    #[test]
    fn a_retry_narrows_to_what_it_lost() {
        let mut q = queue_with(&["d1", "d2"]);
        q.replace_owed("m1|bob", devices(&["d2"]));
        assert_eq!(q.entries[0].owed_device_ids, devices(&["d2"]));
        q.replace_owed("m1|bob", Vec::new());
        assert!(q.entries.is_empty(), "nothing lost: done, not plan again");
    }

    /// The day is the clients' rule (iOS `FanoutRetryQueue.swift` kept 24 h, matching its wire-payload
    /// store), so it is pinned
    /// by value: the test below counts from the constant and would follow a wrong one.
    #[test]
    fn the_entry_lifetime_is_a_day() {
        assert_eq!(ENTRY_TTL_MS, 86_400_000);
    }

    /// Mutation: compare the age with `<=` the day, or drop the expiry.
    #[test]
    fn an_entry_lives_a_day() {
        let mut q = queue_with(&["d1"]);
        assert_eq!(q.due(T + ENTRY_TTL_MS - 1).len(), 1);
        assert!(q.due(T + ENTRY_TTL_MS).is_empty());
        assert!(
            q.entries.is_empty(),
            "the expired entry is dropped on the way"
        );
        assert_eq!(q.next_due(T + ENTRY_TTL_MS), None);
    }

    /// Mutation: sort by the next attempt instead of the age.
    #[test]
    fn due_entries_come_oldest_first() {
        let mut q = Queue::default();
        q.enqueue("old", "bob", "me", devices(&["d1"]), T);
        q.enqueue("new", "bob", "me", devices(&["d1"]), T + 10);
        q.entries[0].next_attempt_at_ms = T + 40_000;
        q.entries[1].next_attempt_at_ms = T + 35_000;
        let ids: Vec<String> = q
            .due(T + 50_000)
            .into_iter()
            .map(|e| e.base_message_id)
            .collect();
        assert_eq!(ids, vec!["old".to_string(), "new".to_string()]);
    }

    #[test]
    fn remove_and_remove_all() {
        let mut q = queue_with(&["d1"]);
        q.enqueue("m2", "bob", "me", devices(&["d1"]), T);
        q.remove("m1|bob");
        assert_eq!(q.entries.len(), 1);
        q.remove_all();
        assert!(q.entries.is_empty());
    }
}
