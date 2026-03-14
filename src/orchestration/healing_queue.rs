/// Session healing queue — Rust port of Swift `SessionHealingService`.
///
/// When a Double Ratchet session desynchronises (typically detected by a
/// decryption failure on message number 0), the receiver queues the message
/// for replay after a fresh session is negotiated.
///
/// Rules:
/// - Only `msg_number == 0` can trigger healing.
/// - Maximum 3 retry attempts per contact before giving up.
/// - Records expire after 24 hours (TTL).
/// - Enqueue is idempotent: a second call for the same contact replaces the
///   existing record rather than creating a duplicate.
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::orchestration::actions::Action;

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_MAX_ATTEMPTS: u32 = 3;
const DEFAULT_TTL_SECONDS: u64 = 24 * 60 * 60; // 24 hours

// ── Public types ──────────────────────────────────────────────────────────────

/// Decision returned by `record_attempt`.
#[derive(Debug, Clone, PartialEq)]
pub enum HealingDecision {
    /// Healing may proceed; `attempt` is the 1-based attempt index.
    RetryAllowed { attempt: u32 },
    /// Maximum attempts exhausted — the caller should send END_SESSION.
    MaxAttemptsReached,
    /// No healing record exists for this contact.
    NotFound,
}

/// A queued healing record for a single contact.
#[derive(Debug, Clone)]
pub struct HealingRecord {
    pub contact_id: String,
    /// JSON-serialised original message (stored for replay after re-key).
    pub message_json: String,
    pub attempts: u32,
    pub created_at: u64,
}

// ── HealingQueue ──────────────────────────────────────────────────────────────

pub struct HealingQueue {
    records: HashMap<String, HealingRecord>,
    max_attempts: u32,
    ttl_seconds: u64,
}

impl HealingQueue {
    pub fn new(max_attempts: u32, ttl_seconds: u64) -> Self {
        Self {
            records: HashMap::new(),
            max_attempts,
            ttl_seconds,
        }
    }

    /// Default configuration matching the Swift implementation.
    pub fn default() -> Self {
        Self::new(DEFAULT_MAX_ATTEMPTS, DEFAULT_TTL_SECONDS)
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Returns `true` if `msg_number == 0` — the only case that warrants healing.
    ///
    /// This mirrors Swift's `canHeal(messageNumber:)` check.
    pub fn can_heal(msg_number: u32) -> bool {
        msg_number == 0
    }

    /// Return the healing record for `contact_id` if one exists.
    pub fn get(&self, contact_id: &str) -> Option<&HealingRecord> {
        self.records.get(contact_id)
    }

    /// `true` if a record exists for `contact_id`.
    pub fn has_pending(&self, contact_id: &str) -> bool {
        self.records.contains_key(contact_id)
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Enqueue a message for healing (idempotent).
    ///
    /// If a record already exists for `contact_id`, it is replaced. Returns
    /// `Action`s requesting the platform to persist the record.
    pub fn enqueue(&mut self, contact_id: &str, message_json: &str) -> Vec<Action> {
        let now = unix_now();
        let record = HealingRecord {
            contact_id: contact_id.to_string(),
            message_json: message_json.to_string(),
            attempts: 0,
            created_at: now,
        };
        self.records.insert(contact_id.to_string(), record);

        let json = format!(
            r#"{{"contact_id":"{}","created_at":{},"attempts":0}}"#,
            contact_id.replace('"', "\\\""),
            now
        );
        vec![Action::PersistMessage { message_json: json }]
    }

    /// Increment the attempt counter for `contact_id`.
    ///
    /// Returns a `HealingDecision` indicating whether another attempt is allowed.
    pub fn record_attempt(&mut self, contact_id: &str) -> HealingDecision {
        match self.records.get_mut(contact_id) {
            None => HealingDecision::NotFound,
            Some(record) => {
                record.attempts += 1;
                if record.attempts >= self.max_attempts {
                    HealingDecision::MaxAttemptsReached
                } else {
                    HealingDecision::RetryAllowed {
                        attempt: record.attempts,
                    }
                }
            }
        }
    }

    /// Remove the healing record for `contact_id` (call after successful re-key).
    pub fn remove(&mut self, contact_id: &str) -> bool {
        self.records.remove(contact_id).is_some()
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    /// Evict records whose `created_at` timestamp is older than `ttl_seconds`.
    ///
    /// Returns `Action`s requesting the platform to delete the expired rows from
    /// persistent storage.
    pub fn prune_expired(&mut self) -> Vec<Action> {
        let now = unix_now();
        let cutoff = now.saturating_sub(self.ttl_seconds);

        let expired: Vec<String> = self
            .records
            .iter()
            .filter(|(_, r)| r.created_at < cutoff)
            .map(|(k, _)| k.clone())
            .collect();

        let mut actions = Vec::new();
        for contact_id in &expired {
            self.records.remove(contact_id);
            actions.push(Action::PersistMessage {
                message_json: format!(
                    r#"{{"_prune_healing":true,"contact_id":"{}"}}"#,
                    contact_id.replace('"', "\\\"")
                ),
            });
        }
        actions
    }

    /// Current number of pending healing records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Insert a record with an explicit `created_at` timestamp.
    /// Used in tests to simulate aged records without sleeping.
    #[cfg(test)]
    pub(crate) fn enqueue_at(
        &mut self,
        contact_id: &str,
        message_json: &str,
        created_at: u64,
    ) {
        self.records.insert(
            contact_id.to_string(),
            HealingRecord {
                contact_id: contact_id.to_string(),
                message_json: message_json.to_string(),
                attempts: 0,
                created_at,
            },
        );
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_heal_only_msg_zero() {
        assert!(HealingQueue::can_heal(0));
        assert!(!HealingQueue::can_heal(1));
        assert!(!HealingQueue::can_heal(42));
    }

    #[test]
    fn test_enqueue_creates_record() {
        let mut q = HealingQueue::default();
        let actions = q.enqueue("alice", r#"{"data":"..."}"#);
        assert!(!actions.is_empty());
        assert!(q.has_pending("alice"));
    }

    #[test]
    fn test_enqueue_is_idempotent() {
        let mut q = HealingQueue::default();
        q.enqueue("bob", r#"{"msg":"first"}"#);
        q.enqueue("bob", r#"{"msg":"second"}"#);
        assert_eq!(q.len(), 1);
        assert_eq!(
            q.get("bob").unwrap().message_json,
            r#"{"msg":"second"}"#
        );
    }

    #[test]
    fn test_record_attempt_increments() {
        let mut q = HealingQueue::default();
        q.enqueue("carol", "{}");
        let d = q.record_attempt("carol");
        assert_eq!(d, HealingDecision::RetryAllowed { attempt: 1 });
        let d = q.record_attempt("carol");
        assert_eq!(d, HealingDecision::RetryAllowed { attempt: 2 });
    }

    #[test]
    fn test_record_attempt_max_attempts_reached() {
        let mut q = HealingQueue::new(3, DEFAULT_TTL_SECONDS);
        q.enqueue("dave", "{}");
        q.record_attempt("dave"); // 1
        q.record_attempt("dave"); // 2
        let d = q.record_attempt("dave"); // 3 → reached
        assert_eq!(d, HealingDecision::MaxAttemptsReached);
    }

    #[test]
    fn test_record_attempt_not_found() {
        let mut q = HealingQueue::default();
        assert_eq!(q.record_attempt("nobody"), HealingDecision::NotFound);
    }

    #[test]
    fn test_remove() {
        let mut q = HealingQueue::default();
        q.enqueue("eve", "{}");
        assert!(q.remove("eve"));
        assert!(!q.has_pending("eve"));
        assert!(!q.remove("eve")); // already gone
    }

    #[test]
    fn test_prune_expired_removes_old_records() {
        let mut q = HealingQueue::new(3, DEFAULT_TTL_SECONDS);
        // Inject a record with created_at = 0 (Unix epoch) → always expired.
        q.enqueue_at("old", "{}", 0);
        let actions = q.prune_expired();
        assert!(!actions.is_empty());
        assert!(!q.has_pending("old"));
    }

    #[test]
    fn test_prune_keeps_fresh_records() {
        let mut q = HealingQueue::new(3, DEFAULT_TTL_SECONDS);
        q.enqueue("fresh", "{}");
        q.prune_expired();
        assert!(q.has_pending("fresh")); // should survive
    }
}
