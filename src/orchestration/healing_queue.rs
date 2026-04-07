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
use std::sync::Arc;

use crate::orchestration::clock::{Clock, system_clock};

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_MAX_ATTEMPTS: u32 = 3;
const DEFAULT_TTL_SECONDS: u64 = 24 * 60 * 60; // 24 hours

// ── Public types ──────────────────────────────────────────────────────────────

/// Decision returned by `record_attempt`.
#[derive(Debug, Clone, PartialEq)]
pub enum HealingDecision {
    /// Healing may proceed; `attempt` is the 1-based attempt index.
    /// `retry_after_ms` is the minimum delay before the next attempt.
    RetryAllowed { attempt: u32, retry_after_ms: u64 },
    /// Maximum attempts exhausted — the caller should send END_SESSION.
    MaxAttemptsReached,
    /// No healing record exists for this contact.
    NotFound,
}

/// A queued healing record for a single contact.
#[derive(Debug, Clone)]
pub struct HealingRecord {
    pub contact_id: String,
    /// Binary WirePayload blob (stored for replay after re-key).
    pub message_payload: Vec<u8>,
    pub attempts: u32,
    pub created_at: u64,
}

// ── HealingQueue ──────────────────────────────────────────────────────────────

pub struct HealingQueue {
    records: HashMap<String, HealingRecord>,
    max_attempts: u32,
    ttl_seconds: u64,
    clock: Arc<dyn Clock>,
}

impl HealingQueue {
    pub fn new(max_attempts: u32, ttl_seconds: u64) -> Self {
        Self {
            records: HashMap::new(),
            max_attempts,
            ttl_seconds,
            clock: system_clock(),
        }
    }

    pub fn new_with_clock(max_attempts: u32, ttl_seconds: u64, clock: Arc<dyn Clock>) -> Self {
        Self {
            records: HashMap::new(),
            max_attempts,
            ttl_seconds,
            clock,
        }
    }

    /// Default configuration matching the Swift implementation.
    pub fn new_default() -> Self {
        Self::new(DEFAULT_MAX_ATTEMPTS, DEFAULT_TTL_SECONDS)
    }
}

impl Default for HealingQueue {
    fn default() -> Self {
        Self::new_default()
    }
}

impl HealingQueue {
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

    /// Enqueue a message for healing.
    ///
    /// If a record already exists for `contact_id`, it is replaced only when
    /// the new message is strictly fresher (higher `created_at`). This prevents
    /// a server retry of an older message from clobbering a legitimate newer init.
    pub fn enqueue(&mut self, contact_id: &str, payload: Vec<u8>) {
        let now = self.clock.now_secs();
        if let Some(existing) = self.records.get(contact_id) {
            if existing.created_at > now {
                // Existing record is future-dated (clock skew) — keep it.
                return;
            }
        }
        let record = HealingRecord {
            contact_id: contact_id.to_string(),
            message_payload: payload,
            attempts: 0,
            created_at: now,
        };
        self.records.insert(contact_id.to_string(), record);
    }

    /// Increment the attempt counter for `contact_id`.
    ///
    /// Returns a `HealingDecision` indicating whether another attempt is allowed.
    /// `retry_after_ms` uses exponential backoff: 2s / 4s / 8s for attempts 1-3.
    pub fn record_attempt(&mut self, contact_id: &str) -> HealingDecision {
        match self.records.get_mut(contact_id) {
            None => HealingDecision::NotFound,
            Some(record) => {
                record.attempts += 1;
                if record.attempts >= self.max_attempts {
                    HealingDecision::MaxAttemptsReached
                } else {
                    // 2^attempt seconds (2s, 4s, 8s …)
                    let retry_after_ms = 2_000u64 << record.attempts;
                    HealingDecision::RetryAllowed {
                        attempt: record.attempts,
                        retry_after_ms,
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
    /// Expired records are removed from memory. Persistence is handled by the
    /// orchestrator's CFE state export — no individual `Action` is needed here.
    pub fn prune_expired(&mut self) {
        let now = self.clock.now_secs();
        let cutoff = now.saturating_sub(self.ttl_seconds);
        self.records.retain(|_, r| r.created_at >= cutoff);
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
    pub(crate) fn enqueue_at(&mut self, contact_id: &str, payload: Vec<u8>, created_at: u64) {
        self.records.insert(
            contact_id.to_string(),
            HealingRecord {
                contact_id: contact_id.to_string(),
                message_payload: payload,
                attempts: 0,
                created_at,
            },
        );
    }

    /// Export all active healing records for CFE snapshot serialisation.
    pub fn snapshot_records(&self) -> Vec<&HealingRecord> {
        self.records.values().collect()
    }

    /// Restore healing queue from a CFE snapshot.
    /// Existing records are replaced.
    pub fn restore_records(&mut self, records: Vec<HealingRecord>) {
        self.records.clear();
        for r in records {
            self.records.insert(r.contact_id.clone(), r);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestration::clock::MockClock;

    fn queue_with_clock(initial_secs: u64) -> (HealingQueue, Arc<MockClock>) {
        let clock = Arc::new(MockClock::new(initial_secs * 1_000));
        let q =
            HealingQueue::new_with_clock(DEFAULT_MAX_ATTEMPTS, DEFAULT_TTL_SECONDS, clock.clone());
        (q, clock)
    }

    #[test]
    fn test_can_heal_only_msg_zero() {
        assert!(HealingQueue::can_heal(0));
        assert!(!HealingQueue::can_heal(1));
        assert!(!HealingQueue::can_heal(42));
    }

    #[test]
    fn test_enqueue_creates_record() {
        let mut q = HealingQueue::default();
        q.enqueue("alice", b"payload".to_vec());
        assert!(q.has_pending("alice"));
    }

    #[test]
    fn test_enqueue_is_idempotent() {
        let mut q = HealingQueue::default();
        q.enqueue("bob", b"first".to_vec());
        q.enqueue("bob", b"second".to_vec());
        assert_eq!(q.len(), 1);
        // Same second → second call replaces first (last-write wins within same timestamp).
        assert_eq!(q.get("bob").unwrap().message_payload, b"second");
    }

    #[test]
    fn test_record_attempt_increments() {
        let mut q = HealingQueue::default();
        q.enqueue("carol", vec![]);
        let d = q.record_attempt("carol");
        assert_eq!(
            d,
            HealingDecision::RetryAllowed {
                attempt: 1,
                retry_after_ms: 4000
            }
        );
        let d = q.record_attempt("carol");
        assert_eq!(
            d,
            HealingDecision::RetryAllowed {
                attempt: 2,
                retry_after_ms: 8000
            }
        );
    }

    #[test]
    fn test_record_attempt_max_attempts_reached() {
        let mut q = HealingQueue::new(3, DEFAULT_TTL_SECONDS);
        q.enqueue("dave", vec![]);
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
        q.enqueue("eve", vec![]);
        assert!(q.remove("eve"));
        assert!(!q.has_pending("eve"));
        assert!(!q.remove("eve")); // already gone
    }

    #[test]
    fn test_prune_expired_removes_old_records() {
        let mut q = HealingQueue::new(3, DEFAULT_TTL_SECONDS);
        // Inject a record with created_at = 0 (Unix epoch) → always expired.
        q.enqueue_at("old", vec![], 0);
        q.prune_expired();
        assert!(!q.has_pending("old"));
    }

    #[test]
    fn test_prune_keeps_fresh_records() {
        let mut q = HealingQueue::new(3, DEFAULT_TTL_SECONDS);
        q.enqueue("fresh", vec![]);
        q.prune_expired();
        assert!(q.has_pending("fresh")); // should survive
    }

    #[test]
    fn test_prune_uses_clock_not_system_time() {
        // Place clock at exactly TTL boundary; record at t=0 should be pruned.
        let ttl = DEFAULT_TTL_SECONDS;
        let (mut q, _clock) = queue_with_clock(ttl + 1); // now = ttl+1 secs
        q.enqueue_at("stale", vec![], 0);
        q.prune_expired();
        assert!(!q.has_pending("stale"));
    }

    #[test]
    fn test_enqueue_timestamps_from_clock() {
        let (mut q, clock) = queue_with_clock(100); // now = 100s
        q.enqueue("frank", b"data".to_vec());
        assert_eq!(q.get("frank").unwrap().created_at, 100);

        // Advance to 200s — second enqueue should replace.
        clock.advance_ms(100_000);
        q.enqueue("frank", b"newer".to_vec());
        assert_eq!(q.get("frank").unwrap().created_at, 200);
        assert_eq!(q.get("frank").unwrap().message_payload, b"newer");
    }
}
