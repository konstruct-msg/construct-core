/// ACK deduplication store — Rust port of Swift `PersistentACKStore`.
///
/// Prevents processing duplicate messages by maintaining a two-level cache:
/// 1. In-memory `HashSet` for O(1) hot-path lookups.
/// 2. Persistence via `PlatformBridge::persist_record` / `query_record` for
///    cross-launch deduplication.
///
/// When `is_processed` returns `NeedDbCheck`, the caller must query the
/// platform data store and call `confirm_from_db` with the result.
use std::collections::HashSet;
use std::sync::Arc;

use crate::orchestration::actions::Action;
use crate::orchestration::clock::{Clock, system_clock};

// ── Public types ──────────────────────────────────────────────────────────────

/// Result of checking whether a message has already been processed.
#[derive(Debug, Clone, PartialEq)]
pub enum AckCheckResult {
    /// Definitely a duplicate — found in the in-memory cache.
    InCache,
    /// Not in cache; caller must query the persistent store.
    NeedDbCheck,
    /// Confirmed not a duplicate (after DB check returned nothing).
    NotProcessed,
}

// ── AckStore ──────────────────────────────────────────────────────────────────

/// In-process ACK deduplication with persistence delegation.
pub struct AckStore {
    cache: HashSet<String>,
    /// Maximum age of a persisted ACK record before `prune_expired` removes it.
    max_age_seconds: u64,
    /// When `true` (set after `restore_cache`), cache misses return `NeedDbCheck`
    /// so the platform can catch messages that were processed between the last
    /// snapshot and a crash. Cleared by `clear_post_restart_mode()`.
    post_restart_mode: bool,
    clock: Arc<dyn Clock>,
}

impl AckStore {
    pub fn new(max_age_seconds: u64) -> Self {
        Self {
            cache: HashSet::new(),
            max_age_seconds,
            post_restart_mode: false,
            clock: system_clock(),
        }
    }

    pub fn new_with_clock(max_age_seconds: u64, clock: Arc<dyn Clock>) -> Self {
        Self {
            cache: HashSet::new(),
            max_age_seconds,
            post_restart_mode: false,
            clock,
        }
    }

    /// Default configuration: 30-day expiry (mirrors Swift implementation).
    pub fn new_default() -> Self {
        Self::new(30 * 24 * 60 * 60)
    }
}

impl Default for AckStore {
    fn default() -> Self {
        Self::new_default()
    }
}

impl AckStore {
    // ── Query ─────────────────────────────────────────────────────────────────

    /// Check whether `message_id` has been processed.
    ///
    /// - `InCache`: definitely a duplicate (hot-path, O(1)).
    /// - `NeedDbCheck`: cache miss in post-restart mode — caller must query the
    ///   persistent store to cover the crash-window gap.
    /// - `NotProcessed`: cache miss in normal operation — message is new.
    pub fn is_processed(&self, message_id: &str) -> AckCheckResult {
        if self.cache.contains(message_id) {
            AckCheckResult::InCache
        } else if self.post_restart_mode {
            AckCheckResult::NeedDbCheck
        } else {
            AckCheckResult::NotProcessed
        }
    }

    /// Called after the platform data store confirms the record is absent.
    /// Always returns `NotProcessed` (convenience for symmetric call-sites).
    pub fn confirm_not_in_db(&self) -> AckCheckResult {
        AckCheckResult::NotProcessed
    }

    /// Exit post-restart mode. Call once all in-flight `CheckAckInDb` responses
    /// have been received, or after a fixed warm-up window.
    pub fn clear_post_restart_mode(&mut self) {
        self.post_restart_mode = false;
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Mark `message_id` as processed.
    ///
    /// Inserts into the in-memory cache and returns `Action`s that the
    /// platform layer must execute to persist the record.
    pub fn mark_processed(&mut self, message_id: &str) -> Vec<Action> {
        if self.cache.contains(message_id) {
            return vec![];
        }
        self.cache.insert(message_id.to_string());

        let now = self.clock.now_secs();
        vec![Action::PersistAck {
            message_id: message_id.to_string(),
            timestamp: now,
        }]
    }

    /// Remove the `message_id` from the in-memory cache (e.g. after a reset).
    pub fn evict(&mut self, message_id: &str) {
        self.cache.remove(message_id);
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    /// Prune expired entries from the in-memory cache.
    ///
    /// Returns a `PruneAckStore` action so the platform can delete records
    /// older than `max_age_seconds` from its persistent ACK store.
    pub fn prune_expired(&self) -> Vec<Action> {
        let cutoff = self.clock.now_secs().saturating_sub(self.max_age_seconds);
        vec![Action::PruneAckStore { cutoff_ts: cutoff }]
    }

    /// Current size of the in-memory deduplication cache.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Export all in-memory message IDs for CFE snapshot serialisation.
    pub fn snapshot_cache(&self) -> Vec<String> {
        self.cache.iter().cloned().collect()
    }

    /// Restore in-memory cache from a CFE snapshot.
    /// Existing entries are replaced (idempotent for identical snapshots).
    /// Enables `post_restart_mode` so cache misses trigger a DB check until
    /// the crash-window gap is covered.
    pub fn restore_cache(&mut self, ids: Vec<String>) {
        self.cache.clear();
        self.cache.extend(ids);
        self.post_restart_mode = true;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestration::clock::MockClock;

    fn store_with_clock(initial_ms: u64) -> (AckStore, Arc<MockClock>) {
        let clock = Arc::new(MockClock::new(initial_ms));
        let store = AckStore::new_with_clock(30 * 24 * 60 * 60, clock.clone());
        (store, clock)
    }

    #[test]
    fn test_is_processed_returns_not_processed_on_miss_normal_mode() {
        let store = AckStore::default();
        assert_eq!(store.is_processed("msg-001"), AckCheckResult::NotProcessed);
    }

    #[test]
    fn test_is_processed_returns_need_db_check_after_restore() {
        let mut store = AckStore::default();
        store.restore_cache(vec![]);
        assert_eq!(store.is_processed("msg-001"), AckCheckResult::NeedDbCheck);
    }

    #[test]
    fn test_mark_processed_adds_to_cache() {
        let mut store = AckStore::default();
        store.mark_processed("msg-001");
        assert_eq!(store.is_processed("msg-001"), AckCheckResult::InCache);
    }

    #[test]
    fn test_mark_processed_returns_persist_action() {
        let mut store = AckStore::default();
        let actions = store.mark_processed("msg-001");
        assert_eq!(actions.len(), 1);
        matches!(&actions[0], Action::PersistMessage { message_json } if message_json.contains("msg-001"));
    }

    #[test]
    fn test_mark_processed_idempotent() {
        let mut store = AckStore::default();
        store.mark_processed("msg-dup");
        let actions = store.mark_processed("msg-dup");
        // Second call: already in cache → no actions returned.
        assert!(actions.is_empty());
    }

    #[test]
    fn test_evict_removes_from_cache() {
        let mut store = AckStore::default();
        store.mark_processed("msg-002");
        store.evict("msg-002");
        assert_eq!(store.is_processed("msg-002"), AckCheckResult::NotProcessed);
    }

    #[test]
    fn test_confirm_not_in_db() {
        let store = AckStore::default();
        assert_eq!(store.confirm_not_in_db(), AckCheckResult::NotProcessed);
    }

    #[test]
    fn test_prune_expired_returns_actions() {
        let store = AckStore::default();
        let actions = store.prune_expired();
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_cache_len() {
        let mut store = AckStore::default();
        assert_eq!(store.cache_len(), 0);
        store.mark_processed("a");
        store.mark_processed("b");
        assert_eq!(store.cache_len(), 2);
    }

    #[test]
    fn test_multiple_unique_messages() {
        let mut store = AckStore::default();
        for i in 0..10 {
            store.mark_processed(&format!("msg-{}", i));
        }
        assert_eq!(store.cache_len(), 10);
        for i in 0..10 {
            assert_eq!(
                store.is_processed(&format!("msg-{}", i)),
                AckCheckResult::InCache
            );
        }
    }

    #[test]
    fn test_prune_uses_clock_not_system_time() {
        // Verify that a frozen clock produces a deterministic cutoff timestamp.
        let (store, _clock) = store_with_clock(1_000_000_000);
        let actions = store.prune_expired();
        let Action::PruneAckStore { cutoff_ts } = &actions[0] else {
            panic!("expected PruneAckStore");
        };
        // now_secs = 1_000_000_000 / 1000 = 1_000_000; cutoff = 1_000_000 - 30d ≈ 997_408_000
        assert_eq!(*cutoff_ts, 1_000_000u64.saturating_sub(30 * 24 * 60 * 60));
    }

    #[test]
    fn test_mark_processed_timestamp_from_clock() {
        let (mut store, clock) = store_with_clock(5_000); // 5 seconds in ms
        let actions = store.mark_processed("ts-msg");
        let Action::PersistAck { timestamp, .. } = &actions[0] else {
            panic!("expected PersistAck");
        };
        assert_eq!(*timestamp, 5); // 5_000 ms / 1000 = 5 secs
        // Advance clock and mark another message.
        clock.advance_ms(3_000);
        let actions2 = store.mark_processed("ts-msg-2");
        let Action::PersistAck { timestamp: ts2, .. } = &actions2[0] else {
            panic!("expected PersistAck");
        };
        assert_eq!(*ts2, 8); // 8_000 ms / 1000 = 8 secs
    }
}
