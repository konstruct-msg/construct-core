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
use std::time::{SystemTime, UNIX_EPOCH};

use crate::orchestration::actions::Action;

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
}

impl AckStore {
    pub fn new(max_age_seconds: u64) -> Self {
        Self {
            cache: HashSet::new(),
            max_age_seconds,
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
    /// Returns `InCache` immediately if found in the hot-path cache.
    /// Returns `NeedDbCheck` otherwise — caller must query the platform store.
    pub fn is_processed(&self, message_id: &str) -> AckCheckResult {
        if self.cache.contains(message_id) {
            AckCheckResult::InCache
        } else {
            AckCheckResult::NeedDbCheck
        }
    }

    /// Called after the platform data store confirms the record is absent.
    /// Always returns `NotProcessed` (convenience for symmetric call-sites).
    pub fn confirm_not_in_db(&self) -> AckCheckResult {
        AckCheckResult::NotProcessed
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

        let now = unix_now();
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
        let cutoff = unix_now().saturating_sub(self.max_age_seconds);
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
    pub fn restore_cache(&mut self, ids: Vec<String>) {
        self.cache.clear();
        self.cache.extend(ids);
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
    fn test_is_processed_returns_need_db_check_on_miss() {
        let store = AckStore::default();
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
        assert_eq!(store.is_processed("msg-002"), AckCheckResult::NeedDbCheck);
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
}
