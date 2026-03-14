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
    pub fn default() -> Self {
        Self::new(30 * 24 * 60 * 60)
    }

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
        let json = format!(
            r#"{{"id":{},"ts":{}}}"#,
            serde_json_string(message_id),
            now
        );

        vec![Action::PersistMessage { message_json: json }]
    }

    /// Remove the `message_id` from the in-memory cache (e.g. after a reset).
    pub fn evict(&mut self, message_id: &str) {
        self.cache.remove(message_id);
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    /// Prune expired entries from the in-memory cache.
    ///
    /// Note: the cache stores only IDs (no timestamps), so in-memory pruning
    /// is not possible without a separate timestamp map. This method returns
    /// a `Vec<Action>` requesting the platform to delete records older than
    /// `max_age_seconds` from the persistent store.
    pub fn prune_expired(&self) -> Vec<Action> {
        let cutoff = unix_now().saturating_sub(self.max_age_seconds);
        // The real delete is issued as a PersistMessage with a special sentinel
        // that the Swift Core Data adapter interprets as a batch-delete.
        // TODO(Phase 3): add dedicated Action::PruneAckStore { cutoff_ts } once
        //               the full Action enum is stabilised.
        vec![Action::PersistMessage {
            message_json: format!(r#"{{"_prune":true,"cutoff":{}}}"#, cutoff),
        }]
    }

    /// Current size of the in-memory deduplication cache.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Minimal JSON string escape (handles only `"` and `\` for message IDs).
fn serde_json_string(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_processed_returns_need_db_check_on_miss() {
        let store = AckStore::default();
        assert_eq!(
            store.is_processed("msg-001"),
            AckCheckResult::NeedDbCheck
        );
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
