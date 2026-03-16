//! Time-bucketed replay filter for obfs4 handshake MACs.
//!
//! Prevents active probing attacks: an adversary who captures a valid
//! client handshake cannot replay it to fingerprint the server as obfs4.
//!
//! ## Design
//!
//! Mirrors the Go reference `replayfilter.ReplayFilter`:
//! - Two rotating buckets (current epoch hour + previous epoch hour)
//! - On each new connection, the 16-byte handshake MAC is checked against
//!   both buckets. If found → replay, reject with random delay.
//! - If not found → insert into current bucket and proceed.
//! - When the epoch hour rolls over, `prev = current; current = new empty`.
//!
//! This gives a ~2-hour replay protection window, matching the ±1h clock
//! skew tolerance in the MAC verification.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Time-bucketed replay filter. Must be shared via `Arc<Mutex<ReplayFilter>>`
/// across concurrent `accept()` calls.
pub struct ReplayFilter {
    current_epoch: u64,
    current_bucket: HashSet<[u8; 16]>,
    prev_bucket: HashSet<[u8; 16]>,
}

impl ReplayFilter {
    /// Create a new empty replay filter.
    pub fn new() -> Self {
        ReplayFilter {
            current_epoch: epoch_hour(),
            current_bucket: HashSet::new(),
            prev_bucket: HashSet::new(),
        }
    }

    /// Test whether `mac` was seen before, and if not, record it.
    ///
    /// Returns `true` if this is a **replay** (already seen) → caller should
    /// reject the connection.
    /// Returns `false` if this is a new MAC → connection is allowed.
    pub fn test_and_set(&mut self, mac: [u8; 16]) -> bool {
        self.maybe_rotate();

        if self.current_bucket.contains(&mac) || self.prev_bucket.contains(&mac) {
            return true; // replay detected
        }

        self.current_bucket.insert(mac);
        false
    }

    /// Rotate buckets if the epoch hour has changed.
    fn maybe_rotate(&mut self) {
        let now = epoch_hour();
        if now != self.current_epoch {
            self.prev_bucket = std::mem::take(&mut self.current_bucket);
            self.current_epoch = now;
        }
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn epoch_hour() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_mac_is_not_replay() {
        let mut f = ReplayFilter::new();
        let mac = [1u8; 16];
        assert!(!f.test_and_set(mac));
    }

    #[test]
    fn second_same_mac_is_replay() {
        let mut f = ReplayFilter::new();
        let mac = [2u8; 16];
        assert!(!f.test_and_set(mac));
        assert!(f.test_and_set(mac));
    }

    #[test]
    fn different_macs_not_replay() {
        let mut f = ReplayFilter::new();
        for i in 0u8..=10 {
            let mac = [i; 16];
            assert!(!f.test_and_set(mac), "mac {i} should not be a replay");
        }
    }

    #[test]
    fn rotation_clears_old_current_into_prev() {
        let mut f = ReplayFilter::new();
        let mac = [42u8; 16];

        // Insert in current epoch
        assert!(!f.test_and_set(mac));

        // Simulate epoch rollover
        f.current_epoch -= 1;
        f.maybe_rotate();

        // mac should now be in prev_bucket — still a replay
        assert!(f.test_and_set(mac));
    }

    #[test]
    fn after_two_rotations_mac_is_forgotten() {
        let mut f = ReplayFilter::new();
        let mac = [7u8; 16];
        assert!(!f.test_and_set(mac));

        // Two epoch rollovers
        f.current_epoch -= 1;
        f.maybe_rotate(); // mac moves to prev_bucket
        f.current_epoch -= 1;
        f.maybe_rotate(); // prev_bucket is replaced → mac forgotten

        // Now the same MAC should be accepted again
        assert!(!f.test_and_set(mac));
    }
}
