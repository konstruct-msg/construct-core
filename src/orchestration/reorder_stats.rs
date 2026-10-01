//! How late messages arrive — the measurement PQR-4 waits on (construct-docs TODO 64.3).
//!
//! A message tagged with a PQ epoch older than the chains a state holds opens only by a skipped
//! key, and fails if none was kept: that is a lost message, not a degraded one. Whether keeping
//! two epochs' chains (`PQ_CHAIN_RETENTION`) is enough is a question about real reordering
//! depth, which nothing measured. These counters do, for this process: the platform reads them
//! (`OrchestratorCore::reorder_stats`) and writes them to its diagnostics log. They never leave
//! the device.

use crate::crypto::messaging::double_ratchet::DrHealthSnapshot;

/// Counters since the process started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReorderStats {
    /// Messages decrypted.
    pub decrypted: u64,
    /// …of which tagged with the epoch before the decrypting state's current one.
    pub previous_epoch: u64,
    /// …of which tagged two or more epochs back — opened only by a skipped key.
    pub older_epoch: u64,
    /// The largest epoch lag of a decrypted message.
    pub max_epoch_lag: u32,
    /// The most keys a single message made the receiver skip: how many messages it overtook.
    pub max_skip_depth: u32,
    /// Messages that did not decrypt and were tagged with an epoch older than every chain the
    /// current state holds — the loss PQR-4 is about.
    pub evicted_epoch_failures: u64,
}

impl ReorderStats {
    /// A message tagged `message_epoch` decrypted on a state that looked like `before` and
    /// then like `after`.
    pub fn record_decrypted(
        &mut self,
        before: &DrHealthSnapshot,
        after: &DrHealthSnapshot,
        message_epoch: u32,
    ) {
        self.decrypted += 1;
        if message_epoch > 0 {
            let lag = before.pq_epoch.saturating_sub(message_epoch);
            match lag {
                0 => {}
                1 => self.previous_epoch += 1,
                _ => self.older_epoch += 1,
            }
            self.max_epoch_lag = self.max_epoch_lag.max(lag);
        }
        let skipped = after
            .skipped_keys_count
            .saturating_sub(before.skipped_keys_count)
            .max(
                after
                    .pq_skipped_keys_count
                    .saturating_sub(before.pq_skipped_keys_count),
            );
        self.max_skip_depth = self
            .max_skip_depth
            .max(u32::try_from(skipped).unwrap_or(u32::MAX));
    }

    /// A message tagged `message_epoch` decrypted on no state; `current` is the current state.
    pub fn record_failed(&mut self, current: Option<&DrHealthSnapshot>, message_epoch: u32) {
        let evicted = current
            .and_then(|s| s.pq_oldest_chain_epoch)
            .is_some_and(|oldest| message_epoch > 0 && message_epoch < oldest);
        if evicted {
            self.evicted_epoch_failures += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kyber_prekey_auth::{PqAuthentication, PqHandshake};

    fn snap(
        pq_epoch: u32,
        oldest: Option<u32>,
        skipped: usize,
        pq_skipped: usize,
    ) -> DrHealthSnapshot {
        DrHealthSnapshot {
            messages_sent: 0,
            messages_received: 0,
            skipped_keys_count: skipped,
            is_pq_strengthened: true,
            pq_authentication: PqAuthentication::Unknown,
            pq_handshake: PqHandshake::InitialV2,
            last_ratchet_at: 0,
            session_id: String::new(),
            pq_epoch,
            pq_oldest_chain_epoch: oldest,
            pq_skipped_keys_count: pq_skipped,
        }
    }

    #[test]
    fn epoch_lag_is_counted_against_the_state_before_the_message() {
        let mut stats = ReorderStats::default();
        stats.record_decrypted(&snap(5, Some(4), 0, 0), &snap(5, Some(4), 0, 0), 5);
        stats.record_decrypted(&snap(5, Some(4), 0, 0), &snap(5, Some(4), 0, 0), 4);
        stats.record_decrypted(&snap(5, Some(4), 3, 3), &snap(5, Some(4), 2, 2), 2);
        // Epoch 0 is before any exchange: no lag to speak of, even on an epoch-5 state.
        stats.record_decrypted(&snap(5, Some(4), 0, 0), &snap(5, Some(4), 0, 0), 0);
        assert_eq!(stats.decrypted, 4);
        assert_eq!(stats.previous_epoch, 1);
        assert_eq!(stats.older_epoch, 1);
        assert_eq!(stats.max_epoch_lag, 3);
    }

    #[test]
    fn skip_depth_is_the_keys_one_message_made_us_keep() {
        let mut stats = ReorderStats::default();
        stats.record_decrypted(&snap(1, Some(1), 2, 0), &snap(1, Some(1), 9, 7), 1);
        stats.record_decrypted(&snap(1, Some(1), 9, 7), &snap(1, Some(1), 8, 6), 1);
        assert_eq!(stats.max_skip_depth, 7);
    }

    #[test]
    fn only_a_failure_older_than_every_held_chain_is_an_eviction() {
        let mut stats = ReorderStats::default();
        let current = snap(6, Some(5), 0, 0);
        stats.record_failed(Some(&current), 4); // evicted
        stats.record_failed(Some(&current), 5); // held chain: a failure of another kind
        stats.record_failed(Some(&current), 7); // not yet known
        stats.record_failed(Some(&current), 0); // no PQ key at all
        stats.record_failed(None, 4); // no session
        assert_eq!(stats.evicted_epoch_failures, 1);
    }
}
