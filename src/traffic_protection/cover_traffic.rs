//! Cover traffic generation
//!
//! Generates dummy messages to hide real communication patterns.
//!
//! ## Energy Efficiency (Battery-First Design)
//!
//! - Battery-aware: auto-disable when battery < 20%
//! - Network coalescing: piggyback on real messages
//! - Adaptive intervals: increase when idle, with a random gap so the cadence is not a signature
//! - Minimal wake-ups: use existing network windows
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use construct_core::traffic_protection::cover_traffic::*;
//!
//! // Create manager
//! let mut manager = CoverTrafficManager::new(CoverTrafficConfig::default());
//!
//! // Update battery level (from iOS/Android)
//! manager.update_battery_level(0.75); // 75%
//!
//! // Check if should send dummy
//! if manager.should_send_dummy() {
//!     let dummy = manager.generate_dummy();
//!     // Send to server as the transport's dummy type
//! }
//!
//! // Record real message sent (for coalescing)
//! manager.record_real_message_sent();
//! ```

use rand::{Rng, RngCore};
use std::time::{Duration, Instant};

/// Generate a dummy message body of exactly `size` random bytes.
///
/// A dummy is told apart from a real message by the envelope the transport puts around it
/// (the server drops the dummy type), never by its content, so the body carries no marker:
/// a marker would be the one thing an observer could look for. The body is exactly `size`
/// bytes so that a dummy and a real message of the configured size are the same length on
/// the wire — until 0.54.1 the body was built as a serialised struct and came out ~27 bytes
/// short of `size`, which made every dummy recognisable by length alone.
pub fn generate_dummy_message(size: usize) -> Vec<u8> {
    let mut body = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut body);
    body
}

/// Configuration for cover traffic generation
#[derive(Debug, Clone, Copy)]
pub struct CoverTrafficConfig {
    /// Enable cover traffic
    pub enabled: bool,

    /// Battery level threshold (0.0-1.0, e.g. 0.2 = 20%)
    /// Disable cover traffic when battery below this level
    pub battery_level_threshold: f32,

    /// Minimum interval between dummy messages (ms)
    pub min_interval_ms: u64,

    /// Maximum interval between dummy messages (ms)
    pub max_interval_ms: u64,

    /// Target size for dummy messages (bytes)
    pub message_size: usize,

    /// Coalesce with real messages (send dummy only if no real messages sent recently)
    pub coalesce_with_real_messages: bool,

    /// Coalescing window (ms) - if real message sent within this window, skip dummy
    pub coalesce_window_ms: u64,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default (opt-in for privacy-conscious users)
            battery_level_threshold: 0.2, // 20%
            min_interval_ms: 30000, // 30 seconds (conservative)
            max_interval_ms: 300000, // 5 minutes
            message_size: 255, // Match padding block size
            coalesce_with_real_messages: true, // Energy efficient
            coalesce_window_ms: 10000, // 10 seconds
        }
    }
}

/// Cover Traffic Manager with state and battery awareness
///
/// Manages the sending of dummy messages with energy-efficient strategies.
///
/// ## Energy Optimizations
///
/// 1. **Battery-aware**: Auto-disables when battery < threshold
/// 2. **Adaptive intervals**: Increases intervals based on activity
/// 3. **Network coalescing**: Skips dummy if real message sent recently
/// 4. **Lazy scheduling**: No background threads, pull-based model
pub struct CoverTrafficManager {
    config: CoverTrafficConfig,

    /// Current battery level (0.0-1.0)
    battery_level: f32,

    /// Last time a real message was sent
    last_real_message: Option<Instant>,

    /// The next dummy is not due before this instant (set when a dummy goes out).
    next_dummy_not_before: Option<Instant>,

    /// Current adaptive base interval (adjusts based on activity). The actual gap between two
    /// dummies is drawn uniformly from `[base, base * 3 / 2]` — see `generate_dummy_at`.
    current_interval_ms: u64,

    /// Number of consecutive dummy messages sent
    consecutive_dummies: u32,

    /// Energy metrics
    metrics: EnergyMetrics,
}

impl CoverTrafficManager {
    /// Create a new manager with the given configuration
    pub fn new(mut config: CoverTrafficConfig) -> Self {
        // A ceiling below the floor would make adaptation *shorten* the interval below the
        // configured minimum; the floor wins.
        config.max_interval_ms = config.max_interval_ms.max(config.min_interval_ms);
        Self {
            current_interval_ms: config.min_interval_ms,
            battery_level: 1.0, // Assume full battery initially
            last_real_message: None,
            next_dummy_not_before: None,
            consecutive_dummies: 0,
            config,
            metrics: EnergyMetrics::default(),
        }
    }

    /// Update current battery level (0.0-1.0)
    ///
    /// Should be called from iOS/Android when battery level changes.
    pub fn update_battery_level(&mut self, level: f32) {
        self.battery_level = level.clamp(0.0, 1.0);
    }

    /// Check if cover traffic should be active based on battery and config
    fn is_active(&self) -> bool {
        self.config.enabled && self.battery_level >= self.config.battery_level_threshold
    }

    /// Record that a real message was sent (for coalescing)
    pub fn record_real_message_sent(&mut self) {
        self.record_real_message_sent_at(Instant::now());
    }

    fn record_real_message_sent_at(&mut self, now: Instant) {
        self.last_real_message = Some(now);

        // Reset adaptive interval when user is active
        self.current_interval_ms = self.config.min_interval_ms;
        self.consecutive_dummies = 0;
    }

    /// Check if a dummy message should be sent now
    ///
    /// Returns `true` if all conditions are met:
    /// - Cover traffic is enabled
    /// - Battery level is sufficient
    /// - Enough time has passed since last dummy
    /// - No real message was sent recently (coalescing)
    pub fn should_send_dummy(&mut self) -> bool {
        self.should_send_dummy_at(Instant::now())
    }

    fn should_send_dummy_at(&mut self, now: Instant) -> bool {
        // Check if active
        if !self.is_active() {
            // Enabled but under the battery threshold: that is the skip this counter names.
            // A disabled manager is not skipping anything.
            if self.config.enabled {
                self.metrics.battery_skipped += 1;
            }
            return false;
        }

        // Check coalescing: skip if real message sent recently
        if self.config.coalesce_with_real_messages
            && let Some(last_real) = self.last_real_message
        {
            let elapsed = now.duration_since(last_real).as_millis() as u64;
            if elapsed < self.config.coalesce_window_ms {
                self.metrics.coalesced_count += 1;
                return false;
            }
        }

        // Check interval: is the next dummy due yet?
        if let Some(not_before) = self.next_dummy_not_before
            && now < not_before
        {
            return false;
        }

        // All checks passed
        true
    }

    /// Generate and record a dummy message
    ///
    /// Call this after `should_send_dummy()` returns `true`.
    ///
    /// # Returns
    /// Serialized dummy message ready to send
    pub fn generate_dummy(&mut self) -> Vec<u8> {
        self.generate_dummy_at(Instant::now())
    }

    fn generate_dummy_at(&mut self, now: Instant) -> Vec<u8> {
        self.consecutive_dummies += 1;
        self.metrics.dummies_sent += 1;

        // Adaptive interval: increase if sending many dummies in a row
        self.adapt_interval();

        // The gap to the next dummy is drawn at random from [base, base * 3 / 2]. A fixed
        // gap is a signature: an observer who sees one message every 30.000 s knows which
        // ones are the dummies, and the real messages are the rest.
        let base = self.current_interval_ms;
        let gap = rand::thread_rng().gen_range(base..=base.saturating_add(base / 2));
        self.next_dummy_not_before = Some(now + Duration::from_millis(gap));

        generate_dummy_message(self.config.message_size)
    }

    /// Adapt the interval based on activity patterns
    ///
    /// If many consecutive dummies are sent, increase the interval to save battery.
    fn adapt_interval(&mut self) {
        // Increase interval every 5 consecutive dummies
        if self.consecutive_dummies.is_multiple_of(5) && self.consecutive_dummies > 0 {
            // `+ 1` so that a 1 ms floor still grows (1 * 3 / 2 == 1 in integers).
            let grown = (self.current_interval_ms.saturating_mul(3) / 2).saturating_add(1);
            self.current_interval_ms = grown
                .min(self.config.max_interval_ms)
                .max(self.config.min_interval_ms);
        }
    }

    /// Get current energy metrics
    pub fn metrics(&self) -> &EnergyMetrics {
        &self.metrics
    }

    /// Reset metrics (useful for testing or periodic reporting)
    pub fn reset_metrics(&mut self) {
        self.metrics = EnergyMetrics::default();
    }

    /// Get current adaptive base interval (for debugging/monitoring). The next dummy is due
    /// somewhere in `[base, base * 3 / 2]` after the previous one.
    pub fn current_interval_ms(&self) -> u64 {
        self.current_interval_ms
    }

    /// Check if currently active (enabled and battery sufficient)
    pub fn is_currently_active(&self) -> bool {
        self.is_active()
    }
}

/// Energy consumption metrics for monitoring
#[derive(Debug, Clone, Default)]
pub struct EnergyMetrics {
    /// Total dummy messages sent
    pub dummies_sent: u64,

    /// Dummy messages skipped due to coalescing
    pub coalesced_count: u64,

    /// Dummy messages skipped due to low battery
    pub battery_skipped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn active(config: CoverTrafficConfig) -> CoverTrafficManager {
        let mut manager = CoverTrafficManager::new(CoverTrafficConfig {
            enabled: true,
            ..config
        });
        manager.update_battery_level(1.0);
        manager
    }

    #[test]
    fn a_dummy_is_exactly_the_configured_size() {
        for size in [0, 1, 128, 255, 256, 512, 1024] {
            assert_eq!(generate_dummy_message(size).len(), size, "size {size}");
        }
    }

    #[test]
    fn a_dummy_carries_no_marker_and_is_not_a_constant() {
        let a = generate_dummy_message(255);
        let b = generate_dummy_message(255);
        assert_ne!(a, b, "two dummies must not be identical");
        assert!(
            !a.windows(11).any(|w| w == b"__CONSTRUCT"),
            "a dummy must not carry a recognisable marker"
        );
    }

    #[test]
    fn test_manager_creation() {
        let config = CoverTrafficConfig::default();
        let manager = CoverTrafficManager::new(config);

        assert_eq!(manager.battery_level, 1.0);
        assert_eq!(manager.consecutive_dummies, 0);
        assert!(!manager.is_currently_active()); // Disabled by default
    }

    #[test]
    fn test_battery_aware_behavior() {
        let config = CoverTrafficConfig {
            enabled: true,
            battery_level_threshold: 0.2,
            ..Default::default()
        };

        let mut manager = CoverTrafficManager::new(config);

        // High battery - should be active
        manager.update_battery_level(0.5);
        assert!(manager.is_currently_active());

        // Low battery - should be inactive
        manager.update_battery_level(0.1);
        assert!(!manager.is_currently_active());
        assert!(!manager.should_send_dummy());
    }

    #[test]
    fn a_real_message_inside_the_coalesce_window_suppresses_the_dummy() {
        let mut manager = active(CoverTrafficConfig {
            coalesce_with_real_messages: true,
            coalesce_window_ms: 100,
            ..Default::default()
        });
        let t0 = Instant::now();

        manager.record_real_message_sent_at(t0);
        assert!(!manager.should_send_dummy_at(t0 + Duration::from_millis(50)));
        assert_eq!(manager.metrics().coalesced_count, 1);

        assert!(manager.should_send_dummy_at(t0 + Duration::from_millis(150)));
    }

    #[test]
    fn the_gap_between_dummies_is_not_fixed() {
        let mut manager = active(CoverTrafficConfig {
            min_interval_ms: 30_000,
            max_interval_ms: 30_000,
            ..Default::default()
        });
        let t0 = Instant::now();
        let mut gaps = std::collections::BTreeSet::new();
        for _ in 0..64 {
            manager.generate_dummy_at(t0);
            let due = manager.next_dummy_not_before.unwrap();
            let gap = due.duration_since(t0).as_millis() as u64;
            assert!(
                (30_000..=45_000).contains(&gap),
                "gap {gap} outside [base, 1.5 base]"
            );
            gaps.insert(gap);
        }
        assert!(
            gaps.len() > 1,
            "64 draws gave one gap: the cadence is deterministic"
        );
    }

    #[test]
    fn a_dummy_is_not_due_before_its_gap_and_is_due_after() {
        let mut manager = active(CoverTrafficConfig {
            min_interval_ms: 1_000,
            max_interval_ms: 1_000,
            coalesce_with_real_messages: false,
            ..Default::default()
        });
        let t0 = Instant::now();
        assert!(
            manager.should_send_dummy_at(t0),
            "nothing sent yet: due now"
        );
        manager.generate_dummy_at(t0);
        assert!(!manager.should_send_dummy_at(t0 + Duration::from_millis(999)));
        assert!(manager.should_send_dummy_at(t0 + Duration::from_millis(1_500)));
    }

    #[test]
    fn the_base_interval_grows_every_five_dummies_up_to_the_ceiling() {
        let mut manager = active(CoverTrafficConfig {
            min_interval_ms: 10,
            max_interval_ms: 1_000,
            ..Default::default()
        });
        let t0 = Instant::now();
        let initial = manager.current_interval_ms();
        for _ in 0..4 {
            manager.generate_dummy_at(t0);
        }
        assert_eq!(
            manager.current_interval_ms(),
            initial,
            "no growth before the fifth"
        );
        manager.generate_dummy_at(t0);
        assert!(manager.current_interval_ms() > initial);
        for _ in 0..200 {
            manager.generate_dummy_at(t0);
        }
        assert_eq!(
            manager.current_interval_ms(),
            1_000,
            "capped at the ceiling"
        );
    }

    #[test]
    fn a_one_millisecond_floor_still_grows() {
        let mut manager = active(CoverTrafficConfig {
            min_interval_ms: 1,
            max_interval_ms: 1_000,
            ..Default::default()
        });
        let t0 = Instant::now();
        for _ in 0..5 {
            manager.generate_dummy_at(t0);
        }
        assert!(manager.current_interval_ms() > 1);
    }

    #[test]
    fn a_ceiling_below_the_floor_never_shortens_the_interval_below_the_floor() {
        let mut manager = active(CoverTrafficConfig {
            min_interval_ms: 100,
            max_interval_ms: 50,
            ..Default::default()
        });
        let t0 = Instant::now();
        for _ in 0..10 {
            manager.generate_dummy_at(t0);
        }
        assert!(manager.current_interval_ms() >= 100);
    }

    #[test]
    fn test_metrics_tracking() {
        let mut manager = active(CoverTrafficConfig {
            min_interval_ms: 10,
            ..Default::default()
        });
        let mut t = Instant::now();
        for _ in 0..3 {
            assert!(manager.should_send_dummy_at(t));
            manager.generate_dummy_at(t);
            t += Duration::from_millis(20);
        }
        assert_eq!(manager.metrics().dummies_sent, 3);

        // A real message just went out: the next dummy is coalesced
        manager.record_real_message_sent_at(t);
        assert!(!manager.should_send_dummy_at(t));
        assert_eq!(manager.metrics().coalesced_count, 1);
    }

    #[test]
    fn test_low_battery_is_counted_as_skipped() {
        let config = CoverTrafficConfig {
            enabled: true,
            ..Default::default()
        };
        let mut manager = CoverTrafficManager::new(config);
        manager.update_battery_level(0.0);
        assert!(!manager.should_send_dummy());
        assert_eq!(manager.metrics().battery_skipped, 1);

        // Disabled is not a battery skip
        let mut off = CoverTrafficManager::new(CoverTrafficConfig::default());
        assert!(!off.should_send_dummy());
        assert_eq!(off.metrics().battery_skipped, 0);
    }

    #[test]
    fn test_real_message_resets_adaptive_interval() {
        let config = CoverTrafficConfig {
            enabled: true,
            min_interval_ms: 100,
            ..Default::default()
        };

        let mut manager = CoverTrafficManager::new(config);
        manager.update_battery_level(1.0);

        // Increase interval
        manager.consecutive_dummies = 10;
        manager.current_interval_ms = 500;

        // Record real message
        manager.record_real_message_sent();

        // Should reset to min
        assert_eq!(manager.current_interval_ms, config.min_interval_ms);
        assert_eq!(manager.consecutive_dummies, 0);
    }
}
