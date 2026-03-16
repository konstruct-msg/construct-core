//! Cover traffic generation
//!
//! Generates dummy messages to hide real communication patterns.
//!
//! ## Energy Efficiency (Battery-First Design)
//!
//! - Battery-aware: auto-disable when battery < 20%
//! - Network coalescing: piggyback on real messages
//! - Adaptive intervals: increase when idle
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
//!     let dummy = generate_dummy_message(255);
//!     // Send to server
//! }
//!
//! // Record real message sent (for coalescing)
//! manager.record_real_message_sent();
//! ```

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Marker bytes for dummy messages (server ignores these)
const DUMMY_MARKER: &[u8] = b"__CONSTRUCT_DUMMY__";

/// Dummy message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyMessage {
    /// Marker to identify as dummy
    marker: String,

    /// Random padding
    #[serde(with = "serde_bytes")]
    padding: Vec<u8>,
}

/// Generate a dummy message that looks like real traffic
///
/// # Arguments
/// * `size` - Target size in bytes (will pad to this size)
///
/// # Returns
/// Serialized dummy message bytes
///
/// # Energy Efficiency
/// - Pre-allocated buffer
/// - Single RNG call
pub fn generate_dummy_message(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let overhead = DUMMY_MARKER.len() + 32; // Approximate serialization overhead
    let padding_size = size.saturating_sub(overhead);

    let mut padding = vec![0u8; padding_size];
    rng.fill_bytes(&mut padding);

    let dummy = DummyMessage {
        marker: String::from_utf8_lossy(DUMMY_MARKER).to_string(),
        padding,
    };

    rmp_serde::to_vec(&dummy).unwrap_or_else(|_| vec![0u8; size])
}

/// Check if a message is a dummy message
///
/// Server should call this and discard dummy messages.
pub fn is_dummy_message(data: &[u8]) -> bool {
    // Try to deserialize
    if let Ok(msg) = rmp_serde::from_slice::<DummyMessage>(data) {
        return msg.marker == String::from_utf8_lossy(DUMMY_MARKER);
    }

    // Fallback: check raw bytes
    if data.len() > DUMMY_MARKER.len() {
        return data.windows(DUMMY_MARKER.len()).any(|w| w == DUMMY_MARKER);
    }

    false
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

    /// Last time a dummy message was sent
    last_dummy_message: Option<Instant>,

    /// Current adaptive interval (adjusts based on activity)
    current_interval_ms: u64,

    /// Number of consecutive dummy messages sent
    consecutive_dummies: u32,

    /// Energy metrics
    metrics: EnergyMetrics,
}

impl CoverTrafficManager {
    /// Create a new manager with the given configuration
    pub fn new(config: CoverTrafficConfig) -> Self {
        Self {
            current_interval_ms: config.min_interval_ms,
            battery_level: 1.0, // Assume full battery initially
            last_real_message: None,
            last_dummy_message: None,
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
        self.last_real_message = Some(Instant::now());

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
        // Check if active
        if !self.is_active() {
            return false;
        }

        let now = Instant::now();

        // Check coalescing: skip if real message sent recently
        if self.config.coalesce_with_real_messages {
            if let Some(last_real) = self.last_real_message {
                let elapsed = now.duration_since(last_real).as_millis() as u64;
                if elapsed < self.config.coalesce_window_ms {
                    self.metrics.coalesced_count += 1;
                    return false;
                }
            }
        }

        // Check interval: has enough time passed since last dummy?
        if let Some(last_dummy) = self.last_dummy_message {
            let elapsed = now.duration_since(last_dummy).as_millis() as u64;
            if elapsed < self.current_interval_ms {
                return false;
            }
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
        self.last_dummy_message = Some(Instant::now());
        self.consecutive_dummies += 1;
        self.metrics.dummies_sent += 1;

        // Adaptive interval: increase if sending many dummies in a row
        self.adapt_interval();

        generate_dummy_message(self.config.message_size)
    }

    /// Adapt the interval based on activity patterns
    ///
    /// If many consecutive dummies are sent, increase the interval to save battery.
    fn adapt_interval(&mut self) {
        // Increase interval every 5 consecutive dummies
        if self.consecutive_dummies % 5 == 0 && self.consecutive_dummies > 0 {
            self.current_interval_ms =
                (self.current_interval_ms * 3 / 2).min(self.config.max_interval_ms);
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

    /// Get current adaptive interval (for debugging/monitoring)
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

impl EnergyMetrics {
    /// Calculate energy efficiency ratio
    ///
    /// Higher is better. 0.0 means all dummies sent, 1.0 means all coalesced.
    pub fn efficiency_ratio(&self) -> f32 {
        let total = self.dummies_sent + self.coalesced_count;
        if total == 0 {
            return 0.0;
        }
        self.coalesced_count as f32 / total as f32
    }

    /// Total messages considered (sent + skipped)
    pub fn total_considered(&self) -> u64 {
        self.dummies_sent + self.coalesced_count + self.battery_skipped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_dummy_message_detection() {
        let dummy = generate_dummy_message(255);
        assert!(is_dummy_message(&dummy));

        let real_msg = b"This is a real message";
        assert!(!is_dummy_message(real_msg));
    }

    #[test]
    fn test_dummy_message_size() {
        for size in [128, 255, 512, 1024] {
            let dummy = generate_dummy_message(size);
            // Allow some variance due to serialization
            assert!(dummy.len() >= size / 2 && dummy.len() <= size * 2);
        }
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
    fn test_coalescing_behavior() {
        let config = CoverTrafficConfig {
            enabled: true,
            coalesce_with_real_messages: true,
            coalesce_window_ms: 100, // 100ms for faster testing
            ..Default::default()
        };

        let mut manager = CoverTrafficManager::new(config);
        manager.update_battery_level(1.0);

        // Record real message
        manager.record_real_message_sent();

        // Should not send dummy within coalesce window
        assert!(!manager.should_send_dummy());
        assert_eq!(manager.metrics().coalesced_count, 1);

        // Wait for coalesce window to pass
        thread::sleep(Duration::from_millis(150));

        // Now should be able to send
        assert!(manager.should_send_dummy());
    }

    #[test]
    fn test_adaptive_interval() {
        let config = CoverTrafficConfig {
            enabled: true,
            min_interval_ms: 10, // Very short for testing
            max_interval_ms: 1000,
            ..Default::default()
        };

        let mut manager = CoverTrafficManager::new(config);
        manager.update_battery_level(1.0);

        let initial_interval = manager.current_interval_ms();

        // Send multiple dummies to trigger adaptive interval
        for _ in 0..10 {
            if manager.should_send_dummy() {
                manager.generate_dummy();
                thread::sleep(Duration::from_millis(20)); // Wait for interval
            }
        }

        // Interval should have increased
        assert!(manager.current_interval_ms() > initial_interval);
        assert!(manager.current_interval_ms() <= config.max_interval_ms);
    }

    #[test]
    fn test_metrics_tracking() {
        let config = CoverTrafficConfig {
            enabled: true,
            min_interval_ms: 10, // Very short for testing
            ..Default::default()
        };

        let mut manager = CoverTrafficManager::new(config);
        manager.update_battery_level(1.0);

        // Send some dummies
        for _ in 0..3 {
            if manager.should_send_dummy() {
                manager.generate_dummy();
                thread::sleep(Duration::from_millis(20)); // Wait for interval
            }
        }

        let metrics = manager.metrics();
        assert_eq!(metrics.dummies_sent, 3);

        // Test efficiency ratio
        manager.record_real_message_sent();
        assert!(!manager.should_send_dummy()); // Coalesced
        let efficiency = manager.metrics().efficiency_ratio();
        assert!(efficiency > 0.0);
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
