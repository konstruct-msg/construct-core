//! Timing utilities for traffic analysis resistance
//!
//! Provides jittered intervals and delays to prevent timing correlation.
//!
//! ## Energy Efficiency
//!
//! - Minimal CPU wake-ups: No timers, pull-based model
//! - Coalesced with network activity: Piggyback on existing requests
//! - No background threads: Zero overhead when idle
//! - Adaptive delays: Shorter jitter when battery low
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use construct_core::traffic_protection::timing::*;
//! use std::time::Duration;
//!
//! // Add jitter to heartbeat
//! let heartbeat = heartbeat_interval(30); // 30s ± 5s
//!
//! // Delay message sending (prevents timing correlation)
//! let delay = random_send_delay(100); // 0-100ms
//! // ... sleep(delay) then send ...
//!
//! // Battery-aware jitter
//! let battery_level = 0.3; // 30%
//! let jitter = battery_aware_jitter(1000, 500, battery_level); // Reduced jitter
//! ```

use rand::Rng;
use std::time::Duration;

/// Generate a jittered interval
///
/// # Arguments
/// * `base_ms` - Base interval in milliseconds
/// * `jitter_ms` - Maximum random jitter to add
///
/// # Returns
/// Duration with random jitter added
pub fn jittered_interval(base_ms: u64, jitter_ms: u64) -> Duration {
    let jitter = rand::thread_rng().gen_range(0..=jitter_ms);
    Duration::from_millis(base_ms + jitter)
}

/// Generate a random delay before sending a message
///
/// This helps prevent timing correlation between when a message
/// is composed and when it's sent.
///
/// # Arguments
/// * `max_delay_ms` - Maximum delay in milliseconds
///
/// # Returns
/// Random duration between 0 and max_delay_ms
pub fn random_send_delay(max_delay_ms: u64) -> Duration {
    let delay = rand::thread_rng().gen_range(0..=max_delay_ms);
    Duration::from_millis(delay)
}

/// Heartbeat timing with jitter
///
/// # Arguments
/// * `base_interval_sec` - Base heartbeat interval in seconds
///
/// # Returns
/// Jittered interval (±5 seconds)
pub fn heartbeat_interval(base_interval_sec: u64) -> Duration {
    jittered_interval(base_interval_sec * 1000, 5000)
}

/// Battery-aware jittered interval
///
/// Reduces jitter when battery is low to save energy (fewer random number generations,
/// less variance in timers).
///
/// # Arguments
/// * `base_ms` - Base interval in milliseconds
/// * `max_jitter_ms` - Maximum jitter when battery is full
/// * `battery_level` - Current battery level (0.0-1.0)
///
/// # Returns
/// Duration with battery-scaled jitter added
///
/// # Energy Optimization
/// When battery is low (<20%), jitter is reduced by 50% to minimize CPU wake-up variance.
pub fn battery_aware_jitter(base_ms: u64, max_jitter_ms: u64, battery_level: f32) -> Duration {
    // Scale jitter based on battery level
    let jitter_scale = if battery_level < 0.2 {
        0.5 // Reduce jitter by 50% when battery low
    } else if battery_level < 0.5 {
        0.75 // Reduce by 25% when battery medium
    } else {
        1.0 // Full jitter when battery high
    };

    let effective_jitter_ms = (max_jitter_ms as f32 * jitter_scale) as u64;
    jittered_interval(base_ms, effective_jitter_ms)
}

/// Calculate recommended send delay based on message priority and battery
///
/// # Arguments
/// * `is_high_priority` - Whether the message is high priority (user-initiated)
/// * `battery_level` - Current battery level (0.0-1.0)
///
/// # Returns
/// Recommended delay duration
///
/// # Energy Optimization
/// - High priority: minimal delay (0-50ms)
/// - Normal priority + high battery: moderate delay (0-100ms)
/// - Normal priority + low battery: no delay (save energy)
pub fn recommended_send_delay(is_high_priority: bool, battery_level: f32) -> Duration {
    if is_high_priority {
        // High priority messages get minimal delay
        random_send_delay(50)
    } else if battery_level < 0.2 {
        // Low battery: skip delay to save energy
        Duration::from_millis(0)
    } else {
        // Normal case
        random_send_delay(100)
    }
}

/// Configuration for timing behavior
#[derive(Debug, Clone, Copy)]
pub struct TimingConfig {
    /// Base heartbeat interval (seconds)
    pub heartbeat_interval_sec: u64,

    /// Heartbeat jitter (milliseconds)
    pub heartbeat_jitter_ms: u64,

    /// Maximum send delay (milliseconds)
    pub max_send_delay_ms: u64,

    /// Enable timing protection
    pub enabled: bool,

    /// Battery-aware mode (reduce jitter when battery low)
    pub battery_aware: bool,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_sec: 30,
            heartbeat_jitter_ms: 5000, // ±5 seconds
            max_send_delay_ms: 100,    // 0-100ms delay
            enabled: true,
            battery_aware: true, // Enable battery awareness by default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jittered_interval_range() {
        for _ in 0..100 {
            let duration = jittered_interval(1000, 500);
            let ms = duration.as_millis() as u64;
            assert!((1000..=1500).contains(&ms));
        }
    }

    #[test]
    fn test_random_delay_range() {
        for _ in 0..100 {
            let delay = random_send_delay(100);
            assert!(delay.as_millis() <= 100);
        }
    }

    #[test]
    fn test_heartbeat_interval() {
        // Heartbeat should be base ± 5 seconds
        let duration = heartbeat_interval(30);
        let ms = duration.as_millis() as u64;
        assert!((30000..=35000).contains(&ms)); // 30s-35s
    }

    #[test]
    fn test_battery_aware_jitter_full_battery() {
        // Full battery should have full jitter
        let duration = battery_aware_jitter(1000, 500, 1.0);
        let ms = duration.as_millis() as u64;
        assert!((1000..=1500).contains(&ms));
    }

    #[test]
    fn test_battery_aware_jitter_low_battery() {
        // Low battery should have reduced jitter (50%)
        for _ in 0..20 {
            let duration = battery_aware_jitter(1000, 500, 0.1);
            let ms = duration.as_millis() as u64;
            // 50% of 500ms = 250ms, so range is 1000-1250
            assert!((1000..=1250).contains(&ms));
        }
    }

    #[test]
    fn test_battery_aware_jitter_medium_battery() {
        // Medium battery should have 75% jitter
        for _ in 0..20 {
            let duration = battery_aware_jitter(1000, 400, 0.4);
            let ms = duration.as_millis() as u64;
            // 75% of 400ms = 300ms, so range is 1000-1300
            assert!((1000..=1300).contains(&ms));
        }
    }

    #[test]
    fn test_recommended_send_delay_high_priority() {
        // High priority should have minimal delay
        let delay = recommended_send_delay(true, 0.5);
        assert!(delay.as_millis() <= 50);
    }

    #[test]
    fn test_recommended_send_delay_low_battery() {
        // Low battery + normal priority = no delay
        let delay = recommended_send_delay(false, 0.1);
        assert_eq!(delay.as_millis(), 0);
    }

    #[test]
    fn test_recommended_send_delay_normal() {
        // Normal case should have moderate delay
        let delay = recommended_send_delay(false, 0.8);
        assert!(delay.as_millis() <= 100);
    }

    #[test]
    fn test_timing_config_defaults() {
        let config = TimingConfig::default();
        assert!(config.enabled);
        assert!(config.battery_aware);
        assert_eq!(config.heartbeat_interval_sec, 30);
        assert_eq!(config.heartbeat_jitter_ms, 5000);
        assert_eq!(config.max_send_delay_ms, 100);
    }
}
