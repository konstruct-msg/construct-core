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
//! // Delay message sending (prevents timing correlation)
//! let delay = random_send_delay(100); // 0-100ms
//! // ... sleep(delay) then send ...
//! ```

use rand::Rng;
use std::time::Duration;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_delay_range() {
        for _ in 0..100 {
            let delay = random_send_delay(100);
            assert!(delay.as_millis() <= 100);
        }
    }

    #[test]
    fn a_send_delay_near_the_top_of_u64_does_not_overflow() {
        let delay = random_send_delay(u64::MAX);
        assert!(delay.as_millis() <= u64::MAX as u128);
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
}
