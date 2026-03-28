//! Traffic Protection module
//!
//! Implements countermeasures against traffic analysis:
//! - Message padding (hide message length)
//! - Cover traffic (hide communication patterns)
//! - Timing jitter (hide timing patterns)
//!
//! ## Energy Efficiency
//!
//! This module is designed with mobile battery life as a priority:
//! - Padding: Zero overhead (only during encryption/decryption)
//! - Cover traffic: Battery-aware with adaptive intervals
//! - Timing jitter: Minimal CPU wake-ups

pub mod cover_traffic;
pub mod padding;
pub mod timing;

// Re-exports
pub use cover_traffic::{
    CoverTrafficConfig, CoverTrafficManager, EnergyMetrics, generate_dummy_message,
    is_dummy_message,
};
pub use padding::{
    DEFAULT_BLOCK_SIZE, PaddingError, pad_message, pad_message_default, unpad_message,
};
pub use timing::{
    TimingConfig, battery_aware_jitter, heartbeat_interval, jittered_interval, random_send_delay,
    recommended_send_delay,
};
