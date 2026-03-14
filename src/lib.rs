// Construct Core
// Cryptographic engine for Construct Messenger with E2EE

#![warn(clippy::all)]
#![allow(clippy::too_many_arguments)]
#![allow(unsafe_attr_outside_unsafe)] // Allow UniFFI generated code

// Core modules (platform-independent)
pub mod api;
pub mod config;
pub mod crypto;
pub mod device_id;
pub mod error;
pub mod orchestration;
pub mod pow;
pub mod storage;
pub mod traffic_protection;
pub mod utils;

// UniFFI bindings module (types and implementations)
#[cfg(any(feature = "ios", feature = "mac"))]
mod uniffi_bindings;

// Re-export UniFFI bindings types so generated code can see them
#[cfg(any(feature = "ios", feature = "mac"))]
pub use uniffi_bindings::*;

// Include UniFFI generated scaffolding when ios or mac feature is enabled
#[cfg(any(feature = "ios", feature = "mac"))]
include!(concat!(env!("OUT_DIR"), "/construct_core.uniffi.rs"));
