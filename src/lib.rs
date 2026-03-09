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
pub mod pow;
pub mod storage;
pub mod traffic_protection;
pub mod utils;

// UniFFI bindings module (types and implementations)
#[cfg(feature = "ios")]
mod uniffi_bindings;

// Re-export UniFFI bindings types so generated code can see them
#[cfg(feature = "ios")]
pub use uniffi_bindings::*;

// Include UniFFI generated scaffolding when ios feature is enabled
#[cfg(feature = "ios")]
include!(concat!(env!("OUT_DIR"), "/construct_core.uniffi.rs"));
