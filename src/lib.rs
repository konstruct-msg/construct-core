// Construct Core
// Cryptographic engine for Construct Messenger with E2EE

#![warn(clippy::all)]
#![allow(clippy::too_many_arguments)]
#![allow(unsafe_attr_outside_unsafe)] // Allow UniFFI generated code

/// Which build this is, readable from the shipped library and nothing else.
///
/// The Android README has told integrators to identify a build by running
/// `strings -a libconstruct_core.so | grep -o 'CONSTRUCT_CORE_VERSION=[^ ]*'`
/// since the
/// pipeline was written, and until this static existed that command printed
/// nothing — an instruction whose reader had no producer.
///
/// It has to be *inside* the library. The install step copies `jniLibs/` and
/// the Kotlin file into the app and leaves the archive behind, so a README, a
/// release note or a sibling `VERSION` file does not travel with the `.so` that
/// ends up in a build. And the rolling `latest` release republishes one URL on
/// every push to main, so two downloads are otherwise indistinguishable.
///
/// `#[used]` because nothing in this crate reads it: the reader is `strings`,
/// and without it the linker is free to drop a static no code references.
#[used]
pub static CONSTRUCT_CORE_VERSION: &str = concat!(
    "CONSTRUCT_CORE_VERSION=",
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("CONSTRUCT_CORE_COMMIT"),
    // Terminator, and the reason the recipe is a plain grep rather than a
    // grammar. `opt-level = "z"` packs `.rodata` literals with no separator
    // between them, so without this the stamp runs straight into whichever
    // literal the linker placed next — `…+847067fdfef7primary_send_covered…`
    // in the archive published on 2026-09-04. `strings` ends a run at the
    // first non-printable byte, so a NUL is what makes the value self-
    // delimiting in the artifact instead of in whoever greps it.
    "\0"
);

// Core modules (platform-independent)
pub mod api;
pub mod cfe;
pub mod config;
pub mod crypto;
pub mod device_id;
pub mod error;
pub mod orchestration;
pub mod pow;
pub mod storage;
pub mod traffic_protection;
pub mod utils;
pub mod wire_payload;

// Kani formal verification proofs (only compiled under `cargo kani`)
#[cfg(kani)]
mod proofs;

// MLS group chat (RFC 9420) — feature-gated, pulls in openmls
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
pub mod group;

#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
pub use group::{MemberAddition, MlsError};

// UniFFI bindings module (types and implementations)
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
mod uniffi_bindings;

// Re-export UniFFI bindings types so generated code can see them
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
pub use uniffi_bindings::*;

// Include UniFFI generated scaffolding when a binding feature is enabled.
// Without `android` in this list, the Android cdylib contains none of the
// uniffi_construct_core_* symbols and linker GC strips ~everything as
// unreachable (the .so is ~458KB with only __wbindgen_* shims exported).
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
include!(concat!(env!("OUT_DIR"), "/construct_core.uniffi.rs"));

// Re-export construct-veil's raw C FFI symbols so the cdylib link keeps them
// alive. Without this `pub use`, `#[no_mangle] pub extern "C" fn veil_start`
// lives in the construct-veil rlib but has no reachable caller from the
// construct-core cdylib — linker GC drops it. iOS uses staticlib (.a) which
// preserves all .o files regardless, so iOS doesn't need this hint.
#[cfg(feature = "android")]
pub use construct_veil::ffi::*;
