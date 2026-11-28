// Construct Core
// Cryptographic engine for Construct Messenger with E2EE

#![warn(clippy::all)]
#![allow(clippy::too_many_arguments)]
#![allow(unsafe_attr_outside_unsafe)]
// Allow UniFFI generated code
// UniFFI's generated UDL metadata is one large const (clippy 1.100 asks for a static); the code
// is uniffi's, included below, and an attribute on `include!` is ignored.
#![cfg_attr(
    any(feature = "ios", feature = "mac", feature = "android"),
    allow(clippy::large_const_arrays)
)]

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
pub mod cfe;
pub mod config;
pub mod crypto;
pub mod device_id;
pub mod device_link_qr;
pub mod error;
pub mod history;
pub mod intake;
pub mod knst;
mod limits;
pub mod media;
pub mod orchestration;
pub mod pow;
mod protobuf_wire;
pub mod rule_state;
pub mod session_token;
pub mod share_draft;
pub mod traffic_protection;
pub mod utils;
pub mod wire_payload;

// The lib test binary's allocator: finds secrets freed without being wiped.
#[cfg(test)]
pub(crate) mod freed_secret_scan;

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

// The local store (`construct-store`) in this library's UniFFI component.
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
mod local_store_bindings;
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
pub use local_store_bindings::*;

// The client rules (`construct-rules`) in this library's UniFFI component.
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
mod rules_bindings;
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
pub use rules_bindings::*;

// Include UniFFI generated scaffolding when a binding feature is enabled.
// Without `android` in this list, the Android cdylib contains none of the
// uniffi_construct_core_* symbols and linker GC strips ~everything as
// unreachable (the .so is ~458KB with only __wbindgen_* shims exported).
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
include!(concat!(env!("OUT_DIR"), "/construct_core.uniffi.rs"));

// construct-veil's C ABI (`veil_start`, `veil_front_ferry_fd`, …) ships inside this library.
// Without a path from here rustc leaves the construct-veil rlib out of the staticlib, and the
// cdylib's linker drops it. On Apple that was made up for outside: the app's build script
// merged construct-veil's own staticlib into this one, two archives with a copy of std and the
// shared crates each, and neither could be link-time optimised (todo 341).
#[cfg(any(feature = "ios", feature = "mac", feature = "android"))]
pub use construct_veil::ffi::*;
