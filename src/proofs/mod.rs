//! Kani formal verification proofs
//!
//! Each submodule contains `#[kani::proof]` harnesses that verify
//! security-critical invariants using bounded model checking.
//!
//! Run: `cargo kani --enable-unstable`

#[cfg(kani)]
mod padding_kani;

#[cfg(kani)]
mod suite_id_kani;

#[cfg(kani)]
mod device_id_kani;

#[cfg(kani)]
mod wire_payload_kani;
