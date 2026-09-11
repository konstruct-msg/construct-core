//! Fuzz target: `wire_payload::unpack` — binary protocol parser.
//!
//! Feeds arbitrary bytes into the wire payload decoder to find panics,
//! OOM, or unexpected behaviour on malformed input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser must never panic on any input.
    let _ = construct_core::wire_payload::unpack(data);
});
