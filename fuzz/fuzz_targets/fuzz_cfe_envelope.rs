//! Fuzz target: `cfe::envelope::decode` — CFE binary envelope parser.
//!
//! Tests that arbitrary bytes never cause a panic in the CFE header/CRC
//! parsing path. Also exercises the legacy JSON detection code path.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = construct_core::cfe::decode(data);
});
