//! Fuzz target: CFE envelope round-trip — encode → decode must be lossless.
//!
//! Uses `arbitrary` to generate structured input, encodes it as a CFE
//! envelope (with CRC32), then decodes and verifies the envelope matches.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Arbitrary)]
struct FuzzPayload {
    a: u64,
    b: i32,
    c: String,
    d: Vec<u8>,
}

fuzz_target!(|input: FuzzPayload| {
    // Limit string/vec sizes to prevent trivial OOM.
    if input.c.len() > 4096 || input.d.len() > 4096 {
        return;
    }

    let encoded = match construct_core::cfe::encode(
        construct_core::cfe::CfeMessageType::Generic,
        &input,
    ) {
        Ok(e) => e,
        Err(_) => return,
    };

    let envelope =
        construct_core::cfe::decode(&encoded).expect("round-trip decode must succeed");

    assert_eq!(envelope.version, 0x01);
    assert_eq!(
        envelope.msg_type,
        construct_core::cfe::CfeMessageType::Generic
    );
    assert_eq!(envelope.flags, 0);

    // Verify the deserialized payload matches.
    let decoded: FuzzPayload =
        rmp_serde::from_slice(&envelope.payload).expect("msgpack round-trip must succeed");
    assert_eq!(decoded, input);
});
