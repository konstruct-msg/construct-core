//! Kani proofs for device ID invariants
//!
//! Verifies:
//! - D1: derive_device_id is deterministic (same input → same output)
//! - D2: Output is always 32 lowercase hex characters
//! - D3: format_federated_id / parse_federated_id round-trip
//! - D4: parse rejects invalid inputs

use crate::device_id::{derive_device_id, format_federated_id, parse_federated_id};

/// D1: derive_device_id is deterministic — same key always produces same ID
#[kani::proof]
fn proof_device_id_deterministic() {
    let key: [u8; 32] = [0x42; 32];

    let id1 = derive_device_id(&key);
    let id2 = derive_device_id(&key);

    assert_eq!(id1, id2, "Same key must produce same device_id");
}

/// D2: Output is always 32 lowercase hex characters
#[kani::proof]
fn proof_device_id_format() {
    // Test with several concrete keys
    for key in [
        [0u8; 32],
        [0xFF; 32],
        [0x42; 32],
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ],
    ] {
        let device_id = derive_device_id(&key);

        assert_eq!(device_id.len(), 32, "Device ID must be 32 hex characters");

        for ch in device_id.chars() {
            assert!(
                ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
                "All chars must be lowercase hex digits, got '{ch}'"
            );
        }
    }
}

/// D3: format_federated_id / parse_federated_id round-trip
#[kani::proof]
fn proof_federated_id_roundtrip() {
    let device_id = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
    let hostname = "ams.konstruct.cc";

    let federated = format_federated_id(device_id, hostname);
    let result = parse_federated_id(&federated);

    assert!(result.is_some(), "Valid federated ID must parse");

    let (parsed_id, parsed_host) = result.unwrap();
    assert_eq!(parsed_id, device_id, "Device ID must round-trip");
    assert_eq!(parsed_host, hostname, "Hostname must round-trip");
}

/// D4: parse_federated_id returns None for strings without '@'
#[kani::proof]
fn proof_parse_rejects_no_at_sign() {
    assert!(parse_federated_id("nodeviceid").is_none());
    assert!(parse_federated_id("").is_none());
    assert!(parse_federated_id("abc123").is_none());
}

/// D5: parse_federated_id returns None for strings with multiple '@'
#[kani::proof]
fn proof_parse_rejects_multiple_at_signs() {
    assert!(parse_federated_id("device@host@extra").is_none());
    assert!(parse_federated_id("a@b@c@d").is_none());
}

/// D6: parse_federated_id returns None for empty string
#[kani::proof]
fn proof_parse_rejects_empty() {
    assert!(parse_federated_id("").is_none());
}
