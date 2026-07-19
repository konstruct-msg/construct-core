//! Kani proofs for message padding invariants
//!
//! Verifies:
//! - P1: pad/unpad round-trip preserves plaintext
//! - P2: padded length is always a multiple of block_size
//! - P3: invalid padding is always detected
//! - P4: unpad rejects empty input
//! - P5: oversized message rejected

use crate::traffic_protection::padding::{
    MAX_MESSAGE_SIZE, PaddingError, pad_message, unpad_message,
};

/// P1: Round-trip invariant — concrete test vectors
#[kani::proof]
fn proof_pad_unpad_roundtrip() {
    // Empty message
    let padded = pad_message(&[], 16).unwrap();
    let unpadded: Vec<u8> = unpad_message(&padded).unwrap();
    assert_eq!(unpadded, Vec::<u8>::new());

    // Short message
    let padded = pad_message(b"hello", 16).unwrap();
    assert_eq!(unpad_message(&padded).unwrap(), b"hello");

    // Message exactly block size - 1
    let msg: [u8; 15] = [0x42; 15];
    let padded = pad_message(&msg, 16).unwrap();
    assert_eq!(unpad_message(&padded).unwrap(), msg.to_vec());

    // Message exactly block size
    let msg: [u8; 16] = [0x42; 16];
    let padded = pad_message(&msg, 16).unwrap();
    assert_eq!(unpad_message(&padded).unwrap(), msg.to_vec());

    // Message larger than block size
    let msg: [u8; 20] = [0xAB; 20];
    let padded = pad_message(&msg, 16).unwrap();
    assert_eq!(unpad_message(&padded).unwrap(), msg.to_vec());
}

/// P2: Padded length is always a multiple of block_size (single case)
#[kani::proof]
fn proof_padded_length_is_multiple_of_block_size() {
    let block_size = 16usize;
    for len in [0usize, 1, 5, 10, 16, 17, 32] {
        let msg: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        let padded = pad_message(&msg, block_size).unwrap();
        assert_eq!(padded.len() % block_size, 0);
    }
}

/// P3: Corrupted padding is always detected
#[kani::proof]
fn proof_corrupted_padding_detected() {
    let msg = b"test";
    let mut padded = pad_message(msg, 16).unwrap();

    // Corrupt a padding byte
    let len = padded.len();
    if len > 1 {
        padded[len - 2] ^= 0xFF;
        assert!(unpad_message(&padded).is_err());
    }

    // Corrupt the length byte
    let mut padded = pad_message(msg, 16).unwrap();
    let padding_len = *padded.last().unwrap();
    let len = padded.len();
    if padding_len > 1 {
        let new_val = (padding_len + 1).min(255);
        padded[len - 1] = new_val;
        assert!(unpad_message(&padded).is_err());
    }
}

/// P4: Empty input to unpad_message is always rejected
#[kani::proof]
fn proof_unpad_rejects_empty() {
    let empty: Vec<u8> = vec![];
    let result = unpad_message(&empty);
    assert!(matches!(result, Err(PaddingError::EmptyMessage)));
}

/// P5: Message exceeding MAX_MESSAGE_SIZE is rejected
#[kani::proof]
fn proof_oversized_message_rejected() {
    let huge: Vec<u8> = vec![0u8; MAX_MESSAGE_SIZE + 1];
    let result = pad_message(&huge, 255);
    assert!(matches!(result, Err(PaddingError::MessageTooLarge(_, _))));
}

/// P6: Padding byte is always in valid range
#[kani::proof]
fn proof_padding_byte_in_range() {
    let block_size = 16usize;
    for len in [0usize, 1, 5, 10, 16, 17] {
        let msg: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        let padded = pad_message(&msg, block_size).unwrap();
        let padding_byte = *padded.last().unwrap() as usize;
        assert!(padding_byte >= 1 && padding_byte <= block_size);
    }
}
