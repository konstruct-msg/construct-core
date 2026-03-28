//! Message padding to prevent length-based traffic analysis
//!
//! All messages are padded to fixed block sizes to prevent
//! an observer from determining message length.
//!
//! ## Energy Efficiency
//!
//! - Zero overhead: padding only happens during encrypt/decrypt
//! - No background tasks or timers
//! - Minimal allocations (pre-allocated Vec with capacity)

use thiserror::Error;

/// Default block size for padding (255 bytes)
/// Must be <= 255 to fit padding length in u8
pub const DEFAULT_BLOCK_SIZE: usize = 255;

/// Maximum supported message size (64KB)
pub const MAX_MESSAGE_SIZE: usize = 65536;

#[derive(Debug, Error)]
pub enum PaddingError {
    #[error("Message too large: {0} bytes (max {1})")]
    MessageTooLarge(usize, usize),

    #[error("Padding is invalid or corrupted")]
    InvalidPadding,

    #[error("Message is empty")]
    EmptyMessage,
}

/// Pad a message to a multiple of block_size using PKCS7-style padding
///
/// # Arguments
/// * `plaintext` - Original message bytes
/// * `block_size` - Block size to pad to (default: 256 bytes)
///
/// # Returns
/// Padded message where:
/// - Length is multiple of block_size
/// - Last byte indicates padding length
///
/// # Energy Efficiency
/// - Single allocation with exact capacity
/// - No heap fragmentation
/// - Constant-time operation
///
/// # Example
/// ```
/// use construct_core::traffic_protection::padding::pad_message;
/// let msg = b"Hello";
/// let padded = pad_message(msg, 255).unwrap();
/// assert_eq!(padded.len(), 255);
/// ```
pub fn pad_message(plaintext: &[u8], block_size: usize) -> Result<Vec<u8>, PaddingError> {
    if plaintext.len() > MAX_MESSAGE_SIZE {
        return Err(PaddingError::MessageTooLarge(
            plaintext.len(),
            MAX_MESSAGE_SIZE,
        ));
    }

    // Calculate padding needed
    let blocks = (plaintext.len() / block_size) + 1;
    let padded_len = blocks * block_size;
    let padding_len = padded_len - plaintext.len();

    // Padding length must fit in u8 (1-255)
    // Since block_size <= 256, this is always true
    let padding_byte = padding_len as u8;

    // Pre-allocate with exact capacity (energy efficient)
    let mut result = Vec::with_capacity(padded_len);
    result.extend_from_slice(plaintext);
    result.extend(std::iter::repeat_n(padding_byte, padding_len));

    debug_assert_eq!(result.len() % block_size, 0);
    Ok(result)
}

/// Pad message with default block size (256 bytes)
pub fn pad_message_default(plaintext: &[u8]) -> Result<Vec<u8>, PaddingError> {
    pad_message(plaintext, DEFAULT_BLOCK_SIZE)
}

/// Remove PKCS7-style padding from a message
///
/// # Arguments
/// * `padded` - Padded message bytes
///
/// # Returns
/// Original plaintext with padding removed
///
/// # Security
/// Uses constant-time comparison for padding validation
///
/// # Energy Efficiency
/// - Single allocation
/// - Early validation before allocation
pub fn unpad_message(padded: &[u8]) -> Result<Vec<u8>, PaddingError> {
    if padded.is_empty() {
        return Err(PaddingError::EmptyMessage);
    }

    let padding_len = *padded.last().unwrap() as usize;

    // Validate padding length
    if padding_len == 0 || padding_len > padded.len() || padding_len > 255 {
        return Err(PaddingError::InvalidPadding);
    }

    // Verify all padding bytes are correct (constant-time comparison)
    // ✅ SECURITY: Use constant-time validation to prevent timing attacks
    // Ref: SECURITY_AUDIT.md #12 - Non-constant-time padding check
    let start = padded.len() - padding_len;
    let expected_byte = padding_len as u8;

    // XOR-based constant-time comparison - accumulator stays 0 only if all bytes match
    let mut diff: u8 = 0;
    for &byte in &padded[start..] {
        diff |= byte ^ expected_byte;
    }

    if diff != 0 {
        return Err(PaddingError::InvalidPadding);
    }

    Ok(padded[..start].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let messages = vec![
            b"Hello".to_vec(),
            b"A".to_vec(),
            vec![0u8; 254], // Just under block size
            vec![0u8; 255], // Exactly block size
            vec![0u8; 256], // Just over block size
            b"".to_vec(),   // Empty message -> 255 bytes of padding
        ];

        for msg in &messages {
            let padded = pad_message(msg, 255).unwrap();
            assert_eq!(
                padded.len() % 255,
                0,
                "Padded length should be multiple of 255"
            );

            let unpadded = unpad_message(&padded).unwrap();
            assert_eq!(&unpadded, msg, "Roundtrip should preserve message");
        }
    }

    #[test]
    fn test_all_messages_same_block_size() {
        // Short messages should all pad to same size
        let short_msgs: Vec<&[u8]> = vec![b"Hi", b"Hello there", b"How are you doing today?"];

        let padded_sizes: Vec<_> = short_msgs
            .iter()
            .map(|m| pad_message(m, 255).unwrap().len())
            .collect();

        assert!(
            padded_sizes.iter().all(|&s| s == 255),
            "All short messages should pad to 255 bytes"
        );
    }

    #[test]
    fn test_invalid_padding_detected() {
        // Corrupted padding
        let mut bad = vec![0u8; 255];
        bad[254] = 10; // Claims 10 bytes padding
        bad[253] = 5; // But this byte is wrong

        assert!(unpad_message(&bad).is_err());
    }

    #[test]
    fn test_message_too_large() {
        let huge_msg = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(pad_message(&huge_msg, 256).is_err());
    }

    #[test]
    fn test_empty_message_pads_to_block_size() {
        let empty = b"";
        let padded = pad_message(empty, 255).unwrap();
        assert_eq!(padded.len(), 255);

        let unpadded = unpad_message(&padded).unwrap();
        assert_eq!(unpadded, empty);
    }
}
