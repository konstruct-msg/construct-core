//! Frame encoding/decoding for obfs4 data channel.
//!
//! ## Wire format per frame (obfs4 spec §5)
//! ```text
//! [obfuscated_len: 2 bytes][NaCl secretbox: Tag[16] || Type[1] || PayloadLen[2] || Payload || Padding]
//! ```

pub mod decoder;
pub mod encoder;
pub mod length_dist;

pub use encoder::PaddingStrategy;

/// Maximum allowed frame length (secretbox portion), per obfs4 spec §5.
pub const MAX_FRAME_LENGTH: usize = 1448;

/// Overhead inside the secretbox: Tag(16) + Type(1) + PayloadLen(2).
pub const FRAME_OVERHEAD: usize = 16 + 1 + 2;

/// Maximum useful payload per frame.
pub const MAX_FRAME_PAYLOAD: usize = MAX_FRAME_LENGTH - FRAME_OVERHEAD; // 1429

/// Frame header: 2-byte obfuscated length field (before the secretbox).
pub const FRAME_HEADER_LEN: usize = 2;

/// NaCl Poly1305 tag length.
pub const SECRETBOX_TAG_LEN: usize = 16;

/// NaCl secretbox nonce length (prefix[16] + counter[8]).
pub const SECRETBOX_NONCE_LEN: usize = 24;

/// Packet types inside a frame.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Application data payload.
    Payload = 0x00,
    /// PRNG seed for protocol polymorphism (24 bytes of seeding material).
    PrngSeed = 0x01,
}

impl PacketType {
    /// Parse a byte into a PacketType, returning None for unknown types.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(PacketType::Payload),
            0x01 => Some(PacketType::PrngSeed),
            _ => None,
        }
    }
}

/// Length of PRNG seed payload in a TYPE_PRNG_SEED frame.
pub const PRNG_SEED_LEN: usize = 24;
