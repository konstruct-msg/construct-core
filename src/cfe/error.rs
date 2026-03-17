use super::types::CfeMessageType;

#[derive(Debug, thiserror::Error)]
pub enum CfeError {
    #[error("Data too short: need ≥{min} bytes, got {got}")]
    TooShort { min: usize, got: usize },

    #[error("Invalid magic bytes (expected 0x4346)")]
    InvalidMagic,

    #[error("Legacy JSON detected — use migration path")]
    LegacyJson,

    #[error("Unsupported CFE version {0}")]
    UnsupportedVersion(u8),

    #[error("Unknown message type 0x{0:02X}")]
    UnknownType(u8),

    #[error("CRC32 mismatch: stored=0x{stored:08X}, computed=0x{computed:08X} — data corruption!")]
    ChecksumMismatch { stored: u32, computed: u32 },

    #[error("Payload too large: max={max}, got={got}")]
    PayloadTooLarge { max: usize, got: usize },

    #[error("Truncated payload: expected={expected}, got={got}")]
    TruncatedPayload { expected: usize, got: usize },

    #[error("Invalid reserved bytes (must be 0x000000)")]
    InvalidReservedBytes,

    #[error("Unsupported flags byte 0x{0:02X}")]
    UnsupportedFlags(u8),

    #[error("Type mismatch: expected {expected:?}, got {got:?}")]
    TypeMismatch {
        expected: CfeMessageType,
        got: CfeMessageType,
    },

    #[error("Serialize failed: {0}")]
    SerializeFailed(String),

    #[error("Deserialize failed: {0}")]
    DeserializeFailed(String),

    #[error("Legacy JSON parse failed: {0}")]
    LegacyJsonParseFailed(String),

    #[error("Base64 decode failed: {0}")]
    Base64DecodeFailed(String),

    #[error("Hex decode failed: {0}")]
    HexDecodeFailed(String),

    #[error("Invalid field: {0}")]
    InvalidField(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}
