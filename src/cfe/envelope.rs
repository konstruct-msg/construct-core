use super::compat::legacy_json_error_if_detected;
use super::error::CfeError;
use super::types::CfeMessageType;
use crc32fast::Hasher as Crc32Hasher;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub const CFE_MAGIC: [u8; 2] = [0x43, 0x46]; // "CF"
pub const CFE_VERSION: u8 = 0x01;
pub const CFE_HEADER_LEN: usize = 16;

pub const FLAG_COMPRESSED: u8 = 0x01;
pub const FLAG_ENCRYPTED: u8 = 0x02;
pub const FLAG_CHUNKED: u8 = 0x04;
pub const FLAG_SIGNED: u8 = 0x08;

pub const SUPPORTED_FLAGS_MASK: u8 = 0x00;

/// Maximum allowed payload size (64 MiB). Protects against malformed length field.
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfeEnvelope {
    pub version: u8,
    pub msg_type: CfeMessageType,
    pub flags: u8,
    pub payload: Vec<u8>,
}

pub fn encode<T: Serialize>(msg_type: CfeMessageType, value: &T) -> Result<Vec<u8>, CfeError> {
    encode_with_flags(msg_type, value, 0)
}

pub fn encode_with_flags<T: Serialize>(
    msg_type: CfeMessageType,
    value: &T,
    flags: u8,
) -> Result<Vec<u8>, CfeError> {
    if flags & !SUPPORTED_FLAGS_MASK != 0 {
        return Err(CfeError::UnsupportedFlags(flags));
    }

    let payload =
        rmp_serde::to_vec_named(value).map_err(|e| CfeError::SerializeFailed(e.to_string()))?;

    let crc = {
        let mut hasher = Crc32Hasher::new();
        hasher.update(&payload);
        hasher.finalize()
    };

    let mut out = Vec::with_capacity(CFE_HEADER_LEN + payload.len());
    out.extend_from_slice(&CFE_MAGIC);
    out.push(CFE_VERSION);
    out.push(msg_type as u8);
    out.push(flags);
    out.extend_from_slice(&[0u8; 3]); // reserved
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode(data: &[u8]) -> Result<CfeEnvelope, CfeError> {
    parse_header(data)
}

pub fn decode_as<T: DeserializeOwned>(
    data: &[u8],
    expected_type: CfeMessageType,
) -> Result<T, CfeError> {
    let envelope = parse_header(data)?;
    if envelope.msg_type != expected_type {
        return Err(CfeError::TypeMismatch {
            expected: expected_type,
            got: envelope.msg_type,
        });
    }
    rmp_serde::from_slice(&envelope.payload).map_err(|e| CfeError::DeserializeFailed(e.to_string()))
}

pub fn parse_header(data: &[u8]) -> Result<CfeEnvelope, CfeError> {
    if data.len() < CFE_HEADER_LEN {
        legacy_json_error_if_detected(data)?;
        return Err(CfeError::TooShort {
            min: CFE_HEADER_LEN,
            got: data.len(),
        });
    }

    if data[0..2] != CFE_MAGIC {
        legacy_json_error_if_detected(data)?;
        return Err(CfeError::InvalidMagic);
    }

    let version = data[2];
    if version != CFE_VERSION {
        return Err(CfeError::UnsupportedVersion(version));
    }

    let msg_type_raw = data[3];
    let msg_type =
        CfeMessageType::from_u8(msg_type_raw).ok_or(CfeError::UnknownType(msg_type_raw))?;

    let flags = data[4];
    if flags & !SUPPORTED_FLAGS_MASK != 0 {
        return Err(CfeError::UnsupportedFlags(flags));
    }

    if data[5] != 0 || data[6] != 0 || data[7] != 0 {
        return Err(CfeError::InvalidReservedBytes);
    }

    let payload_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(CfeError::PayloadTooLarge {
            max: MAX_PAYLOAD_LEN,
            got: payload_len,
        });
    }

    let total_len = CFE_HEADER_LEN + payload_len;
    if data.len() < total_len {
        return Err(CfeError::TruncatedPayload {
            expected: payload_len,
            got: data.len().saturating_sub(CFE_HEADER_LEN),
        });
    }

    let stored_crc = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let raw_payload = &data[CFE_HEADER_LEN..total_len];

    let computed_crc = {
        let mut hasher = Crc32Hasher::new();
        hasher.update(raw_payload);
        hasher.finalize()
    };
    if stored_crc != computed_crc {
        return Err(CfeError::ChecksumMismatch {
            stored: stored_crc,
            computed: computed_crc,
        });
    }

    Ok(CfeEnvelope {
        version,
        msg_type,
        flags,
        payload: raw_payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Dummy {
        a: u32,
        b: String,
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let msg = Dummy {
            a: 42,
            b: "hello".to_string(),
        };
        let bytes = encode(CfeMessageType::Generic, &msg).expect("encode");
        let decoded: Dummy = decode_as(&bytes, CfeMessageType::Generic).expect("decode_as");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_crc_corruption_detected() {
        let msg = Dummy {
            a: 7,
            b: "world".to_string(),
        };
        let mut bytes = encode(CfeMessageType::Generic, &msg).expect("encode");
        let payload_start = CFE_HEADER_LEN;
        bytes[payload_start] ^= 0xFF;
        let err = decode(&bytes).expect_err("must fail");
        assert!(matches!(err, CfeError::ChecksumMismatch { .. }));
    }

    #[test]
    fn test_legacy_json_detected() {
        let data = br#"{"k":"v"}"#;
        let err = decode(data).expect_err("must fail");
        assert!(matches!(err, CfeError::LegacyJson), "got {err:?}");
    }

    #[test]
    fn test_reserved_bytes_validation() {
        let msg = Dummy {
            a: 1,
            b: "x".to_string(),
        };
        let mut bytes = encode(CfeMessageType::Generic, &msg).expect("encode");
        bytes[5] = 1;
        let err = decode(&bytes).expect_err("must fail");
        assert!(matches!(err, CfeError::InvalidReservedBytes));
    }

    #[test]
    fn test_truncated_payload_detected() {
        let msg = Dummy {
            a: 2,
            b: "y".to_string(),
        };
        let bytes = encode(CfeMessageType::Generic, &msg).expect("encode");
        let truncated = &bytes[..bytes.len() - 1];
        let err = decode(truncated).expect_err("must fail");
        assert!(matches!(err, CfeError::TruncatedPayload { .. }));
    }

    #[test]
    fn test_payload_too_large_rejected() {
        let mut bytes = vec![0u8; CFE_HEADER_LEN];
        bytes[0..2].copy_from_slice(&CFE_MAGIC);
        bytes[2] = CFE_VERSION;
        bytes[3] = CfeMessageType::Generic as u8;
        bytes[4] = 0;
        bytes[5] = 0;
        bytes[6] = 0;
        bytes[7] = 0;
        let too_large = (MAX_PAYLOAD_LEN as u32) + 1;
        bytes[8..12].copy_from_slice(&too_large.to_le_bytes());
        bytes[12..16].copy_from_slice(&0u32.to_le_bytes());

        let err = decode(&bytes).expect_err("must fail");
        assert!(matches!(err, CfeError::PayloadTooLarge { .. }));
    }
}
