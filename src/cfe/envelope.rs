use super::compat::legacy_json_error_if_detected;
use super::error::CfeError;
use super::types::CfeMessageType;
use crc32fast::Hasher as Crc32Hasher;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub const CFE_MAGIC: [u8; 2] = [0x43, 0x46]; // "CF"
pub const CFE_VERSION: u8 = 0x01;
pub const CFE_HEADER_LEN: usize = 16;

/// Largest payload of a message-sized envelope (`Generic`, 256 KiB).
///
/// Plaintext is limited to 64 KiB (`MAX_MESSAGE_SIZE`); after padding, AEAD and the ratchet
/// header a legitimate message envelope is well under 128 KiB. The cap stops an attacker from
/// making the reader allocate multi-MiB buffers before authentication fails.
pub const MAX_PAYLOAD_LEN: usize = 256 * 1024;

/// Largest payload of a state blob (64 MiB): the orchestrator state, the MLS store, a session
/// record and the key stores grow with use and are read back from this device's own secure
/// store, never from the network. Until 0.54.2 every type shared the 256 KiB cap, and only on
/// decode: a state blob that grew past it was written without complaint and refused at the
/// next launch, so the state it held was gone.
pub const MAX_STATE_PAYLOAD_LEN: usize = 64 * 1024 * 1024;

/// The payload cap of `msg_type`, applied on both sides: `encode` refuses to write a blob the
/// reader would refuse, so the writer learns at write time, not the next launch.
pub fn max_payload_len(msg_type: CfeMessageType) -> usize {
    match msg_type {
        CfeMessageType::Generic => MAX_PAYLOAD_LEN,
        CfeMessageType::PrivateKeys
        | CfeMessageType::SessionState
        | CfeMessageType::OtpkBundle
        | CfeMessageType::RegistrationBundle
        | CfeMessageType::OrchestratorState
        | CfeMessageType::KyberPrivateKeys
        | CfeMessageType::MlsStore => MAX_STATE_PAYLOAD_LEN,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfeEnvelope {
    pub version: u8,
    pub msg_type: CfeMessageType,
    pub flags: u8,
    pub payload: Vec<u8>,
}

/// The flags byte is part of the header format but no flag is defined: it is written as zero
/// and any other value is refused on read.
pub fn encode<T: Serialize>(msg_type: CfeMessageType, value: &T) -> Result<Vec<u8>, CfeError> {
    let payload =
        rmp_serde::to_vec_named(value).map_err(|e| CfeError::SerializeFailed(e.to_string()))?;
    let max = max_payload_len(msg_type);
    if payload.len() > max {
        return Err(CfeError::PayloadTooLarge {
            max,
            got: payload.len(),
        });
    }

    let crc = {
        let mut hasher = Crc32Hasher::new();
        hasher.update(&payload);
        hasher.finalize()
    };

    let mut out = Vec::with_capacity(CFE_HEADER_LEN + payload.len());
    out.extend_from_slice(&CFE_MAGIC);
    out.push(CFE_VERSION);
    out.push(msg_type as u8);
    out.push(0); // flags: none defined
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
    if flags != 0 {
        return Err(CfeError::UnsupportedFlags(flags));
    }

    if data[5] != 0 || data[6] != 0 || data[7] != 0 {
        return Err(CfeError::InvalidReservedBytes);
    }

    let payload_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let max = max_payload_len(msg_type);
    if payload_len > max {
        return Err(CfeError::PayloadTooLarge {
            max,
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

    #[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Big {
        #[serde(with = "serde_bytes")]
        blob: Vec<u8>,
    }

    #[test]
    fn a_state_blob_past_256_kib_is_written_and_read_back() {
        let big = Big {
            blob: vec![7u8; MAX_PAYLOAD_LEN + 1],
        };
        for msg_type in [
            CfeMessageType::OrchestratorState,
            CfeMessageType::MlsStore,
            CfeMessageType::SessionState,
            CfeMessageType::PrivateKeys,
            CfeMessageType::OtpkBundle,
            CfeMessageType::KyberPrivateKeys,
            CfeMessageType::RegistrationBundle,
        ] {
            let bytes = encode(msg_type, &big).expect("a state blob is not capped at 256 KiB");
            let back: Big = decode_as(&bytes, msg_type).expect("and reads back");
            assert_eq!(back, big);
        }
    }

    #[test]
    fn a_generic_payload_past_256_kib_is_refused_when_written_not_when_read() {
        let big = Big {
            blob: vec![7u8; MAX_PAYLOAD_LEN + 1],
        };
        assert!(matches!(
            encode(CfeMessageType::Generic, &big),
            Err(CfeError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn a_state_blob_past_its_own_cap_is_refused_on_read() {
        // A header that claims more than the state cap is refused before any allocation.
        let mut bytes = encode(CfeMessageType::OrchestratorState, &Big { blob: vec![1] }).unwrap();
        let claimed = (MAX_STATE_PAYLOAD_LEN as u32 + 1).to_le_bytes();
        bytes[8..12].copy_from_slice(&claimed);
        assert!(matches!(
            decode_as::<Big>(&bytes, CfeMessageType::OrchestratorState),
            Err(CfeError::PayloadTooLarge { .. })
        ));
    }
}
