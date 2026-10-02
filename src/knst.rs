//! The KNST plaintext frame: the 30-byte header every message body is framed with before it is
//! encrypted.
//!
//! ```text
//! [0..4]   magic b"KNST"
//! [4]      version 0x01
//! [5]      content_type — inside the ciphertext, which is why the server cannot read it
//! [6..22]  message id, the UUID's 16 raw bytes
//! [22..24] chunk_index      (u16, big-endian)
//! [24..26] total_chunks     (u16, big-endian)
//! [26..30] plaintext_length (u32, big-endian)
//! [30..]   payload
//! ```
//!
//! iOS, Android and the TUI each read and write this by hand. The core reads it since 0.29 so it
//! can name a sealed message's real type — a sealed envelope says GENERIC, and the type is only
//! here (TODO 94). The rule is fixed for every reader by `construct-protos/conformance/
//! knst_frame.json`, vendored in `tests/conformance/`; a change there is copied here in the same
//! change that makes the core pass it.

pub const MAGIC: [u8; 4] = *b"KNST";
pub const VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 30;

/// `ContentType::CALL_SIGNAL` in `construct-protos/core/envelope.proto`.
pub const CONTENT_TYPE_CALL_SIGNAL: u8 = 12;

/// A parsed frame. The payload is borrowed from the plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub content_type: u8,
    pub message_id: [u8; 16],
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub plaintext_length: u32,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// `None` unless the magic, the version and a whole header are there.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < HEADER_LEN || data[..4] != MAGIC || data[4] != VERSION {
            return None;
        }
        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&data[6..22]);
        Some(Self {
            content_type: data[5],
            message_id,
            chunk_index: u16::from_be_bytes([data[22], data[23]]),
            total_chunks: u16::from_be_bytes([data[24], data[25]]),
            plaintext_length: u32::from_be_bytes([data[26], data[27], data[28], data[29]]),
            payload: &data[HEADER_LEN..],
        })
    }

    /// The body of a control frame — one message, never split: `total_chunks` is 1 and
    /// `plaintext_length` fits the payload. `None` for anything else; a reader must not guess.
    pub fn control_body(&self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.plaintext_length).ok()?;
        (self.total_chunks == 1 && length <= self.payload.len()).then(|| &self.payload[..length])
    }
}

/// `(content_type, body)` when `plaintext` is a control frame.
pub fn control_frame(plaintext: &[u8]) -> Option<(u8, &[u8])> {
    let frame = Frame::parse(plaintext)?;
    Some((frame.content_type, frame.control_body()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cases() -> Vec<serde_json::Value> {
        let text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/conformance/knst_frame.json"
        ));
        let root: serde_json::Value = serde_json::from_str(text).expect("vectors parse");
        let cases = root["cases"].as_array().expect("cases").clone();
        // An empty list would let every assertion below pass by never running.
        assert!(cases.len() >= 9, "vectors look truncated");
        cases
    }

    /// Every case reads as `knst_frame.json` says. Mutation: accept `total_chunks != 1`, drop the
    /// length check, or cut the body at the payload's end — a case reddens.
    #[test]
    fn every_vector_reads_as_stated() {
        for case in cases() {
            let name = case["name"].as_str().unwrap();
            let bytes = hex::decode(case["frame"].as_str().unwrap()).unwrap();
            let frame = Frame::parse(&bytes);
            assert_eq!(
                frame.is_some(),
                case["is_frame"].as_bool().unwrap(),
                "{name}: is_frame"
            );
            let Some(frame) = frame else { continue };
            assert_eq!(
                u64::from(frame.content_type),
                case["content_type"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                u64::from(frame.total_chunks),
                case["total_chunks"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                u64::from(frame.plaintext_length),
                case["plaintext_length"].as_u64().unwrap(),
                "{name}"
            );
            let id = uuid_string(&frame.message_id);
            assert_eq!(
                id,
                case["message_id"].as_str().unwrap(),
                "{name}: message id"
            );
            let body = frame.control_body().map(hex::encode);
            assert_eq!(
                body.is_some(),
                case["control"].as_bool().unwrap(),
                "{name}: control"
            );
            assert_eq!(body.as_deref(), case["body"].as_str(), "{name}: body");
        }
    }

    fn uuid_string(b: &[u8; 16]) -> String {
        let h = hex::encode(b);
        format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        )
    }
}
