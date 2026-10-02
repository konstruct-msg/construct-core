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
//! iOS, Android and the TUI each read and wrote this by hand. The core reads it since 0.29 so it
//! can name a sealed message's real type — a sealed envelope says GENERIC, and the type is only
//! here (TODO 94) — and since 0.31 writes it too, splitting a body into frames for every platform
//! (`encode_chunks`, `frame_whole`), so the hand-written copies can go. The rule is fixed for every reader by `construct-protos/conformance/
//! knst_frame.json`, vendored in `tests/conformance/`; a change there is copied here in the same
//! change that makes the core pass it.

pub const MAGIC: [u8; 4] = *b"KNST";
pub const VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 30;

/// The most body bytes one frame carries. A larger body is split into frames of this size.
pub const CHUNK_PAYLOAD_SIZE: usize = 3770;
/// The most frames one body is split into; a body that needs more is refused, not truncated.
pub const MAX_CHUNKS: usize = 256;

/// `ContentType::CALL_SIGNAL` in `construct-protos/core/envelope.proto`.
pub const CONTENT_TYPE_CALL_SIGNAL: u8 = 12;

/// The content types a KNST control frame carries silently: never a chat message, so never a
/// notification or a transcript row — the rows of `knst_content_types.json` with
/// `knst_byte5: true` and `disposition: silent_control` (12 is among them, and has its own
/// action). Pinned against that file by a test, so a type added there and not here reddens.
pub const SILENT_CONTROL_TYPES: [u8; 7] = [12, 13, 14, 25, 26, 27, 29];

/// Whether `content_type` in byte 5 makes a control frame silent.
pub fn is_silent_control(content_type: u8) -> bool {
    SILENT_CONTROL_TYPES.contains(&content_type)
}

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

/// A message id as the header carries it: the UUID's 16 bytes. Accepts the usual dashed form,
/// any case. `None` for anything that is not 32 hex digits.
pub fn message_id_bytes(id: &str) -> Option<[u8; 16]> {
    let digits: String = id.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(digits).ok()?;
    bytes.try_into().ok()
}

/// The dashed lowercase form of a header's message id.
pub fn message_id_string(id: &[u8; 16]) -> String {
    let h = hex::encode(id);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

fn frame(
    body: &[u8],
    content_type: u8,
    message_id: &[u8; 16],
    chunk_index: u16,
    total_chunks: u16,
    plaintext_length: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(content_type);
    out.extend_from_slice(message_id);
    out.extend_from_slice(&chunk_index.to_be_bytes());
    out.extend_from_slice(&total_chunks.to_be_bytes());
    out.extend_from_slice(&plaintext_length.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// One frame holding the whole body, whatever its size — for a control carrier, which is sent as
/// one message and never split. `None` when the body is longer than a u32 can say.
pub fn frame_whole(body: &[u8], content_type: u8, message_id: &[u8; 16]) -> Option<Vec<u8>> {
    let length = u32::try_from(body.len()).ok()?;
    Some(frame(body, content_type, message_id, 0, 1, length))
}

/// `body` as frames of at most `CHUNK_PAYLOAD_SIZE` bytes, each carrying the whole body's length;
/// an empty body is one frame. `None` when it would take more than `MAX_CHUNKS` frames.
pub fn encode_chunks(body: &[u8], content_type: u8, message_id: &[u8; 16]) -> Option<Vec<Vec<u8>>> {
    let total = body.len().div_ceil(CHUNK_PAYLOAD_SIZE).max(1);
    if total > MAX_CHUNKS {
        return None;
    }
    let length = u32::try_from(body.len()).ok()?;
    let total_u16 = u16::try_from(total).ok()?;
    Some(
        (0..total)
            .map(|i| {
                let start = i * CHUNK_PAYLOAD_SIZE;
                let end = (start + CHUNK_PAYLOAD_SIZE).min(body.len());
                frame(
                    &body[start..end],
                    content_type,
                    message_id,
                    i as u16,
                    total_u16,
                    length,
                )
            })
            .collect(),
    )
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

    /// The silent set is exactly what the cross-client table says: framed in byte 5 and
    /// `silent_control`. Mutation: drop 29 from the set, or add 1 — this reddens.
    #[test]
    fn the_silent_set_is_the_tables() {
        let text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/conformance/knst_content_types.json"
        ));
        let root: serde_json::Value = serde_json::from_str(text).expect("table parses");
        let mut table: Vec<u8> = root["types"]
            .as_array()
            .expect("types")
            .iter()
            .filter(|row| row["knst_byte5"] == true && row["disposition"] == "silent_control")
            .map(|row| row["value"].as_u64().unwrap() as u8)
            .collect();
        table.sort_unstable();
        assert!(table.len() >= 5, "table looks truncated");
        assert_eq!(table, SILENT_CONTROL_TYPES.to_vec());
    }

    fn uuid_string(b: &[u8; 16]) -> String {
        message_id_string(b)
    }

    /// Every encode case splits as `knst_frame.json` says, byte for byte — the frames iOS,
    /// Android and the TUI produced by hand. Mutation: an off-by-one in the chunk size, the
    /// chunk's own length in the header instead of the body's, or no frame for an empty body —
    /// a case reddens.
    #[test]
    fn every_encode_vector_splits_as_stated() {
        let text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/conformance/knst_frame.json"
        ));
        let root: serde_json::Value = serde_json::from_str(text).expect("vectors parse");
        assert_eq!(
            root["chunk_payload_size"].as_u64(),
            Some(CHUNK_PAYLOAD_SIZE as u64)
        );
        assert_eq!(root["max_chunks"].as_u64(), Some(MAX_CHUNKS as u64));
        let id = message_id_bytes(root["message_id"].as_str().unwrap()).expect("message id");
        let cases = root["encode"].as_array().expect("encode");
        assert!(cases.len() >= 6, "vectors look truncated");
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let len = case["payload_len"].as_u64().unwrap() as usize;
            let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let ct = case["content_type"].as_u64().unwrap() as u8;
            let got = encode_chunks(&body, ct, &id)
                .map(|f| f.iter().map(hex::encode).collect::<Vec<_>>());
            let want = case["frames"].as_array().map(|f| {
                f.iter()
                    .map(|x| x.as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            });
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn a_whole_frame_reads_back_as_a_control_frame() {
        let id = message_id_bytes("0B8E2F5C-6A1D-4E7B-9C3F-1A2B3C4D5E6F").unwrap();
        let framed = frame_whole(b"signal", 12, &id).unwrap();
        assert_eq!(control_frame(&framed), Some((12, &b"signal"[..])));
        assert_eq!(
            message_id_string(&Frame::parse(&framed).unwrap().message_id),
            "0b8e2f5c-6a1d-4e7b-9c3f-1a2b3c4d5e6f"
        );
    }

    #[test]
    fn a_message_id_that_is_not_a_uuid_is_refused() {
        assert_eq!(message_id_bytes("not-a-uuid"), None);
        assert_eq!(message_id_bytes("0b8e2f5c6a1d4e7b9c3f1a2b3c4d5e"), None);
    }
}
