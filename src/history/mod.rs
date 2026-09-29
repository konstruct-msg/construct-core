//! History transfer between two devices of one account: the CTH1 record stream, its sealed chunk
//! layer, and the two envelopes it travels in — CTT1 v2 over the local network, CTHF as a file.
//!
//! Sans-I/O. The core takes and returns byte buffers; the platform owns the socket, the file and
//! its store. A transcript record crosses the FFI as its protobuf bytes and is decoded once, by the
//! platform, straight into its store; the core reads only what the protocol rules need (the
//! manifest's version, phase and ids, whether a message carries a body, a media blob's header).
//! Media is streamed, never held whole.
//!
//! Until 2026-09 this was Swift, shared by iOS and macOS and by nothing else. Two clients must
//! read each other's snapshots byte for byte, so it lives here.
//! Design: `construct-docs/decisions/history-transfer-protocol-in-the-core.md`.
//! Format: `construct-docs/client/specs/DEVICE_LINK_HISTORY_TRANSFER.md` §4–§6.
//! Vectors: `construct-protos/conformance/knst_history_snapshot.json`, vendored in
//! `tests/conformance/`.

pub mod cth1;
pub mod discovery;
mod wire;

/// 512 MiB. A record announcing more is malformed and nothing is allocated for it. A legal
/// 500 MB video fits; the encoder skips a blob at or over this and counts it.
pub const MAX_RECORD_BYTES: u64 = 512 * 1024 * 1024;

/// Record types of CTH1 v1. `0x09`–`0x0D` are reserved for groups (CTH1 v2); any type the reader
/// does not know is skipped, never an error.
pub mod record_type {
    pub const END: u8 = 0x00;
    pub const MANIFEST: u8 = 0x01;
    pub const CONTACT: u8 = 0x02;
    pub const CHAT: u8 = 0x03;
    pub const MESSAGE: u8 = 0x04;
    pub const REACTION: u8 = 0x05;
    pub const PEER_DEVICE: u8 = 0x06;
    pub const CALL: u8 = 0x07;
    pub const MEDIA_BLOB: u8 = 0x08;
}

/// Why a snapshot was refused. One set for every platform, so the same failure reads the same in
/// every log and maps to the same message for a person. `as_str` is the spec's name for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryFailure {
    /// Bytes that are not the format, or break a rule of it that has no name of its own.
    Malformed,
    /// The stream ended before its End record.
    Truncated,
    /// A manifest `format_version` this reader does not speak.
    UnknownVersion,
    /// A record the phase does not allow, or one out of the required order.
    RecordOrder,
    /// The manifest names a different snapshot or account than the envelope it arrived in.
    EnvelopeManifestMismatch,
    /// A history frame on CTT1 v1, the PIN-HMAC backup handshake.
    V1RefusedForHistory,
    /// Keys or ids in a frame are not the ones the directory holds for that device.
    IdentityMismatch,
    /// The frame was made for a Kyber prekey this device no longer holds.
    KemKeyIdMismatch,
    /// The link QR pinned other keys than the frame carries.
    QrPinMismatch,
    /// No QR pin and no bundle-only allowance: nothing authenticates the other device.
    QrPinAbsent,
    /// The other device has no hybrid identity key to verify with.
    NoHybridKey,
    /// The hybrid signature does not verify under the known key.
    SignatureInvalid,
    /// A sealed chunk did not open: wrong key, reordered, spliced or corrupted.
    ChunkOpenFailed,
}

impl HistoryFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Truncated => "truncated",
            Self::UnknownVersion => "unknown_version",
            Self::RecordOrder => "record_order",
            Self::EnvelopeManifestMismatch => "envelope_manifest_mismatch",
            Self::V1RefusedForHistory => "v1_refused_for_history",
            Self::IdentityMismatch => "identity_mismatch",
            Self::KemKeyIdMismatch => "kem_key_id_mismatch",
            Self::QrPinMismatch => "qr_pin_mismatch",
            Self::QrPinAbsent => "qr_pin_absent",
            Self::NoHybridKey => "no_hybrid_key",
            Self::SignatureInvalid => "signature_invalid",
            Self::ChunkOpenFailed => "chunk_open_failed",
        }
    }
}

impl std::fmt::Display for HistoryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for HistoryFailure {}

/// Equal length and equal bytes, without returning at the first difference.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
pub(crate) mod vectors {
    //! The vendored cross-client vectors. A copy of
    //! `construct-protos/conformance/knst_history_snapshot.json` (construct-protos 4eb233d); a
    //! change there is copied here in the same change that makes the core pass it.

    pub fn all() -> Vec<serde_json::Value> {
        let text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/conformance/knst_history_snapshot.json"
        ));
        let root: serde_json::Value = serde_json::from_str(text).expect("vectors parse");
        root["vectors"].as_array().expect("vectors array").clone()
    }

    pub fn named(name: &str) -> serde_json::Value {
        all()
            .into_iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("no vector named {name}"))
    }

    pub fn hex_field(v: &serde_json::Value, key: &str) -> Vec<u8> {
        hex::decode(v[key].as_str().unwrap_or_else(|| panic!("{key} missing"))).expect("hex")
    }
}
