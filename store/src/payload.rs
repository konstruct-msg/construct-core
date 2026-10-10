//! What a message row's `body` holds, and the order key of a row the server never placed.
//!
//! **CTM1** (`construct-docs/client/specs/local-message-payload-binary.md`): `"CTM1"`, a kind
//! byte, then the kind's bytes. Until 2026-10-10 each client kept its own codec (Swift, and a
//! Kotlin copy held to shared vectors); the history projection is the first reader here.
//! A body without the magic is a row from before CTM1 — legacy UTF-8, iOS only.

/// `"CTM1"`.
pub const MAGIC: [u8; 4] = *b"CTM1";

/// Kind bytes, at offset 4.
pub mod kind {
    /// Raw UTF-8 text.
    pub const TEXT: u8 = 0x01;
    /// A serialized `MediaAlbumMessage`.
    pub const MEDIA_ALBUM: u8 = 0x02;
    /// A serialized wire `MessageContent`.
    pub const MESSAGE_CONTENT: u8 = 0x03;
    /// `ProfileShareData` binary.
    pub const PROFILE: u8 = 0x04;
}

/// A body, read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'a> {
    Text(&'a str),
    MediaAlbum(&'a [u8]),
    MessageContent(&'a [u8]),
    Profile(&'a [u8]),
    /// No CTM1 envelope, an unknown kind, or text that is not UTF-8: the bytes as stored.
    Legacy(&'a [u8]),
}

impl<'a> Payload<'a> {
    pub fn decode(body: &'a [u8]) -> Self {
        if body.len() < 5 || body[..4] != MAGIC {
            return Self::Legacy(body);
        }
        let rest = &body[5..];
        match body[4] {
            kind::TEXT => std::str::from_utf8(rest).map_or(Self::Legacy(body), Self::Text),
            kind::MEDIA_ALBUM => Self::MediaAlbum(rest),
            kind::MESSAGE_CONTENT => Self::MessageContent(rest),
            kind::PROFILE => Self::Profile(rest),
            _ => Self::Legacy(body),
        }
    }
}

/// `kind`'s envelope around `bytes`.
pub fn encode(kind: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.extend_from_slice(&MAGIC);
    out.push(kind);
    out.extend_from_slice(bytes);
    out
}

const ORDER_WIDTH: usize = 20;

/// The order key of a row with no server position and none to come — a local notice, an
/// imported row: at its own time, `<ms, 20 digits>-<20 zeros>-<id>`. The id makes the key total;
/// a time at or before the epoch is clamped to 1 ms. iOS `ServerMessageOrder.local`.
pub fn local_order_key(timestamp_ms: i64, message_id: &str) -> String {
    format!(
        "{:0width$}-{:0width$}-{}",
        timestamp_ms.max(1),
        0,
        message_id.to_lowercase(),
        width = ORDER_WIDTH
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_round_trips_and_anything_else_is_legacy() {
        assert_eq!(
            Payload::decode(&encode(kind::TEXT, "héllo".as_bytes())),
            Payload::Text("héllo")
        );
        assert_eq!(
            Payload::decode(&encode(kind::MEDIA_ALBUM, &[1, 2])),
            Payload::MediaAlbum(&[1, 2])
        );
        assert_eq!(
            Payload::decode(&encode(kind::MESSAGE_CONTENT, &[3])),
            Payload::MessageContent(&[3])
        );
        assert_eq!(
            Payload::decode(&encode(kind::PROFILE, &[])),
            Payload::Profile(&[])
        );
        for legacy in [
            &b"hello"[..],
            b"CTM1",
            b"CTM2\x01x",
            b"CTM1\x09x",
            b"CTM1\x01\xff",
        ] {
            assert_eq!(
                Payload::decode(legacy),
                Payload::Legacy(legacy),
                "{legacy:?}"
            );
        }
    }

    /// The same bytes iOS writes. Mutation: drop the clamp — a zero time keys as all zeros.
    #[test]
    fn a_local_key_is_the_time_then_zeros_then_the_id() {
        assert_eq!(
            local_order_key(1_700_000_000_123, "ABC-def"),
            "00000001700000000123-00000000000000000000-abc-def"
        );
        assert_eq!(
            local_order_key(0, "x"),
            "00000000000000000001-00000000000000000000-x"
        );
    }
}
