//! The transcript records of a CTH1 stream, read and written by field number.
//!
//! `wire.rs` reads only what the protocol rules judge; this reads and writes whole records, for
//! the projection to and from the local store (`project.rs`,
//! `construct-docs/decisions/history-projection-in-the-core.md`). By field number for the same
//! reason `wire.rs` gives: no generated protobuf in this crate, no second copy of the schema. The
//! vectors in `knst_history_snapshot.json` hold both sides to the same bytes.
//!
//! Proto3 throughout: an absent field is its zero, a repeated scalar takes the last value, and a
//! writer leaves zeros out, in field-number order — the bytes SwiftProtobuf writes.

use super::HistoryFailure;
use super::wire::{self, Value};

type Result<T> = std::result::Result<T, HistoryFailure>;

// MARK: - Records

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactRecord {
    pub user_id: Vec<u8>,
    pub username: String,
    pub display_name: String,
    pub local_alias: String,
    pub avatar: Vec<u8>,
    pub is_contact: bool,
    pub is_blocked: bool,
    pub am_i_sharing_with: bool,
    pub is_sharing_with_me: bool,
    pub added_at_unix: i64,
    pub shared_with_me_at_unix: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChatRecord {
    pub other_user_id: Vec<u8>,
    pub is_pinned: bool,
    pub is_muted: bool,
}

/// A message's body: one of the three cases of the `body` oneof, as its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageBody {
    /// Field 6, a wire `MessageContent`.
    Content(Vec<u8>),
    /// Field 15, a `MediaAlbumMessage`.
    Album(Vec<u8>),
    /// Field 16, `ProfileShareData` binary.
    Profile(Vec<u8>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageRecord {
    pub id: String,
    pub from_user_id: Vec<u8>,
    pub to_user_id: Vec<u8>,
    pub timestamp_unix_ms: i64,
    pub is_sent_by_me: bool,
    pub body: Option<MessageBody>,
    pub reply_to_message_id: String,
    pub reply_to_content: String,
    pub is_edited: bool,
    pub edited_at_unix_ms: i64,
    pub transcript_text: String,
    pub transcript_language: String,
    pub transcript_generated_at_unix: i64,
    pub suite_id: u32,
    /// A field this version does not know — with no body, a future body case.
    pub has_unknown_fields: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReactionRecord {
    pub target_message_id: String,
    pub reactor_user_id: Vec<u8>,
    pub emoji: String,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerDeviceRecord {
    pub account_id: Vec<u8>,
    pub device_id: String,
    pub identity_key: Vec<u8>,
    pub first_seen_at_unix: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallRecord {
    pub id: String,
    pub peer_user_id: Vec<u8>,
    pub is_outgoing: bool,
    pub status: u32,
    pub started_at_unix: i64,
    pub duration_seconds: i64,
}

// MARK: - Reading

fn text(b: &[u8]) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| HistoryFailure::Malformed)
}

/// Every field of `buf`: `known(number, value)` answers whether it took the field; a known
/// number with the wrong wire type is malformed, and the rest are reported as unknown.
fn read(
    buf: &[u8],
    known_numbers: std::ops::RangeInclusive<u32>,
    mut known: impl FnMut(u32, Value<'_>) -> Result<bool>,
) -> Result<bool> {
    let mut unknown = false;
    for field in wire::fields(buf) {
        let (number, value) = field?;
        if known_numbers.contains(&number) {
            if !known(number, value)? {
                return Err(HistoryFailure::Malformed);
            }
        } else {
            unknown = true;
        }
    }
    Ok(unknown)
}

impl ContactRecord {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Self::default();
        read(buf, 1..=11, |number, value| {
            match (number, value) {
                (1, Value::Bytes(b)) => r.user_id = b.to_vec(),
                (2, Value::Bytes(b)) => r.username = text(b)?,
                (3, Value::Bytes(b)) => r.display_name = text(b)?,
                (4, Value::Bytes(b)) => r.local_alias = text(b)?,
                (5, Value::Bytes(b)) => r.avatar = b.to_vec(),
                (6, Value::Varint(v)) => r.is_contact = v != 0,
                (7, Value::Varint(v)) => r.is_blocked = v != 0,
                (8, Value::Varint(v)) => r.am_i_sharing_with = v != 0,
                (9, Value::Varint(v)) => r.is_sharing_with_me = v != 0,
                (10, Value::Varint(v)) => r.added_at_unix = v as i64,
                (11, Value::Varint(v)) => r.shared_with_me_at_unix = v as i64,
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok(r)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(1, &self.user_id);
        w.bytes(2, self.username.as_bytes());
        w.bytes(3, self.display_name.as_bytes());
        w.bytes(4, self.local_alias.as_bytes());
        w.bytes(5, &self.avatar);
        w.bool(6, self.is_contact);
        w.bool(7, self.is_blocked);
        w.bool(8, self.am_i_sharing_with);
        w.bool(9, self.is_sharing_with_me);
        w.int(10, self.added_at_unix);
        w.int(11, self.shared_with_me_at_unix);
        w.out
    }
}

impl ChatRecord {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Self::default();
        read(buf, 1..=3, |number, value| {
            match (number, value) {
                (1, Value::Bytes(b)) => r.other_user_id = b.to_vec(),
                (2, Value::Varint(v)) => r.is_pinned = v != 0,
                (3, Value::Varint(v)) => r.is_muted = v != 0,
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok(r)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(1, &self.other_user_id);
        w.bool(2, self.is_pinned);
        w.bool(3, self.is_muted);
        w.out
    }
}

impl MessageRecord {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Self::default();
        r.has_unknown_fields = read(buf, 1..=16, |number, value| {
            match (number, value) {
                (1, Value::Bytes(b)) => r.id = text(b)?,
                (2, Value::Bytes(b)) => r.from_user_id = b.to_vec(),
                (3, Value::Bytes(b)) => r.to_user_id = b.to_vec(),
                (4, Value::Varint(v)) => r.timestamp_unix_ms = v as i64,
                (5, Value::Varint(v)) => r.is_sent_by_me = v != 0,
                (6, Value::Bytes(b)) => r.body = Some(MessageBody::Content(b.to_vec())),
                (7, Value::Bytes(b)) => r.reply_to_message_id = text(b)?,
                (8, Value::Bytes(b)) => r.reply_to_content = text(b)?,
                (9, Value::Varint(v)) => r.is_edited = v != 0,
                (10, Value::Varint(v)) => r.edited_at_unix_ms = v as i64,
                (11, Value::Bytes(b)) => r.transcript_text = text(b)?,
                (12, Value::Bytes(b)) => r.transcript_language = text(b)?,
                (13, Value::Varint(v)) => r.transcript_generated_at_unix = v as i64,
                (14, Value::Varint(v)) => r.suite_id = v as u32,
                (15, Value::Bytes(b)) => r.body = Some(MessageBody::Album(b.to_vec())),
                (16, Value::Bytes(b)) => r.body = Some(MessageBody::Profile(b.to_vec())),
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok(r)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(1, self.id.as_bytes());
        w.bytes(2, &self.from_user_id);
        w.bytes(3, &self.to_user_id);
        w.int(4, self.timestamp_unix_ms);
        w.bool(5, self.is_sent_by_me);
        // A oneof case is written even when empty: it is set, and the reader must see which.
        if let Some(MessageBody::Content(b)) = &self.body {
            w.always_bytes(6, b);
        }
        w.bytes(7, self.reply_to_message_id.as_bytes());
        w.bytes(8, self.reply_to_content.as_bytes());
        w.bool(9, self.is_edited);
        w.int(10, self.edited_at_unix_ms);
        w.bytes(11, self.transcript_text.as_bytes());
        w.bytes(12, self.transcript_language.as_bytes());
        w.int(13, self.transcript_generated_at_unix);
        w.int(14, i64::from(self.suite_id));
        match &self.body {
            Some(MessageBody::Album(b)) => w.always_bytes(15, b),
            Some(MessageBody::Profile(b)) => w.always_bytes(16, b),
            _ => {}
        }
        w.out
    }
}

impl ReactionRecord {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Self::default();
        read(buf, 1..=4, |number, value| {
            match (number, value) {
                (1, Value::Bytes(b)) => r.target_message_id = text(b)?,
                (2, Value::Bytes(b)) => r.reactor_user_id = b.to_vec(),
                (3, Value::Bytes(b)) => r.emoji = text(b)?,
                (4, Value::Varint(v)) => r.timestamp_ms = v as i64,
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok(r)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(1, self.target_message_id.as_bytes());
        w.bytes(2, &self.reactor_user_id);
        w.bytes(3, self.emoji.as_bytes());
        w.int(4, self.timestamp_ms);
        w.out
    }
}

impl PeerDeviceRecord {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Self::default();
        read(buf, 1..=4, |number, value| {
            match (number, value) {
                (1, Value::Bytes(b)) => r.account_id = b.to_vec(),
                (2, Value::Bytes(b)) => r.device_id = text(b)?,
                (3, Value::Bytes(b)) => r.identity_key = b.to_vec(),
                (4, Value::Varint(v)) => r.first_seen_at_unix = v as i64,
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok(r)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(1, &self.account_id);
        w.bytes(2, self.device_id.as_bytes());
        w.bytes(3, &self.identity_key);
        w.int(4, self.first_seen_at_unix);
        w.out
    }
}

impl CallRecord {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Self::default();
        read(buf, 1..=6, |number, value| {
            match (number, value) {
                (1, Value::Bytes(b)) => r.id = text(b)?,
                (2, Value::Bytes(b)) => r.peer_user_id = b.to_vec(),
                (3, Value::Varint(v)) => r.is_outgoing = v != 0,
                (4, Value::Varint(v)) => r.status = v as u32,
                (5, Value::Varint(v)) => r.started_at_unix = v as i64,
                (6, Value::Varint(v)) => r.duration_seconds = v as i64,
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok(r)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(1, self.id.as_bytes());
        w.bytes(2, &self.peer_user_id);
        w.bool(3, self.is_outgoing);
        w.int(4, i64::from(self.status));
        w.int(5, self.started_at_unix);
        w.int(6, self.duration_seconds);
        w.out
    }
}

// MARK: - Bodies

/// A wire `MessageContent` holding only `text` — what a stored text body travels as.
pub fn text_content(s: &str) -> Vec<u8> {
    let mut text_message = Writer::default();
    text_message.bytes(1, s.as_bytes());
    let mut content = Writer::default();
    content.always_bytes(1, &text_message.out);
    content.out
}

/// A media file a body refers to: the server's media id and its MIME type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRef {
    pub id: String,
    pub mime: String,
}

/// The media a body refers to, in order: an album's items, a single media item, a voice note.
/// A body that does not parse refers to nothing.
pub fn media_refs(body: &MessageBody) -> Vec<MediaRef> {
    match body {
        MessageBody::Album(b) => album_refs(b),
        MessageBody::Content(b) => content_refs(b),
        MessageBody::Profile(_) => Vec::new(),
    }
}

fn content_refs(buf: &[u8]) -> Vec<MediaRef> {
    let mut refs = Vec::new();
    for field in wire::fields(buf) {
        let Ok((number, value)) = field else {
            return Vec::new();
        };
        match (number, value) {
            (2, Value::Bytes(b)) => refs = media_ref(b).into_iter().collect(),
            (6, Value::Bytes(b)) => refs = voice_ref(b).into_iter().collect(),
            (10, Value::Bytes(b)) => refs = album_refs(b),
            // Another case of the `content` oneof (1–11), set after: the last one wins.
            (1..=11, _) => refs.clear(),
            _ => {}
        }
    }
    refs
}

fn album_refs(buf: &[u8]) -> Vec<MediaRef> {
    let mut refs = Vec::new();
    for field in wire::fields(buf) {
        match field {
            Ok((1, Value::Bytes(item))) => refs.extend(media_ref(item)),
            Ok(_) => {}
            Err(_) => return Vec::new(),
        }
    }
    refs
}

/// A `MediaMessage`'s id and MIME type; its `media_type` names one when the type is absent.
fn media_ref(buf: &[u8]) -> Option<MediaRef> {
    let (mut id, mut mime, mut media_type) = (String::new(), String::new(), 0);
    for field in wire::fields(buf) {
        match field.ok()? {
            (13, Value::Bytes(b)) => id = std::str::from_utf8(b).ok()?.to_owned(),
            (6, Value::Bytes(b)) => mime = std::str::from_utf8(b).ok()?.to_owned(),
            (1, Value::Varint(v)) => media_type = v,
            _ => {}
        }
    }
    if id.is_empty() {
        return None;
    }
    if mime.is_empty() {
        mime = match media_type {
            1 | 5 => "image/jpeg",
            2 => "video/mp4",
            3 => "audio/m4a",
            _ => "application/octet-stream",
        }
        .to_owned();
    }
    Some(MediaRef { id, mime })
}

/// A voice note's `codec` carries `<mime>|<media id>`.
fn voice_ref(buf: &[u8]) -> Option<MediaRef> {
    let mut codec = "";
    for field in wire::fields(buf) {
        if let (6, Value::Bytes(b)) = field.ok()? {
            codec = std::str::from_utf8(b).ok()?;
        }
    }
    let mut parts = codec.splitn(3, '|');
    let mime = parts
        .next()
        .filter(|m| !m.is_empty())
        .unwrap_or("audio/m4a");
    let id = parts.next().unwrap_or("");
    (!id.is_empty()).then(|| MediaRef {
        id: id.to_owned(),
        mime: mime.to_owned(),
    })
}

// MARK: - Account ids

/// A 16-byte UUID as the dashed lowercase text the stores key accounts by.
pub fn dashed(raw: &[u8]) -> Option<String> {
    if raw.len() != 16 {
        return None;
    }
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// A dashed UUID, in either case, as its 16 bytes; anything else is `None`.
pub fn raw(dashed: &str) -> Option<Vec<u8>> {
    let b = dashed.as_bytes();
    let dash = |i: usize| [8, 13, 18, 23].contains(&i);
    if b.len() != 36
        || b.iter().enumerate().any(|(i, &c)| {
            if dash(i) {
                c != b'-'
            } else {
                !c.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    let hex: Vec<u8> = b.iter().copied().filter(|&c| c != b'-').collect();
    hex.chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

// MARK: - Writing

#[derive(Default)]
pub(crate) struct Writer {
    pub(crate) out: Vec<u8>,
}

impl Writer {
    fn key(&mut self, number: u32, wire_type: u8) {
        wire::write_varint(u64::from(number) << 3 | u64::from(wire_type), &mut self.out);
    }

    pub(crate) fn always_bytes(&mut self, number: u32, b: &[u8]) {
        self.key(number, 2);
        wire::write_varint(b.len() as u64, &mut self.out);
        self.out.extend_from_slice(b);
    }

    pub(crate) fn bytes(&mut self, number: u32, b: &[u8]) {
        if !b.is_empty() {
            self.always_bytes(number, b);
        }
    }

    fn int(&mut self, number: u32, v: i64) {
        if v != 0 {
            self.key(number, 0);
            wire::write_varint(v as u64, &mut self.out);
        }
    }

    fn bool(&mut self, number: u32, v: bool) {
        self.int(number, i64::from(v));
    }
}
