//! CTH1: the record stream inside every history transfer.
//!
//! ```text
//! [4] "CTH1"  [1] version 0x01
//! repeated: [1] record_type  [8] payload_len LE  [payload_len] protobuf of that type
//! [1] 0x00 End
//! ```
//!
//! The reader is incremental and holds no more than one transcript record: bytes go in as they
//! arrive (one opened chunk at a time), events come out as soon as a record completes. A media
//! blob is not held at all — its header is parsed and its bytes pass through as they arrive, so a
//! 400 MB video costs one chunk of memory. That needs the blob's fields in order 1, 2, 3
//! (`media_id`, `mime_type`, `blob`), which every encoder writes; a blob field before the others is
//! malformed.

use super::wire::{self, Body};
use super::{HistoryFailure, MAX_RECORD_BYTES, ct_eq, record_type};

pub const MAGIC: [u8; 4] = *b"CTH1";
pub const VERSION: u8 = 0x01;
const PREAMBLE_LEN: usize = 5;
const RECORD_HEADER_LEN: usize = 9;
/// A media blob's `media_id` and `mime_type` must fit in this much of its payload, ahead of the
/// blob. Both are short strings; a longer head is an attempt to make the reader buffer.
const MEDIA_HEAD_CAP: usize = 4096;

/// What the reader hands the platform, in stream order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A transcript record (manifest, contact, chat, message, reaction, peer device hint, call)
    /// as its protobuf bytes, already checked against the protocol rules. The platform decodes it.
    Record {
        record_type: u8,
        proto: Vec<u8>,
    },
    /// A record this version does not read — an unknown type, or a message with a future body.
    Skipped {
        record_type: u8,
    },
    /// A media blob begins: `byte_len` bytes follow as `MediaBytes`, then `MediaEnd`.
    MediaStart {
        media_id: String,
        mime_type: String,
        byte_len: u64,
    },
    MediaBytes(Vec<u8>),
    MediaEnd,
    /// The End record. Nothing may follow it.
    End,
}

/// The snapshot and account the envelope announced. The manifest must name the same ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub snapshot_id: [u8; 16],
    pub user_id: [u8; 16],
}

#[derive(Debug)]
enum State {
    Preamble,
    RecordHeader,
    /// A transcript record, accumulating.
    Record {
        record_type: u8,
        remaining: u64,
    },
    /// A record this version skips: its bytes are counted off, never kept.
    Discard {
        record_type: u8,
        remaining: u64,
    },
    /// A media blob's head: `media_id`, `mime_type`, and the blob's own length prefix.
    MediaHead {
        payload_len: u64,
    },
    MediaBlob {
        remaining: u64,
    },
    Done,
    Failed(HistoryFailure),
}

/// The incremental CTH1 reader.
#[derive(Debug)]
pub struct Reader {
    state: State,
    /// Bytes of the unit being assembled: the preamble, a record header, a transcript record, or
    /// a media head. Never a blob.
    buf: Vec<u8>,
    order: Order,
    envelope: Option<Envelope>,
}

impl Reader {
    /// `envelope` is what the CTT1 v2 opening or CTHF header announced; `None` only for a bare
    /// stream (the vectors).
    pub fn new(envelope: Option<Envelope>) -> Self {
        Self {
            state: State::Preamble,
            buf: Vec::new(),
            order: Order::default(),
            envelope,
        }
    }

    /// Feed the next bytes of the stream. Events for every unit they complete are appended to
    /// `out`. After a failure every call returns the same failure.
    pub fn push(&mut self, mut data: &[u8], out: &mut Vec<Event>) -> Result<(), HistoryFailure> {
        if let State::Failed(f) = self.state {
            return Err(f);
        }
        while !data.is_empty() {
            if let Err(f) = self.step(&mut data, out) {
                self.state = State::Failed(f);
                self.buf.clear();
                return Err(f);
            }
        }
        Ok(())
    }

    /// The stream is over. Anything short of a complete End is `Truncated`.
    pub fn finish(&mut self) -> Result<(), HistoryFailure> {
        match self.state {
            State::Done => Ok(()),
            State::Failed(f) => Err(f),
            _ => {
                self.state = State::Failed(HistoryFailure::Truncated);
                Err(HistoryFailure::Truncated)
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    fn step(&mut self, data: &mut &[u8], out: &mut Vec<Event>) -> Result<(), HistoryFailure> {
        match self.state {
            State::Preamble => {
                if !self.fill(data, PREAMBLE_LEN) {
                    return Ok(());
                }
                if self.buf[..4] != MAGIC {
                    return Err(HistoryFailure::Malformed);
                }
                if self.buf[4] != VERSION {
                    return Err(HistoryFailure::UnknownVersion);
                }
                self.buf.clear();
                self.state = State::RecordHeader;
            }
            State::RecordHeader => {
                if self.buf.is_empty() && data[0] == record_type::END {
                    *data = &data[1..];
                    self.order.check(record_type::END)?;
                    out.push(Event::End);
                    self.state = State::Done;
                    return Ok(());
                }
                if !self.fill(data, RECORD_HEADER_LEN) {
                    return Ok(());
                }
                let ty = self.buf[0];
                let len = u64::from_le_bytes(self.buf[1..9].try_into().expect("8 bytes"));
                self.buf.clear();
                if len > MAX_RECORD_BYTES {
                    return Err(HistoryFailure::Malformed);
                }
                self.state = match ty {
                    record_type::MANIFEST..=record_type::CALL => {
                        self.order.check(ty)?;
                        State::Record {
                            record_type: ty,
                            remaining: len,
                        }
                    }
                    record_type::MEDIA_BLOB => {
                        self.order.check(ty)?;
                        State::MediaHead { payload_len: len }
                    }
                    _ => State::Discard {
                        record_type: ty,
                        remaining: len,
                    },
                };
                // A zero-length payload completes now; nothing more will arrive for it.
                if len == 0 {
                    self.complete_empty(out)?;
                }
            }
            State::Record {
                record_type,
                remaining,
            } => {
                let take = take_len(remaining, data.len());
                self.buf.extend_from_slice(&data[..take]);
                *data = &data[take..];
                let remaining = remaining - take as u64;
                if remaining > 0 {
                    self.state = State::Record {
                        record_type,
                        remaining,
                    };
                    return Ok(());
                }
                let proto = std::mem::take(&mut self.buf);
                self.state = State::RecordHeader;
                self.record(record_type, proto, out)?;
            }
            State::Discard {
                record_type,
                remaining,
            } => {
                let take = take_len(remaining, data.len());
                *data = &data[take..];
                let remaining = remaining - take as u64;
                if remaining > 0 {
                    self.state = State::Discard {
                        record_type,
                        remaining,
                    };
                } else {
                    // Reported once, at its end, so a skipped record is one event however it
                    // arrived.
                    self.state = State::RecordHeader;
                    out.push(Event::Skipped { record_type });
                }
            }
            State::MediaHead { payload_len } => {
                let want = usize::try_from(payload_len)
                    .unwrap_or(usize::MAX)
                    .min(MEDIA_HEAD_CAP);
                let before = self.buf.len();
                let take = (want - before).min(data.len());
                self.buf.extend_from_slice(&data[..take]);
                match media_head(&self.buf, payload_len)? {
                    None if self.buf.len() >= want => return Err(HistoryFailure::Malformed),
                    None => *data = &data[take..],
                    Some(head) => {
                        // Bytes of this push past the head are blob bytes; give them back.
                        let used_now = head.consumed - before;
                        *data = &data[used_now..];
                        self.buf.clear();
                        out.push(Event::MediaStart {
                            media_id: head.media_id,
                            mime_type: head.mime_type,
                            byte_len: head.blob_len,
                        });
                        if head.blob_len == 0 {
                            out.push(Event::MediaEnd);
                            self.state = State::RecordHeader;
                        } else {
                            self.state = State::MediaBlob {
                                remaining: head.blob_len,
                            };
                        }
                    }
                }
            }
            State::MediaBlob { remaining } => {
                let take = take_len(remaining, data.len());
                out.push(Event::MediaBytes(data[..take].to_vec()));
                *data = &data[take..];
                let remaining = remaining - take as u64;
                if remaining == 0 {
                    out.push(Event::MediaEnd);
                    self.state = State::RecordHeader;
                } else {
                    self.state = State::MediaBlob { remaining };
                }
            }
            // Anything after End breaks the rule that End is last.
            State::Done => return Err(HistoryFailure::Malformed),
            State::Failed(f) => return Err(f),
        }
        Ok(())
    }

    /// Append from `data` until `buf` holds `len` bytes; true once it does.
    fn fill(&mut self, data: &mut &[u8], len: usize) -> bool {
        let take = (len - self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..take]);
        *data = &data[take..];
        self.buf.len() == len
    }

    fn complete_empty(&mut self, out: &mut Vec<Event>) -> Result<(), HistoryFailure> {
        match self.state {
            State::Record { record_type, .. } => {
                self.state = State::RecordHeader;
                self.record(record_type, Vec::new(), out)
            }
            State::Discard { record_type, .. } => {
                self.state = State::RecordHeader;
                out.push(Event::Skipped { record_type });
                Ok(())
            }
            State::MediaHead { .. } => {
                // An empty blob record names no media.
                Err(HistoryFailure::Malformed)
            }
            _ => Ok(()),
        }
    }

    /// Judge a complete transcript record and emit it.
    fn record(
        &mut self,
        ty: u8,
        proto: Vec<u8>,
        out: &mut Vec<Event>,
    ) -> Result<(), HistoryFailure> {
        match ty {
            record_type::MANIFEST => {
                let m = wire::manifest(&proto)?;
                if m.format_version != 1 {
                    return Err(HistoryFailure::UnknownVersion);
                }
                if !(1..=3).contains(&m.phase) {
                    return Err(HistoryFailure::Malformed);
                }
                if let Some(env) = &self.envelope
                    && !(ct_eq(&m.snapshot_id, &env.snapshot_id) & ct_eq(&m.user_id, &env.user_id))
                {
                    return Err(HistoryFailure::EnvelopeManifestMismatch);
                }
                self.order.phase = m.phase as u8;
            }
            record_type::MESSAGE => match wire::message_body(&proto)? {
                Body::Known => {}
                Body::Unknown => {
                    out.push(Event::Skipped { record_type: ty });
                    return Ok(());
                }
                Body::Unset => return Err(HistoryFailure::Malformed),
            },
            _ => wire::well_formed(&proto)?,
        }
        out.push(Event::Record {
            record_type: ty,
            proto,
        });
        Ok(())
    }
}

fn take_len(remaining: u64, available: usize) -> usize {
    usize::try_from(remaining).map_or(available, |r| r.min(available))
}

struct MediaHead {
    media_id: String,
    mime_type: String,
    blob_len: u64,
    /// Bytes of the payload the head occupies, blob length prefix included.
    consumed: usize,
}

/// Parse a media blob's head from the first bytes of its payload. `None` while more bytes are
/// needed. Fields must come in order 1, 2, 3, and the blob must run to the end of the payload.
fn media_head(buf: &[u8], payload_len: u64) -> Result<Option<MediaHead>, HistoryFailure> {
    let mut pos = 0usize;
    let mut media_id = String::new();
    let mut mime_type = String::new();
    for (number, slot) in [(1u8, &mut media_id), (2u8, &mut mime_type)] {
        if pos as u64 == payload_len {
            break;
        }
        let Some(&key) = buf.get(pos) else {
            return Ok(None);
        };
        if key != wire::tag(number, 2) {
            continue;
        }
        let mut p = pos + 1;
        let Some(len) = wire::read_varint(buf, &mut p)? else {
            return Ok(None);
        };
        let end = p.checked_add(usize::try_from(len).map_err(|_| HistoryFailure::Malformed)?);
        let end = end.ok_or(HistoryFailure::Malformed)?;
        if end as u64 > payload_len {
            return Err(HistoryFailure::Malformed);
        }
        if end > buf.len() {
            return Ok(None);
        }
        *slot = std::str::from_utf8(&buf[p..end])
            .map_err(|_| HistoryFailure::Malformed)?
            .to_owned();
        pos = end;
    }
    if media_id.is_empty() {
        return Err(HistoryFailure::Malformed);
    }
    if pos as u64 == payload_len {
        return Ok(Some(MediaHead {
            media_id,
            mime_type,
            blob_len: 0,
            consumed: pos,
        }));
    }
    let Some(&key) = buf.get(pos) else {
        return Ok(None);
    };
    if key != wire::tag(3, 2) {
        return Err(HistoryFailure::Malformed);
    }
    let mut p = pos + 1;
    let Some(blob_len) = wire::read_varint(buf, &mut p)? else {
        return Ok(None);
    };
    if p as u64 + blob_len != payload_len {
        return Err(HistoryFailure::Malformed);
    }
    Ok(Some(MediaHead {
        media_id,
        mime_type,
        blob_len,
        consumed: p,
    }))
}

// ── Record order ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    Manifest,
    Meta,
    Message,
    Reaction,
    Media,
    End,
}

fn rank(ty: u8) -> Option<Rank> {
    Some(match ty {
        record_type::MANIFEST => Rank::Manifest,
        record_type::CONTACT | record_type::CHAT | record_type::PEER_DEVICE | record_type::CALL => {
            Rank::Meta
        }
        record_type::MESSAGE => Rank::Message,
        record_type::REACTION => Rank::Reaction,
        record_type::MEDIA_BLOB => Rank::Media,
        record_type::END => Rank::End,
        _ => return None,
    })
}

/// The required order: one manifest, first; then contacts, chats, peer hints and calls in any
/// mix; then messages; then reactions; then media; then End. The rank never goes back, so a
/// reaction before its message is refused rather than silently dropped by a streaming import.
/// Which of those the stream may carry at all is `manifest.phase`: 1 transcript, 2 media, 3 both.
#[derive(Debug, Default)]
struct Order {
    last: Option<Rank>,
    phase: u8,
}

impl Order {
    fn check(&mut self, ty: u8) -> Result<(), HistoryFailure> {
        let Some(incoming) = rank(ty) else {
            return Ok(());
        };
        let Some(last) = self.last else {
            if incoming != Rank::Manifest {
                return Err(HistoryFailure::RecordOrder);
            }
            self.last = Some(incoming);
            return Ok(());
        };
        let allowed = match incoming {
            Rank::Manifest => false,
            Rank::Meta | Rank::Message | Rank::Reaction => self.phase != 2,
            Rank::Media => self.phase != 1,
            Rank::End => true,
        };
        if !allowed || incoming < last {
            return Err(HistoryFailure::RecordOrder);
        }
        self.last = Some(incoming);
        Ok(())
    }
}

// ── Writer ────────────────────────────────────────────────────────────────────

/// Frames records for a CTH1 stream, and refuses to frame one out of order: the rule is checked
/// where the stream is made, not only where it is read.
#[derive(Debug, Default)]
pub struct Writer {
    order: Order,
    started: bool,
    ended: bool,
    /// Blob bytes still owed by the media record being written.
    media_remaining: u64,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    /// The preamble, on the first call only.
    fn preamble(&mut self, out: &mut Vec<u8>) {
        if !self.started {
            out.extend_from_slice(&MAGIC);
            out.push(VERSION);
            self.started = true;
        }
    }

    fn ready(&self) -> Result<(), HistoryFailure> {
        if self.ended || self.media_remaining > 0 {
            return Err(HistoryFailure::RecordOrder);
        }
        Ok(())
    }

    /// Frame one transcript record (types 0x01–0x07) from its protobuf bytes. The manifest is
    /// judged as the reader will judge it.
    pub fn record(
        &mut self,
        ty: u8,
        proto: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), HistoryFailure> {
        self.ready()?;
        if !(record_type::MANIFEST..=record_type::CALL).contains(&ty) {
            return Err(HistoryFailure::Malformed);
        }
        if proto.len() as u64 > MAX_RECORD_BYTES {
            return Err(HistoryFailure::Malformed);
        }
        self.order.check(ty)?;
        match ty {
            record_type::MANIFEST => {
                let m = wire::manifest(proto)?;
                if m.format_version != 1 || !(1..=3).contains(&m.phase) {
                    return Err(HistoryFailure::Malformed);
                }
                self.order.phase = m.phase as u8;
            }
            record_type::MESSAGE => {
                if wire::message_body(proto)? == Body::Unset {
                    return Err(HistoryFailure::Malformed);
                }
            }
            _ => wire::well_formed(proto)?,
        }
        self.preamble(out);
        out.push(ty);
        out.extend_from_slice(&(proto.len() as u64).to_le_bytes());
        out.extend_from_slice(proto);
        Ok(())
    }

    /// Begin a media blob of `byte_len` bytes: the record header and the blob's head. The blob
    /// itself follows through `media_bytes`, in any pieces, exactly `byte_len` in all.
    pub fn begin_media(
        &mut self,
        media_id: &str,
        mime_type: &str,
        byte_len: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), HistoryFailure> {
        self.ready()?;
        if media_id.is_empty() {
            return Err(HistoryFailure::Malformed);
        }
        let mut head = Vec::with_capacity(media_id.len() + mime_type.len() + 16);
        head.push(wire::tag(1, 2));
        wire::write_varint(media_id.len() as u64, &mut head);
        head.extend_from_slice(media_id.as_bytes());
        if !mime_type.is_empty() {
            head.push(wire::tag(2, 2));
            wire::write_varint(mime_type.len() as u64, &mut head);
            head.extend_from_slice(mime_type.as_bytes());
        }
        if byte_len > 0 {
            head.push(wire::tag(3, 2));
            wire::write_varint(byte_len, &mut head);
        }
        if head.len() > MEDIA_HEAD_CAP {
            return Err(HistoryFailure::Malformed);
        }
        let payload_len = head.len() as u64 + byte_len;
        if payload_len > MAX_RECORD_BYTES {
            return Err(HistoryFailure::Malformed);
        }
        self.order.check(record_type::MEDIA_BLOB)?;
        self.preamble(out);
        out.push(record_type::MEDIA_BLOB);
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&head);
        self.media_remaining = byte_len;
        Ok(())
    }

    /// The next piece of the blob begun by `begin_media`.
    pub fn media_bytes(&mut self, piece: &[u8], out: &mut Vec<u8>) -> Result<(), HistoryFailure> {
        if piece.len() as u64 > self.media_remaining {
            return Err(HistoryFailure::Malformed);
        }
        self.media_remaining -= piece.len() as u64;
        out.extend_from_slice(piece);
        Ok(())
    }

    /// The End record. A blob still owed bytes is an error, not a short blob.
    pub fn end(&mut self, out: &mut Vec<u8>) -> Result<(), HistoryFailure> {
        self.ready()?;
        self.order.check(record_type::END)?;
        self.preamble(out);
        out.push(record_type::END);
        self.ended = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::vectors;

    fn read_all(
        bytes: &[u8],
        envelope: Option<Envelope>,
        piece: usize,
    ) -> Result<Vec<Event>, HistoryFailure> {
        let mut r = Reader::new(envelope);
        let mut out = Vec::new();
        for chunk in bytes.chunks(piece.max(1)) {
            r.push(chunk, &mut out)?;
        }
        r.finish()?;
        Ok(out)
    }

    fn kinds(events: &[Event]) -> Vec<&'static str> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Record { record_type, .. } => Some(match *record_type {
                    record_type::MANIFEST => "manifest",
                    record_type::CONTACT => "contact",
                    record_type::CHAT => "chat",
                    record_type::MESSAGE => "message",
                    record_type::REACTION => "reaction",
                    record_type::PEER_DEVICE => "peer",
                    record_type::CALL => "call",
                    _ => "?",
                }),
                Event::Skipped { .. } => Some("unknown"),
                Event::MediaStart { .. } => Some("media"),
                Event::End => Some("end"),
                Event::MediaBytes(_) | Event::MediaEnd => None,
            })
            .collect()
    }

    fn expect_of(v: &serde_json::Value) -> Result<(), HistoryFailure> {
        match v["expect"].as_str().unwrap() {
            "decode_ok" | "applied" | "skipped" | "hint_dropped_bad_id" => Ok(()),
            "malformed" => Err(HistoryFailure::Malformed),
            "record_order" => Err(HistoryFailure::RecordOrder),
            "envelope_manifest_mismatch" => Err(HistoryFailure::EnvelopeManifestMismatch),
            other => panic!("unmapped expectation {other}"),
        }
    }

    /// Every CTH1 vector, fed whole and one byte at a time: the incremental reader must reach the
    /// same verdict however the bytes are cut. `applied` and `hint_dropped_bad_id` are importer
    /// outcomes; for the reader they are streams that decode.
    #[test]
    fn every_cth1_vector_reads_to_its_expected_verdict() {
        let mut checked = 0;
        for v in vectors::all() {
            let kind = v["kind"].as_str().unwrap();
            if kind != "cth1_stream" && kind != "cth1_header_only" {
                continue;
            }
            let bytes = vectors::hex_field(&v, "hex");
            let envelope = v.get("envelope_snapshot_id").map(|s| Envelope {
                snapshot_id: hex::decode(s.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                user_id: hex::decode("00000000000040008000000000000001")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            });
            let expected = expect_of(&v);
            for piece in [bytes.len(), 1, 7] {
                let got = read_all(&bytes, envelope.clone(), piece);
                match (&got, &expected) {
                    (Ok(events), Ok(())) => {
                        let want: Vec<&str> = v["records"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|r| r.as_str().unwrap())
                            .collect();
                        assert_eq!(kinds(events), want, "{} piece {piece}", v["name"]);
                    }
                    (Err(g), Err(e)) => assert_eq!(g, e, "{} piece {piece}", v["name"]),
                    _ => panic!(
                        "{} piece {piece}: got {got:?}, expected {expected:?}",
                        v["name"]
                    ),
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 17, "the CTH1 vectors did not all run");
    }

    fn manifest(phase: u8) -> Vec<u8> {
        let mut m = vec![wire::tag(1, 0), 1];
        m.extend_from_slice(&[wire::tag(2, 2), 16]);
        m.extend_from_slice(&[0xaa; 16]);
        m.extend_from_slice(&[wire::tag(3, 2), 16]);
        m.extend_from_slice(&[0x01; 16]);
        m.extend_from_slice(&[wire::tag(13, 0), phase]);
        m
    }

    /// The writer's output reads back as the same events — including a blob written in odd pieces
    /// and read in odd pieces, which arrives byte-exact.
    #[test]
    fn a_written_stream_reads_back_with_the_blob_byte_exact() {
        let blob: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut w = Writer::new();
        let mut bytes = Vec::new();
        w.record(record_type::MANIFEST, &manifest(3), &mut bytes)
            .unwrap();
        w.record(record_type::MESSAGE, &[wire::tag(6, 2), 0], &mut bytes)
            .unwrap();
        w.begin_media("m-1", "image/jpeg", blob.len() as u64, &mut bytes)
            .unwrap();
        for piece in blob.chunks(9_999) {
            w.media_bytes(piece, &mut bytes).unwrap();
        }
        w.begin_media("m-empty", "", 0, &mut bytes).unwrap();
        w.end(&mut bytes).unwrap();

        for piece in [bytes.len(), 65_536, 13] {
            let events = read_all(&bytes, None, piece).unwrap();
            assert_eq!(
                kinds(&events),
                ["manifest", "message", "media", "media", "end"]
            );
            let mut got = Vec::new();
            let mut starts = Vec::new();
            for e in &events {
                match e {
                    Event::MediaStart {
                        media_id,
                        mime_type,
                        byte_len,
                    } => starts.push((media_id.clone(), mime_type.clone(), *byte_len)),
                    Event::MediaBytes(b) if starts.len() == 1 => got.extend_from_slice(b),
                    Event::MediaBytes(_) => panic!("bytes for the empty blob"),
                    _ => {}
                }
            }
            assert_eq!(got, blob, "piece {piece}");
            assert_eq!(
                starts,
                [
                    ("m-1".to_owned(), "image/jpeg".to_owned(), blob.len() as u64),
                    ("m-empty".to_owned(), String::new(), 0)
                ]
            );
        }
    }

    /// No media event carries more than the bytes that arrived with it: memory is one push, not
    /// one blob.
    #[test]
    fn a_blob_is_never_held_whole() {
        let blob = vec![7u8; 1_000_000];
        let mut w = Writer::new();
        let mut bytes = Vec::new();
        w.record(record_type::MANIFEST, &manifest(2), &mut bytes)
            .unwrap();
        w.begin_media("big", "video/mp4", blob.len() as u64, &mut bytes)
            .unwrap();
        w.media_bytes(&blob, &mut bytes).unwrap();
        w.end(&mut bytes).unwrap();
        let events = read_all(&bytes, None, 65_536).unwrap();
        let largest = events
            .iter()
            .filter_map(|e| match e {
                Event::MediaBytes(b) => Some(b.len()),
                _ => None,
            })
            .max()
            .unwrap();
        assert!(largest <= 65_536, "a media event held {largest} bytes");
    }

    /// The canonical-order amendment: a blob field ahead of `media_id` cannot be streamed, and is
    /// refused rather than buffered.
    #[test]
    fn a_blob_field_before_the_media_id_is_malformed() {
        let mut payload = vec![wire::tag(3, 2), 3, 1, 2, 3];
        payload.extend_from_slice(&[wire::tag(1, 2), 1, b'm']);
        let mut bytes = MAGIC.to_vec();
        bytes.push(VERSION);
        bytes.push(record_type::MANIFEST);
        let m = manifest(2);
        bytes.extend_from_slice(&(m.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&m);
        bytes.push(record_type::MEDIA_BLOB);
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.push(record_type::END);
        assert_eq!(
            read_all(&bytes, None, bytes.len()),
            Err(HistoryFailure::Malformed)
        );
    }

    #[test]
    fn the_writer_refuses_what_the_reader_would_refuse() {
        let mut out = Vec::new();
        let mut w = Writer::new();
        assert_eq!(
            w.record(record_type::MESSAGE, &[wire::tag(6, 2), 0], &mut out),
            Err(HistoryFailure::RecordOrder),
            "no manifest first"
        );
        let mut w = Writer::new();
        w.record(record_type::MANIFEST, &manifest(1), &mut out)
            .unwrap();
        assert_eq!(
            w.begin_media("m", "", 1, &mut out),
            Err(HistoryFailure::RecordOrder),
            "media in phase 1"
        );
        w.record(record_type::REACTION, &[], &mut out).unwrap();
        assert_eq!(
            w.record(record_type::MESSAGE, &[wire::tag(6, 2), 0], &mut out),
            Err(HistoryFailure::RecordOrder),
            "a message after a reaction"
        );
        let mut w = Writer::new();
        w.record(record_type::MANIFEST, &manifest(2), &mut out)
            .unwrap();
        w.begin_media("m", "", 2, &mut out).unwrap();
        w.media_bytes(&[1], &mut out).unwrap();
        assert_eq!(
            w.end(&mut out),
            Err(HistoryFailure::RecordOrder),
            "a blob one byte short"
        );
        assert_eq!(
            w.media_bytes(&[1, 2], &mut out),
            Err(HistoryFailure::Malformed),
            "a blob too long"
        );
    }

    /// A message is its body: none at all is malformed; one this version does not know is a
    /// future body case, skipped like an unknown record type.
    #[test]
    fn a_message_without_a_body_is_malformed_and_one_with_a_future_body_is_skipped() {
        fn stream(message: &[u8]) -> Vec<u8> {
            let mut bytes = Vec::new();
            let mut w = Writer::new();
            w.record(record_type::MANIFEST, &manifest(1), &mut bytes)
                .unwrap();
            bytes.push(record_type::MESSAGE);
            bytes.extend_from_slice(&(message.len() as u64).to_le_bytes());
            bytes.extend_from_slice(message);
            w.end(&mut bytes).unwrap();
            bytes
        }
        let unset = [wire::tag(1, 2), 1, b'a'];
        assert_eq!(
            read_all(&stream(&unset), None, 4),
            Err(HistoryFailure::Malformed)
        );

        // Field 17, length-delimited: a body case from a later version.
        let future = [wire::tag(1, 2), 1, b'a', 0x8a, 0x01, 0];
        let events = read_all(&stream(&future), None, 4).unwrap();
        assert_eq!(
            events[1],
            Event::Skipped {
                record_type: record_type::MESSAGE
            }
        );
    }

    #[test]
    fn nothing_may_follow_end_and_a_stream_without_end_is_truncated() {
        let mut w = Writer::new();
        let mut bytes = Vec::new();
        w.record(record_type::MANIFEST, &manifest(1), &mut bytes)
            .unwrap();
        assert_eq!(read_all(&bytes, None, 5), Err(HistoryFailure::Truncated));
        w.end(&mut bytes).unwrap();
        let mut with_tail = bytes.clone();
        with_tail.push(0);
        assert_eq!(
            read_all(&with_tail, None, 3),
            Err(HistoryFailure::Malformed)
        );
        assert!(read_all(&bytes, None, 3).is_ok());
    }

    #[test]
    fn an_unknown_record_is_skipped_without_being_kept() {
        let mut bytes = Vec::new();
        let mut w = Writer::new();
        w.record(record_type::MANIFEST, &manifest(1), &mut bytes)
            .unwrap();
        bytes.push(0x0c);
        bytes.extend_from_slice(&(100_000u64).to_le_bytes());
        bytes.extend_from_slice(&[0xee; 100_000]);
        w.end(&mut bytes).unwrap();
        let events = read_all(&bytes, None, 4096).unwrap();
        assert_eq!(events[1], Event::Skipped { record_type: 0x0c });
        assert_eq!(kinds(&events), ["manifest", "unknown", "end"]);
    }
}
