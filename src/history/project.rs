//! History records ↔ local store rows: how a transferred transcript lands in the receiver's
//! store, and how a store's rows become records. Pure — the caller reads what it holds, calls
//! these, and writes what they return (`construct-docs/decisions/history-projection-in-the-core.md`).
//!
//! The receiver's policy, which every client must apply alike or the same transfer lands as two
//! different transcripts:
//! - a contact's names, alias and avatar are only filled in, never overwritten;
//! - the sharing flags are only raised; a block is only added, never lifted;
//! - a message already held is kept (the store's insert does not overwrite);
//! - our own message lands sent, never delivered — this device saw no receipt; an incoming one
//!   lands delivered;
//! - an imported message has no server position: it takes a local order key at its own time;
//! - message ids are lowercase.
//!
//! Times: the records carry Unix seconds except where a field says ms; the store keeps ms.

use construct_store::delivery::{DELIVERED, SENT};
use construct_store::payload::{self, Payload};
use construct_store::{CallRecord, Contact, Message, PeerDevice, Reaction};

use super::HistoryFailure;
use super::records::{self, MediaRef, MessageBody};

type Result<T> = std::result::Result<T, HistoryFailure>;

fn secs_to_ms(secs: i64) -> i64 {
    secs.saturating_mul(1000)
}

/// Seconds, rounded to the nearest — what the iOS encoder wrote.
fn ms_to_secs(ms: i64) -> i64 {
    (ms as f64 / 1000.0).round() as i64
}

fn account(raw: &[u8]) -> Result<String> {
    records::dashed(raw).ok_or(HistoryFailure::Malformed)
}

// MARK: - Import

/// A contact record merged into what the receiver holds (`None`: nothing yet).
///
/// The caller passes a display name it generated itself as empty, so the record's real one can
/// fill it. Left as the receiver has them: the identity key, the key-transparency status, the
/// security notice, the profile edit time and any pending avatar — what this device verified or
/// fetched is its own.
pub fn import_contact(record: &[u8], existing: Option<Contact>, now_ms: i64) -> Result<Contact> {
    let r = records::ContactRecord::decode(record)?;
    let id = account(&r.user_id)?;
    let mut c = existing.unwrap_or_else(|| Contact {
        id: id.clone(),
        ..Default::default()
    });
    if c.username.is_empty() {
        c.username = r.username;
    }
    if c.display_name.is_empty() {
        c.display_name = r.display_name;
    }
    if c.local_alias.as_deref().unwrap_or("").is_empty() && !r.local_alias.is_empty() {
        c.local_alias = Some(r.local_alias);
    }
    if c.avatar.as_deref().unwrap_or(&[]).is_empty() && !r.avatar.is_empty() {
        c.avatar = Some(r.avatar);
    }
    c.is_contact |= r.is_contact;
    c.am_i_sharing_with |= r.am_i_sharing_with;
    c.is_sharing_with_me |= r.is_sharing_with_me;
    c.is_blocked |= r.is_blocked;
    if c.added_at.is_none() {
        c.added_at = Some(if r.added_at_unix > 0 {
            secs_to_ms(r.added_at_unix)
        } else {
            now_ms
        });
    }
    if c.shared_with_me_at.is_none() && r.shared_with_me_at_unix > 0 {
        c.shared_with_me_at = Some(secs_to_ms(r.shared_with_me_at_unix));
    }
    Ok(c)
}

/// What a chat record asks of the receiver's chat with `peer_id`: that it exist, pinned if `pin`
/// (never unpinned), its unread count cleared. The record's mute is not kept — no client has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatImport {
    pub peer_id: String,
    pub pin: bool,
}

pub fn import_chat(record: &[u8]) -> Result<ChatImport> {
    let r = records::ChatRecord::decode(record)?;
    Ok(ChatImport {
        peer_id: account(&r.other_user_id)?,
        pin: r.is_pinned,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageImport {
    /// The row to insert into the chat with `peer_id`. Its `chat_id` is empty: the caller opens
    /// that chat and sets it.
    Row {
        peer_id: String,
        message: Box<Message>,
    },
    /// A body this version does not know — a future case of the oneof. Skipped, like an unknown
    /// record type.
    UnknownBody,
}

/// A message record as a row. `own_account_id` decides which side is the peer.
pub fn import_message(record: &[u8], own_account_id: &str) -> Result<MessageImport> {
    let r = records::MessageRecord::decode(record)?;
    let id = r.id.to_lowercase();
    if id.is_empty() {
        return Err(HistoryFailure::Malformed);
    }
    let body = match r.body {
        Some(MessageBody::Content(b)) => payload::encode(payload::kind::MESSAGE_CONTENT, &b),
        Some(MessageBody::Album(b)) => payload::encode(payload::kind::MEDIA_ALBUM, &b),
        Some(MessageBody::Profile(b)) => payload::encode(payload::kind::PROFILE, &b),
        None if r.has_unknown_fields => return Ok(MessageImport::UnknownBody),
        None => return Err(HistoryFailure::Malformed),
    };
    let from = account(&r.from_user_id)?;
    let to = account(&r.to_user_id)?;
    let own = own_account_id.to_lowercase();
    let peer_id = if from == own {
        to.clone()
    } else if to == own {
        from.clone()
    } else if r.is_sent_by_me {
        to.clone()
    } else {
        from.clone()
    };
    let non_empty = |s: String| (!s.is_empty()).then_some(s);
    let message = Message {
        id: id.clone(),
        chat_id: String::new(),
        from_user_id: from,
        to_user_id: to,
        is_sent_by_me: r.is_sent_by_me,
        timestamp: r.timestamp_unix_ms,
        order_key: payload::local_order_key(r.timestamp_unix_ms, &id),
        body,
        content_type: 0,
        delivery_status: if r.is_sent_by_me { SENT } else { DELIVERED },
        retry_count: 0,
        suite_id: r.suite_id as u16 as i16,
        is_edited: r.is_edited,
        edited_at: (r.edited_at_unix_ms > 0).then_some(r.edited_at_unix_ms),
        reply_to_message_id: non_empty(r.reply_to_message_id.to_lowercase()),
        reply_to_content: non_empty(r.reply_to_content),
        transcript_text: non_empty(r.transcript_text),
        transcript_language: non_empty(r.transcript_language),
        transcript_generated_at: (r.transcript_generated_at_unix > 0)
            .then(|| secs_to_ms(r.transcript_generated_at_unix)),
    };
    Ok(MessageImport::Row {
        peer_id,
        message: Box::new(message),
    })
}

/// A reaction record as a row, received now. The caller keeps one whose message it does not
/// hold out, and one the reactor already has on that message.
pub fn import_reaction(record: &[u8], received_at_ms: i64) -> Result<Reaction> {
    let r = records::ReactionRecord::decode(record)?;
    let target = r.target_message_id.to_lowercase();
    if target.is_empty() {
        return Err(HistoryFailure::Malformed);
    }
    Ok(Reaction {
        target_message_id: target,
        reactor_user_id: account(&r.reactor_user_id)?,
        emoji: r.emoji,
        timestamp_ms: r.timestamp_ms,
        received_at: Some(received_at_ms),
    })
}

/// A peer device the sender knew, or `None` when its id is not the one its key derives — a hint
/// that would pin the wrong key is dropped, not trusted.
pub fn import_peer_device(record: &[u8], now_ms: i64) -> Result<Option<PeerDevice>> {
    let r = records::PeerDeviceRecord::decode(record)?;
    if crate::device_id::derive_device_id(&r.identity_key) != r.device_id.to_lowercase() {
        return Ok(None);
    }
    Ok(Some(PeerDevice {
        device_id: r.device_id.to_lowercase(),
        account_id: account(&r.account_id)?,
        identity_key: r.identity_key,
        first_seen_at: if r.first_seen_at_unix > 0 {
            secs_to_ms(r.first_seen_at_unix)
        } else {
            now_ms
        },
    }))
}

/// Call directions and statuses as the stores keep them (iOS `CTCallRecord`).
pub mod call {
    pub const OUTGOING: i16 = 0;
    pub const INCOMING: i16 = 1;
    pub const COMPLETED: i16 = 0;
    /// The highest status this version knows (failed); a higher one reads as completed.
    pub const LAST_STATUS: i16 = 3;
}

/// A call record as a row; `peer_name` is the receiver's name for the peer (the record carries
/// none). A completed call with a duration ends that long after it started.
pub fn import_call(record: &[u8], peer_name: &str, now_ms: i64) -> Result<CallRecord> {
    let r = records::CallRecord::decode(record)?;
    if r.id.is_empty() {
        return Err(HistoryFailure::Malformed);
    }
    let peer_user_id = account(&r.peer_user_id)?;
    let status = i16::try_from(r.status)
        .ok()
        .filter(|s| (0..=call::LAST_STATUS).contains(s))
        .unwrap_or(call::COMPLETED);
    let started = if r.started_at_unix > 0 {
        secs_to_ms(r.started_at_unix)
    } else {
        now_ms
    };
    let ended = (status == call::COMPLETED && r.duration_seconds > 0)
        .then(|| started.saturating_add(secs_to_ms(r.duration_seconds)));
    Ok(CallRecord {
        id: r.id,
        peer_user_id,
        peer_name: peer_name.to_owned(),
        direction: if r.is_outgoing {
            call::OUTGOING
        } else {
            call::INCOMING
        },
        status,
        started_at: Some(started),
        ended_at: ended,
        duration_seconds: i32::try_from(r.duration_seconds.max(0)).unwrap_or(i32::MAX),
    })
}

// MARK: - Export

pub fn export_contact(c: &Contact) -> Vec<u8> {
    records::ContactRecord {
        user_id: records::raw(&c.id).unwrap_or_default(),
        username: c.username.clone(),
        display_name: c.display_name.clone(),
        local_alias: c.local_alias.clone().unwrap_or_default(),
        avatar: c.avatar.clone().unwrap_or_default(),
        is_contact: c.is_contact,
        is_blocked: c.is_blocked,
        am_i_sharing_with: c.am_i_sharing_with,
        is_sharing_with_me: c.is_sharing_with_me,
        added_at_unix: c.added_at.map_or(0, ms_to_secs),
        shared_with_me_at_unix: c.shared_with_me_at.map_or(0, ms_to_secs),
    }
    .encode()
}

pub fn export_chat(peer_id: &str, is_pinned: bool) -> Vec<u8> {
    records::ChatRecord {
        other_user_id: records::raw(peer_id).unwrap_or_default(),
        is_pinned,
        is_muted: false,
    }
    .encode()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageExport {
    /// The record, and the media files its body refers to.
    Record {
        record: Vec<u8>,
        media: Vec<MediaRef>,
    },
    /// A control row (a session signal, a profile carrier): not transcript.
    Control,
    /// No body — a message this device never read.
    Empty,
    /// A body from before CTM1, which the client that wrote it reads.
    Legacy,
}

/// Content types of rows that are not transcript (iOS `MessageContentType.isEphemeral`).
const CONTROL_CONTENT_TYPES: [i16; 4] = [1, 10, 11, 12];

/// A row as a record. A side whose stored id is not an account id is the one the row's role
/// names: ours for a sent row, the chat's peer (`chat_peer_id`) for a received one — older iOS
/// rows carry something else there, and a record without a parseable side is refused whole.
pub fn export_message(
    m: &Message,
    own_account_id: &str,
    chat_peer_id: Option<&str>,
) -> MessageExport {
    if CONTROL_CONTENT_TYPES.contains(&m.content_type) {
        return MessageExport::Control;
    }
    if m.body.is_empty() {
        return MessageExport::Empty;
    }
    let body = match Payload::decode(&m.body) {
        Payload::Text(s) => MessageBody::Content(records::text_content(s)),
        Payload::MessageContent(b) => MessageBody::Content(b.to_vec()),
        Payload::MediaAlbum(b) => MessageBody::Album(b.to_vec()),
        Payload::Profile(b) => MessageBody::Profile(b.to_vec()),
        Payload::Legacy(_) => return MessageExport::Legacy,
    };
    let side = |stored: &str, ours: bool| {
        records::raw(stored)
            .or_else(|| records::raw(if ours { own_account_id } else { chat_peer_id? }))
            .unwrap_or_default()
    };
    let media = records::media_refs(&body);
    let record = records::MessageRecord {
        id: m.id.to_lowercase(),
        from_user_id: side(&m.from_user_id, m.is_sent_by_me),
        to_user_id: side(&m.to_user_id, !m.is_sent_by_me),
        timestamp_unix_ms: m.timestamp,
        is_sent_by_me: m.is_sent_by_me,
        body: Some(body),
        reply_to_message_id: m
            .reply_to_message_id
            .as_deref()
            .unwrap_or("")
            .to_lowercase(),
        reply_to_content: m.reply_to_content.clone().unwrap_or_default(),
        is_edited: m.is_edited,
        edited_at_unix_ms: m.edited_at.unwrap_or(0),
        transcript_text: m.transcript_text.clone().unwrap_or_default(),
        transcript_language: m.transcript_language.clone().unwrap_or_default(),
        transcript_generated_at_unix: m.transcript_generated_at.map_or(0, ms_to_secs),
        suite_id: u32::from(m.suite_id as u16),
        has_unknown_fields: false,
    }
    .encode();
    MessageExport::Record { record, media }
}

pub fn export_reaction(r: &Reaction) -> Vec<u8> {
    records::ReactionRecord {
        target_message_id: r.target_message_id.to_lowercase(),
        reactor_user_id: records::raw(&r.reactor_user_id).unwrap_or_default(),
        emoji: r.emoji.clone(),
        timestamp_ms: r.timestamp_ms,
    }
    .encode()
}

pub fn export_peer_device(d: &PeerDevice) -> Vec<u8> {
    records::PeerDeviceRecord {
        account_id: records::raw(&d.account_id).unwrap_or_default(),
        device_id: d.device_id.to_lowercase(),
        identity_key: d.identity_key.clone(),
        first_seen_at_unix: ms_to_secs(d.first_seen_at),
    }
    .encode()
}

pub fn export_call(c: &CallRecord) -> Vec<u8> {
    records::CallRecord {
        id: c.id.clone(),
        peer_user_id: records::raw(&c.peer_user_id).unwrap_or_default(),
        is_outgoing: c.direction == call::OUTGOING,
        status: u32::from(c.status as u16),
        started_at_unix: c.started_at.map_or(0, ms_to_secs),
        duration_seconds: i64::from(c.duration_seconds),
    }
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::cth1::{Event, Reader};
    use crate::history::{record_type, vectors};

    const OWN: &str = "00000000-0000-4000-8000-000000000001";
    const PEER: &str = "00000000-0000-4000-8000-000000000002";

    /// The records of a vector stream, by type, as the reader releases them.
    fn records(name: &str) -> Vec<(u8, Vec<u8>)> {
        let v = vectors::named(name);
        let mut reader = Reader::new(None);
        let mut events = Vec::new();
        reader
            .push(&vectors::hex_field(&v, "hex"), &mut events)
            .unwrap();
        events
            .into_iter()
            .filter_map(|e| match e {
                Event::Record { record_type, proto } => Some((record_type, proto)),
                _ => None,
            })
            .collect()
    }

    fn of(name: &str, kind: u8) -> Vec<u8> {
        records(name)
            .into_iter()
            .find(|(t, _)| *t == kind)
            .map(|(_, p)| p)
            .unwrap_or_else(|| panic!("{name} has no record of type {kind}"))
    }

    /// Every record in the vectors reads, writes and reads back to the same fields. The vector
    /// generator writes zero fields out; the writer here leaves them out, as SwiftProtobuf does —
    /// both are proto3, so the fields are compared, not the bytes. Mutation: drop a field from a
    /// writer — it reads back as its zero.
    #[test]
    fn vector_records_read_back_through_the_writer() {
        fn again<T: PartialEq + std::fmt::Debug>(
            proto: &[u8],
            decode: fn(&[u8]) -> Result<T>,
            encode: fn(&T) -> Vec<u8>,
        ) {
            let first = decode(proto).unwrap();
            assert_eq!(decode(&encode(&first)).unwrap(), first);
        }
        let mut seen = 0;
        for name in [
            "contact_chat_peer_call",
            "message_content_text",
            "message_media_album",
            "message_profile_share",
            "reaction_after_message",
        ] {
            for (kind, proto) in records(name) {
                match kind {
                    record_type::CONTACT => again(
                        &proto,
                        records::ContactRecord::decode,
                        records::ContactRecord::encode,
                    ),
                    record_type::CHAT => again(
                        &proto,
                        records::ChatRecord::decode,
                        records::ChatRecord::encode,
                    ),
                    record_type::MESSAGE => again(
                        &proto,
                        records::MessageRecord::decode,
                        records::MessageRecord::encode,
                    ),
                    record_type::REACTION => again(
                        &proto,
                        records::ReactionRecord::decode,
                        records::ReactionRecord::encode,
                    ),
                    record_type::PEER_DEVICE => again(
                        &proto,
                        records::PeerDeviceRecord::decode,
                        records::PeerDeviceRecord::encode,
                    ),
                    record_type::CALL => again(
                        &proto,
                        records::CallRecord::decode,
                        records::CallRecord::encode,
                    ),
                    _ => continue,
                }
                seen += 1;
            }
        }
        assert!(seen >= 9, "the vectors' records were read ({seen})");
    }

    /// A writer leaves zero fields out, in field-number order — SwiftProtobuf's bytes. Mutation:
    /// write a false flag.
    #[test]
    fn a_writer_leaves_zeros_out() {
        let chat = records::ChatRecord {
            other_user_id: vec![1],
            is_pinned: false,
            is_muted: true,
        };
        assert_eq!(chat.encode(), [0x0a, 0x01, 0x01, 0x18, 0x01]);
        assert!(records::ContactRecord::default().encode().is_empty());
    }

    /// A text message lands as the receiver's row: CTM1 around the content bytes, delivered,
    /// a local order key at its time, in the chat with its sender. Mutation: own message
    /// delivered — the sent copy reads delivered; drop the order key's id.
    #[test]
    fn a_message_record_lands_as_a_row() {
        let proto = of("message_content_text", record_type::MESSAGE);
        let r = records::MessageRecord::decode(&proto).unwrap();
        let Some(MessageBody::Content(content)) = r.body.clone() else {
            panic!("a content body")
        };
        let from = records::dashed(&r.from_user_id).unwrap();
        let to = records::dashed(&r.to_user_id).unwrap();

        let MessageImport::Row { peer_id, message } = import_message(&proto, &to).unwrap() else {
            panic!("a row")
        };
        assert_eq!(peer_id, from, "received: the peer is the sender");
        assert_eq!(
            message.body,
            payload::encode(payload::kind::MESSAGE_CONTENT, &content)
        );
        assert_eq!(message.id, r.id.to_lowercase());
        assert_eq!(message.timestamp, r.timestamp_unix_ms);
        assert_eq!(
            message.order_key,
            payload::local_order_key(r.timestamp_unix_ms, &r.id)
        );
        assert_eq!(message.delivery_status, DELIVERED);
        assert!(message.chat_id.is_empty(), "the caller's to set");

        let MessageImport::Row { peer_id, message } = import_message(&proto, &from).unwrap() else {
            panic!("a row")
        };
        assert_eq!(peer_id, to, "sent: the peer is the recipient");
        assert_eq!(
            message.delivery_status,
            if r.is_sent_by_me { SENT } else { DELIVERED }
        );

        // Neither side is ours: the record's own flag decides.
        let mut mine = r.clone();
        mine.is_sent_by_me = true;
        let MessageImport::Row { message, .. } =
            import_message(&mine.encode(), "ffffffff-ffff-4fff-8fff-ffffffffffff").unwrap()
        else {
            panic!("a row")
        };
        assert_eq!(message.delivery_status, SENT, "this device saw no receipt");
    }

    /// No body: malformed, unless a field this version does not know is there — a future body,
    /// skipped. Mutation: treat both alike.
    #[test]
    fn a_message_without_a_body_is_refused_or_skipped() {
        let mut r =
            records::MessageRecord::decode(&of("message_content_text", record_type::MESSAGE))
                .unwrap();
        r.body = None;
        let bare = r.encode();
        assert_eq!(import_message(&bare, OWN), Err(HistoryFailure::Malformed));
        let mut future = bare.clone();
        future.extend_from_slice(&[0x8a, 0x01, 0x01, 0x00]); // field 17, one byte
        assert_eq!(import_message(&future, OWN), Ok(MessageImport::UnknownBody));
    }

    /// A row goes out and comes back the same row. Mutation: drop a field from either side.
    #[test]
    fn a_row_round_trips_through_a_record() {
        let row = Message {
            id: "abc".into(),
            chat_id: "c".into(),
            from_user_id: OWN.into(),
            to_user_id: PEER.into(),
            is_sent_by_me: true,
            timestamp: 1_700_000_000_000,
            order_key: payload::local_order_key(1_700_000_000_000, "abc"),
            body: payload::encode(payload::kind::PROFILE, &[1, 2, 3]),
            content_type: 0,
            delivery_status: SENT,
            retry_count: 0,
            suite_id: -2,
            is_edited: true,
            edited_at: Some(1_700_000_000_500),
            reply_to_message_id: Some("def".into()),
            reply_to_content: Some("quote".into()),
            transcript_text: Some("words".into()),
            transcript_language: Some("en".into()),
            transcript_generated_at: Some(1_700_000_001_000),
        };
        let MessageExport::Record { record, media } = export_message(&row, OWN, Some(PEER)) else {
            panic!("a record")
        };
        assert!(media.is_empty());
        let MessageImport::Row { peer_id, message } = import_message(&record, OWN).unwrap() else {
            panic!("a row")
        };
        assert_eq!(peer_id, PEER);
        assert_eq!(
            *message,
            Message {
                chat_id: String::new(),
                ..row
            }
        );
    }

    /// A stored text travels as `MessageContent{text}`; control rows, unread rows and rows from
    /// before CTM1 do not travel. Mutation: drop a control content type.
    #[test]
    fn what_a_row_exports_as() {
        let mut row = Message {
            id: "m".into(),
            from_user_id: PEER.into(),
            to_user_id: OWN.into(),
            body: payload::encode(payload::kind::TEXT, b"hello"),
            ..Default::default()
        };
        let MessageExport::Record { record, .. } = export_message(&row, OWN, Some(PEER)) else {
            panic!("a record")
        };
        let r = records::MessageRecord::decode(&record).unwrap();
        assert_eq!(
            r.body,
            Some(MessageBody::Content(records::text_content("hello")))
        );
        assert_eq!(
            records::text_content("hello"),
            [0x0a, 0x07, 0x0a, 0x05, b'h', b'e', b'l', b'l', b'o']
        );
        for control in [1, 10, 11, 12] {
            row.content_type = control;
            assert_eq!(export_message(&row, OWN, None), MessageExport::Control);
        }
        row.content_type = 0;
        row.body = b"{\"type\":\"voice\"}".to_vec();
        assert_eq!(export_message(&row, OWN, None), MessageExport::Legacy);
        row.body.clear();
        assert_eq!(export_message(&row, OWN, None), MessageExport::Empty);
    }

    /// A side that is not an account id takes the one the row's role names. Mutation: swap the
    /// roles — a received row names us as its sender.
    #[test]
    fn an_unparseable_side_is_the_one_the_role_names() {
        let row = Message {
            id: "m".into(),
            from_user_id: "".into(),
            to_user_id: "6f5e37ac".into(),
            is_sent_by_me: false,
            body: payload::encode(payload::kind::TEXT, b"x"),
            ..Default::default()
        };
        let MessageExport::Record { record, .. } = export_message(&row, OWN, Some(PEER)) else {
            panic!("a record")
        };
        let r = records::MessageRecord::decode(&record).unwrap();
        assert_eq!(records::dashed(&r.from_user_id).as_deref(), Some(PEER));
        assert_eq!(records::dashed(&r.to_user_id).as_deref(), Some(OWN));
    }

    /// The media an album or a voice note refers to. Mutation: skip the voice codec's id.
    #[test]
    fn a_bodys_media_are_listed() {
        let album = of("message_media_album", record_type::MESSAGE);
        let r = records::MessageRecord::decode(&album).unwrap();
        let refs = records::media_refs(r.body.as_ref().unwrap());
        assert!(!refs.is_empty(), "the album vector names its media");

        let mut voice = records::Writer::default();
        voice.bytes(6, b"audio/ogg|media-7");
        let mut content = records::Writer::default();
        content.always_bytes(6, &voice.out);
        assert_eq!(
            records::media_refs(&MessageBody::Content(content.out)),
            [MediaRef {
                id: "media-7".into(),
                mime: "audio/ogg".into()
            }]
        );
    }

    /// Names and avatar only fill in, flags only rise, a block is never lifted, and the added
    /// time is kept. Mutation: assign instead of `|=` for the block — it is lifted.
    #[test]
    fn a_contact_record_only_adds_to_what_is_held() {
        let proto = of("contact_chat_peer_call", record_type::CONTACT);
        let r = records::ContactRecord::decode(&proto).unwrap();
        let id = records::dashed(&r.user_id).unwrap();

        let fresh = import_contact(&proto, None, 99).unwrap();
        assert_eq!(fresh.id, id);
        assert_eq!(fresh.display_name, r.display_name);
        assert_eq!(
            fresh.added_at,
            Some(if r.added_at_unix > 0 {
                r.added_at_unix * 1000
            } else {
                99
            })
        );

        let held = Contact {
            id: id.clone(),
            display_name: "Mine".into(),
            is_blocked: true,
            is_contact: false,
            added_at: Some(5),
            ..Default::default()
        };
        let mut unblocked = r.clone();
        unblocked.is_blocked = false;
        unblocked.is_contact = true;
        let merged = import_contact(&unblocked.encode(), Some(held), 99).unwrap();
        assert_eq!(merged.display_name, "Mine", "never overwritten");
        assert!(merged.is_blocked, "a block is never lifted");
        assert!(merged.is_contact, "a flag rises");
        assert_eq!(merged.added_at, Some(5), "kept");
        assert_eq!(merged.username, r.username, "an empty one is filled");
    }

    /// A hint whose id is not its key's is dropped. Mutation: skip the derivation check.
    #[test]
    fn a_peer_hint_must_name_its_own_key() {
        let proto = of("contact_chat_peer_call", record_type::PEER_DEVICE);
        let device = import_peer_device(&proto, 1)
            .unwrap()
            .expect("the vector's hint is sound");
        assert_eq!(device.identity_key.len(), 32);
        let mut forged = records::PeerDeviceRecord::decode(&proto).unwrap();
        forged.device_id = "00".repeat(16);
        assert_eq!(import_peer_device(&forged.encode(), 1), Ok(None));
    }

    /// A call, a chat and a reaction land as the vectors say; a completed call ends after its
    /// duration. Mutation: end every call — a missed one gets an end.
    #[test]
    fn calls_chats_and_reactions_land() {
        let proto = of("contact_chat_peer_call", record_type::CALL);
        let r = records::CallRecord::decode(&proto).unwrap();
        let call = import_call(&proto, "Alice", 7).unwrap();
        assert_eq!(call.peer_name, "Alice");
        assert_eq!(
            records::CallRecord::decode(&export_call(&call)).unwrap(),
            r,
            "back to the same record"
        );
        let mut missed = r.clone();
        missed.status = 1;
        missed.duration_seconds = 30;
        assert_eq!(import_call(&missed.encode(), "", 7).unwrap().ended_at, None);
        let mut done = missed.clone();
        done.status = 0;
        let ended = import_call(&done.encode(), "", 7).unwrap();
        assert_eq!(ended.ended_at, ended.started_at.map(|s| s + 30_000));

        let chat = import_chat(&of("contact_chat_peer_call", record_type::CHAT)).unwrap();
        assert!(!chat.peer_id.is_empty());

        let reaction = of("reaction_after_message", record_type::REACTION);
        let row = import_reaction(&reaction, 42).unwrap();
        assert_eq!(row.received_at, Some(42));
        assert_eq!(
            records::ReactionRecord::decode(&export_reaction(&row)).unwrap(),
            records::ReactionRecord::decode(&reaction).unwrap()
        );
    }

    #[test]
    fn account_ids_convert_both_ways() {
        let raw = records::raw("AAAAAAAA-0000-4000-8000-00000000000F").unwrap();
        assert_eq!(raw.len(), 16);
        assert_eq!(
            records::dashed(&raw).unwrap(),
            "aaaaaaaa-0000-4000-8000-00000000000f"
        );
        for bad in [
            "",
            "aaaaaaaa00004000800000000000000f",
            "aaaaaaaa-0000-4000-8000-00000000000g",
        ] {
            assert_eq!(records::raw(bad), None, "{bad}");
        }
    }
}
