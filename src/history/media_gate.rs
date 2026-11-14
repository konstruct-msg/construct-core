//! Which media blobs of a history transfer the receiver may write.
//!
//! A blob is the other device's word for a file on this device's disk, under the name the blob
//! gives. Two rules, one place, so no platform writes its own (`construct-docs/decisions/
//! history-transfer-whole-in-the-core.md` §1–2, todo 314):
//!
//! 1. The name is a server media id: a dashed UUID. It becomes a file name on every platform, so
//!    a `..` or a `/` must never reach one. Until 2026-11-14 iOS checked only `/` and empty.
//! 2. A message of the transcript names it — one from this transfer (phase 1 and 3 carry the
//!    messages before the media) or one this device already holds (phase 2 carries media alone;
//!    the platform passes those ids in with [`MediaGate::expect`]). A blob nobody refers to is a
//!    file planted on the disk.
//!
//! A refused blob is dropped whole: its bytes never reach the platform, and one event says why.
//! The transfer goes on — the import is additive, like a blob the encoder skipped as too large.
//! This sits above the CTH1 reader, not in it: the format, and the vectors that pin it, do not
//! change.

use std::collections::HashSet;

use super::cth1::Event;
use super::record_type;
use super::records::{MessageRecord, media_refs};

/// Why a blob was not let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaRefusal {
    /// The id is not a dashed UUID.
    BadId,
    /// No message of the transcript names this id.
    NotReferenced,
}

/// What the gate hands on: a reader event, or the refusal that replaced a whole blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gated {
    Event(Event),
    Refused(MediaRefusal),
}

/// A server media id as the server issues it: `8-4-4-4-12` hex digits with dashes. Either case —
/// the id is compared with the body's byte for byte, never normalised.
pub fn is_media_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The receiver's media rules over one transfer's events, in stream order.
#[derive(Debug, Default)]
pub struct MediaGate {
    referenced: HashSet<String>,
    /// Inside a refused blob: its bytes and end are swallowed.
    dropping: bool,
}

impl MediaGate {
    /// Media ids the messages this device already holds refer to (phase 2: the transcript came in
    /// an earlier transfer).
    pub fn expect(&mut self, ids: impl IntoIterator<Item = String>) {
        self.referenced
            .extend(ids.into_iter().filter(|id| is_media_id(id)));
    }

    /// Whether a blob named `media_id` may be written now.
    pub fn admit(&self, media_id: &str) -> Result<(), MediaRefusal> {
        if !is_media_id(media_id) {
            return Err(MediaRefusal::BadId);
        }
        if !self.referenced.contains(media_id) {
            return Err(MediaRefusal::NotReferenced);
        }
        Ok(())
    }

    /// A message record adds the media its body names. Other records, and a message that does
    /// not decode (the reader already let it through; the platform's import refuses it), add
    /// nothing.
    fn note(&mut self, record_type: u8, proto: &[u8]) {
        if record_type != record_type::MESSAGE {
            return;
        }
        let Ok(message) = MessageRecord::decode(proto) else {
            return;
        };
        if let Some(body) = &message.body {
            self.referenced.extend(
                media_refs(body)
                    .into_iter()
                    .map(|r| r.id)
                    .filter(|id| is_media_id(id)),
            );
        }
    }

    /// Pass `events` through the rules: records are noted and passed on; a blob that is let
    /// through passes whole; a refused one becomes a single [`Gated::Refused`].
    pub fn filter(&mut self, events: Vec<Event>) -> Vec<Gated> {
        let mut out = Vec::with_capacity(events.len());
        for event in events {
            match event {
                Event::Record {
                    record_type,
                    ref proto,
                } => {
                    self.note(record_type, proto);
                    out.push(Gated::Event(event));
                }
                Event::MediaStart { ref media_id, .. } => match self.admit(media_id) {
                    Ok(()) => {
                        self.dropping = false;
                        out.push(Gated::Event(event));
                    }
                    Err(reason) => {
                        self.dropping = true;
                        out.push(Gated::Refused(reason));
                    }
                },
                Event::MediaBytes(_) if self.dropping => {}
                Event::MediaEnd if self.dropping => self.dropping = false,
                other => out.push(Gated::Event(other)),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::records::Writer;

    const ID: &str = "0b5c2f1e-8d3a-4c6b-9e7f-1a2b3c4d5e6f";
    const OTHER: &str = "9f8e7d6c-5b4a-4321-8fed-cba987654321";

    /// A Message record whose `MessageContent` carries one `MediaMessage` with `id`.
    fn message_with_media(id: &str) -> Vec<u8> {
        let mut media = Writer::default();
        media.bytes(13, id.as_bytes());
        media.bytes(6, b"image/jpeg");
        let mut content = Writer::default();
        content.always_bytes(2, &media.out);
        let mut record = Writer::default();
        record.bytes(1, b"6f1c0a4e-2b3d-4e5f-8a9b-0c1d2e3f4a5b");
        record.always_bytes(6, &content.out);
        record.out
    }

    fn record(id: &str) -> Event {
        Event::Record {
            record_type: record_type::MESSAGE,
            proto: message_with_media(id),
        }
    }

    fn blob(id: &str, bytes: &[u8]) -> Vec<Event> {
        let mut v = vec![Event::MediaStart {
            media_id: id.to_owned(),
            mime_type: "image/jpeg".to_owned(),
            byte_len: bytes.len() as u64,
        }];
        if !bytes.is_empty() {
            v.push(Event::MediaBytes(bytes.to_vec()));
        }
        v.push(Event::MediaEnd);
        v
    }

    fn passed(out: &[Gated]) -> Vec<&Event> {
        out.iter()
            .filter_map(|g| match g {
                Gated::Event(e) => Some(e),
                Gated::Refused(_) => None,
            })
            .collect()
    }

    fn refused(out: &[Gated]) -> Vec<MediaRefusal> {
        out.iter()
            .filter_map(|g| match g {
                Gated::Refused(r) => Some(*r),
                Gated::Event(_) => None,
            })
            .collect()
    }

    #[test]
    fn a_media_id_is_a_dashed_uuid_in_either_case() {
        assert!(is_media_id(ID));
        assert!(is_media_id(&ID.to_uppercase()));
        for bad in [
            "",
            "..",
            ".",
            "media-split",
            "0b5c2f1e8d3a4c6b9e7f1a2b3c4d5e6f",      // undashed
            "0b5c2f1e-8d3a-4c6b-9e7f-1a2b3c4d5e6",   // 35
            "0b5c2f1e-8d3a-4c6b-9e7f-1a2b3c4d5e6f0", // 37
            "0b5c2f1e-8d3a-4c6b-9e7f-1a2b3c4d5e/f",  // a path
            "0b5c2f1e_8d3a-4c6b-9e7f-1a2b3c4d5e6f",  // dash replaced
            "0b5c2f1e-8d3a-4c6b-9e7f-1a2b3c4d5e6g",  // not hex
            "../../5c2f1e-8d3a-4c6b-9e7f-1a2b3c4d5e",
        ] {
            assert!(!is_media_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_blob_a_message_of_the_stream_names_passes_whole() {
        let mut gate = MediaGate::default();
        let mut events = vec![record(ID)];
        events.extend(blob(ID, b"jpeg bytes"));
        events.push(Event::End);
        let out = gate.filter(events.clone());
        assert_eq!(passed(&out), events.iter().collect::<Vec<_>>());
        assert!(refused(&out).is_empty());
    }

    #[test]
    fn a_blob_nobody_names_is_dropped_bytes_and_all() {
        let mut gate = MediaGate::default();
        let mut events = vec![record(ID)];
        events.extend(blob(OTHER, b"planted"));
        events.extend(blob(ID, b"wanted"));
        let out = gate.filter(events);
        assert_eq!(refused(&out), [MediaRefusal::NotReferenced]);
        let bytes: Vec<&[u8]> = passed(&out)
            .into_iter()
            .filter_map(|e| match e {
                Event::MediaBytes(b) => Some(b.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(
            bytes,
            [b"wanted".as_slice()],
            "the planted bytes never pass"
        );
        // The blob after the refused one is whole: one start, one end.
        let starts = passed(&out)
            .iter()
            .filter(|e| matches!(e, Event::MediaStart { .. }))
            .count();
        let ends = passed(&out)
            .iter()
            .filter(|e| matches!(e, Event::MediaEnd))
            .count();
        assert_eq!((starts, ends), (1, 1));
    }

    #[test]
    fn a_bad_id_is_refused_even_when_a_message_names_it() {
        let mut gate = MediaGate::default();
        let mut events = vec![record("..")];
        events.extend(blob("..", b"x"));
        let out = gate.filter(events);
        assert_eq!(refused(&out), [MediaRefusal::BadId]);
        assert!(
            !passed(&out)
                .iter()
                .any(|e| matches!(e, Event::MediaStart { .. } | Event::MediaBytes(_)))
        );
    }

    #[test]
    fn phase_two_takes_the_ids_the_device_already_holds() {
        let mut gate = MediaGate::default();
        let out = gate.filter(blob(ID, b"x"));
        assert_eq!(
            refused(&out),
            [MediaRefusal::NotReferenced],
            "nothing expected yet"
        );

        let mut gate = MediaGate::default();
        gate.expect([ID.to_owned(), "..".to_owned()]);
        assert_eq!(refused(&gate.filter(blob(ID, b"x"))), []);
        assert_eq!(
            gate.admit(".."),
            Err(MediaRefusal::BadId),
            "an expected bad id stays bad"
        );
    }

    #[test]
    fn an_empty_refused_blob_leaves_no_end_behind() {
        let mut gate = MediaGate::default();
        let mut events = blob(OTHER, b"");
        events.push(Event::End);
        let out = gate.filter(events);
        assert_eq!(
            out,
            [
                Gated::Refused(MediaRefusal::NotReferenced),
                Gated::Event(Event::End)
            ]
        );
    }

    #[test]
    fn a_refused_blob_split_across_feeds_stays_dropped() {
        let mut gate = MediaGate::default();
        let first = gate.filter(vec![
            Event::MediaStart {
                media_id: OTHER.to_owned(),
                mime_type: "image/jpeg".to_owned(),
                byte_len: 4,
            },
            Event::MediaBytes(b"ab".to_vec()),
        ]);
        assert_eq!(first, [Gated::Refused(MediaRefusal::NotReferenced)]);
        let second = gate.filter(vec![
            Event::MediaBytes(b"cd".to_vec()),
            Event::MediaEnd,
            Event::End,
        ]);
        assert_eq!(second, [Gated::Event(Event::End)]);
    }

    #[test]
    fn a_reference_from_an_album_or_a_voice_note_counts() {
        // The same extraction the encoder lists media with (`records::media_refs`).
        let mut album_item = Writer::default();
        album_item.bytes(13, ID.as_bytes());
        let mut album = Writer::default();
        album.always_bytes(1, &album_item.out);
        let mut rec = Writer::default();
        rec.always_bytes(15, &album.out);
        let mut voice = Writer::default();
        voice.bytes(6, format!("audio/m4a|{OTHER}").as_bytes());
        let mut content = Writer::default();
        content.always_bytes(6, &voice.out);
        let mut rec2 = Writer::default();
        rec2.always_bytes(6, &content.out);

        let mut gate = MediaGate::default();
        let mut events = vec![
            Event::Record {
                record_type: record_type::MESSAGE,
                proto: rec.out,
            },
            Event::Record {
                record_type: record_type::MESSAGE,
                proto: rec2.out,
            },
        ];
        events.extend(blob(ID, b"a"));
        events.extend(blob(OTHER, b"b"));
        assert!(refused(&gate.filter(events)).is_empty());
    }

    #[test]
    fn only_a_message_record_adds_references() {
        let mut gate = MediaGate::default();
        let out = gate.filter(vec![Event::Record {
            record_type: record_type::CONTACT,
            proto: message_with_media(ID),
        }]);
        assert_eq!(out.len(), 1);
        assert_eq!(gate.admit(ID), Err(MediaRefusal::NotReferenced));
    }
}
