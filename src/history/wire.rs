//! Just enough of the protobuf wire format to judge a record, never to decode one into a struct.
//!
//! The platform decodes transcript records with its own generated code, straight into its store.
//! The core needs four things from them: the manifest's version, phase and ids; whether a message
//! carries a body; the header of a media blob; and that a record is well-formed protobuf at all,
//! so garbage is refused the same way on every platform. A generated decoder for all of that would
//! be a second copy of the schema in this crate; this reads fields by number.

use super::HistoryFailure;
use crate::protobuf_wire::Malformed;
pub(crate) use crate::protobuf_wire::{Value, fields, read_varint, tag, write_varint};

impl From<Malformed> for HistoryFailure {
    fn from(_: Malformed) -> Self {
        Self::Malformed
    }
}

/// Whether `buf` is a well-formed protobuf message at the top level. Nested messages are the
/// platform decoder's to judge; it decodes them anyway.
pub(crate) fn well_formed(buf: &[u8]) -> Result<(), HistoryFailure> {
    for field in fields(buf) {
        field?;
    }
    Ok(())
}

/// The manifest fields the protocol rules read. Proto3: a field that appears twice takes the last
/// value, and an absent one is its zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ManifestFields {
    pub format_version: u64,
    pub snapshot_id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub phase: u64,
}

pub(crate) fn manifest(buf: &[u8]) -> Result<ManifestFields, HistoryFailure> {
    let mut m = ManifestFields::default();
    for field in fields(buf) {
        match field? {
            (1, Value::Varint(v)) => m.format_version = v,
            (2, Value::Bytes(b)) => m.snapshot_id = b.to_vec(),
            (3, Value::Bytes(b)) => m.user_id = b.to_vec(),
            (13, Value::Varint(v)) => m.phase = v,
            // A known number with the wrong wire type is not this schema.
            (1 | 2 | 3 | 13, _) => return Err(HistoryFailure::Malformed),
            _ => {}
        }
    }
    Ok(m)
}

/// What a message record's body says about how to treat the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Body {
    /// One of the three bodies this version knows (`message_content`, `media_album`,
    /// `profile_share`).
    Known,
    /// No known body, and a field this version does not know: a future body case. Skipped, like
    /// an unknown record type.
    Unknown,
    /// No body at all. Malformed — a message is its body.
    Unset,
}

/// Field numbers of `HistoryMessage` v1: 1–16, of which 6, 15 and 16 are the body oneof.
const MESSAGE_FIELDS: std::ops::RangeInclusive<u32> = 1..=16;
const BODY_FIELDS: [u32; 3] = [6, 15, 16];

pub(crate) fn message_body(buf: &[u8]) -> Result<Body, HistoryFailure> {
    let mut known = false;
    let mut unknown = false;
    for field in fields(buf) {
        let (number, value) = field?;
        if BODY_FIELDS.contains(&number) {
            if !matches!(value, Value::Bytes(_)) {
                return Err(HistoryFailure::Malformed);
            }
            known = true;
        } else if !MESSAGE_FIELDS.contains(&number) {
            unknown = true;
        }
    }
    Ok(match (known, unknown) {
        (true, _) => Body::Known,
        (false, true) => Body::Unknown,
        (false, false) => Body::Unset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_varint_round_trips() {
        for v in [
            0u64,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let mut out = Vec::new();
            write_varint(v, &mut out);
            let mut pos = 0;
            assert_eq!(read_varint(&out, &mut pos).unwrap(), Some(v));
            assert_eq!(pos, out.len());
        }
    }

    #[test]
    fn hostile_varints_and_lengths_are_malformed_not_panics() {
        // Eleven continuation bytes.
        assert_eq!(read_varint(&[0xff; 11], &mut 0), Err(Malformed));
        // A length-delimited field claiming more than the buffer holds.
        assert_eq!(
            well_formed(&[tag(2, 2), 0x05, 1, 2]),
            Err(HistoryFailure::Malformed)
        );
        // Field number 0, and a group wire type.
        assert_eq!(well_formed(&[0x02, 0x00]), Err(HistoryFailure::Malformed));
        assert_eq!(well_formed(&[tag(1, 3)]), Err(HistoryFailure::Malformed));
        // A truncated key.
        assert_eq!(well_formed(&[0x80]), Err(HistoryFailure::Malformed));
    }

    #[test]
    fn a_message_body_is_known_unknown_or_unset() {
        let mut known = vec![tag(1, 2), 1, b'a', tag(6, 2), 0];
        assert_eq!(message_body(&known).unwrap(), Body::Known);
        known.extend_from_slice(&[tag(15, 2), 0]);
        assert_eq!(message_body(&known).unwrap(), Body::Known);

        // Field 17: a body case from a later version.
        let future = [tag(1, 2), 1, b'a', 0x8a, 0x01, 0];
        assert_eq!(message_body(&future).unwrap(), Body::Unknown);

        let unset = [tag(1, 2), 1, b'a', tag(5, 0), 1];
        assert_eq!(message_body(&unset).unwrap(), Body::Unset);
        // A body field with a varint wire type is not this schema.
        assert_eq!(
            message_body(&[tag(6, 0), 1]),
            Err(HistoryFailure::Malformed)
        );
    }

    // ── Mutation audit, tier 2 (TODO 302) ────────────────────────────────────

    /// The tenth byte of a varint carries one bit: 0 and 1 read, 2 does not. Mutation:
    /// `byte > 1` → `byte < 1`.
    #[test]
    fn the_tenth_varint_byte_carries_one_bit() {
        let mut zero = vec![0x80; 9];
        zero.push(0x00);
        assert_eq!(read_varint(&zero, &mut 0), Ok(Some(0)));
        let mut two = vec![0xff; 9];
        two.push(0x02);
        assert_eq!(read_varint(&two, &mut 0), Err(Malformed));
    }

    /// Fixed-width fields are stepped over by their width and the next field still reads.
    /// Mutation: the `1` or `5` arm of `Fields::field` deleted — they are refused.
    #[test]
    fn fixed_width_fields_are_stepped_over() {
        let mut buf = vec![tag(1, 1)];
        buf.extend_from_slice(&[9; 8]);
        buf.push(tag(2, 5));
        buf.extend_from_slice(&[9; 4]);
        buf.extend_from_slice(&[tag(3, 0), 5]);
        let read: Vec<_> = fields(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(
            read,
            [
                (1, Value::Fixed64),
                (2, Value::Fixed32),
                (3, Value::Varint(5))
            ]
        );
    }

    /// Mutation: the wrong-wire-type arm of `manifest` deleted — a snapshot id sent as a varint
    /// reads as no snapshot id.
    #[test]
    fn a_manifest_field_of_the_wrong_wire_type_is_malformed() {
        assert_eq!(
            manifest(&[tag(1, 0), 1, tag(2, 0), 7]),
            Err(HistoryFailure::Malformed)
        );
    }
}
