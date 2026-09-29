//! Just enough of the protobuf wire format to judge a record, never to decode one into a struct.
//!
//! The platform decodes transcript records with its own generated code, straight into its store.
//! The core needs four things from them: the manifest's version, phase and ids; whether a message
//! carries a body; the header of a media blob; and that a record is well-formed protobuf at all,
//! so garbage is refused the same way on every platform. A generated decoder for all of that would
//! be a second copy of the schema in this crate; this reads fields by number.

use super::HistoryFailure;

/// One field as it appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    Varint(u64),
    Fixed64,
    Bytes(&'a [u8]),
    Fixed32,
}

/// A varint at `buf[*pos..]`, advancing `pos`. `None` when the buffer ends first; an error for a
/// varint longer than ten bytes.
pub(crate) fn read_varint(buf: &[u8], pos: &mut usize) -> Result<Option<u64>, HistoryFailure> {
    let mut value = 0u64;
    for i in 0..10 {
        let Some(&byte) = buf.get(*pos + i) else {
            return Ok(None);
        };
        if i == 9 && byte > 1 {
            return Err(HistoryFailure::Malformed);
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            *pos += i + 1;
            return Ok(Some(value));
        }
    }
    Err(HistoryFailure::Malformed)
}

/// The fields of a complete message, in wire order.
pub(crate) fn fields(buf: &[u8]) -> Fields<'_> {
    Fields { buf, pos: 0 }
}

pub(crate) struct Fields<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<(u32, Value<'a>), HistoryFailure>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        Some(self.field())
    }
}

impl<'a> Fields<'a> {
    fn field(&mut self) -> Result<(u32, Value<'a>), HistoryFailure> {
        let key = read_varint(self.buf, &mut self.pos)?.ok_or(HistoryFailure::Malformed)?;
        let number = u32::try_from(key >> 3).map_err(|_| HistoryFailure::Malformed)?;
        if number == 0 {
            return Err(HistoryFailure::Malformed);
        }
        let value = match key & 7 {
            0 => Value::Varint(
                read_varint(self.buf, &mut self.pos)?.ok_or(HistoryFailure::Malformed)?,
            ),
            1 => {
                self.skip(8)?;
                Value::Fixed64
            }
            2 => {
                let len = read_varint(self.buf, &mut self.pos)?.ok_or(HistoryFailure::Malformed)?;
                let len = usize::try_from(len).map_err(|_| HistoryFailure::Malformed)?;
                let start = self.pos;
                self.skip(len)?;
                Value::Bytes(&self.buf[start..self.pos])
            }
            5 => {
                self.skip(4)?;
                Value::Fixed32
            }
            // Groups (3, 4) are proto2 and absent from every schema here; 6 and 7 do not exist.
            _ => return Err(HistoryFailure::Malformed),
        };
        Ok((number, value))
    }

    fn skip(&mut self, n: usize) -> Result<(), HistoryFailure> {
        let end = self.pos.checked_add(n).ok_or(HistoryFailure::Malformed)?;
        if end > self.buf.len() {
            return Err(HistoryFailure::Malformed);
        }
        self.pos = end;
        Ok(())
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

/// A key byte: field number and wire type. Every tag this module writes is one byte.
pub(crate) const fn tag(number: u8, wire_type: u8) -> u8 {
    (number << 3) | wire_type
}

pub(crate) fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
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
        assert_eq!(
            read_varint(&[0xff; 11], &mut 0),
            Err(HistoryFailure::Malformed)
        );
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
}
