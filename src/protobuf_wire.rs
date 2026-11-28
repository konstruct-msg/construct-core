//! Schema-independent protobuf field scanning and varint encoding.

/// Bytes that do not form a valid field in the supported protobuf wire types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed")]
pub(crate) struct Malformed;

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
pub(crate) fn read_varint(buf: &[u8], pos: &mut usize) -> Result<Option<u64>, Malformed> {
    let mut value = 0u64;
    for i in 0..10 {
        let Some(&byte) = buf.get(*pos + i) else {
            return Ok(None);
        };
        if i == 9 && byte > 1 {
            return Err(Malformed);
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            *pos += i + 1;
            return Ok(Some(value));
        }
    }
    Err(Malformed)
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
    type Item = Result<(u32, Value<'a>), Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        Some(self.field())
    }
}

impl<'a> Fields<'a> {
    fn field(&mut self) -> Result<(u32, Value<'a>), Malformed> {
        let key = read_varint(self.buf, &mut self.pos)?.ok_or(Malformed)?;
        let number = u32::try_from(key >> 3).map_err(|_| Malformed)?;
        if number == 0 {
            return Err(Malformed);
        }
        let value = match key & 7 {
            0 => Value::Varint(read_varint(self.buf, &mut self.pos)?.ok_or(Malformed)?),
            1 => {
                self.skip(8)?;
                Value::Fixed64
            }
            2 => {
                let len = read_varint(self.buf, &mut self.pos)?.ok_or(Malformed)?;
                let len = usize::try_from(len).map_err(|_| Malformed)?;
                let start = self.pos;
                self.skip(len)?;
                Value::Bytes(&self.buf[start..self.pos])
            }
            5 => {
                self.skip(4)?;
                Value::Fixed32
            }
            // Groups (3, 4) are proto2 and absent from every schema here; 6 and 7 do not exist.
            _ => return Err(Malformed),
        };
        Ok((number, value))
    }

    fn skip(&mut self, n: usize) -> Result<(), Malformed> {
        let end = self.pos.checked_add(n).ok_or(Malformed)?;
        if end > self.buf.len() {
            return Err(Malformed);
        }
        self.pos = end;
        Ok(())
    }
}

/// A single-byte protobuf tag for small field numbers and their wire types.
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
