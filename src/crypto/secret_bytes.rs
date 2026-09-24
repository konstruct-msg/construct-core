//! Bytes that are a secret: wiped when dropped, never printed.
//!
//! Private keys, shared secrets and ratchet keys travelled as `Vec<u8>` / `ByteBuf`. Neither is
//! zeroed on drop, and both derive `Debug` into whatever holds them — so the persisted key
//! record, a pending PQ contribution or an ML-KEM keypair printed its secret the first time
//! anything formatted it with `{:?}` (an `assert_eq!` failure, an error context, a log field).
//!
//! `SecretBytes` is the one type for that:
//! - `Drop` zeroes the buffer (`ZeroizeOnDrop`); `Clone` makes a second buffer that is zeroed on
//!   its own drop.
//! - `Debug` prints the length only.
//! - serde reads and writes it exactly as `serde_bytes::ByteBuf` does, so a CFE field changed from
//!   `ByteBuf` to `SecretBytes` is the same bytes on disk.
//!
//! What it does not do: stop copies the program makes on purpose. `expose()` / `as_ref()` hand
//! out the bytes; a `.to_vec()` of them is an ordinary `Vec` again. And a `Vec` that grew by
//! reallocation may have left an earlier copy behind — build secrets at their final size.
//!
//! `PartialEq` is ordinary, not constant-time: it is there for tests and state comparison, never
//! for checking a MAC or a token.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// The bytes, for the one operation that needs them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Hand the buffer to a caller that takes a plain `Vec` (an FFI record, a legacy API).
    /// From here on it is not wiped on drop — keep that hand-off at the boundary.
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_bytes::ByteBuf::deserialize(deserializer).map(|b| Self(b.into_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_the_length_not_the_bytes() {
        let s = SecretBytes::new(vec![0xAB; 32]);
        let printed = format!("{s:?}");
        assert_eq!(printed, "SecretBytes(<32 bytes redacted>)");
        assert!(
            !printed.contains("171"),
            "171 = 0xAB as a decimal Debug element"
        );
    }

    /// A field moved from `ByteBuf` to `SecretBytes` must read what the old field wrote, and
    /// write what the old field read — in both encodings the crate persists with.
    #[test]
    fn serde_is_byte_identical_to_bytebuf() {
        let raw = vec![1u8, 2, 3, 250];
        let old = serde_bytes::ByteBuf::from(raw.clone());
        let new = SecretBytes::new(raw.clone());

        let old_mp = rmp_serde::to_vec_named(&old).unwrap();
        assert_eq!(rmp_serde::to_vec_named(&new).unwrap(), old_mp);
        let back: SecretBytes = rmp_serde::from_slice(&old_mp).unwrap();
        assert_eq!(back.expose(), &raw[..]);

        let old_pc = postcard::to_allocvec(&old).unwrap();
        assert_eq!(postcard::to_allocvec(&new).unwrap(), old_pc);
        let back: SecretBytes = postcard::from_bytes(&old_pc).unwrap();
        assert_eq!(back.expose(), &raw[..]);
    }

    #[test]
    fn into_vec_hands_over_the_bytes() {
        assert_eq!(SecretBytes::new(vec![9, 8, 7]).into_vec(), vec![9, 8, 7]);
    }
}
