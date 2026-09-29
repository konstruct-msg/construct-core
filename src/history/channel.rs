//! The channel key and the sealed chunk layer every CTH1 stream travels in.
//!
//! ```text
//! key   = HKDF-SHA256(ikm = ecdh ‖ kem_ss, salt, info = snapshot_id)      32 bytes
//!         salt "construct_transfer_v2" (nearby) | "construct_history_file_v1" (file)
//! chunk = [4] sealed_len LE  [12] nonce  [≤ 65536] ChaCha20-Poly1305(plaintext)  [16] tag
//!         nonce = chunk index LE ‖ 8 zero bytes; AAD = snapshot_id ‖ user_id ‖ index LE
//! EOF   = [4] 0x00000000
//! ```
//!
//! The AAD is on every chunk, not only the first, so a chunk spliced from another stream or moved
//! within this one does not open. Chunks are sealed in place: the plaintext is written once into
//! the output buffer and encrypted there.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::HistoryFailure;

/// Plaintext per chunk. The sender fills each chunk to this before sealing it.
pub const CHUNK_PLAINTEXT: usize = 65_536;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The most a sealed chunk may claim; checked before a byte of it is read.
pub const MAX_SEALED_CHUNK: usize = CHUNK_PLAINTEXT + NONCE_LEN + TAG_LEN;
pub const LEN_PREFIX: usize = 4;
pub const EOF: [u8; 4] = [0; 4];

/// Which envelope the key is for. The salts keep a nearby key and a file key for the same inputs
/// apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Salt {
    Nearby,
    File,
}

impl Salt {
    fn bytes(self) -> &'static [u8] {
        match self {
            Salt::Nearby => b"construct_transfer_v2",
            Salt::File => b"construct_history_file_v1",
        }
    }
}

pub fn channel_key(
    ecdh: &[u8],
    kem_shared_secret: &[u8],
    salt: Salt,
    snapshot_id: &[u8; 16],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(ecdh.len() + kem_shared_secret.len()));
    ikm.extend_from_slice(ecdh);
    ikm.extend_from_slice(kem_shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt.bytes()), &ikm)
        .expand(snapshot_id, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    key
}

fn aad(snapshot_id: &[u8; 16], user_id: &[u8; 16], index: u32) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..16].copy_from_slice(snapshot_id);
    out[16..32].copy_from_slice(user_id);
    out[32..].copy_from_slice(&index.to_le_bytes());
    out
}

fn nonce(index: u32) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out[..4].copy_from_slice(&index.to_le_bytes());
    out
}

/// One direction of one stream: seals or opens chunks in order.
pub struct ChunkCipher {
    cipher: ChaCha20Poly1305,
    snapshot_id: [u8; 16],
    user_id: [u8; 16],
    index: u32,
}

impl ChunkCipher {
    pub fn new(key: &[u8; 32], snapshot_id: [u8; 16], user_id: [u8; 16]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            snapshot_id,
            user_id,
            index: 0,
        }
    }

    /// Seal `plaintext` as the next chunk and append it, length prefix included, to `out`.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), HistoryFailure> {
        if plaintext.is_empty() || plaintext.len() > CHUNK_PLAINTEXT {
            return Err(HistoryFailure::Malformed);
        }
        let index = self.next_index()?;
        let sealed_len = (NONCE_LEN + plaintext.len() + TAG_LEN) as u32;
        out.reserve(LEN_PREFIX + sealed_len as usize);
        out.extend_from_slice(&sealed_len.to_le_bytes());
        let nonce = nonce(index);
        out.extend_from_slice(&nonce);
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad(&self.snapshot_id, &self.user_id, index),
                &mut out[start..],
            )
            .map_err(|_| HistoryFailure::Malformed)?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Open the next chunk — `sealed` is what followed its length prefix — in place. The nonce must
    /// be the one its index gives: every writer derives it, so any other is a moved chunk.
    pub fn open(&mut self, mut sealed: Vec<u8>) -> Result<Vec<u8>, HistoryFailure> {
        if sealed.len() < NONCE_LEN + TAG_LEN + 1 || sealed.len() > MAX_SEALED_CHUNK {
            return Err(HistoryFailure::Malformed);
        }
        let index = self.next_index()?;
        let expected = nonce(index);
        if sealed[..NONCE_LEN] != expected {
            return Err(HistoryFailure::ChunkOpenFailed);
        }
        let tag_at = sealed.len() - TAG_LEN;
        let tag = Tag::clone_from_slice(&sealed[tag_at..]);
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&expected),
                &aad(&self.snapshot_id, &self.user_id, index),
                &mut sealed[NONCE_LEN..tag_at],
                &tag,
            )
            .map_err(|_| HistoryFailure::ChunkOpenFailed)?;
        sealed.truncate(tag_at);
        sealed.drain(..NONCE_LEN);
        Ok(sealed)
    }

    fn next_index(&mut self) -> Result<u32, HistoryFailure> {
        let index = self.index;
        // 2^32 chunks of 64 KiB is 256 TiB; a stream that long is not a snapshot.
        self.index = index.checked_add(1).ok_or(HistoryFailure::Malformed)?;
        Ok(index)
    }
}

/// The length a chunk's 4-byte prefix announces: `Ok(None)` for EOF, an error for a length no
/// writer produces — checked before any of the chunk is read.
pub fn sealed_len(prefix: [u8; 4]) -> Result<Option<usize>, HistoryFailure> {
    let len = u32::from_le_bytes(prefix) as usize;
    if len == 0 {
        return Ok(None);
    }
    if !(NONCE_LEN + TAG_LEN + 1..=MAX_SEALED_CHUNK).contains(&len) {
        return Err(HistoryFailure::Malformed);
    }
    Ok(Some(len))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "post-quantum")]
    use crate::history::vectors;

    const SNAPSHOT: [u8; 16] = [0xaa; 16];
    const USER: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];

    /// The file key from the vector's own inputs (receiver identity secret × sender ephemeral,
    /// and the Kyber decapsulation), and chunk 0 opening under it to the vector's plaintext.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn the_file_channel_key_and_chunk_zero_are_the_vectors() {
        #[allow(deprecated)]
        use ml_kem::{Decapsulate, ExpandedKeyEncoding, MlKem1024};

        let v = vectors::named("cthf_header");
        let keys = vectors::keys();
        let header = vectors::hex_field(&v, "hex");
        // sender_eph at 69..101, kem_ct at 2121..2121+1568 (spec §6, CTHF layout).
        let sender_eph: [u8; 32] = header[69..101].try_into().unwrap();
        let kem_ct = &header[2121..2121 + 1568];

        let receiver: [u8; 32] = vectors::hex_field(&keys, "receiver_identity_secret")
            .try_into()
            .unwrap();
        let ecdh = x25519_dalek::StaticSecret::from(receiver)
            .diffie_hellman(&x25519_dalek::PublicKey::from(sender_eph));
        let expanded = vectors::hex_field(&keys, "kyber_secret");
        #[allow(deprecated)]
        let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_expanded_bytes(
            expanded.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let kem_ss = dk.decapsulate_slice(kem_ct).unwrap();

        let key = channel_key(ecdh.as_bytes(), &kem_ss, Salt::File, &SNAPSHOT);
        assert_eq!(hex::encode(*key), v["file_channel_key"].as_str().unwrap());
        assert_eq!(
            hex::encode(aad(&SNAPSHOT, &USER, 0)),
            v["aad"].as_str().unwrap()
        );

        let mut cipher = ChunkCipher::new(&key, SNAPSHOT, USER);
        let opened = cipher
            .open(vectors::hex_field(&v, "chunk0_combined"))
            .unwrap();
        assert_eq!(opened, vectors::hex_field(&v, "chunk0_plaintext"));

        // And the sealing side writes the same bytes.
        let mut out = Vec::new();
        ChunkCipher::new(&key, SNAPSHOT, USER)
            .seal(&vectors::hex_field(&v, "chunk0_plaintext"), &mut out)
            .unwrap();
        assert_eq!(
            out[LEN_PREFIX..],
            vectors::hex_field(&v, "chunk0_combined")[..]
        );
    }

    #[test]
    fn a_chunk_opens_only_in_its_place_in_its_stream() {
        let key = [9u8; 32];
        let mut sealer = ChunkCipher::new(&key, SNAPSHOT, USER);
        let mut stream = Vec::new();
        sealer.seal(b"first", &mut stream).unwrap();
        let first_end = stream.len();
        sealer.seal(b"second", &mut stream).unwrap();
        let first = stream[LEN_PREFIX..first_end].to_vec();
        let second = stream[first_end + LEN_PREFIX..].to_vec();

        // In order: opens.
        let mut opener = ChunkCipher::new(&key, SNAPSHOT, USER);
        assert_eq!(opener.open(first.clone()).unwrap(), b"first");
        assert_eq!(opener.open(second.clone()).unwrap(), b"second");

        // Swapped: the second chunk at index 0 fails.
        let mut opener = ChunkCipher::new(&key, SNAPSHOT, USER);
        assert_eq!(
            opener.open(second.clone()),
            Err(HistoryFailure::ChunkOpenFailed)
        );

        // Its index's nonce but another index's AAD: rewrite the nonce and it still fails.
        let mut moved = second.clone();
        moved[..4].copy_from_slice(&0u32.to_le_bytes());
        let mut opener = ChunkCipher::new(&key, SNAPSHOT, USER);
        assert_eq!(opener.open(moved), Err(HistoryFailure::ChunkOpenFailed));

        // Another snapshot or account: fails.
        let mut opener = ChunkCipher::new(&key, [0xbb; 16], USER);
        assert_eq!(
            opener.open(first.clone()),
            Err(HistoryFailure::ChunkOpenFailed)
        );
        let mut opener = ChunkCipher::new(&key, SNAPSHOT, [0x02; 16]);
        assert_eq!(opener.open(first), Err(HistoryFailure::ChunkOpenFailed));
    }

    #[test]
    fn a_chunk_length_no_writer_produces_is_refused_before_it_is_read() {
        assert_eq!(sealed_len(EOF), Ok(None));
        assert_eq!(sealed_len(29u32.to_le_bytes()), Ok(Some(29)));
        assert_eq!(
            sealed_len((MAX_SEALED_CHUNK as u32).to_le_bytes()),
            Ok(Some(MAX_SEALED_CHUNK))
        );
        assert_eq!(
            sealed_len(28u32.to_le_bytes()),
            Err(HistoryFailure::Malformed)
        );
        assert_eq!(
            sealed_len((MAX_SEALED_CHUNK as u32 + 1).to_le_bytes()),
            Err(HistoryFailure::Malformed)
        );
    }

    #[test]
    fn the_salts_keep_nearby_and_file_keys_apart() {
        let a = channel_key(&[1; 32], &[2; 32], Salt::Nearby, &SNAPSHOT);
        let b = channel_key(&[1; 32], &[2; 32], Salt::File, &SNAPSHOT);
        assert_ne!(*a, *b);
    }
}
