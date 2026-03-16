//! Frame encoder: wraps plaintext payload into obfs4 wire frames.
//!
//! ## Wire format per frame (obfs4 spec §5)
//! ```text
//! [obfuscated_len: 2 bytes][NaCl secretbox(Type[1] || PayloadLen[2] || Payload || Padding)]
//! ```
//! The secretbox includes a 16-byte Poly1305 tag prepended by NaCl convention.
//! The 2-byte length field is obfuscated via SipHash-2-4 OFB XOR mask.

use bytes::{BufMut, BytesMut};
use crypto_secretbox::{
    KeyInit, XSalsa20Poly1305,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use rand::{Rng, RngCore};

use super::{
    FRAME_HEADER_LEN, MAX_FRAME_LENGTH, MAX_FRAME_PAYLOAD, PacketType, SECRETBOX_NONCE_LEN,
    SECRETBOX_TAG_LEN, length_dist::LengthObfuscator,
};
use crate::{Error, Result};

/// Controls how much random padding is appended to each data frame.
///
/// Padding breaks the correlation between application payload size and
/// wire frame size, making traffic analysis significantly harder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaddingStrategy {
    /// No padding — frame size = payload + overhead. Matches obfs4 spec default.
    #[default]
    None,
    /// Pad each frame to the maximum frame size (1448B secretbox).
    /// Maximum obfuscation: all frames are the same size on the wire.
    PadToMax,
    /// Add a random amount of padding uniformly chosen from `[0, max_pad]` bytes.
    /// `max_pad` is clamped so the total frame never exceeds MAX_FRAME_LENGTH.
    Random {
        /// Maximum padding bytes to add (uniformly chosen from `[0, max_pad]`).
        max_pad: usize,
    },
}

/// Encodes plaintext application data into obfs4 frames.
pub struct FrameEncoder {
    cipher: XSalsa20Poly1305,
    nonce_prefix: [u8; 16],
    nonce_counter: u64,
    length_obf: LengthObfuscator,
    padding: PaddingStrategy,
}

impl FrameEncoder {
    /// Create a new encoder with session key material.
    ///
    /// # Arguments
    /// * `key` — 32-byte NaCl secretbox key (from KDF)
    /// * `nonce_prefix` — 16-byte nonce prefix (from KDF)
    /// * `siphash_key` — 16-byte SipHash key (from KDF)
    /// * `siphash_iv` — 8-byte SipHash OFB IV (from KDF)
    pub fn new(
        key: &[u8; 32],
        nonce_prefix: &[u8; 16],
        siphash_key: &[u8; 16],
        siphash_iv: &[u8; 8],
    ) -> Self {
        FrameEncoder {
            cipher: XSalsa20Poly1305::new(GenericArray::from_slice(key)),
            nonce_prefix: *nonce_prefix,
            nonce_counter: 1, // starts at 1 per spec
            length_obf: LengthObfuscator::new(siphash_key, siphash_iv),
            padding: PaddingStrategy::None,
        }
    }

    /// Set the padding strategy for data frames.
    pub fn with_padding(mut self, strategy: PaddingStrategy) -> Self {
        self.padding = strategy;
        self
    }

    /// Build the 24-byte nonce: prefix[16] || counter[8] (big-endian).
    fn next_nonce(&mut self) -> Result<[u8; SECRETBOX_NONCE_LEN]> {
        if self.nonce_counter == 0 {
            return Err(Error::NonceExhausted);
        }
        let mut nonce = [0u8; SECRETBOX_NONCE_LEN];
        nonce[..16].copy_from_slice(&self.nonce_prefix);
        nonce[16..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter = self
            .nonce_counter
            .checked_add(1)
            .ok_or(Error::NonceExhausted)?;
        Ok(nonce)
    }

    /// Compute how many padding bytes to add for the given payload length.
    fn compute_pad_len(&self, payload_len: usize, rng: &mut impl Rng) -> usize {
        // Maximum padding allowed = remaining space in the frame after payload + overhead
        let max_allowed = MAX_FRAME_PAYLOAD.saturating_sub(payload_len);
        match self.padding {
            PaddingStrategy::None => 0,
            PaddingStrategy::PadToMax => max_allowed,
            PaddingStrategy::Random { max_pad } => {
                let effective_max = max_pad.min(max_allowed);
                if effective_max == 0 {
                    0
                } else {
                    rng.gen_range(0..=effective_max)
                }
            }
        }
    }

    /// Encode application data into one or more frames.
    ///
    /// Large payloads are split across multiple frames automatically.
    /// Each frame receives random padding according to the configured
    /// [`PaddingStrategy`].
    pub fn encode(&mut self, payload: &[u8], dst: &mut BytesMut) -> Result<()> {
        self.encode_with_rng(payload, dst, &mut rand::rngs::OsRng)
    }

    /// Encode with an explicit RNG (for testing determinism).
    pub fn encode_with_rng(
        &mut self,
        payload: &[u8],
        dst: &mut BytesMut,
        rng: &mut impl Rng,
    ) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        while offset < payload.len() {
            let chunk_end = (offset + MAX_FRAME_PAYLOAD).min(payload.len());
            let chunk = &payload[offset..chunk_end];
            let pad_len = self.compute_pad_len(chunk.len(), rng);
            self.encode_frame_padded(PacketType::Payload, chunk, pad_len, rng, dst)?;
            offset = chunk_end;
        }
        Ok(())
    }

    /// Encode a single frame with specified type, payload, and padding.
    pub fn encode_frame(
        &mut self,
        pkt_type: PacketType,
        payload: &[u8],
        pad_len: usize,
        dst: &mut BytesMut,
    ) -> Result<()> {
        self.encode_frame_padded(pkt_type, payload, pad_len, &mut rand::rngs::OsRng, dst)
    }

    /// Encode a cover-traffic heartbeat frame (empty payload with padding).
    ///
    /// The receiver's decoder will see a `Payload(vec![])` which the
    /// transport layer silently discards. Use this to keep idle connections
    /// active and generate noise that hinders traffic analysis.
    pub fn encode_heartbeat(&mut self, dst: &mut BytesMut) -> Result<()> {
        let mut rng = rand::rngs::OsRng;
        let pad_len = self.compute_pad_len(0, &mut rng);
        self.encode_frame_padded(PacketType::Payload, &[], pad_len, &mut rng, dst)
    }

    /// Core frame encoder: builds the secretbox with random-filled padding.
    fn encode_frame_padded(
        &mut self,
        pkt_type: PacketType,
        payload: &[u8],
        pad_len: usize,
        rng: &mut impl RngCore,
        dst: &mut BytesMut,
    ) -> Result<()> {
        let payload_len = payload.len();
        // plaintext inside secretbox: type(1) + payload_len(2) + payload + padding
        let plaintext_len = 1 + 2 + payload_len + pad_len;
        // secretbox output = tag(16) + plaintext
        let secretbox_len = SECRETBOX_TAG_LEN + plaintext_len;

        assert!(secretbox_len <= MAX_FRAME_LENGTH, "frame too large");

        // Build plaintext
        let mut plaintext = vec![0u8; plaintext_len];
        plaintext[0] = pkt_type as u8;
        plaintext[1..3].copy_from_slice(&(payload_len as u16).to_be_bytes());
        plaintext[3..3 + payload_len].copy_from_slice(payload);
        // Fill padding with random bytes (not zeros — avoids known-plaintext leak)
        if pad_len > 0 {
            rng.fill_bytes(&mut plaintext[3 + payload_len..]);
        }

        // Encrypt in-place and get tag
        let nonce = self.next_nonce()?;
        let nonce_ga = GenericArray::from_slice(&nonce);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce_ga, b"", &mut plaintext)
            .expect("encryption should not fail");

        // Write obfuscated length (2 bytes, big-endian, XOR-masked)
        let masked_len = self.length_obf.mask_length(secretbox_len as u16);
        dst.reserve(FRAME_HEADER_LEN + secretbox_len);
        dst.put_slice(&masked_len);

        // Write secretbox: tag || encrypted_plaintext
        dst.put_slice(tag.as_slice());
        dst.put_slice(&plaintext);

        Ok(())
    }

    /// Encode a TYPE_PRNG_SEED frame with 24 bytes of seed material.
    pub fn encode_prng_seed(&mut self, seed: &[u8; 24], dst: &mut BytesMut) -> Result<()> {
        self.encode_frame(PacketType::PrngSeed, seed, 0, dst)
    }
}
