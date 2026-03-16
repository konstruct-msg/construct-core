//! Frame decoder: reads obfs4 wire frames and returns plaintext payload.
//!
//! Handles length deobfuscation, NaCl secretbox decryption, and packet type parsing.

use bytes::{Buf, BytesMut};
use crypto_secretbox::{
    KeyInit, XSalsa20Poly1305,
    aead::{AeadInPlace, generic_array::GenericArray},
};

use super::{
    FRAME_HEADER_LEN, MAX_FRAME_LENGTH, PacketType, SECRETBOX_NONCE_LEN, SECRETBOX_TAG_LEN,
    length_dist::LengthObfuscator,
};
use crate::{Error, Result};

/// Decoded frame content.
pub enum DecodedFrame {
    /// Application data payload.
    Payload(Vec<u8>),
    /// PRNG seed for protocol polymorphism (24 bytes).
    PrngSeed([u8; 24]),
}

/// State machine for incremental frame decoding.
pub struct FrameDecoder {
    cipher: XSalsa20Poly1305,
    nonce_prefix: [u8; 16],
    nonce_counter: u64,
    length_obf: LengthObfuscator,
    /// Accumulator for partial reads.
    buf: BytesMut,
    /// Deobfuscated length of the next frame's secretbox (None = not yet decoded).
    next_frame_len: Option<u16>,
}

impl FrameDecoder {
    /// Create a new decoder with session key material.
    pub fn new(
        key: &[u8; 32],
        nonce_prefix: &[u8; 16],
        siphash_key: &[u8; 16],
        siphash_iv: &[u8; 8],
    ) -> Self {
        FrameDecoder {
            cipher: XSalsa20Poly1305::new(GenericArray::from_slice(key)),
            nonce_prefix: *nonce_prefix,
            nonce_counter: 1,
            length_obf: LengthObfuscator::new(siphash_key, siphash_iv),
            buf: BytesMut::with_capacity(4096),
            next_frame_len: None,
        }
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

    /// Feed newly received bytes into the decoder buffer.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to decode one complete frame from the internal buffer.
    ///
    /// Returns:
    /// - `Ok(Some(frame))` — a complete frame was decoded
    /// - `Ok(None)` — not enough data yet, call `feed()` with more bytes
    /// - `Err(...)` — MAC failure or protocol error (connection should be dropped)
    pub fn decode_frame(&mut self) -> Result<Option<DecodedFrame>> {
        // Step 1: Deobfuscate length if we haven't yet
        if self.next_frame_len.is_none() {
            if self.buf.len() < FRAME_HEADER_LEN {
                return Ok(None);
            }
            let obfuscated: [u8; 2] = [self.buf[0], self.buf[1]];
            let frame_len = self.length_obf.unmask_length(&obfuscated);

            if frame_len as usize > MAX_FRAME_LENGTH {
                return Err(Error::FrameTooLarge {
                    size: frame_len as usize,
                    max: MAX_FRAME_LENGTH,
                });
            }

            self.next_frame_len = Some(frame_len);
        }

        let frame_len = self.next_frame_len.unwrap() as usize;
        let total_needed = FRAME_HEADER_LEN + frame_len;

        // Step 2: Wait for full frame
        if self.buf.len() < total_needed {
            return Ok(None);
        }

        // Step 3: Extract the frame
        self.buf.advance(FRAME_HEADER_LEN);
        let frame_data = self.buf.split_to(frame_len);
        self.next_frame_len = None;

        // Step 4: Split into tag and ciphertext
        if frame_data.len() < SECRETBOX_TAG_LEN {
            return Err(Error::FrameMacMismatch);
        }
        let tag_bytes = &frame_data[..SECRETBOX_TAG_LEN];
        let mut ciphertext = frame_data[SECRETBOX_TAG_LEN..].to_vec();

        // Step 5: Decrypt
        let nonce = self.next_nonce()?;
        let nonce_ga = GenericArray::from_slice(&nonce);
        let tag = GenericArray::from_slice(tag_bytes);

        self.cipher
            .decrypt_in_place_detached(nonce_ga, b"", &mut ciphertext, tag)
            .map_err(|_| Error::FrameMacMismatch)?;

        // Step 6: Parse plaintext: type(1) || payload_len(2) || payload || padding
        if ciphertext.len() < 3 {
            return Err(Error::FrameMacMismatch);
        }

        let pkt_type_byte = ciphertext[0];
        let payload_len = u16::from_be_bytes([ciphertext[1], ciphertext[2]]) as usize;

        if 3 + payload_len > ciphertext.len() {
            return Err(Error::FrameMacMismatch);
        }

        let payload = ciphertext[3..3 + payload_len].to_vec();

        match PacketType::from_byte(pkt_type_byte) {
            Some(PacketType::Payload) => Ok(Some(DecodedFrame::Payload(payload))),
            Some(PacketType::PrngSeed) => {
                if payload.len() == 24 {
                    let mut seed = [0u8; 24];
                    seed.copy_from_slice(&payload);
                    Ok(Some(DecodedFrame::PrngSeed(seed)))
                } else {
                    // Invalid seed length, but spec says ignore unknown
                    Ok(Some(DecodedFrame::Payload(vec![])))
                }
            }
            None => {
                // Unknown type — spec says ignore but still decrypt
                Ok(Some(DecodedFrame::Payload(vec![])))
            }
        }
    }
}
