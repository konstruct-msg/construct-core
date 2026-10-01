//! The session envelope: a sealed message whose sender is found by a tag, not by a certificate
//! (construct-docs `decisions/sealed-envelope-keyed-by-the-session.md`, `PQC-1`).
//!
//! The X25519 box beside this (`seal_to_x25519_public`) hides who sent a message from the server
//! today and from nobody who records it and later breaks X25519. Once two devices hold a session,
//! they already share a secret with an ML-KEM-1024 contribution — the session's root `SK`
//! (PQXDH v2). The envelope is keyed from it, so who sent an established-session message is as
//! post-quantum as what it says, and no public-key operation or certificate rides on the message.
//!
//! ```text
//! keys(s→r) = HKDF-SHA256(salt = ∅, ikm = SK,
//!                         info = "construct-envelope-v1" ‖ 0x00 ‖ s ‖ 0x00 ‖ r, 64)
//!           = k_env (32) ‖ k_tag (32)                s, r: sender and recipient device ids
//!
//! envelope  = nonce (12, random) ‖ tag (16) ‖ ChaCha20-Poly1305(k_env, nonce, body, ad = tag)
//! tag       = HMAC-SHA256(k_tag, nonce)[..16]
//! ```
//!
//! The recipient computes the tag under each pair of keys it holds and opens the body under the
//! one that matches. The tag is a function of a random nonce, not of a counter, so there is
//! nothing to keep in step: reordering, loss and replay change nothing. Looking a sender up costs
//! one HMAC over 12 bytes per held key pair — about 0.25 ms for 1200 pairs (measured 2026-10-01).
//!
//! Keys run per direction, so a device's own envelopes never match its own receive keys.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

const INFO: &[u8] = b"construct-envelope-v1";
/// Random per envelope.
pub const ENVELOPE_NONCE_LEN: usize = 12;
/// HMAC-SHA256 truncated to 128 bits: a stranger's envelope matches one held key pair with
/// probability 2⁻¹²⁸.
pub const ENVELOPE_TAG_LEN: usize = 16;
const AEAD_TAG_LEN: usize = 16;
/// The smallest envelope: an empty body.
pub const ENVELOPE_OVERHEAD: usize = ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN + AEAD_TAG_LEN;

/// One direction's keys: what a sender seals with, or what a recipient matches and opens with.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DirectionKeys {
    env: [u8; 32],
    tag: [u8; 32],
}

impl std::fmt::Debug for DirectionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectionKeys(<redacted>)")
    }
}

impl DirectionKeys {
    /// The keys for envelopes from `sender` to `recipient` under the session root `sk`.
    pub fn derive(sk: &[u8], sender: &str, recipient: &str) -> Self {
        let mut info = Vec::with_capacity(INFO.len() + 2 + sender.len() + recipient.len());
        info.extend_from_slice(INFO);
        info.push(0x00);
        info.extend_from_slice(sender.as_bytes());
        info.push(0x00);
        info.extend_from_slice(recipient.as_bytes());

        let mut out = [0u8; 64];
        Hkdf::<Sha256>::new(None, sk)
            .expand(&info, &mut out)
            .expect("HKDF-SHA256 with 64-byte output always succeeds");
        let mut keys = Self {
            env: [0; 32],
            tag: [0; 32],
        };
        keys.env.copy_from_slice(&out[..32]);
        keys.tag.copy_from_slice(&out[32..]);
        out.zeroize();
        keys
    }

    /// Rebuild from stored bytes (`env ‖ tag`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidInputError(format!(
                "envelope keys must be 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut keys = Self {
            env: [0; 32],
            tag: [0; 32],
        };
        keys.env.copy_from_slice(&bytes[..32]);
        keys.tag.copy_from_slice(&bytes[32..]);
        Ok(keys)
    }

    /// `env ‖ tag`, for storage. Secret.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(&self.env);
        v.extend_from_slice(&self.tag);
        v
    }

    fn tag_mac(&self, nonce: &[u8]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.tag)
            .expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(nonce);
        mac
    }

    /// Seal `body` as an envelope under these (sending) keys.
    pub fn seal(&self, body: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; ENVELOPE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        self.seal_with_nonce(body, &nonce)
    }

    pub(crate) fn seal_with_nonce(
        &self,
        body: &[u8],
        nonce: &[u8; ENVELOPE_NONCE_LEN],
    ) -> Result<Vec<u8>, CryptoError> {
        let tag = self.tag_mac(nonce).finalize().into_bytes();
        let tag = &tag[..ENVELOPE_TAG_LEN];
        let ct = ChaCha20Poly1305::new(Key::from_slice(&self.env))
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: tag,
                },
            )
            .map_err(|_| CryptoError::AeadEncryptionError("envelope seal failed".into()))?;
        let mut out = Vec::with_capacity(ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN + ct.len());
        out.extend_from_slice(nonce);
        out.extend_from_slice(tag);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Whether `envelope` was sealed under these keys, by its tag alone — constant time. The
    /// body is not touched; a match is then confirmed by `open`.
    pub fn matches(&self, envelope: &[u8]) -> bool {
        if envelope.len() < ENVELOPE_OVERHEAD {
            return false;
        }
        let (nonce, rest) = envelope.split_at(ENVELOPE_NONCE_LEN);
        self.tag_mac(nonce)
            .verify_truncated_left(&rest[..ENVELOPE_TAG_LEN])
            .is_ok()
    }

    /// Open an envelope sealed under these keys. Fails if the tag or the body does not verify.
    pub fn open(&self, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.matches(envelope) {
            return Err(CryptoError::AeadDecryptionError(
                "envelope tag does not match".into(),
            ));
        }
        let nonce = &envelope[..ENVELOPE_NONCE_LEN];
        let tag = &envelope[ENVELOPE_NONCE_LEN..ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN];
        let ct = &envelope[ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN..];
        ChaCha20Poly1305::new(Key::from_slice(&self.env))
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: tag })
            .map_err(|_| CryptoError::AeadDecryptionError("envelope body does not open".into()))
    }
}

/// What an envelope's body is: its first byte, inside the ciphertext. A number, not a string,
/// and never visible to the server (construct-docs `decisions/signals-are-numbers-not-text.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeKind {
    /// A ratchet wire payload (`wire_payload::pack`).
    Ratchet = 0x01,
    /// A DECRYPTION_ERROR (`orchestration::decryption_error`), plain inside the envelope.
    DecryptionError = 0x02,
}

impl EnvelopeKind {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Ratchet),
            0x02 => Some(Self::DecryptionError),
            _ => None,
        }
    }
}

/// Both directions of one session, from this device's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopePair {
    /// From us to the peer.
    pub send: DirectionKeys,
    /// From the peer to us.
    pub recv: DirectionKeys,
}

impl EnvelopePair {
    /// Both directions under the session root `sk`, from `local`'s side.
    pub fn derive(sk: &[u8], local: &str, peer: &str) -> Self {
        Self {
            send: DirectionKeys::derive(sk, local, peer),
            recv: DirectionKeys::derive(sk, peer, local),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SK: [u8; 32] = [0x42; 32];
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn a_sender_and_its_recipient_derive_the_same_direction() {
        let a_sends = DirectionKeys::derive(&SK, A, B);
        let b_receives = DirectionKeys::derive(&SK, A, B);
        let env = a_sends.seal(b"hello").unwrap();
        assert!(b_receives.matches(&env));
        assert_eq!(b_receives.open(&env).unwrap(), b"hello");
    }

    #[test]
    fn the_two_directions_are_different_keys() {
        let a_to_b = DirectionKeys::derive(&SK, A, B);
        let b_to_a = DirectionKeys::derive(&SK, B, A);
        assert_ne!(a_to_b, b_to_a);
        let env = a_to_b.seal(b"x").unwrap();
        assert!(
            !b_to_a.matches(&env),
            "a device's own envelope must not match its receive keys"
        );
    }

    #[test]
    fn another_session_does_not_match() {
        let ours = DirectionKeys::derive(&SK, A, B);
        let other = DirectionKeys::derive(&[0x43; 32], A, B);
        assert!(!other.matches(&ours.seal(b"x").unwrap()));
    }

    #[test]
    fn a_changed_byte_anywhere_is_refused() {
        let keys = DirectionKeys::derive(&SK, A, B);
        let env = keys.seal(b"body").unwrap();
        for i in 0..env.len() {
            let mut bad = env.clone();
            bad[i] ^= 0x01;
            assert!(
                keys.open(&bad).is_err(),
                "byte {i} flipped and the envelope still opened"
            );
        }
        assert!(keys.open(&env[..ENVELOPE_OVERHEAD - 1]).is_err());
    }

    #[test]
    fn two_envelopes_of_one_session_share_no_bytes_a_server_could_link() {
        let keys = DirectionKeys::derive(&SK, A, B);
        let one = keys.seal(b"same").unwrap();
        let two = keys.seal(b"same").unwrap();
        assert_ne!(
            one[..ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN],
            two[..ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN]
        );
    }

    #[test]
    fn stored_keys_round_trip() {
        let keys = DirectionKeys::derive(&SK, A, B);
        assert_eq!(DirectionKeys::from_bytes(&keys.to_bytes()).unwrap(), keys);
        assert!(DirectionKeys::from_bytes(&[0; 63]).is_err());
    }

    /// Known answer, recomputed outside this code (Python `hmac`/`hashlib` + RFC 5869 HKDF and
    /// `cryptography`'s ChaCha20Poly1305) — the vector a second implementation checks against.
    #[test]
    fn known_answer() {
        let keys = DirectionKeys::derive(&SK, A, B);
        let env = keys.seal_with_nonce(b"konstruct", &[0x07; 12]).unwrap();
        assert_eq!(hex::encode(keys.to_bytes()), KAT_KEYS);
        assert_eq!(hex::encode(&env), KAT_ENVELOPE);
    }

    const KAT_KEYS: &str = "23dd7e9b29418eb7e2e1919c658ce793edc2d7dbb7152cd12e0c00657e5103e3f1826ffe7b465b74e0dccc36d8b5f70a8aaf7555c15cbca3c4688b6ccfc853c7";
    const KAT_ENVELOPE: &str = "070707070707070707070707d10c92335c5a89bfcce99a5a0ef39d19dc1338e107f57639ba5c111c0eb2c89e1053bbad9ad4df3c73";
}
