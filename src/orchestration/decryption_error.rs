//! "I could not read your message" — content type 28, DECRYPTION_ERROR.
//!
//! Sent by the device that failed to read a message to the device that wrote it. It names the
//! unread message's ratchet key, and that is the whole point: the writer retires its current state
//! only when the key is that state's, so an error that is stale — redelivered, reordered, about a
//! state already replaced — is recognised exactly and does nothing. END_SESSION (21), which this
//! replaces, named no state; it could not tell a stale teardown from a live one and was rationed by
//! time windows instead. See `construct-docs/decisions/sessions-renew-by-sending.md`, variant B.
//!
//! The payload is sealed to the recipient's identity key, under its own domain salt so an error box
//! cannot be passed off as a sender-certificate box or the reverse. It cannot be ratchet-encrypted:
//! the ratchet is what failed. The plaintext has a fixed length, so the box does not vary with the
//! message id it carries.
//!
//! ```text
//! version(1) ‖ hint(1) ‖ ratchet_key(32) ‖ id_len(1) ‖ message_id(id_len) ‖ zero pad → 131 bytes
//! ```

use crate::crypto::sealed_sender::{open_in_domain, seal_in_domain};

/// The domain an error box is sealed under.
const DOMAIN: &[u8] = b"ConstructDECRYPTERR-v1";
const VERSION: u8 = 1;
const RATCHET_KEY_LEN: usize = 32;
/// Longest message id an error can name. A per-device copy id is a UUID, `-fd-` and 16 hex
/// characters — 56 bytes — so this leaves room without letting the length vary.
pub const MAX_MESSAGE_ID_LEN: usize = 96;
const PLAINTEXT_LEN: usize = 1 + 1 + RATCHET_KEY_LEN + 1 + MAX_MESSAGE_ID_LEN;

/// What the device that failed can tell the writer about how to open the next state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionErrorHint {
    None,
    /// The one-time prekey (or Kyber prekey) the handshake named is not held here: open the next
    /// state without a one-time prekey. What END_SESSION's `OTPK_UNREPRODUCIBLE` reason said.
    PrekeyUnavailable,
}

impl DecryptionErrorHint {
    fn to_byte(self) -> u8 {
        match self {
            Self::None => 0,
            Self::PrekeyUnavailable => 1,
        }
    }

    /// An unknown hint reads as none: a newer build's advice is optional, the error is not.
    fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::PrekeyUnavailable,
            _ => Self::None,
        }
    }
}

/// The contents of one error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionError {
    /// The DH ratchet key in the unread message's header — the writer's sending key then.
    pub ratchet_key: Vec<u8>,
    /// The unread message, so the writer can send it again.
    pub message_id: String,
    pub hint: DecryptionErrorHint,
}

impl DecryptionError {
    fn encode(&self) -> Result<Vec<u8>, String> {
        if self.ratchet_key.len() != RATCHET_KEY_LEN {
            return Err(format!(
                "DECRYPTION_ERROR: ratchet key must be {RATCHET_KEY_LEN} bytes, got {}",
                self.ratchet_key.len()
            ));
        }
        let id = self.message_id.as_bytes();
        if id.len() > MAX_MESSAGE_ID_LEN {
            return Err(format!(
                "DECRYPTION_ERROR: message id is {} bytes, at most {MAX_MESSAGE_ID_LEN}",
                id.len()
            ));
        }
        let mut out = Vec::with_capacity(PLAINTEXT_LEN);
        out.push(VERSION);
        out.push(self.hint.to_byte());
        out.extend_from_slice(&self.ratchet_key);
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        out.resize(PLAINTEXT_LEN, 0);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != PLAINTEXT_LEN {
            return Err(format!(
                "DECRYPTION_ERROR: plaintext is {} bytes, expected {PLAINTEXT_LEN}",
                bytes.len()
            ));
        }
        if bytes[0] != VERSION {
            return Err(format!("DECRYPTION_ERROR: unknown version {}", bytes[0]));
        }
        let hint = DecryptionErrorHint::from_byte(bytes[1]);
        let ratchet_key = bytes[2..2 + RATCHET_KEY_LEN].to_vec();
        let id_len = bytes[2 + RATCHET_KEY_LEN] as usize;
        if id_len > MAX_MESSAGE_ID_LEN {
            return Err(format!(
                "DECRYPTION_ERROR: message id length {id_len} out of range"
            ));
        }
        let start = 3 + RATCHET_KEY_LEN;
        let message_id = String::from_utf8(bytes[start..start + id_len].to_vec())
            .map_err(|_| "DECRYPTION_ERROR: message id is not UTF-8".to_string())?;
        Ok(Self {
            ratchet_key,
            message_id,
            hint,
        })
    }

    /// Seal this error to the writer's X25519 identity key.
    pub fn seal(&self, recipient_identity: &[u8]) -> Result<Vec<u8>, String> {
        let plaintext = self.encode()?;
        seal_in_domain(&plaintext, recipient_identity, DOMAIN)
            .map_err(|e| format!("DECRYPTION_ERROR: seal failed: {e:?}"))
    }

    /// Open an error sealed to us with our X25519 identity secret.
    pub fn open(sealed: &[u8], our_identity_secret: &[u8]) -> Result<Self, String> {
        let plaintext = open_in_domain(sealed, our_identity_secret, DOMAIN)
            .map_err(|e| format!("DECRYPTION_ERROR: open failed: {e:?}"))?;
        Self::decode(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn pair(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let secret = StaticSecret::from([seed; 32]);
        let public = PublicKey::from(&secret);
        (secret.to_bytes().to_vec(), public.as_bytes().to_vec())
    }

    fn error(id: &str) -> DecryptionError {
        DecryptionError {
            ratchet_key: vec![9; 32],
            message_id: id.to_string(),
            hint: DecryptionErrorHint::PrekeyUnavailable,
        }
    }

    #[test]
    fn an_error_opens_as_it_was_sealed() {
        let (secret, public) = pair(3);
        let sent = error("6d5475fe-0b1c-46da-bae3-4b76726d31a3-fd-0d0e81ab358f88b2");
        let sealed = sent.seal(&public).unwrap();
        assert_eq!(DecryptionError::open(&sealed, &secret).unwrap(), sent);
    }

    /// The box does not say how long the id was. Mutation: drop the pad — this reddens.
    #[test]
    fn every_box_is_the_same_length() {
        let (_, public) = pair(3);
        let short = error("a").seal(&public).unwrap();
        let long = error(&"b".repeat(MAX_MESSAGE_ID_LEN))
            .seal(&public)
            .unwrap();
        assert_eq!(short.len(), long.len());
    }

    /// Sealed to someone else, it does not open.
    #[test]
    fn another_key_does_not_open_it() {
        let (_, public) = pair(3);
        let (other_secret, _) = pair(4);
        let sealed = error("m").seal(&public).unwrap();
        assert!(DecryptionError::open(&sealed, &other_secret).is_err());
    }

    /// An error box is not a sender-certificate box, in either direction.
    /// Mutation: seal under `SEALED_SALT` — this reddens.
    #[test]
    fn the_domain_keeps_it_apart_from_the_certificate_box() {
        let (secret, public) = pair(3);
        let sealed = error("m").seal(&public).unwrap();
        assert!(crate::crypto::sealed_sender::open_with_x25519_secret(&sealed, &secret).is_err());

        let plain = error("m").encode().unwrap();
        let cert_box =
            crate::crypto::sealed_sender::seal_to_x25519_public(&plain, &public).unwrap();
        assert!(DecryptionError::open(&cert_box, &secret).is_err());
    }

    #[test]
    fn what_cannot_be_encoded_is_refused_not_truncated() {
        let (_, public) = pair(3);
        assert!(
            error(&"x".repeat(MAX_MESSAGE_ID_LEN + 1))
                .seal(&public)
                .is_err()
        );
        let mut short_key = error("m");
        short_key.ratchet_key = vec![1; 31];
        assert!(short_key.seal(&public).is_err());
    }

    /// A hint this build does not know is no hint, not a refusal.
    #[test]
    fn an_unknown_hint_reads_as_none() {
        let mut plain = error("m").encode().unwrap();
        plain[1] = 200;
        assert_eq!(
            DecryptionError::decode(&plain).unwrap().hint,
            DecryptionErrorHint::None
        );
    }
}
