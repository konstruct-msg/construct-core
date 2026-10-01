//! The first-flight box: a session's first messages sealed whole, under a hybrid key
//! (construct-docs `decisions/first-flight-sealed-whole.md`, `FF-1`, the rest of `PQC-1`).
//!
//! Until the peer answers, every message an initiator writes carries the PQXDH v2 handshake in
//! its wire header — and with it the initiator's ML-KEM-1024 identity key, the same on every first
//! flight that device writes. Left in the clear beside an X25519-sealed certificate, that key named
//! the sender to the server: an own-device copy travels identified, and a multi-device account's
//! first copy to a sibling carries it. So the box covers everything but what the recipient needs to
//! derive its key — the id of its own Kyber prekey and the ML-KEM ciphertext to it:
//!
//! ```text
//! first_flight = BE32(kyber_prekey_id) ‖ kem_ciphertext (1568) ‖ eph (32) ‖ nonce (12)
//!                ‖ ChaCha20-Poly1305(k_first, nonce, body, ad = everything before nonce)
//! body         = BE16(len certificate) ‖ certificate ‖ wire payload without kem_ciphertext
//!
//! ff_key  = HKDF-SHA256(salt = ∅, ikm = ML-KEM shared secret, info = "construct-first-flight-v1", 32)
//! k_first = HKDF-SHA256(salt = "ConstructSEALED-first-v1",
//!                       ikm  = X25519(eph, IK_recipient) ‖ ff_key,
//!                       info = eph ‖ SHA-256(kem_ciphertext), 32)
//! ```
//!
//! The encapsulation that keys this box also keys the session root, under another label: neither
//! key derives from the other. The ciphertext moves out of the wire payload rather than being
//! copied, so the box costs six bytes over the payload and certificate it carries.
//!
//! `ff_key` is kept beside the session's envelope pair (`book::BookEntry::first_flight`): the
//! initiator seals every message up to the peer's answer with it, and the responder opens the
//! second and later ones with it — the one-time Kyber prekey they name was burned by the first.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::wire_payload::{HEADER_SIZE, KEM_LEN_OFFSET, KYBER_PREKEY_ID_OFFSET};

const FF_KEY_INFO: &[u8] = b"construct-first-flight-v1";
const SALT: &[u8] = b"ConstructSEALED-first-v1";
/// ML-KEM-1024 ciphertext.
pub const KEM_CIPHERTEXT_LEN: usize = 1568;
const ID_LEN: usize = 4;
const EPH_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const AEAD_TAG_LEN: usize = 16;
const AD_LEN: usize = ID_LEN + KEM_CIPHERTEXT_LEN + EPH_LEN;
/// What the box adds to the certificate and the wire payload it carries.
pub const FIRST_FLIGHT_OVERHEAD: usize = ID_LEN + EPH_LEN + NONCE_LEN + AEAD_TAG_LEN + 2;

/// The handshake's contribution to the box key: the ML-KEM shared secret under this box's label.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FirstFlightKey([u8; 32]);

impl std::fmt::Debug for FirstFlightKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FirstFlightKey(<redacted>)")
    }
}

impl FirstFlightKey {
    pub fn from_kem_secret(shared_secret: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];
        hk.expand(FF_KEY_INFO, &mut key)
            .expect("HKDF-SHA256 with 32-byte output always succeeds");
        Self(key)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key: [u8; 32] = bytes.try_into().map_err(|_| {
            CryptoError::InvalidInputError(format!(
                "first-flight key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// A handshake's first-flight key filed under the hash of its ML-KEM ciphertext.
pub type FiledFirstFlightKey = ([u8; 32], FirstFlightKey);

/// What a recipient reads before it can open the box: which of its Kyber prekeys the handshake
/// was made to, and the ciphertext to decapsulate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRef<'a> {
    pub kyber_prekey_id: u32,
    pub kem_ciphertext: &'a [u8],
}

impl HandshakeRef<'_> {
    /// The handshake's name in the book: a first flight is matched to the key its first message
    /// filed by this.
    pub fn ciphertext_hash(&self) -> [u8; 32] {
        ciphertext_hash(self.kem_ciphertext)
    }
}

pub fn ciphertext_hash(kem_ciphertext: &[u8]) -> [u8; 32] {
    Sha256::digest(kem_ciphertext).into()
}

/// The handshake a wire payload carries; `None` when it carries none (not a first flight).
pub fn handshake_of_wire(wire_payload: &[u8]) -> Option<HandshakeRef<'_>> {
    if wire_payload.len() < HEADER_SIZE {
        return None;
    }
    let kyber_prekey_id = u32::from_le_bytes(
        wire_payload[KYBER_PREKEY_ID_OFFSET..KYBER_PREKEY_ID_OFFSET + ID_LEN]
            .try_into()
            .ok()?,
    );
    let kem_len = u16::from_le_bytes(
        wire_payload[KEM_LEN_OFFSET..KEM_LEN_OFFSET + 2]
            .try_into()
            .ok()?,
    ) as usize;
    if kem_len != KEM_CIPHERTEXT_LEN || wire_payload.len() <= HEADER_SIZE + kem_len {
        return None;
    }
    Some(HandshakeRef {
        kyber_prekey_id,
        kem_ciphertext: &wire_payload[HEADER_SIZE..HEADER_SIZE + kem_len],
    })
}

/// The handshake a sealed first flight was made with, read before opening it.
pub fn handshake_of_box(first_flight: &[u8]) -> Result<HandshakeRef<'_>, CryptoError> {
    if first_flight.len() < AD_LEN + NONCE_LEN + AEAD_TAG_LEN {
        return Err(CryptoError::InvalidInputError(format!(
            "first flight too short: {} bytes",
            first_flight.len()
        )));
    }
    Ok(HandshakeRef {
        kyber_prekey_id: u32::from_be_bytes(first_flight[..ID_LEN].try_into().unwrap()),
        kem_ciphertext: &first_flight[ID_LEN..ID_LEN + KEM_CIPHERTEXT_LEN],
    })
}

fn box_key(dh: &[u8; 32], ff_key: &FirstFlightKey, eph: &[u8], kem_ciphertext: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(dh);
    ikm.extend_from_slice(&ff_key.0);
    let mut info = Vec::with_capacity(EPH_LEN + 32);
    info.extend_from_slice(eph);
    info.extend_from_slice(&ciphertext_hash(kem_ciphertext));
    let hk = Hkdf::<Sha256>::new(Some(SALT), &ikm);
    ikm.zeroize();
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF-SHA256 with 32-byte output always succeeds");
    key
}

fn key32(bytes: &[u8], what: &str) -> Result<[u8; 32], CryptoError> {
    bytes.try_into().map_err(|_| {
        CryptoError::InvalidInputError(format!("{what} must be 32 bytes, got {}", bytes.len()))
    })
}

/// Seal a first-flight `wire_payload` and the sender `certificate` to `recipient_identity`.
/// Refuses a wire payload that carries no ML-KEM handshake: there is nothing to key the box with,
/// and PQXDH v2 is mandatory.
pub fn seal(
    ff_key: &FirstFlightKey,
    recipient_identity: &[u8],
    wire_payload: &[u8],
    certificate: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut eph_seed = [0u8; 32];
    OsRng.fill_bytes(&mut eph_seed);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = seal_with(
        ff_key,
        recipient_identity,
        wire_payload,
        certificate,
        &eph_seed,
        &nonce,
    );
    eph_seed.zeroize();
    sealed
}

/// `seal` with its randomness given — for the known-answer vector.
fn seal_with(
    ff_key: &FirstFlightKey,
    recipient_identity: &[u8],
    wire_payload: &[u8],
    certificate: &[u8],
    eph_seed: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let handshake = handshake_of_wire(wire_payload).ok_or_else(|| {
        CryptoError::InvalidInputError("not a first flight: no ML-KEM handshake".into())
    })?;
    let cert_len = u16::try_from(certificate.len()).map_err(|_| {
        CryptoError::InvalidInputError(format!("certificate too large: {}", certificate.len()))
    })?;
    let recipient = PublicKey::from(key32(recipient_identity, "recipient identity key")?);

    let ephemeral = StaticSecret::from(*eph_seed);
    let eph = PublicKey::from(&ephemeral);
    let dh = ephemeral.diffie_hellman(&recipient);
    let mut key = box_key(
        dh.as_bytes(),
        ff_key,
        eph.as_bytes(),
        handshake.kem_ciphertext,
    );

    let mut out =
        Vec::with_capacity(FIRST_FLIGHT_OVERHEAD + certificate.len() + wire_payload.len());
    out.extend_from_slice(&handshake.kyber_prekey_id.to_be_bytes());
    out.extend_from_slice(handshake.kem_ciphertext);
    out.extend_from_slice(eph.as_bytes());

    let kem_end = HEADER_SIZE + KEM_CIPHERTEXT_LEN;
    let mut body =
        Vec::with_capacity(2 + certificate.len() + wire_payload.len() - KEM_CIPHERTEXT_LEN);
    body.extend_from_slice(&cert_len.to_be_bytes());
    body.extend_from_slice(certificate);
    body.extend_from_slice(&wire_payload[..HEADER_SIZE]);
    body.extend_from_slice(&wire_payload[kem_end..]);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &body,
                aad: &out[..AD_LEN],
            },
        )
        .map_err(|_| CryptoError::AeadEncryptionError("first-flight seal failed".into()))?;
    body.zeroize();
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// A first flight opened: the sender certificate and the wire payload, made whole again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFirstFlight {
    pub certificate: Vec<u8>,
    pub wire_payload: Vec<u8>,
}

/// Open a first flight with our X25519 identity secret and the handshake's `ff_key` (from the
/// book, or from decapsulating `handshake_of_box`).
pub fn open(
    ff_key: &FirstFlightKey,
    our_identity_secret: &[u8],
    first_flight: &[u8],
) -> Result<OpenedFirstFlight, CryptoError> {
    let handshake = handshake_of_box(first_flight)?;
    let eph = &first_flight[ID_LEN + KEM_CIPHERTEXT_LEN..AD_LEN];
    let nonce = &first_flight[AD_LEN..AD_LEN + NONCE_LEN];
    let ours = StaticSecret::from(key32(our_identity_secret, "identity secret")?);
    let dh = ours.diffie_hellman(&PublicKey::from(key32(eph, "ephemeral key")?));
    let mut key = box_key(dh.as_bytes(), ff_key, eph, handshake.kem_ciphertext);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();
    let body = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &first_flight[AD_LEN + NONCE_LEN..],
                aad: &first_flight[..AD_LEN],
            },
        )
        .map_err(|_| CryptoError::AeadDecryptionError("first flight does not open".into()))?;

    let malformed = |what: &str| CryptoError::InvalidInputError(format!("first flight: {what}"));
    if body.len() < 2 {
        return Err(malformed("no certificate length"));
    }
    let cert_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let wire_start = 2 + cert_len;
    if body.len() < wire_start + HEADER_SIZE {
        return Err(malformed("body too short"));
    }
    let header = &body[wire_start..wire_start + HEADER_SIZE];
    // The header inside must name the handshake outside: the ciphertext is put back where it says.
    let inner_id = u32::from_le_bytes(
        header[KYBER_PREKEY_ID_OFFSET..KYBER_PREKEY_ID_OFFSET + ID_LEN]
            .try_into()
            .unwrap(),
    );
    let inner_len = u16::from_le_bytes(
        header[KEM_LEN_OFFSET..KEM_LEN_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    if inner_id != handshake.kyber_prekey_id || inner_len != KEM_CIPHERTEXT_LEN {
        return Err(malformed("inner header names another handshake"));
    }
    let mut wire_payload = Vec::with_capacity(body.len() - wire_start + KEM_CIPHERTEXT_LEN);
    wire_payload.extend_from_slice(header);
    wire_payload.extend_from_slice(handshake.kem_ciphertext);
    wire_payload.extend_from_slice(&body[wire_start + HEADER_SIZE..]);
    Ok(OpenedFirstFlight {
        certificate: body[2..wire_start].to_vec(),
        wire_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wire payload with a handshake: the fixed header, a ciphertext, then the rest.
    fn wire(kyber_id: u32, ct_byte: u8) -> Vec<u8> {
        let mut w = vec![0u8; HEADER_SIZE];
        w[KYBER_PREKEY_ID_OFFSET..KYBER_PREKEY_ID_OFFSET + 4]
            .copy_from_slice(&kyber_id.to_le_bytes());
        w[KEM_LEN_OFFSET..KEM_LEN_OFFSET + 2]
            .copy_from_slice(&(KEM_CIPHERTEXT_LEN as u16).to_le_bytes());
        w.extend(std::iter::repeat_n(ct_byte, KEM_CIPHERTEXT_LEN));
        // kem_identity (len + key) and the sealed message: what must not be readable outside.
        w.extend_from_slice(&(1568u16).to_le_bytes());
        w.extend(std::iter::repeat_n(0x1d, 1568));
        w.extend_from_slice(b"ratchet body");
        w
    }

    fn recipient() -> (StaticSecret, Vec<u8>) {
        let secret = StaticSecret::from([7u8; 32]);
        let public = PublicKey::from(&secret).as_bytes().to_vec();
        (secret, public)
    }

    #[test]
    fn a_first_flight_round_trips_and_costs_six_bytes() {
        let (secret, public) = recipient();
        let key = FirstFlightKey::from_kem_secret(&[3; 32]);
        let w = wire(1_000_007, 0xcc);
        let cert = b"certificate".to_vec();
        let sealed = seal(&key, &public, &w, &cert).unwrap();
        // Today's box: eph + nonce + tag around the certificate, beside the whole wire payload.
        let before = 32 + 12 + 16 + cert.len() + w.len();
        assert_eq!(sealed.len(), before + 6);
        let h = handshake_of_box(&sealed).unwrap();
        assert_eq!(h.kyber_prekey_id, 1_000_007);
        let opened = open(&key, secret.as_bytes(), &sealed).unwrap();
        assert_eq!(opened.certificate, cert);
        assert_eq!(opened.wire_payload, w);
    }

    /// FF-1: the initiator's KEM identity key, the ratchet header and the certificate are not
    /// readable outside the box. Mutation: copy the wire payload after the ciphertext unsealed —
    /// this reddens.
    #[test]
    fn nothing_but_the_handshake_is_in_the_clear() {
        let (_, public) = recipient();
        let key = FirstFlightKey::from_kem_secret(&[3; 32]);
        let w = wire(5, 0xcc);
        let sealed = seal(&key, &public, &w, b"cert-cert-cert").unwrap();
        let kem_identity = vec![0x1d; 64];
        assert!(!sealed.windows(64).any(|win| win == kem_identity.as_slice()));
        assert!(!sealed.windows(12).any(|win| win == b"ratchet body"));
        assert!(!sealed.windows(14).any(|win| win == b"cert-cert-cert"));
    }

    #[test]
    fn the_box_needs_both_the_x25519_and_the_ml_kem_halves() {
        let (secret, public) = recipient();
        let key = FirstFlightKey::from_kem_secret(&[3; 32]);
        let sealed = seal(&key, &public, &wire(5, 0xcc), b"c").unwrap();
        let other_kem = FirstFlightKey::from_kem_secret(&[4; 32]);
        assert!(open(&other_kem, secret.as_bytes(), &sealed).is_err());
        assert!(open(&key, &[8u8; 32], &sealed).is_err());
    }

    #[test]
    fn a_swapped_ciphertext_does_not_open() {
        let (secret, public) = recipient();
        let key = FirstFlightKey::from_kem_secret(&[3; 32]);
        let mut sealed = seal(&key, &public, &wire(5, 0xcc), b"c").unwrap();
        sealed[ID_LEN + 10] ^= 1;
        assert!(open(&key, secret.as_bytes(), &sealed).is_err());
        let mut sealed = seal(&key, &public, &wire(5, 0xcc), b"c").unwrap();
        sealed[0] ^= 1;
        assert!(open(&key, secret.as_bytes(), &sealed).is_err());
    }

    /// Known answer, checked against an independent implementation (Python `cryptography`,
    /// 2026-10-01): ff_key from a 32-byte 0x03 secret, recipient secret 0x07…, eph seed 0x11…,
    /// nonce 0x22…, wire = `wire(5, 0xcc)`, certificate "c". SHA-256 of the whole box.
    #[test]
    fn the_box_matches_its_known_answer() {
        let (secret, public) = recipient();
        let key = FirstFlightKey::from_kem_secret(&[3; 32]);
        let sealed = seal_with(
            &key,
            &public,
            &wire(5, 0xcc),
            b"c",
            &[0x11; 32],
            &[0x22; 12],
        )
        .unwrap();
        assert_eq!(hex::encode(Sha256::digest(&sealed)), KAT_SHA256);
        assert_eq!(
            open(&key, secret.as_bytes(), &sealed).unwrap().wire_payload,
            wire(5, 0xcc)
        );
    }
    const KAT_SHA256: &str = "052358e65c8ad3b9a36f78477627e8bb85f8fcb5dc037e959405bda30155f446";

    #[test]
    fn a_payload_without_a_handshake_is_not_sealed() {
        let (_, public) = recipient();
        let key = FirstFlightKey::from_kem_secret(&[3; 32]);
        let mut w = vec![0u8; HEADER_SIZE];
        w.extend_from_slice(b"mid-ratchet");
        assert!(seal(&key, &public, &w, b"c").is_err());
    }
}
