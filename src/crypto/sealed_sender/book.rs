//! The envelope book: every session envelope key pair this device holds, by peer device and
//! session, and the only place they are kept (construct-docs
//! `decisions/sealed-envelope-keyed-by-the-session.md`).
//!
//! Sessions are restored lazily by the platform, one device at a time, so a lookup by tag cannot
//! walk the sessions in memory — it walks this, which is always loaded (it is part of the
//! orchestrator state). A pair is filed when its session is made, the one moment the root that
//! derives it exists.
//!
//! **A pair outlives its ratchet.** Resetting a session or deleting a chat is local and sends
//! nothing, and the peer goes on writing on the state it holds. If the tag were the only way to
//! know who wrote and the pair went with the ratchet, nobody could answer that peer and it would
//! write into the void. So a pair whose state is gone is *retired*, not removed: it still names
//! the writer, and seals the DECRYPTION_ERROR that makes the writer open a new state. A retired
//! pair is dropped after `RETIRED_RETENTION_SECS`, the time the server holds an undelivered
//! message.

use super::envelope::{EnvelopeKind, EnvelopePair};
use super::first_flight::{FiledFirstFlightKey, FirstFlightKey};
use crate::error::CryptoError;

/// How long a retired pair still names its writer: the server's queue window — after it nothing
/// written on the pair can still arrive.
pub const RETIRED_RETENTION_SECS: u64 = crate::crypto::keys::QUEUE_TTL_SECS;

/// One session's pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookEntry {
    /// The peer device.
    pub device: String,
    /// The session the pair belongs to (`Session::session_id`, hex).
    pub session_id: String,
    pub keys: EnvelopePair,
    /// When its ratchet state went away; `None` while it is held.
    pub retired_at: Option<u64>,
    /// The handshake's first-flight key, by the hash of its ML-KEM ciphertext, while first flights
    /// may still be written on this session (`first_flight`): the initiator seals with it until
    /// the peer answers, the responder opens the later ones with it until the initiator proves
    /// itself.
    pub first_flight: Option<FiledFirstFlightKey>,
}

/// An envelope opened by the book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedEnvelope {
    /// Who wrote it: the device of the pair whose tag matched.
    pub device: String,
    /// The session of that pair — the state the writer sealed with.
    pub session_id: String,
    pub kind: EnvelopeKind,
    pub body: Vec<u8>,
    /// The pair is retired: its ratchet state is gone here, so a ratchet body will not decrypt.
    pub retired: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvelopeBook {
    /// Newest first: a lookup tries the pairs most likely to match first.
    entries: Vec<BookEntry>,
}

impl EnvelopeBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[BookEntry] {
        &self.entries
    }

    /// File the pair of a session just made. A session already filed keeps its pair.
    pub fn register(&mut self, device: &str, session_id: &str, keys: EnvelopePair) {
        if self.entries.iter().any(|e| e.session_id == session_id) {
            return;
        }
        self.entries.insert(
            0,
            BookEntry {
                device: device.to_string(),
                session_id: session_id.to_string(),
                keys,
                retired_at: None,
                first_flight: None,
            },
        );
    }

    /// File the first-flight key of `session_id`'s handshake. No-op for a session not filed.
    pub fn set_first_flight(
        &mut self,
        session_id: &str,
        ciphertext_hash: [u8; 32],
        key: FirstFlightKey,
        handshake_at: u64,
    ) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.session_id == session_id) {
            e.first_flight = Some(FiledFirstFlightKey {
                ciphertext_hash,
                key,
                handshake_at,
            });
        }
    }

    /// The first flights of `session_id` are over: no more will be written or need opening.
    pub fn clear_first_flight(&mut self, session_id: &str) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.session_id == session_id) {
            e.first_flight = None;
        }
    }

    /// The first-flight key of `session_id`, if its first flights are not over.
    pub fn first_flight_of_session(&self, session_id: &str) -> Option<&FiledFirstFlightKey> {
        self.entries
            .iter()
            .find(|e| e.session_id == session_id)
            .and_then(|e| e.first_flight.as_ref())
    }

    /// The key of the handshake whose ML-KEM ciphertext hashes to `ciphertext_hash` — a later first
    /// flight of a session the first one opened.
    pub fn first_flight_by_handshake(&self, ciphertext_hash: &[u8; 32]) -> Option<&FirstFlightKey> {
        self.entries.iter().find_map(|e| match &e.first_flight {
            Some(f) if &f.ciphertext_hash == ciphertext_hash => Some(&f.key),
            _ => None,
        })
    }

    pub fn has_session(&self, session_id: &str) -> bool {
        self.entries.iter().any(|e| e.session_id == session_id)
    }

    /// The ratchet state of `session_id` is gone; its pair keeps naming the writer for a while.
    pub fn retire_session(&mut self, session_id: &str, now: u64) {
        for e in self
            .entries
            .iter_mut()
            .filter(|e| e.session_id == session_id)
        {
            e.retired_at.get_or_insert(now);
        }
    }

    /// Every state with `device` is gone (a reset, a deleted chat).
    pub fn retire_device(&mut self, device: &str, now: u64) {
        for e in self.entries.iter_mut().filter(|e| e.device == device) {
            e.retired_at.get_or_insert(now);
        }
    }

    /// Retire every pair of `device` whose session is not in `held`.
    pub fn retire_device_except(&mut self, device: &str, held: &[String], now: u64) {
        for e in self
            .entries
            .iter_mut()
            .filter(|e| e.device == device && !held.contains(&e.session_id))
        {
            e.retired_at.get_or_insert(now);
        }
    }

    /// Drop retired pairs past their retention.
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|e| {
            e.retired_at
                .is_none_or(|at| now.saturating_sub(at) < RETIRED_RETENTION_SECS)
        });
    }

    /// Seal `kind ‖ payload` for the peer of `session_id`. Fails when the session has no pair —
    /// it was made by a core older than the envelope — or the pair is retired.
    pub fn seal(
        &self,
        session_id: &str,
        kind: EnvelopeKind,
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.session_id == session_id)
            .ok_or_else(|| {
                CryptoError::InvalidInputError(format!(
                    "no envelope keys for session {}",
                    crate::crypto::messaging::double_ratchet::id_prefix(session_id)
                ))
            })?;
        let mut body = Vec::with_capacity(1 + payload.len());
        body.push(kind as u8);
        body.extend_from_slice(payload);
        entry.keys.send.seal(&body)
    }

    /// Seal a DECRYPTION_ERROR back along a pair, retired or not: answering a writer whose state we
    /// lost is what a retired pair is kept for.
    pub fn seal_reply(&self, session_id: &str, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.seal(session_id, EnvelopeKind::DecryptionError, payload)
    }

    /// Find the pair whose tag `envelope` carries and open it. `None` when no pair matches — an
    /// envelope for another device, or from a session this device never held.
    pub fn open(&self, envelope: &[u8]) -> Option<OpenedEnvelope> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.keys.recv.matches(envelope))?;
        let body = entry.keys.recv.open(envelope).ok()?;
        let (&kind, rest) = body.split_first()?;
        Some(OpenedEnvelope {
            device: entry.device.clone(),
            session_id: entry.session_id.clone(),
            kind: EnvelopeKind::from_byte(kind)?,
            body: rest.to_vec(),
            retired: entry.retired_at.is_some(),
        })
    }

    /// For the orchestrator state blob, newest first.
    pub fn to_cfe(&self) -> Vec<crate::cfe::CfeEnvelopeEntryV1> {
        self.entries
            .iter()
            .map(|e| {
                let mut keys = e.keys.send.to_bytes();
                keys.extend_from_slice(&e.keys.recv.to_bytes());
                let first_flight = e.first_flight.as_ref().map(|f| {
                    let mut bytes = f.ciphertext_hash.to_vec();
                    bytes.extend_from_slice(&f.key.to_bytes());
                    bytes.extend_from_slice(&f.handshake_at.to_be_bytes());
                    crate::crypto::SecretBytes::new(bytes)
                });
                crate::cfe::CfeEnvelopeEntryV1 {
                    device_id: e.device.clone(),
                    session_id: e.session_id.clone(),
                    keys: crate::crypto::SecretBytes::new(keys),
                    retired_at: e.retired_at,
                    first_flight,
                }
            })
            .collect()
    }

    /// Rebuild from the orchestrator state blob. An entry whose keys are malformed is dropped:
    /// it can name nobody.
    pub fn from_cfe(entries: &[crate::cfe::CfeEnvelopeEntryV1]) -> Self {
        let entries = entries
            .iter()
            .filter_map(|e| {
                let k = e.keys.expose();
                if k.len() != 128 {
                    return None;
                }
                Some(BookEntry {
                    device: e.device_id.clone(),
                    session_id: e.session_id.clone(),
                    keys: EnvelopePair {
                        send: super::envelope::DirectionKeys::from_bytes(&k[..64]).ok()?,
                        recv: super::envelope::DirectionKeys::from_bytes(&k[64..]).ok()?,
                    },
                    retired_at: e.retired_at,
                    // A malformed first-flight record costs only the later first flights.
                    first_flight: e.first_flight.as_ref().and_then(|f| {
                        let f = f.expose();
                        (f.len() == 72).then_some(())?;
                        Some(FiledFirstFlightKey {
                            ciphertext_hash: f[..32].try_into().ok()?,
                            key: FirstFlightKey::from_bytes(&f[32..64]).ok()?,
                            handshake_at: u64::from_be_bytes(f[64..].try_into().ok()?),
                        })
                    }),
                })
            })
            .collect();
        Self { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccc";

    /// Alice's and Bob's books for one session `sid` under root `sk`.
    fn pair(sk: &[u8], sid: &str) -> (EnvelopeBook, EnvelopeBook) {
        let mut alice = EnvelopeBook::new();
        let mut bob = EnvelopeBook::new();
        alice.register(B, sid, EnvelopePair::derive(sk, A, B));
        bob.register(A, sid, EnvelopePair::derive(sk, B, A));
        (alice, bob)
    }

    #[test]
    fn the_tag_names_the_writer() {
        let (alice, mut bob) = pair(&[1; 32], "s1");
        bob.register(C, "s2", EnvelopePair::derive(&[2; 32], B, C));
        let env = alice.seal("s1", EnvelopeKind::Ratchet, b"payload").unwrap();
        let opened = bob.open(&env).unwrap();
        assert_eq!(opened.device, A);
        assert_eq!(opened.session_id, "s1");
        assert_eq!(opened.kind, EnvelopeKind::Ratchet);
        assert_eq!(opened.body, b"payload");
        assert!(!opened.retired);
    }

    #[test]
    fn our_own_envelope_is_not_ours_to_open() {
        let (alice, _) = pair(&[1; 32], "s1");
        let env = alice.seal("s1", EnvelopeKind::Ratchet, b"x").unwrap();
        assert!(alice.open(&env).is_none());
    }

    /// The liveness rule: a reset leaves the pair, so the writer is still named and can be
    /// answered. Mutation: make `retire_device` remove the entries — this reddens.
    #[test]
    fn a_reset_session_still_names_its_writer_and_can_answer() {
        let (alice, mut bob) = pair(&[1; 32], "s1");
        bob.retire_device(A, 1_000);
        let env = alice.seal("s1", EnvelopeKind::Ratchet, b"x").unwrap();
        let opened = bob.open(&env).expect("a retired pair still matches");
        assert!(opened.retired);
        let reply = bob.seal_reply(&opened.session_id, b"error").unwrap();
        let back = alice.open(&reply).unwrap();
        assert_eq!(back.kind, EnvelopeKind::DecryptionError);
        assert_eq!(back.device, B);
        assert_eq!(back.body, b"error");
    }

    #[test]
    fn a_retired_pair_goes_after_the_queue_window() {
        let (alice, mut bob) = pair(&[1; 32], "s1");
        bob.retire_session("s1", 1_000);
        bob.prune(1_000 + RETIRED_RETENTION_SECS - 1);
        let env = alice.seal("s1", EnvelopeKind::Ratchet, b"x").unwrap();
        assert!(bob.open(&env).is_some());
        bob.prune(1_000 + RETIRED_RETENTION_SECS);
        assert!(bob.open(&env).is_none());
    }

    #[test]
    fn a_held_pair_is_never_pruned() {
        let (_, mut bob) = pair(&[1; 32], "s1");
        bob.prune(u64::MAX);
        assert!(bob.has_session("s1"));
    }

    #[test]
    fn only_the_sessions_not_held_are_retired() {
        let mut bob = EnvelopeBook::new();
        bob.register(A, "old", EnvelopePair::derive(&[1; 32], B, A));
        bob.register(A, "new", EnvelopePair::derive(&[2; 32], B, A));
        bob.retire_device_except(A, &["new".to_string()], 5);
        let retired: Vec<_> = bob
            .entries()
            .iter()
            .map(|e| (e.session_id.as_str(), e.retired_at))
            .collect();
        assert!(retired.contains(&("old", Some(5))));
        assert!(retired.contains(&("new", None)));
    }

    #[test]
    fn a_session_without_a_pair_cannot_seal() {
        let book = EnvelopeBook::new();
        assert!(book.seal("s1", EnvelopeKind::Ratchet, b"x").is_err());
    }

    #[test]
    fn the_book_survives_the_orchestrator_blob() {
        let (alice, mut bob) = pair(&[1; 32], "s1");
        bob.retire_session("s1", 9);
        let restored = EnvelopeBook::from_cfe(&bob.to_cfe());
        assert_eq!(restored, bob);
        let env = alice.seal("s1", EnvelopeKind::Ratchet, b"x").unwrap();
        assert_eq!(restored.open(&env).unwrap().device, A);
    }

    #[test]
    fn the_first_flight_key_is_found_by_its_handshake_and_survives_the_blob() {
        let (mut alice, _) = pair(&[1; 32], "s1");
        alice.set_first_flight("s1", [9; 32], FirstFlightKey::from_kem_secret(&[5; 32]), 77);
        let restored = EnvelopeBook::from_cfe(&alice.to_cfe());
        assert_eq!(restored, alice);
        assert_eq!(
            restored.first_flight_by_handshake(&[9; 32]),
            Some(&FirstFlightKey::from_kem_secret(&[5; 32]))
        );
        alice.clear_first_flight("s1");
        assert!(alice.first_flight_by_handshake(&[9; 32]).is_none());
    }

    #[test]
    fn an_unknown_kind_byte_is_not_opened() {
        let (alice, bob) = pair(&[1; 32], "s1");
        let raw = alice.entries()[0].keys.send.seal(&[0x7f, 1, 2, 3]).unwrap();
        assert!(bob.open(&raw).is_none());
    }
}
