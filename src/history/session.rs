//! The two ends of a history transfer as sans-I/O state machines.
//!
//! The sender makes the opening (or file header), takes the receiver's reply on the local
//! network, and turns records into sealed chunks. The receiver says how many bytes it needs next,
//! takes exactly those, and hands back events; it stops once to let the platform fetch the other
//! device's keys from the directory, then verifies, answers and opens. Neither touches a socket or
//! a file, and neither holds a device secret: signing, decapsulation and the identity agreement go
//! through [`DeviceKeys`], which the orchestrator implements over the keys it keeps.

use rand::RngCore;
use zeroize::Zeroizing;

use super::channel::{self, CHUNK_PLAINTEXT, ChunkCipher, EOF, LEN_PREFIX, Salt};
use super::cth1::{self, Envelope, Event};
use super::frames::{
    self, CTHF_HEADER_LEN, CthfHeader, KEM_CT, KnownKeys, Local, OPENING_LEN, Opening, PREFIX_LEN,
    Pin, Prefix, Reply, device_id_raw,
};
use super::{HistoryFailure, ct_eq};

/// What a history transfer needs from this device's keys, without the keys.
pub trait DeviceKeys {
    fn identity_public(&self) -> Result<[u8; 32], HistoryFailure>;
    /// This device's hybrid identity public key. A device without one does not take part.
    fn hybrid_public(&self) -> Result<Vec<u8>, HistoryFailure>;
    /// The id of the Kyber signed prekey a peer encapsulates to now.
    fn current_kyber_key_id(&self) -> Result<u32, HistoryFailure>;
    fn sign_hybrid(&self, message: &[u8]) -> Result<Vec<u8>, HistoryFailure>;
    fn kyber_decapsulate(
        &self,
        key_id: u32,
        kem_ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HistoryFailure>;
    /// The CTHF receiver's channel key: identity agreement and decapsulation, inside the keys.
    fn file_channel_key(
        &self,
        sender_eph: &[u8; 32],
        kem_key_id: u32,
        kem_ct: &[u8],
        snapshot_id: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, HistoryFailure>;
}

/// The other device's keys as the directory serves them: identity and hybrid for the checks, and
/// the Kyber signed prekey the sender encapsulates to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeys {
    pub identity_public: [u8; 32],
    pub hybrid_public: Vec<u8>,
    pub kyber_prekey_public: Vec<u8>,
    pub kyber_prekey_id: u32,
}

impl PeerKeys {
    fn known(&self) -> KnownKeys {
        KnownKeys {
            identity_public: self.identity_public.to_vec(),
            hybrid_public: self.hybrid_public.clone(),
        }
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

fn ephemeral() -> (x25519_dalek::StaticSecret, [u8; 32]) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    (secret, public)
}

#[cfg(feature = "post-quantum")]
fn encapsulate(kyber_public: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HistoryFailure> {
    let enc = crate::crypto::pq_x3dh::mlkem1024_encapsulate(kyber_public)
        .map_err(|_| HistoryFailure::NoHybridKey)?;
    Ok((
        enc.ciphertext,
        Zeroizing::new(enc.shared_secret.as_ref().to_vec()),
    ))
}

#[cfg(not(feature = "post-quantum"))]
fn encapsulate(_: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HistoryFailure> {
    Err(HistoryFailure::NoHybridKey)
}

// ── Sender ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderState {
    AwaitReply,
    Streaming,
    Done,
}

/// The offering device's end.
pub struct Sender {
    state: SenderState,
    /// What was sent first: a CTT1 v2 opening or a CTHF header.
    first_frame: Vec<u8>,
    // Nearby, until the reply is in: the opening it answers, and our halves of the key.
    opening: Option<Opening>,
    eph: Option<x25519_dalek::StaticSecret>,
    kem_ss: Option<Zeroizing<Vec<u8>>>,
    peer: KnownKeys,
    pinned_identity: Option<[u8; 32]>,
    snapshot_id: [u8; 16],
    user_id: [u8; 16],
    writer: cth1::Writer,
    cipher: Option<ChunkCipher>,
    /// Plaintext not yet sealed: never more than one chunk and one call's input.
    pending: Vec<u8>,
}

impl Sender {
    /// A nearby offer: the CTT1 v2 opening to write first, then `accept_reply`. A skip is the same
    /// signed opening with no snapshot and no KEM, and nothing after it.
    pub fn nearby(
        keys: &dyn DeviceKeys,
        user_id: [u8; 16],
        peer: &PeerKeys,
        skip: bool,
        pinned_identity: Option<[u8; 32]>,
    ) -> Result<Self, HistoryFailure> {
        let identity = keys.identity_public()?;
        let hybrid = keys.hybrid_public()?;
        let (eph, eph_pub) = ephemeral();
        let (snapshot_id, kem_ct, kem_ss) = if skip {
            ([0u8; 16], vec![0u8; KEM_CT], None)
        } else {
            let (ct, ss) = encapsulate(&peer.kyber_prekey_public)?;
            (random::<16>(), ct, Some(ss))
        };
        let mut opening = Opening {
            sender_eph: eph_pub,
            skipped: skip,
            payload_len: 0,
            sender_identity: identity,
            sender_hybrid: hybrid,
            snapshot_id,
            sender_device_id: device_id_raw(&identity),
            receiver_device_id: device_id_raw(&peer.identity_public),
            receiver_kyber_key_id: peer.kyber_prekey_id,
            kem_ct,
            signature: Vec::new(),
        };
        opening.signature = keys.sign_hybrid(&opening.signed_message())?;
        let first_frame = opening.to_bytes()?;
        Ok(Self {
            state: if skip {
                SenderState::Done
            } else {
                SenderState::AwaitReply
            },
            first_frame,
            opening: Some(opening),
            eph: Some(eph),
            kem_ss,
            peer: peer.known(),
            pinned_identity,
            snapshot_id,
            user_id,
            writer: cth1::Writer::new(),
            cipher: None,
            pending: Vec::with_capacity(CHUNK_PLAINTEXT),
        })
    }

    /// A file for `peer`: the CTHF header to write first, then chunks straight away — a file has
    /// no reply, so the key is agreed with the recipient's identity key.
    pub fn file(
        keys: &dyn DeviceKeys,
        user_id: [u8; 16],
        peer: &PeerKeys,
    ) -> Result<Self, HistoryFailure> {
        let identity = keys.identity_public()?;
        let (eph, eph_pub) = ephemeral();
        let (kem_ct, kem_ss) = encapsulate(&peer.kyber_prekey_public)?;
        let snapshot_id = random::<16>();
        let mut header = CthfHeader {
            user_id,
            recipient_device_id: device_id_raw(&peer.identity_public),
            source_device_id: device_id_raw(&identity),
            snapshot_id,
            sender_eph: eph_pub,
            sender_identity: identity,
            sender_hybrid: keys.hybrid_public()?,
            recipient_kyber_key_id: peer.kyber_prekey_id,
            kem_ct,
            signature: Vec::new(),
        };
        header.signature = keys.sign_hybrid(&header.signed_message())?;
        let ecdh = eph.diffie_hellman(&x25519_dalek::PublicKey::from(peer.identity_public));
        let key = channel::channel_key(ecdh.as_bytes(), &kem_ss, Salt::File, &snapshot_id);
        Ok(Self {
            state: SenderState::Streaming,
            first_frame: header.to_bytes()?,
            opening: None,
            eph: None,
            kem_ss: None,
            peer: peer.known(),
            pinned_identity: None,
            snapshot_id,
            user_id,
            writer: cth1::Writer::new(),
            cipher: Some(ChunkCipher::new(&key, snapshot_id, user_id)),
            pending: Vec::with_capacity(CHUNK_PLAINTEXT),
        })
    }

    /// The opening or header, to write verbatim before anything else.
    pub fn first_frame(&self) -> &[u8] {
        &self.first_frame
    }

    /// The snapshot id this offer announced — the one the manifest must carry.
    pub fn snapshot_id(&self) -> [u8; 16] {
        self.snapshot_id
    }

    pub fn user_id(&self) -> [u8; 16] {
        self.user_id
    }

    /// The receiver's reply, exactly `frames::REPLY_LEN` bytes. Verified against the directory's
    /// keys (and the Flow B QR identity, when there is one) before the key is derived.
    pub fn accept_reply(&mut self, reply: &[u8]) -> Result<(), HistoryFailure> {
        if self.state != SenderState::AwaitReply {
            return Err(HistoryFailure::Malformed);
        }
        let opening = self.opening.as_ref().ok_or(HistoryFailure::Malformed)?;
        let reply = Reply::parse(reply)?;
        frames::verify_reply(
            &reply,
            opening,
            &self.peer,
            self.pinned_identity.as_ref().map(|p| &p[..]),
        )?;
        let eph = self.eph.take().ok_or(HistoryFailure::Malformed)?;
        let kem_ss = self.kem_ss.take().ok_or(HistoryFailure::Malformed)?;
        let ecdh = eph.diffie_hellman(&x25519_dalek::PublicKey::from(reply.receiver_eph));
        let key = channel::channel_key(ecdh.as_bytes(), &kem_ss, Salt::Nearby, &self.snapshot_id);
        self.cipher = Some(ChunkCipher::new(&key, self.snapshot_id, self.user_id));
        self.state = SenderState::Streaming;
        Ok(())
    }

    fn streaming(&self) -> Result<(), HistoryFailure> {
        if self.state != SenderState::Streaming {
            return Err(HistoryFailure::Malformed);
        }
        Ok(())
    }

    /// Frame transcript records and append every chunk they completed to `out`.
    pub fn push_record(
        &mut self,
        record_type: u8,
        proto: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), HistoryFailure> {
        self.streaming()?;
        self.writer.record(record_type, proto, &mut self.pending)?;
        self.seal(false, out)
    }

    pub fn begin_media(
        &mut self,
        media_id: &str,
        mime_type: &str,
        byte_len: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), HistoryFailure> {
        self.streaming()?;
        self.writer
            .begin_media(media_id, mime_type, byte_len, &mut self.pending)?;
        self.seal(false, out)
    }

    pub fn push_media(&mut self, piece: &[u8], out: &mut Vec<u8>) -> Result<(), HistoryFailure> {
        self.streaming()?;
        // Sealed a chunk at a time, so a large piece never doubles in `pending`.
        for part in piece.chunks(CHUNK_PLAINTEXT) {
            self.writer.media_bytes(part, &mut self.pending)?;
            self.seal(false, out)?;
        }
        Ok(())
    }

    /// The End record, the last partial chunk and the EOF frame.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), HistoryFailure> {
        self.streaming()?;
        self.writer.end(&mut self.pending)?;
        self.seal(true, out)?;
        out.extend_from_slice(&EOF);
        self.state = SenderState::Done;
        Ok(())
    }

    /// Seal every full chunk in `pending` — and the remainder when `all` — then move what is left
    /// to the front once.
    fn seal(&mut self, all: bool, out: &mut Vec<u8>) -> Result<(), HistoryFailure> {
        let cipher = self.cipher.as_mut().ok_or(HistoryFailure::Malformed)?;
        let mut at = 0;
        while self.pending.len() - at >= CHUNK_PLAINTEXT || (all && at < self.pending.len()) {
            let n = (self.pending.len() - at).min(CHUNK_PLAINTEXT);
            cipher.seal(&self.pending[at..at + n], out)?;
            at += n;
        }
        self.pending.drain(..at);
        Ok(())
    }
}

// ── Receiver ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Nearby,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiverState {
    Prefix,
    OpeningRest,
    Header,
    AwaitKeys,
    ChunkLen,
    Chunk(usize),
    Done,
    Skipped,
    Failed(HistoryFailure),
}

/// Where the receiver stands after a `feed` or `accept`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Read `Receiver::need` more bytes and feed them.
    NeedMore,
    /// The frame names the device it came from. Fetch that device's keys from our own account's
    /// directory entry and call `accept`.
    AwaitKeys { sender_device_id: [u8; 16] },
    /// A verified skip: the other device declined to send. Nothing follows.
    Skipped,
    /// The stream ended with End and EOF. Commit.
    Done,
}

/// The new device's end.
pub struct Receiver {
    source: Source,
    state: ReceiverState,
    buf: Vec<u8>,
    user_id: [u8; 16],
    opening: Option<Opening>,
    header: Option<CthfHeader>,
    cipher: Option<ChunkCipher>,
    reader: Option<cth1::Reader>,
}

impl Receiver {
    /// `user_id` is this device's account: the chunk AAD and the manifest are bound to it.
    pub fn new(source: Source, user_id: [u8; 16]) -> Self {
        Self {
            source,
            state: match source {
                Source::Nearby => ReceiverState::Prefix,
                Source::File => ReceiverState::Header,
            },
            buf: Vec::new(),
            user_id,
            opening: None,
            header: None,
            cipher: None,
            reader: None,
        }
    }

    /// How many bytes to read next; 0 while waiting for keys or when finished.
    pub fn need(&self) -> usize {
        let unit = match self.state {
            ReceiverState::Prefix => PREFIX_LEN,
            ReceiverState::OpeningRest => OPENING_LEN,
            ReceiverState::Header => CTHF_HEADER_LEN,
            ReceiverState::ChunkLen => LEN_PREFIX,
            ReceiverState::Chunk(n) => n,
            _ => return 0,
        };
        unit - self.buf.len()
    }

    fn fail(&mut self, f: HistoryFailure) -> HistoryFailure {
        self.state = ReceiverState::Failed(f);
        self.buf = Vec::new();
        f
    }

    /// Feed bytes read from the socket or file — at most `need()` of them is the contract, though
    /// less is accepted. Events for every chunk they complete are returned with the status.
    pub fn feed(&mut self, mut data: &[u8]) -> Result<(Vec<Event>, Status), HistoryFailure> {
        let mut events = Vec::new();
        match self.feed_inner(&mut data, &mut events) {
            Ok(status) => Ok((events, status)),
            Err(f) => Err(self.fail(f)),
        }
    }

    fn feed_inner(
        &mut self,
        data: &mut &[u8],
        events: &mut Vec<Event>,
    ) -> Result<Status, HistoryFailure> {
        if let ReceiverState::Failed(f) = self.state {
            return Err(f);
        }
        loop {
            match self.state {
                ReceiverState::AwaitKeys | ReceiverState::Done | ReceiverState::Skipped => {
                    // Bytes past the point the protocol stops reading are not the protocol.
                    if !data.is_empty() {
                        return Err(HistoryFailure::Malformed);
                    }
                    return Ok(self.status());
                }
                _ => {}
            }
            if data.is_empty() {
                return Ok(Status::NeedMore);
            }
            let take = self.need().min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            *data = &data[take..];
            if self.need() > 0 {
                continue;
            }
            match self.state {
                ReceiverState::Prefix => {
                    Prefix::parse(&self.buf)?.history()?;
                    self.state = ReceiverState::OpeningRest;
                }
                ReceiverState::OpeningRest => {
                    let opening = Opening::parse(&std::mem::take(&mut self.buf))?;
                    self.state = ReceiverState::AwaitKeys;
                    let sender = opening.sender_device_id;
                    self.opening = Some(opening);
                    if !data.is_empty() {
                        return Err(HistoryFailure::Malformed);
                    }
                    return Ok(Status::AwaitKeys {
                        sender_device_id: sender,
                    });
                }
                ReceiverState::Header => {
                    let header = CthfHeader::parse(&std::mem::take(&mut self.buf))?;
                    if !ct_eq(&header.user_id, &self.user_id) {
                        return Err(HistoryFailure::UserMismatch);
                    }
                    let sender = header.source_device_id;
                    self.header = Some(header);
                    self.state = ReceiverState::AwaitKeys;
                    if !data.is_empty() {
                        return Err(HistoryFailure::Malformed);
                    }
                    return Ok(Status::AwaitKeys {
                        sender_device_id: sender,
                    });
                }
                ReceiverState::ChunkLen => {
                    let prefix: [u8; 4] = self.buf[..].try_into().expect("4 bytes");
                    self.buf.clear();
                    match channel::sealed_len(prefix)? {
                        Some(len) => self.state = ReceiverState::Chunk(len),
                        None => {
                            // EOF: the stream must already have ended with End.
                            let reader = self.reader.as_mut().ok_or(HistoryFailure::Malformed)?;
                            reader.finish()?;
                            self.state = ReceiverState::Done;
                        }
                    }
                }
                ReceiverState::Chunk(_) => {
                    let cipher = self.cipher.as_mut().ok_or(HistoryFailure::Malformed)?;
                    let plain = cipher.open(std::mem::take(&mut self.buf))?;
                    self.reader
                        .as_mut()
                        .ok_or(HistoryFailure::Malformed)?
                        .push(&plain, events)?;
                    self.state = ReceiverState::ChunkLen;
                }
                _ => unreachable!("handled above"),
            }
        }
    }

    /// The socket closed or the file ended. Anything short of a verified skip or a stream ended
    /// with End and EOF is `Truncated` — a cut stream is never a short but valid snapshot.
    pub fn end_of_input(&mut self) -> Result<(), HistoryFailure> {
        match self.state {
            ReceiverState::Done | ReceiverState::Skipped => Ok(()),
            ReceiverState::Failed(f) => Err(f),
            _ => Err(self.fail(HistoryFailure::Truncated)),
        }
    }

    fn status(&self) -> Status {
        match self.state {
            ReceiverState::Done => Status::Done,
            ReceiverState::Skipped => Status::Skipped,
            ReceiverState::AwaitKeys => Status::AwaitKeys {
                sender_device_id: self
                    .opening
                    .as_ref()
                    .map(|o| o.sender_device_id)
                    .or(self.header.as_ref().map(|h| h.source_device_id))
                    .unwrap_or_default(),
            },
            _ => Status::NeedMore,
        }
    }

    /// The directory's keys for the device the frame names, and what the QR pinned. Verified in
    /// the spec's order; only then is anything decapsulated. For a nearby opening, returns the
    /// reply to write back; a verified skip returns nothing and the receiver is `Skipped`.
    pub fn accept(
        &mut self,
        keys: &dyn DeviceKeys,
        known: &KnownKeys,
        pin: &Pin,
    ) -> Result<Option<Vec<u8>>, HistoryFailure> {
        match self.accept_inner(keys, known, pin) {
            Ok(reply) => Ok(reply),
            Err(f) => Err(self.fail(f)),
        }
    }

    fn accept_inner(
        &mut self,
        keys: &dyn DeviceKeys,
        known: &KnownKeys,
        pin: &Pin,
    ) -> Result<Option<Vec<u8>>, HistoryFailure> {
        if self.state != ReceiverState::AwaitKeys {
            return Err(HistoryFailure::Malformed);
        }
        let identity = keys.identity_public()?;
        let local = Local {
            device_id: device_id_raw(&identity),
            kyber_key_id: keys.current_kyber_key_id()?,
        };
        match self.source {
            Source::Nearby => {
                let opening = self.opening.take().ok_or(HistoryFailure::Malformed)?;
                frames::verify_opening(&opening, &local, known, pin)?;
                if opening.skipped {
                    self.state = ReceiverState::Skipped;
                    return Ok(None);
                }
                let kem_ss =
                    keys.kyber_decapsulate(opening.receiver_kyber_key_id, &opening.kem_ct)?;
                let (eph, eph_pub) = ephemeral();
                let mut reply = Reply {
                    receiver_eph: eph_pub,
                    receiver_identity: identity,
                    receiver_hybrid: keys.hybrid_public()?,
                    signature: Vec::new(),
                };
                reply.signature = keys.sign_hybrid(&reply.signed_message(&opening))?;
                let ecdh = eph.diffie_hellman(&x25519_dalek::PublicKey::from(opening.sender_eph));
                let key = channel::channel_key(
                    ecdh.as_bytes(),
                    &kem_ss,
                    Salt::Nearby,
                    &opening.snapshot_id,
                );
                self.start_stream(&key, opening.snapshot_id);
                Ok(Some(reply.to_bytes()?))
            }
            Source::File => {
                let header = self.header.take().ok_or(HistoryFailure::Malformed)?;
                frames::verify_cthf(&header, &local, known, pin)?;
                let key = keys.file_channel_key(
                    &header.sender_eph,
                    header.recipient_kyber_key_id,
                    &header.kem_ct,
                    &header.snapshot_id,
                )?;
                self.start_stream(&key, header.snapshot_id);
                Ok(None)
            }
        }
    }

    fn start_stream(&mut self, key: &[u8; 32], snapshot_id: [u8; 16]) {
        self.cipher = Some(ChunkCipher::new(key, snapshot_id, self.user_id));
        self.reader = Some(cth1::Reader::new(Some(Envelope {
            snapshot_id,
            user_id: self.user_id,
        })));
        self.state = ReceiverState::ChunkLen;
    }
}

// ── The orchestrator's keys ───────────────────────────────────────────────────

impl DeviceKeys for crate::orchestration::Orchestrator {
    fn identity_public(&self) -> Result<[u8; 32], HistoryFailure> {
        self.get_registration_bundle_fields()
            .map_err(|_| HistoryFailure::LocalKeysUnavailable)?
            .identity_public
            .try_into()
            .map_err(|_| HistoryFailure::LocalKeysUnavailable)
    }

    fn hybrid_public(&self) -> Result<Vec<u8>, HistoryFailure> {
        self.hybrid_signature_public_key()
            .ok_or(HistoryFailure::LocalKeysUnavailable)
    }

    fn current_kyber_key_id(&self) -> Result<u32, HistoryFailure> {
        self.current_kyber_spk_upload()
            .ok()
            .flatten()
            .map(|spk| spk.key_id)
            .ok_or(HistoryFailure::LocalKeysUnavailable)
    }

    fn sign_hybrid(&self, message: &[u8]) -> Result<Vec<u8>, HistoryFailure> {
        crate::orchestration::Orchestrator::sign_hybrid(self, message)
            .map_err(|_| HistoryFailure::LocalKeysUnavailable)
    }

    fn kyber_decapsulate(
        &self,
        key_id: u32,
        kem_ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HistoryFailure> {
        let ss = self
            .kyber_prekey_decapsulate(key_id, kem_ct)
            .map_err(|_| HistoryFailure::KemKeyIdMismatch)?;
        Ok(Zeroizing::new(ss.as_ref().to_vec()))
    }

    fn file_channel_key(
        &self,
        sender_eph: &[u8; 32],
        kem_key_id: u32,
        kem_ct: &[u8],
        snapshot_id: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>, HistoryFailure> {
        let key = self
            .history_file_channel_key(sender_eph, kem_key_id, kem_ct, snapshot_id)
            .map_err(|_| HistoryFailure::KemKeyIdMismatch)?;
        let key = Zeroizing::new(key);
        Ok(Zeroizing::new(
            key[..].try_into().map_err(|_| HistoryFailure::Malformed)?,
        ))
    }
}

#[cfg(all(test, feature = "post-quantum"))]
mod tests {
    use super::*;
    use crate::history::record_type;
    use crate::history::wire;

    /// A device's keys held in the clear — for tests only; the orchestrator is the real one.
    struct TestDevice {
        identity: x25519_dalek::StaticSecret,
        hybrid_private: crate::crypto::SecretBytes,
        hybrid_public: Vec<u8>,
        kyber_seed: crate::crypto::SecretBytes,
        kyber_public: Vec<u8>,
        kyber_id: u32,
    }

    impl TestDevice {
        fn new(kyber_id: u32) -> Self {
            use crate::crypto::provider::CryptoProvider;
            use crate::crypto::suites::hybrid::HybridSuiteProvider;
            let (hybrid_private, hybrid_public) =
                HybridSuiteProvider::generate_signature_keys().unwrap();
            let (kyber_seed, kyber_public) = crate::crypto::pq_x3dh::mlkem1024_generate().unwrap();
            Self {
                identity: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
                hybrid_private,
                hybrid_public,
                kyber_seed,
                kyber_public,
                kyber_id,
            }
        }

        fn peer(&self) -> PeerKeys {
            PeerKeys {
                identity_public: x25519_dalek::PublicKey::from(&self.identity).to_bytes(),
                hybrid_public: self.hybrid_public.clone(),
                kyber_prekey_public: self.kyber_public.clone(),
                kyber_prekey_id: self.kyber_id,
            }
        }
    }

    impl DeviceKeys for TestDevice {
        fn identity_public(&self) -> Result<[u8; 32], HistoryFailure> {
            Ok(x25519_dalek::PublicKey::from(&self.identity).to_bytes())
        }
        fn hybrid_public(&self) -> Result<Vec<u8>, HistoryFailure> {
            Ok(self.hybrid_public.clone())
        }
        fn current_kyber_key_id(&self) -> Result<u32, HistoryFailure> {
            Ok(self.kyber_id)
        }
        fn sign_hybrid(&self, message: &[u8]) -> Result<Vec<u8>, HistoryFailure> {
            use crate::crypto::provider::CryptoProvider;
            use crate::crypto::suites::hybrid::HybridSuiteProvider;
            HybridSuiteProvider::sign(&self.hybrid_private, message)
                .map_err(|_| HistoryFailure::SignatureInvalid)
        }
        fn kyber_decapsulate(
            &self,
            _: u32,
            kem_ct: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, HistoryFailure> {
            let ss =
                crate::crypto::pq_x3dh::mlkem1024_decapsulate(self.kyber_seed.as_ref(), kem_ct)
                    .map_err(|_| HistoryFailure::Malformed)?;
            Ok(Zeroizing::new(ss.as_ref().to_vec()))
        }
        fn file_channel_key(
            &self,
            sender_eph: &[u8; 32],
            kem_key_id: u32,
            kem_ct: &[u8],
            snapshot_id: &[u8; 16],
        ) -> Result<Zeroizing<[u8; 32]>, HistoryFailure> {
            let ecdh = self
                .identity
                .diffie_hellman(&x25519_dalek::PublicKey::from(*sender_eph));
            let kem = self.kyber_decapsulate(kem_key_id, kem_ct)?;
            Ok(channel::channel_key(
                ecdh.as_bytes(),
                &kem,
                Salt::File,
                snapshot_id,
            ))
        }
    }

    const USER: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];

    fn manifest(snapshot_id: [u8; 16], phase: u8) -> Vec<u8> {
        let mut m = vec![wire::tag(1, 0), 1, wire::tag(2, 2), 16];
        m.extend_from_slice(&snapshot_id);
        m.extend_from_slice(&[wire::tag(3, 2), 16]);
        m.extend_from_slice(&USER);
        m.extend_from_slice(&[wire::tag(13, 0), phase]);
        m
    }

    /// Drive a receiver by `need()` over `bytes`, as a platform reading a socket would. Stops at
    /// `AwaitKeys` and resumes after `accept`.
    fn drive(
        receiver: &mut Receiver,
        bytes: &[u8],
        at: &mut usize,
        events: &mut Vec<Event>,
    ) -> Result<Status, HistoryFailure> {
        loop {
            let need = receiver.need();
            if need == 0 {
                return Ok(receiver.status());
            }
            // Deliver in two halves where possible, to exercise partial feeds.
            let end = (*at + need).min(bytes.len());
            if *at == end {
                return Ok(Status::NeedMore);
            }
            let mid = *at + (end - *at).div_ceil(2);
            for part in [&bytes[*at..mid], &bytes[mid..end]] {
                let (ev, status) = receiver.feed(part)?;
                events.extend(ev);
                if !matches!(status, Status::NeedMore) {
                    *at = end;
                    return Ok(status);
                }
            }
            *at = end;
        }
    }

    fn media_bytes(events: &[Event]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::MediaBytes(b) => Some(b.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    /// Both ends over the local network: opening, directory keys, reply, then a transcript and a
    /// blob larger than several chunks, received byte-exact and ended cleanly.
    #[test]
    fn a_nearby_transfer_arrives_whole() {
        let old = TestDevice::new(1);
        let new = TestDevice::new(7);
        let mut sender = Sender::nearby(&old, USER, &new.peer(), false, None).unwrap();
        let mut receiver = Receiver::new(Source::Nearby, USER);

        let mut events = Vec::new();
        let opening = sender.first_frame().to_vec();
        let mut at = 0;
        let status = drive(&mut receiver, &opening, &mut at, &mut events).unwrap();
        assert_eq!(
            status,
            Status::AwaitKeys {
                sender_device_id: device_id_raw(&old.identity_public().unwrap())
            }
        );
        let reply = receiver
            .accept(&new, &old.peer().known(), &Pin::BundleOnly)
            .unwrap()
            .unwrap();
        sender.accept_reply(&reply).unwrap();

        let blob: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let mut wire_bytes = Vec::new();
        sender
            .push_record(
                record_type::MANIFEST,
                &manifest(sender.snapshot_id(), 3),
                &mut wire_bytes,
            )
            .unwrap();
        sender
            .push_record(record_type::MESSAGE, &[wire::tag(6, 2), 0], &mut wire_bytes)
            .unwrap();
        sender
            .begin_media("m", "image/png", blob.len() as u64, &mut wire_bytes)
            .unwrap();
        for piece in blob.chunks(100_000) {
            sender.push_media(piece, &mut wire_bytes).unwrap();
        }
        sender.finish(&mut wire_bytes).unwrap();

        let mut at = 0;
        let status = drive(&mut receiver, &wire_bytes, &mut at, &mut events).unwrap();
        assert_eq!(status, Status::Done);
        assert_eq!(at, wire_bytes.len(), "everything written was read");
        assert_eq!(media_bytes(&events), blob);
        assert_eq!(events.last(), Some(&Event::End));
    }

    #[test]
    fn a_file_transfer_arrives_whole_and_a_file_for_another_account_is_refused() {
        let old = TestDevice::new(1);
        let new = TestDevice::new(7);
        let mut sender = Sender::file(&old, USER, &new.peer()).unwrap();
        let mut file = sender.first_frame().to_vec();
        sender
            .push_record(
                record_type::MANIFEST,
                &manifest(sender.snapshot_id(), 3),
                &mut file,
            )
            .unwrap();
        sender
            .push_record(record_type::CONTACT, &[wire::tag(2, 2), 1, b'x'], &mut file)
            .unwrap();
        sender.finish(&mut file).unwrap();

        let mut receiver = Receiver::new(Source::File, USER);
        let (mut events, mut at) = (Vec::new(), 0);
        assert!(matches!(
            drive(&mut receiver, &file, &mut at, &mut events).unwrap(),
            Status::AwaitKeys { .. }
        ));
        assert_eq!(
            receiver
                .accept(&new, &old.peer().known(), &Pin::BundleOnly)
                .unwrap(),
            None
        );
        assert_eq!(
            drive(&mut receiver, &file, &mut at, &mut events).unwrap(),
            Status::Done
        );
        assert_eq!(events.len(), 3);

        let mut elsewhere = Receiver::new(Source::File, [9; 16]);
        assert_eq!(
            drive(&mut elsewhere, &file, &mut 0, &mut Vec::new()),
            Err(HistoryFailure::UserMismatch)
        );
    }

    /// The manifest must name the snapshot the opening announced: an encoder that fills the two
    /// carriers differently is refused before any record is applied.
    #[test]
    fn a_manifest_for_another_snapshot_is_refused() {
        let old = TestDevice::new(1);
        let new = TestDevice::new(7);
        let mut sender = Sender::file(&old, USER, &new.peer()).unwrap();
        let mut file = sender.first_frame().to_vec();
        sender
            .push_record(record_type::MANIFEST, &manifest([0x55; 16], 3), &mut file)
            .unwrap();
        sender.finish(&mut file).unwrap();

        let mut receiver = Receiver::new(Source::File, USER);
        let (mut events, mut at) = (Vec::new(), 0);
        drive(&mut receiver, &file, &mut at, &mut events).unwrap();
        receiver
            .accept(&new, &old.peer().known(), &Pin::BundleOnly)
            .unwrap();
        assert_eq!(
            drive(&mut receiver, &file, &mut at, &mut events),
            Err(HistoryFailure::EnvelopeManifestMismatch)
        );
        assert!(events.is_empty(), "no record applied");
    }

    #[test]
    fn a_verified_skip_ends_without_a_reply() {
        let old = TestDevice::new(1);
        let new = TestDevice::new(7);
        let sender = Sender::nearby(&old, USER, &new.peer(), true, None).unwrap();
        let mut receiver = Receiver::new(Source::Nearby, USER);
        let opening = sender.first_frame().to_vec();
        drive(&mut receiver, &opening, &mut 0, &mut Vec::new()).unwrap();
        assert_eq!(
            receiver
                .accept(&new, &old.peer().known(), &Pin::BundleOnly)
                .unwrap(),
            None
        );
        assert_eq!(receiver.need(), 0);
        assert_eq!(receiver.feed(&[]).unwrap().1, Status::Skipped);
    }

    /// A reply from any device but the one the opening named is refused, and the sender never
    /// streams: a LAN peer cannot answer in the new device's place.
    #[test]
    fn a_reply_from_another_device_is_refused() {
        let old = TestDevice::new(1);
        let new = TestDevice::new(7);
        let impostor = TestDevice::new(7);
        let mut sender = Sender::nearby(&old, USER, &new.peer(), false, None).unwrap();
        let mut receiver = Receiver::new(Source::Nearby, USER);
        drive(
            &mut receiver,
            sender.first_frame(),
            &mut 0,
            &mut Vec::new(),
        )
        .unwrap();
        // The impostor cannot pass the opening's check (the opening names the new device) — so
        // build its reply by hand, signed with its own key.
        let opening = Opening::parse(sender.first_frame()).unwrap();
        let mut reply = Reply {
            receiver_eph: [1; 32],
            receiver_identity: impostor.identity_public().unwrap(),
            receiver_hybrid: impostor.hybrid_public.clone(),
            signature: Vec::new(),
        };
        reply.signature = impostor
            .sign_hybrid(&reply.signed_message(&opening))
            .unwrap();
        assert_eq!(
            sender.accept_reply(&reply.to_bytes().unwrap()),
            Err(HistoryFailure::IdentityMismatch)
        );
        assert_eq!(
            sender.push_record(
                record_type::MANIFEST,
                &manifest([0; 16], 1),
                &mut Vec::new()
            ),
            Err(HistoryFailure::Malformed),
            "no stream without an accepted reply"
        );
    }

    /// Chunks reordered on the wire do not open; truncation before EOF is not a short snapshot.
    #[test]
    fn a_reordered_or_truncated_stream_fails_closed() {
        let old = TestDevice::new(1);
        let new = TestDevice::new(7);
        let mut sender = Sender::file(&old, USER, &new.peer()).unwrap();
        let header_len = sender.first_frame().len();
        let mut file = sender.first_frame().to_vec();
        sender
            .push_record(
                record_type::MANIFEST,
                &manifest(sender.snapshot_id(), 3),
                &mut file,
            )
            .unwrap();
        sender.begin_media("m", "", 200_000, &mut file).unwrap();
        sender.push_media(&vec![3u8; 200_000], &mut file).unwrap();
        sender.finish(&mut file).unwrap();

        let open = |bytes: &[u8]| {
            let mut r = Receiver::new(Source::File, USER);
            let (mut ev, mut at) = (Vec::new(), 0);
            drive(&mut r, bytes, &mut at, &mut ev)?;
            r.accept(&new, &old.peer().known(), &Pin::BundleOnly)?;
            drive(&mut r, bytes, &mut at, &mut ev)
        };
        assert_eq!(open(&file), Ok(Status::Done));

        // Swap the first two full chunks.
        let chunk = LEN_PREFIX + channel::MAX_SEALED_CHUNK;
        let mut swapped = file.clone();
        let (a, b) = (header_len, header_len + chunk);
        let first = file[a..a + chunk].to_vec();
        swapped.copy_within(b..b + chunk, a);
        swapped[b..b + chunk].copy_from_slice(&first);
        assert_eq!(open(&swapped), Err(HistoryFailure::ChunkOpenFailed));

        // Cut before EOF: the reader waits; the end of the input makes it a failure.
        let cut = &file[..file.len() - 4];
        let mut r = Receiver::new(Source::File, USER);
        let (mut ev, mut at) = (Vec::new(), 0);
        drive(&mut r, cut, &mut at, &mut ev).unwrap();
        r.accept(&new, &old.peer().known(), &Pin::BundleOnly)
            .unwrap();
        assert_eq!(drive(&mut r, cut, &mut at, &mut ev), Ok(Status::NeedMore));
        assert_eq!(r.end_of_input(), Err(HistoryFailure::Truncated));
    }
}
