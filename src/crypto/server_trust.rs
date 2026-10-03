//! Server keys rooted offline: which server signatures this client accepts, and why.
//!
//! ## What it replaces
//!
//! Until this module the server signed sender certificates, Key Transparency tree heads and
//! sticker manifests with one Ed25519 key (`BUNDLE_SIGNING_KEY`), with no key id and no lifetime,
//! and the clients learned that key from the server's own `/.well-known` — so whoever held the
//! server decided which key was right, and a leaked key signed for ever. Decision:
//! `construct-docs/decisions/server-keys-rooted-offline-and-hybrid.md`.
//!
//! ## What it is
//!
//! Two steps, both hybrid (Ed25519 + ML-DSA-65, both halves must verify):
//!
//! ```text
//! root (offline, pinned in this crate: PINNED_ROOTS)
//!   └─ delegation: "this key, for this purpose, from not_before to not_after"  — signed by a root
//!        └─ server signature: purpose label ‖ kid ‖ body                       — signed by that key
//! ```
//!
//! A root never touches a server; its private half is two 32-byte seeds kept on paper and an
//! offline machine (`construct-docs/manuals&instructions/server-root-key-ceremony.md`), written as
//! 48 words (`root_words`). A server key is accepted only through a delegation a pinned root
//! signed, only for the purpose the delegation names, and only for signatures made inside its
//! window. A server that serves a delegation cannot have made it.
//!
//! The key id is derived from the key (`kid_of`), so the id a signature names and the key that
//! verifies it cannot disagree — there is no second carrier to keep in step.
//!
//! ## Wire
//!
//! ```text
//! delegation = 0x01 ‖ purpose(1) ‖ BE64(not_before) ‖ BE64(not_after)
//!              ‖ public_key(1984) ‖ root_signature(3373)                     — 5 375 bytes
//! signed by the root:   "konstruct/v1/delegation" ‖ 0x01 ‖ purpose ‖ BE64 ‖ BE64 ‖ public_key
//! kid       = SHA-256("konstruct/v1/kid" ‖ public_key)[0..16]
//! signed by the key:    label(purpose) ‖ kid ‖ body
//! ```
//!
//! Every variable-length field inside a body is length-prefixed (`BE16(len) ‖ bytes`), and every
//! signed message starts with a label naming what it is — the Ed25519 certificate signature before
//! this had neither, so a key signing two kinds of message could not tell them apart.

use sha2::{Digest, Sha256};

use crate::crypto::SecretBytes;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::sealed_sender::MAX_DELIVERY_AGE_SECS;
use crate::crypto::suites::hybrid::{
    HYBRID_SIG_PUBLIC_KEY_SIZE, HYBRID_SIGNATURE_SIZE, HybridSuiteProvider,
};

/// The roots this build trusts, as hex of the 1984-byte hybrid public key: the primary first,
/// then the backup. Empty until the root ceremony (manual §3.1) — with no root, no delegation is
/// admitted and nothing verifies, which is why no caller depends on this module yet.
pub const PINNED_ROOTS: &[&str] = &[];

/// Format version of a delegation.
pub const DELEGATION_VERSION: u8 = 1;
/// Length of a key id.
pub const KID_LEN: usize = 16;
/// Length of an encoded delegation.
pub const DELEGATION_LEN: usize =
    1 + 1 + 8 + 8 + HYBRID_SIG_PUBLIC_KEY_SIZE + HYBRID_SIGNATURE_SIZE;

const DELEGATION_LABEL: &[u8] = b"konstruct/v1/delegation";
const KID_LABEL: &[u8] = b"konstruct/v1/kid";

/// A sender certificate lives a day (identity-service); the most it may claim.
pub const SENDER_CERT_MAX_LIFETIME_SECS: i64 = 86_400;

/// A server key id: the first 16 bytes of a labelled hash of the key.
pub type Kid = [u8; KID_LEN];

/// What a server key may sign. One key per purpose: a leaked sticker key signs no certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    SenderCert = 1,
    KtHead = 2,
    StickerManifest = 3,
}

impl Purpose {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::SenderCert),
            2 => Some(Self::KtHead),
            3 => Some(Self::StickerManifest),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::SenderCert => "sender-cert",
            Self::KtHead => "kt-head",
            Self::StickerManifest => "sticker-manifest",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        [Self::SenderCert, Self::KtHead, Self::StickerManifest]
            .into_iter()
            .find(|p| p.name() == name)
    }

    /// The label every message signed for this purpose starts with.
    fn label(self) -> &'static [u8] {
        match self {
            Self::SenderCert => b"konstruct/v1/sender-cert",
            Self::KtHead => b"konstruct/v1/kt-head",
            Self::StickerManifest => b"konstruct/v1/sticker-manifest",
        }
    }

    /// How long after its key's window closes a signature of this purpose is still accepted.
    ///
    /// The holder of a leaked key writes whatever `signed_at` it likes, so this — measured against
    /// the verifier's clock — is what ends a leak, not the window.
    /// - A sender certificate signed on the window's last second lives a day and then rides a
    ///   message the relay holds up to `MAX_DELIVERY_AGE_SECS`; refusing earlier would drop
    ///   genuine first messages sent in a key's last days.
    /// - A tree head is checked when it is fetched: no grace.
    /// - A sticker manifest is signed once and read for as long as the pack is installed, so it is
    ///   not bounded; a leaked sticker key forges sticker packs and nothing else (open question in
    ///   the decision: re-sign packs on rotation instead).
    fn grace_secs(self) -> Option<i64> {
        match self {
            Self::SenderCert => Some(SENDER_CERT_MAX_LIFETIME_SECS + MAX_DELIVERY_AGE_SECS),
            Self::KtHead => Some(0),
            Self::StickerManifest => None,
        }
    }
}

/// Why a server signature or delegation is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    #[error("malformed")]
    Malformed,
    #[error("this build pins no root")]
    NoRoot,
    #[error("no pinned root signed this delegation")]
    NotRooted,
    #[error("no admitted key has this id")]
    UnknownKey,
    #[error("the key was delegated for another purpose")]
    WrongPurpose,
    #[error("signed outside the key's window")]
    OutsideWindow,
    #[error("the key's window closed too long ago")]
    Expired,
    #[error("bad signature")]
    BadSignature,
}

/// The id of a server key.
pub fn kid_of(public_key: &[u8]) -> Kid {
    let digest = Sha256::new()
        .chain_update(KID_LABEL)
        .chain_update(public_key)
        .finalize();
    digest[..KID_LEN].try_into().expect("SHA-256 is 32 bytes")
}

/// A root-signed statement: this key may sign for `purpose` between the two instants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub purpose: Purpose,
    pub not_before: i64,
    pub not_after: i64,
    pub public_key: Vec<u8>,
    pub root_signature: Vec<u8>,
}

impl Delegation {
    pub fn kid(&self) -> Kid {
        kid_of(&self.public_key)
    }

    /// What a root signs.
    fn signable(purpose: Purpose, not_before: i64, not_after: i64, public_key: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(DELEGATION_LABEL.len() + 18 + public_key.len());
        m.extend_from_slice(DELEGATION_LABEL);
        m.push(DELEGATION_VERSION);
        m.push(purpose as u8);
        m.extend_from_slice(&not_before.to_be_bytes());
        m.extend_from_slice(&not_after.to_be_bytes());
        m.extend_from_slice(public_key);
        m
    }

    /// Delegate `public_key` with `root_private_key` (the 2016-byte hybrid private key). Used by
    /// the offline tool, never by a client or a server.
    pub fn issue(
        root_private_key: &SecretBytes,
        purpose: Purpose,
        not_before: i64,
        not_after: i64,
        public_key: &[u8],
    ) -> Result<Self, TrustError> {
        if public_key.len() != HYBRID_SIG_PUBLIC_KEY_SIZE || not_before >= not_after {
            return Err(TrustError::Malformed);
        }
        let message = Self::signable(purpose, not_before, not_after, public_key);
        let root_signature = HybridSuiteProvider::sign(root_private_key, &message)
            .map_err(|_| TrustError::Malformed)?;
        Ok(Self {
            purpose,
            not_before,
            not_after,
            public_key: public_key.to_vec(),
            root_signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DELEGATION_LEN);
        out.push(DELEGATION_VERSION);
        out.push(self.purpose as u8);
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.root_signature);
        out
    }

    /// Parse only; `ServerKeyRing::admit` is what checks it.
    pub fn decode(bytes: &[u8]) -> Result<Self, TrustError> {
        if bytes.len() != DELEGATION_LEN || bytes[0] != DELEGATION_VERSION {
            return Err(TrustError::Malformed);
        }
        let purpose = Purpose::from_byte(bytes[1]).ok_or(TrustError::Malformed)?;
        let be64 = |at: usize| i64::from_be_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let key_at = 18;
        let sig_at = key_at + HYBRID_SIG_PUBLIC_KEY_SIZE;
        Ok(Self {
            purpose,
            not_before: be64(2),
            not_after: be64(10),
            public_key: bytes[key_at..sig_at].to_vec(),
            root_signature: bytes[sig_at..].to_vec(),
        })
    }

    /// Whether one of `roots` signed this delegation.
    pub fn verify_rooted(&self, roots: &[Vec<u8>]) -> Result<(), TrustError> {
        if roots.is_empty() {
            return Err(TrustError::NoRoot);
        }
        if self.not_before >= self.not_after {
            return Err(TrustError::Malformed);
        }
        let message = Self::signable(
            self.purpose,
            self.not_before,
            self.not_after,
            &self.public_key,
        );
        if roots
            .iter()
            .any(|root| HybridSuiteProvider::verify(root, &message, &self.root_signature).is_ok())
        {
            Ok(())
        } else {
            Err(TrustError::NotRooted)
        }
    }
}

/// The message a server key signs: `label(purpose) ‖ kid ‖ body`.
fn server_signable(purpose: Purpose, kid: &Kid, body: &[u8]) -> Vec<u8> {
    let label = purpose.label();
    let mut m = Vec::with_capacity(label.len() + KID_LEN + body.len());
    m.extend_from_slice(label);
    m.extend_from_slice(kid);
    m.extend_from_slice(body);
    m
}

/// Sign `body` for `purpose` with a delegated server key. The server's half of the format; the
/// conformance vectors keep a server that does not link this crate byte-identical to it.
pub fn sign_as_server(
    purpose: Purpose,
    private_key: &SecretBytes,
    public_key: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, TrustError> {
    let message = server_signable(purpose, &kid_of(public_key), body);
    HybridSuiteProvider::sign(private_key, &message).map_err(|_| TrustError::Malformed)
}

fn put_lp(out: &mut Vec<u8>, field: &[u8]) -> Result<(), TrustError> {
    let len = u16::try_from(field.len()).map_err(|_| TrustError::Malformed)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// The body of a sender certificate signature.
pub fn sender_cert_body(
    user_id: &str,
    domain: &str,
    identity_key: &[u8],
    device_id: &str,
    issued_at: i64,
    expires_at: i64,
) -> Result<Vec<u8>, TrustError> {
    let mut b = Vec::with_capacity(
        8 + user_id.len() + domain.len() + identity_key.len() + device_id.len() + 16,
    );
    put_lp(&mut b, user_id.as_bytes())?;
    put_lp(&mut b, domain.as_bytes())?;
    put_lp(&mut b, identity_key)?;
    put_lp(&mut b, device_id.as_bytes())?;
    b.extend_from_slice(&issued_at.to_be_bytes());
    b.extend_from_slice(&expires_at.to_be_bytes());
    Ok(b)
}

/// The body of a tree head signature.
pub fn kt_head_body(tree_size: u64, root_hash: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(40);
    b.extend_from_slice(&tree_size.to_be_bytes());
    b.extend_from_slice(root_hash);
    b
}

/// The body of a sticker manifest signature: its canonical bytes, length-prefixed.
pub fn sticker_manifest_body(canonical: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + canonical.len());
    b.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    b.extend_from_slice(canonical);
    b
}

/// The server keys this client accepts: the pinned roots and the delegations admitted under them.
#[derive(Debug, Clone, Default)]
pub struct ServerKeyRing {
    roots: Vec<Vec<u8>>,
    keys: Vec<Delegation>,
}

impl ServerKeyRing {
    pub fn new(roots: Vec<Vec<u8>>) -> Self {
        Self {
            roots,
            keys: Vec::new(),
        }
    }

    /// A ring over the roots this build pins.
    pub fn pinned() -> Self {
        Self::new(
            PINNED_ROOTS
                .iter()
                .filter_map(|h| hex::decode(h).ok())
                .collect(),
        )
    }

    /// Admit a delegation if a pinned root signed it. A delegation already admitted is kept once.
    pub fn admit(&mut self, encoded: &[u8]) -> Result<Kid, TrustError> {
        let delegation = Delegation::decode(encoded)?;
        delegation.verify_rooted(&self.roots)?;
        let kid = delegation.kid();
        if !self
            .keys
            .iter()
            .any(|k| k.kid() == kid && k.purpose == delegation.purpose)
        {
            self.keys.push(delegation);
        }
        Ok(kid)
    }

    /// Whether the key `kid` names signed `body` for `purpose` at `signed_at`, as seen at `now`.
    pub fn verify(
        &self,
        purpose: Purpose,
        kid: &Kid,
        body: &[u8],
        signature: &[u8],
        signed_at: i64,
        now: i64,
    ) -> Result<(), TrustError> {
        let mut named = self.keys.iter().filter(|k| &k.kid() == kid).peekable();
        if named.peek().is_none() {
            return Err(TrustError::UnknownKey);
        }
        let key = named
            .find(|k| k.purpose == purpose)
            .ok_or(TrustError::WrongPurpose)?;
        if signed_at < key.not_before || signed_at > key.not_after {
            return Err(TrustError::OutsideWindow);
        }
        if let Some(grace) = purpose.grace_secs()
            && now > key.not_after.saturating_add(grace)
        {
            return Err(TrustError::Expired);
        }
        let message = server_signable(purpose, kid, body);
        HybridSuiteProvider::verify(&key.public_key, &message, signature)
            .map_err(|_| TrustError::BadSignature)
    }
}

/// Fingerprint of a public key for a person to compare: SHA-256 as 16 groups of 4 hex digits.
pub fn fingerprint(public_key: &[u8]) -> String {
    let h = hex::encode(Sha256::digest(public_key));
    h.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A root's private half as words: its two 32-byte seeds (Ed25519, then ML-DSA-65), each as a
/// 24-word BIP-39 phrase with its own checksum — 48 words in all.
pub mod root_words {
    use bip39::Mnemonic;
    use zeroize::Zeroizing;

    use crate::crypto::SecretBytes;
    use crate::crypto::suites::hybrid::hybrid_signature_keypair_from_seeds;

    /// Number of words a root is written as.
    pub const WORD_COUNT: usize = 48;

    /// Two seeds → 48 words.
    pub fn encode(ed25519_seed: &[u8; 32], mldsa_seed: &[u8; 32]) -> Zeroizing<String> {
        let a = Mnemonic::from_entropy(ed25519_seed).expect("32 bytes is valid entropy");
        let b = Mnemonic::from_entropy(mldsa_seed).expect("32 bytes is valid entropy");
        Zeroizing::new(format!("{a} {b}"))
    }

    /// 48 words → the two seeds, each phrase's checksum checked. Case and spacing do not matter.
    pub fn decode(words: &str) -> Result<Zeroizing<[u8; 64]>, String> {
        let lower = Zeroizing::new(words.to_lowercase());
        let list: Vec<&str> = lower.split_whitespace().collect();
        if list.len() != WORD_COUNT {
            return Err(format!("expected {WORD_COUNT} words, got {}", list.len()));
        }
        let mut seeds = Zeroizing::new([0u8; 64]);
        for (half, chunk) in list.chunks(24).enumerate() {
            let phrase = Zeroizing::new(chunk.join(" "));
            let m = Mnemonic::parse_normalized(&phrase)
                .map_err(|e| format!("words {}–{}: {e}", half * 24 + 1, half * 24 + 24))?;
            let (entropy, len) = m.to_entropy_array();
            let entropy = Zeroizing::new(entropy);
            if len != 32 {
                return Err("a phrase is not 24 words of 32-byte entropy".into());
            }
            seeds[half * 32..half * 32 + 32].copy_from_slice(&entropy[..32]);
        }
        Ok(seeds)
    }

    /// The hybrid keypair 64 seed bytes determine: `(private, public)`.
    pub fn keypair(seeds: &[u8; 64]) -> (SecretBytes, Vec<u8>) {
        hybrid_signature_keypair_from_seeds(
            seeds[..32].try_into().expect("32"),
            seeds[32..].try_into().expect("32"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suites::hybrid::hybrid_signature_keypair_from_seeds;

    const T0: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn key(seed: u8) -> (SecretBytes, Vec<u8>) {
        hybrid_signature_keypair_from_seeds(&[seed; 32], &[seed.wrapping_add(1); 32])
    }

    struct Setup {
        ring: ServerKeyRing,
        server_sk: SecretBytes,
        server_pk: Vec<u8>,
        kid: Kid,
    }

    fn setup(purpose: Purpose) -> Setup {
        let (root_sk, root_pk) = key(1);
        let (server_sk, server_pk) = key(10);
        let d = Delegation::issue(&root_sk, purpose, T0, T0 + 90 * DAY, &server_pk).unwrap();
        let mut ring = ServerKeyRing::new(vec![root_pk]);
        let kid = ring.admit(&d.encode()).unwrap();
        Setup {
            ring,
            server_sk,
            server_pk,
            kid,
        }
    }

    fn cert_body() -> Vec<u8> {
        sender_cert_body("u", "konstruct.cc", &[7; 32], "d", T0 + DAY, T0 + 2 * DAY).unwrap()
    }

    #[test]
    fn a_signature_through_a_rooted_delegation_verifies() {
        let s = setup(Purpose::SenderCert);
        let body = cert_body();
        let sig = sign_as_server(Purpose::SenderCert, &s.server_sk, &s.server_pk, &body).unwrap();
        assert_eq!(
            s.ring
                .verify(Purpose::SenderCert, &s.kid, &body, &sig, T0 + DAY, T0 + DAY),
            Ok(())
        );
    }

    #[test]
    fn a_delegation_no_pinned_root_signed_is_refused() {
        let (other_root_sk, _) = key(2);
        let (_, root_pk) = key(1);
        let (_, server_pk) = key(10);
        let d =
            Delegation::issue(&other_root_sk, Purpose::KtHead, T0, T0 + DAY, &server_pk).unwrap();
        let mut ring = ServerKeyRing::new(vec![root_pk]);
        assert_eq!(ring.admit(&d.encode()), Err(TrustError::NotRooted));
        assert_eq!(
            ServerKeyRing::new(vec![]).admit(&d.encode()),
            Err(TrustError::NoRoot)
        );
    }

    #[test]
    fn the_backup_root_is_trusted_beside_the_primary() {
        let (_, primary_pk) = key(1);
        let (backup_sk, backup_pk) = key(3);
        let (_, server_pk) = key(10);
        let d = Delegation::issue(&backup_sk, Purpose::KtHead, T0, T0 + DAY, &server_pk).unwrap();
        let mut ring = ServerKeyRing::new(vec![primary_pk, backup_pk]);
        assert!(ring.admit(&d.encode()).is_ok());
    }

    #[test]
    fn every_delegated_field_is_covered_by_the_root_signature() {
        let (root_sk, root_pk) = key(1);
        let (_, server_pk) = key(10);
        let good = Delegation::issue(&root_sk, Purpose::SenderCert, T0, T0 + DAY, &server_pk)
            .unwrap()
            .encode();
        // purpose, not_before, not_after, a key byte, a signature byte in each half
        for at in [1, 9, 17, 18 + 100, 18 + 1984 + 10, DELEGATION_LEN - 1] {
            let mut bad = good.clone();
            bad[at] ^= if at == 1 { 0x03 } else { 0x01 };
            let mut ring = ServerKeyRing::new(vec![root_pk.clone()]);
            assert!(ring.admit(&bad).is_err(), "byte {at} not covered");
        }
    }

    #[test]
    fn a_key_signs_only_for_the_purpose_it_was_delegated() {
        let s = setup(Purpose::StickerManifest);
        let body = kt_head_body(5, &[9; 32]);
        let sig = sign_as_server(Purpose::KtHead, &s.server_sk, &s.server_pk, &body).unwrap();
        assert_eq!(
            s.ring.verify(Purpose::KtHead, &s.kid, &body, &sig, T0, T0),
            Err(TrustError::WrongPurpose)
        );
    }

    #[test]
    fn a_signature_for_one_purpose_does_not_verify_as_another() {
        // Same key delegated twice; the label keeps the two kinds of message apart.
        let (root_sk, root_pk) = key(1);
        let (server_sk, server_pk) = key(10);
        let mut ring = ServerKeyRing::new(vec![root_pk]);
        for p in [Purpose::SenderCert, Purpose::StickerManifest] {
            let d = Delegation::issue(&root_sk, p, T0, T0 + DAY, &server_pk).unwrap();
            ring.admit(&d.encode()).unwrap();
        }
        let body = b"same bytes".to_vec();
        let sig = sign_as_server(Purpose::StickerManifest, &server_sk, &server_pk, &body).unwrap();
        let kid = kid_of(&server_pk);
        assert_eq!(
            ring.verify(Purpose::SenderCert, &kid, &body, &sig, T0, T0),
            Err(TrustError::BadSignature)
        );
    }

    #[test]
    fn a_signature_dated_outside_the_window_is_refused() {
        let s = setup(Purpose::SenderCert);
        let body = cert_body();
        let sig = sign_as_server(Purpose::SenderCert, &s.server_sk, &s.server_pk, &body).unwrap();
        for at in [T0 - 1, T0 + 90 * DAY + 1] {
            assert_eq!(
                s.ring
                    .verify(Purpose::SenderCert, &s.kid, &body, &sig, at, at),
                Err(TrustError::OutsideWindow)
            );
        }
    }

    #[test]
    fn a_certificate_from_the_last_day_opens_until_its_message_could_wait() {
        let s = setup(Purpose::SenderCert);
        let body = cert_body();
        let sig = sign_as_server(Purpose::SenderCert, &s.server_sk, &s.server_pk, &body).unwrap();
        let closed = T0 + 90 * DAY;
        let last = closed + SENDER_CERT_MAX_LIFETIME_SECS + MAX_DELIVERY_AGE_SECS;
        assert_eq!(
            s.ring
                .verify(Purpose::SenderCert, &s.kid, &body, &sig, closed, last),
            Ok(())
        );
        assert_eq!(
            s.ring
                .verify(Purpose::SenderCert, &s.kid, &body, &sig, closed, last + 1),
            Err(TrustError::Expired)
        );
    }

    #[test]
    fn a_tree_head_has_no_grace() {
        let s = setup(Purpose::KtHead);
        let body = kt_head_body(5, &[9; 32]);
        let sig = sign_as_server(Purpose::KtHead, &s.server_sk, &s.server_pk, &body).unwrap();
        let closed = T0 + 90 * DAY;
        assert_eq!(
            s.ring
                .verify(Purpose::KtHead, &s.kid, &body, &sig, closed, closed + 1),
            Err(TrustError::Expired)
        );
    }

    #[test]
    fn a_tampered_body_or_an_unknown_kid_is_refused() {
        let s = setup(Purpose::KtHead);
        let body = kt_head_body(5, &[9; 32]);
        let sig = sign_as_server(Purpose::KtHead, &s.server_sk, &s.server_pk, &body).unwrap();
        let other = kt_head_body(6, &[9; 32]);
        assert_eq!(
            s.ring.verify(Purpose::KtHead, &s.kid, &other, &sig, T0, T0),
            Err(TrustError::BadSignature)
        );
        assert_eq!(
            s.ring
                .verify(Purpose::KtHead, &[0; 16], &body, &sig, T0, T0),
            Err(TrustError::UnknownKey)
        );
    }

    #[test]
    fn both_halves_of_the_hybrid_must_verify() {
        let s = setup(Purpose::KtHead);
        let body = kt_head_body(5, &[9; 32]);
        let sig = sign_as_server(Purpose::KtHead, &s.server_sk, &s.server_pk, &body).unwrap();
        for at in [0, 64 + 5] {
            let mut bad = sig.clone();
            bad[at] ^= 1;
            assert_eq!(
                s.ring.verify(Purpose::KtHead, &s.kid, &body, &bad, T0, T0),
                Err(TrustError::BadSignature),
                "half at {at}"
            );
        }
    }

    #[test]
    fn certificate_fields_cannot_slide_into_each_other() {
        // Without length prefixes "ab"+"c" and "a"+"bc" signed the same bytes.
        let a = sender_cert_body("ab", "c", &[1; 32], "d", 1, 2).unwrap();
        let b = sender_cert_body("a", "bc", &[1; 32], "d", 1, 2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_kid_is_the_key() {
        let (_, a) = key(10);
        let (_, b) = key(11);
        assert_ne!(kid_of(&a), kid_of(&b));
        let s = setup(Purpose::KtHead);
        assert_eq!(s.kid, kid_of(&s.server_pk));
    }

    #[test]
    fn a_root_written_as_words_restores_to_the_same_key() {
        let (sk, pk) = key(1);
        let words = root_words::encode(&[1; 32], &[2; 32]);
        assert_eq!(words.split_whitespace().count(), root_words::WORD_COUNT);
        let seeds = root_words::decode(&words.to_uppercase()).unwrap();
        let (sk2, pk2) = root_words::keypair(&seeds);
        assert_eq!(pk, pk2);
        assert_eq!(sk.expose(), sk2.expose());
    }

    #[test]
    fn a_misspelt_or_swapped_word_is_caught() {
        let words = root_words::encode(&[1; 32], &[2; 32]);
        let mut list: Vec<String> = words.split_whitespace().map(String::from).collect();
        list.swap(3, 4);
        assert!(root_words::decode(&list.join(" ")).is_err());
        assert!(root_words::decode("abandon").is_err());
    }

    #[test]
    fn the_root_signed_message_is_fixed() {
        // Conformance anchor: the bytes a root signs for a fixed delegation. A change here is a
        // format change — every server and offline tool must change with it.
        let m = Delegation::signable(Purpose::KtHead, 1, 2, &[0xAB; 4]);
        assert_eq!(
            hex::encode(m),
            "6b6f6e7374727563742f76312f64656c65676174696f6e010200000000000000010000000000000002abababab"
        );
        assert_eq!(
            hex::encode(kid_of(&[0xAB; 4])),
            hex::encode(&Sha256::digest(b"konstruct/v1/kid\xab\xab\xab\xab")[..16])
        );
    }
}
