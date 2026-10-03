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
//! The bytes — what a root and a server key sign, the delegation encoding, key ids — are the
//! `construct-server-trust` crate, shared with the server and the root tool so that no side
//! rebuilds them. This module adds the signature (this crate's hybrid suite) and the decisions.

use crate::crypto::SecretBytes;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::hybrid::{
    HYBRID_SIG_PUBLIC_KEY_SIZE, HYBRID_SIGNATURE_SIZE, HybridSuiteProvider,
};

pub use construct_server_trust::{
    DELEGATION_LEN, Delegation, KID_LEN, Kid, MAX_DELIVERY_AGE_SECS, Purpose,
    SENDER_CERT_MAX_LIFETIME_SECS, fingerprint, kid_of, kt_head_body, sender_cert_body,
    server_signable, sticker_manifest_body,
};

// The format crate states the hybrid sizes for its encoding; the suite is what produces them.
const _: () = assert!(construct_server_trust::HYBRID_PUBLIC_KEY_LEN == HYBRID_SIG_PUBLIC_KEY_SIZE);
const _: () = assert!(construct_server_trust::HYBRID_SIGNATURE_LEN == HYBRID_SIGNATURE_SIZE);

/// The roots this build trusts, as hex of the 1984-byte hybrid public key: the primary first,
/// then the backup. Empty until the root ceremony (manual §3.1) — with no root, no delegation is
/// admitted and nothing verifies, which is why no caller depends on this module yet.
pub const PINNED_ROOTS: &[&str] = &[];

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

impl From<construct_server_trust::Malformed> for TrustError {
    fn from(_: construct_server_trust::Malformed) -> Self {
        Self::Malformed
    }
}

/// Delegate `public_key` with `root_private_key` (the 2016-byte hybrid private key). Used by the
/// offline tool, never by a client or a server.
pub fn issue_delegation(
    root_private_key: &SecretBytes,
    purpose: Purpose,
    not_before: i64,
    not_after: i64,
    public_key: &[u8],
) -> Result<Delegation, TrustError> {
    if public_key.len() != HYBRID_SIG_PUBLIC_KEY_SIZE || not_before >= not_after {
        return Err(TrustError::Malformed);
    }
    let mut d = Delegation {
        purpose,
        not_before,
        not_after,
        public_key: public_key.to_vec(),
        root_signature: Vec::new(),
    };
    d.root_signature = HybridSuiteProvider::sign(root_private_key, &d.signable())
        .map_err(|_| TrustError::Malformed)?;
    Ok(d)
}

/// Whether one of `roots` signed `delegation`.
pub fn verify_rooted(delegation: &Delegation, roots: &[Vec<u8>]) -> Result<(), TrustError> {
    if roots.is_empty() {
        return Err(TrustError::NoRoot);
    }
    let message = delegation.signable();
    if roots
        .iter()
        .any(|root| HybridSuiteProvider::verify(root, &message, &delegation.root_signature).is_ok())
    {
        Ok(())
    } else {
        Err(TrustError::NotRooted)
    }
}

/// Sign `body` for `purpose` with a delegated server key. Tests and tools only: the server signs
/// with its own crypto over the same `server_signable` bytes.
pub fn sign_as_server(
    purpose: Purpose,
    private_key: &SecretBytes,
    public_key: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, TrustError> {
    let message = server_signable(purpose, &kid_of(public_key), body);
    HybridSuiteProvider::sign(private_key, &message).map_err(|_| TrustError::Malformed)
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
        verify_rooted(&delegation, &self.roots)?;
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
        let d = issue_delegation(&root_sk, purpose, T0, T0 + 90 * DAY, &server_pk).unwrap();
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
            issue_delegation(&other_root_sk, Purpose::KtHead, T0, T0 + DAY, &server_pk).unwrap();
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
        let d = issue_delegation(&backup_sk, Purpose::KtHead, T0, T0 + DAY, &server_pk).unwrap();
        let mut ring = ServerKeyRing::new(vec![primary_pk, backup_pk]);
        assert!(ring.admit(&d.encode()).is_ok());
    }

    #[test]
    fn every_delegated_field_is_covered_by_the_root_signature() {
        let (root_sk, root_pk) = key(1);
        let (_, server_pk) = key(10);
        let good = issue_delegation(&root_sk, Purpose::SenderCert, T0, T0 + DAY, &server_pk)
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
            let d = issue_delegation(&root_sk, p, T0, T0 + DAY, &server_pk).unwrap();
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
}
