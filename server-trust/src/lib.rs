//! The bytes of a Konstruct server signature — one format for clients, servers and the root tool.
//!
//! The server signs sender certificates and Key Transparency tree heads; the offline root signs
//! delegations of the server's keys; clients check both. All three sides must build the same
//! bytes, and before this crate there was nothing to make them: the certificate signature was a
//! bare concatenation reimplemented in the server, the core and Swift. Here is the only place the
//! format is written. The signature primitive (hybrid Ed25519 + ML-DSA-65, both halves must
//! verify) stays with each side's crypto, whose parity is pinned separately; this crate has no
//! cryptographic dependency beyond SHA-256 for key ids.
//!
//! Decision: `construct-docs/decisions/server-keys-rooted-offline-and-hybrid.md`.
//!
//! ```text
//! delegation = 0x01 ‖ purpose(1) ‖ BE64(not_before) ‖ BE64(not_after)
//!              ‖ public_key(1984) ‖ root_signature(3373)                     — 5 375 bytes
//! signed by the root:   "konstruct/v1/delegation" ‖ 0x01 ‖ purpose ‖ BE64 ‖ BE64 ‖ public_key
//! kid       = SHA-256("konstruct/v1/kid" ‖ public_key)[0..16]
//! signed by a key:      label(purpose) ‖ kid ‖ body
//! ```
//!
//! The kid is derived from the key, so the id a signature names and the key that checks it cannot
//! disagree. Every message starts with a label naming what it is, and every variable-length field
//! in a body is length-prefixed — the certificate signature before this had neither, so `"ab"+"c"`
//! and `"a"+"bc"` signed the same bytes and a key signing two kinds of message could not tell them
//! apart.

use sha2::{Digest, Sha256};

/// Hybrid signature public key: Ed25519 (32) ‖ ML-DSA-65 (1952).
pub const HYBRID_PUBLIC_KEY_LEN: usize = 32 + 1952;
/// Hybrid signature: Ed25519 (64) ‖ ML-DSA-65 (3309).
pub const HYBRID_SIGNATURE_LEN: usize = 64 + 3309;

/// Format version of a delegation.
pub const DELEGATION_VERSION: u8 = 1;
/// Length of a key id.
pub const KID_LEN: usize = 16;
/// Length of an encoded delegation.
pub const DELEGATION_LEN: usize = 1 + 1 + 8 + 8 + HYBRID_PUBLIC_KEY_LEN + HYBRID_SIGNATURE_LEN;

/// A sender certificate lives a day (identity-service); the most one may claim.
pub const SENDER_CERT_MAX_LIFETIME_SECS: i64 = 86_400;
/// How long the relay holds an undelivered message (`MESSAGE_TTL_DAYS=7` in construct-server).
pub const MAX_DELIVERY_AGE_SECS: i64 = 7 * 86_400;

const DELEGATION_LABEL: &[u8] = b"konstruct/v1/delegation";
const KID_LABEL: &[u8] = b"konstruct/v1/kid";

/// A server key id.
pub type Kid = [u8; KID_LEN];

/// What a server key may sign. One key per purpose: a leaked sticker key signs no certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    SenderCert = 1,
    KtHead = 2,
    StickerManifest = 3,
}

impl Purpose {
    pub const ALL: [Purpose; 3] = [Self::SenderCert, Self::KtHead, Self::StickerManifest];

    pub fn from_byte(b: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|p| *p as u8 == b)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::SenderCert => "sender-cert",
            Self::KtHead => "kt-head",
            Self::StickerManifest => "sticker-manifest",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// The label every message signed for this purpose starts with.
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::SenderCert => b"konstruct/v1/sender-cert",
            Self::KtHead => b"konstruct/v1/kt-head",
            Self::StickerManifest => b"konstruct/v1/sticker-manifest",
        }
    }

    /// How long after its key's window closes a signature of this purpose is still accepted.
    ///
    /// The holder of a leaked key writes whatever signing time it likes, so this — measured
    /// against the verifier's clock — is what ends a leak, not the window.
    /// - A sender certificate signed on the window's last second lives a day and then rides a
    ///   message the relay holds up to `MAX_DELIVERY_AGE_SECS`; refusing earlier would drop genuine
    ///   first messages sent in a key's last days.
    /// - A tree head is checked when it is fetched: no grace.
    /// - A sticker manifest is signed once and read for as long as the pack is installed, so it is
    ///   not bounded; a leaked sticker key forges sticker packs and nothing else (open question in
    ///   the decision: re-sign packs on rotation instead).
    pub fn grace_secs(self) -> Option<i64> {
        match self {
            Self::SenderCert => Some(SENDER_CERT_MAX_LIFETIME_SECS + MAX_DELIVERY_AGE_SECS),
            Self::KtHead => Some(0),
            Self::StickerManifest => None,
        }
    }
}

/// A format error: the bytes are not a delegation, or a field does not fit its length prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed server-trust bytes")]
pub struct Malformed;

/// The id of a server key.
pub fn kid_of(public_key: &[u8]) -> Kid {
    let digest = Sha256::new()
        .chain_update(KID_LABEL)
        .chain_update(public_key)
        .finalize();
    digest[..KID_LEN].try_into().expect("SHA-256 is 32 bytes")
}

/// A root-signed statement: this key may sign for `purpose` between the two instants. Parsing and
/// building only — whether a pinned root signed it is the verifier's question.
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

    /// What a root signs for this delegation.
    pub fn signable(&self) -> Vec<u8> {
        delegation_signable(
            self.purpose,
            self.not_before,
            self.not_after,
            &self.public_key,
        )
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

    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() != DELEGATION_LEN || bytes[0] != DELEGATION_VERSION {
            return Err(Malformed);
        }
        let purpose = Purpose::from_byte(bytes[1]).ok_or(Malformed)?;
        let be64 = |at: usize| i64::from_be_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let key_at = 18;
        let sig_at = key_at + HYBRID_PUBLIC_KEY_LEN;
        let d = Self {
            purpose,
            not_before: be64(2),
            not_after: be64(10),
            public_key: bytes[key_at..sig_at].to_vec(),
            root_signature: bytes[sig_at..].to_vec(),
        };
        if d.not_before >= d.not_after {
            return Err(Malformed);
        }
        Ok(d)
    }
}

/// What a root signs: `"konstruct/v1/delegation" ‖ version ‖ purpose ‖ BE64 ‖ BE64 ‖ public_key`.
pub fn delegation_signable(
    purpose: Purpose,
    not_before: i64,
    not_after: i64,
    public_key: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(DELEGATION_LABEL.len() + 18 + public_key.len());
    m.extend_from_slice(DELEGATION_LABEL);
    m.push(DELEGATION_VERSION);
    m.push(purpose as u8);
    m.extend_from_slice(&not_before.to_be_bytes());
    m.extend_from_slice(&not_after.to_be_bytes());
    m.extend_from_slice(public_key);
    m
}

/// What a server key signs: `label(purpose) ‖ kid ‖ body`.
pub fn server_signable(purpose: Purpose, kid: &Kid, body: &[u8]) -> Vec<u8> {
    let label = purpose.label();
    let mut m = Vec::with_capacity(label.len() + KID_LEN + body.len());
    m.extend_from_slice(label);
    m.extend_from_slice(kid);
    m.extend_from_slice(body);
    m
}

fn put_lp(out: &mut Vec<u8>, field: &[u8]) -> Result<(), Malformed> {
    let len = u16::try_from(field.len()).map_err(|_| Malformed)?;
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
) -> Result<Vec<u8>, Malformed> {
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
pub fn sticker_manifest_body(canonical: &[u8]) -> Result<Vec<u8>, Malformed> {
    let len = u32::try_from(canonical.len()).map_err(|_| Malformed)?;
    let mut b = Vec::with_capacity(4 + canonical.len());
    b.extend_from_slice(&len.to_be_bytes());
    b.extend_from_slice(canonical);
    Ok(b)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_fields_cannot_slide_into_each_other() {
        let a = sender_cert_body("ab", "c", &[1; 32], "d", 1, 2).unwrap();
        let b = sender_cert_body("a", "bc", &[1; 32], "d", 1, 2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_delegation_round_trips_and_rejects_a_bad_window() {
        let d = Delegation {
            purpose: Purpose::KtHead,
            not_before: 1,
            not_after: 2,
            public_key: vec![7; HYBRID_PUBLIC_KEY_LEN],
            root_signature: vec![9; HYBRID_SIGNATURE_LEN],
        };
        let bytes = d.encode();
        assert_eq!(bytes.len(), DELEGATION_LEN);
        assert_eq!(Delegation::decode(&bytes), Ok(d.clone()));
        let backwards = Delegation {
            not_before: 2,
            not_after: 2,
            ..d
        };
        assert_eq!(Delegation::decode(&backwards.encode()), Err(Malformed));
        assert_eq!(Delegation::decode(&bytes[1..]), Err(Malformed));
    }

    #[test]
    fn every_purpose_has_its_own_label_and_byte() {
        for p in Purpose::ALL {
            assert_eq!(Purpose::from_byte(p as u8), Some(p));
            assert_eq!(Purpose::from_name(p.name()), Some(p));
            assert!(p.label().starts_with(b"konstruct/v1/"));
        }
        let labels: std::collections::HashSet<_> = Purpose::ALL.iter().map(|p| p.label()).collect();
        assert_eq!(labels.len(), Purpose::ALL.len());
    }

    #[test]
    fn the_root_signed_message_is_fixed() {
        // Conformance anchor: a change here is a format change — every server, client and the
        // offline tool must change with it.
        let m = delegation_signable(Purpose::KtHead, 1, 2, &[0xAB; 4]);
        assert_eq!(
            hex::encode(m),
            "6b6f6e7374727563742f76312f64656c65676174696f6e010200000000000000010000000000000002abababab"
        );
        assert_eq!(
            kid_of(&[0xAB; 4]).as_slice(),
            &Sha256::digest(b"konstruct/v1/kid\xab\xab\xab\xab")[..16]
        );
    }
}
