//! The handshake frames of a history transfer: CTT1 v2 over the local network, the CTHF file
//! header. Parsed as hostile input — every length is checked before a field is read — and
//! verified in one order: ids, Kyber key id, known keys, QR pin, signature. Only a frame that
//! passes all of it may be decapsulated.
//!
//! ```text
//! CTT1 v2 opening (S→R), 7055 bytes
//!   [4] "CTT1" [1] 0x02 [32] sender_eph [1] type [8] payload_len LE          ← 46-byte prefix,
//!   [32] sender_identity [1984] sender_hybrid [16] snapshot_id                  shared with v1
//!   [16] sender_device_id [16] receiver_device_id [4] receiver_kyber_key_id LE
//!   [1568] kem_ct [3373] sig = hybrid("ctt1v2-s" ‖ eph ‖ identity ‖ hybrid ‖ snapshot
//!                                    ‖ sender_dev ‖ receiver_dev ‖ key_id ‖ kem_ct
//!                                    ‖ type ‖ payload_len)
//! CTT1 v2 reply (R→S), 5421 bytes
//!   [32] receiver_eph [32] receiver_identity [1984] receiver_hybrid
//!   [3373] sig = hybrid("ctt1v2-r" ‖ receiver_eph ‖ sender_eph ‖ receiver_identity
//!                       ‖ receiver_hybrid ‖ snapshot ‖ sender_dev ‖ receiver_dev ‖ kem_ct)
//! CTHF header, 7062 bytes
//!   [4] "CTHF" [1] 0x01 [16] user_id [16] recipient_device_id [16] source_device_id
//!   [16] snapshot_id [32] sender_eph [32] sender_identity [1984] sender_hybrid
//!   [4] recipient_kyber_key_id LE [1568] kem_ct
//!   [3373] sig = hybrid("cthf1" ‖ every field above after the version)
//! ```
//!
//! `kem_ct` is ML-KEM-1024 since PQXDH v2 (the spec's layout still says ML-KEM-768 / 1088); the
//! version bytes did not change, and every frame is length-checked exactly.

use sha2::{Digest, Sha256};

use super::{HistoryFailure, ct_eq};

pub const PREFIX_LEN: usize = 4 + 1 + 32 + 1 + 8;
const EPH: usize = 32;
const IDENTITY: usize = 32;
pub const HYBRID_PUBLIC: usize = 32 + 1952;
const ID16: usize = 16;
const KEY_ID: usize = 4;
pub const KEM_CT: usize = 1568;
pub const HYBRID_SIGNATURE: usize = 64 + 3309;
pub const OPENING_LEN: usize =
    PREFIX_LEN + IDENTITY + HYBRID_PUBLIC + ID16 + ID16 + ID16 + KEY_ID + KEM_CT + HYBRID_SIGNATURE;
pub const REPLY_LEN: usize = EPH + IDENTITY + HYBRID_PUBLIC + HYBRID_SIGNATURE;
pub const CTHF_HEADER_LEN: usize =
    4 + 1 + ID16 * 4 + EPH + IDENTITY + HYBRID_PUBLIC + KEY_ID + KEM_CT + HYBRID_SIGNATURE;

const CTT1_MAGIC: &[u8; 4] = b"CTT1";
const CTHF_MAGIC: &[u8; 4] = b"CTHF";
const CTT1_V1: u8 = 0x01;
const CTT1_V2: u8 = 0x02;
const CTHF_V1: u8 = 0x01;
/// An unauthenticated payload length above this is refused before anything else is read.
const MAX_PAYLOAD_LEN: u64 = 2 * 1024 * 1024 * 1024;

const SENDER_TAG: &[u8] = b"ctt1v2-s";
const RECEIVER_TAG: &[u8] = b"ctt1v2-r";
const FILE_TAG: &[u8] = b"cthf1";

/// CTT1 transfer types. Backup (0x01) is the PIN-HMAC v1 path and is not history.
pub mod transfer_type {
    pub const BACKUP: u8 = 0x01;
    pub const HISTORY: u8 = 0x02;
    pub const HISTORY_SKIPPED: u8 = 0x03;
}

/// A device's raw 16-byte id: `SHA256(identity_public)[0..16]` — the bytes behind the hex
/// `derive_device_id` returns.
pub fn device_id_raw(identity_public: &[u8]) -> [u8; 16] {
    Sha256::digest(identity_public)[..16]
        .try_into()
        .expect("16 of 32 bytes")
}

/// The 46 bytes both CTT1 versions begin with, read before deciding how much more to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    pub version: u8,
    pub sender_eph: [u8; 32],
    pub transfer_type: u8,
    pub payload_len: u64,
}

impl Prefix {
    pub fn parse(bytes: &[u8]) -> Result<Self, HistoryFailure> {
        if bytes.len() != PREFIX_LEN || &bytes[..4] != CTT1_MAGIC {
            return Err(HistoryFailure::Malformed);
        }
        let version = bytes[4];
        if version != CTT1_V1 && version != CTT1_V2 {
            return Err(HistoryFailure::Malformed);
        }
        let transfer_type = bytes[37];
        if !(transfer_type::BACKUP..=transfer_type::HISTORY_SKIPPED).contains(&transfer_type) {
            return Err(HistoryFailure::Malformed);
        }
        let payload_len = u64::from_le_bytes(bytes[38..46].try_into().expect("8 bytes"));
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(HistoryFailure::Malformed);
        }
        Ok(Self {
            version,
            sender_eph: bytes[5..37].try_into().expect("32 bytes"),
            transfer_type,
            payload_len,
        })
    }

    /// Whether this prefix begins a history handshake. History on v1 is refused before any
    /// PIN-HMAC is attempted; a backup is not history.
    pub fn history(&self) -> Result<(), HistoryFailure> {
        match (self.version, self.transfer_type) {
            (_, transfer_type::BACKUP) => Err(HistoryFailure::Malformed),
            (CTT1_V1, _) => Err(HistoryFailure::V1RefusedForHistory),
            _ => Ok(()),
        }
    }
}

/// Cuts a frame into fixed fields; the caller has checked the total length.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let out = &self.bytes[self.at..self.at + n];
        self.at += n;
        out
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        self.take(N).try_into().expect("fixed field")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    pub sender_eph: [u8; 32],
    pub skipped: bool,
    pub payload_len: u64,
    pub sender_identity: [u8; 32],
    pub sender_hybrid: Vec<u8>,
    pub snapshot_id: [u8; 16],
    pub sender_device_id: [u8; 16],
    pub receiver_device_id: [u8; 16],
    pub receiver_kyber_key_id: u32,
    pub kem_ct: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Opening {
    pub fn parse(bytes: &[u8]) -> Result<Self, HistoryFailure> {
        if bytes.len() != OPENING_LEN {
            return Err(HistoryFailure::Malformed);
        }
        let prefix = Prefix::parse(&bytes[..PREFIX_LEN])?;
        if prefix.version != CTT1_V2 || prefix.transfer_type == transfer_type::BACKUP {
            return Err(HistoryFailure::Malformed);
        }
        let mut c = Cursor {
            bytes,
            at: PREFIX_LEN,
        };
        let o = Self {
            sender_eph: prefix.sender_eph,
            skipped: prefix.transfer_type == transfer_type::HISTORY_SKIPPED,
            payload_len: prefix.payload_len,
            sender_identity: c.array(),
            sender_hybrid: c.take(HYBRID_PUBLIC).to_vec(),
            snapshot_id: c.array(),
            sender_device_id: c.array(),
            receiver_device_id: c.array(),
            receiver_kyber_key_id: u32::from_le_bytes(c.array()),
            kem_ct: c.take(KEM_CT).to_vec(),
            signature: c.take(HYBRID_SIGNATURE).to_vec(),
        };
        o.check_kem_shape()?;
        Ok(o)
    }

    /// A history opening carries a KEM ciphertext; a skip carries none. Both halves of the key are
    /// mandatory, so there is no history frame without one.
    fn check_kem_shape(&self) -> Result<(), HistoryFailure> {
        let zero = self.kem_ct.iter().all(|&b| b == 0);
        if self.skipped != zero {
            return Err(HistoryFailure::Malformed);
        }
        Ok(())
    }

    fn transfer_type(&self) -> u8 {
        if self.skipped {
            transfer_type::HISTORY_SKIPPED
        } else {
            transfer_type::HISTORY
        }
    }

    /// The tagged transcript the sender signs.
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(OPENING_LEN);
        m.extend_from_slice(SENDER_TAG);
        m.extend_from_slice(&self.sender_eph);
        m.extend_from_slice(&self.sender_identity);
        m.extend_from_slice(&self.sender_hybrid);
        m.extend_from_slice(&self.snapshot_id);
        m.extend_from_slice(&self.sender_device_id);
        m.extend_from_slice(&self.receiver_device_id);
        m.extend_from_slice(&self.receiver_kyber_key_id.to_le_bytes());
        m.extend_from_slice(&self.kem_ct);
        m.push(self.transfer_type());
        m.extend_from_slice(&self.payload_len.to_le_bytes());
        m
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, HistoryFailure> {
        if self.sender_hybrid.len() != HYBRID_PUBLIC
            || self.kem_ct.len() != KEM_CT
            || self.signature.len() != HYBRID_SIGNATURE
            || self.payload_len > MAX_PAYLOAD_LEN
        {
            return Err(HistoryFailure::Malformed);
        }
        self.check_kem_shape()?;
        let mut out = Vec::with_capacity(OPENING_LEN);
        out.extend_from_slice(CTT1_MAGIC);
        out.push(CTT1_V2);
        out.extend_from_slice(&self.sender_eph);
        out.push(self.transfer_type());
        out.extend_from_slice(&self.payload_len.to_le_bytes());
        out.extend_from_slice(&self.sender_identity);
        out.extend_from_slice(&self.sender_hybrid);
        out.extend_from_slice(&self.snapshot_id);
        out.extend_from_slice(&self.sender_device_id);
        out.extend_from_slice(&self.receiver_device_id);
        out.extend_from_slice(&self.receiver_kyber_key_id.to_le_bytes());
        out.extend_from_slice(&self.kem_ct);
        out.extend_from_slice(&self.signature);
        debug_assert_eq!(out.len(), OPENING_LEN);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub receiver_eph: [u8; 32],
    pub receiver_identity: [u8; 32],
    pub receiver_hybrid: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Reply {
    pub fn parse(bytes: &[u8]) -> Result<Self, HistoryFailure> {
        if bytes.len() != REPLY_LEN {
            return Err(HistoryFailure::Malformed);
        }
        let mut c = Cursor { bytes, at: 0 };
        Ok(Self {
            receiver_eph: c.array(),
            receiver_identity: c.array(),
            receiver_hybrid: c.take(HYBRID_PUBLIC).to_vec(),
            signature: c.take(HYBRID_SIGNATURE).to_vec(),
        })
    }

    /// The tagged transcript the receiver signs. Echoing `kem_ct` shows it saw the ciphertext the
    /// sender sent; it is not a second KEM.
    pub fn signed_message(&self, opening: &Opening) -> Vec<u8> {
        let mut m = Vec::with_capacity(REPLY_LEN + KEM_CT);
        m.extend_from_slice(RECEIVER_TAG);
        m.extend_from_slice(&self.receiver_eph);
        m.extend_from_slice(&opening.sender_eph);
        m.extend_from_slice(&self.receiver_identity);
        m.extend_from_slice(&self.receiver_hybrid);
        m.extend_from_slice(&opening.snapshot_id);
        m.extend_from_slice(&opening.sender_device_id);
        m.extend_from_slice(&opening.receiver_device_id);
        m.extend_from_slice(&opening.kem_ct);
        m
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, HistoryFailure> {
        if self.receiver_hybrid.len() != HYBRID_PUBLIC || self.signature.len() != HYBRID_SIGNATURE {
            return Err(HistoryFailure::Malformed);
        }
        let mut out = Vec::with_capacity(REPLY_LEN);
        out.extend_from_slice(&self.receiver_eph);
        out.extend_from_slice(&self.receiver_identity);
        out.extend_from_slice(&self.receiver_hybrid);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CthfHeader {
    pub user_id: [u8; 16],
    pub recipient_device_id: [u8; 16],
    pub source_device_id: [u8; 16],
    pub snapshot_id: [u8; 16],
    pub sender_eph: [u8; 32],
    pub sender_identity: [u8; 32],
    pub sender_hybrid: Vec<u8>,
    pub recipient_kyber_key_id: u32,
    pub kem_ct: Vec<u8>,
    pub signature: Vec<u8>,
}

impl CthfHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, HistoryFailure> {
        if bytes.len() != CTHF_HEADER_LEN || &bytes[..4] != CTHF_MAGIC || bytes[4] != CTHF_V1 {
            return Err(HistoryFailure::Malformed);
        }
        let mut c = Cursor { bytes, at: 5 };
        let h = Self {
            user_id: c.array(),
            recipient_device_id: c.array(),
            source_device_id: c.array(),
            snapshot_id: c.array(),
            sender_eph: c.array(),
            sender_identity: c.array(),
            sender_hybrid: c.take(HYBRID_PUBLIC).to_vec(),
            recipient_kyber_key_id: u32::from_le_bytes(c.array()),
            kem_ct: c.take(KEM_CT).to_vec(),
            signature: c.take(HYBRID_SIGNATURE).to_vec(),
        };
        if h.kem_ct.iter().all(|&b| b == 0) {
            return Err(HistoryFailure::Malformed);
        }
        Ok(h)
    }

    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(CTHF_HEADER_LEN);
        m.extend_from_slice(FILE_TAG);
        self.fields(&mut m);
        m
    }

    fn fields(&self, m: &mut Vec<u8>) {
        m.extend_from_slice(&self.user_id);
        m.extend_from_slice(&self.recipient_device_id);
        m.extend_from_slice(&self.source_device_id);
        m.extend_from_slice(&self.snapshot_id);
        m.extend_from_slice(&self.sender_eph);
        m.extend_from_slice(&self.sender_identity);
        m.extend_from_slice(&self.sender_hybrid);
        m.extend_from_slice(&self.recipient_kyber_key_id.to_le_bytes());
        m.extend_from_slice(&self.kem_ct);
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, HistoryFailure> {
        if self.sender_hybrid.len() != HYBRID_PUBLIC
            || self.kem_ct.len() != KEM_CT
            || self.signature.len() != HYBRID_SIGNATURE
        {
            return Err(HistoryFailure::Malformed);
        }
        let mut out = Vec::with_capacity(CTHF_HEADER_LEN);
        out.extend_from_slice(CTHF_MAGIC);
        out.push(CTHF_V1);
        self.fields(&mut out);
        out.extend_from_slice(&self.signature);
        debug_assert_eq!(out.len(), CTHF_HEADER_LEN);
        Ok(out)
    }
}

// ── Verification ──────────────────────────────────────────────────────────────

/// What the link QR pinned for the other device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// Flow A: `SHA256(identity ‖ hybrid)` of the offering device.
    Fingerprint([u8; 32]),
    /// Flow B, or a file imported outside the link session: the directory is the only pin.
    /// Accepted, and named in the log.
    BundleOnly,
    /// Nothing pins the other device. Refused.
    Absent,
}

/// The other device's keys as the directory (`GetPreKeyBundles`) returned them. Advertised keys
/// in a frame are compared to these and the signature is verified with these — never with the
/// frame's own, which would trust whoever is on the LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownKeys {
    pub identity_public: Vec<u8>,
    pub hybrid_public: Vec<u8>,
}

/// This device, as the frames name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    pub device_id: [u8; 16],
    pub kyber_key_id: u32,
}

fn check_known(identity: &[u8], hybrid: &[u8], known: &KnownKeys) -> Result<(), HistoryFailure> {
    if known.hybrid_public.is_empty() {
        return Err(HistoryFailure::NoHybridKey);
    }
    if !(ct_eq(identity, &known.identity_public) & ct_eq(hybrid, &known.hybrid_public)) {
        return Err(HistoryFailure::IdentityMismatch);
    }
    Ok(())
}

fn check_pin(identity: &[u8], hybrid: &[u8], pin: &Pin) -> Result<(), HistoryFailure> {
    match pin {
        Pin::Absent => Err(HistoryFailure::QrPinAbsent),
        Pin::BundleOnly => Ok(()),
        Pin::Fingerprint(fp) => {
            if ct_eq(&super::discovery::qr_fingerprint(identity, hybrid), fp) {
                Ok(())
            } else {
                Err(HistoryFailure::QrPinMismatch)
            }
        }
    }
}

#[cfg(feature = "post-quantum")]
fn check_signature(hybrid: &[u8], message: &[u8], signature: &[u8]) -> Result<(), HistoryFailure> {
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::hybrid::HybridSuiteProvider;
    HybridSuiteProvider::verify(&hybrid.to_vec(), message, signature)
        .map_err(|_| HistoryFailure::SignatureInvalid)
}

#[cfg(not(feature = "post-quantum"))]
fn check_signature(_: &[u8], _: &[u8], _: &[u8]) -> Result<(), HistoryFailure> {
    Err(HistoryFailure::SignatureInvalid)
}

/// The receiver's check of an opening: ids, Kyber key id, known keys, QR pin, signature.
pub fn verify_opening(
    o: &Opening,
    local: &Local,
    known: &KnownKeys,
    pin: &Pin,
) -> Result<(), HistoryFailure> {
    if !(ct_eq(&o.sender_device_id, &device_id_raw(&o.sender_identity))
        & ct_eq(&o.receiver_device_id, &local.device_id))
    {
        return Err(HistoryFailure::IdentityMismatch);
    }
    if o.receiver_kyber_key_id != local.kyber_key_id {
        return Err(HistoryFailure::KemKeyIdMismatch);
    }
    check_known(&o.sender_identity, &o.sender_hybrid, known)?;
    check_pin(&o.sender_identity, &o.sender_hybrid, pin)?;
    check_signature(&known.hybrid_public, &o.signed_message(), &o.signature)
}

/// The sender's check of a reply to its own opening. `pinned_identity` is the new device's
/// identity from a Flow B QR (`konstruct://link-to-me?pubkey=…`), when this side scanned one.
pub fn verify_reply(
    r: &Reply,
    opening: &Opening,
    known: &KnownKeys,
    pinned_identity: Option<&[u8]>,
) -> Result<(), HistoryFailure> {
    if !ct_eq(
        &device_id_raw(&r.receiver_identity),
        &opening.receiver_device_id,
    ) {
        return Err(HistoryFailure::IdentityMismatch);
    }
    if let Some(pinned) = pinned_identity
        && !ct_eq(pinned, &r.receiver_identity)
    {
        return Err(HistoryFailure::QrPinMismatch);
    }
    check_known(&r.receiver_identity, &r.receiver_hybrid, known)?;
    check_signature(
        &known.hybrid_public,
        &r.signed_message(opening),
        &r.signature,
    )
}

/// The importer's check of a file header, in the same order as an opening.
pub fn verify_cthf(
    h: &CthfHeader,
    local: &Local,
    known: &KnownKeys,
    pin: &Pin,
) -> Result<(), HistoryFailure> {
    if !(ct_eq(&h.recipient_device_id, &local.device_id)
        & ct_eq(&h.source_device_id, &device_id_raw(&h.sender_identity)))
    {
        return Err(HistoryFailure::IdentityMismatch);
    }
    if h.recipient_kyber_key_id != local.kyber_key_id {
        return Err(HistoryFailure::KemKeyIdMismatch);
    }
    check_known(&h.sender_identity, &h.sender_hybrid, known)?;
    check_pin(&h.sender_identity, &h.sender_hybrid, pin)?;
    check_signature(&known.hybrid_public, &h.signed_message(), &h.signature)
}

#[cfg(all(test, feature = "post-quantum"))]
mod tests {
    use super::*;
    use crate::history::vectors;

    fn keys() -> (KnownKeys, KnownKeys, Local) {
        let k = vectors::keys();
        let hybrid = vectors::hex_field(&k, "hybrid_public");
        let offering = KnownKeys {
            identity_public: vectors::hex_field(&k, "offering_identity_public"),
            hybrid_public: hybrid.clone(),
        };
        let receiver = KnownKeys {
            identity_public: vectors::hex_field(&k, "receiver_identity_public"),
            hybrid_public: hybrid,
        };
        let local = Local {
            device_id: vectors::hex_field(&k, "receiver_device_id_raw")
                .try_into()
                .unwrap(),
            kyber_key_id: k["kyber_key_id"].as_u64().unwrap() as u32,
        };
        (offering, receiver, local)
    }

    #[test]
    fn the_layout_sums_are_the_vector_lengths() {
        assert_eq!(OPENING_LEN, 7055);
        assert_eq!(REPLY_LEN, 5421);
        assert_eq!(CTHF_HEADER_LEN, 7062);
    }

    /// The opening verifies with its tag against the directory's keys, round-trips byte-exact,
    /// and fails when the tag is left out of the signed message.
    #[test]
    fn the_opening_vector_verifies_with_its_tag_only() {
        let (offering, _, local) = keys();
        let v = vectors::named("ctt1_v2_opening");
        let bytes = vectors::hex_field(&v, "hex");
        let o = Opening::parse(&bytes).unwrap();
        assert_eq!(o.to_bytes().unwrap(), bytes);
        assert_eq!(
            verify_opening(&o, &local, &offering, &Pin::BundleOnly),
            Ok(())
        );

        let fp = crate::history::discovery::qr_fingerprint(
            &offering.identity_public,
            &offering.hybrid_public,
        );
        assert_eq!(
            verify_opening(&o, &local, &offering, &Pin::Fingerprint(fp)),
            Ok(())
        );

        let untagged = &o.signed_message()[SENDER_TAG.len()..];
        assert_eq!(
            check_signature(&offering.hybrid_public, untagged, &o.signature),
            Err(HistoryFailure::SignatureInvalid)
        );
    }

    #[test]
    fn the_reply_vector_verifies_against_the_opening() {
        let (_, receiver, _) = keys();
        let o = Opening::parse(&vectors::hex_field(
            &vectors::named("ctt1_v2_opening"),
            "hex",
        ))
        .unwrap();
        let bytes = vectors::hex_field(&vectors::named("ctt1_v2_reply"), "hex");
        let r = Reply::parse(&bytes).unwrap();
        assert_eq!(r.to_bytes().unwrap(), bytes);
        assert_eq!(verify_reply(&r, &o, &receiver, None), Ok(()));
        assert_eq!(
            verify_reply(&r, &o, &receiver, Some(&receiver.identity_public)),
            Ok(()),
            "the Flow B pin is the new device's identity"
        );
        assert_eq!(
            verify_reply(&r, &o, &receiver, Some(&[0u8; 32])),
            Err(HistoryFailure::QrPinMismatch)
        );
    }

    #[test]
    fn an_ed25519_only_signature_fails_and_a_zero_kem_ct_is_malformed() {
        let (offering, _, local) = keys();
        let o = Opening::parse(&vectors::hex_field(
            &vectors::named("ctt1_v2_opening_ed25519_only"),
            "hex",
        ))
        .unwrap();
        assert_eq!(
            verify_opening(&o, &local, &offering, &Pin::BundleOnly),
            Err(HistoryFailure::SignatureInvalid)
        );
        assert_eq!(
            Opening::parse(&vectors::hex_field(
                &vectors::named("ctt1_v2_opening_zero_kem_ct"),
                "hex"
            )),
            Err(HistoryFailure::Malformed)
        );
    }

    #[test]
    fn the_cthf_header_verifies_and_a_rotated_kyber_key_is_named() {
        let (offering, _, local) = keys();
        let bytes = vectors::hex_field(&vectors::named("cthf_header"), "hex");
        let h = CthfHeader::parse(&bytes).unwrap();
        assert_eq!(h.to_bytes().unwrap(), bytes);
        assert_eq!(verify_cthf(&h, &local, &offering, &Pin::BundleOnly), Ok(()));

        let wrong = vectors::named("cthf_wrong_kyber_key_id");
        let h = CthfHeader::parse(&vectors::hex_field(&wrong, "hex")).unwrap();
        assert_eq!(
            h.recipient_kyber_key_id,
            wrong["recipient_kyber_key_id"].as_u64().unwrap() as u32
        );
        assert_eq!(
            verify_cthf(&h, &local, &offering, &Pin::BundleOnly),
            Err(HistoryFailure::KemKeyIdMismatch)
        );
    }

    /// Each check refuses on its own, in the order the spec gives — a frame whose keys do not
    /// match the directory never reaches the signature, and never reaches decapsulation.
    #[test]
    fn each_check_refuses_with_its_own_reason() {
        let (offering, receiver, local) = keys();
        let o = Opening::parse(&vectors::hex_field(
            &vectors::named("ctt1_v2_opening"),
            "hex",
        ))
        .unwrap();

        let mut claims_another = o.clone();
        claims_another.sender_device_id = [0; 16];
        assert_eq!(
            verify_opening(&claims_another, &local, &offering, &Pin::BundleOnly),
            Err(HistoryFailure::IdentityMismatch),
            "a sender id its identity key does not derive to"
        );
        let h =
            CthfHeader::parse(&vectors::hex_field(&vectors::named("cthf_header"), "hex")).unwrap();
        let mut from_another = h.clone();
        from_another.source_device_id = [0; 16];
        assert_eq!(
            verify_cthf(&from_another, &local, &offering, &Pin::BundleOnly),
            Err(HistoryFailure::IdentityMismatch)
        );
        assert_eq!(
            verify_cthf(&h, &local, &receiver, &Pin::BundleOnly),
            Err(HistoryFailure::IdentityMismatch),
            "a file whose keys are not the directory's"
        );

        let elsewhere = Local {
            device_id: [0; 16],
            ..local.clone()
        };
        assert_eq!(
            verify_opening(&o, &elsewhere, &offering, &Pin::BundleOnly),
            Err(HistoryFailure::IdentityMismatch)
        );
        let rotated = Local {
            kyber_key_id: local.kyber_key_id + 1,
            ..local.clone()
        };
        assert_eq!(
            verify_opening(&o, &rotated, &offering, &Pin::BundleOnly),
            Err(HistoryFailure::KemKeyIdMismatch)
        );
        assert_eq!(
            verify_opening(&o, &local, &receiver, &Pin::BundleOnly),
            Err(HistoryFailure::IdentityMismatch),
            "advertised keys that are not the directory's"
        );
        let no_hybrid = KnownKeys {
            hybrid_public: Vec::new(),
            ..offering.clone()
        };
        assert_eq!(
            verify_opening(&o, &local, &no_hybrid, &Pin::BundleOnly),
            Err(HistoryFailure::NoHybridKey)
        );
        assert_eq!(
            verify_opening(&o, &local, &offering, &Pin::Fingerprint([0; 32])),
            Err(HistoryFailure::QrPinMismatch)
        );
        assert_eq!(
            verify_opening(&o, &local, &offering, &Pin::Absent),
            Err(HistoryFailure::QrPinAbsent)
        );

        let mut tampered = o.clone();
        tampered.payload_len += 1;
        assert_eq!(
            verify_opening(&tampered, &local, &offering, &Pin::BundleOnly),
            Err(HistoryFailure::SignatureInvalid),
            "the payload length is signed"
        );
    }

    #[test]
    fn the_prefix_decides_the_read_and_refuses_history_on_v1() {
        let o = vectors::hex_field(&vectors::named("ctt1_v2_opening"), "hex");
        let p = Prefix::parse(&o[..PREFIX_LEN]).unwrap();
        assert_eq!(p.history(), Ok(()));

        let mut v1 = o[..PREFIX_LEN].to_vec();
        v1[4] = CTT1_V1;
        assert_eq!(
            Prefix::parse(&v1).unwrap().history(),
            Err(HistoryFailure::V1RefusedForHistory)
        );
        v1[37] = transfer_type::BACKUP;
        assert_eq!(
            Prefix::parse(&v1).unwrap().history(),
            Err(HistoryFailure::Malformed)
        );

        let mut huge = o[..PREFIX_LEN].to_vec();
        huge[38..46].copy_from_slice(&(MAX_PAYLOAD_LEN + 1).to_le_bytes());
        assert_eq!(Prefix::parse(&huge), Err(HistoryFailure::Malformed));
    }
}
