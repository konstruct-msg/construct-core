//! Devices of one account vouch for each other: the device certificate.
//!
//! ## What it is for
//!
//! Which devices belong to an account is something only the server says (`GetPreKeyBundles`,
//! `active_devices`). A server that adds a device of its own to someone's account receives every
//! later message to that account, and until this module nothing on a peer's side could tell that
//! device from one the owner linked (`security/SERVER_COMPROMISE_MODEL.md`, S2). The alarm that
//! tried was removed on 2026-09-30 because it fired on every honest link too
//! (`decisions/new-device-alarm-waits-for-cross-signing.md`).
//!
//! Here the account's own devices say it instead. When the owner links a new device, the old one
//! signs the new one's keys; a peer that already trusts the old device trusts the new one through
//! the signature, and a device nobody signed is the one the alarm is about
//! (`decisions/devices-of-an-account-sign-each-other.md`).
//!
//! ## Only keys that did not come from the server are signed
//!
//! Signing whatever the directory returns would turn a server substitution into a vouched device.
//! [`issue`] therefore takes evidence that the keys are the ones the owner held next to the old
//! device:
//!
//! - **Flow B** (the new device shows the QR): the QR carries
//!   `history_qr_fingerprint(identity, hybrid)` of the new device — [`LinkEvidence::QrFingerprint`].
//! - **Flow A** (the old device shows the QR): the QR carries a 32-byte secret the server never
//!   sees; the new device proves its keys with [`link_key_proof`], the server only relays the proof
//!   — [`LinkEvidence::QrSecret`].
//!
//! ## Format
//!
//! ```text
//! message = "KonstruktDeviceCert-v1" ‖ 0x00
//!           ‖ signer_device_id (16) ‖ subject_device_id (16)
//!           ‖ subject identity X25519 (32) ‖ subject verifying Ed25519 (32)
//!           ‖ subject hybrid public (1984)
//!           ‖ issued_at (u64 BE, unix seconds)
//! signature = hybrid (Ed25519 ‖ ML-DSA-65) by the signer's hybrid identity key
//!
//! certificate = version 0x01 ‖ signer_device_id (16) ‖ issued_at (u64 BE)
//!               ‖ signer hybrid public (1984) ‖ signature (3373)
//! ```
//!
//! The subject's keys are not in the certificate: they are in the subject's bundle, and the
//! verifier rebuilds the message from it. The **signer's** hybrid key is, so a device signed by a
//! phone that has since left the account still verifies against whoever pinned that phone; the
//! verifier compares its SHA-256 with its own pin, never trusts it on its own.
//!
//! Who is trusted is decided by [`judge`], identically on every client: the platform hands over
//! the devices of one account it already trusts and the bundles it just received, and gets a
//! verdict per device. The `account → devices` directory stays with the platform — the core does
//! not know accounts (`decisions/identity-spaces.md`).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::crypto::suites::hybrid::{
    HYBRID_SIG_PUBLIC_KEY_SIZE, HYBRID_SIGNATURE_SIZE, HybridSuiteProvider,
};
use crate::device_id::derive_device_id_bytes;

/// Domain separation for the certificate signature. Must stay byte-identical on every client.
pub const DEVICE_CERT_PROLOGUE: &[u8] = b"KonstruktDeviceCert-v1";
/// Domain separation for the Flow A proof of keys.
pub const LINK_PROOF_PROLOGUE: &[u8] = b"KonstruktLinkProof-v1";
/// The only certificate version.
pub const DEVICE_CERT_VERSION: u8 = 1;
/// Length of the Flow A QR secret.
pub const LINK_SECRET_LEN: usize = 32;

const DEVICE_ID_LEN: usize = 16;
const X25519_LEN: usize = 32;
const ED25519_LEN: usize = 32;
const CERT_LEN: usize = 1 + DEVICE_ID_LEN + 8 + HYBRID_SIG_PUBLIC_KEY_SIZE + HYBRID_SIGNATURE_SIZE;

/// A device's public keys as its bundle presents them.
#[derive(Clone, Copy, Debug)]
pub struct DeviceKeys<'a> {
    pub identity_public: &'a [u8],
    pub verifying_key: &'a [u8],
    pub hybrid_public: &'a [u8],
    /// Ed25519 signature by `verifying_key` over `KonstruktHybridId-v1 ‖ hybrid_public`.
    pub hybrid_binding: &'a [u8],
}

/// Why a certificate was not issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    /// A key has the wrong length.
    KeysMalformed,
    /// The hybrid key is not bound to the device's Ed25519 key.
    BindingInvalid,
    /// The keys are not the ones the QR named: refused, this is the substitution being caught.
    EvidenceMismatch,
    /// A device does not vouch for itself.
    SignerIsSubject,
    /// The signer's own hybrid key is missing or signing failed.
    SigningFailed,
}

/// What shows the keys came from the device next to the owner, not from the server.
#[derive(Clone, Copy, Debug)]
pub enum LinkEvidence<'a> {
    /// Flow B: the new device's QR carried `qr_fingerprint(identity, hybrid)`.
    QrFingerprint(&'a [u8]),
    /// Flow A: our QR carried `secret`; the new device answered with `proof`.
    QrSecret { secret: &'a [u8], proof: &'a [u8] },
}

/// A device's verdict, given the devices of its account already trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceVerdict {
    /// Already trusted, with the same hybrid key.
    Pinned,
    /// Nothing of this account was trusted yet: trusted on first use, as the first device always
    /// was.
    FirstOfAccount,
    /// Signed by a trusted device of the account, directly or through a chain.
    Vouched { by: String },
    /// Signed by nobody we trust. The one case that is an alarm.
    Unvouched,
    /// Trusted before, and now presents another hybrid key under the same id.
    KeyChanged,
    /// The bundle does not hold together (key lengths, id, binding). Not a device.
    Invalid,
}

/// A device of the account the platform already trusts, and the hybrid key it pinned for it, if
/// any.
#[derive(Clone, Debug)]
pub struct TrustedDevice {
    pub device_id: String,
    pub hybrid_pin: Option<[u8; 32]>,
}

/// A device the server just listed for the account.
#[derive(Clone, Copy, Debug)]
pub struct OfferedDevice<'a> {
    pub device_id: &'a str,
    pub keys: DeviceKeys<'a>,
    pub certificate: Option<&'a [u8]>,
}

/// A parsed certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    pub signer_device_id: [u8; DEVICE_ID_LEN],
    pub issued_at: u64,
    pub signer_hybrid_public: Vec<u8>,
    pub signature: Vec<u8>,
}

impl DeviceCertificate {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CERT_LEN);
        out.push(DEVICE_CERT_VERSION);
        out.extend_from_slice(&self.signer_device_id);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.signer_hybrid_public);
        out.extend_from_slice(&self.signature);
        out
    }

    /// `None` for anything but a version-1 certificate of the exact length.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CERT_LEN || bytes[0] != DEVICE_CERT_VERSION {
            return None;
        }
        let mut at = 1;
        let signer_device_id: [u8; DEVICE_ID_LEN] =
            bytes[at..at + DEVICE_ID_LEN].try_into().ok()?;
        at += DEVICE_ID_LEN;
        let issued_at = u64::from_be_bytes(bytes[at..at + 8].try_into().ok()?);
        at += 8;
        let signer_hybrid_public = bytes[at..at + HYBRID_SIG_PUBLIC_KEY_SIZE].to_vec();
        at += HYBRID_SIG_PUBLIC_KEY_SIZE;
        let signature = bytes[at..].to_vec();
        Some(Self {
            signer_device_id,
            issued_at,
            signer_hybrid_public,
            signature,
        })
    }
}

/// The bytes a certificate signs.
pub fn certificate_message(
    signer_device_id: &[u8; DEVICE_ID_LEN],
    subject_device_id: &[u8; DEVICE_ID_LEN],
    subject: &DeviceKeys<'_>,
    issued_at: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        DEVICE_CERT_PROLOGUE.len()
            + 1
            + 2 * DEVICE_ID_LEN
            + X25519_LEN
            + ED25519_LEN
            + subject.hybrid_public.len()
            + 8,
    );
    msg.extend_from_slice(DEVICE_CERT_PROLOGUE);
    msg.push(0x00);
    msg.extend_from_slice(signer_device_id);
    msg.extend_from_slice(subject_device_id);
    msg.extend_from_slice(subject.identity_public);
    msg.extend_from_slice(subject.verifying_key);
    msg.extend_from_slice(subject.hybrid_public);
    msg.extend_from_slice(&issued_at.to_be_bytes());
    msg
}

/// Flow A: the new device's answer to the secret in the old device's QR.
///
/// `HMAC-SHA256(secret, "KonstruktLinkProof-v1" ‖ 0x00 ‖ qr_fingerprint(identity, hybrid))`.
/// The server relays it and learns nothing: without the secret it can neither read nor forge it.
pub fn link_key_proof(
    secret: &[u8],
    identity_public: &[u8],
    hybrid_public: &[u8],
) -> Result<[u8; 32], CertError> {
    if secret.len() != LINK_SECRET_LEN {
        return Err(CertError::KeysMalformed);
    }
    Ok(link_proof_mac(secret, identity_public, hybrid_public)
        .finalize()
        .into_bytes()
        .into())
}

fn link_proof_mac(secret: &[u8], identity_public: &[u8], hybrid_public: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(LINK_PROOF_PROLOGUE);
    mac.update(&[0x00]);
    mac.update(&crate::history::discovery::qr_fingerprint(
        identity_public,
        hybrid_public,
    ));
    mac
}

/// Check that a bundle's keys hold together and return the device id they make.
fn check_keys(keys: &DeviceKeys<'_>) -> Result<[u8; DEVICE_ID_LEN], CertError> {
    if keys.identity_public.len() != X25519_LEN
        || keys.verifying_key.len() != ED25519_LEN
        || keys.hybrid_public.len() != HYBRID_SIG_PUBLIC_KEY_SIZE
    {
        return Err(CertError::KeysMalformed);
    }
    use crate::crypto::keys::KeyManager;
    let bind =
        KeyManager::<ClassicSuiteProvider>::build_hybrid_identity_bind_message(keys.hybrid_public);
    let vk = ClassicSuiteProvider::signature_public_key_from_bytes(keys.verifying_key.to_vec());
    ClassicSuiteProvider::verify(&vk, &bind, keys.hybrid_binding)
        .map_err(|_| CertError::BindingInvalid)?;
    Ok(derive_device_id_bytes(keys.identity_public))
}

fn check_evidence(keys: &DeviceKeys<'_>, evidence: &LinkEvidence<'_>) -> Result<(), CertError> {
    match evidence {
        LinkEvidence::QrFingerprint(fingerprint) => {
            let ours =
                crate::history::discovery::qr_fingerprint(keys.identity_public, keys.hybrid_public);
            // Public values: no need for a constant-time compare.
            if fingerprint[..] == ours[..] {
                Ok(())
            } else {
                Err(CertError::EvidenceMismatch)
            }
        }
        LinkEvidence::QrSecret { secret, proof } => {
            if secret.len() != LINK_SECRET_LEN {
                return Err(CertError::KeysMalformed);
            }
            link_proof_mac(secret, keys.identity_public, keys.hybrid_public)
                .verify_slice(proof)
                .map_err(|_| CertError::EvidenceMismatch)
        }
    }
}

/// Issue a certificate for `subject`, signed by the device whose identity key is
/// `signer_identity_public` and whose hybrid key is `signer_hybrid_public`.
///
/// `sign` signs with that hybrid key; the secret stays wherever the caller keeps it.
pub fn issue(
    signer_identity_public: &[u8],
    signer_hybrid_public: &[u8],
    subject: &DeviceKeys<'_>,
    evidence: &LinkEvidence<'_>,
    issued_at: u64,
    sign: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, CertError> {
    let subject_id = check_keys(subject)?;
    check_evidence(subject, evidence)?;
    if signer_hybrid_public.len() != HYBRID_SIG_PUBLIC_KEY_SIZE {
        return Err(CertError::SigningFailed);
    }
    let signer_id = derive_device_id_bytes(signer_identity_public);
    if signer_id == subject_id {
        return Err(CertError::SignerIsSubject);
    }
    let message = certificate_message(&signer_id, &subject_id, subject, issued_at);
    let signature = sign(&message).ok_or(CertError::SigningFailed)?;
    if signature.len() != HYBRID_SIGNATURE_SIZE {
        return Err(CertError::SigningFailed);
    }
    Ok(DeviceCertificate {
        signer_device_id: signer_id,
        issued_at,
        signer_hybrid_public: signer_hybrid_public.to_vec(),
        signature,
    }
    .encode())
}

fn hybrid_pin(hybrid_public: &[u8]) -> [u8; 32] {
    Sha256::digest(hybrid_public).into()
}

/// A verdict for every offered device, in the order given.
///
/// `trusted` are the devices of **one** account the platform already trusts; `offered` are the
/// devices the server lists for that account now. Trust spreads from the trusted devices through
/// certificates, to any depth: C signed by B, B signed by a pinned A.
pub fn judge(trusted: &[TrustedDevice], offered: &[OfferedDevice<'_>]) -> Vec<DeviceVerdict> {
    let mut verdicts: Vec<Option<DeviceVerdict>> = vec![None; offered.len()];
    // device id (hex) → SHA-256 of the hybrid key it is trusted with.
    let mut anchors: std::collections::BTreeMap<String, [u8; 32]> = Default::default();

    for (i, device) in offered.iter().enumerate() {
        match check_keys(&device.keys) {
            Ok(id) if hex::encode(id) == device.device_id => {}
            _ => verdicts[i] = Some(DeviceVerdict::Invalid),
        }
    }

    for t in trusted {
        let offered_here = offered
            .iter()
            .enumerate()
            .find(|(i, d)| verdicts[*i].is_none() && d.device_id == t.device_id);
        match (offered_here, t.hybrid_pin) {
            (Some((i, d)), pin) => {
                let presented = hybrid_pin(d.keys.hybrid_public);
                if pin.is_some_and(|p| p != presented) {
                    verdicts[i] = Some(DeviceVerdict::KeyChanged);
                } else {
                    verdicts[i] = Some(DeviceVerdict::Pinned);
                    anchors.insert(t.device_id.clone(), presented);
                }
            }
            (None, Some(pin)) => {
                anchors.insert(t.device_id.clone(), pin);
            }
            (None, None) => {}
        }
    }

    if trusted.is_empty() {
        return verdicts
            .into_iter()
            .map(|v| v.unwrap_or(DeviceVerdict::FirstOfAccount))
            .collect();
    }

    loop {
        let mut progressed = false;
        for (i, device) in offered.iter().enumerate() {
            if verdicts[i].is_some() {
                continue;
            }
            let Some(signer) = vouching_signer(device, &anchors) else {
                continue;
            };
            anchors.insert(
                device.device_id.to_string(),
                hybrid_pin(device.keys.hybrid_public),
            );
            verdicts[i] = Some(DeviceVerdict::Vouched { by: signer });
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    verdicts
        .into_iter()
        .map(|v| v.unwrap_or(DeviceVerdict::Unvouched))
        .collect()
}

/// The trusted signer whose certificate vouches for `device`, if its certificate checks out.
fn vouching_signer(
    device: &OfferedDevice<'_>,
    anchors: &std::collections::BTreeMap<String, [u8; 32]>,
) -> Option<String> {
    let cert = DeviceCertificate::decode(device.certificate?)?;
    let signer = hex::encode(cert.signer_device_id);
    if signer == device.device_id {
        return None;
    }
    let anchor = anchors.get(&signer)?;
    if hybrid_pin(&cert.signer_hybrid_public) != *anchor {
        return None;
    }
    let subject_id: [u8; DEVICE_ID_LEN] = hex::decode(device.device_id).ok()?.try_into().ok()?;
    let message = certificate_message(
        &cert.signer_device_id,
        &subject_id,
        &device.keys,
        cert.issued_at,
    );
    HybridSuiteProvider::verify(&cert.signer_hybrid_public, &message, &cert.signature).ok()?;
    Some(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suites::hybrid::hybrid_signature_keypair_from_seeds;
    use ed25519_dalek::{Signer, SigningKey};

    /// A device with deterministic keys: X25519 identity, Ed25519 verifying key, hybrid key and
    /// the binding between the last two.
    struct TestDevice {
        identity: Vec<u8>,
        verifying: Vec<u8>,
        hybrid_public: Vec<u8>,
        hybrid_private: crate::crypto::SecretBytes,
        binding: Vec<u8>,
    }

    impl TestDevice {
        fn new(seed: u8) -> Self {
            let x = x25519_dalek::StaticSecret::from([seed; 32]);
            let identity = x25519_dalek::PublicKey::from(&x).as_bytes().to_vec();
            let ed = SigningKey::from_bytes(&[seed.wrapping_add(100); 32]);
            let (hybrid_private, hybrid_public) =
                hybrid_signature_keypair_from_seeds(&[seed.wrapping_add(50); 32], &[seed; 32]);
            use crate::crypto::keys::KeyManager;
            let bind = KeyManager::<ClassicSuiteProvider>::build_hybrid_identity_bind_message(
                &hybrid_public,
            );
            let binding = ed.sign(&bind).to_bytes().to_vec();
            Self {
                identity,
                verifying: ed.verifying_key().to_bytes().to_vec(),
                hybrid_public,
                hybrid_private,
                binding,
            }
        }

        fn keys(&self) -> DeviceKeys<'_> {
            DeviceKeys {
                identity_public: &self.identity,
                verifying_key: &self.verifying,
                hybrid_public: &self.hybrid_public,
                hybrid_binding: &self.binding,
            }
        }

        fn id(&self) -> String {
            hex::encode(derive_device_id_bytes(&self.identity))
        }

        fn fingerprint(&self) -> [u8; 32] {
            crate::history::discovery::qr_fingerprint(&self.identity, &self.hybrid_public)
        }

        fn vouch(&self, subject: &TestDevice) -> Vec<u8> {
            let fp = subject.fingerprint();
            issue(
                &self.identity,
                &self.hybrid_public,
                &subject.keys(),
                &LinkEvidence::QrFingerprint(&fp),
                1_790_000_000,
                |m| HybridSuiteProvider::sign(&self.hybrid_private, m).ok(),
            )
            .unwrap()
        }

        fn trusted(&self) -> TrustedDevice {
            TrustedDevice {
                device_id: self.id(),
                hybrid_pin: Some(hybrid_pin(&self.hybrid_public)),
            }
        }
    }

    fn offered<'a>(d: &'a TestDevice, id: &'a str, cert: Option<&'a [u8]>) -> OfferedDevice<'a> {
        OfferedDevice {
            device_id: id,
            keys: d.keys(),
            certificate: cert,
        }
    }

    #[test]
    fn flow_b_fingerprint_must_name_the_keys() {
        let (old, new, other) = (TestDevice::new(1), TestDevice::new(2), TestDevice::new(3));
        let fp_of_other = other.fingerprint();
        let refused = issue(
            &old.identity,
            &old.hybrid_public,
            &new.keys(),
            &LinkEvidence::QrFingerprint(&fp_of_other),
            0,
            |m| HybridSuiteProvider::sign(&old.hybrid_private, m).ok(),
        );
        assert_eq!(refused, Err(CertError::EvidenceMismatch));
    }

    #[test]
    fn flow_a_proof_must_come_from_the_secret_and_the_keys() {
        let (old, new, other) = (TestDevice::new(1), TestDevice::new(2), TestDevice::new(3));
        let secret = [7u8; LINK_SECRET_LEN];
        let proof = link_key_proof(&secret, &new.identity, &new.hybrid_public).unwrap();
        let sign = |m: &[u8]| HybridSuiteProvider::sign(&old.hybrid_private, m).ok();

        let issued = issue(
            &old.identity,
            &old.hybrid_public,
            &new.keys(),
            &LinkEvidence::QrSecret {
                secret: &secret,
                proof: &proof,
            },
            0,
            sign,
        );
        assert!(issued.is_ok());

        // The server substitutes its own device's keys and relays the honest proof.
        let substituted = issue(
            &old.identity,
            &old.hybrid_public,
            &other.keys(),
            &LinkEvidence::QrSecret {
                secret: &secret,
                proof: &proof,
            },
            0,
            sign,
        );
        assert_eq!(substituted, Err(CertError::EvidenceMismatch));

        // A proof made without the secret.
        let forged = link_key_proof(
            &[8u8; LINK_SECRET_LEN],
            &other.identity,
            &other.hybrid_public,
        )
        .unwrap();
        let forged = issue(
            &old.identity,
            &old.hybrid_public,
            &other.keys(),
            &LinkEvidence::QrSecret {
                secret: &secret,
                proof: &forged,
            },
            0,
            sign,
        );
        assert_eq!(forged, Err(CertError::EvidenceMismatch));
    }

    #[test]
    fn unbound_hybrid_key_is_not_signed() {
        let (old, new, other) = (TestDevice::new(1), TestDevice::new(2), TestDevice::new(3));
        // New's identity with another device's hybrid key, under new's binding: does not hold.
        let mixed = DeviceKeys {
            hybrid_public: &other.hybrid_public,
            ..new.keys()
        };
        let fp = crate::history::discovery::qr_fingerprint(&new.identity, &other.hybrid_public);
        let refused = issue(
            &old.identity,
            &old.hybrid_public,
            &mixed,
            &LinkEvidence::QrFingerprint(&fp),
            0,
            |m| HybridSuiteProvider::sign(&old.hybrid_private, m).ok(),
        );
        assert_eq!(refused, Err(CertError::BindingInvalid));
    }

    #[test]
    fn a_device_does_not_vouch_for_itself() {
        let old = TestDevice::new(1);
        let fp = old.fingerprint();
        let refused = issue(
            &old.identity,
            &old.hybrid_public,
            &old.keys(),
            &LinkEvidence::QrFingerprint(&fp),
            0,
            |m| HybridSuiteProvider::sign(&old.hybrid_private, m).ok(),
        );
        assert_eq!(refused, Err(CertError::SignerIsSubject));
    }

    #[test]
    fn verdicts_across_a_chain() {
        let (a, b, c, rogue) = (
            TestDevice::new(1),
            TestDevice::new(2),
            TestDevice::new(3),
            TestDevice::new(4),
        );
        let (cert_b, cert_c) = (a.vouch(&b), b.vouch(&c));
        let (ida, idb, idc, idr) = (a.id(), b.id(), c.id(), rogue.id());
        // C is listed before B: the order the server lists them in must not matter.
        let set = [
            offered(&c, &idc, Some(&cert_c)),
            offered(&rogue, &idr, None),
            offered(&a, &ida, None),
            offered(&b, &idb, Some(&cert_b)),
        ];
        let verdicts = judge(&[a.trusted()], &set);
        assert_eq!(
            verdicts,
            vec![
                DeviceVerdict::Vouched { by: idb.clone() },
                DeviceVerdict::Unvouched,
                DeviceVerdict::Pinned,
                DeviceVerdict::Vouched { by: ida.clone() },
            ]
        );
    }

    #[test]
    fn first_sight_of_an_account_trusts_on_first_use() {
        let (a, b) = (TestDevice::new(1), TestDevice::new(2));
        let (ida, idb) = (a.id(), b.id());
        let verdicts = judge(&[], &[offered(&a, &ida, None), offered(&b, &idb, None)]);
        assert_eq!(
            verdicts,
            vec![DeviceVerdict::FirstOfAccount, DeviceVerdict::FirstOfAccount]
        );
    }

    #[test]
    fn a_signer_that_left_the_account_still_vouches_through_its_pin() {
        let (a, b) = (TestDevice::new(1), TestDevice::new(2));
        let cert_b = a.vouch(&b);
        let idb = b.id();
        let verdicts = judge(&[a.trusted()], &[offered(&b, &idb, Some(&cert_b))]);
        assert_eq!(verdicts, vec![DeviceVerdict::Vouched { by: a.id() }]);
    }

    #[test]
    fn a_certificate_from_an_untrusted_signer_does_not_vouch() {
        // The server's own device R signs its second device S; the peer trusts only A.
        let (a, r, s) = (TestDevice::new(1), TestDevice::new(4), TestDevice::new(5));
        let cert_s = r.vouch(&s);
        let (idr, ids) = (r.id(), s.id());
        let verdicts = judge(
            &[a.trusted()],
            &[offered(&r, &idr, None), offered(&s, &ids, Some(&cert_s))],
        );
        assert_eq!(
            verdicts,
            vec![DeviceVerdict::Unvouched, DeviceVerdict::Unvouched]
        );
    }

    #[test]
    fn a_certificate_does_not_move_to_other_keys() {
        // A's certificate for B, presented on the server's device R.
        let (a, b, r) = (TestDevice::new(1), TestDevice::new(2), TestDevice::new(4));
        let cert_b = a.vouch(&b);
        let idr = r.id();
        let verdicts = judge(&[a.trusted()], &[offered(&r, &idr, Some(&cert_b))]);
        assert_eq!(verdicts, vec![DeviceVerdict::Unvouched]);
    }

    #[test]
    fn a_signer_key_other_than_the_pinned_one_does_not_vouch() {
        // R presents a certificate claiming to be from A, signed with R's own hybrid key.
        let (a, b, r) = (TestDevice::new(1), TestDevice::new(2), TestDevice::new(4));
        let message = certificate_message(
            &derive_device_id_bytes(&a.identity),
            &derive_device_id_bytes(&b.identity),
            &b.keys(),
            0,
        );
        let forged = DeviceCertificate {
            signer_device_id: derive_device_id_bytes(&a.identity),
            issued_at: 0,
            signer_hybrid_public: r.hybrid_public.clone(),
            signature: HybridSuiteProvider::sign(&r.hybrid_private, &message).unwrap(),
        }
        .encode();
        let idb = b.id();
        let verdicts = judge(&[a.trusted()], &[offered(&b, &idb, Some(&forged))]);
        assert_eq!(verdicts, vec![DeviceVerdict::Unvouched]);
    }

    #[test]
    fn a_pinned_device_with_another_hybrid_key_is_a_key_change() {
        let (a, other) = (TestDevice::new(1), TestDevice::new(4));
        let ida = a.id();
        let pinned_elsewhere = TrustedDevice {
            device_id: ida.clone(),
            hybrid_pin: Some(hybrid_pin(&other.hybrid_public)),
        };
        let verdicts = judge(&[pinned_elsewhere], &[offered(&a, &ida, None)]);
        assert_eq!(verdicts, vec![DeviceVerdict::KeyChanged]);
    }

    #[test]
    fn a_bundle_under_a_foreign_id_is_invalid() {
        let (a, b) = (TestDevice::new(1), TestDevice::new(2));
        let ida = a.id();
        let verdicts = judge(&[a.trusted()], &[offered(&b, &ida, None)]);
        assert_eq!(verdicts, vec![DeviceVerdict::Invalid]);
    }

    /// Pinned vectors — the contract with every other implementation.
    ///
    /// **These values come from this module**, the first implementation; there is no second one
    /// to take them from yet, so for now they pin the format against change, not its correctness.
    /// Mirrored in `construct-protos/conformance/knst_device_certificate.json`; a second
    /// implementation (Swift, Kotlin, `construct-client`) asserts the same bytes. Changing any
    /// value here is a wire change.
    #[test]
    fn pinned_vectors() {
        let (a, b) = (TestDevice::new(1), TestDevice::new(2));
        let message = certificate_message(
            &derive_device_id_bytes(&a.identity),
            &derive_device_id_bytes(&b.identity),
            &b.keys(),
            1_790_000_000,
        );
        let cert = a.vouch(&b);
        let proof = link_key_proof(&[7u8; LINK_SECRET_LEN], &b.identity, &b.hybrid_public).unwrap();
        let got = [
            a.id(),
            b.id(),
            hex::encode(Sha256::digest(&message)),
            hex::encode(Sha256::digest(&cert)),
            hex::encode(proof),
        ];
        assert_eq!(
            got,
            [
                "1a92f23852dc908d97316a3b13578281",
                "cfa570c653bd212b10a9cb551fd7a1b4",
                // SHA-256 of the signed message.
                "7ce25953620cb9464208b862c4eae1eb386461f381f89fa9d4d57c258befd855",
                // SHA-256 of the certificate; both halves of the hybrid signature are deterministic.
                "ed2a8b4c8b428cb7ffb71c774150cc9ca721add9e922dd284ad83376a3605a4c",
                // Flow A proof for secret 07×32.
                "e39d71c4bf86292eb426a8137eb246237c06e1524a8e7fbb20504658aaafac45",
            ]
            .map(String::from)
        );
    }

    #[test]
    fn certificate_round_trips_and_rejects_other_lengths() {
        let (a, b) = (TestDevice::new(1), TestDevice::new(2));
        let cert = a.vouch(&b);
        assert_eq!(cert.len(), CERT_LEN);
        assert_eq!(DeviceCertificate::decode(&cert).unwrap().encode(), cert);
        assert!(DeviceCertificate::decode(&cert[..cert.len() - 1]).is_none());
        let mut v2 = cert.clone();
        v2[0] = 2;
        assert!(DeviceCertificate::decode(&v2).is_none());
    }
}
