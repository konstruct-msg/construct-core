//! Which Kyber prekey an initiator encapsulates to — or why it opens no session at all (PQXDH v2).
//!
//! PQ is mandatory for new sessions (construct-docs `decisions/pqxdh-v2-mandatory-pq-cutover.md`):
//! there is no classic outcome. A bundle either yields a Kyber prekey this device can trust, or
//! the session is refused before anything is created (`PQ_REQUIRED: <reason>`). The table is
//! `cryptocore/PQXDH_V2_DESIGN.md` §5.4.
//!
//! What "trust" means here:
//! - the device's **hybrid identity key** (Ed25519 + ML-DSA-65) is in the bundle, bound to its
//!   Ed25519 identity by the cross-signature, and is the one pinned for this device the first time
//!   it was seen — the binding alone is Ed25519, which is what a quantum adversary could forge;
//! - the Kyber prekey carries **both** signatures over
//!   `"KonstruktX3DH-v1" ‖ 0x00 0x11 ‖ created_at ‖ public`: Ed25519 by the identity key and
//!   hybrid by the pinned hybrid key;
//! - a signed prekey is no older than `KYBER_SPK_MAX_AGE_SECS` by its **signed** time.
//!
//! A one-time prekey is preferred (its secret is burned after use). Anything wrong with it falls
//! back to the signed prekey rather than refusing: a server can always omit the one-time key, so
//! refusing on a bad one would add no protection and cost availability.

use crate::crypto::kyber_prekey_auth::{
    KYBER_SPK_MAX_AGE_SECS, KyberPrekeySignature, check_kyber_prekey_hybrid_signature,
    check_kyber_prekey_signature_v2,
};
use crate::crypto::kyber_prekeys::KYBER_OTPK_ID_START;
use crate::crypto::pq_x3dh::MLKEM1024_PK_SIZE;

/// One Kyber prekey as the bundle presents it.
#[derive(Debug, Clone, Copy)]
pub struct KyberPrekeyOffer<'a> {
    pub key_id: u32,
    pub public: &'a [u8],
    /// Signed creation time; the signatures cannot verify without it.
    pub created_at: Option<u64>,
    pub signature: Option<&'a [u8]>,
    pub hybrid_signature: Option<&'a [u8]>,
}

/// The PQ-relevant part of a peer device's bundle.
#[derive(Debug, Clone, Copy)]
pub struct PqxdhOffer<'a> {
    /// Ed25519 identity verifying key (the bundle's `verifying_key`).
    pub verifying_key: &'a [u8],
    /// Hybrid identity key (key-service field 20).
    pub hybrid_identity_key: Option<&'a [u8]>,
    /// Ed25519 cross-signature binding it to `verifying_key` (field 21).
    pub hybrid_identity_signature: Option<&'a [u8]>,
    pub signed_prekey: Option<KyberPrekeyOffer<'a>>,
    pub one_time_prekey: Option<KyberPrekeyOffer<'a>>,
}

/// What this device already knows.
#[derive(Debug, Clone, Copy)]
pub struct PqxdhContext<'a> {
    pub now: u64,
    /// SHA-256 of the hybrid identity key pinned for this device, if it was seen before.
    pub pinned_hybrid_identity: Option<&'a [u8; 32]>,
}

/// Why no session is opened. `PQ_REQUIRED: {reason:?}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqxdhRefusal {
    /// The bundle has no Kyber signed prekey.
    NoKyberPrekey,
    /// Wrong size or an id outside its range.
    KyberPrekeyMalformed,
    /// No Ed25519 signature (or no signed time) on the Kyber signed prekey.
    KyberSignatureMissing,
    /// An Ed25519 signature that does not verify — tampering, not a transition.
    KyberSignatureInvalid,
    /// Older than `KYBER_SPK_MAX_AGE_SECS` by its signed time.
    KyberPrekeyStale,
    /// No hybrid identity key, or no cross-signature binding it.
    HybridIdentityMissing,
    /// The cross-signature does not verify under the device's identity key.
    HybridIdentityBindingInvalid,
    /// A hybrid identity key other than the one pinned for this device.
    HybridIdentityChanged,
    /// No hybrid signature on the Kyber signed prekey.
    HybridSignatureMissing,
    /// A hybrid signature that does not verify.
    HybridSignatureInvalid,
}

/// The prekey to encapsulate to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqxdhChoice {
    pub kyber_prekey_id: u32,
    pub kyber_public: Vec<u8>,
    /// SHA-256 of the hybrid identity key that authenticated it — pin it once X3DH has verified
    /// the bundle.
    pub hybrid_identity_fingerprint: [u8; 32],
    /// A one-time prekey was offered and could not be used (logged by the caller).
    pub one_time_prekey_rejected: Option<PqxdhRefusal>,
}

pub fn hybrid_identity_fingerprint(hybrid_identity_key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(hybrid_identity_key).into()
}

pub fn plan_pqxdh(
    offer: &PqxdhOffer<'_>,
    ctx: &PqxdhContext<'_>,
) -> Result<PqxdhChoice, PqxdhRefusal> {
    let hybrid_key = check_hybrid_identity(offer)?;
    let fingerprint = hybrid_identity_fingerprint(hybrid_key);
    if let Some(pinned) = ctx.pinned_hybrid_identity
        && *pinned != fingerprint
    {
        return Err(PqxdhRefusal::HybridIdentityChanged);
    }

    let mut one_time_prekey_rejected = None;
    if let Some(otpk) = offer.one_time_prekey {
        match check_prekey(
            offer.verifying_key,
            hybrid_key,
            &otpk,
            Range::OneTime,
            ctx.now,
        ) {
            Ok(()) => {
                return Ok(PqxdhChoice {
                    kyber_prekey_id: otpk.key_id,
                    kyber_public: otpk.public.to_vec(),
                    hybrid_identity_fingerprint: fingerprint,
                    one_time_prekey_rejected: None,
                });
            }
            Err(reason) => one_time_prekey_rejected = Some(reason),
        }
    }

    let spk = offer.signed_prekey.ok_or(PqxdhRefusal::NoKyberPrekey)?;
    check_prekey(
        offer.verifying_key,
        hybrid_key,
        &spk,
        Range::Signed,
        ctx.now,
    )?;
    Ok(PqxdhChoice {
        kyber_prekey_id: spk.key_id,
        kyber_public: spk.public.to_vec(),
        hybrid_identity_fingerprint: fingerprint,
        one_time_prekey_rejected,
    })
}

fn check_hybrid_identity<'a>(offer: &PqxdhOffer<'a>) -> Result<&'a [u8], PqxdhRefusal> {
    use crate::crypto::keys::KeyManager;
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    let key = offer
        .hybrid_identity_key
        .filter(|k| !k.is_empty())
        .ok_or(PqxdhRefusal::HybridIdentityMissing)?;
    let binding = offer
        .hybrid_identity_signature
        .filter(|s| !s.is_empty())
        .ok_or(PqxdhRefusal::HybridIdentityMissing)?;
    let message = KeyManager::<ClassicSuiteProvider>::build_hybrid_identity_bind_message(key);
    let vk = ClassicSuiteProvider::signature_public_key_from_bytes(offer.verifying_key.to_vec());
    ClassicSuiteProvider::verify(&vk, &message, binding)
        .map_err(|_| PqxdhRefusal::HybridIdentityBindingInvalid)?;
    Ok(key)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Range {
    Signed,
    OneTime,
}

fn check_prekey(
    verifying_key: &[u8],
    hybrid_key: &[u8],
    prekey: &KyberPrekeyOffer<'_>,
    range: Range,
    now: u64,
) -> Result<(), PqxdhRefusal> {
    let id_ok = match range {
        Range::Signed => (1..KYBER_OTPK_ID_START).contains(&prekey.key_id),
        Range::OneTime => prekey.key_id >= KYBER_OTPK_ID_START,
    };
    if prekey.public.len() != MLKEM1024_PK_SIZE || !id_ok {
        return Err(PqxdhRefusal::KyberPrekeyMalformed);
    }
    let created_at = prekey
        .created_at
        .ok_or(PqxdhRefusal::KyberSignatureMissing)?;
    match check_kyber_prekey_signature_v2(
        verifying_key,
        prekey.public,
        created_at,
        prekey.signature,
    ) {
        KyberPrekeySignature::Valid => {}
        KyberPrekeySignature::Missing => return Err(PqxdhRefusal::KyberSignatureMissing),
        KyberPrekeySignature::Invalid => return Err(PqxdhRefusal::KyberSignatureInvalid),
    }
    match check_kyber_prekey_hybrid_signature(
        hybrid_key,
        prekey.public,
        created_at,
        prekey.hybrid_signature,
    ) {
        KyberPrekeySignature::Valid => {}
        KyberPrekeySignature::Missing => return Err(PqxdhRefusal::HybridSignatureMissing),
        KyberPrekeySignature::Invalid => return Err(PqxdhRefusal::HybridSignatureInvalid),
    }
    // A one-time key is burned on use; replaying one only reaches a deleted secret.
    if range == Range::Signed && now.saturating_sub(created_at) > KYBER_SPK_MAX_AGE_SECS {
        return Err(PqxdhRefusal::KyberPrekeyStale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyManager;
    use crate::crypto::kyber_prekey_auth::kyber_prekey_sign_message_v2;
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::classic::ClassicSuiteProvider;
    use crate::crypto::suites::hybrid::HybridSuiteProvider;

    const NOW: u64 = 1_800_000_000;

    /// A peer device: identity signing key, hybrid key bound to it, and a way to sign prekeys.
    struct Peer {
        sk: Vec<u8>,
        vk: Vec<u8>,
        hsk: crate::crypto::SecretBytes,
        hpk: Vec<u8>,
        binding: Vec<u8>,
    }

    struct Prekey {
        id: u32,
        public: Vec<u8>,
        created_at: u64,
        sig: Vec<u8>,
        hsig: Vec<u8>,
    }

    impl Peer {
        fn new() -> Self {
            let (sk, vk) = ClassicSuiteProvider::generate_signature_keys().unwrap();
            let (hsk, hpk) = HybridSuiteProvider::generate_signature_keys().unwrap();
            let bind = KeyManager::<ClassicSuiteProvider>::build_hybrid_identity_bind_message(&hpk);
            let binding = ClassicSuiteProvider::sign(&sk, &bind).unwrap();
            Self {
                sk: sk.as_ref().to_vec(),
                vk,
                hsk,
                hpk,
                binding,
            }
        }

        fn prekey(&self, id: u32, created_at: u64) -> Prekey {
            let public = vec![id as u8; MLKEM1024_PK_SIZE];
            let msg = kyber_prekey_sign_message_v2(created_at, &public);
            let sk = ClassicSuiteProvider::signature_private_key_from_bytes(self.sk.clone());
            Prekey {
                id,
                sig: ClassicSuiteProvider::sign(&sk, &msg).unwrap(),
                hsig: HybridSuiteProvider::sign(&self.hsk, &msg).unwrap(),
                public,
                created_at,
            }
        }
    }

    fn offer_of(p: &Prekey) -> KyberPrekeyOffer<'_> {
        KyberPrekeyOffer {
            key_id: p.id,
            public: &p.public,
            created_at: Some(p.created_at),
            signature: Some(&p.sig),
            hybrid_signature: Some(&p.hsig),
        }
    }

    fn bundle<'a>(
        peer: &'a Peer,
        spk: Option<&'a Prekey>,
        otpk: Option<&'a Prekey>,
    ) -> PqxdhOffer<'a> {
        PqxdhOffer {
            verifying_key: &peer.vk,
            hybrid_identity_key: Some(&peer.hpk),
            hybrid_identity_signature: Some(&peer.binding),
            signed_prekey: spk.map(offer_of),
            one_time_prekey: otpk.map(offer_of),
        }
    }

    fn ctx() -> PqxdhContext<'static> {
        PqxdhContext {
            now: NOW,
            pinned_hybrid_identity: None,
        }
    }

    #[test]
    fn a_signed_one_time_key_is_preferred() {
        let peer = Peer::new();
        let (spk, otpk) = (peer.prekey(3, NOW), peer.prekey(1_000_005, NOW));
        let choice = plan_pqxdh(&bundle(&peer, Some(&spk), Some(&otpk)), &ctx()).unwrap();
        assert_eq!(choice.kyber_prekey_id, 1_000_005);
        assert_eq!(choice.kyber_public, otpk.public);
        assert_eq!(
            choice.hybrid_identity_fingerprint,
            hybrid_identity_fingerprint(&peer.hpk)
        );
    }

    #[test]
    fn without_a_usable_one_time_key_the_signed_key_is_used() {
        let peer = Peer::new();
        let spk = peer.prekey(3, NOW);
        let choice = plan_pqxdh(&bundle(&peer, Some(&spk), None), &ctx()).unwrap();
        assert_eq!(choice.kyber_prekey_id, 3);
        assert_eq!(choice.one_time_prekey_rejected, None);

        // An unsigned one-time key (the server not serving its signature yet) and a tampered one
        // both fall back to the signed key — the server could have omitted either.
        let mut unsigned = peer.prekey(1_000_001, NOW);
        unsigned.sig.clear();
        let choice = plan_pqxdh(&bundle(&peer, Some(&spk), Some(&unsigned)), &ctx()).unwrap();
        assert_eq!(choice.kyber_prekey_id, 3);
        assert_eq!(
            choice.one_time_prekey_rejected,
            Some(PqxdhRefusal::KyberSignatureMissing)
        );

        let mut tampered = peer.prekey(1_000_002, NOW);
        tampered.public[0] ^= 1;
        let choice = plan_pqxdh(&bundle(&peer, Some(&spk), Some(&tampered)), &ctx()).unwrap();
        assert_eq!(
            choice.one_time_prekey_rejected,
            Some(PqxdhRefusal::KyberSignatureInvalid)
        );
    }

    /// Every row of the table that ends in a refusal.
    #[test]
    fn each_refusal() {
        let peer = Peer::new();
        let good = peer.prekey(3, NOW);
        let refuse = |offer: PqxdhOffer<'_>| plan_pqxdh(&offer, &ctx()).unwrap_err();

        assert_eq!(
            refuse(bundle(&peer, None, None)),
            PqxdhRefusal::NoKyberPrekey
        );

        let mut short = peer.prekey(3, NOW);
        short.public.truncate(1184);
        assert_eq!(
            refuse(bundle(&peer, Some(&short), None)),
            PqxdhRefusal::KyberPrekeyMalformed
        );
        let one_time_id_as_spk = peer.prekey(1_000_000, NOW);
        assert_eq!(
            refuse(bundle(&peer, Some(&one_time_id_as_spk), None)),
            PqxdhRefusal::KyberPrekeyMalformed
        );

        let mut no_sig = peer.prekey(3, NOW);
        no_sig.sig.clear();
        assert_eq!(
            refuse(bundle(&peer, Some(&no_sig), None)),
            PqxdhRefusal::KyberSignatureMissing
        );
        let mut no_time = bundle(&peer, Some(&good), None);
        no_time.signed_prekey.as_mut().unwrap().created_at = None;
        assert_eq!(refuse(no_time), PqxdhRefusal::KyberSignatureMissing);

        let mut rewritten_time = bundle(&peer, Some(&good), None);
        rewritten_time.signed_prekey.as_mut().unwrap().created_at = Some(NOW + 1);
        assert_eq!(refuse(rewritten_time), PqxdhRefusal::KyberSignatureInvalid);

        let stale = peer.prekey(3, NOW - KYBER_SPK_MAX_AGE_SECS - 1);
        assert_eq!(
            refuse(bundle(&peer, Some(&stale), None)),
            PqxdhRefusal::KyberPrekeyStale
        );
        let old_but_fine = peer.prekey(3, NOW - KYBER_SPK_MAX_AGE_SECS);
        assert!(plan_pqxdh(&bundle(&peer, Some(&old_but_fine), None), &ctx()).is_ok());

        let mut no_hsig = peer.prekey(3, NOW);
        no_hsig.hsig.clear();
        assert_eq!(
            refuse(bundle(&peer, Some(&no_hsig), None)),
            PqxdhRefusal::HybridSignatureMissing
        );
        let other = Peer::new();
        let mut foreign_hsig = peer.prekey(3, NOW);
        foreign_hsig.hsig = other.prekey(3, NOW).hsig;
        assert_eq!(
            refuse(bundle(&peer, Some(&foreign_hsig), None)),
            PqxdhRefusal::HybridSignatureInvalid
        );

        let mut no_hybrid = bundle(&peer, Some(&good), None);
        no_hybrid.hybrid_identity_key = None;
        assert_eq!(refuse(no_hybrid), PqxdhRefusal::HybridIdentityMissing);
        let mut no_binding = bundle(&peer, Some(&good), None);
        no_binding.hybrid_identity_signature = None;
        assert_eq!(refuse(no_binding), PqxdhRefusal::HybridIdentityMissing);
        let mut foreign_binding = bundle(&peer, Some(&good), None);
        foreign_binding.hybrid_identity_signature = Some(&other.binding);
        assert_eq!(
            refuse(foreign_binding),
            PqxdhRefusal::HybridIdentityBindingInvalid
        );
    }

    /// A server that swaps in its own hybrid key — with a binding it can only forge by breaking
    /// Ed25519 — is caught by the pin, not the binding.
    #[test]
    fn a_changed_hybrid_identity_is_refused() {
        let peer = Peer::new();
        let spk = peer.prekey(3, NOW);
        let pinned = hybrid_identity_fingerprint(&peer.hpk);
        let with_pin = PqxdhContext {
            now: NOW,
            pinned_hybrid_identity: Some(&pinned),
        };
        assert!(plan_pqxdh(&bundle(&peer, Some(&spk), None), &with_pin).is_ok());

        let other = Peer::new();
        let other_pin = hybrid_identity_fingerprint(&other.hpk);
        let pinned_other = PqxdhContext {
            now: NOW,
            pinned_hybrid_identity: Some(&other_pin),
        };
        assert_eq!(
            plan_pqxdh(&bundle(&peer, Some(&spk), None), &pinned_other).unwrap_err(),
            PqxdhRefusal::HybridIdentityChanged
        );
    }
}
