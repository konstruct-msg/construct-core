//! Which Kyber prekey an initiator encapsulates to — or whether it may open the session at all.
//!
//! # Why this is a plan in the core
//!
//! "Is this bundle's Kyber key usable, and what is the session called" is a decision two clients
//! must make identically; made in each client, it diverged before it existed (iOS logged
//! "proceeding via classic X3DH" on a failed hybrid check and then used the unverified Kyber key
//! anyway). The client hands over the bundle's Kyber keys and signatures and one fact it cannot
//! know from the bundle — whether this device has presented a signed Kyber SPK before — and gets
//! back what to do.
//!
//! # The rules
//!
//! | Bundle | Decision |
//! |---|---|
//! | a present signature does not verify, device never presented a signed SPK | classic, security error — this is tampering, not a transition (the server rejects such uploads) |
//! | a present signature does not verify, device presented one before | refuse |
//! | SPK signature verifies | encapsulate, [`Authenticated`] — to the OTPK if *its* signature verifies, else to the SPK |
//! | no verifiable SPK, device presented one before | refuse — the signature or the key was taken away |
//! | no signatures, device never presented one | encapsulate, [`Unauthenticated`] — OTPK first, as before |
//! | no Kyber key, device never presented one | classic |
//!
//! Stripping the key or its signature is the real attack of a transition period: a client that
//! silently falls back to classic makes it invisible. Remembering that a device has presented a
//! signed SPK is what makes it visible, and a signature that is *present and wrong* is the same
//! strip by other means — so for a remembered device it is refused too.
//!
//! **An unsigned OTPK never wins over a verified SPK.** The server's bundle has no field for the
//! OTPK's signature (iOS signs OTPKs; `DevicePreKeyBundle` does not carry it), so today every OTPK
//! is unsigned. Preferring it would let whoever serves the bundle choose the unauthenticated key
//! over the authenticated one — the downgrade this plan exists to stop. The cost is the OTPK's
//! one-time property for the PQ layer; the classical layer keeps its own OTPK. Once the bundle
//! carries the OTPK signature, a verified OTPK is used again.
//!
//! A build without `post-quantum` cannot encapsulate at all; it opens classic sessions and refuses
//! nothing, since refusing would break every PQ peer.
//!
//! [`Authenticated`]: PqAuthentication::Authenticated
//! [`Unauthenticated`]: PqAuthentication::Unauthenticated

use crate::crypto::kyber_prekey_auth::{
    KyberPrekeySignature, PqAuthentication, check_kyber_prekey_signature,
};

/// The Kyber half of a peer's bundle, as fetched.
#[derive(Debug, Clone, Copy, Default)]
pub struct KyberPrekeyOffer<'a> {
    /// The bundle's Ed25519 identity signing key (`verifying_key`) — the one that signed the
    /// classic SPK this crate already verifies.
    pub verifying_key: &'a [u8],
    pub spk_public: Option<&'a [u8]>,
    pub spk_signature: Option<&'a [u8]>,
    pub otpk_public: Option<&'a [u8]>,
    pub otpk_id: Option<u32>,
    pub otpk_signature: Option<&'a [u8]>,
}

/// What this device already knows about the peer device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KyberPrekeyContext {
    /// This build can run ML-KEM (`post-quantum` feature).
    pub local_pq_available: bool,
    /// The peer device has presented a Kyber SPK whose signature verified, in an earlier bundle.
    pub presented_signed_spk_before: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicReason {
    /// The bundle has no Kyber key.
    NoKyberKey,
    /// A Kyber signature in the bundle is present and does not verify. Log as a security event.
    InvalidSignature,
    /// This build has no ML-KEM.
    LocalBuildWithoutPq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// The device presented a signed Kyber SPK before; this bundle has none, or none that
    /// verifies.
    SignedKyberWithdrawn,
    /// The device presented a signed Kyber SPK before; this bundle's signature is wrong.
    InvalidSignature,
    /// The device advertised the sparse PQ ratchet (suite 3) before, or opened a suite-3
    /// session with us; this bundle does not advertise it.
    PqRatchetWithdrawn,
}

/// Whether an initiator may open a session with a device whose bundle does not advertise the
/// sparse PQ ratchet (suite 3). `None`: go ahead, and negotiation picks what the bundle offers.
///
/// `supports_pq_ratchet` is a flag the server serves beside the bundle, unsigned. Dropping it is
/// the cheapest downgrade there is: the initiator negotiates `CLASSIC`, nothing fails, and the
/// session simply never gets its PQ ratchet. A device that has advertised the ratchet — or used
/// it with us — and now arrives without it is the same strip as a missing Kyber signature, and
/// is refused the same way.
///
/// A build without the ratchet (`local_pq_ratchet_available == false`) refuses nothing: it
/// would negotiate `CLASSIC` with every peer anyway.
pub fn plan_pq_ratchet_capability(
    local_pq_ratchet_available: bool,
    advertised: bool,
    advertised_before: bool,
) -> Option<RefuseReason> {
    (local_pq_ratchet_available && advertised_before && !advertised)
        .then_some(RefuseReason::PqRatchetWithdrawn)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KyberPrekeyDecision {
    /// Encapsulate to `kyber_public`. `otpk_id` is the Kyber OTPK id to report, 0 for the SPK.
    Encapsulate {
        kyber_public: Vec<u8>,
        otpk_id: u32,
        authentication: PqAuthentication,
    },
    /// Open a classical session.
    Classic { reason: ClassicReason },
    /// Do not open the session.
    Refuse { reason: RefuseReason },
}

/// The decision, and whether the caller must now remember that this device presented a signed
/// Kyber SPK (true exactly when the SPK signature verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KyberPrekeyPlan {
    pub decision: KyberPrekeyDecision,
    pub presented_signed_spk: bool,
}

pub fn plan_kyber_prekey(offer: KyberPrekeyOffer<'_>, ctx: KyberPrekeyContext) -> KyberPrekeyPlan {
    let judge = |public: Option<&[u8]>, signature: Option<&[u8]>| {
        public.map(|pk| check_kyber_prekey_signature(offer.verifying_key, pk, signature))
    };
    let spk = judge(offer.spk_public, offer.spk_signature);
    let otpk = judge(offer.otpk_public, offer.otpk_signature);
    let presented_signed_spk = spk == Some(KyberPrekeySignature::Valid);
    let plan = |decision| KyberPrekeyPlan {
        decision,
        presented_signed_spk,
    };

    if !ctx.local_pq_available {
        return plan(KyberPrekeyDecision::Classic {
            reason: ClassicReason::LocalBuildWithoutPq,
        });
    }

    let invalid = Some(KyberPrekeySignature::Invalid);
    if spk == invalid || otpk == invalid {
        return plan(if ctx.presented_signed_spk_before {
            KyberPrekeyDecision::Refuse {
                reason: RefuseReason::InvalidSignature,
            }
        } else {
            KyberPrekeyDecision::Classic {
                reason: ClassicReason::InvalidSignature,
            }
        });
    }

    let encapsulate =
        |public: Option<&[u8]>, otpk_id: u32, authentication| KyberPrekeyDecision::Encapsulate {
            kyber_public: public.map(<[u8]>::to_vec).unwrap_or_default(),
            otpk_id,
            authentication,
        };
    let otpk_id = offer.otpk_id.unwrap_or(0);
    let valid = Some(KyberPrekeySignature::Valid);

    if otpk == valid {
        return plan(encapsulate(
            offer.otpk_public,
            otpk_id,
            PqAuthentication::Authenticated,
        ));
    }
    if spk == valid {
        return plan(encapsulate(
            offer.spk_public,
            0,
            PqAuthentication::Authenticated,
        ));
    }
    if ctx.presented_signed_spk_before {
        return plan(KyberPrekeyDecision::Refuse {
            reason: RefuseReason::SignedKyberWithdrawn,
        });
    }
    if otpk.is_some() {
        return plan(encapsulate(
            offer.otpk_public,
            otpk_id,
            PqAuthentication::Unauthenticated,
        ));
    }
    if spk.is_some() {
        return plan(encapsulate(
            offer.spk_public,
            0,
            PqAuthentication::Unauthenticated,
        ));
    }
    plan(KyberPrekeyDecision::Classic {
        reason: ClassicReason::NoKyberKey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyManager;
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    struct Peer {
        sk: crate::crypto::SecretBytes,
        vk: Vec<u8>,
    }

    impl Peer {
        fn new() -> Self {
            let (sk, vk) = ClassicSuiteProvider::generate_signature_keys().unwrap();
            Self { sk, vk }
        }
        fn sign(&self, kyber_public: &[u8]) -> Vec<u8> {
            let msg =
                KeyManager::<ClassicSuiteProvider>::build_x3dh_sign_message(0x10, kyber_public);
            ClassicSuiteProvider::sign(&self.sk, &msg).unwrap()
        }
    }

    const SPK: &[u8] = &[1; 1184];
    const OTPK: &[u8] = &[2; 1184];

    fn fresh() -> KyberPrekeyContext {
        KyberPrekeyContext {
            local_pq_available: true,
            presented_signed_spk_before: false,
        }
    }
    fn remembered() -> KyberPrekeyContext {
        KyberPrekeyContext {
            presented_signed_spk_before: true,
            ..fresh()
        }
    }

    fn encapsulates(plan: &KyberPrekeyPlan, key: &[u8], id: u32, auth: PqAuthentication) -> bool {
        plan.decision
            == KyberPrekeyDecision::Encapsulate {
                kyber_public: key.to_vec(),
                otpk_id: id,
                authentication: auth,
            }
    }

    #[test]
    fn a_signed_spk_is_authenticated_and_remembered() {
        let peer = Peer::new();
        let sig = peer.sign(SPK);
        let plan = plan_kyber_prekey(
            KyberPrekeyOffer {
                verifying_key: &peer.vk,
                spk_public: Some(SPK),
                spk_signature: Some(&sig),
                ..Default::default()
            },
            fresh(),
        );
        assert!(encapsulates(&plan, SPK, 0, PqAuthentication::Authenticated));
        assert!(plan.presented_signed_spk);
    }

    /// Mutation: prefer any OTPK over the SPK — this reddens.
    #[test]
    fn an_unsigned_otpk_does_not_win_over_a_verified_spk() {
        let peer = Peer::new();
        let sig = peer.sign(SPK);
        let plan = plan_kyber_prekey(
            KyberPrekeyOffer {
                verifying_key: &peer.vk,
                spk_public: Some(SPK),
                spk_signature: Some(&sig),
                otpk_public: Some(OTPK),
                otpk_id: Some(9),
                otpk_signature: None,
            },
            fresh(),
        );
        assert!(encapsulates(&plan, SPK, 0, PqAuthentication::Authenticated));
    }

    #[test]
    fn a_verified_otpk_is_preferred() {
        let peer = Peer::new();
        let (spk_sig, otpk_sig) = (peer.sign(SPK), peer.sign(OTPK));
        let plan = plan_kyber_prekey(
            KyberPrekeyOffer {
                verifying_key: &peer.vk,
                spk_public: Some(SPK),
                spk_signature: Some(&spk_sig),
                otpk_public: Some(OTPK),
                otpk_id: Some(9),
                otpk_signature: Some(&otpk_sig),
            },
            fresh(),
        );
        assert!(encapsulates(
            &plan,
            OTPK,
            9,
            PqAuthentication::Authenticated
        ));
    }

    #[test]
    fn unsigned_keys_from_a_new_device_are_used_and_labelled() {
        let peer = Peer::new();
        let with_otpk = plan_kyber_prekey(
            KyberPrekeyOffer {
                verifying_key: &peer.vk,
                spk_public: Some(SPK),
                otpk_public: Some(OTPK),
                otpk_id: Some(4),
                ..Default::default()
            },
            fresh(),
        );
        assert!(encapsulates(
            &with_otpk,
            OTPK,
            4,
            PqAuthentication::Unauthenticated
        ));
        assert!(!with_otpk.presented_signed_spk);

        let spk_only = plan_kyber_prekey(
            KyberPrekeyOffer {
                verifying_key: &peer.vk,
                spk_public: Some(SPK),
                ..Default::default()
            },
            fresh(),
        );
        assert!(encapsulates(
            &spk_only,
            SPK,
            0,
            PqAuthentication::Unauthenticated
        ));
    }

    #[test]
    fn a_wrong_signature_is_never_used() {
        let peer = Peer::new();
        let other = Peer::new();
        let forged = other.sign(SPK);
        let offer = KyberPrekeyOffer {
            verifying_key: &peer.vk,
            spk_public: Some(SPK),
            spk_signature: Some(&forged),
            otpk_public: Some(OTPK),
            otpk_id: Some(4),
            ..Default::default()
        };
        assert_eq!(
            plan_kyber_prekey(offer, fresh()).decision,
            KyberPrekeyDecision::Classic {
                reason: ClassicReason::InvalidSignature
            },
            "not even the unsigned OTPK of the same bundle"
        );
        assert_eq!(
            plan_kyber_prekey(offer, remembered()).decision,
            KyberPrekeyDecision::Refuse {
                reason: RefuseReason::InvalidSignature
            }
        );
    }

    /// The transition-period attack: the key or its signature taken away from a device known to
    /// sign. Mutation: fall back to classic here — this reddens.
    #[test]
    fn a_remembered_device_without_a_verifiable_spk_is_refused() {
        let peer = Peer::new();
        let stripped_signature = KyberPrekeyOffer {
            verifying_key: &peer.vk,
            spk_public: Some(SPK),
            otpk_public: Some(OTPK),
            otpk_id: Some(4),
            ..Default::default()
        };
        let stripped_key = KyberPrekeyOffer {
            verifying_key: &peer.vk,
            ..Default::default()
        };
        for offer in [stripped_signature, stripped_key] {
            assert_eq!(
                plan_kyber_prekey(offer, remembered()).decision,
                KyberPrekeyDecision::Refuse {
                    reason: RefuseReason::SignedKyberWithdrawn
                }
            );
        }
    }

    #[test]
    fn no_kyber_key_from_a_new_device_is_classic() {
        let peer = Peer::new();
        let plan = plan_kyber_prekey(
            KyberPrekeyOffer {
                verifying_key: &peer.vk,
                ..Default::default()
            },
            fresh(),
        );
        assert_eq!(
            plan.decision,
            KyberPrekeyDecision::Classic {
                reason: ClassicReason::NoKyberKey
            }
        );
    }

    /// Only a device known to have the PQ ratchet, arriving without it, is refused — and only
    /// by a build that has the ratchet itself.
    #[test]
    fn pq_ratchet_capability_rows() {
        // (local, advertised, before) -> refused?
        let rows = [
            ((true, true, true), false),
            ((true, true, false), false),
            ((true, false, false), false),
            ((true, false, true), true),
            ((false, false, true), false),
        ];
        for ((local, advertised, before), refused) in rows {
            assert_eq!(
                plan_pq_ratchet_capability(local, advertised, before),
                refused.then_some(RefuseReason::PqRatchetWithdrawn),
                "local={local} advertised={advertised} before={before}"
            );
        }
    }

    #[test]
    fn a_build_without_pq_refuses_nothing() {
        let peer = Peer::new();
        let plan = plan_kyber_prekey(
            KyberPrekeyOffer {
                verifying_key: &peer.vk,
                ..Default::default()
            },
            KyberPrekeyContext {
                local_pq_available: false,
                presented_signed_spk_before: true,
            },
        );
        assert_eq!(
            plan.decision,
            KyberPrekeyDecision::Classic {
                reason: ClassicReason::LocalBuildWithoutPq
            }
        );
    }
}
