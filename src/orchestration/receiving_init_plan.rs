//! Which message can open a receiving session.
//!
//! A classification over the header, and the header only: whether a message *could* open a
//! session must not require holding its body. `Orchestrator::open_receiving` asks it of each
//! queued carrier; `message_router::opens_session` asks it of a message no state decrypted.
//!
//! Until 2026-09-27 the answer was "message number 0, unless a PQ epoch says it is a re-key", and
//! it was the one line that kept a session from opening from any message but the first. The
//! initiator repeats the handshake header on every message until the peer answers, and the
//! ratchet skips to message N on its own, so the first message was never needed — only its
//! header. PQXDH is mandatory: every handshake carries a KEM ciphertext, and nothing else does
//! (`construct-docs/decisions/sessions-renew-by-sending.md`).

/// The wire-visible shape of a message — everything the rule reads, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivingInitCarrier {
    pub message_number: u32,
    pub one_time_prekey_id: u32,
    pub kem_ciphertext_bytes: u32,
    pub pq_message_epoch: u32,
}

/// What a message is, for the purpose of opening a receiving session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceivingInitKind {
    /// Carries the initiator's handshake header: this message can open a session.
    Handshake,
    /// Carries none. It decrypts on a state we hold or not at all.
    MidRatchet,
}

/// Classify one message.
///
/// With `post-quantum` — every platform build — a KEM ciphertext is the handshake, at any message
/// number. A build without it has no ciphertext to go by, and keeps the rule a classical first
/// flight allows: message 0 without a PQ epoch, or any message naming a one-time pre-key.
pub fn receiving_init_kind(carrier: &ReceivingInitCarrier) -> ReceivingInitKind {
    if carrier.kem_ciphertext_bytes > 0 {
        return ReceivingInitKind::Handshake;
    }
    if cfg!(not(feature = "post-quantum"))
        && (carrier.one_time_prekey_id != 0
            || (carrier.message_number == 0 && carrier.pq_message_epoch == 0))
    {
        return ReceivingInitKind::Handshake;
    }
    ReceivingInitKind::MidRatchet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carrier(message_number: u32, kem_ciphertext_bytes: u32) -> ReceivingInitCarrier {
        ReceivingInitCarrier {
            message_number,
            one_time_prekey_id: 0,
            kem_ciphertext_bytes,
            pq_message_epoch: 0,
        }
    }

    /// The change of 2026-09-27, stated as a test: a header on message 5 opens. The rule it
    /// replaces answered `MidRatchet` on any number but 0, and a lost first message cost the
    /// session until a reset.
    #[test]
    fn a_header_opens_at_any_message_number() {
        assert_eq!(
            receiving_init_kind(&carrier(5, 1568)),
            ReceivingInitKind::Handshake
        );
        assert_eq!(
            receiving_init_kind(&carrier(0, 1568)),
            ReceivingInitKind::Handshake
        );
    }

    #[test]
    fn a_message_without_a_header_never_opens() {
        assert_eq!(
            receiving_init_kind(&carrier(3, 0)),
            ReceivingInitKind::MidRatchet
        );
    }

    /// A build with PQXDH has no classical handshake: a bare message 0 is a DH chain restarting,
    /// not an opener.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn a_bare_first_message_is_not_a_handshake() {
        assert_eq!(
            receiving_init_kind(&carrier(0, 0)),
            ReceivingInitKind::MidRatchet
        );
        let mut with_otpk = carrier(0, 0);
        with_otpk.one_time_prekey_id = 1_000_461;
        assert_eq!(
            receiving_init_kind(&with_otpk),
            ReceivingInitKind::MidRatchet
        );
    }

    #[cfg(not(feature = "post-quantum"))]
    #[test]
    fn a_classical_build_opens_from_a_bare_first_message() {
        assert_eq!(
            receiving_init_kind(&carrier(0, 0)),
            ReceivingInitKind::Handshake
        );
        let mut leftover = carrier(0, 0);
        leftover.pq_message_epoch = 4;
        assert_eq!(
            receiving_init_kind(&leftover),
            ReceivingInitKind::MidRatchet
        );
    }
}
