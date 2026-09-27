//! Which queued message can open a receiving session.
//!
//! A classification over the header, and the header only: whether a message *could* open a
//! session must not require holding its body. `Orchestrator::open_receiving` asks it of each
//! queued carrier; `message_router::opens_session` asks it of a refused one.
//!
//! Until 2026-09-27 this module also planned the attempts — every carrier against every device
//! bundle of the account (`plan_receiving_init`), because nothing the recipient held said which
//! device had written the message. The sender certificate says so, signed, and the key it names is
//! the key a session opens with; there is nothing left to search
//! (`construct-docs/decisions/first-message-opens-without-the-server.md`).

/// The wire-visible shape of a queued message — everything the eligibility rule reads, and nothing
/// else. No ciphertext: deciding whether a message *could* be a handshake must not require holding
/// its body, so the client can plan before it commits to anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivingInitCarrier {
    pub message_number: u32,
    pub one_time_prekey_id: u32,
    pub kem_ciphertext_bytes: u32,
    pub pq_message_epoch: u32,
    pub is_session_reset_init: bool,
}

/// What a queued message is, for the purpose of opening a receiving session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceivingInitKind {
    /// Carries an X3DH init: this message can open a session.
    Handshake,
    /// Already inside a ratchet. Initialising from it fails and destroys the queue behind it.
    MidRatchet,
    /// `message_number == 0` but a PQ epoch has advanced, so it is a re-keyed continuation rather
    /// than a fresh handshake. Shaped like an opener and is not one — which is exactly why the
    /// rule is a named function and not an inline `msg_number == 0`.
    MidSessionLeftover,
}

/// Classify one queued message.
///
/// Order matters and each line is load-bearing: a `session_reset_init` is an opener whatever else
/// it looks like; an OTPK id or a KEM ciphertext proves an X3DH header is present; a PQ epoch on an
/// otherwise bare `message_number == 0` means a re-key, not a first message.
pub fn receiving_init_kind(carrier: &ReceivingInitCarrier) -> ReceivingInitKind {
    if carrier.message_number != 0 {
        return ReceivingInitKind::MidRatchet;
    }
    if carrier.is_session_reset_init {
        return ReceivingInitKind::Handshake;
    }
    if carrier.one_time_prekey_id != 0 {
        return ReceivingInitKind::Handshake;
    }
    if carrier.kem_ciphertext_bytes > 0 {
        return ReceivingInitKind::Handshake;
    }
    if carrier.pq_message_epoch > 0 {
        return ReceivingInitKind::MidSessionLeftover;
    }
    ReceivingInitKind::Handshake
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carrier(message_number: u32) -> ReceivingInitCarrier {
        ReceivingInitCarrier {
            message_number,
            one_time_prekey_id: 0,
            kem_ciphertext_bytes: 0,
            pq_message_epoch: 0,
            is_session_reset_init: false,
        }
    }

    // ── Eligibility ───────────────────────────────────────────────────────────

    #[test]
    fn a_mid_ratchet_message_never_opens_a_session() {
        assert_eq!(
            receiving_init_kind(&carrier(3)),
            ReceivingInitKind::MidRatchet
        );
    }

    #[test]
    fn a_bare_first_message_is_a_handshake() {
        assert_eq!(
            receiving_init_kind(&carrier(0)),
            ReceivingInitKind::Handshake
        );
    }

    #[test]
    fn an_otpk_id_or_a_kem_ciphertext_proves_a_handshake() {
        let mut with_otpk = carrier(0);
        with_otpk.one_time_prekey_id = 1_000_461;
        assert_eq!(
            receiving_init_kind(&with_otpk),
            ReceivingInitKind::Handshake
        );

        let mut with_kem = carrier(0);
        with_kem.kem_ciphertext_bytes = 1088;
        assert_eq!(receiving_init_kind(&with_kem), ReceivingInitKind::Handshake);
    }

    /// Shaped like an opener and is not one. Without this line a re-key would be fed to X3DH,
    /// which fails and takes the queue behind it.
    #[test]
    fn a_pq_epoch_on_a_first_message_is_a_leftover_not_an_opener() {
        let mut leftover = carrier(0);
        leftover.pq_message_epoch = 4;
        assert_eq!(
            receiving_init_kind(&leftover),
            ReceivingInitKind::MidSessionLeftover
        );
    }

    /// A session reset init opens a session whatever else it looks like — including with a PQ epoch
    /// set, which would otherwise class it as a leftover. Asserted with the epoch present, because
    /// with it absent the test passes against a rule that never checks the flag at all.
    #[test]
    fn a_session_reset_init_opens_even_with_a_pq_epoch() {
        let mut sri = carrier(0);
        sri.pq_message_epoch = 4;
        sri.is_session_reset_init = true;
        assert_eq!(receiving_init_kind(&sri), ReceivingInitKind::Handshake);
    }

    // ── The plan ──────────────────────────────────────────────────────────────
}
