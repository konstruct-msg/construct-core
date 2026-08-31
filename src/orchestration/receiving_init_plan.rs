//! Which queued message opens a receiving session, against which of the sender's devices.
//!
//! # Why this is here and not in a client
//!
//! Choosing the session to open on receive is a plan, and a plan is protocol. The iOS client made
//! this choice in two Swift functions and got the *shape* of the search wrong, not the arithmetic:
//! it picked **one** carrier — `queued.first { kind == handshake }` — and then varied only the
//! device bundle around it.
//!
//! That is a one-dimensional walk through a two-dimensional space. The pending queue is keyed by
//! account, so with a multi-device peer it holds handshakes from several devices *and* several
//! reset generations at once. Measured 2026-08-30, one account, one window: seven distinct
//! `message_number == 0` carriers with different ephemerals, some 3-DH (`one_time_prekey_id == 0`)
//! and some 4-DH, feeding two concurrent ratchet chains. Holding the carrier fixed and rotating the
//! bundle asks "which device sent this handshake" when the open question was "which of these seven
//! handshakes is the live one for the device I am testing". Every attempt failed with an AEAD
//! error on a bundle that was entirely valid.
//!
//! The client keeps what this crate cannot have: it fetches the bundles and holds the queue. What
//! it hands over is both **sets**; what it gets back is the order to try them in.
//!
//! See `construct-docs/decisions/a-peer-is-a-set-of-devices.md`.

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

/// One attempt: open carrier `carrier_index` against bundle `bundle_index`. Indices into the
/// caller's own arrays, so nothing here needs to carry or copy the payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivingInitAttempt {
    pub carrier_index: u32,
    pub bundle_index: u32,
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

/// Every (carrier, bundle) pair worth attempting, in the order to attempt them.
///
/// **Both dimensions vary.** That is the whole point: a client that fixes one of them can only find
/// the session if it happened to fix the right one, and a wrong guess is indistinguishable from a
/// broken bundle — the symptom is an AEAD failure against valid keys.
///
/// Carrier-major, caller order preserved within each dimension. Which dimension varies faster is a
/// wash for the expected number of attempts (the likely device is already first in the caller's
/// bundle order, and the carriers are roughly uniform), so the order is fixed for reproducibility
/// rather than for speed: a plan whose order changes between runs makes a failure reproduce on one
/// launch and not the next.
///
/// **Deliberately unbounded.** The plan is `eligible_carriers × bundle_count`, and a queue that has
/// been flooded can make that large. Capping it would silently drop a carrier that might be the
/// right one — the exact failure mode this whole line of work exists to remove, and the caller
/// could not tell a cap from an exhausted search. If the cost becomes real the answer is to stop
/// searching, by naming the sending device on the wire (§D), not to search less and hope.
///
/// A failed responder init opens no session and advances no ratchet, which is what makes attempting
/// safe; if that ever stops being true, this function's contract goes with it.
pub fn plan_receiving_init(
    carriers: &[ReceivingInitCarrier],
    bundle_count: u32,
) -> Vec<ReceivingInitAttempt> {
    if bundle_count == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (carrier_index, carrier) in carriers.iter().enumerate() {
        if receiving_init_kind(carrier) != ReceivingInitKind::Handshake {
            continue;
        }
        for bundle_index in 0..bundle_count {
            out.push(ReceivingInitAttempt {
                carrier_index: carrier_index as u32,
                bundle_index,
            });
        }
    }
    out
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

    fn pairs(plan: &[ReceivingInitAttempt]) -> Vec<(u32, u32)> {
        plan.iter()
            .map(|a| (a.carrier_index, a.bundle_index))
            .collect()
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

    /// **The defect, stated as a test.** Two eligible carriers, two devices: all four pairs are
    /// tried. The implementation this replaces produced only the two pairs containing carrier 0,
    /// and when the live handshake was carrier 1 it failed against both valid bundles.
    #[test]
    fn both_dimensions_vary() {
        let plan = plan_receiving_init(&[carrier(0), carrier(0)], 2);
        assert_eq!(pairs(&plan), vec![(0, 0), (0, 1), (1, 0), (1, 1)]);
    }

    /// Ineligible carriers are skipped, and the indices that survive still point into the caller's
    /// original array — an implementation that compacted the list would return indices that address
    /// the wrong messages.
    #[test]
    fn skipped_carriers_do_not_shift_the_indices_of_the_others() {
        let plan = plan_receiving_init(&[carrier(3), carrier(0)], 1);
        assert_eq!(pairs(&plan), vec![(1, 0)]);
    }

    /// The single-device case is the overwhelmingly common one and must stay exactly one attempt
    /// per eligible carrier — this change must not cost a single-device peer anything.
    #[test]
    fn one_device_is_one_attempt_per_eligible_carrier() {
        let plan = plan_receiving_init(&[carrier(0), carrier(5), carrier(0)], 1);
        assert_eq!(pairs(&plan), vec![(0, 0), (2, 0)]);
    }

    /// No eligible carrier is an empty plan, not an attempt against a leftover. Initialising from
    /// one fails and clears the queue behind it, so silence here is the correct answer.
    #[test]
    fn no_eligible_carrier_is_an_empty_plan() {
        assert!(plan_receiving_init(&[carrier(3), carrier(9)], 3).is_empty());
    }

    /// No bundles, no plan. An empty bundle list means the fetch told us nothing, which is not the
    /// same as the account having no devices — attempting against a device we cannot name is not a
    /// fallback this function offers.
    #[test]
    fn no_bundles_is_an_empty_plan() {
        assert!(plan_receiving_init(&[carrier(0)], 0).is_empty());
    }

    /// The order is fixed. Asserted as a full sequence rather than a set, because the reason the
    /// order exists at all is that a plan which reshuffles makes a failure reproduce on one launch
    /// and not the next.
    #[test]
    fn the_order_is_carrier_major_and_stable() {
        let plan = plan_receiving_init(&[carrier(0), carrier(0)], 3);
        assert_eq!(
            pairs(&plan),
            vec![(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]
        );
    }
}
