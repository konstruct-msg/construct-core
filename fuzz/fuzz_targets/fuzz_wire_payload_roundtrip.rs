//! Fuzz target: `wire_payload` round-trip — pack → unpack must be lossless.
//!
//! Uses `arbitrary` to generate structured input, packs it into binary,
//! then unpacks and verifies every field matches. Finds encode/decode
//! asymmetries, off-by-one errors in length handling, and KEM edge cases.
//!
//! `pq_message_epoch` and `pq_ratchet_field` are covered here deliberately.
//! They were added to `pack` after this target was written, and because the
//! fuzz crate is not in git and not built by anything, the target simply stopped
//! compiling and nobody saw it — the same two fields AGENTS.md records as having
//! been silently dropped at the unseal boundary. A target that does not build is
//! indistinguishable from a target that finds nothing.

#![no_main]

use arbitrary::Arbitrary;
use construct_core::crypto::messaging::double_ratchet::PqRatchetWireField;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum PqField {
    None,
    PublicKey { epoch: u32, key: Vec<u8> },
    Ciphertext { epoch: u32, ek_hash: [u8; 8], ct: Vec<u8> },
}

#[derive(Debug, Arbitrary)]
struct WireInput {
    message_number: u32,
    one_time_prekey_id: u32,
    kyber_otpk_id: u32,
    previous_chain_length: u32,
    suite_id: u16,
    /// Whether to include a KEM ciphertext.
    has_kem: bool,
    /// Raw bytes used as KEM ciphertext (length capped to u16::MAX).
    kem_bytes: Vec<u8>,
    /// Raw bytes used as sealed box (must be non-empty for valid payload).
    sealed_box: Vec<u8>,
    /// Suite-3 PQ epoch tag. Written for every suite-3 message.
    pq_message_epoch: u32,
    /// Suite-3 sparse PQ field.
    pq_field: PqField,
}

fuzz_target!(|input: WireInput| {
    // Need non-empty sealed_box for a valid round-trip.
    if input.sealed_box.is_empty() {
        return;
    }

    // Cap KEM length to u16::MAX.
    let kem_bytes: Vec<u8> = input
        .kem_bytes
        .into_iter()
        .take(u16::MAX as usize)
        .collect();

    let kem_ref = if input.has_kem && !kem_bytes.is_empty() {
        Some(kem_bytes.as_slice())
    } else {
        None
    };

    // The PQ section is only written for suite 3; for every other suite `pack`
    // drops both values on the floor, so the expectation has to follow the same
    // rule or the assertions below would fail on a correct implementation.
    let pq_field = match input.pq_field {
        PqField::None => None,
        PqField::PublicKey { epoch, key } => Some(PqRatchetWireField::PublicKey {
            epoch,
            key: key.into_iter().take(u16::MAX as usize).collect(),
        }),
        PqField::Ciphertext { epoch, ek_hash, ct } => Some(PqRatchetWireField::Ciphertext {
            epoch,
            ek_hash,
            ct: ct.into_iter().take(u16::MAX as usize).collect(),
        }),
    };
    // `pack` owns the PQXDH v2 flag: it strips it from the caller's suite and sets it exactly
    // when a KEM ciphertext is present, so the ratchet suite is the input without the bit.
    let ratchet_suite = input.suite_id & !construct_core::wire_payload::PQXDH_V2_FLAG;
    let is_suite3 = ratchet_suite == 3;
    let expected_epoch = if is_suite3 { input.pq_message_epoch } else { 0 };
    let expected_pq_field = if is_suite3 { pq_field.clone() } else { None };

    // Use a fixed 32-byte DH key.
    let dh_key = [0xAA_u8; 32];

    let packed = match construct_core::wire_payload::pack(
        &dh_key,
        input.message_number,
        input.one_time_prekey_id,
        input.kyber_otpk_id,
        input.previous_chain_length,
        input.suite_id,
        kem_ref,
        &input.sealed_box,
        input.pq_message_epoch,
        pq_field,
    ) {
        Ok(p) => p,
        Err(_) => return,
    };

    let decoded = construct_core::wire_payload::unpack(&packed).expect("round-trip must succeed");

    assert_eq!(decoded.message_number, input.message_number);
    assert_eq!(decoded.dh_public_key, dh_key.to_vec());
    assert_eq!(decoded.one_time_prekey_id, input.one_time_prekey_id);
    assert_eq!(decoded.kyber_otpk_id, input.kyber_otpk_id);
    assert_eq!(decoded.previous_chain_length, input.previous_chain_length);
    assert_eq!(decoded.suite_id, ratchet_suite);
    assert_eq!(decoded.pqxdh_v2, kem_ref.is_some());
    assert_eq!(decoded.sealed_box, input.sealed_box);
    assert_eq!(decoded.pq_message_epoch, expected_epoch);
    assert_eq!(decoded.pq_ratchet_field, expected_pq_field);

    match kem_ref {
        Some(kem) => assert_eq!(decoded.kem_ciphertext.as_deref(), Some(kem)),
        None => assert!(decoded.kem_ciphertext.is_none()),
    }
});
