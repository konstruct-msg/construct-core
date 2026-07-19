//! Kani proofs for wire payload pack/unpack invariants
//!
//! Verifies:
//! - W1: pack/unpack round-trip preserves all fields
//! - W2: unpack rejects payloads shorter than HEADER_SIZE
//! - W3: pack rejects DH keys that aren't 32 bytes
//! - W4: sealed_box is always at the end of the packed payload
//! - W5: Suite-3 PQ section round-trip (no field)

use crate::wire_payload::{pack, unpack, DecodedWirePayload, HEADER_SIZE};

/// W1: Round-trip invariant — unpack(pack(fields)) == fields
/// Bounded sealed_box and kem_ciphertext for tractable verification.
#[kani::proof]
fn proof_pack_unpack_roundtrip_no_pqc() {
    let msg_num: u32 = kani::any();
    let otpk_id: u32 = kani::any();
    let kyber_otpk_id: u32 = kani::any();
    let prev_chain_len: u32 = kani::any();
    let suite_id: u16 = kani::any();
    kani::assume(suite_id == 1 || suite_id == 2); // Non-suite-3 for this test

    let dh_key: [u8; 32] = kani::any();

    let sealed_len: usize = kani::any();
    kani::assume(sealed_len >= 60 && sealed_len <= 128);
    let sealed_box: Vec<u8> = (0..sealed_len).map(|_| kani::any()).collect();

    let packed = pack(
        &dh_key,
        msg_num,
        otpk_id,
        kyber_otpk_id,
        prev_chain_len,
        suite_id,
        None,
        &sealed_box,
        0,
        None,
    )
    .unwrap();

    let decoded = unpack(&packed).unwrap();

    assert_eq!(decoded.message_number, msg_num);
    assert_eq!(decoded.dh_public_key, dh_key.to_vec());
    assert_eq!(decoded.one_time_prekey_id, otpk_id);
    assert_eq!(decoded.kyber_otpk_id, kyber_otpk_id);
    assert_eq!(decoded.previous_chain_length, prev_chain_len);
    assert_eq!(decoded.suite_id, suite_id);
    assert!(decoded.kem_ciphertext.is_none());
    assert_eq!(decoded.pq_message_epoch, 0);
    assert!(decoded.pq_ratchet_field.is_none());
    assert_eq!(decoded.sealed_box, sealed_box);
}

/// W1b: Round-trip with PQC (KEM ciphertext present)
#[kani::proof]
fn proof_pack_unpack_roundtrip_with_pqc() {
    let msg_num: u32 = kani::any();
    let otpk_id: u32 = kani::any();

    let dh_key: [u8; 32] = kani::any();

    // Bounded KEM ciphertext (smaller than real ML-KEM-768 for tractability)
    let kem_len: usize = kani::any();
    kani::assume(kem_len >= 16 && kem_len <= 128);
    let kem_ct: Vec<u8> = (0..kem_len).map(|_| kani::any()).collect();

    let sealed_len: usize = kani::any();
    kani::assume(sealed_len >= 60 && sealed_len <= 128);
    let sealed_box: Vec<u8> = (0..sealed_len).map(|_| kani::any()).collect();

    let packed = pack(
        &dh_key,
        msg_num,
        otpk_id,
        0,
        0,
        1,
        Some(&kem_ct),
        &sealed_box,
        0,
        None,
    )
    .unwrap();

    let decoded = unpack(&packed).unwrap();

    assert_eq!(decoded.message_number, msg_num);
    assert_eq!(decoded.dh_public_key, dh_key.to_vec());
    assert_eq!(decoded.one_time_prekey_id, otpk_id);
    assert_eq!(
        decoded.kem_ciphertext.as_deref(),
        Some(kem_ct.as_slice()),
        "KEM ciphertext must round-trip"
    );
    assert_eq!(decoded.sealed_box, sealed_box);
}

/// W2: Payloads shorter than HEADER_SIZE are always rejected
#[kani::proof]
fn proof_unpack_rejects_too_short() {
    let len: usize = kani::any();
    kani::assume(len < HEADER_SIZE);

    let data: Vec<u8> = (0..len).map(|_| kani::any()).collect();

    let result = unpack(&data);
    assert!(
        result.is_err(),
        "Payload shorter than HEADER_SIZE ({HEADER_SIZE}) must be rejected, got len={len}"
    );
}

/// W3: pack rejects DH keys that aren't exactly 32 bytes
#[kani::proof]
fn proof_pack_rejects_bad_dh_key() {
    let bad_len: usize = kani::any();
    kani::assume(bad_len != 32 && bad_len < 64);

    let bad_key: Vec<u8> = (0..bad_len).map(|_| kani::any()).collect();
    let sealed_box: Vec<u8> = vec![0xAA; 60];

    let result = pack(
        &bad_key,
        0,
        0,
        0,
        0,
        1,
        None,
        &sealed_box,
        0,
        None,
    );

    assert!(
        result.is_err(),
        "DH key of length {bad_len} must be rejected"
    );
}

/// W4: Packed payload length equals HEADER_SIZE + kem_len + sealed_box_len
/// (plus PQ section for suite 3)
#[kani::proof]
fn proof_packed_length_correct() {
    let dh_key: [u8; 32] = kani::any();

    let sealed_len: usize = kani::any();
    kani::assume(sealed_len >= 60 && sealed_len <= 128);
    let sealed_box: Vec<u8> = (0..sealed_len).map(|_| kani::any()).collect();

    let packed = pack(
        &dh_key,
        0,
        0,
        0,
        0,
        1,
        None,
        &sealed_box,
        0,
        None,
    )
    .unwrap();

    assert_eq!(
        packed.len(),
        HEADER_SIZE + sealed_len,
        "Packed length must be HEADER_SIZE + sealed_box_len"
    );
}

/// W5: Suite-3 with no PQ field round-trips correctly
#[kani::proof]
fn proof_suite3_no_field_roundtrip() {
    let dh_key: [u8; 32] = kani::any();
    let pq_epoch: u32 = kani::any();

    let sealed_len: usize = kani::any();
    kani::assume(sealed_len >= 60 && sealed_len <= 128);
    let sealed_box: Vec<u8> = (0..sealed_len).map(|_| kani::any()).collect();

    let packed = pack(
        &dh_key,
        42,
        0,
        0,
        5,
        3, // Suite 3
        None,
        &sealed_box,
        pq_epoch,
        None,
    )
    .unwrap();

    // Suite-3 always writes 5-byte PQ section (epoch + type 0)
    assert_eq!(packed.len(), HEADER_SIZE + 5 + sealed_len);

    let decoded = unpack(&packed).unwrap();

    assert_eq!(decoded.suite_id, 3);
    assert_eq!(decoded.message_number, 42);
    assert_eq!(decoded.previous_chain_length, 5);
    assert_eq!(decoded.pq_message_epoch, pq_epoch);
    assert!(decoded.pq_ratchet_field.is_none());
    assert_eq!(decoded.sealed_box, sealed_box);
}

/// W6: Exactly HEADER_SIZE bytes is rejected (need at least header + 1 byte sealed_box)
#[kani::proof]
fn proof_exactly_header_size_rejected() {
    let data: Vec<u8> = (0..HEADER_SIZE).map(|_| kani::any()).collect();
    let result = unpack(&data);
    assert!(
        result.is_err(),
        "Payload of exactly HEADER_SIZE bytes must be rejected (no sealed_box)"
    );
}
