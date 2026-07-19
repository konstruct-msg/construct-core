//! Kani proofs for SuiteID invariants
//!
//! Verifies:
//! - S1: SuiteID::new accepts exactly {1, 2, 3}
//! - S2: is_supported agrees with new() success
//! - S3: name returns correct string for each valid suite
//! - S4: from_u16_unchecked round-trips through as_u16
//! - S5: TryFrom/Serde round-trip

use crate::crypto::SuiteID;

/// S1: SuiteID::new accepts exactly 1, 2, 3 and rejects all others
#[kani::proof]
fn proof_suite_id_new_exactly_123() {
    let id: u16 = kani::any();

    let result = SuiteID::new(id);

    if id == 1 {
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SuiteID::CLASSIC);
    } else if id == 2 {
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SuiteID::PQ_HYBRID);
    } else if id == 3 {
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SuiteID::PQ_RATCHET);
    } else {
        assert!(result.is_err());
    }
}

/// S2: is_supported(id) == true iff SuiteID::new(id) is Ok
#[kani::proof]
fn proof_is_supported_agrees_with_new() {
    let id: u16 = kani::any();

    let supported = SuiteID::is_supported(id);
    let new_ok = SuiteID::new(id).is_ok();

    assert_eq!(
        supported, new_ok,
        "is_supported({id}) must agree with new({id}).is_ok()"
    );
}

/// S3: name() returns the correct string for each valid suite
#[kani::proof]
fn proof_suite_id_name_correct() {
    for (id, expected_name) in [(1, "CLASSIC"), (2, "PQ_HYBRID"), (3, "PQ_RATCHET")] {
        let suite = SuiteID::new(id).unwrap();
        assert_eq!(
            suite.name(),
            expected_name,
            "SuiteID({id}).name() must be '{expected_name}'"
        );
    }
}

/// S4: from_u16_unchecked round-trips through as_u16
#[kani::proof]
fn proof_unchecked_roundtrip() {
    let id: u16 = kani::any();
    kani::assume(id >= 1 && id <= 3);

    let suite = SuiteID::from_u16_unchecked(id);
    assert_eq!(
        suite.as_u16(),
        id,
        "from_u16_unchecked({id}).as_u16() must equal {id}"
    );
}

/// S5: Each suite's predicate methods are mutually exclusive
#[kani::proof]
fn proof_suite_predicates_mutually_exclusive() {
    for id in [1u16, 2, 3] {
        let suite = SuiteID::new(id).unwrap();

        let is_classic = suite.is_classic();
        let is_hybrid = suite.is_pq_hybrid();
        let is_ratchet = suite.is_pq_ratchet();

        // Exactly one predicate must be true
        let true_count = [is_classic, is_hybrid, is_ratchet]
            .iter()
            .filter(|&&b| b)
            .count();
        assert_eq!(
            true_count, 1,
            "Exactly one predicate must be true for suite {id}"
        );

        // Verify correct mapping
        match id {
            1 => assert!(is_classic && !is_hybrid && !is_ratchet),
            2 => assert!(!is_classic && is_hybrid && !is_ratchet),
            3 => assert!(!is_classic && !is_hybrid && is_ratchet),
            _ => unreachable!(),
        }
    }
}

/// S6: TryFrom<u16> is equivalent to SuiteID::new
#[kani::proof]
fn proof_try_from_equivalent_to_new() {
    let id: u16 = kani::any();

    let try_result = SuiteID::try_from(id);
    let new_result = SuiteID::new(id);

    assert_eq!(
        try_result.is_ok(),
        new_result.is_ok(),
        "TryFrom and new must agree on validity"
    );

    if let (Ok(try_suite), Ok(new_suite)) = (try_result, new_result) {
        assert_eq!(try_suite, new_suite, "TryFrom and new must produce same suite");
    }
}

/// S7: From<SuiteID> for u16 round-trips
#[kani::proof]
fn proof_from_suite_id_for_u16() {
    for id in [1u16, 2, 3] {
        let suite = SuiteID::new(id).unwrap();
        let back: u16 = suite.into();
        assert_eq!(back, id, "From<SuiteID> for u16 must round-trip");
    }
}
