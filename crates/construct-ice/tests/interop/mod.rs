//! Interoperability tests against Go reference obfs4 implementation.
//!
//! The actual Go cross-reference vectors are in the unit tests:
//! - `src/crypto/elligator2.rs` — 10 Elligator2 vectors (representative, pubkey, DH)
//! - `src/crypto/ntor.rs` — ntor KEY_SEED + AUTH vectors
//! - `src/crypto/kdf.rs` — KDF session key vectors
//!
//! This file contains integration-level Go interop tests that require
//! a running Go obfs4 server. See README.md for setup.
//!
//! Run with: `cargo test --test interop -- --ignored`

/// Test that our client can complete a handshake with the Go reference server.
#[tokio::test]
#[ignore = "requires Go reference server running on localhost:54321"]
async fn test_handshake_with_go_server() {
    // This test requires running a Go obfs4 server externally.
    // The Go cross-reference vectors for Elligator2, ntor, and KDF
    // are tested as unit tests in the respective modules.
    todo!("implement Go server subprocess helper")
}
