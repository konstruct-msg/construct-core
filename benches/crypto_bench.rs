//! Performance benchmarks for Construct Core crypto primitives.
//!
//! Run with:
//!   cargo bench
//!   cargo bench -- encrypt   # run only encrypt benchmarks
//!
//! Results are printed to stdout and saved as HTML reports in target/criterion/.

use construct_core::crypto::CryptoProvider;
use construct_core::crypto::SuiteID;
use construct_core::crypto::handshake::KeyAgreement;
use construct_core::crypto::handshake::x3dh::{X3DHProtocol, X3DHPublicKeyBundle};
use construct_core::crypto::keys::build_prologue;
use construct_core::crypto::messaging::SecureMessaging;
use construct_core::crypto::messaging::double_ratchet::DoubleRatchetSession;
use construct_core::crypto::suites::classic::ClassicSuiteProvider;
use construct_core::wire_payload;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

type Provider = ClassicSuiteProvider;

// ── Shared setup ──────────────────────────────────────────────────────────────

/// Perform a full X3DH handshake and return two initialised DR sessions.
fn setup_sessions() -> (
    DoubleRatchetSession<Provider>,
    DoubleRatchetSession<Provider>,
) {
    let (alice_identity_priv, alice_identity_pub) = Provider::generate_kem_keys().unwrap();
    let (bob_identity_priv, bob_identity_pub) = Provider::generate_kem_keys().unwrap();
    let (bob_signed_prekey_priv, bob_signed_prekey_pub) = Provider::generate_kem_keys().unwrap();
    let (bob_signing_key, bob_verifying_key) = Provider::generate_signature_keys().unwrap();

    let bob_signature = {
        let prologue = build_prologue(SuiteID::CLASSIC);
        let mut msg = prologue;
        msg.extend_from_slice(bob_signed_prekey_pub.as_ref());
        Provider::sign(&bob_signing_key, &msg).unwrap()
    };

    let bob_bundle = X3DHPublicKeyBundle {
        identity_public: bob_identity_pub.clone(),
        signed_prekey_public: bob_signed_prekey_pub.clone(),
        signature: bob_signature,
        verifying_key: bob_verifying_key,
        suite_id: SuiteID::CLASSIC,
        one_time_prekey_public: None,
        one_time_prekey_id: None,
        spk_uploaded_at: 0,
        spk_rotation_epoch: 0,
        kyber_spk_uploaded_at: 0,
        kyber_spk_rotation_epoch: 0,
    };

    let (root_key_alice, initiator_state) =
        X3DHProtocol::<Provider>::perform_as_initiator(&alice_identity_priv, &bob_bundle).unwrap();

    let mut alice_session = DoubleRatchetSession::<Provider>::new_initiator_session(
        &root_key_alice,
        initiator_state,
        &bob_identity_pub,
        "bob".to_string(),
        "alice".to_string(),
    )
    .unwrap();

    let init_msg = alice_session.encrypt(b"__init__").unwrap();

    let alice_ephemeral_pub = Provider::kem_public_key_from_bytes(init_msg.dh_public_key.to_vec());
    let root_key_bob = X3DHProtocol::<Provider>::perform_as_responder(
        &bob_identity_priv,
        &bob_signed_prekey_priv,
        &alice_identity_pub,
        &alice_ephemeral_pub,
        None,
    )
    .unwrap();

    let (bob_session, _) = DoubleRatchetSession::<Provider>::new_responder_session(
        &root_key_bob,
        &bob_identity_priv,
        &init_msg,
        "alice".to_string(),
        "bob".to_string(),
    )
    .unwrap();

    (alice_session, bob_session)
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

/// encrypt: measures one `encrypt()` call on an established session.
fn bench_encrypt(c: &mut Criterion) {
    let plaintexts: &[(&str, &[u8])] = &[
        ("50B", &[0x41u8; 50]),
        ("512B", &[0x41u8; 512]),
        ("4KB", &[0x41u8; 4096]),
    ];

    let mut group = c.benchmark_group("encrypt");
    for (label, plaintext) in plaintexts {
        group.bench_with_input(BenchmarkId::from_parameter(label), plaintext, |b, pt| {
            // Set up a fresh session for each benchmark *group*, then iterate.
            // We re-create once per benchmark group because encrypt mutates state.
            let (mut alice, _) = setup_sessions();
            b.iter(|| alice.encrypt(pt).expect("encrypt failed"));
        });
    }
    group.finish();
}

/// decrypt: measures one `decrypt()` call on an established session.
fn bench_decrypt(c: &mut Criterion) {
    let plaintexts: &[(&str, &[u8])] = &[
        ("50B", &[0x41u8; 50]),
        ("512B", &[0x41u8; 512]),
        ("4KB", &[0x41u8; 4096]),
    ];

    let mut group = c.benchmark_group("decrypt");
    for (label, plaintext) in plaintexts {
        group.bench_with_input(BenchmarkId::from_parameter(label), plaintext, |b, pt| {
            // Pre-encrypt a batch of messages so Bob can decrypt them in the loop.
            // Each iteration pops one pre-computed ciphertext from the queue.
            let (mut alice, mut bob) = setup_sessions();
            const BATCH: usize = 1000;
            let mut ciphertexts: std::collections::VecDeque<_> = (0..BATCH)
                .map(|_| alice.encrypt(pt).expect("pre-encrypt failed"))
                .collect();
            b.iter(|| {
                if ciphertexts.is_empty() {
                    // Refill when exhausted (rare in short bench runs).
                    ciphertexts.extend((0..BATCH).map(|_| alice.encrypt(pt).unwrap()));
                }
                let msg = ciphertexts.pop_front().unwrap();
                bob.decrypt(&msg).expect("decrypt failed")
            });
        });
    }
    group.finish();
}

/// roundtrip: end-to-end encrypt + decrypt latency.
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");
    group.bench_function("128B", |b| {
        let (mut alice, mut bob) = setup_sessions();
        let pt = vec![0x42u8; 128];
        b.iter(|| {
            let ct = alice.encrypt(&pt).expect("encrypt");
            bob.decrypt(&ct).expect("decrypt")
        });
    });
    group.finish();
}

/// wire_payload: pack + unpack (binary framing, no crypto).
fn bench_wire_payload(c: &mut Criterion) {
    let sealed_box = vec![0xABu8; 60]; // 12-byte nonce + 32-byte ct + 16-byte tag
    let dh_pub_key = vec![0x01u8; 32];

    let mut group = c.benchmark_group("wire_payload");

    group.bench_function("pack", |b| {
        b.iter(|| {
            wire_payload::pack(&dh_pub_key, 42, 0, 0, 0, 1, None, &sealed_box).expect("pack failed")
        });
    });

    let packed = wire_payload::pack(&dh_pub_key, 42, 0, 0, 0, 1, None, &sealed_box).unwrap();
    group.bench_function("unpack", |b| {
        b.iter(|| wire_payload::unpack(&packed).expect("unpack failed"));
    });

    group.finish();
}

/// session_serialize: DR session to CFE v1 and back.
fn bench_session_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_serialize");

    group.bench_function("to_cfe_v1", |b| {
        let (alice, _) = setup_sessions();
        b.iter(|| {
            alice
                .to_serializable()
                .to_cfe_v1()
                .expect("to_cfe_v1 failed")
        });
    });

    group.bench_function("from_cfe_v1", |b| {
        let (alice, _) = setup_sessions();
        let cfe = alice
            .to_serializable()
            .to_cfe_v1()
            .expect("to_cfe_v1 failed");
        b.iter(|| {
            use construct_core::crypto::messaging::SerializableSession;
            let snap = SerializableSession::from_cfe_v1(cfe.clone()).expect("from_cfe_v1 failed");
            DoubleRatchetSession::<Provider>::from_serializable(snap)
                .expect("from_serializable failed")
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_roundtrip,
    bench_wire_payload,
    bench_session_serialize,
);
criterion_main!(benches);
