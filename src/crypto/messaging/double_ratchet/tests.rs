use super::{DoubleRatchetSession, SuiteID};
use crate::crypto::handshake::{KeyAgreement, x3dh::X3DHProtocol};
use crate::crypto::keys::build_prologue;
use crate::crypto::messaging::SecureMessaging;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;

// ── Shared test helper ────────────────────────────────────────────────────
//
// Returns the classic key bundle for "Bob" and the matching private keys.
// Used by every AD-identity test to avoid repeating boilerplate setup.
#[allow(clippy::type_complexity)]
fn make_bob_bundle() -> (
    crate::crypto::handshake::x3dh::X3DHPublicKeyBundle,
    <ClassicSuiteProvider as CryptoProvider>::KemPrivateKey, // bob identity priv
    <ClassicSuiteProvider as CryptoProvider>::KemPrivateKey, // bob SPK priv
    <ClassicSuiteProvider as CryptoProvider>::KemPublicKey,  // bob identity pub
) {
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

    let (bob_priv, bob_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_spk_priv, bob_spk_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_sk, bob_vk) = ClassicSuiteProvider::generate_signature_keys().unwrap();
    let bob_sig = {
        let mut msg = build_prologue(SuiteID::CLASSIC);
        msg.extend_from_slice(bob_spk_pub.as_ref());
        ClassicSuiteProvider::sign(&bob_sk, &msg).unwrap()
    };
    let bundle = X3DHPublicKeyBundle {
        identity_public: bob_pub.clone(),
        signed_prekey_public: bob_spk_pub,
        signature: bob_sig,
        verifying_key: bob_vk,
        suite_id: SuiteID::CLASSIC,
        one_time_prekey_public: None,
        one_time_prekey_id: None,
        spk_uploaded_at: 0,
        spk_rotation_epoch: 0,
        kyber_spk_uploaded_at: 0,
        kyber_spk_rotation_epoch: 0,
    };
    (bundle, bob_priv, bob_spk_priv, bob_pub)
}

#[test]
fn test_alice_bob_full_exchange() {
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

    // Setup: Alice and Bob both have identity keys
    let (alice_identity_priv, alice_identity_pub) =
        ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_identity_priv, bob_identity_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();

    // Bob generates his registration keys
    let (bob_signed_prekey_priv, bob_signed_prekey_pub) =
        ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_signing_key, bob_verifying_key) =
        ClassicSuiteProvider::generate_signature_keys().unwrap();
    let bob_signature = {
        let prologue = build_prologue(SuiteID::CLASSIC);
        let mut msg = prologue;
        msg.extend_from_slice(bob_signed_prekey_pub.as_ref());
        ClassicSuiteProvider::sign(&bob_signing_key, &msg).unwrap()
    };

    // Bob's public bundle (what Alice gets from server)
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

    // Alice performs X3DH as initiator
    let (root_key_alice, initiator_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(
            &alice_identity_priv,
            &bob_bundle,
        )
        .unwrap();

    // Alice creates session
    let mut alice_session = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &root_key_alice,
        initiator_state,
        &bob_identity_pub,
        "bob".to_string(),
        "alice".to_string(),
    )
    .unwrap();

    // Alice sends first message
    let plaintext1 = b"Hello Bob!";
    let encrypted1 = alice_session.encrypt(plaintext1).unwrap();

    // Bob extracts Alice's ephemeral public from first message
    // and performs X3DH as responder
    let alice_ephemeral_pub =
        ClassicSuiteProvider::kem_public_key_from_bytes(encrypted1.dh_public_key.to_vec());

    let root_key_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_identity_priv,
        &bob_signed_prekey_priv,
        &alice_identity_pub,
        &alice_ephemeral_pub,
        None,
    )
    .unwrap();

    // Bob creates session from first message
    // ⚠️ ВАЖНО: new_responder_session теперь возвращает (session, plaintext)
    let (mut bob_session, decrypted1) =
        DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
            &root_key_bob,
            &bob_identity_priv,
            &encrypted1,
            "alice".to_string(),
            "bob".to_string(),
        )
        .unwrap();

    // Verify first message was decrypted correctly
    assert_eq!(decrypted1, plaintext1);

    // Bob replies
    let plaintext2 = b"Hi Alice!";
    let encrypted2 = bob_session.encrypt(plaintext2).unwrap();

    // Alice decrypts Bob's reply
    let decrypted2 = alice_session.decrypt(&encrypted2).unwrap();
    assert_eq!(decrypted2, plaintext2);
}

#[test]
fn test_out_of_order_messages() {
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

    // Setup session (simplified)
    let (alice_identity_priv, alice_identity_pub) =
        ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_identity_priv, bob_identity_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();

    // Bob generates his registration keys
    let (bob_signed_prekey_priv, bob_signed_prekey_pub) =
        ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_signing_key, bob_verifying_key) =
        ClassicSuiteProvider::generate_signature_keys().unwrap();
    let bob_signature = {
        let prologue = build_prologue(SuiteID::CLASSIC);
        let mut msg = prologue;
        msg.extend_from_slice(bob_signed_prekey_pub.as_ref());
        ClassicSuiteProvider::sign(&bob_signing_key, &msg).unwrap()
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

    let (root_key, initiator_state) = X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(
        &alice_identity_priv,
        &bob_bundle,
    )
    .unwrap();

    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &root_key,
        initiator_state,
        &bob_identity_pub,
        "bob".to_string(),
        "alice".to_string(),
    )
    .unwrap();

    // Alice sends 3 messages
    let msg1 = alice.encrypt(b"Message 1").unwrap();
    let msg2 = alice.encrypt(b"Message 2").unwrap();
    let msg3 = alice.encrypt(b"Message 3").unwrap();

    // Bob receives messages out of order: 1, 3, 2
    let alice_ephemeral_pub =
        ClassicSuiteProvider::kem_public_key_from_bytes(msg1.dh_public_key.to_vec());

    let root_key_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_identity_priv,
        &bob_signed_prekey_priv,
        &alice_identity_pub,
        &alice_ephemeral_pub,
        None,
    )
    .unwrap();

    // ⚠️ ВАЖНО: new_responder_session теперь возвращает (session, plaintext первого сообщения)
    let (mut bob, dec1) = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &root_key_bob,
        &bob_identity_priv,
        &msg1,
        "alice".to_string(),
        "bob".to_string(),
    )
    .unwrap();

    // Verify first message was decrypted
    assert_eq!(dec1, b"Message 1");

    // Receive msg3 before msg2 - should work with skipped keys
    let dec3 = bob.decrypt(&msg3).unwrap();
    assert_eq!(dec3, b"Message 3");

    // Now receive msg2 - should use skipped key
    let dec2 = bob.decrypt(&msg2).unwrap();
    assert_eq!(dec2, b"Message 2");
}

/// Verify that apply_pq_contribution produces symmetric root keys on both sides.
///
/// Before the fix, INITIATOR applied PQ to RK1 but RESPONDER applied PQ to RK2,
/// causing irreversible key divergence. After the fix, both sides apply PQ to RK1
/// (the root key after the first DH ratchet step), and RESPONDER re-derives its
/// second ratchet from the PQ-enhanced root key.
#[test]
fn test_pqxdh_symmetric_contribution() {
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

    let (alice_identity_priv, alice_identity_pub) =
        ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_identity_priv, bob_identity_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();

    let (bob_signed_prekey_priv, bob_signed_prekey_pub) =
        ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_signing_key, bob_verifying_key) =
        ClassicSuiteProvider::generate_signature_keys().unwrap();
    let bob_signature = {
        let prologue = build_prologue(SuiteID::CLASSIC);
        let mut msg = prologue;
        msg.extend_from_slice(bob_signed_prekey_pub.as_ref());
        ClassicSuiteProvider::sign(&bob_signing_key, &msg).unwrap()
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

    // Alice: INITIATOR
    let (root_key_alice, initiator_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(
            &alice_identity_priv,
            &bob_bundle,
        )
        .unwrap();

    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &root_key_alice,
        initiator_state,
        &bob_identity_pub,
        "bob".to_string(),
        "alice".to_string(),
    )
    .unwrap();

    // Alice encrypts msg0
    let msg0 = alice.encrypt(b"Hello with PQ!").unwrap();

    // Bob: RESPONDER
    let alice_eph_pub =
        ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let root_key_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_identity_priv,
        &bob_signed_prekey_priv,
        &alice_identity_pub,
        &alice_eph_pub,
        None,
    )
    .unwrap();

    let (mut bob, plaintext0) =
        DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
            &root_key_bob,
            &bob_identity_priv,
            &msg0,
            "alice".to_string(),
            "bob".to_string(),
        )
        .unwrap();
    assert_eq!(plaintext0, b"Hello with PQ!");

    // Simulate a KEM shared secret (same on both sides, as if from ML-KEM encaps/decaps)
    let kem_shared_secret = b"fake-but-identical-kem-shared-secret-32b";

    // Apply PQ contribution on both sides
    alice.apply_pq_contribution(kem_shared_secret).unwrap();
    bob.apply_pq_contribution(kem_shared_secret).unwrap();

    // Bob sends reply AFTER PQ contribution — this is the critical test.
    // Before the fix, Alice could NOT decrypt this because root keys diverged.
    let reply = bob.encrypt(b"Reply after PQ!").unwrap();
    let decrypted_reply = alice.decrypt(&reply).unwrap();
    assert_eq!(decrypted_reply, b"Reply after PQ!");

    // Continue with a multi-turn conversation to verify ratchet stays in sync
    let msg2 = alice.encrypt(b"Message 2 from Alice").unwrap();
    let dec2 = bob.decrypt(&msg2).unwrap();
    assert_eq!(dec2, b"Message 2 from Alice");

    let msg3 = bob.encrypt(b"Message 3 from Bob").unwrap();
    let dec3 = alice.decrypt(&msg3).unwrap();
    assert_eq!(dec3, b"Message 3 from Bob");
}

/// Verify that decrypt() rolls back session state on AEAD failure,
/// allowing subsequent valid messages to still be decrypted.
#[test]
fn test_decrypt_rollback_on_failure() {
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_priv, bob_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();

    let (bob_spk_priv, bob_spk_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_signing, bob_verifying) = ClassicSuiteProvider::generate_signature_keys().unwrap();
    let bob_sig = {
        let prologue = build_prologue(SuiteID::CLASSIC);
        let mut msg = prologue;
        msg.extend_from_slice(bob_spk_pub.as_ref());
        ClassicSuiteProvider::sign(&bob_signing, &msg).unwrap()
    };

    let bob_bundle = X3DHPublicKeyBundle {
        identity_public: bob_pub.clone(),
        signed_prekey_public: bob_spk_pub.clone(),
        signature: bob_sig,
        verifying_key: bob_verifying,
        suite_id: SuiteID::CLASSIC,
        one_time_prekey_public: None,
        one_time_prekey_id: None,
        spk_uploaded_at: 0,
        spk_rotation_epoch: 0,
        kyber_spk_uploaded_at: 0,
        kyber_spk_rotation_epoch: 0,
    };

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bob_bundle)
            .unwrap();

    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        "bob".to_string(),
        "alice".to_string(),
    )
    .unwrap();

    let msg0 = alice.encrypt(b"Init").unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();

    let (mut bob, _) = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        "alice".to_string(),
        "bob".to_string(),
    )
    .unwrap();

    // Bob sends a valid reply
    let reply = bob.encrypt(b"Real reply").unwrap();

    // Craft a corrupted message with Bob's DH key but garbage ciphertext.
    // This triggers a DH ratchet in Alice (new remote DH key) + AEAD failure.
    let mut corrupt = reply.clone();
    corrupt.ciphertext = vec![0xDE; corrupt.ciphertext.len()];

    // Alice tries to decrypt the corrupted message — should fail
    assert!(alice.decrypt(&corrupt).is_err());

    // Alice decrypts the REAL reply — should succeed because state was rolled back
    let dec = alice.decrypt(&reply).unwrap();
    assert_eq!(dec, b"Real reply");
}

#[test]
fn test_max_message_jump_dos_guard() {
    // Verify that a message with a forward jump exceeding max_message_jump is
    // rejected immediately — before any HKDF work is done — preventing CPU DoS.
    use crate::config::Config;
    use crate::crypto::handshake::x3dh::{X3DHProtocol, X3DHPublicKeyBundle};
    use crate::crypto::keys::build_prologue;

    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_priv, bob_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_spk_priv, bob_spk_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_sk, bob_vk) = ClassicSuiteProvider::generate_signature_keys().unwrap();
    let sig = {
        let mut msg = build_prologue(SuiteID::CLASSIC);
        msg.extend_from_slice(bob_spk_pub.as_ref());
        ClassicSuiteProvider::sign(&bob_sk, &msg).unwrap()
    };
    let bundle = X3DHPublicKeyBundle {
        identity_public: bob_pub.clone(),
        signed_prekey_public: bob_spk_pub,
        signature: sig,
        verifying_key: bob_vk,
        suite_id: SuiteID::CLASSIC,
        one_time_prekey_public: None,
        one_time_prekey_id: None,
        spk_uploaded_at: 0,
        spk_rotation_epoch: 0,
        kyber_spk_uploaded_at: 0,
        kyber_spk_rotation_epoch: 0,
    };

    let (rk, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk,
        init_state,
        &bob_pub,
        "bob".to_string(),
        "alice".to_string(),
    )
    .unwrap();

    let msg0 = alice.encrypt(b"Hi").unwrap();
    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();
    let (mut bob, _) = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        "alice".to_string(),
        "bob".to_string(),
    )
    .unwrap();

    // Alice sends one message normally so Bob has a receiving chain set up.
    let legit = alice.encrypt(b"legitimate").unwrap();

    // Craft a message with msg_num strictly beyond receiving_chain_length + max_jump.
    let max_jump = Config::global().max_message_jump;
    let mut malicious = legit.clone();
    // Use max_jump * 2 to ensure we're well beyond the guard threshold
    // regardless of Bob's current receiving_chain_length.
    malicious.message_number = max_jump * 2;

    let err = bob.decrypt(&malicious);
    assert!(err.is_err(), "Expected DoS guard to reject large jump");
    let msg = err.unwrap_err();
    assert!(msg.contains("jump"), "Error should mention jump: {}", msg);

    // Bob's state must still be intact — legitimate message decrypts fine.
    let dec = bob.decrypt(&legit).unwrap();
    assert_eq!(dec, b"legitimate");
}

#[test]
fn test_cleanup_on_deserialize() {
    // After deserializing a session, stale skipped-message keys must be evicted
    // before the first real decrypt call, not only after 100 messages.
    use crate::crypto::handshake::x3dh::{X3DHProtocol, X3DHPublicKeyBundle};
    use crate::crypto::keys::build_prologue;

    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_priv, bob_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_spk_priv, bob_spk_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bob_sk, bob_vk) = ClassicSuiteProvider::generate_signature_keys().unwrap();
    let sig = {
        let mut msg = build_prologue(SuiteID::CLASSIC);
        msg.extend_from_slice(bob_spk_pub.as_ref());
        ClassicSuiteProvider::sign(&bob_sk, &msg).unwrap()
    };
    let bundle = X3DHPublicKeyBundle {
        identity_public: bob_pub.clone(),
        signed_prekey_public: bob_spk_pub,
        signature: sig,
        verifying_key: bob_vk,
        suite_id: SuiteID::CLASSIC,
        one_time_prekey_public: None,
        one_time_prekey_id: None,
        spk_uploaded_at: 0,
        spk_rotation_epoch: 0,
        kyber_spk_uploaded_at: 0,
        kyber_spk_rotation_epoch: 0,
    };

    let (rk, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk,
        init_state,
        &bob_pub,
        "bob".to_string(),
        "alice".to_string(),
    )
    .unwrap();

    let msg0 = alice.encrypt(b"Hi").unwrap();
    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();
    let (mut bob, _) = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        "alice".to_string(),
        "bob".to_string(),
    )
    .unwrap();

    // Alice sends 3 messages; Bob only receives the 3rd → 2 skipped keys stored.
    let _m1 = alice.encrypt(b"skipped 1").unwrap();
    let _m2 = alice.encrypt(b"skipped 2").unwrap();
    let m3 = alice.encrypt(b"received 3").unwrap();
    bob.decrypt(&m3).unwrap();

    let skipped_before = bob.skipped_message_keys.len();
    assert_eq!(
        skipped_before, 2,
        "Expected 2 skipped keys before serialize"
    );

    // Serialize Bob's session and give skipped keys an ancient timestamp.
    let mut snap = bob.to_serializable();
    for entry in &mut snap.skipped_keys {
        entry.timestamp = 0; // epoch → older than any max_age
    }

    // Deserialize — cleanup should run automatically on restore.
    let bob2 = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(snap).unwrap();
    assert_eq!(
        bob2.skipped_message_keys.len(),
        0,
        "Stale skipped keys must be evicted on from_serializable"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// AD-Identity tests
//
// These tests cover the exact bug where CryptoManager.cryptoLocalUserId
// returned a 32-char device-hash instead of the 36-char server UUID.
// Double Ratchet AD is:
//   ENCRYPT: AD_VERSION || local_user_id || contact_id || session_id || dh_pub || msg_num
//   DECRYPT: AD_VERSION || contact_id   || local_user_id || …  (roles swapped — intentional)
// Both fields MUST use the same identity space (server UUIDs) on both sides.
// ══════════════════════════════════════════════════════════════════════════

/// Regression test: full two-party exchange using production-format server UUIDs
/// (36-char with dashes).  This is the fixed behavior and must succeed.
#[test]
fn test_ad_symmetric_with_realistic_uuid_ids() {
    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    // Production-format server UUIDs — same length and format on both sides.
    let alice_uuid = "14f28d31-2dab-44aa-a123-456789abcdef";
    let bob_uuid = "81f02199-8374-48f8-8a5f-549434ccc53f";

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();

    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        bob_uuid.to_string(),   // contact_id
        alice_uuid.to_string(), // local_user_id
    )
    .unwrap();

    let msg0 = alice.encrypt(b"Hello Bob - UUID IDs!").unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();

    let (mut bob, plaintext0) =
        DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
            &rk_bob,
            &bob_priv,
            &msg0,
            alice_uuid.to_string(), // contact_id = Alice's UUID (matches alice.local_user_id)
            bob_uuid.to_string(),   // local_user_id
        )
        .unwrap();

    assert_eq!(
        plaintext0, b"Hello Bob - UUID IDs!",
        "First message must decrypt"
    );

    // Continue the conversation to verify the ratchet stays in sync.
    let msg1 = bob.encrypt(b"Hi Alice!").unwrap();
    assert_eq!(alice.decrypt(&msg1).unwrap(), b"Hi Alice!");

    let msg2 = alice.encrypt(b"Message 2").unwrap();
    assert_eq!(bob.decrypt(&msg2).unwrap(), b"Message 2");

    let msg3 = bob.encrypt(b"Message 3").unwrap();
    assert_eq!(alice.decrypt(&msg3).unwrap(), b"Message 3");
}

/// AD is a strong binding: ANY mismatch between initiator's `local_user_id` and
/// responder's `contact_id` — regardless of format — causes AEAD failure.
/// This test uses strings that don't trigger the debug_assert guards (not 32-char hex)
/// but are still inconsistent: Alice uses "alice_local" while Bob knows her as "alice_uuid".
#[test]
fn test_ad_mismatch_inconsistent_ids_fails() {
    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    // Alice's self-view vs Bob's view of Alice — both non-UUID, non-32-hex,
    // so the debug_assert doesn't fire, but the values don't match.
    let alice_local_id = "alice_local_node_id"; // Alice's view of herself
    let alice_id_as_seen_by_bob = "alice_server_node"; // Bob's contact entry for Alice
    let bob_id = "bob_node_id";

    assert_ne!(
        alice_local_id, alice_id_as_seen_by_bob,
        "Precondition: IDs differ"
    );

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        bob_id.to_string(),
        alice_local_id.to_string(), // local_user_id: Alice's self-view
    )
    .unwrap();

    let msg0 = alice.encrypt(b"mismatch test").unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();

    // Bob uses a different string for Alice — AEAD must fail.
    let result = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        alice_id_as_seen_by_bob.to_string(), // ≠ alice_local_id
        bob_id.to_string(),
    );

    assert!(
        result.is_err(),
        "Any local_user_id / contact_id mismatch must cause AEAD failure"
    );
}

/// Bug-reproduction test: Alice stores `local_user_id` as a 32-char device-hash
/// but Bob stores `contact_id` for Alice as a 36-char server UUID.  The AD bytes
/// differ in length → AEAD authentication MUST fail.
///
/// This test only runs in release mode (`--release`); in debug mode the
/// `debug_assert!` guard in `new_initiator_session` fires before AEAD is reached.
/// The debug-mode path is covered by `test_debug_assert_catches_device_hash_as_local_user_id`.
#[cfg(not(debug_assertions))]
#[test]
fn test_ad_mismatch_device_hash_vs_uuid_fails() {
    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    // Alice (buggy): local_user_id = 32-char hex device-hash (old broken behavior).
    let alice_device_hash = "6f5e37ac88bd2cc53348f01f78cdf5db"; // 32 chars, no dashes
    // Bob's view of Alice: a 36-char server UUID (what the server hands out).
    let alice_server_uuid = "14f28d31-2dab-44aa-a123-456789abcdef"; // 36 chars
    let bob_uuid = "81f02199-8374-48f8-8a5f-549434ccc53f";

    assert_ne!(
        alice_device_hash.len(),
        alice_server_uuid.len(),
        "Precondition: device-hash and server UUID must have different lengths"
    );

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();

    // Alice creates session with WRONG local_user_id (device hash, not server UUID).
    // The debug_assert in new_initiator_session would fire here in a debug build;
    // we bypass it for this test to verify the AEAD layer also catches it.
    let mut alice = {
        // Temporarily side-step the debug_assert by calling through the internal path.
        // We construct the session directly to ensure the mismatch reaches AEAD.
        DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
            &rk_alice,
            init_state,
            &bob_pub,
            bob_uuid.to_string(),          // contact_id (UUID — OK)
            alice_device_hash.to_string(), // local_user_id (device hash — WRONG)
        )
        .unwrap()
    };

    let msg0 = alice
        .encrypt(b"This AEAD tag will not verify on Bob's side")
        .unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();

    // Bob knows Alice by her server UUID, not her device hash.
    // AD mismatch: Alice used "6f5e37ac…" (32B), Bob expects "14f28d31-…" (36B).
    let result = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        alice_server_uuid.to_string(), // contact_id = Alice UUID (≠ alice device hash)
        bob_uuid.to_string(),
    );

    assert!(
        result.is_err(),
        "AEAD must fail when initiator local_user_id (device hash) \
         differs from responder contact_id (server UUID)"
    );
    let err_msg = result.err().unwrap();
    assert!(
        err_msg.contains("Decryption failed"),
        "Error should come from AEAD decryption, got: {}",
        err_msg
    );
}

/// Verify that the AD check is a FORMAT CONSISTENCY requirement, not a UUID requirement.
/// When both parties use the SAME format (even short strings), the session works.
/// This confirms the fix is about matching formats, not enforcing UUID specifically.
#[test]
fn test_ad_symmetric_any_consistent_format_works() {
    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    // Both sides use a consistent (non-UUID) format.
    // This should work because the formats match — the invariant is CONSISTENCY.
    let alice_id = "alice_node";
    let bob_id = "bob_node";

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        bob_id.to_string(),
        alice_id.to_string(),
    )
    .unwrap();

    let msg0 = alice.encrypt(b"consistent short IDs").unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();

    let (_, plaintext) = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        alice_id.to_string(),
        bob_id.to_string(),
    )
    .unwrap();

    assert_eq!(plaintext, b"consistent short IDs");
}

/// Edge case: same user ID on both sides (e.g., self-message or test misconfiguration).
/// AD = AD_VERSION || id || id on both encrypt and decrypt → bytes are identical → succeeds.
/// Documents this (potentially surprising) behavior explicitly.
#[test]
fn test_ad_same_id_both_sides_accidentally_works() {
    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    let shared_id = "shared-user-id-for-both";

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        shared_id.to_string(), // contact_id
        shared_id.to_string(), // local_user_id (same — not production-valid but tests AD symmetry)
    )
    .unwrap();

    let msg0 = alice.encrypt(b"same ID both sides").unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();

    // When both IDs are identical, AD is symmetric: encrypt and decrypt produce same bytes.
    let result = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        shared_id.to_string(),
        shared_id.to_string(),
    );
    assert!(
        result.is_ok(),
        "Same ID on both sides → AD is still symmetric → must succeed"
    );
}

/// Edge case: empty local_user_id on one side (misconfigured Swift layer, e.g. when
/// _cachedUserId is nil and cryptoLocalUserId returns "").
#[test]
fn test_ad_mismatch_empty_local_user_id_fails() {
    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    let bob_uuid = "81f02199-8374-48f8-8a5f-549434ccc53f";

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        bob_uuid.to_string(),
        "".to_string(), // empty — cryptoLocalUserId returned "" (nil cachedUserId)
    )
    .unwrap();

    let msg0 = alice.encrypt(b"empty id test").unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();

    let alice_uuid = "14f28d31-2dab-44aa-a123-456789abcdef";
    let result = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        alice_uuid.to_string(), // contact_id = Alice's UUID (non-empty)
        bob_uuid.to_string(),
    );

    assert!(
        result.is_err(),
        "Empty local_user_id must cause AEAD failure — \
         guards against nil _cachedUserId in Swift layer"
    );
}

/// Edge case: wrong user — correct format but different UUID value.
/// Bob receives a message from Alice but processes it as if it came from Carol.
/// AD still mismatches → AEAD fails (guards against contact_id confusion bugs).
#[test]
fn test_ad_mismatch_wrong_contact_id_same_format_fails() {
    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    let alice_uuid = "14f28d31-2dab-44aa-a123-456789abcdef";
    let carol_uuid = "99999999-0000-0000-0000-111111111111"; // different user, same format
    let bob_uuid = "81f02199-8374-48f8-8a5f-549434ccc53f";

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        bob_uuid.to_string(),
        alice_uuid.to_string(),
    )
    .unwrap();

    let msg0 = alice.encrypt(b"only for bob, not carol").unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();

    // Bob mistakenly thinks the message came from Carol (wrong contact_id attribution).
    let result = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        carol_uuid.to_string(), // WRONG — should be alice_uuid
        bob_uuid.to_string(),
    );

    assert!(
        result.is_err(),
        "AD must bind sender identity: wrong contact_id (Carol vs Alice) must fail"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// Desync Protection Tests
//
// Covers scenarios that can cause session desynchronization beyond the AD-
// identity bug: concurrent initialization, session replacement (END_SESSION),
// state persistence across restarts, adversarial message patterns.
// ══════════════════════════════════════════════════════════════════════════

/// Shared helper: builds a ready Alice–Bob session pair where both sides are
/// past message 0. `new_responder_session` decrypts msg0 internally, so on
/// return both sessions are ready for normal bidirectional exchange.
#[allow(clippy::type_complexity)]
fn make_session_pair(
    alice_uuid: &str,
    bob_uuid: &str,
) -> (
    DoubleRatchetSession<ClassicSuiteProvider>,
    DoubleRatchetSession<ClassicSuiteProvider>,
) {
    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        bob_uuid.to_string(),   // contact_id
        alice_uuid.to_string(), // local_user_id
    )
    .unwrap();
    let msg0 = alice.encrypt(b"session-init-ping").unwrap();

    let alice_eph = ClassicSuiteProvider::kem_public_key_from_bytes(msg0.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();
    let (bob, _) = DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
        &rk_bob,
        &bob_priv,
        &msg0,
        alice_uuid.to_string(), // contact_id = Alice's UUID (the initiator)
        bob_uuid.to_string(),   // local_user_id = Bob's UUID (the responder)
    )
    .unwrap();

    (alice, bob)
}

/// Concurrent init / tie-break: both parties call new_initiator_session
/// simultaneously. The LOSE side (Bob) receives Alice's msg0, discards its
/// own initiator session, and switches to new_responder_session.
///
/// This mirrors the Swift SessionService tie-break path:
///   WIN → stays INITIATOR, sends ping
///   LOSE → wipes session, calls init_receiving_session(alice_msg0)
///
/// Verifies: the resulting sessions produce correct bidirectional exchange.
#[test]
fn test_concurrent_init_loser_switches_to_responder() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000001";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000002";

    let (alice_priv, alice_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
    let (bundle, bob_priv, bob_spk_priv, bob_pub) = make_bob_bundle();

    // ── Alice: INITIATOR (WIN) ────────────────────────────────────────────
    let (rk_alice, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk_alice,
        init_state,
        &bob_pub,
        bob_uuid.to_string(),
        alice_uuid.to_string(),
    )
    .unwrap();
    let msg0_from_alice = alice.encrypt(b"concurrent-init-ping").unwrap();

    // ── Bob: LOSE side — receives Alice's msg0 and switches to RESPONDER ──
    // Bob's own initiator session (created simultaneously) is discarded here.
    let alice_eph =
        ClassicSuiteProvider::kem_public_key_from_bytes(msg0_from_alice.dh_public_key.to_vec());
    let rk_bob = X3DHProtocol::<ClassicSuiteProvider>::perform_as_responder(
        &bob_priv,
        &bob_spk_priv,
        &alice_pub,
        &alice_eph,
        None,
    )
    .unwrap();
    let (mut bob, init_plain) =
        DoubleRatchetSession::<ClassicSuiteProvider>::new_responder_session(
            &rk_bob,
            &bob_priv,
            &msg0_from_alice,
            alice_uuid.to_string(), // contact_id = Alice's UUID (the initiator)
            bob_uuid.to_string(),   // local_user_id = Bob's UUID (the responder)
        )
        .unwrap();
    assert_eq!(
        init_plain, b"concurrent-init-ping",
        "RESPONDER must decrypt INITIATOR's opening message"
    );

    // ── Bidirectional exchange after tie-break resolution ─────────────────
    let bob_reply = bob.encrypt(b"tie-break ok, bob here").unwrap();
    let alice_msg2 = alice.encrypt(b"alice second message").unwrap();
    let bob_msg3 = bob.encrypt(b"bob second message").unwrap();

    assert_eq!(
        alice.decrypt(&bob_reply).unwrap(),
        b"tie-break ok, bob here"
    );
    assert_eq!(bob.decrypt(&alice_msg2).unwrap(), b"alice second message");
    assert_eq!(alice.decrypt(&bob_msg3).unwrap(), b"bob second message");
}

/// Session replacement (END_SESSION equivalent): after exchanging messages in
/// session-1, both parties re-initialise with fresh X3DH (session-2).
///
/// Verifies:
/// - session-2 messages decrypt correctly in session-2
/// - session-1 messages do NOT decrypt in session-2 (different root key → different AD)
/// - session-2 messages do NOT decrypt in session-1
#[test]
fn test_session_replacement_creates_independent_state() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000001";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000002";

    // ── Session 1 ─────────────────────────────────────────────────────────
    let (mut alice1, mut bob1) = make_session_pair(alice_uuid, bob_uuid);
    let old_msg = alice1.encrypt(b"old session message").unwrap();
    assert_eq!(bob1.decrypt(&old_msg).unwrap(), b"old session message");

    // ── Session 2 (END_SESSION → fresh X3DH re-init) ──────────────────────
    let (mut alice2, mut bob2) = make_session_pair(alice_uuid, bob_uuid);

    let new_msg = alice2.encrypt(b"new session message").unwrap();
    assert_eq!(
        bob2.decrypt(&new_msg).unwrap(),
        b"new session message",
        "session-2 message must decrypt in session-2"
    );

    // Cross-session must fail
    let old_msg2 = alice1.encrypt(b"old session msg2").unwrap();
    assert!(
        bob2.decrypt(&old_msg2).is_err(),
        "session-1 message must NOT decrypt in session-2"
    );

    let new_msg2 = alice2.encrypt(b"new session msg2").unwrap();
    assert!(
        bob1.decrypt(&new_msg2).is_err(),
        "session-2 message must NOT decrypt in session-1"
    );
}

/// Serialize mid-conversation, restore, continue: simulates an app restart
/// between messages. Verifies no desync after round-trip through storage.
#[test]
fn test_serialize_midconversation_no_desync() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000001";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000002";

    let (mut alice, mut bob) = make_session_pair(alice_uuid, bob_uuid);

    // Phase 1: exchange before "crash"
    let a1 = alice.encrypt(b"pre-crash 1").unwrap();
    let a2 = alice.encrypt(b"pre-crash 2").unwrap();
    let b1 = bob.encrypt(b"pre-crash reply 1").unwrap();

    bob.decrypt(&a1).unwrap();
    bob.decrypt(&a2).unwrap();
    alice.decrypt(&b1).unwrap();

    // Simulate app restart: serialize → deserialize
    let (mut alice, mut bob) = (
        DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(alice.to_serializable())
            .unwrap(),
        DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(bob.to_serializable())
            .unwrap(),
    );

    // Phase 2: exchange after restore
    let a3 = alice.encrypt(b"post-crash 3").unwrap();
    let b2 = bob.encrypt(b"post-crash reply 2").unwrap();
    let a4 = alice.encrypt(b"post-crash 4").unwrap();

    assert_eq!(bob.decrypt(&a3).unwrap(), b"post-crash 3");
    assert_eq!(alice.decrypt(&b2).unwrap(), b"post-crash reply 2");
    assert_eq!(bob.decrypt(&a4).unwrap(), b"post-crash 4");
}

/// Long one-sided flood: Alice sends 100 messages without Bob responding.
/// Bob decrypts all 100 in order. Catches off-by-one bugs in chain key
/// advancement and verifies skipped_keys do not accumulate during in-order delivery.
#[test]
fn test_long_one_sided_flood_then_reply() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000001";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000002";

    let (mut alice, mut bob) = make_session_pair(alice_uuid, bob_uuid);
    const COUNT: usize = 100;

    let mut messages = Vec::with_capacity(COUNT);
    for i in 0..COUNT {
        messages.push((i, alice.encrypt(format!("flood-{i}").as_bytes()).unwrap()));
    }

    for (i, msg) in &messages {
        assert_eq!(
            bob.decrypt(msg).unwrap(),
            format!("flood-{i}").as_bytes(),
            "flood message {i} must decrypt correctly"
        );
    }

    // No skipped keys: everything arrived in order
    let snap = bob.to_serializable();
    assert!(
        snap.skipped_keys.is_empty(),
        "In-order delivery must not accumulate any skipped keys"
    );

    // Session remains usable
    let ack = bob.encrypt(b"all 100 received").unwrap();
    assert_eq!(alice.decrypt(&ack).unwrap(), b"all 100 received");
}

/// Replay attack: feed the same encrypted message to decrypt twice.
/// The second call must fail — the ratchet chain advanced past message 0 and
/// the consumed key was never stored in skipped_message_keys.
/// The session must remain fully functional after the failed replay.
#[test]
fn test_replay_attack_fails_gracefully() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000001";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000002";

    let (mut alice, mut bob) = make_session_pair(alice_uuid, bob_uuid);

    let msg = alice.encrypt(b"original message").unwrap();

    // First decrypt: succeeds
    assert_eq!(bob.decrypt(&msg).unwrap(), b"original message");

    // Replay: must fail (chain advanced; consumed key not in skipped_message_keys)
    assert!(
        bob.decrypt(&msg).is_err(),
        "Replaying a consumed message must fail"
    );

    // Session is still usable after the replay attempt
    let msg2 = alice.encrypt(b"after replay attempt").unwrap();
    assert_eq!(
        bob.decrypt(&msg2).unwrap(),
        b"after replay attempt",
        "Session must remain functional after a replay failure"
    );
}

/// 10-round alternating exchange (100 messages, ~20 DH ratchet steps).
/// Verifies that the ratchet stays synchronised over many turns and that
/// skipped_message_keys are empty after a clean alternating exchange.
#[test]
fn test_alternating_10_round_exchange_no_desync() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000001";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000002";

    let (mut alice, mut bob) = make_session_pair(alice_uuid, bob_uuid);

    for round in 0..10_u32 {
        // Alice → Bob (5 messages)
        let alice_batch: Vec<_> = (0..5_u32)
            .map(|i| {
                let plain = format!("r{round}-a{i}");
                let enc = alice.encrypt(plain.as_bytes()).unwrap();
                (plain, enc)
            })
            .collect();
        for (plain, enc) in &alice_batch {
            assert_eq!(
                bob.decrypt(enc).unwrap(),
                plain.as_bytes(),
                "round {round}: bob decrypt failed"
            );
        }

        // Bob → Alice (5 messages)
        let bob_batch: Vec<_> = (0..5_u32)
            .map(|i| {
                let plain = format!("r{round}-b{i}");
                let enc = bob.encrypt(plain.as_bytes()).unwrap();
                (plain, enc)
            })
            .collect();
        for (plain, enc) in &bob_batch {
            assert_eq!(
                alice.decrypt(enc).unwrap(),
                plain.as_bytes(),
                "round {round}: alice decrypt failed"
            );
        }
    }

    // No stale skipped keys after clean alternating exchange
    let a_snap = alice.to_serializable();
    let b_snap = bob.to_serializable();
    assert!(
        a_snap.skipped_keys.is_empty(),
        "Alice must have 0 skipped keys"
    );
    assert!(
        b_snap.skipped_keys.is_empty(),
        "Bob must have 0 skipped keys"
    );
}

/// Cross-session binding: a message encrypted under session-A must not decrypt
/// under session-B even when both sessions have identical participant UUIDs.
/// The `session_id` field in the AD (derived from the X3DH root key) is unique
/// per session instance and binds each ciphertext to exactly one session.
#[test]
fn test_cross_session_message_rejected_by_ad() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000001";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000002";

    // Two independent session instances with the SAME participant UUIDs
    let (mut alice1, _bob1) = make_session_pair(alice_uuid, bob_uuid);
    let (_alice2, mut bob2) = make_session_pair(alice_uuid, bob_uuid);

    let msg_from_session1 = alice1.encrypt(b"belongs to session 1").unwrap();

    assert!(
        bob2.decrypt(&msg_from_session1).is_err(),
        "session-1 ciphertext must be rejected by session-2 (session_id in AD differs)"
    );
}

/// desync-test-skipped-keys-limit: DoS protection.
///
/// Alice encrypts `limit + 2` messages but only delivers the last one to Bob.
/// Bob must receive `Err("Too many skipped messages")` — no panic — when trying
/// to skip `limit + 1` keys to reach the delivered message.
///
/// After the failed decrypt the session state must be rolled back to the
/// snapshot (restore_snapshot path), so a normally-delivered follow-up message
/// still decrypts successfully.
#[test]
fn test_skipped_keys_dos_limit_returns_error_and_session_survives() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000011";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000012";

    let (mut alice, mut bob) = make_session_pair(alice_uuid, bob_uuid);

    let limit = crate::config::Config::global().max_skipped_messages as usize;

    // Alice encrypts `limit + 2` messages (indices 0 … limit+1).
    // We keep only the very last one to present a gap of limit+1 to Bob.
    let mut overflow_msg = None;
    for i in 0..=(limit + 1) {
        let ct = alice.encrypt(format!("msg-{i}").as_bytes()).unwrap();
        if i == limit + 1 {
            overflow_msg = Some(ct);
        }
    }
    let overflow_msg = overflow_msg.unwrap();

    // Bob tries to decrypt a message that requires skipping limit+1 keys.
    // This must return an error, not panic.
    let result = bob.decrypt(&overflow_msg);
    assert!(
        result.is_err(),
        "decrypt must return Err when the gap exceeds MAX_SKIPPED_MESSAGES"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("Too many skipped"),
        "error message should mention skipped messages, got: {err}"
    );

    // Session must be rolled back to the pre-decrypt snapshot — Bob's
    // skipped_message_keys must be empty (no partial state leaked).
    let bob_snap = bob.to_serializable();
    assert!(
        bob_snap.skipped_keys.is_empty(),
        "snapshot restore must leave skipped_keys empty after overflow error"
    );

    // Bob's SENDING chain is independent of his receiving chain and must still
    // be usable — the overflow only affects Alice→Bob decryption.
    // (Alice→Bob requires END_SESSION + re-init once the gap exceeds the limit;
    //  that is correct, intentional DR behaviour — not a bug to fix here.)
    let bob_msg = bob.encrypt(b"bob send after overflow").unwrap();
    let alice_received = alice.decrypt(&bob_msg);
    assert!(
        alice_received.is_ok(),
        "Bob must still be able to send after the overflow; Alice decrypt failed: {:?}",
        alice_received.err()
    );
    assert_eq!(alice_received.unwrap(), b"bob send after overflow");
}
