#[cfg(feature = "post-quantum")]
use super::PqRatchetWireField;
use super::{DoubleRatchetSession, EncryptedRatchetMessage, SuiteID};
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
        supports_pq_ratchet: false,
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
        supports_pq_ratchet: false,
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
        SuiteID::CLASSIC,
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
        supports_pq_ratchet: false,
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
        SuiteID::CLASSIC,
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
        supports_pq_ratchet: false,
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
        SuiteID::CLASSIC,
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
        supports_pq_ratchet: false,
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
        SuiteID::CLASSIC,
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
        supports_pq_ratchet: false,
    };

    let (rk, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk,
        init_state,
        &bob_pub,
        "bob".to_string(),
        "alice".to_string(),
        SuiteID::CLASSIC,
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
        supports_pq_ratchet: false,
    };

    let (rk, init_state) =
        X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(&alice_priv, &bundle).unwrap();
    let mut alice = DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
        &rk,
        init_state,
        &bob_pub,
        "bob".to_string(),
        "alice".to_string(),
        SuiteID::CLASSIC,
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
        SuiteID::CLASSIC,
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
        SuiteID::CLASSIC,
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
            SuiteID::CLASSIC,
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
        SuiteID::CLASSIC,
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
        SuiteID::CLASSIC,
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
        SuiteID::CLASSIC,
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
        SuiteID::CLASSIC,
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
        SuiteID::CLASSIC,
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
        SuiteID::CLASSIC,
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

// ══════════════════════════════════════════════════════════════════════════
// AD v2 → v3 graceful migration tests
//
// When AD_VERSION was bumped from 2 to 3 (marking the session_id v2 era),
// in-flight messages from old clients (still using AD v2) must be decryptable
// by new clients via the fallback in `decrypt_with_key`.
// ══════════════════════════════════════════════════════════════════════════

/// Core assertion: `decrypt_with_key` retries with the previous AD version
/// when the current version fails, so "old-client" messages don't cause
/// a session rupture during a rolling upgrade.
#[test]
fn test_ad_v2_fallback_decrypts_legacy_messages() {
    use crate::traffic_protection::padding::pad_message_default;

    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000031";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000032";
    let (_alice, bob) = make_session_pair(alice_uuid, bob_uuid);

    // Bob is the receiver. His decrypt-side AD is:
    //   ad_version || contact_id (alice) || local_user_id (bob) || session_id || dh_pub || msg_num
    let session_id_bytes = hex::decode(bob.session_id()).unwrap();

    // Synthetic message key and wire fields (not derived from the real ratchet chain).
    let message_key = ClassicSuiteProvider::aead_key_from_bytes(vec![0x42u8; 32]);
    let dh_public_key = [0xABu8; 32];
    let nonce = vec![0u8; 12]; // 12-byte ChaCha20Poly1305 nonce
    let message_number: u32 = 7;

    let plaintext = b"hello from old client";
    let padded = pad_message_default(plaintext).unwrap();

    // Build v2 AD (AD_VERSION_PREV = 2).
    let mut ad_v2: Vec<u8> = Vec::new();
    ad_v2.push(2u8); // AD_VERSION_PREV
    ad_v2.extend_from_slice(alice_uuid.as_bytes()); // contact_id
    ad_v2.extend_from_slice(bob_uuid.as_bytes()); // local_user_id
    ad_v2.extend_from_slice(&session_id_bytes);
    ad_v2.extend_from_slice(&dh_public_key);
    ad_v2.extend_from_slice(&message_number.to_be_bytes());

    let ciphertext =
        ClassicSuiteProvider::aead_encrypt(&message_key, &nonce, &padded, Some(&ad_v2))
            .expect("test AEAD encrypt with v2 AD failed");

    let old_msg = EncryptedRatchetMessage {
        dh_public_key,
        message_number,
        ciphertext,
        nonce,
        previous_chain_length: 0,
        suite_id: SuiteID::CLASSIC.as_u16(),
        pq_message_epoch: 0,
        pq_ratchet_field: None,
    };

    // Current AD version (v3) must NOT decrypt a v2-encrypted message.
    assert!(
        bob.try_aead_decrypt(&message_key, &old_msg, 3u8).is_err(),
        "v3 AD must not decrypt a v2-encrypted message — these are different AD bytes"
    );

    // Previous AD version (v2) must succeed (direct call).
    let result_v2 = bob.try_aead_decrypt(&message_key, &old_msg, 2u8);
    assert!(
        result_v2.is_ok(),
        "v2 AD fallback must succeed: {:?}",
        result_v2.err()
    );
    assert_eq!(result_v2.unwrap(), plaintext);

    // `decrypt_with_key` (tries v3, falls back to v2) must also succeed.
    let fallback_result = bob.decrypt_with_key(&message_key, &old_msg);
    assert!(
        fallback_result.is_ok(),
        "decrypt_with_key must succeed via AD v2 fallback: {:?}",
        fallback_result.err()
    );
    assert_eq!(fallback_result.unwrap(), plaintext);
}

/// Current AD version (v3) messages must still decrypt normally (no regression).
#[test]
fn test_ad_v3_normal_path_unaffected() {
    let alice_uuid = "aaaaaaaa-0000-4000-8000-000000000033";
    let bob_uuid = "bbbbbbbb-0000-4000-8000-000000000034";
    let (mut alice, mut bob) = make_session_pair(alice_uuid, bob_uuid);

    let msg = alice.encrypt(b"v3 normal message").unwrap();
    assert_eq!(bob.decrypt(&msg).unwrap(), b"v3 normal message");

    let reply = bob.encrypt(b"v3 reply").unwrap();
    assert_eq!(alice.decrypt(&reply).unwrap(), b"v3 reply");
}

// ── Sparse continuous PQ ratchet (suite_id = PQ_RATCHET) ─────────────────────
//
// SPQR-style construction (see construct-docs/decisions/
// pq-ratchet-spqr-message-key-mixing.md): the PQ layer never touches the DR
// root key. Completed epoch secrets are mixed into *message keys* only, and
// every suite-3 message carries the epoch tag it was encrypted under, so both
// sides always mix the exact same secret for the same message — interleaving
// and reordering are handled by tags + the classical skipped-key machinery,
// not by a shared-moment assumption. These tests drive the full construction
// through the real `encrypt()`/`decrypt()` path.

/// Session pair on `SuiteID::PQ_RATCHET` — same bootstrap as
/// `make_session_pair`, different suite. Alice is the DR initiator and thus
/// the (sole) PQ exchange initiator.
#[cfg(feature = "post-quantum")]
fn make_pq_session_pair(
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
        bob_uuid.to_string(),
        alice_uuid.to_string(),
        SuiteID::PQ_RATCHET,
    )
    .unwrap();
    let msg0 = alice.encrypt(b"session-init-ping").unwrap();
    assert_eq!(msg0.suite_id, SuiteID::PQ_RATCHET.as_u16());
    assert_eq!(msg0.pq_message_epoch, 0, "no PQ epoch at bootstrap");

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
        alice_uuid.to_string(),
        bob_uuid.to_string(),
    )
    .unwrap();

    assert!(alice.is_pq_initiator, "initiator drives the PQ cadence");
    assert!(!bob.is_pq_initiator, "responder only answers");
    (alice, bob)
}

/// One full conversational round: Alice → Bob, then Bob → Alice. Each
/// direction change triggers a DH ratchet turn on the receiving side, which is
/// what drives the PQ cadence. Panics if either decrypt fails.
#[cfg(feature = "post-quantum")]
fn pq_round(
    alice: &mut DoubleRatchetSession<ClassicSuiteProvider>,
    bob: &mut DoubleRatchetSession<ClassicSuiteProvider>,
    label: &str,
) {
    let m = alice.encrypt(format!("a->b {label}").as_bytes()).unwrap();
    bob.decrypt(&m)
        .unwrap_or_else(|e| panic!("bob failed to decrypt a->b {label}: {e}"));
    let r = bob.encrypt(format!("b->a {label}").as_bytes()).unwrap();
    alice
        .decrypt(&r)
        .unwrap_or_else(|e| panic!("alice failed to decrypt b->a {label}: {e}"));
}

/// Drive a fresh pair up to (at least) the given completed epoch, panicking if
/// it takes unreasonably long. Returns the number of rounds it took.
#[cfg(feature = "post-quantum")]
fn pq_drive_to_epoch(
    alice: &mut DoubleRatchetSession<ClassicSuiteProvider>,
    bob: &mut DoubleRatchetSession<ClassicSuiteProvider>,
    epoch: u32,
) -> u32 {
    let interval = crate::config::Config::global().pq_ratchet_interval;
    let budget = (interval + 4) * epoch;
    for round in 1..=budget {
        pq_round(alice, bob, &format!("drive round {round}"));
        if alice.current_pq_epoch >= epoch && bob.current_pq_epoch >= epoch {
            return round;
        }
    }
    panic!(
        "epoch {epoch} not reached within {budget} rounds \
         (alice at {}, bob at {})",
        alice.current_pq_epoch, bob.current_pq_epoch
    );
}

/// The §A.2 blocker test: a full conversation on suite 3 through the real
/// encrypt/decrypt path, past multiple cadence firings, with every message
/// decrypting and both sides converging on identical epoch secrets. Under the
/// removed root-key fold this scenario bricked at the first cadence firing.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_full_conversation_advances_epochs() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000b1",
        "bbbbbbbb-0000-4000-8000-0000000000b2",
    );

    pq_drive_to_epoch(&mut alice, &mut bob, 2);

    assert_eq!(alice.current_pq_epoch, 2);
    assert_eq!(bob.current_pq_epoch, 2);
    for epoch in [1u32, 2] {
        let a = alice
            .lookup_pq_epoch_secret(epoch)
            .expect("alice must retain the epoch secret");
        let b = bob
            .lookup_pq_epoch_secret(epoch)
            .expect("bob must retain the epoch secret");
        assert_eq!(
            a, b,
            "epoch {epoch} secrets must be identical on both sides"
        );
        assert_eq!(a.len(), 32, "ML-KEM-768 shared secret is 32 bytes");
    }
    assert_ne!(
        alice.lookup_pq_epoch_secret(1).unwrap(),
        alice.lookup_pq_epoch_secret(2).unwrap(),
        "each epoch must contribute fresh key material"
    );

    // Conversation continues normally after multiple mixes.
    pq_round(&mut alice, &mut bob, "post-epoch-2");
}

/// The PQ secret must actually participate in the message key: corrupting one
/// side's epoch secret must make decryption fail (and roll back cleanly).
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_secret_participates_in_message_key() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000b3",
        "bbbbbbbb-0000-4000-8000-0000000000b4",
    );
    pq_drive_to_epoch(&mut alice, &mut bob, 1);

    // Corrupt Bob's copy of the epoch-1 secret.
    let original = {
        let slot = bob
            .pq_epoch_secrets
            .iter_mut()
            .find(|(e, _)| *e == 1)
            .expect("bob holds epoch 1");
        let orig = slot.1.clone();
        slot.1 = vec![0u8; 32];
        orig
    };

    let msg = alice.encrypt(b"tagged with epoch 1").unwrap();
    assert_eq!(msg.pq_message_epoch, 1);
    assert!(
        bob.decrypt(&msg).is_err(),
        "a wrong epoch secret must fail AEAD — the PQ mix is load-bearing"
    );

    // Restore the real secret: the same message must now decrypt (proves the
    // failed attempt rolled back chain state instead of corrupting it).
    bob.pq_epoch_secrets
        .iter_mut()
        .find(|(e, _)| *e == 1)
        .unwrap()
        .1 = original;
    assert_eq!(bob.decrypt(&msg).unwrap(), b"tagged with epoch 1");
}

/// Tampering with the epoch tag on the wire must reject the message (key
/// mismatch / unknown epoch), and the session must survive for a clean retry.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_tampered_epoch_tag_rejected_then_recovers() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000b5",
        "bbbbbbbb-0000-4000-8000-0000000000b6",
    );
    pq_drive_to_epoch(&mut alice, &mut bob, 1);

    let msg = alice.encrypt(b"epoch tag integrity").unwrap();
    assert_eq!(msg.pq_message_epoch, 1);

    let mut tampered = msg.clone();
    tampered.pq_message_epoch = 0; // "skip the PQ mix" downgrade attempt
    assert!(
        bob.decrypt(&tampered).is_err(),
        "downgraded tag must not decrypt"
    );

    let mut tampered_up = msg.clone();
    tampered_up.pq_message_epoch = 9; // unknown epoch
    assert!(
        bob.decrypt(&tampered_up).is_err(),
        "unknown epoch tag must be rejected before AEAD"
    );

    // The untampered original still decrypts — state was rolled back both times.
    assert_eq!(bob.decrypt(&msg).unwrap(), b"epoch tag integrity");
}

/// Interleaving: reordered delivery across the epoch-activation boundary.
/// Bob receives a message tagged with the *new* epoch before an older message
/// tagged with the *previous* epoch (classical skipped-key path) — both must
/// decrypt, and promotion must not disturb the older message's key.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_reordered_delivery_across_epoch_boundary() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000b7",
        "bbbbbbbb-0000-4000-8000-0000000000b8",
    );
    let interval = crate::config::Config::global().pq_ratchet_interval;

    // Drive until Alice has an exchange in flight (EK pending).
    for round in 1..=(interval + 2) {
        pq_round(&mut alice, &mut bob, &format!("warmup {round}"));
        if alice.pending_pq_exchange.is_some() {
            break;
        }
    }
    assert!(alice.pending_pq_exchange.is_some(), "EK must be in flight");

    // Alice sends m_old (still tagged with the pre-completion epoch, carrying
    // the EK). We withhold it.
    let m_old = alice.encrypt(b"held back, old epoch tag").unwrap();
    let old_tag = m_old.pq_message_epoch;

    // Deliver a *copy* of the same EK via the next message so the exchange
    // completes despite m_old being delayed (resend-until-ack).
    let m_ek = alice.encrypt(b"ek resend carrier").unwrap();
    assert!(matches!(
        m_ek.pq_ratchet_field,
        Some(PqRatchetWireField::PublicKey { .. })
    ));
    bob.decrypt(&m_ek).unwrap();
    let r_ct = bob.encrypt(b"ct carrier").unwrap();
    assert!(matches!(
        r_ct.pq_ratchet_field,
        Some(PqRatchetWireField::Ciphertext { .. })
    ));
    alice.decrypt(&r_ct).unwrap();
    let new_epoch = alice.current_pq_epoch;
    assert_eq!(new_epoch, old_tag + 1, "alice activated the new epoch");

    // Alice's next message is tagged with the new epoch; deliver it first.
    let m_new = alice.encrypt(b"new epoch, delivered early").unwrap();
    assert_eq!(m_new.pq_message_epoch, new_epoch);
    assert_eq!(bob.decrypt(&m_new).unwrap(), b"new epoch, delivered early");
    assert_eq!(
        bob.current_pq_epoch, new_epoch,
        "first new-epoch tag promotes bob's provisional secret"
    );

    // Now the delayed old-epoch message arrives (skipped-key path) — must
    // still decrypt with the *old* epoch's mix.
    assert_eq!(bob.decrypt(&m_old).unwrap(), b"held back, old epoch tag");
}

/// A lost EK-carrying message is healed by re-attachment on the next message.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_lost_ek_carrier_healed_by_resend() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000b9",
        "bbbbbbbb-0000-4000-8000-0000000000c0",
    );
    let interval = crate::config::Config::global().pq_ratchet_interval;
    for round in 1..=(interval + 2) {
        pq_round(&mut alice, &mut bob, &format!("warmup {round}"));
        if alice.pending_pq_exchange.is_some() {
            break;
        }
    }
    assert!(alice.pending_pq_exchange.is_some());

    // First EK carrier is lost in transit.
    let _lost = alice.encrypt(b"lost in transit").unwrap();

    // Next message re-attaches the same EK; the exchange completes normally.
    let m2 = alice.encrypt(b"ek retry").unwrap();
    assert!(matches!(
        m2.pq_ratchet_field,
        Some(PqRatchetWireField::PublicKey { .. })
    ));
    bob.decrypt(&m2).unwrap();
    let r = bob.encrypt(b"ct reply").unwrap();
    alice.decrypt(&r).unwrap();
    assert_eq!(alice.current_pq_epoch, 1, "exchange completed despite loss");

    pq_round(&mut alice, &mut bob, "post-loss convergence");
    assert_eq!(bob.current_pq_epoch, 1);
    assert_eq!(
        alice.lookup_pq_epoch_secret(1).unwrap(),
        bob.lookup_pq_epoch_secret(1).unwrap()
    );
}

/// A lost CT-carrying reply is healed the same way: the responder re-attaches
/// the ciphertext to every message until the initiator's tag acknowledges it.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_lost_ct_carrier_healed_by_resend() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000c1",
        "bbbbbbbb-0000-4000-8000-0000000000c2",
    );
    let interval = crate::config::Config::global().pq_ratchet_interval;
    for round in 1..=(interval + 2) {
        pq_round(&mut alice, &mut bob, &format!("warmup {round}"));
        if alice.pending_pq_exchange.is_some() {
            break;
        }
    }

    let m_ek = alice.encrypt(b"ek carrier").unwrap();
    bob.decrypt(&m_ek).unwrap();

    // Bob's first CT carrier is lost.
    let _lost_ct = bob.encrypt(b"lost ct carrier").unwrap();
    // His next message still carries the CT (no ack seen yet).
    let r2 = bob.encrypt(b"ct retry").unwrap();
    assert!(matches!(
        r2.pq_ratchet_field,
        Some(PqRatchetWireField::Ciphertext { .. })
    ));
    alice.decrypt(&r2).unwrap();
    assert_eq!(alice.current_pq_epoch, 1);

    pq_round(&mut alice, &mut bob, "post-ct-loss convergence");
    assert_eq!(bob.current_pq_epoch, 1);
    assert_eq!(
        alice.lookup_pq_epoch_secret(1).unwrap(),
        bob.lookup_pq_epoch_secret(1).unwrap()
    );
}

/// Duplicate EK delivery must NOT re-encapsulate: re-encapsulating would
/// silently replace the provisional secret the first ciphertext committed to.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_duplicate_ek_is_idempotent() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000c3",
        "bbbbbbbb-0000-4000-8000-0000000000c4",
    );
    let interval = crate::config::Config::global().pq_ratchet_interval;
    for round in 1..=(interval + 2) {
        pq_round(&mut alice, &mut bob, &format!("warmup {round}"));
        if alice.pending_pq_exchange.is_some() {
            break;
        }
    }

    let m1 = alice.encrypt(b"ek carrier 1").unwrap();
    bob.decrypt(&m1).unwrap();
    let (ct_before, secret_before) = {
        let p = bob.pending_pq_ciphertext.as_ref().unwrap();
        (p.ciphertext.clone(), p.secret.clone())
    };

    // Same EK arrives again on the next message.
    let m2 = alice.encrypt(b"ek carrier 2").unwrap();
    assert!(matches!(
        m2.pq_ratchet_field,
        Some(PqRatchetWireField::PublicKey { .. })
    ));
    bob.decrypt(&m2).unwrap();
    let p = bob.pending_pq_ciphertext.as_ref().unwrap();
    assert_eq!(
        p.ciphertext, ct_before,
        "duplicate EK must not re-encapsulate"
    );
    assert_eq!(p.secret, secret_before, "provisional secret must be stable");
}

/// Abandon + re-propose: a ciphertext built against an abandoned keypair is
/// rejected by `ek_hash`, and the re-proposed exchange (same epoch id, fresh
/// keypair) completes cleanly.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_stale_ct_for_abandoned_keypair_ignored() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000c5",
        "bbbbbbbb-0000-4000-8000-0000000000c6",
    );
    let interval = crate::config::Config::global().pq_ratchet_interval;
    for round in 1..=(interval + 2) {
        pq_round(&mut alice, &mut bob, &format!("warmup {round}"));
        if alice.pending_pq_exchange.is_some() {
            break;
        }
    }

    // Bob encapsulates against the original EK.
    let m1 = alice.encrypt(b"original ek").unwrap();
    bob.decrypt(&m1).unwrap();
    let stale_ct_msg = bob.encrypt(b"stale ct carrier").unwrap();

    // Alice's exchange times out and is abandoned; the next cadence firing
    // re-proposes the same epoch id with a fresh keypair.
    let max_age = crate::config::Config::global().max_skipped_message_age_seconds as u64;
    alice.pq_pending_since = super::unix_now().saturating_sub(max_age + 3600);
    alice.pq_turns_since_mix = interval - 1;
    let old_public = alice
        .pending_pq_exchange
        .as_ref()
        .unwrap()
        .keypair
        .public
        .clone();
    alice.maybe_advance_pq_ratchet().unwrap();
    let new_exchange = alice.pending_pq_exchange.as_ref().expect("re-proposed");
    assert_eq!(new_exchange.epoch, 1, "same epoch id is reused");
    assert_ne!(new_exchange.keypair.public, old_public, "fresh keypair");

    // The stale ciphertext arrives — ek_hash mismatch, must be ignored.
    alice.decrypt(&stale_ct_msg).unwrap();
    assert_eq!(
        alice.current_pq_epoch, 0,
        "stale CT must not activate an epoch"
    );
    assert!(
        alice.pending_pq_exchange.is_some(),
        "re-proposed exchange must survive the stale CT"
    );

    // The fresh EK reaches Bob (replacing his stale provisional state), and
    // the exchange completes end-to-end.
    let m_new_ek = alice.encrypt(b"fresh ek").unwrap();
    bob.decrypt(&m_new_ek).unwrap();
    let r_new_ct = bob.encrypt(b"fresh ct").unwrap();
    alice.decrypt(&r_new_ct).unwrap();
    assert_eq!(alice.current_pq_epoch, 1);
    pq_round(&mut alice, &mut bob, "post-reproposal convergence");
    assert_eq!(bob.current_pq_epoch, 1);
    assert_eq!(
        alice.lookup_pq_epoch_secret(1).unwrap(),
        bob.lookup_pq_epoch_secret(1).unwrap()
    );
}

/// A malformed EK must be logged-and-dropped without affecting classical
/// delivery of the message that carried it (fail-open on the PQ bonus layer,
/// fail-closed stays reserved for the classical layer).
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_malformed_field_does_not_block_classical() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000c7",
        "bbbbbbbb-0000-4000-8000-0000000000c8",
    );

    let mut msg = alice.encrypt(b"carrier of garbage").unwrap();
    msg.pq_ratchet_field = Some(PqRatchetWireField::PublicKey {
        epoch: 1,
        key: vec![0u8; 10], // not a valid ML-KEM-768 public key
    });
    assert_eq!(
        bob.decrypt(&msg).unwrap(),
        b"carrier of garbage",
        "classical content must be delivered despite the bad PQ field"
    );
    assert!(
        bob.pending_pq_ciphertext.is_none(),
        "garbage must not create provisional state"
    );
}

/// Existing `CLASSIC`/`PQ_HYBRID` sessions must see zero behavior change: the
/// sparse ratchet is strictly opt-in via `suite_id == PQ_RATCHET`.
#[test]
fn test_pq_ratchet_noop_on_non_pq_ratchet_suite() {
    let (mut alice, _bob) = make_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000a1",
        "bbbbbbbb-0000-4000-8000-0000000000a2",
    );
    assert_eq!(alice.suite_id, SuiteID::CLASSIC);

    for _ in 0..100 {
        alice.maybe_advance_pq_ratchet().unwrap();
    }

    assert_eq!(
        alice.pq_turns_since_mix, 0,
        "counter must never advance off PQ_RATCHET"
    );
    assert!(alice.pending_pq_exchange.is_none());
    assert!(alice.pending_pq_ciphertext.is_none());
    assert_eq!(alice.current_pq_epoch, 0);
}

/// Single-initiator discipline: the responder never starts an exchange no
/// matter how many turns pass.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_responder_never_initiates() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000c9",
        "bbbbbbbb-0000-4000-8000-0000000000d0",
    );
    let interval = crate::config::Config::global().pq_ratchet_interval;
    for round in 1..=(interval * 2) {
        pq_round(&mut alice, &mut bob, &format!("round {round}"));
        assert!(
            bob.pending_pq_exchange.is_none(),
            "responder must never generate an EK proposal"
        );
    }
}

/// Cadence: the initiator starts an exchange on exactly the configured turn.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_cadence_fires_after_default_interval() {
    let (mut alice, _bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000d1",
        "bbbbbbbb-0000-4000-8000-0000000000d2",
    );
    let interval = crate::config::Config::global().pq_ratchet_interval;

    alice.pq_turns_since_mix = interval - 2;
    alice.maybe_advance_pq_ratchet().unwrap();
    assert!(
        alice.pending_pq_exchange.is_none(),
        "no exchange before the {interval}th turn"
    );
    alice.maybe_advance_pq_ratchet().unwrap();
    let ex = alice
        .pending_pq_exchange
        .as_ref()
        .expect("must start an exchange exactly on the interval-th turn");
    assert_eq!(ex.epoch, 1, "first proposal targets epoch 1");
    assert_eq!(
        alice.pq_turns_since_mix, 0,
        "counter resets once an exchange starts"
    );
}

/// Epoch secret retention is bounded: only the last `PQ_EPOCH_RETENTION`
/// epochs are kept, oldest evicted.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_epoch_retention_bounded() {
    let (mut alice, _bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000d3",
        "bbbbbbbb-0000-4000-8000-0000000000d4",
    );
    for epoch in 1..=(super::PQ_EPOCH_RETENTION as u32 + 2) {
        alice.insert_pq_epoch_secret(epoch, vec![epoch as u8; 32]);
    }
    assert_eq!(alice.pq_epoch_secrets.len(), super::PQ_EPOCH_RETENTION);
    assert!(alice.lookup_pq_epoch_secret(1).is_none(), "oldest evicted");
    assert!(alice.lookup_pq_epoch_secret(2).is_none(), "oldest evicted");
    assert!(
        alice
            .lookup_pq_epoch_secret(super::PQ_EPOCH_RETENTION as u32 + 2)
            .is_some()
    );
}

// ── PQ ratchet state persistence (step 3 of the activation sequence) ─────────
//
// A restored suite-3 session must behave identically to the live one: keep
// mixing the right epoch secrets, complete in-flight exchanges, and keep
// driving the cadence. The critical field is the responder's provisional
// secret (pending ciphertext) — after the initiator activates an epoch it is
// the responder's only copy, so dropping it on restore bricks the epoch.

/// Serialize a live session through the full production path
/// (`to_serializable` → `to_cfe_v1` → CFE envelope encode → decode →
/// `from_cfe_v1` → `from_serializable`) and hand back the restored session.
#[cfg(feature = "post-quantum")]
fn cfe_round_trip(
    session: &DoubleRatchetSession<ClassicSuiteProvider>,
) -> DoubleRatchetSession<ClassicSuiteProvider> {
    let cfe = session.to_serializable().to_cfe_v1().unwrap();
    let bytes = crate::cfe::encode(crate::cfe::CfeMessageType::SessionState, &cfe).unwrap();
    let decoded = crate::cfe::decode_as::<crate::cfe::CfeSessionStateV1>(
        &bytes,
        crate::cfe::CfeMessageType::SessionState,
    )
    .unwrap();
    let ser = super::SerializableSession::from_cfe_v1(decoded).unwrap();
    DoubleRatchetSession::from_serializable(ser).unwrap()
}

/// Main persistence test: both sides are serialized mid-exchange (initiator
/// holds a pending epoch-2 keypair, responder holds the provisional epoch-2
/// secret + ciphertext, not yet promoted), restored through the full CFE
/// path, and the conversation + exchange + cadence all continue seamlessly.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_state_survives_cfe_round_trip_mid_exchange() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000e3",
        "bbbbbbbb-0000-4000-8000-0000000000e4",
    );
    let interval = crate::config::Config::global().pq_ratchet_interval;

    // Reach epoch 1, then drive until the epoch-2 exchange is in flight.
    pq_drive_to_epoch(&mut alice, &mut bob, 1);
    for round in 1..=(interval + 2) {
        pq_round(&mut alice, &mut bob, &format!("toward epoch 2, {round}"));
        if alice.pending_pq_exchange.is_some() {
            break;
        }
    }
    assert!(alice.pending_pq_exchange.is_some(), "epoch-2 EK in flight");

    // Deliver the EK so Bob holds the provisional epoch-2 secret (unpromoted).
    let m_ek = alice.encrypt(b"ek carrier before snapshot").unwrap();
    bob.decrypt(&m_ek).unwrap();
    assert!(
        bob.pending_pq_ciphertext.is_some(),
        "provisional CT pending"
    );
    assert_eq!(bob.current_pq_epoch, 1, "not yet promoted");

    // Snapshot + restore BOTH sides through the full CFE path.
    let mut alice2 = cfe_round_trip(&alice);
    let mut bob2 = cfe_round_trip(&bob);
    drop(alice);
    drop(bob);

    assert!(
        alice2.is_pq_initiator,
        "initiator role must survive restore"
    );
    assert!(!bob2.is_pq_initiator);
    assert_eq!(alice2.current_pq_epoch, 1);
    assert_eq!(bob2.current_pq_epoch, 1);
    assert_eq!(
        alice2.lookup_pq_epoch_secret(1).unwrap(),
        bob2.lookup_pq_epoch_secret(1).unwrap(),
        "epoch-1 secret survives on both sides"
    );
    assert!(
        alice2.pending_pq_exchange.is_some(),
        "in-flight exchange survives"
    );
    assert!(
        bob2.pending_pq_ciphertext.is_some(),
        "provisional secret + ciphertext survive (the critical field)"
    );

    // The exchange completes across the restore boundary.
    let r_ct = bob2.encrypt(b"ct after restore").unwrap();
    assert!(matches!(
        r_ct.pq_ratchet_field,
        Some(PqRatchetWireField::Ciphertext { .. })
    ));
    alice2.decrypt(&r_ct).unwrap();
    assert_eq!(
        alice2.current_pq_epoch, 2,
        "restored initiator completed epoch 2"
    );

    let m_tag2 = alice2.encrypt(b"tagged 2 after restore").unwrap();
    assert_eq!(m_tag2.pq_message_epoch, 2);
    assert_eq!(bob2.decrypt(&m_tag2).unwrap(), b"tagged 2 after restore");
    assert_eq!(bob2.current_pq_epoch, 2, "restored responder promoted");
    assert_eq!(
        alice2.lookup_pq_epoch_secret(2).unwrap(),
        bob2.lookup_pq_epoch_secret(2).unwrap()
    );

    // Cadence survives restore: the restored pair reaches epoch 3 unassisted.
    pq_drive_to_epoch(&mut alice2, &mut bob2, 3);
}

/// A suite-3 blob without the `pqr` field (written by the pre-persistence
/// build) restores degraded-but-alive: classical DR state intact, PQ state
/// empty. Peer messages tagged > 0 then fail loudly at decrypt.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_blob_without_pqr_restores_degraded() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000e5",
        "bbbbbbbb-0000-4000-8000-0000000000e6",
    );
    pq_drive_to_epoch(&mut alice, &mut bob, 1);

    let mut cfe = bob.to_serializable().to_cfe_v1().unwrap();
    assert!(cfe.pqr.is_some());
    cfe.pqr = None; // simulate a pre-persistence blob

    let ser = super::SerializableSession::from_cfe_v1(cfe).unwrap();
    let mut bob2 = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(ser).unwrap();
    assert_eq!(bob2.current_pq_epoch, 0, "PQ state reset");
    assert!(bob2.pending_pq_ciphertext.is_none());

    // Epoch-tagged traffic fails loudly (no silent downgrade)…
    let tagged = alice.encrypt(b"tagged 1").unwrap();
    assert_eq!(tagged.pq_message_epoch, 1);
    assert!(bob2.decrypt(&tagged).is_err(), "unknown epoch must fail");
}

/// Old decoders (struct without the `pqr` field) must still parse new blobs:
/// rmp_serde named-map encoding ignores unknown keys.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_new_blob_readable_by_old_decoder() {
    use serde::Deserialize;
    use serde_bytes::ByteBuf;

    /// The required (non-default) subset of `CfeSessionStateV1` as an old
    /// build would have declared it — no `pqr` field.
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct OldCfeSessionState {
        ver: u8,
        suite_id: u8,
        contact_id: String,
        local_uid: String,
        session_id: ByteBuf,
        rk: ByteBuf,
        sck: ByteBuf,
        rck: ByteBuf,
        scl: u32,
        rcl: u32,
        psl: u32,
        dh_pub: ByteBuf,
    }

    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000e7",
        "bbbbbbbb-0000-4000-8000-0000000000e8",
    );
    pq_drive_to_epoch(&mut alice, &mut bob, 1);

    let cfe = alice.to_serializable().to_cfe_v1().unwrap();
    assert!(cfe.pqr.is_some(), "new blob carries the PQ state");
    let bytes = rmp_serde::to_vec_named(&cfe).unwrap();
    let old: Result<OldCfeSessionState, _> = rmp_serde::from_slice(&bytes);
    assert!(
        old.is_ok(),
        "old decoder must ignore the unknown pqr key: {:?}",
        old.err()
    );
}

/// Structurally corrupted PQ state is dropped on restore (degrade-not-fail):
/// the session survives, the PQ state is reset.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_corrupted_state_dropped_on_restore() {
    use serde_bytes::ByteBuf;

    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000e9",
        "bbbbbbbb-0000-4000-8000-0000000000f0",
    );
    pq_drive_to_epoch(&mut alice, &mut bob, 1);

    // Corrupt variant 1: wrong secret length.
    let mut cfe = alice.to_serializable().to_cfe_v1().unwrap();
    cfe.pqr.as_mut().unwrap().epoch_secrets[0].secret = ByteBuf::from(vec![0u8; 5]);
    let ser = super::SerializableSession::from_cfe_v1(cfe).unwrap();
    let restored = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(ser).unwrap();
    assert_eq!(
        restored.current_pq_epoch, 0,
        "corrupted state must be dropped"
    );
    assert!(restored.pq_epoch_secrets.is_empty());

    // Corrupt variant 2: pending-exchange epoch violating the current+1 invariant.
    let mut cfe = alice.to_serializable().to_cfe_v1().unwrap();
    cfe.pqr.as_mut().unwrap().pending_exchange = Some(crate::cfe::CfePqPendingExchangeV1 {
        epoch: 9,
        public: ByteBuf::from(vec![0u8; 1184]),
        secret: ByteBuf::from(vec![0u8; 2400]),
    });
    let ser = super::SerializableSession::from_cfe_v1(cfe).unwrap();
    let restored = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(ser).unwrap();
    assert_eq!(restored.current_pq_epoch, 0);
    assert!(restored.pending_pq_exchange.is_none());
}

/// The legacy JSON import path (`import_session` fallback) round-trips the PQ
/// state too — `SerializableSession` carries it in both encodings.
#[cfg(feature = "post-quantum")]
#[test]
fn test_pq_ratchet_state_survives_json_round_trip() {
    let (mut alice, mut bob) = make_pq_session_pair(
        "aaaaaaaa-0000-4000-8000-0000000000f5",
        "bbbbbbbb-0000-4000-8000-0000000000f6",
    );
    pq_drive_to_epoch(&mut alice, &mut bob, 1);

    let json = serde_json::to_string(&alice.to_serializable()).unwrap();
    let ser: super::SerializableSession = serde_json::from_str(&json).unwrap();
    let alice2 = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(ser).unwrap();

    assert!(alice2.is_pq_initiator);
    assert_eq!(alice2.current_pq_epoch, 1);
    assert_eq!(
        alice2.lookup_pq_epoch_secret(1).unwrap(),
        alice.lookup_pq_epoch_secret(1).unwrap()
    );
}
