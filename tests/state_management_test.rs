//! State Management Tests for Double Ratchet
//!
//! Тестируем критически важные сценарии:
//! 1. Out-of-order message delivery
//! 2. Message gaps (missing messages)
//! 3. DoS protection (max skipped messages)
//! 4. Cleanup old skipped keys
//! 5. Session desync detection

use construct_core::crypto::handshake::KeyAgreement;
use construct_core::crypto::handshake::x3dh::{X3DHProtocol, X3DHPublicKeyBundle};
use construct_core::crypto::keys::build_prologue;
use construct_core::crypto::messaging::SecureMessaging;
use construct_core::crypto::messaging::double_ratchet::DoubleRatchetSession;
use construct_core::crypto::suites::classic::ClassicSuiteProvider;
use construct_core::crypto::{CryptoProvider, SuiteID};

type Provider = ClassicSuiteProvider;

/// Создать две сессии Alice <-> Bob после X3DH handshake
fn setup_sessions() -> (
    DoubleRatchetSession<Provider>,
    DoubleRatchetSession<Provider>,
) {
    // Generate identity keys
    let (alice_identity_priv, alice_identity_pub) = Provider::generate_kem_keys().unwrap();
    let (bob_identity_priv, bob_identity_pub) = Provider::generate_kem_keys().unwrap();

    // Bob generates signed prekey
    let (bob_signed_prekey_priv, bob_signed_prekey_pub) = Provider::generate_kem_keys().unwrap();
    let (bob_signing_key, bob_verifying_key) = Provider::generate_signature_keys().unwrap();

    // Sign with prologue (required by X3DH verifier)
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

    // Alice performs X3DH as initiator
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

    // Alice sends handshake message — required to initialise Bob's responder session
    let init_msg = alice_session.encrypt(b"__init__").unwrap();

    // Bob performs X3DH as responder
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

#[test]
fn test_in_order_messages() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice отправляет 5 сообщений по порядку
    let messages: Vec<_> = (0..5)
        .map(|i| {
            let plaintext = format!("Message {}", i);
            alice.encrypt(plaintext.as_bytes()).unwrap()
        })
        .collect();

    // Bob получает их по порядку
    for (i, msg) in messages.iter().enumerate() {
        let decrypted = bob.decrypt(msg).unwrap();
        let expected = format!("Message {}", i);
        assert_eq!(decrypted, expected.as_bytes());
    }
}

#[test]
fn test_out_of_order_delivery() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice отправляет 6 сообщений
    let messages: Vec<_> = (0..6)
        .map(|i| {
            let plaintext = format!("Message {}", i);
            alice.encrypt(plaintext.as_bytes()).unwrap()
        })
        .collect();

    // Доставляем в порядке: 0, 1, 5, 2, 3, 4
    let delivery_order = vec![0, 1, 5, 2, 3, 4];

    for &idx in &delivery_order {
        let decrypted = bob.decrypt(&messages[idx]).unwrap();
        let expected = format!("Message {}", idx);
        assert_eq!(
            decrypted,
            expected.as_bytes(),
            "Failed to decrypt message {} in out-of-order delivery",
            idx
        );
    }
}

#[test]
fn test_message_gap() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice отправляет сообщения 0, 1, 10
    let msg0 = alice.encrypt(b"Message 0").unwrap();
    let msg1 = alice.encrypt(b"Message 1").unwrap();

    // Пропускаем 2-9
    for _ in 2..10 {
        alice.encrypt(b"Skipped").unwrap();
    }

    let msg10 = alice.encrypt(b"Message 10").unwrap();

    // Bob получает 0, 1, 10 (gap)
    assert_eq!(bob.decrypt(&msg0).unwrap(), b"Message 0");
    assert_eq!(bob.decrypt(&msg1).unwrap(), b"Message 1");

    // Сообщение 10 должно успешно расшифроваться
    // Ключи 2-9 должны быть сохранены в skipped_message_keys
    assert_eq!(bob.decrypt(&msg10).unwrap(), b"Message 10");
}

#[test]
fn test_max_skipped_messages_protection() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice отправляет сообщение 0
    let msg0 = alice.encrypt(b"Message 0").unwrap();
    assert_eq!(bob.decrypt(&msg0).unwrap(), b"Message 0");

    // Alice генерирует много сообщений (не отправляет)
    for _ in 1..1001 {
        alice.encrypt(b"Skipped").unwrap();
    }

    // Отправляем сообщение 1001
    let msg1001 = alice.encrypt(b"Message 1001").unwrap();

    // Bob пытается расшифровать → должен получить ошибку DoS protection
    let result = bob.decrypt(&msg1001);
    assert!(
        result.is_err(),
        "Should fail with 'Too many skipped messages'"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("Too many skipped messages"),
        "Error message should mention skipped messages limit, got: {}",
        err_msg
    );
}

#[test]
fn test_duplicate_message_rejected() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice отправляет сообщения
    let msg0 = alice.encrypt(b"Message 0").unwrap();
    let msg1 = alice.encrypt(b"Message 1").unwrap();
    let msg2 = alice.encrypt(b"Message 2").unwrap();

    // Bob получает 0, 1, 2
    assert_eq!(bob.decrypt(&msg0).unwrap(), b"Message 0");
    assert_eq!(bob.decrypt(&msg1).unwrap(), b"Message 1");
    assert_eq!(bob.decrypt(&msg2).unwrap(), b"Message 2");

    // Попытка повторно расшифровать msg1 (replay attack)
    let result = bob.decrypt(&msg1);
    assert!(
        result.is_err(),
        "Duplicate message should be rejected (key already used)"
    );
}

#[test]
fn test_bidirectional_out_of_order() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice → Bob: 0, 1, 2
    let alice_msgs: Vec<_> = (0..3)
        .map(|i| {
            alice
                .encrypt(format!("Alice→Bob {}", i).as_bytes())
                .unwrap()
        })
        .collect();

    // Bob → Alice: 0, 1, 2
    let bob_msgs: Vec<_> = (0..3)
        .map(|i| bob.encrypt(format!("Bob→Alice {}", i).as_bytes()).unwrap())
        .collect();

    // Доставка вперемешку: Alice0, Bob2, Alice2, Bob0, Alice1, Bob1
    assert_eq!(
        bob.decrypt(&alice_msgs[0]).unwrap(),
        b"Alice\xe2\x86\x92Bob 0"
    );
    assert_eq!(
        alice.decrypt(&bob_msgs[2]).unwrap(),
        b"Bob\xe2\x86\x92Alice 2"
    );
    assert_eq!(
        bob.decrypt(&alice_msgs[2]).unwrap(),
        b"Alice\xe2\x86\x92Bob 2"
    );
    assert_eq!(
        alice.decrypt(&bob_msgs[0]).unwrap(),
        b"Bob\xe2\x86\x92Alice 0"
    );
    assert_eq!(
        bob.decrypt(&alice_msgs[1]).unwrap(),
        b"Alice\xe2\x86\x92Bob 1"
    );
    assert_eq!(
        alice.decrypt(&bob_msgs[1]).unwrap(),
        b"Bob\xe2\x86\x92Alice 1"
    );
}

/// Сценарий из документации Signal Protocol:
/// "Messages may be lost, reordered, or duplicated by the network"
#[test]
fn test_signal_protocol_network_scenarios() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice отправляет 10 сообщений
    let messages: Vec<_> = (0..10)
        .map(|i| alice.encrypt(format!("Msg {}", i).as_bytes()).unwrap())
        .collect();

    // Сценарий 1: Потеря сообщений (3, 7 потеряны навсегда)
    for &i in &[0, 1, 2, 4, 5, 6, 8, 9] {
        bob.decrypt(&messages[i]).unwrap();
    }

    // Сценарий 2: Reordering
    let msg_a = alice.encrypt(b"A").unwrap();
    let msg_b = alice.encrypt(b"B").unwrap();
    let msg_c = alice.encrypt(b"C").unwrap();

    assert_eq!(bob.decrypt(&msg_c).unwrap(), b"C");
    assert_eq!(bob.decrypt(&msg_a).unwrap(), b"A");
    assert_eq!(bob.decrypt(&msg_b).unwrap(), b"B");

    // Сценарий 3: Дубликат (уже протестирован в test_duplicate_message_rejected)
}

#[test]
fn test_dh_ratchet_with_out_of_order() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice отправляет 3 сообщения
    let alice_msg0 = alice.encrypt(b"Alice 0").unwrap();
    let alice_msg1 = alice.encrypt(b"Alice 1").unwrap();
    let alice_msg2 = alice.encrypt(b"Alice 2").unwrap();

    // Bob получает только первое
    assert_eq!(bob.decrypt(&alice_msg0).unwrap(), b"Alice 0");

    // Bob отвечает (DH ratchet!)
    let bob_msg0 = bob.encrypt(b"Bob 0").unwrap();
    let bob_msg1 = bob.encrypt(b"Bob 1").unwrap();

    // Alice получает ответ Bob
    assert_eq!(alice.decrypt(&bob_msg0).unwrap(), b"Bob 0");

    // Теперь Alice получает старые сообщения (до DH ratchet)
    // Эти сообщения должны всё ещё расшифровываться
    assert_eq!(bob.decrypt(&alice_msg1).unwrap(), b"Alice 1");
    assert_eq!(bob.decrypt(&alice_msg2).unwrap(), b"Alice 2");

    // Alice продолжает получать от Bob
    assert_eq!(alice.decrypt(&bob_msg1).unwrap(), b"Bob 1");
}
