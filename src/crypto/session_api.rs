//! Session API - High-level interface for secure messaging sessions
//!
//! Объединяет KeyAgreement (handshake) + SecureMessaging (Double Ratchet)
//! в единый удобный API для работы с сессиями.
//!
//! ## Архитектура
//!
//! ```text
//! Session
//!   ├── KeyAgreement (X3DH)     - для установки root key
//!   └── SecureMessaging (DR)    - для обмена сообщениями
//! ```
//!
//! ## Типичный сценарий использования
//!
//! ### Alice (инициатор)
//! ```text
//! 1. Alice получает Bob's public bundle от сервера
//! 2. Alice: session = Session::init_as_initiator(alice_identity, bob_bundle)
//!    - Выполняется X3DH handshake
//!    - Создаётся Double Ratchet session
//! 3. Alice: encrypted = session.encrypt(plaintext)
//! 4. Alice отправляет encrypted → Server → Bob
//! ```
//!
//! ### Bob (получатель)
//! ```text
//! 1. Bob получает первое зашифрованное сообщение от Alice
//! 2. Bob извлекает Alice's identity public от сервера
//! 3. Bob: session = Session::init_as_responder(
//!       bob_identity,
//!       bob_signed_prekey,
//!       alice_identity_pub,
//!       first_encrypted_message
//!    )
//!    - Выполняется X3DH handshake
//!    - Создаётся Double Ratchet session
//!    - Расшифровывается первое сообщение
//! 4. Bob: plaintext = session.decrypt(first_encrypted_message)
//! 5. Bob: encrypted_reply = session.encrypt(reply)
//! ```
//!
//! ## Ответственность
//!
//! - Координация handshake + messaging
//! - Упрощение API для end-user кода
//! - Валидация параметров
//!
//! ## Не отвечает за
//!
//! - Управление множественными сессиями (это делает Client)
//! - Хранение ключей (это делает KeyManager)
//! - Сетевой транспорт (это делает transport layer)

use crate::crypto::handshake::KeyAgreement;
use crate::crypto::messaging::SecureMessaging;
use crate::crypto::provider::CryptoProvider;
use std::marker::PhantomData;

/// High-level Session для обмена сообщениями с одним контактом
///
/// Объединяет handshake protocol (KeyAgreement) и messaging protocol (SecureMessaging).
///
/// ## Generics
///
/// - `P`: CryptoProvider - криптографический suite (Classic, Hybrid, etc.)
/// - `H`: KeyAgreement - handshake protocol (X3DH, PQ-X3DH, etc.)
/// - `M`: SecureMessaging - messaging protocol (Double Ratchet, etc.)
pub struct Session<P: CryptoProvider, H: KeyAgreement<P>, M: SecureMessaging<P>> {
    /// Идентификатор контакта
    contact_id: String,

    /// Активная messaging session (Double Ratchet)
    messaging_session: M,

    /// PhantomData для generic types
    _phantom: PhantomData<(P, H)>,
}

impl<P: CryptoProvider, H: KeyAgreement<P>, M: SecureMessaging<P>> Session<P, H, M>
where
    H::SharedSecret: AsRef<[u8]>,
{
    /// Инициализировать сессию как инициатор (Alice)
    ///
    /// Alice вызывает этот метод для начала новой сессии с Bob.
    ///
    /// # Процесс
    ///
    /// 1. Выполняет KeyAgreement::perform_as_initiator()
    ///    - Генерирует ephemeral key
    ///    - Выполняет X3DH handshake
    ///    - Получает (root_key, InitiatorState)
    /// 2. Создаёт SecureMessaging::new_initiator_session()
    ///    - Использует root_key от handshake
    ///    - Передаёт ephemeral_private из InitiatorState
    ///    - Создаёт Double Ratchet session
    ///
    /// # Параметры
    ///
    /// - `local_identity`: Alice's identity private key
    /// - `remote_bundle`: Bob's public key bundle (от сервера)
    /// - `remote_identity`: Bob's identity public key (для Double Ratchet)
    /// - `contact_id`: Идентификатор контакта (Bob)
    ///
    /// # Возвращает
    ///
    /// Готовую сессию для шифрования и отправки сообщений
    ///
    /// # Пример
    ///
    /// ```rust,ignore
    /// use construct_core::crypto::session_api::Session;
    /// use construct_core::crypto::handshake::x3dh::X3DHProtocol;
    /// use construct_core::crypto::messaging::double_ratchet::DoubleRatchetSession;
    /// use construct_core::crypto::suites::classic::ClassicSuiteProvider;
    ///
    /// let session = Session::<
    ///     ClassicSuiteProvider,
    ///     X3DHProtocol<ClassicSuiteProvider>,
    ///     DoubleRatchetSession<ClassicSuiteProvider>
    /// >::init_as_initiator(
    ///     &alice_identity_private,
    ///     &bob_public_bundle,
    ///     &bob_identity_public,
    ///     "bob".to_string(),
    /// )?;
    ///
    /// let encrypted = session.encrypt(b"Hello Bob!")?;
    /// ```
    pub fn init_as_initiator(
        local_identity: &P::KemPrivateKey,
        remote_bundle: &H::PublicKeyBundle,
        remote_identity: &P::KemPublicKey,
        contact_id: String,
        local_user_id: String,
    ) -> Result<Self, String> {
        use tracing::{error, info};

        info!(
            target: "crypto::session",
            contact_id = %contact_id,
            "Initializing session as initiator (Alice)"
        );

        // 1. Perform handshake (X3DH)
        let (root_key, initiator_state) = H::perform_as_initiator(local_identity, remote_bundle)
            .map_err(|e| {
                error!(
                    target: "crypto::session",
                    error = %e,
                    "X3DH handshake failed"
                );
                e
            })?;

        info!(
            target: "crypto::session",
            "Handshake completed, creating messaging session"
        );

        // 2. Create messaging session (Double Ratchet)
        // Convert root_key to &[u8] - X3DH returns Vec<u8>
        let messaging_session = M::new_initiator_session(
            root_key.as_ref(),
            initiator_state,
            remote_identity,
            contact_id.clone(),
            local_user_id,
        )
        .map_err(|e| {
            error!(
                target: "crypto::session",
                error = %e,
                "Double Ratchet initialization failed"
            );
            e
        })?;

        info!(
            target: "crypto::session",
            session_id = %messaging_session.session_id(),
            "Session initialized successfully"
        );

        Ok(Self {
            contact_id,
            messaging_session,
            _phantom: PhantomData,
        })
    }

    /// Инициализировать сессию как получатель (Bob)
    ///
    /// Bob вызывает этот метод при получении первого сообщения от Alice.
    ///
    /// # Процесс
    ///
    /// 1. Выполняет KeyAgreement::perform_as_responder()
    ///    - Использует свои identity и signed prekey
    ///    - Использует Alice's identity и ephemeral public (извлечённый из сообщения)
    ///    - Получает root_key
    /// 2. Создаёт SecureMessaging::new_responder_session()
    ///    - Использует root_key от handshake
    ///    - Парсит first_message
    ///    - Создаёт Double Ratchet session
    ///
    /// # Параметры
    ///
    /// - `local_identity`: Bob's identity private key
    /// - `local_signed_prekey`: Bob's signed prekey private key
    /// - `remote_identity`: Alice's identity public key (от сервера)
    /// - `remote_ephemeral`: Alice's ephemeral public key (из first_message.dh_public_key)
    /// - `first_message`: Первое зашифрованное сообщение от Alice
    /// - `contact_id`: Идентификатор контакта (Alice)
    ///
    /// # Возвращает
    ///
    /// Кортеж: (сессия, расшифрованный plaintext первого сообщения)
    ///
    /// # Пример
    ///
    /// ```rust,ignore
    /// // Extract Alice's ephemeral key from first message
    /// let alice_ephemeral = P::kem_public_key_from_bytes(
    ///     first_message.dh_public_key.to_vec()
    /// );
    ///
    /// let (session, plaintext) = Session::init_as_responder(
    ///     &bob_identity_private,
    ///     &bob_signed_prekey_private,
    ///     &alice_identity_public,
    ///     &alice_ephemeral,
    ///     &first_encrypted_message,
    ///     "alice".to_string(),
    /// )?;
    ///
    /// // Plaintext уже расшифрован! НЕ вызывайте decrypt() снова.
    /// println!("First message: {}", String::from_utf8_lossy(&plaintext));
    /// ```
    pub fn init_as_responder(
        local_identity: &P::KemPrivateKey,
        local_signed_prekey: &P::KemPrivateKey,
        remote_identity: &P::KemPublicKey,
        remote_ephemeral: &P::KemPublicKey,
        first_message: &M::EncryptedMessage,
        contact_id: String,
        local_user_id: String,
        local_one_time_prekey: Option<&P::KemPrivateKey>,
    ) -> Result<(Self, Vec<u8>), String> {
        use tracing::info;

        info!(
            target: "crypto::session",
            contact_id = %contact_id,
            has_otpk = local_one_time_prekey.is_some(),
            "Initializing session as responder (Bob)"
        );

        // 1. Perform handshake (X3DH) as responder
        let root_key = H::perform_as_responder(
            local_identity,
            local_signed_prekey,
            remote_identity,
            remote_ephemeral,
            local_one_time_prekey,
        )?;

        info!(
            target: "crypto::session",
            "Handshake completed, creating messaging session"
        );

        // 2. Create messaging session (Double Ratchet) from first message
        // Convert root_key to &[u8] - X3DH returns Vec<u8>
        // ⚠️ ВАЖНО: new_responder_session теперь возвращает (session, plaintext)
        let (messaging_session, plaintext) = M::new_responder_session(
            root_key.as_ref(),
            local_identity,
            first_message,
            contact_id.clone(),
            local_user_id,
        )?;

        info!(
            target: "crypto::session",
            session_id = %messaging_session.session_id(),
            plaintext_len = %plaintext.len(),
            "Session initialized and first message decrypted successfully"
        );

        let session = Self {
            contact_id,
            messaging_session,
            _phantom: PhantomData,
        };

        Ok((session, plaintext))
    }

    /// Зашифровать сообщение
    ///
    /// # Параметры
    ///
    /// - `plaintext`: Данные для шифрования
    ///
    /// # Возвращает
    ///
    /// Зашифрованное сообщение для отправки
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<M::EncryptedMessage, String> {
        self.messaging_session.encrypt(plaintext)
    }

    /// Расшифровать сообщение
    ///
    /// # Параметры
    ///
    /// - `message`: Зашифрованное сообщение
    ///
    /// # Возвращает
    ///
    /// Расшифрованный plaintext
    pub fn decrypt(&mut self, message: &M::EncryptedMessage) -> Result<Vec<u8>, String> {
        self.messaging_session.decrypt(message)
    }

    /// Получить session ID
    pub fn session_id(&self) -> &str {
        self.messaging_session.session_id()
    }

    /// Получить contact ID
    pub fn contact_id(&self) -> &str {
        &self.contact_id
    }

    /// Cleanup старых skipped message keys
    pub fn cleanup_old_skipped_keys(&mut self, max_age_seconds: i64) {
        self.messaging_session
            .cleanup_old_skipped_keys(max_age_seconds);
    }

    /// Получить изменяемую ссылку на messaging session
    ///
    /// Для advanced использования
    pub fn messaging_session_mut(&mut self) -> &mut M {
        &mut self.messaging_session
    }

    /// Получить неизменяемую ссылку на messaging session
    ///
    /// Для advanced использования
    pub fn messaging_session(&self) -> &M {
        &self.messaging_session
    }

    /// Создать сессию из существующей messaging session
    ///
    /// Используется для импорта сессий из persistent storage.
    ///
    /// # Параметры
    /// - `contact_id`: ID контакта
    /// - `messaging_session`: Восстановленная messaging session
    ///
    /// # Возвращает
    /// Новую Session instance
    pub fn from_messaging_session(contact_id: String, messaging_session: M) -> Self {
        Self {
            contact_id,
            messaging_session,
            _phantom: PhantomData,
        }
    }
}

/// Convenience type alias для X3DH + Double Ratchet с Classic Suite
pub type ClassicSession<P> = Session<
    P,
    crate::crypto::handshake::x3dh::X3DHProtocol<P>,
    crate::crypto::messaging::double_ratchet::DoubleRatchetSession<P>,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::handshake::x3dh::{X3DHProtocol, X3DHPublicKeyBundle};
    use crate::crypto::keys::build_prologue;
    use crate::crypto::messaging::double_ratchet::DoubleRatchetSession;
    use crate::crypto::suites::classic::ClassicSuiteProvider;
    use crate::crypto::SuiteID;

    type TestSession = Session<
        ClassicSuiteProvider,
        X3DHProtocol<ClassicSuiteProvider>,
        DoubleRatchetSession<ClassicSuiteProvider>,
    >;

    #[test]
    fn test_session_init_as_initiator() {
        // Setup: Alice and Bob identity keys
        let (alice_identity_priv, _alice_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (_bob_identity_priv, bob_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();

        // Bob's registration bundle
        let (_bob_signed_prekey_priv, bob_signed_prekey_pub) =
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

        // Alice initializes session
        let mut session = TestSession::init_as_initiator(
            &alice_identity_priv,
            &bob_bundle,
            &bob_identity_pub,
            "bob".to_string(),
            "alice".to_string(),
        )
        .unwrap();

        assert_eq!(session.contact_id(), "bob");

        // Alice encrypts a message
        let encrypted = session.encrypt(b"Hello Bob!").unwrap();
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn test_session_full_alice_bob_exchange() {
        // Setup: Alice and Bob both have identity keys
        let (alice_identity_priv, alice_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (bob_identity_priv, bob_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();

        // Bob's registration bundle
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

        // Alice initializes session as initiator
        let mut alice_session = TestSession::init_as_initiator(
            &alice_identity_priv,
            &bob_bundle,
            &bob_identity_pub,
            "bob".to_string(),
            "alice".to_string(),
        )
        .unwrap();

        // Alice encrypts first message
        let plaintext1 = b"Hello Bob! This is Alice.";
        let encrypted1 = alice_session.encrypt(plaintext1).unwrap();

        // Bob extracts Alice's ephemeral public key from first message
        let alice_ephemeral_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(encrypted1.dh_public_key.to_vec());

        // Bob initializes session as responder
        // ⚠️ ВАЖНО: init_as_responder теперь возвращает (session, plaintext первого сообщения)
        let (mut bob_session, decrypted1) = TestSession::init_as_responder(
            &bob_identity_priv,
            &bob_signed_prekey_priv,
            &alice_identity_pub,
            &alice_ephemeral_pub,
            &encrypted1,
            "alice".to_string(),
            "bob".to_string(),
            None,
        )
        .unwrap();

        // Verify first message was decrypted correctly
        assert_eq!(decrypted1, plaintext1);

        // Bob sends a reply
        let plaintext2 = b"Hi Alice! This is Bob.";
        let encrypted2 = bob_session.encrypt(plaintext2).unwrap();

        // Alice decrypts Bob's reply
        let decrypted2 = alice_session.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted2, plaintext2);

        // Continue conversation: Alice replies again
        let plaintext3 = b"How are you, Bob?";
        let encrypted3 = alice_session.encrypt(plaintext3).unwrap();

        // Bob decrypts
        let decrypted3 = bob_session.decrypt(&encrypted3).unwrap();
        assert_eq!(decrypted3, plaintext3);

        // Verify session IDs are set
        assert!(!alice_session.session_id().is_empty());
        assert!(!bob_session.session_id().is_empty());
        assert_eq!(alice_session.contact_id(), "bob");
        assert_eq!(bob_session.contact_id(), "alice");
    }

    #[test]
    fn test_session_cleanup_skipped_keys() {
        let (alice_identity_priv, _alice_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (_bob_identity_priv, bob_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();

        let (_bob_signed_prekey_priv, bob_signed_prekey_pub) =
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

        let mut session = TestSession::init_as_initiator(
            &alice_identity_priv,
            &bob_bundle,
            &bob_identity_pub,
            "bob".to_string(),
            "alice".to_string(),
        )
        .unwrap();

        // Test cleanup method exists and doesn't panic
        session.cleanup_old_skipped_keys(7 * 24 * 60 * 60); // 7 days
    }
}
