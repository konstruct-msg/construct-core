//! Secure Messaging Protocols
//!
//! Этот модуль содержит протоколы защищённого обмена сообщениями.
//!
//! Цель: Обеспечить конфиденциальность, аутентичность и forward secrecy
//! при обмене сообщениями между двумя сторонами.
//!
//! ## Протоколы
//! - **Double Ratchet**: Основной протокол Signal
//!
//! ## Dataflow
//! ```text
//! После успешного KeyAgreement:
//!
//! Alice (инициатор)                          Bob (получатель)
//! ==================                         =================
//!
//! 1. Создаёт session:
//!    SecureMessaging::new_initiator_session(
//!      root_key,           ← от KeyAgreement
//!      initiator_state,    ← содержит ephemeral_private
//!      bob_identity_pub
//!    )
//!
//! 2. Шифрует первое сообщение:
//!    encrypted_msg = session.encrypt(plaintext)
//!    → encrypted_msg.dh_public_key = ephemeral_public
//!
//! 3. Отправляет encrypted_msg → Server → Bob
//!
//!                                            1. Создаёт session из первого сообщения:
//!                                               SecureMessaging::new_responder_session(
//!                                                 root_key,        ← от KeyAgreement
//!                                                 bob_identity,
//!                                                 encrypted_msg    ← содержит Alice's ephemeral_public
//!                                               )
//!
//!                                            2. Расшифровывает:
//!                                               plaintext = session.decrypt(encrypted_msg)
//!
//! 4. Bidirectional обмен с DH ratcheting:
//!    Alice → Bob: msg2
//!    Bob → Alice: msg3 (DH ratchet step!)
//!    Alice → Bob: msg4 (DH ratchet step!)
//!    ...
//! ```
//!
//! ## Security Properties
//!
//! ### Forward Secrecy
//! Компрометация текущих ключей НЕ раскрывает прошлые сообщения.
//! Достигается через постоянное ratcheting ключей.
//!
//! ### Break-in Recovery (Backward Secrecy)
//! После компрометации, новый DH ratchet step восстанавливает безопасность.
//! Атакующий НЕ может расшифровать будущие сообщения.
//!
//! ### Out-of-Order Messages
//! Сообщения могут быть получены в произвольном порядке и всё равно расшифруются.
//! Достигается через skipped message keys.

use crate::crypto::handshake::InitiatorState;
use crate::crypto::provider::CryptoProvider;
use serde::{Deserialize, Serialize};

/// Протокол защищённого обмена сообщениями
///
/// Этот trait абстрагирует процесс шифрования и расшифровки сообщений
/// с forward secrecy, break-in recovery и поддержкой out-of-order доставки.
///
/// ## Ответственность
/// - Шифрование и расшифровка сообщений
/// - DH ratcheting для forward secrecy
/// - Symmetric key ratcheting (chain keys)
/// - Управление skipped message keys для out-of-order сообщений
///
/// ## Не отвечает за:
/// - Key agreement / handshake (это делает KeyAgreement)
/// - Управление множественными сессиями (это делает Client)
/// - Отправку/получение через сеть (это делает transport layer)
///
/// ## Типовые реализации
/// - Double Ratchet: Протокол Signal
pub trait SecureMessaging<P: CryptoProvider>: Sized {
    /// Зашифрованное сообщение в wire format
    ///
    /// Содержит всё необходимое для расшифровки получателем:
    /// - DH public key (для ratcheting)
    /// - Message number (для key derivation и порядка)
    /// - Ciphertext (зашифрованный plaintext)
    /// - Nonce (для AEAD)
    type EncryptedMessage: Clone + Serialize + for<'de> Deserialize<'de>;

    /// Создать сессию как инициатор (Alice)
    ///
    /// Alice вызывает это ПОСЛЕ успешного KeyAgreement.
    ///
    /// # Процесс
    /// 1. Alice получила root_key от KeyAgreement::perform_as_initiator()
    /// 2. Alice получила initiator_state с ephemeral_private
    /// 3. **ВАЖНО**: ephemeral_private становится первым DH ratchet key!
    /// 4. Alice выполняет DH ratchet: DH(ephemeral_private, bob_identity_public)
    /// 5. Alice создаёт sending chain key из root_key
    ///
    /// # Параметры
    /// - `root_key`: Shared secret от KeyAgreement (32 bytes)
    /// - `initiator_state`: Содержит ephemeral_private (первый DH key)
    /// - `remote_identity`: Bob's identity public key
    /// - `contact_id`: Идентификатор контакта (для логирования)
    ///
    /// # Возвращает
    /// Готовую сессию для шифрования сообщений
    ///
    /// # Ошибки
    /// - Invalid root_key length
    /// - DH operation failure
    ///
    /// # ⚠️ КРИТИЧЕСКИ ВАЖНО
    /// Ephemeral key НЕ генерируется заново! Он приходит от KeyAgreement.
    /// Это гарантирует, что Bob сможет извлечь ephemeral_public из первого
    /// сообщения и выполнить KeyAgreement::perform_as_responder().
    fn new_initiator_session(
        root_key: &[u8],
        initiator_state: InitiatorState<P>,
        remote_identity: &P::KemPublicKey,
        contact_id: String,
        local_user_id: String,
    ) -> Result<Self, String>;

    /// Создать сессию как получатель (Bob)
    ///
    /// Bob вызывает это при получении первого сообщения от Alice.
    ///
    /// # Процесс
    /// 1. Bob получил root_key от KeyAgreement::perform_as_responder()
    /// 2. Bob получил первое зашифрованное сообщение от Alice
    /// 3. Bob извлекает Alice's ephemeral_public из first_message.dh_public_key
    /// 4. Bob создаёт receiving session и **расшифровывает первое сообщение**
    ///
    /// # Параметры
    /// - `root_key`: Shared secret от KeyAgreement (32 bytes)
    /// - `local_identity`: Bob's identity private key
    /// - `first_message`: Первое зашифрованное сообщение от Alice
    /// - `contact_id`: Идентификатор контакта
    ///
    /// # Возвращает
    /// Кортеж: (сессия, расшифрованный plaintext первого сообщения)
    ///
    /// # Ошибки
    /// - Invalid root_key
    /// - Invalid first_message format
    /// - Missing dh_public_key in first_message
    /// - Decryption failure
    ///
    /// # ⚠️ КРИТИЧЕСКИ ВАЖНО
    /// Первое сообщение расшифровывается ВНУТРИ этого метода!
    /// Caller НЕ должен вызывать decrypt() для первого сообщения.
    fn new_responder_session(
        root_key: &[u8],
        local_identity: &P::KemPrivateKey,
        first_message: &Self::EncryptedMessage,
        contact_id: String,
        local_user_id: String,
    ) -> Result<(Self, Vec<u8>), String>;

    /// Зашифровать сообщение
    ///
    /// # Процесс
    /// 1. Increment message number
    /// 2. Derive message key: (chain_key', msg_key) = KDF_CK(chain_key)
    /// 3. Encrypt: ciphertext = AEAD(msg_key, nonce, plaintext)
    /// 4. Return EncryptedMessage with current DH public key
    ///
    /// # Параметры
    /// - `plaintext`: Данные для шифрования
    ///
    /// # Возвращает
    /// EncryptedMessage для отправки получателю
    ///
    /// # Ошибки
    /// - Encryption failure
    /// - Key derivation failure
    ///
    /// # Side Effects
    /// - Обновляет sending_chain_key
    /// - Увеличивает sending_chain_length
    /// - Может выполнить DH ratchet step
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Self::EncryptedMessage, String>;

    /// Расшифровать сообщение
    ///
    /// # Процесс
    /// 1. Проверяет DH public key - если изменился, выполняет DH ratchet
    /// 2. Проверяет message number - если пропущены сообщения, сохраняет skipped keys
    /// 3. Derive message key: (chain_key', msg_key) = KDF_CK(chain_key)
    /// 4. Decrypt: plaintext = AEAD_decrypt(msg_key, nonce, ciphertext)
    ///
    /// # Параметры
    /// - `message`: Зашифрованное сообщение
    ///
    /// # Возвращает
    /// Расшифрованный plaintext
    ///
    /// # Ошибки
    /// - Invalid DH public key
    /// - Message number too far in future (DoS protection)
    /// - Decryption failure (wrong key, tampered ciphertext)
    /// - Replay attack (message number уже обработан)
    ///
    /// # Side Effects
    /// - Обновляет receiving_chain_key
    /// - Увеличивает receiving_chain_length
    /// - Может сохранить skipped message keys
    /// - Может выполнить DH ratchet step
    fn decrypt(&mut self, message: &Self::EncryptedMessage) -> Result<Vec<u8>, String>;

    /// Получить session ID
    fn session_id(&self) -> &str;

    /// Получить contact ID
    fn contact_id(&self) -> &str;

    /// Cleanup старых skipped message keys
    ///
    /// Удаляет ключи старше указанного возраста для защиты от DoS.
    ///
    /// # Параметры
    /// - `max_age_seconds`: Максимальный возраст ключа в секундах
    fn cleanup_old_skipped_keys(&mut self, max_age_seconds: i64);

    /// Return a read-only health snapshot of this session's ratchet state.
    fn health_snapshot(&self) -> crate::crypto::messaging::double_ratchet::DrHealthSnapshot;

    /// Mix a post-quantum KEM shared secret into the session root key (PQXDH).
    ///
    /// Default implementation is a no-op for non-PQ session types.
    /// `DoubleRatchetSession` overrides this to do the actual HKDF mixing.
    fn apply_pq_contribution(&mut self, _kem_shared_secret: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

// Re-exports
pub mod double_ratchet;

// Backward compatibility
pub use double_ratchet::{DoubleRatchetSession, EncryptedRatchetMessage, SerializableSession};
