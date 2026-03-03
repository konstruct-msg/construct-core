//! Key Agreement Protocols
//!
//! Этот модуль содержит протоколы установки ключей (key agreement).
//!
//! Цель: Установить общий секретный ключ между двумя сторонами без предварительного
//! обмена секретами.
//!
//! ## Протоколы
//! - **X3DH**: Extended Triple Diffie-Hellman (Signal Protocol)
//! - **PQ-X3DH**: Post-Quantum X3DH (будущее)
//!
//! ## Dataflow
//! ```text
//! Alice (инициатор)                          Bob (получатель)
//! ==================                         =================
//!
//! 1. Генерирует ephemeral key
//! 2. Получает Bob's bundle от сервера
//! 3. Выполняет KeyAgreement::perform_as_initiator()
//!    → возвращает (shared_secret, InitiatorState)
//! 4. InitiatorState содержит ephemeral_private
//!    (который станет первым DH ratchet key)
//!
//!                                            1. Получает первое сообщение от Alice
//!                                            2. Извлекает Alice's ephemeral_public
//!                                            3. Выполняет KeyAgreement::perform_as_responder()
//!                                               → возвращает shared_secret (тот же!)
//! ```

use crate::crypto::provider::CryptoProvider;
use serde::{Deserialize, Serialize};

/// Состояние инициатора после key agreement
///
/// Содержит ephemeral private key, который будет использован
/// как первый DH ratchet key в Double Ratchet протоколе.
///
/// ⚠️ КРИТИЧЕСКИ ВАЖНО: Ephemeral key НЕ генерируется заново в Double Ratchet!
/// Он используется дважды:
/// 1. В X3DH для DH2 и DH3
/// 2. Как первый DH key в Double Ratchet
#[derive(Debug, Clone)]
pub struct InitiatorState<P: CryptoProvider> {
    /// Ephemeral private key, сгенерированный в perform_as_initiator()
    pub ephemeral_private: P::KemPrivateKey,
}

/// Протокол установки ключей (Key Agreement)
///
/// Этот trait абстрагирует процесс установки общего секретного ключа
/// между двумя сторонами (Alice и Bob).
///
/// ## Ответственность
/// - Генерация регистрационных данных для сервера
/// - Установка общего секретного ключа (root key) через криптографический handshake
/// - Проверка подлинности ключей через подписи
///
/// ## Не отвечает за:
/// - Шифрование сообщений (это делает SecureMessaging)
/// - Управление сессиями (это делает Session и Client)
/// - Хранение ключей (это делает KeyManager)
///
/// ## Типовые реализации
/// - X3DH: Extended Triple Diffie-Hellman (Signal Protocol)
/// - PQ-X3DH: Post-Quantum X3DH (hybrid classical + PQ)
pub trait KeyAgreement<P: CryptoProvider> {
    /// Регистрационные данные для отправки на сервер
    ///
    /// Содержит долгосрочные публичные ключи пользователя:
    /// - Identity Public Key
    /// - Signed Prekey Public Key
    /// - Signature над Signed Prekey
    /// - Verifying Key (для проверки подписи)
    type RegistrationBundle: Clone + Serialize + for<'de> Deserialize<'de>;

    /// Публичные ключи для обмена при инициации сессии
    ///
    /// Подмножество RegistrationBundle, необходимое для выполнения handshake
    type PublicKeyBundle: Clone + Serialize + for<'de> Deserialize<'de>;

    /// Общий секретный ключ (shared secret / root key)
    ///
    /// Результат успешного handshake. Используется как root key
    /// для Double Ratchet протокола.
    type SharedSecret;

    /// Генерировать регистрационный bundle
    ///
    /// Создаёт новые долгосрочные ключи:
    /// - Identity Key (IK)
    /// - Signed Prekey (SPK)
    /// - Signing Key (для подписи SPK)
    ///
    /// # Возвращает
    /// RegistrationBundle для отправки на сервер
    ///
    /// # Ошибки
    /// - Ошибки генерации ключей
    /// - Ошибки создания подписи
    fn generate_registration_bundle() -> Result<Self::RegistrationBundle, String>;

    /// Выполнить handshake как инициатор (Alice)
    ///
    /// Alice инициирует установку сессии с Bob.
    ///
    /// # Процесс
    /// 1. Alice генерирует **ephemeral key pair** (EK_A)
    /// 2. Alice получает Bob's public bundle от сервера
    /// 3. Alice проверяет подпись Bob's signed prekey
    /// 4. Alice выполняет криптографический handshake (напр. X3DH)
    /// 5. Alice получает shared secret (root key)
    ///
    /// # Параметры
    /// - `local_identity`: Alice's identity private key (IK_A)
    /// - `remote_bundle`: Bob's public keys от сервера
    ///
    /// # Возвращает
    /// - `SharedSecret`: Общий секретный ключ (root key) для Double Ratchet
    /// - `InitiatorState`: Содержит ephemeral_private для Double Ratchet
    ///
    /// # Ошибки
    /// - Signature verification failed
    /// - Invalid public key format
    /// - Handshake failure
    fn perform_as_initiator(
        local_identity: &P::KemPrivateKey,
        remote_bundle: &Self::PublicKeyBundle,
    ) -> Result<(Self::SharedSecret, InitiatorState<P>), String>;

    /// Выполнить handshake как получатель (Bob)
    ///
    /// Bob получает первое сообщение от Alice и устанавливает сессию.
    ///
    /// # Процесс
    /// 1. Bob получает Alice's первое сообщение
    /// 2. Bob извлекает Alice's ephemeral public key (EK_A_pub) из сообщения
    /// 3. Bob получает Alice's identity public key (IK_A_pub) от сервера
    /// 4. Bob выполняет криптографический handshake с полученными ключами
    /// 5. Bob получает shared secret (root key) - **тот же что у Alice!**
    ///
    /// # Параметры
    /// - `local_identity`: Bob's identity private key (IK_B)
    /// - `local_signed_prekey`: Bob's signed prekey private key (SPK_B)
    /// - `remote_identity`: Alice's identity public key (IK_A_pub)
    /// - `remote_ephemeral`: Alice's ephemeral public key (EK_A_pub, из первого сообщения)
    ///
    /// # Возвращает
    /// - `SharedSecret`: Общий секретный ключ (root key), **ИДЕНТИЧНЫЙ** тому что у Alice
    ///
    /// # Ошибки
    /// - Invalid ephemeral key
    /// - Handshake failure
    ///
    /// # Математика
    /// ```text
    /// Alice computes:
    ///   DH1 = DH(IK_A, SPK_B)
    ///   DH2 = DH(EK_A, IK_B)
    ///   DH3 = DH(EK_A, SPK_B)
    ///
    /// Bob computes:
    ///   DH1 = DH(SPK_B, IK_A)  // REVERSE, но результат тот же
    ///   DH2 = DH(IK_B, EK_A)   // REVERSE, но результат тот же
    ///   DH3 = DH(SPK_B, EK_A)  // REVERSE, но результат тот же
    ///
    /// DH(a, B) = DH(b, A) → Alice и Bob получают одинаковые shared secrets
    /// ```
    fn perform_as_responder(
        local_identity: &P::KemPrivateKey,
        local_signed_prekey: &P::KemPrivateKey,
        remote_identity: &P::KemPublicKey,
        remote_ephemeral: &P::KemPublicKey,
        local_one_time_prekey: Option<&P::KemPrivateKey>,
    ) -> Result<Self::SharedSecret, String>;
}

// Re-exports
pub mod x3dh;

// Backward compatibility
pub use x3dh::{X3DHProtocol, X3DHPublicKeyBundle, X3DHRegistrationBundle};
