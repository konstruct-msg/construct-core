//! Client API - High-level interface for cryptographic client
//!
//! Объединяет управление ключами + множественными сессиями в единый API.
//!
//! ## Архитектура
//!
//! ```text
//! Client
//!   ├── KeyManager         - долгосрочные ключи (identity, signed_prekey, signing)
//!   └── SessionManager     - множественные сессии с контактами
//!         └── Session      - X3DH + Double Ratchet
//! ```
//!
//! ## Типичный сценарий использования
//!
//! ### Регистрация
//! ```text
//! 1. client = Client::new()
//! 2. bundle = client.get_registration_bundle()
//! 3. Send bundle → Server
//! ```
//!
//! ### Инициация разговора (Alice)
//! ```text
//! 1. alice = Client::new()
//! 2. bob_bundle = alice.fetch_from_server("bob")
//! 3. alice.init_session("bob", bob_bundle)
//! 4. encrypted = alice.encrypt_message("bob", "Hello!")
//! 5. Send encrypted → Server → Bob
//! ```
//!
//! ### Получение сообщения (Bob)
//! ```text
//! 1. bob = Client::new()
//! 2. bob.init_receiving_session("alice", alice_identity, first_message)
//! 3. plaintext = bob.decrypt_message("alice", first_message)
//! ```
//!
//! ## Ответственность
//!
//! - Управление долгосрочными ключами
//! - Управление множественными сессиями
//! - Упрощённый API для приложения
//! - Rotation ключей
//!
//! ## Не отвечает за
//!
//! - Сетевой транспорт (это делает transport layer)
//! - Persistence ключей и сессий (это делает storage layer)
//! - UI/UX логика

use crate::crypto::handshake::{KeyAgreement, X3DHProtocol};
use crate::crypto::keys::KeyManager;
use crate::crypto::messaging::{double_ratchet::DoubleRatchetSession, SecureMessaging};
use crate::crypto::provider::CryptoProvider;
use crate::crypto::session_api::Session;
use std::collections::HashMap;
use std::marker::PhantomData;

/// High-level Client для работы с криптографией
///
/// Объединяет KeyManager (долгосрочные ключи) + SessionManager (множественные сессии).
///
/// ## Generics
///
/// - `P`: CryptoProvider - криптографический suite (Classic, Hybrid)
/// - `H`: KeyAgreement - handshake protocol (X3DH, PQ-X3DH)
/// - `M`: SecureMessaging - messaging protocol (Double Ratchet)
pub struct Client<P: CryptoProvider, H: KeyAgreement<P>, M: SecureMessaging<P>> {
    /// Управление долгосрочными ключами
    key_manager: KeyManager<P>,

    /// Активные сессии с контактами
    sessions: HashMap<String, Session<P, H, M>>,

    /// Pending one-time prekey IDs for outbound sessions:
    /// stored at init_session time, consumed on first encrypt (message_number==0)
    pending_otpk_ids: HashMap<String, u32>,

    /// Идентификатор локального пользователя (UUID от сервера)
    local_user_id: String,

    /// PhantomData для generic types
    _phantom: PhantomData<(P, H, M)>,
}

impl<P: CryptoProvider, H: KeyAgreement<P>, M: SecureMessaging<P>> Client<P, H, M>
where
    H::SharedSecret: AsRef<[u8]>,
{
    /// Создать нового клиента с новыми ключами
    ///
    /// Генерирует долгосрочные ключи:
    /// - Identity Key
    /// - Signed Prekey
    /// - Signing Key
    ///
    /// # Пример
    ///
    /// ```rust,ignore
    /// use construct_core::crypto::client_api::Client;
    /// use construct_core::crypto::handshake::x3dh::X3DHProtocol;
    /// use construct_core::crypto::messaging::double_ratchet::DoubleRatchetSession;
    /// use construct_core::crypto::suites::classic::ClassicSuiteProvider;
    ///
    /// type MyClient = Client<
    ///     ClassicSuiteProvider,
    ///     X3DHProtocol<ClassicSuiteProvider>,
    ///     DoubleRatchetSession<ClassicSuiteProvider>
    /// >;
    ///
    /// let client = MyClient::new()?;
    /// ```
    pub fn new() -> Result<Self, String> {
        let mut key_manager = KeyManager::<P>::new();
        key_manager
            .initialize()
            .map_err(|e| format!("Failed to initialize key manager: {:?}", e))?;

        Ok(Self {
            key_manager,
            sessions: HashMap::new(),
            pending_otpk_ids: HashMap::new(),
            local_user_id: String::new(),
            _phantom: PhantomData,
        })
    }

    /// Создать Client с существующими ключами (для восстановления из storage)
    pub fn from_keys(
        identity_secret: Vec<u8>,
        signing_secret: Vec<u8>,
        prekey_secret: Vec<u8>,
        prekey_signature: Vec<u8>,
    ) -> Result<Self, String> {
        let mut key_manager = KeyManager::<P>::new();
        key_manager
            .initialize_from_keys(
                identity_secret,
                signing_secret,
                prekey_secret,
                prekey_signature,
            )
            .map_err(|e| format!("Failed to initialize key manager from keys: {:?}", e))?;

        Ok(Self {
            key_manager,
            sessions: HashMap::new(),
            pending_otpk_ids: HashMap::new(),
            local_user_id: String::new(),
            _phantom: PhantomData,
        })
    }

    /// Получить registration bundle для отправки на сервер (device-based регистрация)
    ///
    /// Возвращает публичные ключи клиента для регистрации:
    /// - Identity Public Key
    /// - Signed Prekey Public Key
    /// - Signature над Signed Prekey
    /// - Verifying Key
    ///
    /// **ВАЖНО для device-based модели:**
    /// - Bundle используется для безопасного обмена ключами между устройствами
    /// - Содержит ТОЛЬКО публичные данные из существующих ключей
    /// - Приватные ключи никогда не покидают устройство
    ///
    /// # Пример
    ///
    /// ```rust,ignore
    /// let bundle = client.get_registration_bundle()?;
    /// send_to_server(bundle); // Для регистрации устройства
    /// ```
    ///
    /// # ✅ ИСПРАВЛЕНО: Теперь использует существующие ключи
    ///
    /// Метод теперь корректно экспортирует ключи из self.key_manager
    /// вместо генерации новых, что было критической уязвимостью.
    pub fn get_registration_bundle(&self) -> Result<H::RegistrationBundle, String> {
        // Экспортируем существующие публичные ключи из key_manager
        let public_bundle = self
            .key_manager
            .export_device_registration_bundle()
            .map_err(|e| format!("Failed to export registration bundle: {:?}", e))?;

        // Преобразуем через сериализацию/десериализацию (безопасно и generic)
        let json = serde_json::to_string(&public_bundle)
            .map_err(|e| format!("Failed to serialize bundle: {}", e))?;
        let registration_bundle: H::RegistrationBundle = serde_json::from_str(&json)
            .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;

        Ok(registration_bundle)
    }

    /// Инициировать сессию с контактом (Alice)
    ///
    /// Alice вызывает этот метод для начала разговора с Bob.
    ///
    /// # Процесс
    ///
    /// 1. Проверяет что сессии ещё нет
    /// 2. Получает свой identity public key
    /// 3. Создаёт Session::init_as_initiator()
    /// 4. Сохраняет сессию в sessions map
    ///
    /// # Параметры
    ///
    /// - `contact_id`: Идентификатор контакта (Bob)
    /// - `remote_bundle`: Bob's public key bundle (от сервера)
    /// - `remote_identity`: Bob's identity public key (от сервера)
    ///
    /// # Возвращает
    ///
    /// Session ID созданной сессии
    ///
    /// # Ошибки
    ///
    /// - "Session already exists" - сессия уже создана
    /// - Ошибки X3DH handshake
    /// - Ошибки Double Ratchet
    pub fn init_session(
        &mut self,
        contact_id: &str,
        remote_bundle: &H::PublicKeyBundle,
        remote_identity: &P::KemPublicKey,
        one_time_prekey_id: u32,
    ) -> Result<String, String> {
        use tracing::info;

        // Check if session already exists
        if self.sessions.contains_key(contact_id) {
            return Err(format!(
                "Session already exists with contact: {}",
                contact_id
            ));
        }

        info!(
            target: "crypto::client",
            contact_id = %contact_id,
            "Initializing session as initiator"
        );

        // Get our identity private key
        let local_identity_priv = self
            .key_manager
            .identity_secret_key()
            .map_err(|e| format!("Failed to get identity key: {:?}", e))?;

        // Create session
        let session = Session::<P, H, M>::init_as_initiator(
            local_identity_priv,
            remote_bundle,
            remote_identity,
            contact_id.to_string(),
            self.local_user_id.clone(),
        )?;

        let session_id = session.session_id().to_string();

        // Store session
        self.sessions.insert(contact_id.to_string(), session);

        // Store pending OTPK id for first encrypt (burn-on-use after message_number==0 send)
        if one_time_prekey_id != 0 {
            self.pending_otpk_ids
                .insert(contact_id.to_string(), one_time_prekey_id);
        }

        info!(
            target: "crypto::client",
            contact_id = %contact_id,
            session_id = %session_id,
            "Session initialized successfully"
        );

        Ok(session_id)
    }

    /// Инициировать receiving сессию (Bob)
    ///
    /// Bob вызывает этот метод при получении первого сообщения от Alice.
    ///
    /// # Процесс
    ///
    /// 1. Проверяет что сессии ещё нет
    /// 2. Извлекает Alice's ephemeral key из сообщения
    /// 3. Создаёт Session::init_as_responder()
    /// 4. Сохраняет сессию
    ///
    /// # Параметры (device-based модель)
    ///
    /// - `contact_id`: Идентификатор контакта/устройства (Alice)
    /// - `initiator_bundle`: Регистрационный bundle инициатора для верификации подписи
    /// - `first_message`: Первое зашифрованное сообщение от Alice
    ///
    /// # Возвращает
    ///
    /// Кортеж: (session_id, расшифрованное первое сообщение)
    ///
    /// # Безопасность (device-based)
    ///
    /// ✅ **ИСПРАВЛЕНО**: Теперь верифицирует:
    /// - Подпись signed prekey инициатора
    /// - Соответствие identity key из bundle
    /// - Device ID для device-based модели
    ///
    /// # Пример
    ///
    /// ```rust,ignore
    /// // Bob получает первое сообщение от Alice
    /// let (session_id, plaintext) = bob.init_receiving_session(
    ///     "alice",
    ///     &alice_bundle,  // Для верификации подписи
    ///     &first_message,
    /// )?;
    /// ```
    pub fn init_receiving_session(
        &mut self,
        contact_id: &str,
        initiator_bundle: &H::RegistrationBundle,
        first_message: &M::EncryptedMessage,
    ) -> Result<(String, Vec<u8>), String> {
        use tracing::info;

        // Check if session already exists
        if self.sessions.contains_key(contact_id) {
            return Err(format!(
                "Session already exists with contact: {}",
                contact_id
            ));
        }

        info!(
            target: "crypto::client",
            contact_id = %contact_id,
            "Initializing session as responder (device-based)"
        );

        // Извлекаем ephemeral key из первого сообщения
        // Преобразуем через сериализацию, чтобы получить доступ к dh_public_key
        let message_json = serde_json::to_string(first_message)
            .map_err(|e| format!("Failed to serialize message: {}", e))?;
        let ratchet_msg: crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage =
            serde_json::from_str(&message_json)
                .map_err(|e| format!("Failed to deserialize message: {}", e))?;

        let remote_ephemeral = P::kem_public_key_from_bytes(ratchet_msg.dh_public_key.to_vec());

        // Десериализуем bundle для получения данных
        let bundle_json = serde_json::to_string(initiator_bundle)
            .map_err(|e| format!("Failed to serialize bundle: {}", e))?;
        let bundle_data: crate::crypto::handshake::x3dh::X3DHRegistrationBundle =
            serde_json::from_str(&bundle_json)
                .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;

        // ✅ КРИТИЧЕСКАЯ ПРОВЕРКА 1: Верификация подписи signed prekey
        info!(
            target: "crypto::client",
            "Verifying signed prekey signature from initiator"
        );

        let verifying_key = P::signature_public_key_from_bytes(bundle_data.verifying_key.clone());

        // Собираем данные для верификации с prologue (как при создании)
        let prologue = crate::crypto::keys::build_prologue(bundle_data.suite_id);
        let mut message_to_verify =
            Vec::with_capacity(prologue.len() + bundle_data.signed_prekey_public.len());
        message_to_verify.extend_from_slice(&prologue);
        message_to_verify.extend_from_slice(&bundle_data.signed_prekey_public);

        P::verify(&verifying_key, &message_to_verify, &bundle_data.signature)
            .map_err(|_| "Invalid signed prekey signature from initiator".to_string())?;

        info!(
            target: "crypto::client",
            "Signature verification successful"
        );

        // ✅ КРИТИЧЕСКАЯ ПРОВЕРКА 2: Device ID (для device-based модели)
        // Вычисляем device_id из identity_public и проверяем соответствие contact_id
        let derived_device_id = crate::device_id::derive_device_id(&bundle_data.identity_public);

        // В device-based модели contact_id должен соответствовать device_id
        // Формат может быть: device_id@server или просто device_id
        let expected_device_id = if contact_id.contains('@') {
            contact_id.split('@').next().unwrap_or(contact_id)
        } else {
            contact_id
        };

        if derived_device_id != expected_device_id {
            return Err(format!(
                "Device ID mismatch: expected {}, got {}",
                expected_device_id, derived_device_id
            ));
        }

        info!(
            target: "crypto::client",
            device_id = %derived_device_id,
            "Device ID verification successful"
        );

        // Преобразуем identity key из bundle
        let remote_identity = P::kem_public_key_from_bytes(bundle_data.identity_public);

        // Вызываем рабочую версию с ephemeral key
        self.init_receiving_session_with_ephemeral(
            contact_id,
            &remote_identity,
            &remote_ephemeral,
            first_message,
            0, // OTPK consumed upstream when called via init_receiving_session (test path)
        )
    }

    /// Инициировать receiving сессию с явным ephemeral key (Bob)
    ///
    /// Версия init_receiving_session где caller сам извлекает ephemeral key.
    ///
    /// # Параметры
    ///
    /// - `contact_id`: Идентификатор контакта (Alice)
    /// - `remote_identity`: Alice's identity public key
    /// - `remote_ephemeral`: Alice's ephemeral public key (из first_message.dh_public_key)
    /// - `first_message`: Первое зашифрованное сообщение
    ///
    /// # Возвращает
    ///
    /// Кортеж: (session_id, расшифрованный plaintext первого сообщения)
    pub fn init_receiving_session_with_ephemeral(
        &mut self,
        contact_id: &str,
        remote_identity: &P::KemPublicKey,
        remote_ephemeral: &P::KemPublicKey,
        first_message: &M::EncryptedMessage,
        one_time_prekey_id: u32,
    ) -> Result<(String, Vec<u8>), String> {
        use tracing::{info, warn};

        // If a session already exists it was created by the INITIATOR path (we sent
        // first).  Remove it so we can establish the canonical RESPONDER session.
        if self.sessions.contains_key(contact_id) {
            warn!(
                target: "crypto::client",
                contact_id = %contact_id,
                "Removing existing session before RESPONDER init"
            );
            self.sessions.remove(contact_id);
        }

        info!(
            target: "crypto::client",
            contact_id = %contact_id,
            has_otpk = (one_time_prekey_id != 0),
            "Initializing session as responder (with ephemeral)"
        );

        // Consume the OTPK (burn-on-use) BEFORE borrowing identity key
        let consumed_otpk = if one_time_prekey_id != 0 {
            let key = self.key_manager.consume_one_time_prekey(one_time_prekey_id);
            if key.is_none() {
                warn!(
                    target: "crypto::client",
                    contact_id = %contact_id,
                    key_id = one_time_prekey_id,
                    "OTPK key_id not found locally — falling back to 3-DH"
                );
            }
            key
        } else {
            None
        };

        let local_identity = self
            .key_manager
            .identity_secret_key()
            .map_err(|e| format!("Failed to get identity key: {:?}", e))?;

        // Try current prekey first, then fall back to older prekeys (in case the
        // sender encrypted using a prekey that predates our last rotation).
        let candidate_prekeys = self.key_manager.all_prekey_private_keys();
        if candidate_prekeys.is_empty() {
            return Err("No signed prekeys available".to_string());
        }

        let mut last_err = String::from("No prekeys tried");
        for (idx, prekey) in candidate_prekeys.iter().enumerate() {
            match Session::<P, H, M>::init_as_responder(
                local_identity,
                prekey,
                remote_identity,
                remote_ephemeral,
                first_message,
                contact_id.to_string(),
                self.local_user_id.clone(),
                consumed_otpk.as_ref(),
            ) {
                Ok((session, plaintext)) => {
                    let session_id = session.session_id().to_string();
                    self.sessions.insert(contact_id.to_string(), session);

                    if idx > 0 {
                        info!(
                            target: "crypto::client",
                            contact_id = %contact_id,
                            prekey_index = idx,
                            "Receiving session initialized with old prekey (index {})",
                            idx
                        );
                    }

                    info!(
                        target: "crypto::client",
                        contact_id = %contact_id,
                        session_id = %session_id,
                        plaintext_len = %plaintext.len(),
                        "Receiving session initialized and first message decrypted"
                    );

                    return Ok((session_id, plaintext));
                }
                Err(e) => {
                    warn!(
                        target: "crypto::client",
                        contact_id = %contact_id,
                        prekey_index = idx,
                        error = %e,
                        "Prekey {} failed, trying next",
                        idx
                    );
                    last_err = e;
                }
            }
        }

        Err(format!(
            "All {} prekey(s) failed. Last error: {}",
            candidate_prekeys.len(),
            last_err
        ))
    }

    /// Зашифровать сообщение для контакта
    ///
    /// # Параметры
    ///
    /// - `contact_id`: Идентификатор получателя
    /// - `plaintext`: Данные для шифрования
    ///
    /// # Возвращает
    ///
    /// Зашифрованное сообщение для отправки
    ///
    /// # Ошибки
    ///
    /// - "No session with contact" - сессия не найдена
    /// - Ошибки шифрования
    pub fn encrypt_message(
        &mut self,
        contact_id: &str,
        plaintext: &[u8],
    ) -> Result<M::EncryptedMessage, String> {
        let session = self.sessions.get_mut(contact_id).ok_or_else(|| {
            tracing::error!(
                target: "crypto::client",
                contact_id = %contact_id,
                "No session found for contact"
            );
            format!("No session with contact: {}", contact_id)
        })?;

        tracing::debug!(
            target: "crypto::client",
            contact_id = %contact_id,
            plaintext_len = plaintext.len(),
            "Encrypting message"
        );

        session.encrypt(plaintext)
    }

    /// Расшифровать сообщение от контакта
    ///
    /// # Параметры
    ///
    /// - `contact_id`: Идентификатор отправителя
    /// - `message`: Зашифрованное сообщение
    ///
    /// # Возвращает
    ///
    /// Расшифрованный plaintext
    ///
    /// # Ошибки
    ///
    /// - "No session with contact" - сессия не найдена
    /// - Ошибки расшифровки
    pub fn decrypt_message(
        &mut self,
        contact_id: &str,
        message: &M::EncryptedMessage,
    ) -> Result<Vec<u8>, String> {
        let session = self
            .sessions
            .get_mut(contact_id)
            .ok_or_else(|| format!("No session with contact: {}", contact_id))?;

        session.decrypt(message)
    }

    /// Проверить наличие сессии с контактом
    pub fn has_session(&self, contact_id: &str) -> bool {
        self.sessions.contains_key(contact_id)
    }

    /// Получить session ID для контакта
    pub fn get_session_id(&self, contact_id: &str) -> Option<String> {
        self.sessions
            .get(contact_id)
            .map(|s| s.session_id().to_string())
    }

    /// Удалить сессию с контактом
    pub fn remove_session(&mut self, contact_id: &str) -> bool {
        self.sessions.remove(contact_id).is_some()
    }

    /// Apply a post-quantum KEM shared secret to an existing session's root key.
    ///
    /// Call this immediately after `init_session` (sender) or `init_receiving_session`
    /// (receiver) to mix ML-KEM-768 entropy into the session root key, providing
    /// HNDL (Harvest Now Decrypt Later) protection.
    pub fn apply_pq_contribution_to_session(
        &mut self,
        contact_id: &str,
        kem_shared_secret: &[u8],
    ) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(contact_id)
            .ok_or_else(|| format!("Session not found: {}", contact_id))?;
        session
            .messaging_session_mut()
            .apply_pq_contribution(kem_shared_secret)
    }

    ///
    /// Используется для восстановления сессий из persistent storage (Keychain).
    ///
    /// # Параметры
    /// - `contact_id`: ID контакта
    /// - `messaging_session`: Восстановленная messaging session (Double Ratchet)
    ///
    /// # Возвращает
    /// Session ID восстановленной сессии
    pub fn import_session(&mut self, contact_id: &str, messaging_session: M) -> String {
        let session_id = messaging_session.session_id().to_string();

        let session = Session::from_messaging_session(contact_id.to_string(), messaging_session);

        self.sessions.insert(contact_id.to_string(), session);
        session_id
    }

    /// Получить количество активных сессий
    pub fn active_sessions_count(&self) -> usize {
        self.sessions.len()
    }

    /// Получить список контактов с активными сессиями
    pub fn active_contacts(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// Rotate signed prekey
    ///
    /// Генерирует новый signed prekey и подпись.
    /// Старый prekey остаётся валидным до следующей rotation.
    pub fn rotate_prekey(&mut self) -> Result<(), String> {
        self.key_manager
            .rotate_signed_prekey()
            .map_err(|e| format!("Failed to rotate prekey: {:?}", e))
    }

    /// Cleanup старых skipped message keys во всех сессиях
    pub fn cleanup_all_skipped_keys(&mut self, max_age_seconds: i64) {
        for session in self.sessions.values_mut() {
            session.cleanup_old_skipped_keys(max_age_seconds);
        }
    }

    /// Получить изменяемую ссылку на KeyManager
    ///
    /// Для advanced использования
    pub fn key_manager_mut(&mut self) -> &mut KeyManager<P> {
        &mut self.key_manager
    }

    /// Установить идентификатор локального пользователя (вызывается после регистрации/логина)
    pub fn set_local_user_id(&mut self, user_id: String) {
        self.local_user_id = user_id;
    }

    /// Получить идентификатор локального пользователя
    pub fn local_user_id(&self) -> &str {
        &self.local_user_id
    }

    /// Получить неизменяемую ссылку на KeyManager
    ///
    /// Для advanced использования
    pub fn key_manager(&self) -> &KeyManager<P> {
        &self.key_manager
    }

    /// Получить изменяемую ссылку на сессию
    ///
    /// Для advanced использования
    pub fn get_session_mut(&mut self, contact_id: &str) -> Option<&mut Session<P, H, M>> {
        self.sessions.get_mut(contact_id)
    }

    /// Получить неизменяемую ссылку на сессию
    ///
    /// Для advanced использования
    pub fn get_session(&self, contact_id: &str) -> Option<&Session<P, H, M>> {
        self.sessions.get(contact_id)
    }

    /// Pop the pending one-time prekey id for a contact (used by first encrypt, message_number==0).
    /// Returns 0 if no pending OTPK (fallback 3-DH mode).
    pub fn take_pending_otpk_id(&mut self, contact_id: &str) -> u32 {
        self.pending_otpk_ids.remove(contact_id).unwrap_or(0)
    }

    /// Generate new one-time prekeys and return (key_id, public_key_bytes) pairs for upload.
    pub fn generate_one_time_prekeys(&mut self, count: u32) -> Result<Vec<(u32, Vec<u8>)>, String> {
        self.key_manager
            .generate_one_time_prekeys(count)
            .map_err(|e| format!("Failed to generate OTPKs: {:?}", e))
    }

    /// How many one-time prekeys are stored locally (not yet consumed by incoming sessions).
    pub fn one_time_prekey_count(&self) -> usize {
        self.key_manager.one_time_prekey_count()
    }

    /// Export all stored OTPK private/public bytes for Keychain persistence.
    pub fn export_one_time_prekeys(&self) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
        self.key_manager.export_one_time_prekeys()
    }

    /// Import previously persisted OTPKs back into the core after a Keychain restore.
    pub fn import_one_time_prekeys(&mut self, keys: Vec<(u32, Vec<u8>, Vec<u8>)>) {
        self.key_manager.import_one_time_prekeys(keys);
    }
}

/// Convenience type alias для X3DH + Double Ratchet с Classic Suite
pub type ClassicClient<P> = Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
    use crate::crypto::suites::classic::ClassicSuiteProvider;
    use crate::crypto::SuiteID;

    type TestClient = Client<
        ClassicSuiteProvider,
        X3DHProtocol<ClassicSuiteProvider>,
        DoubleRatchetSession<ClassicSuiteProvider>,
    >;

    #[test]
    fn test_client_creation() {
        let client = TestClient::new();
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.active_sessions_count(), 0);
    }

    #[test]
    fn test_client_alice_bob_full_exchange() {
        // Alice and Bob create their clients
        let mut alice = TestClient::new().unwrap();
        let mut bob = TestClient::new().unwrap();
        alice.set_local_user_id("alice".to_string());
        bob.set_local_user_id("bob".to_string());

        // Bob's registration bundle
        let bob_identity_priv = bob.key_manager.identity_secret_key().unwrap();
        let bob_identity_pub =
            ClassicSuiteProvider::from_private_key_to_public_key(&bob_identity_priv).unwrap();

        let bob_prekey = bob.key_manager.current_signed_prekey().unwrap();
        let bob_bundle = X3DHPublicKeyBundle {
            identity_public: bob_identity_pub.clone(),
            signed_prekey_public: bob_prekey.key_pair.1.clone(),
            signature: bob_prekey.signature.clone(),
            verifying_key: bob.key_manager.verifying_key().unwrap().to_vec(),
            suite_id: SuiteID::CLASSIC,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        };

        // Alice initiates session with Bob
        let session_id = alice
            .init_session("bob", &bob_bundle, &bob_identity_pub, 0)
            .unwrap();
        assert!(!session_id.is_empty());
        assert!(alice.has_session("bob"));
        assert_eq!(alice.active_sessions_count(), 1);

        // Alice sends first message
        let plaintext1 = b"Hello Bob!";
        let encrypted1 = alice.encrypt_message("bob", plaintext1).unwrap();

        // Bob extracts Alice's ephemeral key and initializes receiving session
        let alice_ephemeral_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(encrypted1.dh_public_key.to_vec());
        let alice_identity_priv = alice.key_manager.identity_secret_key().unwrap();
        let alice_identity_pub =
            ClassicSuiteProvider::from_private_key_to_public_key(&alice_identity_priv).unwrap();

        // NB: init_receiving_session_with_ephemeral теперь возвращает (session_id, plaintext)
        // Первое сообщение уже расшифровано!
        let (_session_id, decrypted1) = bob
            .init_receiving_session_with_ephemeral(
                "alice",
                &alice_identity_pub,
                &alice_ephemeral_pub,
                &encrypted1,
                0,
            )
            .unwrap();

        assert!(bob.has_session("alice"));

        // Verify first message was decrypted correctly
        assert_eq!(decrypted1, plaintext1);

        // Bob replies
        let plaintext2 = b"Hi Alice!";
        let encrypted2 = bob.encrypt_message("alice", plaintext2).unwrap();

        // Alice decrypts Bob's reply
        let decrypted2 = alice.decrypt_message("bob", &encrypted2).unwrap();
        assert_eq!(decrypted2, plaintext2);

        // Verify both have sessions
        assert_eq!(alice.active_contacts(), vec!["bob"]);
        assert_eq!(bob.active_contacts(), vec!["alice"]);
    }

    #[test]
    fn test_client_remove_session() {
        let mut alice = TestClient::new().unwrap();
        let bob = TestClient::new().unwrap();

        let bob_identity_priv = bob.key_manager.identity_secret_key().unwrap();
        let bob_identity_pub =
            ClassicSuiteProvider::from_private_key_to_public_key(&bob_identity_priv).unwrap();

        let bob_prekey = bob.key_manager.current_signed_prekey().unwrap();
        let bob_bundle = X3DHPublicKeyBundle {
            identity_public: bob_identity_pub.clone(),
            signed_prekey_public: bob_prekey.key_pair.1.clone(),
            signature: bob_prekey.signature.clone(),
            verifying_key: bob.key_manager.verifying_key().unwrap().to_vec(),
            suite_id: SuiteID::CLASSIC,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        };

        alice
            .init_session("bob", &bob_bundle, &bob_identity_pub, 0)
            .unwrap();
        assert!(alice.has_session("bob"));

        // Remove session
        assert!(alice.remove_session("bob"));
        assert!(!alice.has_session("bob"));
        assert_eq!(alice.active_sessions_count(), 0);
    }

    #[test]
    fn test_get_registration_bundle_uses_existing_keys() {
        use crate::crypto::SuiteID;

        // Создаем клиента с новыми ключами
        let client = Client::<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >::new()
        .unwrap();

        // Получаем bundle через key_manager напрямую
        let direct_bundle = client
            .key_manager
            .export_device_registration_bundle()
            .unwrap();

        // Получаем registration bundle через метод Client
        let client_bundle = client.get_registration_bundle().unwrap();

        // Проверяем, что bundles идентичны
        assert_eq!(
            client_bundle.identity_public, direct_bundle.identity_public,
            "Identity public key should match"
        );
        assert_eq!(
            client_bundle.verifying_key, direct_bundle.verifying_key,
            "Verifying key should match"
        );
        assert_eq!(
            client_bundle.signed_prekey_public, direct_bundle.signed_prekey_public,
            "Signed prekey public should match"
        );
        assert_eq!(
            client_bundle.signature, direct_bundle.signature,
            "Signature should match"
        );
        assert_eq!(
            client_bundle.suite_id,
            SuiteID::CLASSIC,
            "Suite ID should be CLASSIC"
        );
    }

    #[test]
    fn test_get_registration_bundle_only_public_data() {
        let client = Client::<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >::new()
        .unwrap();

        // Получаем registration bundle
        let bundle = client.get_registration_bundle().unwrap();

        // Проверяем, что все поля являются публичными данными (Vec<u8>)
        // Приватные ключи не должны быть в bundle
        assert!(
            !bundle.identity_public.is_empty(),
            "Identity public key should not be empty"
        );
        assert!(
            !bundle.signed_prekey_public.is_empty(),
            "Signed prekey public should not be empty"
        );
        assert!(
            !bundle.signature.is_empty(),
            "Signature should not be empty"
        );
        assert!(
            !bundle.verifying_key.is_empty(),
            "Verifying key should not be empty"
        );

        // Проверяем правильность размеров для Classic suite
        assert_eq!(
            bundle.identity_public.len(),
            32,
            "Identity public key should be 32 bytes"
        );
        assert_eq!(
            bundle.signed_prekey_public.len(),
            32,
            "Signed prekey public should be 32 bytes"
        );
        assert_eq!(bundle.signature.len(), 64, "Signature should be 64 bytes");
        assert_eq!(
            bundle.verifying_key.len(),
            32,
            "Verifying key should be 32 bytes"
        );
    }

    #[test]
    fn test_init_receiving_session_with_valid_bundle() {
        use crate::device_id::derive_device_id;

        // Alice и Bob создают клиентов
        let mut alice = Client::<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >::new()
        .unwrap();
        alice.set_local_user_id("alice-device".to_string());

        let mut bob = Client::<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >::new()
        .unwrap();
        bob.set_local_user_id("bob-device".to_string());

        // Alice получает bundle Bob-а для инициации сессии
        let bob_bundle = bob.get_registration_bundle().unwrap();
        let bob_identity = bob.key_manager.identity_public_key().unwrap().clone();
        let bob_device_id = derive_device_id(bob_bundle.identity_public.as_ref());

        // Set actual device IDs as local_user_ids so AAD matches during encrypt/decrypt
        let alice_bundle_pre = alice.get_registration_bundle().unwrap();
        let alice_device_id_pre = derive_device_id(alice_bundle_pre.identity_public.as_ref());
        alice.set_local_user_id(alice_device_id_pre);
        bob.set_local_user_id(bob_device_id.clone());

        // Alice инициирует сессию с Bob
        let bob_bundle_for_init = crate::crypto::handshake::x3dh::X3DHPublicKeyBundle {
            identity_public: bob_bundle.identity_public.clone(),
            signed_prekey_public: bob_bundle.signed_prekey_public.clone(),
            signature: bob_bundle.signature.clone(),
            verifying_key: bob_bundle.verifying_key.clone(),
            suite_id: bob_bundle.suite_id,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        };

        alice
            .init_session(&bob_device_id, &bob_bundle_for_init, &bob_identity, 0)
            .unwrap();

        // Alice отправляет первое сообщение
        let plaintext = b"Hello Bob from Alice!";
        let first_message = alice.encrypt_message(&bob_device_id, plaintext).unwrap();

        // Alice получает bundle для верификации
        let alice_bundle = alice.get_registration_bundle().unwrap();
        let alice_device_id = derive_device_id(alice_bundle.identity_public.as_ref());

        // ✅ Bob инициализирует receiving session с верификацией подписи
        let (session_id, decrypted) = bob
            .init_receiving_session(&alice_device_id, &alice_bundle, &first_message)
            .unwrap();

        // Проверяем результаты
        assert!(bob.has_session(&alice_device_id));
        assert_eq!(decrypted, plaintext);
        assert!(!session_id.is_empty());
    }

    #[test]
    fn test_init_receiving_session_rejects_invalid_signature() {
        use crate::device_id::derive_device_id;

        let mut alice = Client::<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >::new()
        .unwrap();

        let mut bob = Client::<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >::new()
        .unwrap();

        let bob_bundle = bob.get_registration_bundle().unwrap();
        let bob_identity = bob.key_manager.identity_public_key().unwrap().clone();
        let bob_device_id = derive_device_id(bob_bundle.identity_public.as_ref());

        let bob_bundle_for_init = crate::crypto::handshake::x3dh::X3DHPublicKeyBundle {
            identity_public: bob_bundle.identity_public.clone(),
            signed_prekey_public: bob_bundle.signed_prekey_public.clone(),
            signature: bob_bundle.signature.clone(),
            verifying_key: bob_bundle.verifying_key.clone(),
            suite_id: bob_bundle.suite_id,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        };

        alice
            .init_session(&bob_device_id, &bob_bundle_for_init, &bob_identity, 0)
            .unwrap();

        let plaintext = b"Hello Bob!";
        let first_message = alice.encrypt_message(&bob_device_id, plaintext).unwrap();

        // Создаем bundle с невалидной подписью
        let mut alice_bundle = alice.get_registration_bundle().unwrap();
        alice_bundle.signature[0] ^= 0xFF; // Портим подпись

        let alice_device_id = derive_device_id(alice_bundle.identity_public.as_ref());

        // ❌ Bob должен отклонить bundle с невалидной подписью
        let result = bob.init_receiving_session(&alice_device_id, &alice_bundle, &first_message);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid signed prekey signature"));
    }

    #[test]
    fn test_init_receiving_session_rejects_wrong_device_id() {
        use crate::device_id::derive_device_id;

        let mut alice = Client::<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >::new()
        .unwrap();

        let mut bob = Client::<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >::new()
        .unwrap();

        let bob_bundle = bob.get_registration_bundle().unwrap();
        let bob_identity = bob.key_manager.identity_public_key().unwrap().clone();
        let bob_device_id = derive_device_id(bob_bundle.identity_public.as_ref());

        let bob_bundle_for_init = crate::crypto::handshake::x3dh::X3DHPublicKeyBundle {
            identity_public: bob_bundle.identity_public.clone(),
            signed_prekey_public: bob_bundle.signed_prekey_public.clone(),
            signature: bob_bundle.signature.clone(),
            verifying_key: bob_bundle.verifying_key.clone(),
            suite_id: bob_bundle.suite_id,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        };

        alice
            .init_session(&bob_device_id, &bob_bundle_for_init, &bob_identity, 0)
            .unwrap();

        let plaintext = b"Hello Bob!";
        let first_message = alice.encrypt_message(&bob_device_id, plaintext).unwrap();

        let alice_bundle = alice.get_registration_bundle().unwrap();

        // ❌ Bob использует неправильный device_id
        let wrong_device_id = "wrong_device_id_12345678";

        let result = bob.init_receiving_session(wrong_device_id, &alice_bundle, &first_message);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Device ID mismatch"));
    }
}
