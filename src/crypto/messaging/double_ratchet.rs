//! Double Ratchet Protocol Implementation
//!
//! Реализация протокола Double Ratchet (Signal Protocol).
//!
//! ## Архитектура
//!
//! Double Ratchet состоит из двух ratchets:
//! 1. **DH Ratchet**: Постоянная ротация DH ключей для forward secrecy
//! 2. **Symmetric Ratchet**: Ротация chain keys для каждого сообщения
//!
//! ## Key Responsibilities
//!
//! - DH Ratcheting: Генерация новых DH пар при каждом "turn" в диалоге
//! - Chain Key Ratcheting: Вывод message keys из chain keys
//! - Skipped Message Keys: Хранение ключей для out-of-order сообщений
//! - DoS Protection: Лимиты на skipped keys
//!
//! ## Dataflow Example
//!
//! ```text
//! Alice                                    Bob
//! -----                                    ---
//! new_initiator_session(root_key, initiator_state, bob_pub)
//!   ↓
//! ephemeral_priv (from X3DH) → first DH ratchet key
//!   ↓
//! DH(ephemeral_priv, bob_identity) → sending_chain
//!   ↓
//! encrypt(msg1) →                      →  Bob receives msg1
//!                                            ↓
//!                                        new_responder_session(root_key, bob_priv, msg1)
//!                                            ↓
//!                                        Extract alice_ephemeral_pub from msg1
//!                                            ↓
//!                                        DH(bob_identity_priv, alice_ephemeral_pub) → receiving_chain
//!                                            ↓
//!                                        decrypt(msg1) ✅
//!                                            ↓
//!                                        Generate new DH pair for reply
//!                                            ↓
//!                                    ←   encrypt(msg2) with new DH key
//! DH Ratchet Step! (Alice sees new DH key)
//!   ↓
//! decrypt(msg2) ✅
//! ```

use crate::config::Config;
use crate::crypto::handshake::InitiatorState;
use crate::crypto::messaging::SecureMessaging;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::SuiteID;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Double Ratchet Session
///
/// Хранит состояние Double Ratchet для обмена сообщениями с одним контактом.
///
/// ## State Components
///
/// ### Root Key
/// - Обновляется при каждом DH ratchet step
/// - Источник для derivation chain keys
///
/// ### Chain Keys
/// - `sending_chain_key`: Для шифрования исходящих сообщений
/// - `receiving_chain_key`: Для расшифровки входящих сообщений
/// - Обновляются при каждом сообщении
///
/// ### DH Ratchet Keys
/// - `dh_ratchet_private`: Наш текущий DH private key
/// - `dh_ratchet_public`: Наш текущий DH public key (отправляется в сообщениях)
/// - `remote_dh_public`: Последний известный DH public key собеседника
///
/// ### Skipped Message Keys
/// - Ключи для out-of-order сообщений
/// - Имеют timestamp для cleanup
pub struct DoubleRatchetSession<P: CryptoProvider> {
    suite_id: SuiteID,
    root_key: P::AeadKey,

    sending_chain_key: P::AeadKey,
    sending_chain_length: u32,

    receiving_chain_key: P::AeadKey,
    receiving_chain_length: u32,

    dh_ratchet_private: Option<P::KemPrivateKey>,
    dh_ratchet_public: P::KemPublicKey,
    remote_dh_public: Option<P::KemPublicKey>,

    previous_sending_length: u32,
    skipped_message_keys: HashMap<u32, P::AeadKey>,
    skipped_key_timestamps: HashMap<u32, u64>,

    session_id: String,
    contact_id: String,
    local_user_id: String,
}

/// Encrypted message in wire format
///
/// Содержит всё необходимое для расшифровки:
/// - DH public key для ratcheting
/// - Message number для key derivation
/// - Ciphertext с authentication tag
/// - Nonce для AEAD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRatchetMessage {
    pub dh_public_key: [u8; 32],
    pub message_number: u32,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub previous_chain_length: u32,
    pub suite_id: u16,
}

impl<P: CryptoProvider> SecureMessaging<P> for DoubleRatchetSession<P> {
    type EncryptedMessage = EncryptedRatchetMessage;

    /// Создать сессию как инициатор (Alice)
    ///
    /// Alice вызывает это после X3DH handshake.
    ///
    /// # Критически важно
    ///
    /// `initiator_state.ephemeral_private` - это тот же ключ, который использовался в X3DH!
    /// Он становится первым DH ratchet key.
    ///
    /// Это обеспечивает, что Bob сможет:
    /// 1. Извлечь ephemeral_public из первого сообщения
    /// 2. Выполнить X3DH с этим ключом
    /// 3. Получить тот же root_key
    fn new_initiator_session(
        root_key: &[u8],
        initiator_state: InitiatorState<P>,
        remote_identity: &P::KemPublicKey,
        contact_id: String,
        local_user_id: String,
    ) -> Result<Self, String> {
        use tracing::debug;

        debug!(
            target: "crypto::double_ratchet",
            contact_id = %contact_id,
            "Creating initiator session (Alice)"
        );

        // Convert root_key bytes to P::AeadKey
        // ✅ SECURITY: Use dedicated salt for Double Ratchet (different from X3DH)
        let salt = [0xFE_u8; 32];
        let root_key_vec = P::hkdf_derive_key(&salt, root_key, b"InitialRootKey", 32)
            .map_err(|e| format!("Failed to derive root key: {}", e))?;
        let root_key_val = Self::bytes_to_aead_key(&root_key_vec)?;

        // ✅ Use X3DH ephemeral key as first DH ratchet key
        // NOT generating new one!
        let dh_private = initiator_state.ephemeral_private;
        let dh_public = P::from_private_key_to_public_key(&dh_private)
            .map_err(|e| format!("Failed to derive public key: {}", e))?;

        debug!(
            target: "crypto::double_ratchet",
            "Using X3DH ephemeral key as initial DH ratchet key"
        );

        // Perform DH(alice_ephemeral_priv, bob_identity_pub) → sending_chain
        let dh_output_secret = P::kem_decapsulate(&dh_private, remote_identity.as_ref())
            .map_err(|e| format!("Failed to perform DH: {}", e))?;

        let (root_key, chain_key) = P::kdf_rk(&root_key_val, &dh_output_secret)
            .map_err(|e| format!("KDF_RK failed: {}", e))?;

        Ok(Self {
            suite_id: SuiteID::from_u16_unchecked(Config::global().classic_suite_id),
            root_key,
            sending_chain_key: chain_key,
            sending_chain_length: 0,
            receiving_chain_key: P::AeadKey::default(),
            receiving_chain_length: 0,
            dh_ratchet_private: Some(dh_private),
            dh_ratchet_public: dh_public,
            remote_dh_public: Some(remote_identity.clone()),
            previous_sending_length: 0,
            skipped_message_keys: HashMap::new(),
            skipped_key_timestamps: HashMap::new(),
            session_id: uuid::Uuid::new_v4().to_string(),
            contact_id,
            local_user_id,
        })
    }

    /// Создать сессию как получатель (Bob)
    ///
    /// Bob вызывает это при получении первого сообщения от Alice.
    ///
    /// # Процесс
    ///
    /// 1. Извлекает Alice's ephemeral_public из first_message.dh_public_key
    /// 2. Выполняет DH(bob_identity_priv, alice_ephemeral_pub) → receiving_chain
    /// 3. Генерирует новую DH пару для отправки
    /// 4. Выполняет второй DH ratchet для sending_chain
    /// 5. **Расшифровывает первое сообщение**
    fn new_responder_session(
        root_key: &[u8],
        local_identity: &P::KemPrivateKey,
        first_message: &Self::EncryptedMessage,
        contact_id: String,
        local_user_id: String,
    ) -> Result<(Self, Vec<u8>), String> {
        use tracing::debug;

        debug!(
            target: "crypto::double_ratchet",
            contact_id = %contact_id,
            "Creating responder session (Bob)"
        );

        // Extract Alice's ephemeral public key from first message
        let remote_dh_public_bytes = &first_message.dh_public_key;
        let remote_dh_public = Self::bytes_to_kem_public_key(remote_dh_public_bytes)?;

        debug!(
            target: "crypto::double_ratchet",
            "Extracted Alice's ephemeral key from first message"
        );

        // Convert root_key bytes to P::AeadKey
        // ✅ SECURITY: Use dedicated salt for Double Ratchet (different from X3DH)
        let salt = [0xFE_u8; 32];
        let root_key_vec = P::hkdf_derive_key(&salt, root_key, b"InitialRootKey", 32)
            .map_err(|e| format!("Failed to derive root key: {}", e))?;
        let mut root_key_val = Self::bytes_to_aead_key(&root_key_vec)?;

        // Perform DH(bob_identity_priv, alice_ephemeral_pub) → receiving_chain
        let dh_output = P::kem_decapsulate(local_identity, remote_dh_public.as_ref())
            .map_err(|e| format!("Failed to perform DH: {}", e))?;
        let (new_root_key, receiving_chain) =
            P::kdf_rk(&root_key_val, &dh_output).map_err(|e| format!("KDF_RK failed: {}", e))?;
        root_key_val = new_root_key;

        // Generate new DH pair for sending
        let (dh_private, dh_public) =
            P::generate_kem_keys().map_err(|e| format!("Failed to generate DH keys: {}", e))?;

        debug!(
            target: "crypto::double_ratchet",
            "Generated new DH pair for sending"
        );

        // Perform second ratchet for sending chain
        let dh_output2 = P::kem_decapsulate(&dh_private, remote_dh_public.as_ref())
            .map_err(|e| format!("Failed to perform DH: {}", e))?;
        let (final_root_key, sending_chain) =
            P::kdf_rk(&root_key_val, &dh_output2).map_err(|e| format!("KDF_RK failed: {}", e))?;

        // Валидация suite_id из первого сообщения
        let suite_id = SuiteID::new(first_message.suite_id)
            .map_err(|e| format!("Invalid suite_id in first message: {}", e))?;

        let mut session = Self {
            suite_id,
            root_key: final_root_key,
            sending_chain_key: sending_chain,
            sending_chain_length: 0,
            receiving_chain_key: receiving_chain,
            receiving_chain_length: 0,
            dh_ratchet_private: Some(dh_private),
            dh_ratchet_public: dh_public,
            remote_dh_public: Some(remote_dh_public),
            previous_sending_length: 0,
            skipped_message_keys: HashMap::new(),
            skipped_key_timestamps: HashMap::new(),
            session_id: uuid::Uuid::new_v4().to_string(),
            contact_id: contact_id.clone(),
            local_user_id,
        };

        // КРИТИЧЕСКИ ВАЖНО: Расшифровываем первое сообщение!
        // Bob должен прочитать первое сообщение чтобы получить plaintext.
        debug!(
            target: "crypto::double_ratchet",
            "Decrypting first message from Alice"
        );

        let plaintext = session.decrypt(first_message)?;

        debug!(
            target: "crypto::double_ratchet",
            plaintext_len = %plaintext.len(),
            "First message decrypted successfully"
        );

        Ok((session, plaintext))
    }

    /// Зашифровать сообщение
    ///
    /// # Процесс
    ///
    /// 1. Derive message key: (chain_key', msg_key) = KDF_CK(chain_key)
    /// 2. Increment sending_chain_length
    /// 3. Encrypt: ciphertext = AEAD(msg_key, nonce, plaintext)
    /// 4. Return EncryptedMessage with current DH public key
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Self::EncryptedMessage, String> {
        use tracing::trace;

        trace!(
            target: "crypto::double_ratchet",
            plaintext_len = %plaintext.len(),
            chain_length = %self.sending_chain_length,
            "Encrypting message"
        );

        // Apply padding to hide message length (traffic analysis protection)
        use crate::traffic_protection::padding::pad_message_default;
        let padded_plaintext = pad_message_default(plaintext).map_err(|e| {
            tracing::error!(
                target: "crypto::double_ratchet",
                error = %e,
                plaintext_len = plaintext.len(),
                "Padding failed"
            );
            format!("Padding failed: {}", e)
        })?;

        let (message_key, next_chain_key) = P::kdf_ck(&self.sending_chain_key).map_err(|e| {
            tracing::error!(
                target: "crypto::double_ratchet",
                error = %e,
                "KDF (CK) failed"
            );
            format!("KDF (CK) failed: {}", e)
        })?;
        self.sending_chain_key = next_chain_key;

        let message_number = self.sending_chain_length;
        self.sending_chain_length += 1;

        // Generate nonce - use configured nonce length for ChaCha20Poly1305
        let nonce = P::generate_nonce(Config::global().chacha_nonce_length)
            .map_err(|e| format!("Nonce generation failed: {}", e))?;

        // Convert dh_ratchet_public to [u8; 32] first
        let dh_public_key_vec = self.dh_ratchet_public.as_ref().to_vec();
        let dh_public_key: [u8; 32] = dh_public_key_vec
            .try_into()
            .map_err(|_| "Invalid public key length")?;

        // Associated Data: dh_public_key || message_number (per Signal/Noise protocol)
        // Associated Data: local_user_id || contact_id || dh_public_key || message_number
        let mut associated_data =
            Vec::with_capacity(self.local_user_id.len() + self.contact_id.len() + 32 + 4);
        associated_data.extend_from_slice(self.local_user_id.as_bytes());
        associated_data.extend_from_slice(self.contact_id.as_bytes());
        associated_data.extend_from_slice(&dh_public_key);
        associated_data.extend_from_slice(&message_number.to_be_bytes());

        let ciphertext = P::aead_encrypt(
            &message_key,
            &nonce,
            &padded_plaintext,
            Some(&associated_data),
        )
        .map_err(|e| {
            tracing::error!(
                target: "crypto::double_ratchet",
                error = %e,
                padded_plaintext_len = padded_plaintext.len(),
                nonce_len = nonce.len(),
                "AEAD encryption failed"
            );
            format!("Encryption failed: {}", e)
        })?;

        trace!(
            target: "crypto::double_ratchet",
            ciphertext_len = %ciphertext.len(),
            "Encryption successful"
        );

        Ok(EncryptedRatchetMessage {
            dh_public_key,
            message_number,
            ciphertext,
            nonce,
            previous_chain_length: self.previous_sending_length,
            suite_id: self.suite_id.as_u16(),
        })
    }

    /// Расшифровать сообщение
    ///
    /// # Процесс
    ///
    /// 1. Check if DH public key changed → perform DH ratchet if needed
    /// 2. Check if message number is ahead → save skipped keys
    /// 3. Derive message key: (chain_key', msg_key) = KDF_CK(chain_key)
    /// 4. Decrypt: plaintext = AEAD_decrypt(msg_key, nonce, ciphertext)
    ///
    /// # DoS Protection
    ///
    /// - Лимит на количество skipped keys (MAX_SKIPPED_MESSAGES)
    /// - Automatic cleanup старых ключей по timestamp
    fn decrypt(&mut self, encrypted: &Self::EncryptedMessage) -> Result<Vec<u8>, String> {
        use tracing::{debug, trace};

        debug!(
            target: "crypto::double_ratchet",
            msg_num = %encrypted.message_number,
            current_recv_chain_len = %self.receiving_chain_length,
            skipped_keys_count = %self.skipped_message_keys.len(),
            "Decrypting message"
        );

        // Convert DH public key from message
        let remote_dh_public = Self::bytes_to_kem_public_key(&encrypted.dh_public_key)?;

        // Check if we need to perform DH ratchet
        let needs_ratchet = match &self.remote_dh_public {
            Some(current_remote) => {
                // Compare byte representation
                current_remote.as_ref() != remote_dh_public.as_ref()
            }
            None => true,
        };

        if needs_ratchet {
            debug!(target: "crypto::double_ratchet", "Performing DH ratchet");
            self.perform_dh_ratchet(&remote_dh_public)?;
        }

        // Try to find skipped message key
        if let Some(key) = self.skipped_message_keys.remove(&encrypted.message_number) {
            trace!(
                target: "crypto::double_ratchet",
                msg_num = %encrypted.message_number,
                "Found skipped message key"
            );
            return self.decrypt_with_key(&key, encrypted);
        }

        // Derive keys until we reach the message number
        while self.receiving_chain_length <= encrypted.message_number {
            let (msg_key, next_chain) = P::kdf_ck(&self.receiving_chain_key)
                .map_err(|e| format!("KDF_CK failed: {}", e))?;

            if self.receiving_chain_length == encrypted.message_number {
                self.receiving_chain_key = next_chain;
                self.receiving_chain_length += 1;
                return self.decrypt_with_key(&msg_key, encrypted);
            } else {
                // Store skipped key with timestamp
                let timestamp = crate::utils::time::now();

                self.skipped_message_keys
                    .insert(self.receiving_chain_length, msg_key);
                self.skipped_key_timestamps
                    .insert(self.receiving_chain_length, timestamp);
                self.receiving_chain_key = next_chain;
                self.receiving_chain_length += 1;

                // DoS protection
                if self.skipped_message_keys.len() > Config::global().max_skipped_messages as usize
                {
                    return Err("Too many skipped messages".to_string());
                }
            }
        }

        Err("Message key not found".to_string())
    }

    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn contact_id(&self) -> &str {
        &self.contact_id
    }

    fn cleanup_old_skipped_keys(&mut self, max_age_seconds: i64) {
        use tracing::debug;

        let now = crate::utils::time::now();
        let initial_count = self.skipped_message_keys.len();

        // Удаляем старые ключи
        self.skipped_message_keys.retain(|msg_num, _| {
            if let Some(&timestamp) = self.skipped_key_timestamps.get(msg_num) {
                (now as i64 - timestamp as i64) < max_age_seconds
            } else {
                // Если нет timestamp, удаляем ключ (safety measure)
                false
            }
        });

        // Также очищаем timestamps
        self.skipped_key_timestamps
            .retain(|msg_num, _| self.skipped_message_keys.contains_key(msg_num));

        let removed_count = initial_count - self.skipped_message_keys.len();
        if removed_count > 0 {
            debug!(
                target: "crypto::double_ratchet",
                removed = %removed_count,
                remaining = %self.skipped_message_keys.len(),
                "Cleaned up old skipped message keys"
            );
        }
    }
}

// Internal implementation details
impl<P: CryptoProvider> DoubleRatchetSession<P> {
    /// Cleanup старых skipped message keys с дефолтным периодом (7 дней)
    pub fn cleanup_old_skipped_keys_default(&mut self) {
        self.cleanup_old_skipped_keys(Config::global().max_skipped_message_age_seconds);
    }

    /// Выполнить DH ratchet step
    ///
    /// Вызывается когда получаем сообщение с новым DH public key.
    ///
    /// # Процесс
    ///
    /// 1. DH(old_private, new_remote_public) → receiving_chain
    /// 2. Generate new DH pair
    /// 3. DH(new_private, new_remote_public) → sending_chain
    /// 4. Update state
    fn perform_dh_ratchet(&mut self, new_remote_dh: &P::KemPublicKey) -> Result<(), String> {
        use tracing::debug;

        debug!(
            target: "crypto::double_ratchet",
            "Performing DH ratchet step"
        );

        self.previous_sending_length = self.sending_chain_length;

        // 1. Get new receiving chain key using old DH private and new remote DH
        let dh_private = self
            .dh_ratchet_private
            .as_ref()
            .ok_or("No DH private key")?;
        let dh_receive = P::kem_decapsulate(dh_private, new_remote_dh.as_ref())
            .map_err(|e| format!("DH failed: {}", e))?;

        let (new_root_key, new_receiving_chain) =
            P::kdf_rk(&self.root_key, &dh_receive).map_err(|e| format!("KDF_RK failed: {}", e))?;
        self.root_key = new_root_key;
        self.receiving_chain_key = new_receiving_chain;
        self.receiving_chain_length = 0;

        // 2. Generate new DH pair for sending
        let (new_dh_private, new_dh_public) =
            P::generate_kem_keys().map_err(|e| format!("Failed to generate DH keys: {}", e))?;

        // 3. Get sending chain key using new DH private and new remote DH
        let dh_send = P::kem_decapsulate(&new_dh_private, new_remote_dh.as_ref())
            .map_err(|e| format!("DH failed: {}", e))?;

        let (new_root_key2, new_sending_chain) =
            P::kdf_rk(&self.root_key, &dh_send).map_err(|e| format!("KDF_RK failed: {}", e))?;
        self.root_key = new_root_key2;
        self.sending_chain_key = new_sending_chain;
        self.sending_chain_length = 0;

        // 4. Update state
        self.dh_ratchet_private = Some(new_dh_private);
        self.dh_ratchet_public = new_dh_public;
        self.remote_dh_public = Some(new_remote_dh.clone());

        debug!(
            target: "crypto::double_ratchet",
            "DH ratchet step completed"
        );

        Ok(())
    }

    /// Расшифровать с заданным message key
    fn decrypt_with_key(
        &self,
        message_key: &P::AeadKey,
        encrypted: &EncryptedRatchetMessage,
    ) -> Result<Vec<u8>, String> {
        use tracing::{debug, trace};

        trace!(
            target: "crypto::double_ratchet",
            msg_num = %encrypted.message_number,
            nonce_len = %encrypted.nonce.len(),
            ciphertext_len = %encrypted.ciphertext.len(),
            "Decrypting with message key"
        );

        // Reconstruct Associated Data: contact_id (sender) || local_user_id (recipient) || dh_public_key || message_number
        let mut associated_data =
            Vec::with_capacity(self.contact_id.len() + self.local_user_id.len() + 32 + 4);
        associated_data.extend_from_slice(self.contact_id.as_bytes());
        associated_data.extend_from_slice(self.local_user_id.as_bytes());
        associated_data.extend_from_slice(&encrypted.dh_public_key);
        associated_data.extend_from_slice(&encrypted.message_number.to_be_bytes());

        let padded_plaintext = P::aead_decrypt(
            message_key,
            &encrypted.nonce,
            &encrypted.ciphertext,
            Some(&associated_data),
        )
        .map_err(|e| format!("Decryption failed: {}", e))?;

        debug!(target: "crypto::double_ratchet", "Decryption successful");

        // Remove padding to recover original plaintext (traffic analysis protection)
        use crate::traffic_protection::padding::unpad_message;
        let plaintext =
            unpad_message(&padded_plaintext).map_err(|e| format!("Unpadding failed: {}", e))?;

        Ok(plaintext)
    }

    // Helper functions to convert between bytes and keys
    fn bytes_to_aead_key(bytes: &[u8]) -> Result<P::AeadKey, String> {
        Ok(P::aead_key_from_bytes(bytes.to_vec()))
    }

    fn bytes_to_kem_public_key(bytes: &[u8]) -> Result<P::KemPublicKey, String> {
        Ok(P::kem_public_key_from_bytes(bytes.to_vec()))
    }

    fn bytes_to_kem_private_key(bytes: &[u8]) -> Result<P::KemPrivateKey, String> {
        Ok(P::kem_private_key_from_bytes(bytes.to_vec()))
    }

    /// Сериализовать сессию для сохранения
    pub fn to_serializable(&self) -> SerializableSession {
        SerializableSession {
            version: 1, // Current protocol version
            suite_id: self.suite_id.as_u16(),
            root_key: self.root_key.as_ref().to_vec(),
            sending_chain_key: self.sending_chain_key.as_ref().to_vec(),
            sending_chain_length: self.sending_chain_length,
            receiving_chain_key: self.receiving_chain_key.as_ref().to_vec(),
            receiving_chain_length: self.receiving_chain_length,
            dh_ratchet_private: self
                .dh_ratchet_private
                .as_ref()
                .map(|k| k.as_ref().to_vec()),
            dh_ratchet_public: self.dh_ratchet_public.as_ref().to_vec(),
            remote_dh_public: self.remote_dh_public.as_ref().map(|k| k.as_ref().to_vec()),
            previous_sending_length: self.previous_sending_length,
            skipped_message_keys: self
                .skipped_message_keys
                .iter()
                .map(|(k, v)| (*k, v.as_ref().to_vec()))
                .collect(),
            skipped_key_timestamps: self.skipped_key_timestamps.clone(),
            session_id: self.session_id.clone(),
            contact_id: self.contact_id.clone(),
            local_user_id: self.local_user_id.clone(),
        }
    }

    /// Десериализовать сессию
    pub fn from_serializable(data: SerializableSession) -> Result<Self, String> {
        // Check version compatibility
        if data.version != 1 {
            return Err(format!(
                "Unsupported session version: {}. Expected version 1.",
                data.version
            ));
        }

        // Валидация suite_id при десериализации
        let suite_id = SuiteID::new(data.suite_id)
            .map_err(|e| format!("Invalid suite_id in serialized session: {}", e))?;

        Ok(Self {
            suite_id,
            root_key: Self::bytes_to_aead_key(&data.root_key)?,
            sending_chain_key: Self::bytes_to_aead_key(&data.sending_chain_key)?,
            sending_chain_length: data.sending_chain_length,
            receiving_chain_key: Self::bytes_to_aead_key(&data.receiving_chain_key)?,
            receiving_chain_length: data.receiving_chain_length,
            dh_ratchet_private: data
                .dh_ratchet_private
                .map(|bytes| Self::bytes_to_kem_private_key(&bytes))
                .transpose()?,
            dh_ratchet_public: Self::bytes_to_kem_public_key(&data.dh_ratchet_public)?,
            remote_dh_public: data
                .remote_dh_public
                .map(|bytes| Self::bytes_to_kem_public_key(&bytes))
                .transpose()?,
            previous_sending_length: data.previous_sending_length,
            skipped_message_keys: data
                .skipped_message_keys
                .into_iter()
                .map(|(k, v)| Self::bytes_to_aead_key(&v).map(|key| (k, key)))
                .collect::<Result<_, _>>()?,
            skipped_key_timestamps: data.skipped_key_timestamps,
            session_id: data.session_id,
            contact_id: data.contact_id,
            local_user_id: data.local_user_id,
        })
    }
}

/// Serializable session format for storage
///
/// # Security Considerations
///
/// ⚠️ **CRITICAL**: This structure contains sensitive cryptographic material:
/// - `root_key`: Root key for DH ratchet key derivation
/// - `sending_chain_key` / `receiving_chain_key`: Current chain keys
/// - `dh_ratchet_private`: Private DH ratchet key
/// - `skipped_message_keys`: Keys for out-of-order messages
///
/// **SECURITY_AUDIT.md #13**: Sessions stored in plaintext
///
/// ## Defense-in-Depth Strategy:
///
/// 1. **Platform-Level Encryption** (Primary Defense):
///    - iOS: MUST use Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
///    - Web: MUST use IndexedDB (origin-isolated, browser-encrypted)
///    - Never store in UserDefaults, localStorage, or unencrypted files
///
/// 2. **Application-Level Encryption** (Optional, for paranoid mode):
///    - Derive session encryption key from device identity_key
///    - Encrypt SerializableSession before JSON serialization
///    - Note: Creates key management complexity in device-based model
///
/// 3. **Forward Secrecy Preservation**:
///    - Even if serialized session is compromised, past messages remain secure
///    - Only future messages (until next DH ratchet) could be decrypted
///    - Regular session rotation mitigates this window
///
/// ## Current Implementation:
///
/// Relies on platform secure storage (Keychain/IndexedDB encryption).
/// This is acceptable for device-based registration model where:
/// - No master password exists for additional encryption layer
/// - Platform storage provides hardware-backed encryption (iOS Secure Enclave)
/// - Origin isolation prevents cross-app access (Web)
///
/// If additional encryption is needed, implement in `export_session_json()`
/// before JSON conversion, not here (to keep serialization format clean).
#[derive(Serialize, Deserialize)]
pub struct SerializableSession {
    version: u16, // Protocol version for future compatibility
    suite_id: u16,
    root_key: Vec<u8>,
    sending_chain_key: Vec<u8>,
    sending_chain_length: u32,
    receiving_chain_key: Vec<u8>,
    receiving_chain_length: u32,
    dh_ratchet_private: Option<Vec<u8>>,
    dh_ratchet_public: Vec<u8>,
    remote_dh_public: Option<Vec<u8>>,
    previous_sending_length: u32,
    skipped_message_keys: HashMap<u32, Vec<u8>>,
    skipped_key_timestamps: HashMap<u32, u64>,
    session_id: String,
    contact_id: String,
    #[serde(default)]
    local_user_id: String,
}

#[cfg(test)]
mod tests {
    use super::{DoubleRatchetSession, SuiteID};
    use crate::crypto::handshake::{KeyAgreement, x3dh::X3DHProtocol};
    use crate::crypto::messaging::SecureMessaging;
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    #[test]
    fn test_alice_bob_full_exchange() {
        use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

        // Setup: Alice and Bob both have identity keys
        let (alice_identity_priv, alice_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (bob_identity_priv, bob_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();

        // Bob generates his registration keys
        let (bob_signed_prekey_priv, bob_signed_prekey_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (bob_signing_key, bob_verifying_key) =
            ClassicSuiteProvider::generate_signature_keys().unwrap();
        let bob_signature =
            ClassicSuiteProvider::sign(&bob_signing_key, bob_signed_prekey_pub.as_ref()).unwrap();

        // Bob's public bundle (what Alice gets from server)
        let bob_bundle = X3DHPublicKeyBundle {
            identity_public: bob_identity_pub.clone(),
            signed_prekey_public: bob_signed_prekey_pub.clone(),
            signature: bob_signature,
            verifying_key: bob_verifying_key,
            suite_id: SuiteID::CLASSIC,
        };

        // Alice performs X3DH as initiator
        let (root_key_alice, initiator_state) =
            X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(
                &alice_identity_priv,
                &bob_bundle,
            )
            .unwrap();

        // Alice creates session
        let mut alice_session =
            DoubleRatchetSession::<ClassicSuiteProvider>::new_initiator_session(
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
        let (bob_identity_priv, bob_identity_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();

        // Bob generates his registration keys
        let (bob_signed_prekey_priv, bob_signed_prekey_pub) =
            ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (bob_signing_key, bob_verifying_key) =
            ClassicSuiteProvider::generate_signature_keys().unwrap();
        let bob_signature =
            ClassicSuiteProvider::sign(&bob_signing_key, bob_signed_prekey_pub.as_ref()).unwrap();

        let bob_bundle = X3DHPublicKeyBundle {
            identity_public: bob_identity_pub.clone(),
            signed_prekey_public: bob_signed_prekey_pub.clone(),
            signature: bob_signature,
            verifying_key: bob_verifying_key,
            suite_id: SuiteID::CLASSIC,
        };

        let (root_key, initiator_state) =
            X3DHProtocol::<ClassicSuiteProvider>::perform_as_initiator(
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
}
