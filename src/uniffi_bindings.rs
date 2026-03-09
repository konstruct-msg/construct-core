use crate::crypto::client_api::ClassicClient;
use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::crypto::SuiteID;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

// Wrapper for Client to make it work with UniFFI
// Note: We use UDL definition, not derive macro
// UniFFI wraps this in Arc automatically, so we only need Mutex here
pub struct ClassicCryptoCore {
    inner: Mutex<ClassicClient<ClassicSuiteProvider>>,
}

// Error type that matches UDL definition (flat errors)
// Note: We use UDL definition, not derive macro
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Initialization failed")]
    InitializationFailed,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session initialization failed: {message}")]
    SessionInitializationFailed { message: String },

    #[error("Encryption failed: {message}")]
    EncryptionFailed { message: String },

    #[error("Decryption failed: {message}")]
    DecryptionFailed { message: String },

    #[error("Invalid key data")]
    InvalidKeyData,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Serialization failed")]
    SerializationFailed,

    #[error("MessagePack deserialization failed - check format")]
    MessagePackDeserializationFailed,
}

impl From<crate::error::CryptoError> for CryptoError {
    fn from(err: crate::error::CryptoError) -> Self {
        match err {
            crate::error::CryptoError::InvalidKeyData => CryptoError::InvalidKeyData,
            crate::error::CryptoError::InvalidCiphertext => CryptoError::InvalidCiphertext,
            e => CryptoError::SessionInitializationFailed {
                message: e.to_string(),
            },
        }
    }
}

// Re-export PoW types from pow module (for UniFFI UDL)
// Note: We use UDL definition, not derive macro
pub use crate::pow::{PowChallenge, PowProgressCallback, PowSolution};

// Registration bundle as JSON - matches UDL
// Note: We use UDL definition, not derive macro
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationBundleJson {
    pub identity_public: String,
    pub signed_prekey_public: String,
    pub signature: String,
    pub verifying_key: String,
    pub suite_id: String,
}

// Encrypted message components for wire format (matches server ChatMessage)
// Note: We use UDL definition for UniFFI
#[derive(Debug, Clone)]
pub struct EncryptedMessageComponents {
    pub ephemeral_public_key: Vec<u8>, // 32 bytes
    pub message_number: u32,
    pub content: String,         // Base64(nonce || ciphertext_with_tag)
    pub one_time_prekey_id: u32, // OTPK key_id used in X3DH (0 = no OTPK / fallback mode)
}

// Session initialization result with decrypted first message
// Note: We use UDL definition for UniFFI
#[derive(Debug, Clone)]
pub struct SessionInitResult {
    pub session_id: String,
    pub decrypted_message: String, // UTF-8 decoded plaintext
}

/// One-time prekey pair for upload to server
#[derive(Debug, Clone)]
pub struct OtpkPair {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

/// Full OTPK record for persistence (includes private key for Keychain storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpkRecord {
    pub key_id: u32,
    pub private_key: Vec<u8>, // Base64-encoded private key bytes
    pub public_key: Vec<u8>,  // Base64-encoded public key bytes
}

// Key bundle for session initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyBundle {
    identity_public: Vec<u8>,
    signed_prekey_public: Vec<u8>,
    signature: Vec<u8>,
    verifying_key: Vec<u8>,
    suite_id: u16,
    #[serde(default)]
    one_time_prekey_public: Option<Vec<u8>>,
    #[serde(default)]
    one_time_prekey_id: Option<u32>,
}

// Private keys for persistence (exported via UDL)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKeysJson {
    pub identity_secret: String,      // Base64
    pub signing_secret: String,       // Base64
    pub signed_prekey_secret: String, // Base64
    pub prekey_signature: String,     // Base64
    pub suite_id: String,
}

// Invite crypto types (exported via UDL)
// Note: These are UniFFI-compatible wrappers, actual crypto logic is in crypto::invite_crypto
#[derive(Debug, Clone)]
pub struct EphemeralKeyPair {
    pub secret_key: Vec<u8>, // 32 bytes
    pub public_key: Vec<u8>, // 32 bytes
}

#[derive(Debug, Clone)]
pub struct InviteSignature {
    pub signature: Vec<u8>, // 64 bytes
}

// Post-quantum KEM types (exported via UDL)
#[derive(Debug, Clone)]
pub struct MLKEMKeyPair {
    pub public_key: Vec<u8>, // ML-KEM-768: 1184 bytes
    pub secret_key: Vec<u8>, // ML-KEM-768: 2400 bytes
}

#[derive(Debug, Clone)]
pub struct MLKEMEncapsulation {
    pub ciphertext: Vec<u8>,    // ML-KEM-768: 1088 bytes
    pub shared_secret: Vec<u8>, // 32 bytes
}

// UniFFI interface implementation (exported via UDL, not proc-macros)
impl ClassicCryptoCore {
    /// Export registration bundle as JSON string
    pub fn export_registration_bundle_json(&self) -> Result<String, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // TODO(ARCHITECTURE): Обходной путь для экспорта существующих ключей
        // См. подробное описание: packages/core/ARCHITECTURE_TODOS.md
        //
        // ПРОБЛЕМА:
        // - Client::get_registration_bundle() вызывает H::generate_registration_bundle()
        // - Это статический метод, который генерирует НОВЫЕ ключи каждый раз
        // - Нам нужны СУЩЕСТВУЮЩИЕ ключи из KeyManager
        // - KeyManager::export_registration_bundle() возвращает конкретный тип X3DHPublicKeyBundle
        // - Client::get_registration_bundle() возвращает generic H::RegistrationBundle
        //
        // ТЕКУЩЕЕ РЕШЕНИЕ (временное):
        // - Обходим Client::get_registration_bundle()
        // - Напрямую вызываем key_manager().export_registration_bundle()
        //
        // ПРАВИЛЬНОЕ РЕШЕНИЕ:
        // Вариант 1: Сделать KeyManager generic по протоколу handshake
        //   - KeyManager<P, H: KeyAgreement<P>>
        //   - export_registration_bundle() -> Result<H::RegistrationBundle>
        //
        // Вариант 2: Добавить метод в trait KeyAgreement
        //   - fn export_from_key_manager(km: &KeyManager<P>) -> Result<Self::RegistrationBundle>
        //
        // Вариант 3: Сделать Client::get_registration_bundle() не-generic
        //   - pub fn export_registration_bundle() -> Result<конкретный тип>
        //   - Но это нарушает generic design
        //
        // РЕКОМЕНДАЦИЯ: Вариант 1 - наиболее type-safe и правильный архитектурно
        let bundle = client
            .key_manager()
            .export_registration_bundle()
            .map_err(|_| CryptoError::InitializationFailed)?;

        // Convert to base64 strings
        use base64::Engine;
        let json_bundle = RegistrationBundleJson {
            identity_public: base64::engine::general_purpose::STANDARD
                .encode(&bundle.identity_public),
            signed_prekey_public: base64::engine::general_purpose::STANDARD
                .encode(&bundle.signed_prekey_public),
            signature: base64::engine::general_purpose::STANDARD.encode(&bundle.signature),
            verifying_key: base64::engine::general_purpose::STANDARD.encode(&bundle.verifying_key),
            suite_id: bundle.suite_id.as_u16().to_string(),
        };

        serde_json::to_string(&json_bundle).map_err(|_| CryptoError::SerializationFailed)
    }

    /// Sign BundleData JSON string with Ed25519 signing key
    /// This is used for creating the signature in UploadableKeyBundle
    pub fn sign_bundle_data(&self, bundle_data_json: Vec<u8>) -> Result<String, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Sign the BundleData JSON bytes
        let signature = client
            .key_manager()
            .sign(&bundle_data_json)
            .map_err(|_| CryptoError::InitializationFailed)?;

        // Encode signature to base64
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(&signature))
    }

    /// Export private keys as JSON string for persistence
    /// SECURITY: Only call this method to store keys in secure storage (Keychain)
    pub fn export_private_keys_json(&self) -> Result<String, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Get private keys from key manager
        let identity_secret = client
            .key_manager()
            .identity_secret_key()
            .map_err(|_| CryptoError::InvalidKeyData)?;
        let signing_secret = client
            .key_manager()
            .signing_secret_key()
            .map_err(|_| CryptoError::InvalidKeyData)?;
        let prekey = client
            .key_manager()
            .current_signed_prekey()
            .map_err(|_| CryptoError::InvalidKeyData)?;

        // Convert to bytes - use AsRef<[u8]> trait bound
        let identity_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(identity_secret).to_vec();
        let signing_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(signing_secret).to_vec();
        let prekey_secret_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(&prekey.key_pair.0).to_vec();

        // Encode to base64
        use base64::Engine;
        let private_keys_json = PrivateKeysJson {
            identity_secret: base64::engine::general_purpose::STANDARD.encode(&identity_bytes),
            signing_secret: base64::engine::general_purpose::STANDARD.encode(&signing_bytes),
            signed_prekey_secret: base64::engine::general_purpose::STANDARD
                .encode(&prekey_secret_bytes),
            prekey_signature: base64::engine::general_purpose::STANDARD.encode(&prekey.signature),
            suite_id: "1".to_string(),
        };

        serde_json::to_string(&private_keys_json).map_err(|_| CryptoError::SerializationFailed)
    }

    /// Export session to JSON for persistence in Keychain
    ///
    /// # Parameters
    /// - `contact_id`: Contact ID to export session for
    ///
    /// # Returns
    /// JSON string containing serialized session state
    ///
    /// # Security - CRITICAL
    ///
    /// ⚠️ **UNENCRYPTED cryptographic material**: root key, chain keys, DH private key.
    ///
    /// **MUST** store in: iOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) or IndexedDB.
    /// **NEVER** use: UserDefaults, localStorage, or unencrypted files.
    ///
    /// Ref: SECURITY_AUDIT.md #13 - Sessions rely on platform storage encryption
    pub fn export_session_json(&self, contact_id: String) -> Result<String, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Get session from HashMap
        let session = client
            .get_session(&contact_id)
            .ok_or(CryptoError::SessionNotFound)?;

        // Get Double Ratchet session
        let ratchet_session = session.messaging_session();

        // Serialize using existing method
        let serializable = ratchet_session.to_serializable();

        // Convert to JSON
        serde_json::to_string(&serializable).map_err(|_| CryptoError::SerializationFailed)
    }

    /// Import session from JSON (restore from Keychain)
    ///
    /// # Parameters
    /// - `contact_id`: Contact ID to restore session for
    /// - `session_json`: JSON string from export_session_json()
    ///
    /// # Returns
    /// Session ID of the restored session
    ///
    /// # Errors
    /// - `SerializationFailed`: Invalid JSON or unsupported version
    /// - Other crypto errors during deserialization
    pub fn import_session_json(
        &self,
        contact_id: String,
        session_json: String,
    ) -> Result<String, CryptoError> {
        use crate::crypto::messaging::double_ratchet::{DoubleRatchetSession, SerializableSession};

        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Parse JSON
        let serializable: SerializableSession =
            serde_json::from_str(&session_json).map_err(|_| CryptoError::SerializationFailed)?;

        // Deserialize using existing method (also validates version)
        let ratchet_session =
            DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(serializable)
                .map_err(|_| CryptoError::SerializationFailed)?;

        // Import into Client
        let session_id = client.import_session(&contact_id, ratchet_session);

        Ok(session_id)
    }

    /// Get list of all contact IDs with active sessions
    ///
    /// Used for session restore pagination - can load only recent sessions on app startup.
    ///
    /// # Returns
    /// Vector of contact IDs that have active sessions
    pub fn get_all_session_contact_ids(&self) -> Vec<String> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.active_contacts()
    }

    /// Initialize a session with a contact
    pub fn init_session(
        &self,
        contact_id: String,
        recipient_bundle: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let bundle_str =
            std::str::from_utf8(&recipient_bundle).map_err(|_| CryptoError::InvalidKeyData)?;

        let key_bundle: KeyBundle =
            serde_json::from_str(bundle_str).map_err(|_| CryptoError::InvalidKeyData)?;

        // Create X3DHPublicKeyBundle
        let public_bundle = X3DHPublicKeyBundle {
            identity_public: key_bundle.identity_public.clone(),
            signed_prekey_public: key_bundle.signed_prekey_public.clone(),
            signature: key_bundle.signature.clone(),
            verifying_key: key_bundle.verifying_key.clone(),
            suite_id: SuiteID::new(key_bundle.suite_id).map_err(|_| CryptoError::InvalidKeyData)?,
            one_time_prekey_public: key_bundle.one_time_prekey_public.clone(),
            one_time_prekey_id: key_bundle.one_time_prekey_id,
        };

        // Extract remote identity public key
        let remote_identity =
            ClassicSuiteProvider::kem_public_key_from_bytes(key_bundle.identity_public.clone());

        let one_time_prekey_id = key_bundle.one_time_prekey_id.unwrap_or(0);

        tracing::debug!(
            target: "crypto::uniffi",
            contact_id = %contact_id,
            remote_identity_len = key_bundle.identity_public.len(),
            "Initializing session (sender side)"
        );

        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Log local keys for debugging (sender side)
        let local_bundle = client
            .key_manager()
            .export_registration_bundle()
            .map_err(|_| CryptoError::InitializationFailed)?;

        tracing::debug!(
            target: "crypto::uniffi",
            contact_id = %contact_id,
            local_identity_len = local_bundle.identity_public.len(),
            remote_identity_len = key_bundle.identity_public.len(),
            remote_signed_prekey_len = key_bundle.signed_prekey_public.len(),
            verifying_key_len = key_bundle.verifying_key.len(),
            signature_len = key_bundle.signature.len(),
            suite_id = key_bundle.suite_id,
            "Initializing session (sender side)"
        );

        // Initialize the session (returns internal session_id which we ignore)
        client
            .init_session(
                &contact_id,
                &public_bundle,
                &remote_identity,
                one_time_prekey_id,
            )
            .map_err(|e| {
                tracing::error!(
                    target: "crypto::uniffi",
                    contact_id = %contact_id,
                    error = %e,
                    "init_session failed"
                );
                CryptoError::SessionInitializationFailed {
                    message: e.to_string(),
                }
            })?;

        // Return contact_id as the session identifier for Swift
        // Sessions are looked up by contact_id, not by the internal random session_id
        Ok(contact_id)
    }

    /// Initialize a receiving session (for responder) with first message
    ///
    /// Returns SessionInitResult with session_id and decrypted first message
    pub fn init_receiving_session(
        &self,
        contact_id: String,
        recipient_bundle: Vec<u8>,
        first_message: Vec<u8>,
    ) -> Result<SessionInitResult, CryptoError> {
        tracing::debug!("init_receiving_session called for contact: {}", contact_id);

        // Parse recipient bundle JSON
        let bundle_str =
            std::str::from_utf8(&recipient_bundle).map_err(|_| CryptoError::InvalidKeyData)?;

        let key_bundle: KeyBundle =
            serde_json::from_str(bundle_str).map_err(|_| CryptoError::InvalidKeyData)?;

        tracing::debug!("Parsed key bundle, suite_id: {}", key_bundle.suite_id);

        // Parse first message JSON
        let message_str =
            std::str::from_utf8(&first_message).map_err(|_| CryptoError::InvalidCiphertext)?;

        #[derive(Deserialize)]
        struct FirstMessage {
            ephemeral_public_key: Vec<u8>,
            message_number: u32,
            content: String, // Base64
            #[serde(default)]
            one_time_prekey_id: u32,
        }

        let first_msg: FirstMessage =
            serde_json::from_str(message_str).map_err(|_| CryptoError::InvalidCiphertext)?;

        // Decode base64 content
        let sealed_box = base64::engine::general_purpose::STANDARD
            .decode(&first_msg.content)
            .map_err(|_| CryptoError::InvalidCiphertext)?;

        tracing::debug!("Parsing sealed_box - total length: {}", sealed_box.len());

        // Extract nonce (first 12 bytes) and ciphertext (rest)
        if sealed_box.len() < 12 {
            return Err(CryptoError::InvalidCiphertext);
        }
        let nonce = sealed_box[..12].to_vec();
        let ciphertext = sealed_box[12..].to_vec();

        tracing::debug!(
            "Extracted components - nonce length: {}, ciphertext length: {}",
            nonce.len(),
            ciphertext.len()
        );

        // Convert ephemeral_public_key to [u8; 32]
        let dh_public_key: [u8; 32] = first_msg
            .ephemeral_public_key
            .clone()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyData)?;

        // Create EncryptedRatchetMessage
        let encrypted_first_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number: first_msg.message_number,
            ciphertext,
            nonce,
            previous_chain_length: 0,
            suite_id: key_bundle.suite_id,
        };

        // Extract keys for session initialization
        let remote_identity =
            ClassicSuiteProvider::kem_public_key_from_bytes(key_bundle.identity_public.clone());

        let remote_ephemeral =
            ClassicSuiteProvider::kem_public_key_from_bytes(first_msg.ephemeral_public_key.clone());

        tracing::debug!(
            target: "crypto::uniffi",
            contact_id = %contact_id,
            remote_identity_len = key_bundle.identity_public.len(),
            remote_ephemeral_len = first_msg.ephemeral_public_key.len(),
            dh_public_key_len = encrypted_first_message.dh_public_key.len(),
            "Initializing receiving session (receiver side)"
        );

        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Log local keys for debugging
        let local_bundle = client
            .key_manager()
            .export_registration_bundle()
            .map_err(|_| CryptoError::InitializationFailed)?;

        tracing::debug!(
            target: "crypto::uniffi",
            contact_id = %contact_id,
            local_identity_len = local_bundle.identity_public.len(),
            local_signed_prekey_len = local_bundle.signed_prekey_public.len(),
            remote_identity_len = key_bundle.identity_public.len(),
            remote_ephemeral_len = first_msg.ephemeral_public_key.len(),
            message_number = first_msg.message_number,
            "Initializing receiving session (receiver side)"
        );

        let (_internal_session_id, plaintext_bytes) = client
            .init_receiving_session_with_ephemeral(
                &contact_id,
                &remote_identity,
                &remote_ephemeral,
                &encrypted_first_message,
                first_msg.one_time_prekey_id,
            )
            .map_err(|e| {
                tracing::error!(
                    target: "crypto::uniffi",
                    contact_id = %contact_id,
                    error = %e,
                    remote_identity_len = key_bundle.identity_public.len(),
                    remote_ephemeral_len = first_msg.ephemeral_public_key.len(),
                    message_number = first_msg.message_number,
                    "init_receiving_session_with_ephemeral failed"
                );
                CryptoError::SessionInitializationFailed {
                    message: e.to_string(),
                }
            })?;

        // Convert plaintext bytes to UTF-8 string
        let decrypted_message =
            String::from_utf8(plaintext_bytes).map_err(|e| CryptoError::DecryptionFailed {
                message: format!("UTF-8 conversion failed: {}", e),
            })?;

        tracing::info!(
            "Session initialized, plaintext length: {}",
            decrypted_message.len()
        );

        // Return contact_id as session_id for Swift (sessions are looked up by contact_id)
        Ok(SessionInitResult {
            session_id: contact_id,
            decrypted_message,
        })
    }

    /// Encrypt a message for a session - returns wire format components
    pub fn encrypt_message(
        &self,
        session_id: String,
        plaintext: String,
    ) -> Result<EncryptedMessageComponents, CryptoError> {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Note: session_id from Swift is actually contact_id in our new API
        let contact_id = &session_id;

        let encrypted_message = client
            .encrypt_message(contact_id, plaintext.as_bytes())
            .map_err(|e| {
                tracing::error!(
                    target: "crypto::uniffi",
                    contact_id = %contact_id,
                    error = %e,
                    plaintext_len = plaintext.len(),
                    "encrypt_message failed"
                );
                CryptoError::EncryptionFailed {
                    message: e.to_string(),
                }
            })?;

        tracing::debug!(
            target: "crypto::uniffi",
            contact_id = %contact_id,
            dh_public_key_len = encrypted_message.dh_public_key.len(),
            message_number = encrypted_message.message_number,
            nonce_len = encrypted_message.nonce.len(),
            ciphertext_len = encrypted_message.ciphertext.len(),
            "Message encrypted"
        );

        // Create sealed box: nonce || ciphertext_with_tag
        let mut sealed_box = Vec::new();
        sealed_box.extend_from_slice(&encrypted_message.nonce);
        sealed_box.extend_from_slice(&encrypted_message.ciphertext);

        // Pop OTPK id for first message (message_number == 0), else 0
        let one_time_prekey_id = if encrypted_message.message_number == 0 {
            client.take_pending_otpk_id(contact_id)
        } else {
            0
        };

        Ok(EncryptedMessageComponents {
            ephemeral_public_key: encrypted_message.dh_public_key.to_vec(),
            message_number: encrypted_message.message_number,
            content: base64::engine::general_purpose::STANDARD.encode(&sealed_box),
            one_time_prekey_id,
        })
    }

    /// Decrypt a message from a session - accepts wire format components
    pub fn decrypt_message(
        &self,
        session_id: String,
        ephemeral_public_key: Vec<u8>,
        message_number: u32,
        content: String,
    ) -> Result<String, CryptoError> {
        // Decode base64 sealed box
        let sealed_box = base64::engine::general_purpose::STANDARD
            .decode(&content)
            .map_err(|_| CryptoError::InvalidCiphertext)?;

        // Extract nonce (first 12 bytes) and ciphertext (rest)
        if sealed_box.len() < 12 {
            return Err(CryptoError::InvalidCiphertext);
        }
        let nonce = sealed_box[..12].to_vec();
        let ciphertext = sealed_box[12..].to_vec();

        // Convert ephemeral_public_key to [u8; 32]
        let dh_public_key: [u8; 32] = ephemeral_public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyData)?;

        // Reconstruct EncryptedRatchetMessage
        let encrypted_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number,
            ciphertext,
            nonce,
            previous_chain_length: 0, // Not used by decryption
            suite_id: crate::config::Config::global().classic_suite_id,
        };

        // Note: session_id from Swift is actually contact_id in our new API
        let contact_id = &session_id;

        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let plaintext_bytes = client
            .decrypt_message(contact_id, &encrypted_message)
            .map_err(|e| {
                tracing::error!(
                    target: "crypto::uniffi",
                    contact_id = %contact_id,
                    message_number = message_number,
                    error = %e,
                    "decrypt_message failed"
                );
                CryptoError::DecryptionFailed {
                    message: e.to_string(),
                }
            })?;

        String::from_utf8(plaintext_bytes).map_err(|e| CryptoError::DecryptionFailed {
            message: format!("UTF-8 conversion failed: {}", e),
        })
    }

    /// Deletes a session for a contact, allowing a new one to be created.
    pub fn remove_session(&self, contact_id: String) -> bool {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.remove_session(&contact_id)
    }

    /// Returns the total number of available prekeys (current + archived).
    ///
    /// The Swift layer should call `uploadPreKeys` when this drops below a
    /// threshold (e.g. < 5) to ensure incoming sessions can always be
    /// established.
    pub fn prekeys_available_count(&self) -> u32 {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = client.key_manager().old_prekeys_count();
        // +1 for the current prekey (always present after initialization)
        (old + 1) as u32
    }

    /// Generate `count` fresh one-time prekeys and return (key_id, public_key_bytes) pairs.
    /// Caller MUST upload these to the server via KeyService.uploadPreKeys.
    pub fn generate_one_time_prekeys(&self, count: u32) -> Result<Vec<OtpkPair>, CryptoError> {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pairs = client.generate_one_time_prekeys(count).map_err(|e| {
            tracing::error!(target: "crypto::uniffi", error = %e, "generate_one_time_prekeys failed");
            CryptoError::InitializationFailed
        })?;
        Ok(pairs
            .into_iter()
            .map(|(key_id, public_key)| OtpkPair { key_id, public_key })
            .collect())
    }

    /// How many one-time prekeys are stored locally (not yet consumed).
    pub fn one_time_prekey_count(&self) -> u32 {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.one_time_prekey_count() as u32
    }

    /// Export all locally stored OTPKs as a JSON string for Keychain persistence.
    /// Call this after generating and uploading OTPKs to keep Keychain in sync.
    pub fn export_one_time_prekeys_json(&self) -> Result<String, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let records: Vec<OtpkRecord> = client
            .export_one_time_prekeys()
            .into_iter()
            .map(|(key_id, private_key, public_key)| OtpkRecord {
                key_id,
                private_key,
                public_key,
            })
            .collect();
        serde_json::to_string(&records).map_err(|_| CryptoError::SerializationFailed)
    }

    /// Import previously persisted OTPKs from a JSON string back into the core.
    /// Call this after restoring the core from Keychain to ensure OTPK continuity.
    pub fn import_one_time_prekeys_json(&self, json: String) -> Result<(), CryptoError> {
        let records: Vec<OtpkRecord> =
            serde_json::from_str(&json).map_err(|_| CryptoError::SerializationFailed)?;
        let keys: Vec<(u32, Vec<u8>, Vec<u8>)> = records
            .into_iter()
            .map(|r| (r.key_id, r.private_key, r.public_key))
            .collect();
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.import_one_time_prekeys(keys);
        Ok(())
    }

    /// Set the local user ID — must be called after login/registration so AAD binds
    /// the correct sender identity to every encrypted message.
    pub fn set_local_user_id(&self, user_id: String) {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.set_local_user_id(user_id);
    }

    /// Mix a ML-KEM-768 shared secret into an existing session's root key (PQXDH).
    ///
    /// Call after init_session (sender) or init_receiving_session (receiver) with
    /// the kem_shared_secret from mlkem768_encapsulate / mlkem768_decapsulate.
    pub fn apply_pq_contribution(
        &self,
        contact_id: String,
        kem_shared_secret: Vec<u8>,
    ) -> Result<(), CryptoError> {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client
            .apply_pq_contribution_to_session(&contact_id, &kem_shared_secret)
            .map_err(|e| CryptoError::SessionInitializationFailed { message: e })
    }
}

/// Create a new CryptoCore instance (exported via UDL)
/// UniFFI automatically wraps this in Arc<>, so we return Arc<ClassicCryptoCore>
pub fn create_crypto_core() -> Result<Arc<ClassicCryptoCore>, CryptoError> {
    // Инициализировать конфигурацию при первом вызове
    let _ = crate::config::Config::init();

    let client = ClassicClient::<ClassicSuiteProvider>::new()
        .map_err(|_| CryptoError::InitializationFailed)?;

    Ok(Arc::new(ClassicCryptoCore {
        inner: Mutex::new(client),
    }))
}

/// Create a CryptoCore instance from existing private keys (exported via UDL)
/// Used to restore cryptographic state from secure storage (e.g., iOS Keychain)
pub fn create_crypto_core_from_keys_json(
    keys_json: String,
) -> Result<Arc<ClassicCryptoCore>, CryptoError> {
    // Инициализировать конфигурацию при первом вызове
    let _ = crate::config::Config::init();

    // Parse JSON
    let private_keys: PrivateKeysJson =
        serde_json::from_str(&keys_json).map_err(|_| CryptoError::SerializationFailed)?;

    // Decode base64 to bytes
    use base64::Engine;
    let identity_secret = base64::engine::general_purpose::STANDARD
        .decode(&private_keys.identity_secret)
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let signing_secret = base64::engine::general_purpose::STANDARD
        .decode(&private_keys.signing_secret)
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let prekey_secret = base64::engine::general_purpose::STANDARD
        .decode(&private_keys.signed_prekey_secret)
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let prekey_signature = base64::engine::general_purpose::STANDARD
        .decode(&private_keys.prekey_signature)
        .map_err(|_| CryptoError::InvalidKeyData)?;

    // Create client from keys
    let client = ClassicClient::<ClassicSuiteProvider>::from_keys(
        identity_secret,
        signing_secret,
        prekey_secret,
        prekey_signature,
    )
    .map_err(|_| CryptoError::InitializationFailed)?;

    tracing::debug!(target: "crypto::uniffi", "CryptoCore restored from saved keys");

    Ok(Arc::new(ClassicCryptoCore {
        inner: Mutex::new(client),
    }))
}

// ============================================================================
// Invite Crypto Functions
// ============================================================================

use crate::crypto::invite_crypto;

/// Generate ephemeral X25519 keypair for a single invite
/// Returns a fresh keypair. Secret key should be discarded after invite creation.
pub fn generate_ephemeral_keypair() -> Result<EphemeralKeyPair, CryptoError> {
    let keypair = invite_crypto::generate_ephemeral_keypair()?;
    Ok(EphemeralKeyPair {
        secret_key: keypair.secret_key,
        public_key: keypair.public_key,
    })
}

/// Sign invite data with Ed25519 identity key
/// Creates a detached signature proving authenticity.
pub fn sign_invite_data(
    data: String,
    identity_secret_key: Vec<u8>,
) -> Result<InviteSignature, CryptoError> {
    let sig = invite_crypto::sign_invite_data(&data, &identity_secret_key)?;
    Ok(InviteSignature {
        signature: sig.signature,
    })
}

/// Verify invite signature with Ed25519 verifying key
/// Returns true if signature is valid, false otherwise.
pub fn verify_invite_signature(
    data: String,
    signature: Vec<u8>,
    verifying_key: Vec<u8>,
) -> Result<bool, CryptoError> {
    Ok(invite_crypto::verify_invite_signature(
        &data,
        &signature,
        &verifying_key,
    )?)
}

/// Derive verifying (public) key from identity secret key
/// Used for debugging signature verification issues.
pub fn derive_verifying_key_from_secret(
    identity_secret_key: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    Ok(invite_crypto::derive_verifying_key_from_secret(
        &identity_secret_key,
    )?)
}

// ============================================================================
// Account Recovery Bindings (BIP39 + SLIP-0010 Ed25519)
// ============================================================================

use crate::crypto::recovery;

/// Ed25519 keypair derived from a recovery seed (output of mnemonic_to_seed).
pub struct RecoveryKeypair {
    /// 32-byte Ed25519 private key — keep in memory only, never persist.
    pub private_key: Vec<u8>,
    /// 32-byte Ed25519 public key — sent to server during SetRecoveryKey.
    pub public_key: Vec<u8>,
}

/// Generate a BIP39 mnemonic with the given word count (12 or 24).
pub fn generate_mnemonic(word_count: u8) -> Result<String, CryptoError> {
    recovery::generate_mnemonic(word_count).map_err(|_| CryptoError::InitializationFailed)
}

/// Validate BIP39 checksum and word membership.
pub fn validate_mnemonic(mnemonic: String) -> bool {
    recovery::validate_mnemonic(&mnemonic)
}

/// Convert a BIP39 mnemonic to a 64-byte seed via PBKDF2-HMAC-SHA512 (no passphrase).
pub fn mnemonic_to_seed(mnemonic: String) -> Result<Vec<u8>, CryptoError> {
    let seed = recovery::mnemonic_to_seed(&mnemonic).map_err(|_| CryptoError::InvalidKeyData)?;
    Ok(seed.to_vec())
}

/// Derive an Ed25519 recovery keypair from a 64-byte BIP39 seed.
/// Path: m/44'/0'/0'/0'/0' (SLIP-0010, all hardened — required for Ed25519).
pub fn derive_recovery_keypair(seed: Vec<u8>) -> Result<RecoveryKeypair, CryptoError> {
    let kp = recovery::derive_recovery_keypair(&seed).map_err(|_| CryptoError::InvalidKeyData)?;
    Ok(RecoveryKeypair {
        private_key: kp.private_key.to_vec(),
        public_key: kp.public_key.to_vec(),
    })
}

/// Sign a message string with a 32-byte Ed25519 private key. Returns 64 bytes.
/// Used for SetRecoveryKey.setup_signature and RecoverAccount.recovery_signature.
pub fn sign_recovery_challenge(
    private_key: Vec<u8>,
    message: String,
) -> Result<Vec<u8>, CryptoError> {
    let key: [u8; 32] = private_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let sig = recovery::sign_recovery_challenge(&key, &message)
        .map_err(|_| CryptoError::InvalidKeyData)?;
    Ok(sig.to_vec())
}

/// Verify a 64-byte Ed25519 signature over a message using a 32-byte public key.
pub fn verify_recovery_signature(public_key: Vec<u8>, message: String, signature: Vec<u8>) -> bool {
    let Ok(pk): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(sig): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    recovery::verify_recovery_signature(&pk, &message, &sig)
}

// ============================================================================
// Traffic Protection Bindings
// ============================================================================

use crate::traffic_protection::{
    CoverTrafficConfig as RustCoverTrafficConfig, CoverTrafficManager,
    EnergyMetrics as RustEnergyMetrics, TimingConfig as RustTimingConfig,
};

// UniFFI-compatible structs (must match UDL dictionaries)
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    pub enabled: bool,
    pub battery_level_threshold: f32,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
    pub message_size: u64,
    pub coalesce_with_real_messages: bool,
    pub coalesce_window_ms: u64,
}

impl From<CoverTrafficConfig> for RustCoverTrafficConfig {
    fn from(config: CoverTrafficConfig) -> Self {
        Self {
            enabled: config.enabled,
            battery_level_threshold: config.battery_level_threshold,
            min_interval_ms: config.min_interval_ms,
            max_interval_ms: config.max_interval_ms,
            message_size: config.message_size as usize,
            coalesce_with_real_messages: config.coalesce_with_real_messages,
            coalesce_window_ms: config.coalesce_window_ms,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnergyMetrics {
    pub dummies_sent: u64,
    pub coalesced_count: u64,
    pub battery_skipped: u64,
}

impl From<&RustEnergyMetrics> for EnergyMetrics {
    fn from(metrics: &RustEnergyMetrics) -> Self {
        Self {
            dummies_sent: metrics.dummies_sent,
            coalesced_count: metrics.coalesced_count,
            battery_skipped: metrics.battery_skipped,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimingConfig {
    pub heartbeat_interval_sec: u64,
    pub heartbeat_jitter_ms: u64,
    pub max_send_delay_ms: u64,
    pub enabled: bool,
    pub battery_aware: bool,
}

impl From<TimingConfig> for RustTimingConfig {
    fn from(config: TimingConfig) -> Self {
        Self {
            heartbeat_interval_sec: config.heartbeat_interval_sec,
            heartbeat_jitter_ms: config.heartbeat_jitter_ms,
            max_send_delay_ms: config.max_send_delay_ms,
            enabled: config.enabled,
            battery_aware: config.battery_aware,
        }
    }
}

/// Traffic Protection Manager (UniFFI wrapper)
///
/// Manages cover traffic generation with energy-efficient strategies.
pub struct TrafficProtectionManager {
    inner: Mutex<CoverTrafficManager>,
}

impl TrafficProtectionManager {
    /// Create a new TrafficProtectionManager
    pub fn new(config: CoverTrafficConfig) -> Self {
        let rust_config: RustCoverTrafficConfig = config.into();
        Self {
            inner: Mutex::new(CoverTrafficManager::new(rust_config)),
        }
    }

    /// Update battery level (0.0-1.0)
    ///
    /// Should be called from iOS/Android when battery level changes.
    pub fn update_battery_level(&self, level: f32) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .update_battery_level(level);
    }

    /// Record that a real message was sent (for coalescing)
    pub fn record_real_message_sent(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_real_message_sent();
    }

    /// Check if a dummy message should be sent now
    pub fn should_send_dummy(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .should_send_dummy()
    }

    /// Generate a dummy message
    ///
    /// Call this after should_send_dummy() returns true.
    pub fn generate_dummy(&self) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generate_dummy()
    }

    /// Get current energy metrics
    pub fn get_metrics(&self) -> EnergyMetrics {
        let manager = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        manager.metrics().into()
    }

    /// Reset metrics
    pub fn reset_metrics(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reset_metrics();
    }

    /// Get current adaptive interval (for debugging/monitoring)
    pub fn current_interval_ms(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .current_interval_ms()
    }

    /// Check if currently active (enabled and battery sufficient)
    pub fn is_currently_active(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_currently_active()
    }
}

// Namespace functions (exported via UDL)

/// Generate a dummy message of specified size
pub fn generate_dummy_message(size: u64) -> Vec<u8> {
    crate::traffic_protection::generate_dummy_message(size as usize)
}

/// Check if data is a dummy message
pub fn is_dummy_message(data: Vec<u8>) -> bool {
    crate::traffic_protection::is_dummy_message(&data)
}

/// Generate jittered interval in milliseconds
pub fn jittered_interval_ms(base_ms: u64, jitter_ms: u64) -> u64 {
    crate::traffic_protection::jittered_interval(base_ms, jitter_ms).as_millis() as u64
}

/// Generate random send delay in milliseconds
pub fn random_send_delay_ms(max_delay_ms: u64) -> u64 {
    crate::traffic_protection::random_send_delay(max_delay_ms).as_millis() as u64
}

/// Generate heartbeat interval with jitter in milliseconds
pub fn heartbeat_interval_ms(base_interval_sec: u64) -> u64 {
    crate::traffic_protection::heartbeat_interval(base_interval_sec).as_millis() as u64
}

/// Generate battery-aware jittered interval in milliseconds
pub fn battery_aware_jitter_ms(base_ms: u64, max_jitter_ms: u64, battery_level: f32) -> u64 {
    crate::traffic_protection::battery_aware_jitter(base_ms, max_jitter_ms, battery_level)
        .as_millis() as u64
}

/// Get recommended send delay based on priority and battery
pub fn recommended_send_delay_ms(is_high_priority: bool, battery_level: f32) -> u64 {
    crate::traffic_protection::recommended_send_delay(is_high_priority, battery_level).as_millis()
        as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to convert RegistrationBundleJson to KeyBundle format
    fn convert_bundle_for_init(bundle_json: &str) -> Vec<u8> {
        use base64::Engine;

        #[derive(serde::Deserialize)]
        struct RegBundle {
            identity_public: String,
            signed_prekey_public: String,
            signature: String,
            verifying_key: String,
            suite_id: String,
        }

        let bundle: RegBundle = serde_json::from_str(bundle_json).unwrap();

        // Convert base64 to bytes
        let identity_pub = base64::engine::general_purpose::STANDARD
            .decode(&bundle.identity_public)
            .unwrap();
        let signed_prekey = base64::engine::general_purpose::STANDARD
            .decode(&bundle.signed_prekey_public)
            .unwrap();
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&bundle.signature)
            .unwrap();
        let verifying_key = base64::engine::general_purpose::STANDARD
            .decode(&bundle.verifying_key)
            .unwrap();
        let suite_id: u16 = bundle.suite_id.parse().unwrap();

        // Create KeyBundle and serialize it properly
        let key_bundle = KeyBundle {
            identity_public: identity_pub,
            signed_prekey_public: signed_prekey,
            signature,
            verifying_key,
            suite_id,
        };

        serde_json::to_vec(&key_bundle).unwrap()
    }

    /// Test that verifies session_id returned from init_session is the contact_id
    /// This ensures the bug where random UUID was returned is fixed
    #[test]
    fn test_init_session_returns_contact_id() {
        let alice = create_crypto_core().unwrap();
        let bob = create_crypto_core().unwrap();

        // Get Bob's registration bundle and convert it
        let bob_bundle_json = bob.export_registration_bundle_json().unwrap();
        let bob_bundle_bytes = convert_bundle_for_init(&bob_bundle_json);

        // Alice initializes session with Bob
        let contact_id = "bob_user_id_123".to_string();
        let session_id = alice
            .init_session(contact_id.clone(), bob_bundle_bytes)
            .unwrap();

        // CRITICAL: session_id should equal contact_id
        assert_eq!(
            session_id, contact_id,
            "init_session must return contact_id as session_id for Swift compatibility"
        );
    }

    /// Test full end-to-end encryption/decryption flow
    /// Verifies that sessions are created consistently and messages can be exchanged
    #[test]
    fn test_full_e2e_encryption_flow() {
        let alice = create_crypto_core().unwrap();
        let bob = create_crypto_core().unwrap();

        // Get registration bundles and convert them
        let alice_bundle_json = alice.export_registration_bundle_json().unwrap();
        let alice_bundle_bytes = convert_bundle_for_init(&alice_bundle_json);

        let bob_bundle_json = bob.export_registration_bundle_json().unwrap();
        let bob_bundle_bytes = convert_bundle_for_init(&bob_bundle_json);

        // Alice initializes session with Bob
        let alice_to_bob_session = alice
            .init_session("bob_user_id".to_string(), bob_bundle_bytes)
            .unwrap();

        assert_eq!(
            alice_to_bob_session, "bob_user_id",
            "Alice's session_id for Bob should be bob's user_id"
        );

        // Alice encrypts a message for Bob
        let plaintext = "Hello Bob!".to_string();
        let encrypted = alice
            .encrypt_message(alice_to_bob_session.clone(), plaintext.clone())
            .unwrap();

        // Verify encrypted message has required components
        assert!(
            !encrypted.ephemeral_public_key.is_empty(),
            "Ephemeral key should not be empty"
        );
        assert!(!encrypted.content.is_empty(), "Content should not be empty");
        assert_eq!(
            encrypted.message_number, 0,
            "First message should have message_number 0"
        );

        // Bob initializes receiving session with Alice's first message
        let first_msg_json = serde_json::json!({
            "ephemeral_public_key": encrypted.ephemeral_public_key,
            "message_number": encrypted.message_number,
            "content": encrypted.content
        });
        let first_msg_bytes = serde_json::to_vec(&first_msg_json).unwrap();

        let bob_session_result = bob
            .init_receiving_session(
                "alice_user_id".to_string(),
                alice_bundle_bytes,
                first_msg_bytes,
            )
            .unwrap();

        // CRITICAL: Bob's session_id should be alice_user_id
        assert_eq!(
            bob_session_result.session_id, "alice_user_id",
            "Bob's session_id for Alice should be alice's user_id"
        );

        // First message should be decrypted automatically
        assert_eq!(
            bob_session_result.decrypted_message, plaintext,
            "First message should be decrypted correctly by init_receiving_session"
        );

        // Bob encrypts a reply
        let reply_plaintext = "Hi Alice!".to_string();
        let reply_encrypted = bob
            .encrypt_message(
                bob_session_result.session_id.clone(),
                reply_plaintext.clone(),
            )
            .unwrap();

        assert_eq!(
            reply_encrypted.message_number, 0,
            "Bob's first message should also have message_number 0"
        );

        // Alice decrypts Bob's reply
        let decrypted_reply = alice
            .decrypt_message(
                alice_to_bob_session,
                reply_encrypted.ephemeral_public_key,
                reply_encrypted.message_number,
                reply_encrypted.content,
            )
            .unwrap();

        assert_eq!(
            decrypted_reply, reply_plaintext,
            "Alice should decrypt Bob's reply correctly"
        );
    }

    /// Test that encryption fails with proper error when session doesn't exist
    #[test]
    fn test_encrypt_without_session_fails() {
        let alice = create_crypto_core().unwrap();

        let result =
            alice.encrypt_message("nonexistent_user".to_string(), "test message".to_string());

        assert!(
            result.is_err(),
            "Encryption should fail when session doesn't exist"
        );
        match result {
            Err(CryptoError::EncryptionFailed { .. }) => {} // Expected
            _ => panic!("Should return EncryptionFailed error"),
        }
    }

    /// Test session attribute consistency
    /// Verifies that both participants have matching session attributes
    #[test]
    fn test_session_attribute_consistency() {
        let alice = create_crypto_core().unwrap();
        let bob = create_crypto_core().unwrap();

        let bob_bundle_json = bob.export_registration_bundle_json().unwrap();
        let alice_bundle_json = alice.export_registration_bundle_json().unwrap();

        // Convert bundles to KeyBundle format
        let bob_bundle_bytes = convert_bundle_for_init(&bob_bundle_json);
        let alice_bundle_bytes = convert_bundle_for_init(&alice_bundle_json);

        // Alice initializes session
        let alice_session_id = alice
            .init_session("bob_contact".to_string(), bob_bundle_bytes)
            .unwrap();

        // Alice sends first message
        let msg1 = alice
            .encrypt_message(alice_session_id.clone(), "Test message".to_string())
            .unwrap();

        // Bob initializes receiving session
        let first_msg_json = serde_json::json!({
            "ephemeral_public_key": msg1.ephemeral_public_key,
            "message_number": msg1.message_number,
            "content": msg1.content
        });

        let bob_session_result = bob
            .init_receiving_session(
                "alice_contact".to_string(),
                alice_bundle_bytes,
                serde_json::to_vec(&first_msg_json).unwrap(),
            )
            .unwrap();

        // Verify session IDs are the contact IDs
        assert_eq!(alice_session_id, "bob_contact");
        assert_eq!(bob_session_result.session_id, "alice_contact");

        // Both should be able to continue communication
        let msg2 = bob
            .encrypt_message(bob_session_result.session_id.clone(), "Reply".to_string())
            .unwrap();

        let decrypted = alice
            .decrypt_message(
                alice_session_id,
                msg2.ephemeral_public_key,
                msg2.message_number,
                msg2.content,
            )
            .unwrap();

        assert_eq!(decrypted, "Reply");
    }

    /// Simple test using Client API directly (bypassing UniFFI)
    #[test]
    fn test_direct_client_api_e2e() {
        use crate::crypto::client_api::Client;
        use crate::crypto::handshake::x3dh::X3DHProtocol;
        use crate::crypto::messaging::double_ratchet::DoubleRatchetSession;
        use crate::crypto::suites::classic::ClassicSuiteProvider;

        type TestClient = Client<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >;

        // Create Alice and Bob
        let mut alice = TestClient::new().unwrap();
        let mut bob = TestClient::new().unwrap();

        eprintln!("\n[DIRECT TEST] Creating clients...");

        // Get bundles
        let alice_bundle = alice.key_manager().export_registration_bundle().unwrap();
        let bob_bundle = bob.key_manager().export_registration_bundle().unwrap();

        eprintln!(
            "[DIRECT TEST] Alice identity: {}",
            hex::encode(&alice_bundle.identity_public)
        );
        eprintln!(
            "[DIRECT TEST] Bob identity: {}",
            hex::encode(&bob_bundle.identity_public)
        );

        // Alice creates session with Bob
        let alice_identity_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(alice_bundle.identity_public.clone());
        let bob_identity_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(bob_bundle.identity_public.clone());

        alice
            .init_session("bob", &bob_bundle, &bob_identity_pub)
            .unwrap();
        eprintln!("[DIRECT TEST] Alice created session with Bob");

        // Alice encrypts message
        let plaintext1 = b"Hello Bob!";
        let encrypted1 = alice.encrypt_message("bob", plaintext1).unwrap();
        eprintln!(
            "[DIRECT TEST] Alice encrypted message, dh_key: {}",
            hex::encode(&encrypted1.dh_public_key)
        );

        // Bob creates receiving session
        let alice_ephemeral_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(encrypted1.dh_public_key.to_vec());

        let (_session_id, decrypted1) = bob
            .init_receiving_session_with_ephemeral(
                "alice",
                &alice_identity_pub,
                &alice_ephemeral_pub,
                &encrypted1,
            )
            .unwrap();

        eprintln!("[DIRECT TEST] Bob received and decrypted!");
        assert_eq!(decrypted1, plaintext1);
        eprintln!("[DIRECT TEST] ✅ Direct Client API test PASSED!");
    }

    /// Test that mimics UniFFI flow but uses EncryptedMessageComponents
    #[test]
    fn test_uniffi_flow_with_components() {
        use crate::crypto::client_api::Client;
        use crate::crypto::handshake::x3dh::X3DHProtocol;
        use crate::crypto::messaging::double_ratchet::{
            DoubleRatchetSession, EncryptedRatchetMessage,
        };
        use crate::crypto::suites::classic::ClassicSuiteProvider;

        type TestClient = Client<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >;

        // Create Alice and Bob
        let mut alice = TestClient::new().unwrap();
        let mut bob = TestClient::new().unwrap();

        eprintln!("\n[UNIFFI FLOW TEST] Creating clients...");

        // Get bundles
        let alice_bundle = alice.key_manager().export_registration_bundle().unwrap();
        let bob_bundle = bob.key_manager().export_registration_bundle().unwrap();

        let alice_identity_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(alice_bundle.identity_public.clone());
        let bob_identity_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(bob_bundle.identity_public.clone());

        // Alice creates session with Bob
        alice
            .init_session("bob", &bob_bundle, &bob_identity_pub)
            .unwrap();

        // Alice encrypts message
        let plaintext1 = b"Hello Bob!";
        let encrypted1 = alice.encrypt_message("bob", plaintext1).unwrap();

        eprintln!("[UNIFFI FLOW TEST] Alice encrypted:");
        eprintln!(
            "  dh_public_key: {}",
            hex::encode(&encrypted1.dh_public_key)
        );
        eprintln!("  nonce len: {}", encrypted1.nonce.len());
        eprintln!("  ciphertext len: {}", encrypted1.ciphertext.len());
        eprintln!("  suite_id: {}", encrypted1.suite_id);

        // Mimic UniFFI: create sealed box
        let mut sealed_box = Vec::new();
        sealed_box.extend_from_slice(&encrypted1.nonce);
        sealed_box.extend_from_slice(&encrypted1.ciphertext);

        eprintln!("[UNIFFI FLOW TEST] Sealed box length: {}", sealed_box.len());

        // Mimic UniFFI: extract nonce and ciphertext
        let nonce_parsed = sealed_box[..12].to_vec();
        let ciphertext_parsed = sealed_box[12..].to_vec();

        eprintln!("[UNIFFI FLOW TEST] After parsing:");
        eprintln!("  nonce len: {}", nonce_parsed.len());
        eprintln!("  ciphertext len: {}", ciphertext_parsed.len());

        // Mimic UniFFI: reconstruct EncryptedRatchetMessage
        let reconstructed_message = EncryptedRatchetMessage {
            dh_public_key: encrypted1.dh_public_key,
            message_number: encrypted1.message_number,
            ciphertext: ciphertext_parsed,
            nonce: nonce_parsed,
            previous_chain_length: 0,
            suite_id: alice_bundle.suite_id.as_u16(), // Use Alice's bundle suite_id
        };

        eprintln!("[UNIFFI FLOW TEST] Reconstructed message:");
        eprintln!(
            "  dh_public_key: {}",
            hex::encode(&reconstructed_message.dh_public_key)
        );
        eprintln!("  suite_id: {}", reconstructed_message.suite_id);

        // Bob creates receiving session with RECONSTRUCTED message
        let alice_ephemeral_pub = ClassicSuiteProvider::kem_public_key_from_bytes(
            reconstructed_message.dh_public_key.to_vec(),
        );

        let result = bob.init_receiving_session_with_ephemeral(
            "alice",
            &alice_identity_pub,
            &alice_ephemeral_pub,
            &reconstructed_message,
        );

        match &result {
            Ok(_) => eprintln!("[UNIFFI FLOW TEST] ✅ PASSED!"),
            Err(e) => eprintln!("[UNIFFI FLOW TEST] ❌ FAILED: {}", e),
        }

        let (_session_id, decrypted1) = result.unwrap();
        assert_eq!(decrypted1, plaintext1);
    }
}

// ============================================================================
// Device-Based Authentication (PoW + Device ID)
// ============================================================================

/// Compute Argon2id-based Proof of Work
/// UniFFI wrapper - accepts owned String instead of &str
pub fn compute_pow(challenge: String, difficulty: u32) -> PowSolution {
    crate::pow::compute_pow(&challenge, difficulty)
}

/// Compute PoW with progress callback
/// UniFFI wrapper - accepts owned String instead of &str
pub fn compute_pow_with_progress(
    challenge: String,
    difficulty: u32,
    progress_callback: Option<Box<dyn PowProgressCallback>>,
) -> PowSolution {
    crate::pow::compute_pow_with_progress(&challenge, difficulty, progress_callback)
}

/// Verify PoW solution (server-side)  
/// UniFFI wrapper - accepts owned String and PowSolution
pub fn verify_pow(challenge: String, solution: PowSolution, required_difficulty: u32) -> bool {
    crate::pow::verify_pow(&challenge, &solution, required_difficulty)
}

/// Derive device ID from identity public key
/// UniFFI wrapper - accepts owned Vec<u8> instead of &[u8]
pub fn derive_device_id(identity_public_key: Vec<u8>) -> String {
    crate::device_id::derive_device_id(&identity_public_key)
}

/// Format federated identifier
/// UniFFI wrapper - accepts owned Strings
pub fn format_federated_id(device_id: String, server_hostname: String) -> String {
    crate::device_id::format_federated_id(&device_id, &server_hostname)
}

// ── Post-Quantum KEM Namespace Functions ─────────────────────────────────────

/// Generate an ML-KEM-768 keypair for registration/upload to key server.
///
/// Returns (public_key=1184 bytes, secret_key=2400 bytes).
/// Store secret_key securely in Keychain; upload public_key as KyberSignedPreKey.
pub fn mlkem768_keygen() -> Result<MLKEMKeyPair, CryptoError> {
    crate::crypto::pq_x3dh::mlkem768_keygen()
        .map(|kp| MLKEMKeyPair {
            public_key: kp.public_key,
            secret_key: kp.secret_key,
        })
        .map_err(|_e| CryptoError::InitializationFailed)
}

/// Encapsulate to a recipient's ML-KEM-768 public key (sender side PQXDH).
///
/// - `public_key`: recipient's Kyber SPK public key (1184 bytes) from their PreKeyBundle
/// - Returns: ciphertext (include in PreKeySignalMessage.kem_ciphertext) + shared_secret
///   (pass to ClassicCryptoCore.apply_pq_contribution)
pub fn mlkem768_encapsulate(public_key: Vec<u8>) -> Result<MLKEMEncapsulation, CryptoError> {
    crate::crypto::pq_x3dh::mlkem768_encapsulate(&public_key)
        .map(|enc| MLKEMEncapsulation {
            ciphertext: enc.ciphertext,
            shared_secret: enc.shared_secret,
        })
        .map_err(|e| CryptoError::EncryptionFailed { message: e })
}

/// Decapsulate a received ML-KEM-768 ciphertext (receiver side PQXDH).
///
/// - `secret_key`: our Kyber SPK secret key from Keychain (2400 bytes)
/// - `ciphertext`: from PreKeySignalMessage.kem_ciphertext (1088 bytes)
/// - Returns: shared_secret (pass to ClassicCryptoCore.apply_pq_contribution)
pub fn mlkem768_decapsulate(
    secret_key: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    crate::crypto::pq_x3dh::mlkem768_decapsulate(&secret_key, &ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed { message: e })
}
