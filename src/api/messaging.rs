// API для отправки и получения сообщений

use crate::crypto::client_api::Client;
use crate::crypto::handshake::KeyAgreement;
use crate::crypto::handshake::x3dh::X3DHProtocol;
use crate::crypto::messaging::double_ratchet::{DoubleRatchetSession, EncryptedRatchetMessage};
use crate::crypto::{CryptoProvider, SuiteID};
use crate::utils::error::{ConstructError, Result};
use serde::{Deserialize, Serialize};

/// Зашифрованное сообщение для передачи
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub session_id: String,
    pub ciphertext: Vec<u8>,
    pub dh_public_key: [u8; 32],
    pub nonce: Vec<u8>,
    pub message_number: u32,
    pub previous_chain_length: u32,
    pub suite_id: u16,
}

impl From<EncryptedRatchetMessage> for EncryptedMessage {
    fn from(msg: EncryptedRatchetMessage) -> Self {
        Self {
            session_id: String::new(), // Will be set by caller
            ciphertext: msg.ciphertext,
            dh_public_key: msg.dh_public_key,
            nonce: msg.nonce,
            message_number: msg.message_number,
            previous_chain_length: msg.previous_chain_length,
            suite_id: msg.suite_id,
        }
    }
}

impl From<EncryptedMessage> for EncryptedRatchetMessage {
    fn from(msg: EncryptedMessage) -> Self {
        Self {
            ciphertext: msg.ciphertext,
            dh_public_key: msg.dh_public_key,
            nonce: msg.nonce,
            message_number: msg.message_number,
            previous_chain_length: msg.previous_chain_length,
            suite_id: msg.suite_id,
        }
    }
}

/// Отправить зашифрованное сообщение
pub fn encrypt_message<P: CryptoProvider>(
    client: &mut Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>>,
    contact_id: &str,
    plaintext: &str,
) -> Result<EncryptedMessage>
where
    X3DHProtocol<P>:
        KeyAgreement<P, PublicKeyBundle = crate::crypto::handshake::x3dh::X3DHPublicKeyBundle>,
    <X3DHProtocol<P> as KeyAgreement<P>>::SharedSecret: AsRef<[u8]>,
{
    let encrypted = client
        .encrypt_message(contact_id, plaintext.as_bytes())
        .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::Other(e)))?;

    let mut msg: EncryptedMessage = encrypted.into();
    msg.session_id = contact_id.to_string();
    Ok(msg)
}

/// Получить и расшифровать сообщение
pub fn decrypt_message<P: CryptoProvider>(
    client: &mut Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>>,
    contact_id: &str,
    encrypted: EncryptedMessage,
) -> Result<String>
where
    X3DHProtocol<P>:
        KeyAgreement<P, PublicKeyBundle = crate::crypto::handshake::x3dh::X3DHPublicKeyBundle>,
    <X3DHProtocol<P> as KeyAgreement<P>>::SharedSecret: AsRef<[u8]>,
{
    let ratchet_msg: EncryptedRatchetMessage = encrypted.into();

    let plaintext = client
        .decrypt_message(contact_id, &ratchet_msg)
        .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::Other(e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| ConstructError::SerializationError(format!("Invalid UTF-8: {}", e)))
}

/// Инициализировать сессию с контактом (отправитель)
pub fn init_session<P: CryptoProvider>(
    client: &mut Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>>,
    contact_id: &str,
    remote_bundle: &crate::api::crypto::KeyBundle,
) -> Result<String>
where
    X3DHProtocol<P>:
        KeyAgreement<P, PublicKeyBundle = crate::crypto::handshake::x3dh::X3DHPublicKeyBundle>,
    <X3DHProtocol<P> as KeyAgreement<P>>::SharedSecret: AsRef<[u8]>,
{
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;

    let bundle_data = X3DHPublicKeyBundle {
        identity_public: remote_bundle.identity_public.clone(),
        signed_prekey_public: remote_bundle.signed_prekey_public.clone(),
        signature: remote_bundle.signature.clone(),
        verifying_key: remote_bundle.verifying_key.clone(),
        suite_id: SuiteID::new(remote_bundle.suite_id)
            .map_err(|e| ConstructError::ValidationError(format!("Invalid suite_id: {}", e)))?,
        one_time_prekey_public: None,
        one_time_prekey_id: None,
        spk_uploaded_at: 0,
        spk_rotation_epoch: 0,
        kyber_spk_uploaded_at: 0,
        kyber_spk_rotation_epoch: 0,
    };

    let remote_identity = P::kem_public_key_from_bytes(bundle_data.identity_public.clone());
    let public_bundle = &bundle_data as &<X3DHProtocol<P> as KeyAgreement<P>>::PublicKeyBundle;

    client
        .init_session(contact_id, public_bundle, &remote_identity, 0)
        .map_err(ConstructError::SessionError)
}

/// Инициализировать сессию получателя при получении первого сообщения
pub fn init_receiving_session<P: CryptoProvider>(
    client: &mut Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>>,
    contact_id: &str,
    remote_bundle: &crate::api::crypto::KeyBundle,
    first_encrypted_msg: &EncryptedMessage,
) -> Result<String>
where
    X3DHProtocol<P>:
        KeyAgreement<P, PublicKeyBundle = crate::crypto::handshake::x3dh::X3DHPublicKeyBundle>,
    <X3DHProtocol<P> as KeyAgreement<P>>::SharedSecret: AsRef<[u8]>,
{
    use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
    let public_bundle: X3DHPublicKeyBundle = remote_bundle.clone().into();
    let ratchet_msg: EncryptedRatchetMessage = first_encrypted_msg.clone().into();

    // Конвертируем concrete X3DHPublicKeyBundle в generic H::RegistrationBundle через serde_json
    let generic_bundle: <X3DHProtocol<P> as KeyAgreement<P>>::RegistrationBundle =
        serde_json::from_value(
            serde_json::to_value(&public_bundle)
                .map_err(|e| ConstructError::SerializationError(e.to_string()))?,
        )
        .map_err(|e| ConstructError::SerializationError(e.to_string()))?;

    client
        .init_receiving_session(contact_id, &generic_bundle, &ratchet_msg)
        .map(|(session_id, _plaintext)| session_id)
        .map_err(ConstructError::SessionError)
}

/// Сериализовать зашифрованное сообщение в JSON
pub fn serialize_encrypted_message(msg: &EncryptedMessage) -> Result<String> {
    serde_json::to_string(msg).map_err(|e| ConstructError::SerializationError(e.to_string()))
}

/// Десериализовать зашифрованное сообщение из JSON
pub fn deserialize_encrypted_message(json: &str) -> Result<EncryptedMessage> {
    serde_json::from_str(json).map_err(|e| ConstructError::SerializationError(e.to_string()))
}
