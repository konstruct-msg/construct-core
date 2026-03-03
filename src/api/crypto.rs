use crate::crypto::client_api::Client;
use crate::crypto::handshake::x3dh::{X3DHProtocol, X3DHPublicKeyBundle};
use crate::crypto::handshake::KeyAgreement;
use crate::crypto::messaging::double_ratchet::DoubleRatchetSession;
use crate::crypto::{CryptoProvider, SuiteID};
use crate::utils::error::{ConstructError, Result};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub suite_id: u16, // Added
}

impl From<X3DHPublicKeyBundle> for KeyBundle {
    fn from(bundle: X3DHPublicKeyBundle) -> Self {
        Self {
            identity_public: bundle.identity_public,
            signed_prekey_public: bundle.signed_prekey_public,
            signature: bundle.signature,
            verifying_key: bundle.verifying_key,
            suite_id: bundle.suite_id.as_u16(),
        }
    }
}

impl From<KeyBundle> for X3DHPublicKeyBundle {
    fn from(bundle: KeyBundle) -> Self {
        // Валидация suite_id при конвертации
        let suite_id = SuiteID::new(bundle.suite_id)
            .map_err(|e| format!("Invalid suite_id in KeyBundle: {}", e))
            .unwrap_or_else(|_| {
                // Fallback на CLASSIC если suite_id невалидный (для backward compatibility)
                tracing::warn!(
                    suite_id = bundle.suite_id,
                    "Invalid suite_id in KeyBundle, falling back to CLASSIC"
                );
                SuiteID::CLASSIC
            });

        Self {
            identity_public: bundle.identity_public,
            signed_prekey_public: bundle.signed_prekey_public,
            signature: bundle.signature,
            verifying_key: bundle.verifying_key,
            suite_id,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationBundleB64 {
    pub identity_public: String,
    pub signed_prekey_public: String,
    pub signature: String,
    pub verifying_key: String,
    pub suite_id: String, // Added
}

pub struct CryptoCore<P: CryptoProvider>
where
    X3DHProtocol<P>: KeyAgreement<P>,
{
    client: Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>>,
    _phantom: PhantomData<P>,
}

impl<P: CryptoProvider> CryptoCore<P>
where
    X3DHProtocol<P>: KeyAgreement<P, PublicKeyBundle = X3DHPublicKeyBundle>,
    <X3DHProtocol<P> as KeyAgreement<P>>::SharedSecret: AsRef<[u8]>,
{
    pub fn new() -> Result<Self> {
        let client = Client::<P, X3DHProtocol<P>, DoubleRatchetSession<P>>::new()
            .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::Other(e)))?;

        Ok(Self {
            client,
            _phantom: PhantomData,
        })
    }

    pub fn export_registration_bundle(&self) -> Result<KeyBundle> {
        let bundle = self.client.key_manager().export_registration_bundle()?;
        Ok(bundle.into())
    }

    pub fn export_registration_bundle_b64(&self) -> Result<RegistrationBundleB64> {
        use base64::Engine;
        let bundle = self.client.key_manager().export_registration_bundle()?;
        Ok(RegistrationBundleB64 {
            identity_public: base64::engine::general_purpose::STANDARD
                .encode(&bundle.identity_public),
            signed_prekey_public: base64::engine::general_purpose::STANDARD
                .encode(&bundle.signed_prekey_public),
            signature: base64::engine::general_purpose::STANDARD.encode(&bundle.signature),
            verifying_key: base64::engine::general_purpose::STANDARD.encode(&bundle.verifying_key),
            suite_id: bundle.suite_id.as_u16().to_string(),
        })
    }

    /// Подписать BundleData JSON с помощью Ed25519 signing key
    /// Используется для создания signature в UploadableKeyBundle
    pub fn sign_bundle_data(&self, bundle_data_json: Vec<u8>) -> Result<String> {
        use base64::Engine;

        // Получить подпись от KeyManager
        let signature = self
            .client
            .key_manager()
            .sign(&bundle_data_json)
            .map_err(|e| {
                ConstructError::Crypto(crate::error::CryptoError::Other(format!(
                    "Failed to sign BundleData: {:?}",
                    e
                )))
            })?;

        // Base64-encode подпись
        Ok(base64::engine::general_purpose::STANDARD.encode(&signature))
    }

    pub fn export_public_bundle(&self) -> Result<KeyBundle> {
        let bundle = self.client.key_manager().export_public_bundle()?;
        Ok(bundle.into())
    }

    pub fn has_session(&self, contact_id: &str) -> bool {
        self.client.has_session(contact_id)
    }

    pub fn active_sessions_count(&self) -> usize {
        self.client.active_sessions_count()
    }

    pub fn init_session(&mut self, contact_id: &str, remote_bundle: &KeyBundle) -> Result<String> {
        // Convert to X3DHPublicKeyBundle and then use it
        let bundle_data = X3DHPublicKeyBundle {
            identity_public: remote_bundle.identity_public.clone(),
            signed_prekey_public: remote_bundle.signed_prekey_public.clone(),
            signature: remote_bundle.signature.clone(),
            verifying_key: remote_bundle.verifying_key.clone(),
            suite_id: SuiteID::new(remote_bundle.suite_id)
                .map_err(|e| ConstructError::ValidationError(format!("Invalid suite_id: {}", e)))?,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        };

        // Extract remote identity from bundle
        let remote_identity = P::kem_public_key_from_bytes(bundle_data.identity_public.clone());

        // Cast to the expected generic type
        let public_bundle = &bundle_data as &<X3DHProtocol<P> as KeyAgreement<P>>::PublicKeyBundle;

        self.client
            .init_session(contact_id, public_bundle, &remote_identity, 0)
            .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::Other(e)))
    }

    pub fn init_receiving_session(
        &mut self,
        contact_id: &str,
        remote_bundle: &KeyBundle,
        first_message: &crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage,
    ) -> Result<String> {
        let public_bundle: X3DHPublicKeyBundle = remote_bundle.clone().into();

        // Конвертируем concrete X3DHPublicKeyBundle в generic H::RegistrationBundle через serde_json
        let generic_bundle: <X3DHProtocol<P> as crate::crypto::handshake::KeyAgreement<P>>::RegistrationBundle =
            serde_json::from_value(serde_json::to_value(&public_bundle)
                .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::SerializationError(e.to_string())))?)
                .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::DeserializationError(e.to_string())))?;

        self.client
            .init_receiving_session(contact_id, &generic_bundle, first_message)
            .map(|(session_id, _plaintext)| session_id)
            .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::Other(e)))
    }

    pub fn encrypt_message(
        &mut self,
        contact_id: &str,
        plaintext: &str,
    ) -> Result<crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage> {
        self.client
            .encrypt_message(contact_id, plaintext.as_bytes())
            .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::Other(e)))
    }

    pub fn decrypt_message(
        &mut self,
        contact_id: &str,
        message: &crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage,
    ) -> Result<String> {
        let plaintext = self
            .client
            .decrypt_message(contact_id, message)
            .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::Other(e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| ConstructError::SerializationError(format!("Invalid UTF-8: {}", e)))
    }

    pub fn client(&self) -> &Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>> {
        &self.client
    }

    pub fn client_mut(&mut self) -> &mut Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>> {
        &mut self.client
    }

    // DEPRECATED: These methods don't work with generic CryptoProvider
    // They should be refactored to work with Vec<u8> instead of concrete types
    // pub fn export_private_keys(&self) -> Result<crate::crypto::master_key::PrivateKeys> {
    //     let identity_secret = self.key_manager.identity_secret_key()?;
    //     let identity_bytes = identity_secret.as_ref().to_vec();
    //
    //     let signing_key = self.key_manager.signing_secret_key()?;
    //     let signing_bytes = signing_key.as_ref().to_vec();
    //
    //     let prekey = self.key_manager.current_signed_prekey()?;
    //     let prekey_bytes = prekey.key_pair.0.as_ref().to_vec();
    //
    //     Ok(crate::crypto::master_key::PrivateKeys::new(
    //         identity_bytes,
    //         signing_bytes,
    //         prekey_bytes,
    //     ))
    // }
    //
    // pub fn import_private_keys(
    //     &mut self,
    //     keys: &crate::crypto::master_key::PrivateKeys,
    //     prekey_signature: Vec<u8>,
    // ) -> Result<()> {
    //     // This method requires a generic way to construct keys from bytes
    //     // which is not currently supported in CryptoProvider trait
    //     unimplemented!("import_private_keys not compatible with generic CryptoProvider")
    // }
}

impl<P: CryptoProvider> Default for CryptoCore<P>
where
    X3DHProtocol<P>: KeyAgreement<P, PublicKeyBundle = X3DHPublicKeyBundle>,
    <X3DHProtocol<P> as KeyAgreement<P>>::SharedSecret: AsRef<[u8]>,
{
    fn default() -> Self {
        Self::new().expect("Failed to create CryptoCore")
    }
}

pub fn create_client<P: CryptoProvider>(
) -> Result<Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>>>
where
    X3DHProtocol<P>: KeyAgreement<P, PublicKeyBundle = X3DHPublicKeyBundle>,
    <X3DHProtocol<P> as KeyAgreement<P>>::SharedSecret: AsRef<[u8]>,
{
    Client::<P, X3DHProtocol<P>, DoubleRatchetSession<P>>::new()
        .map_err(|e| ConstructError::Crypto(crate::error::CryptoError::Other(e)))
}

pub fn get_registration_bundle<P: CryptoProvider>(
    client: &Client<P, X3DHProtocol<P>, DoubleRatchetSession<P>>,
) -> Result<KeyBundle>
where
    X3DHProtocol<P>: KeyAgreement<P, PublicKeyBundle = X3DHPublicKeyBundle>,
    <X3DHProtocol<P> as KeyAgreement<P>>::SharedSecret: AsRef<[u8]>,
{
    let bundle = client.key_manager().export_registration_bundle()?;
    Ok(KeyBundle {
        identity_public: bundle.identity_public,
        signed_prekey_public: bundle.signed_prekey_public,
        signature: bundle.signature,
        verifying_key: bundle.verifying_key,
        suite_id: bundle.suite_id.as_u16(),
    })
}

pub fn serialize_key_bundle(bundle: &KeyBundle) -> Result<String> {
    serde_json::to_string(bundle).map_err(|e| ConstructError::SerializationError(e.to_string()))
}

pub fn deserialize_key_bundle(json: &str) -> Result<KeyBundle> {
    serde_json::from_str(json).map_err(|e| ConstructError::SerializationError(e.to_string()))
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn base64_to_bytes(base64_str: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(base64_str)
        .map_err(|e| ConstructError::SerializationError(format!("Invalid base64: {}", e)))
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    #[test]
    fn test_crypto_manager_creation() {
        let manager = CryptoCore::<ClassicSuiteProvider>::new();
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert_eq!(manager.active_sessions_count(), 0);
    }

    #[test]
    fn test_base64_conversion() {
        let data = b"hello world";
        let b64 = bytes_to_base64(data);
        let decoded = base64_to_bytes(&b64).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = generate_random_bytes(32);
        let bytes2 = generate_random_bytes(32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Должны быть разными
    }

    #[test]
    fn test_export_registration_bundle() {
        let manager = CryptoCore::<ClassicSuiteProvider>::new().unwrap();
        let bundle = manager.export_registration_bundle();
        assert!(bundle.is_ok());

        let bundle = bundle.unwrap();
        assert_eq!(bundle.identity_public.len(), 32);
        assert_eq!(bundle.signed_prekey_public.len(), 32);
        assert_eq!(bundle.signature.len(), 64);
        assert_eq!(bundle.verifying_key.len(), 32);
    }
}
