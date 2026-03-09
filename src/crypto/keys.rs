// Управление ключами
// Хранение и ротация криптографических ключей

use crate::crypto::CryptoProvider;
use crate::crypto::SuiteID;
use crate::utils::error::{ConstructError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use std::collections::HashMap;
use std::marker::PhantomData;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Build prologue for X3DH signature (как в Noise Protocol)
/// Prologue включает протокол и suite ID для предотвращения key substitution attacks
pub fn build_prologue(suite_id: SuiteID) -> Vec<u8> {
    let protocol_name = b"KonstruktX3DH-v1";
    let suite_id_bytes = suite_id.as_u16().to_be_bytes();
    let mut prologue = Vec::with_capacity(protocol_name.len() + suite_id_bytes.len());
    prologue.extend_from_slice(protocol_name);
    prologue.extend_from_slice(&suite_id_bytes);
    prologue
}

/// Пара ключей X25519
#[derive(Clone, Zeroize)]
pub struct X25519KeyPair {
    pub private_key: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let private_key = Zeroizing::new(bytes);
        let arr = *private_key;
        let secret = StaticSecret::from(arr);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn from_secret(secret: StaticSecret) -> Self {
        let public_key = PublicKey::from(&secret).to_bytes();
        let private_key = Zeroizing::new(secret.to_bytes());
        Self {
            private_key,
            public_key,
        }
    }

    pub fn get_secret(&self) -> StaticSecret {
        let arr = *self.private_key;
        StaticSecret::from(arr)
    }

    pub fn get_public(&self) -> PublicKey {
        PublicKey::from(self.public_key)
    }
}

/// Пара ключей Ed25519 для подписи
#[derive(Clone, Zeroize)]
pub struct Ed25519KeyPair {
    pub private_key: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
}

impl Ed25519KeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let private_key = Zeroizing::new(signing_key.to_bytes());
        let public_key = verifying_key.to_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn get_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.private_key)
    }

    pub fn get_verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public_key).unwrap()
    }
}

/// Хранилище prekey с метаданными
#[derive(Clone)]
pub struct PrekeyStore<P: CryptoProvider> {
    pub key_pair: (P::KemPrivateKey, P::KemPublicKey),
    pub signature: Vec<u8>,
    pub created_at: i64,
    pub key_id: u32,
}

/// Менеджер криптографических ключей
pub struct KeyManager<P: CryptoProvider> {
    /// Identity ключ (долговременный)
    identity_key: Option<(P::KemPrivateKey, P::KemPublicKey)>,

    /// Signing ключ для подписей
    signing_key: Option<(P::SignaturePrivateKey, P::SignaturePublicKey)>,

    /// Текущий signed prekey
    current_signed_prekey: Option<PrekeyStore<P>>,

    /// История старых prekey для обратной совместимости
    old_prekeys: HashMap<u32, PrekeyStore<P>>,

    /// One-time prekeys (OTPKs) — burn-on-use, stored until consumed by incoming X3DH
    one_time_prekeys: HashMap<u32, (P::KemPrivateKey, P::KemPublicKey)>,

    /// Счетчик для key_id signed prekeys
    next_prekey_id: u32,

    /// Счетчик для OTPK key_id (separate range: starts at 1_000_000 to avoid collisions)
    next_otpk_id: u32,

    _phantom: PhantomData<P>,
}

impl<P: CryptoProvider> KeyManager<P> {
    /// Создать новый KeyManager
    pub fn new() -> Self {
        Self {
            identity_key: None,
            signing_key: None,
            current_signed_prekey: None,
            old_prekeys: HashMap::new(),
            one_time_prekeys: HashMap::new(),
            next_prekey_id: 1,
            next_otpk_id: 1_000_000,
            _phantom: PhantomData,
        }
    }

    /// Инициализировать с новыми ключами
    pub fn initialize(&mut self) -> Result<()> {
        self.identity_key = Some(P::generate_kem_keys().map_err(ConstructError::Crypto)?);
        self.signing_key = Some(P::generate_signature_keys().map_err(ConstructError::Crypto)?);
        self.rotate_signed_prekey()?;
        Ok(())
    }

    /// Инициализировать с существующими ключами (для восстановления из storage)
    pub fn initialize_from_keys(
        &mut self,
        identity_secret_bytes: Vec<u8>,
        signing_secret_bytes: Vec<u8>,
        prekey_secret_bytes: Vec<u8>,
        prekey_signature: Vec<u8>,
    ) -> Result<()> {
        // Создать ключи из байтов
        let identity_secret = P::kem_private_key_from_bytes(identity_secret_bytes);
        let identity_public =
            P::from_private_key_to_public_key(&identity_secret).map_err(ConstructError::Crypto)?;

        let signing_secret = P::signature_private_key_from_bytes(signing_secret_bytes);
        let signing_public =
            P::from_signature_private_to_public(&signing_secret).map_err(ConstructError::Crypto)?;

        let prekey_secret = P::kem_private_key_from_bytes(prekey_secret_bytes);
        let prekey_public =
            P::from_private_key_to_public_key(&prekey_secret).map_err(ConstructError::Crypto)?;

        // Сохранить ключи
        self.identity_key = Some((identity_secret, identity_public));
        self.signing_key = Some((signing_secret, signing_public));
        self.current_signed_prekey = Some(PrekeyStore {
            key_pair: (prekey_secret, prekey_public),
            signature: prekey_signature,
            created_at: 0, // Не важно для восстановленных ключей
            key_id: 1,
        });

        Ok(())
    }

    /// Получить identity public key
    pub fn identity_public_key(&self) -> Result<&P::KemPublicKey> {
        self.identity_key.as_ref().map(|k| &k.1).ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Identity key not initialized".to_string(),
            ))
        })
    }

    /// Получить identity secret key
    pub fn identity_secret_key(&self) -> Result<&P::KemPrivateKey> {
        self.identity_key.as_ref().map(|k| &k.0).ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Identity key not initialized".to_string(),
            ))
        })
    }

    /// Получить verifying key
    pub fn verifying_key(&self) -> Result<&P::SignaturePublicKey> {
        self.signing_key.as_ref().map(|k| &k.1).ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Signing key not initialized".to_string(),
            ))
        })
    }

    /// Получить текущий signed prekey
    pub fn current_signed_prekey(&self) -> Result<&PrekeyStore<P>> {
        self.current_signed_prekey.as_ref().ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "No signed prekey available".to_string(),
            ))
        })
    }

    /// Ротация signed prekey
    pub fn rotate_signed_prekey(&mut self) -> Result<()> {
        let (signing_key, _) = self.signing_key.as_ref().ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Signing key not initialized".to_string(),
            ))
        })?;

        // Генерируем новый prekey
        let key_pair = P::generate_kem_keys().map_err(ConstructError::Crypto)?;

        // Подписываем signed prekey с prologue (как в Noise Protocol)
        // Prologue включает протокол и suite ID для предотвращения key substitution attacks
        let suite_id = SuiteID::from_u16_unchecked(P::suite_id()); // Provider гарантирует валидный suite_id
        let prologue = build_prologue(suite_id);
        let mut message_to_sign = Vec::with_capacity(prologue.len() + key_pair.1.as_ref().len());
        message_to_sign.extend_from_slice(&prologue);
        message_to_sign.extend_from_slice(key_pair.1.as_ref());
        let signature = P::sign(signing_key, &message_to_sign).map_err(ConstructError::Crypto)?;

        let key_id = self.next_prekey_id;
        self.next_prekey_id += 1;

        let prekey_store = PrekeyStore {
            key_pair,
            signature,
            created_at: crate::utils::time::current_timestamp(),
            key_id,
        };

        // Сохраняем старый prekey в историю
        if let Some(old_prekey) = self.current_signed_prekey.take() {
            self.old_prekeys.insert(old_prekey.key_id, old_prekey);
        }

        self.current_signed_prekey = Some(prekey_store);

        // Очищаем старые prekeys (используя конфигурируемый период)
        self.cleanup_old_prekeys(crate::config::Config::global().prekey_cleanup_period_secs);

        Ok(())
    }

    /// Получить prekey по ID
    pub fn get_prekey(&self, key_id: u32) -> Option<&PrekeyStore<P>> {
        if let Some(current) = &self.current_signed_prekey {
            if current.key_id == key_id {
                return Some(current);
            }
        }
        self.old_prekeys.get(&key_id)
    }

    /// Очистка старых prekeys
    fn cleanup_old_prekeys(&mut self, max_age_seconds: i64) {
        let now = crate::utils::time::current_timestamp();
        self.old_prekeys
            .retain(|_, prekey| now - prekey.created_at < max_age_seconds);
    }

    /// Экспорт регистрационного bundle
    ///
    /// TODO(ARCHITECTURE): Этот метод возвращает конкретный тип X3DHPublicKeyBundle
    /// См. полное описание: packages/core/ARCHITECTURE_TODOS.md
    ///
    /// ПРОБЛЕМА:
    /// - KeyManager<P> generic только по CryptoProvider
    /// - Не знает о handshake protocol (X3DH, PQ-X3DH, etc.)
    /// - Поэтому возвращает конкретный тип X3DHPublicKeyBundle
    /// - Это создаёт несоответствие с Client<P, H, M> где H - generic handshake protocol
    ///
    /// ПОСЛЕДСТВИЯ:
    /// - Client::get_registration_bundle() не может использовать этот метод
    /// - Потому что возвращаемые типы не совпадают:
    ///   - Этот метод: X3DHPublicKeyBundle (конкретный)
    ///   - Client метод: H::RegistrationBundle (generic)
    /// - Приходится обходить Client и вызывать этот метод напрямую
    ///
    /// ПРАВИЛЬНОЕ РЕШЕНИЕ:
    /// Сделать KeyManager generic по handshake protocol:
    /// ```rust,ignore
    /// pub struct KeyManager<P: CryptoProvider, H: KeyAgreement<P>> {
    ///     // ...
    /// }
    ///
    /// impl<P: CryptoProvider, H: KeyAgreement<P>> KeyManager<P, H> {
    ///     pub fn export_registration_bundle(&self) -> Result<H::RegistrationBundle> {
    ///         // Делегировать создание bundle протоколу handshake
    ///         H::export_from_key_manager(self)
    ///     }
    /// }
    /// ```
    ///
    /// Это потребует:
    /// 1. Добавить в trait KeyAgreement метод export_from_key_manager()
    /// 2. Обновить KeyManager<P> -> KeyManager<P, H>
    /// 3. Обновить все места использования KeyManager
    ///
    /// Смотрите также:
    /// - client_api.rs:137-161 - проблема в Client::get_registration_bundle()
    /// - uniffi_bindings.rs:93-118 - workaround и полное описание решений
    pub fn export_registration_bundle(
        &self,
    ) -> Result<crate::crypto::handshake::x3dh::X3DHPublicKeyBundle> {
        let identity_public = self.identity_public_key()?.as_ref().to_vec();
        let verifying_key = self.verifying_key()?.as_ref().to_vec();
        let prekey = self.current_signed_prekey()?;

        Ok(crate::crypto::handshake::x3dh::X3DHPublicKeyBundle {
            identity_public,
            signed_prekey_public: prekey.key_pair.1.as_ref().to_vec(),
            signature: prekey.signature.clone(),
            verifying_key,
            suite_id: SuiteID::from_u16_unchecked(P::suite_id()), // Provider гарантирует валидный suite_id
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        })
    }

    /// Экспорт публичного key bundle
    pub fn export_public_bundle(
        &self,
    ) -> Result<crate::crypto::handshake::x3dh::X3DHPublicKeyBundle> {
        let identity_public = self.identity_public_key()?.as_ref().to_vec();
        let verifying_key = self.verifying_key()?.as_ref().to_vec();
        let prekey = self.current_signed_prekey()?;

        Ok(crate::crypto::handshake::x3dh::X3DHPublicKeyBundle {
            identity_public,
            signed_prekey_public: prekey.key_pair.1.as_ref().to_vec(),
            signature: prekey.signature.clone(),
            verifying_key,
            suite_id: SuiteID::from_u16_unchecked(P::suite_id()), // Provider гарантирует валидный suite_id
            one_time_prekey_public: None,
            one_time_prekey_id: None,
        })
    }

    /// Экспорт device registration bundle для device-based регистрации
    ///
    /// Возвращает X3DHRegistrationBundle, содержащий ТОЛЬКО публичные данные
    /// для безопасного обмена ключами между устройствами.
    ///
    /// # Безопасность
    ///
    /// Этот метод гарантирует, что:
    /// - Возвращаются только публичные ключи
    /// - Приватные ключи никогда не покидают KeyManager
    /// - Bundle можно безопасно отправлять по сети
    pub fn export_device_registration_bundle(
        &self,
    ) -> Result<crate::crypto::handshake::x3dh::X3DHRegistrationBundle> {
        let identity_public = self.identity_public_key()?.as_ref().to_vec();
        let verifying_key = self.verifying_key()?.as_ref().to_vec();
        let prekey = self.current_signed_prekey()?;

        Ok(crate::crypto::handshake::x3dh::X3DHRegistrationBundle {
            identity_public,
            signed_prekey_public: prekey.key_pair.1.as_ref().to_vec(),
            signature: prekey.signature.clone(),
            verifying_key,
            suite_id: SuiteID::from_u16_unchecked(P::suite_id()),
        })
    }

    /// Подписать данные
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (signing_key, _) = self.signing_key.as_ref().ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Signing key not initialized".to_string(),
            ))
        })?;

        P::sign(signing_key, data).map_err(ConstructError::Crypto)
    }

    /// Количество сохраненных старых prekeys
    pub fn old_prekeys_count(&self) -> usize {
        self.old_prekeys.len()
    }

    // ============================================================================
    // One-Time Prekeys (OTPKs)
    // ============================================================================

    /// Generate `count` new one-time prekeys, store private keys, return (key_id, public_key_bytes) pairs.
    /// Caller uploads the public keys to the server via UploadPreKeys.
    pub fn generate_one_time_prekeys(&mut self, count: u32) -> Result<Vec<(u32, Vec<u8>)>> {
        let mut result = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (private_key, public_key) =
                P::generate_kem_keys().map_err(ConstructError::Crypto)?;
            let key_id = self.next_otpk_id;
            self.next_otpk_id = self.next_otpk_id.wrapping_add(1);
            let public_bytes = public_key.as_ref().to_vec();
            self.one_time_prekeys.insert(key_id, (private_key, public_key));
            result.push((key_id, public_bytes));
        }
        Ok(result)
    }

    /// Consume (burn) a one-time prekey by key_id. Returns the private key if found.
    /// The key is removed from storage — it cannot be reused.
    pub fn consume_one_time_prekey(&mut self, key_id: u32) -> Option<P::KemPrivateKey> {
        self.one_time_prekeys.remove(&key_id).map(|(private, _)| private)
    }

    /// How many OTPKs are currently stored locally (not yet consumed).
    pub fn one_time_prekey_count(&self) -> usize {
        self.one_time_prekeys.len()
    }

    /// Export all stored OTPK (key_id, private_bytes, public_bytes) for persistence.
    pub fn export_one_time_prekeys(&self) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
        self.one_time_prekeys
            .iter()
            .map(|(&id, (priv_key, pub_key))| {
                (id, priv_key.as_ref().to_vec(), pub_key.as_ref().to_vec())
            })
            .collect()
    }

    /// Import previously exported OTPKs back into the store (used after core restore).
    /// Also restores next_otpk_id to avoid collisions with persisted keys.
    pub fn import_one_time_prekeys(&mut self, keys: Vec<(u32, Vec<u8>, Vec<u8>)>) {
        for (key_id, priv_bytes, pub_bytes) in keys {
            let private_key = P::kem_private_key_from_bytes(priv_bytes);
            let public_key = P::kem_public_key_from_bytes(pub_bytes);
            self.one_time_prekeys.insert(key_id, (private_key, public_key));
            // Keep next_otpk_id above all imported IDs to avoid collisions
            if key_id >= self.next_otpk_id {
                self.next_otpk_id = key_id.wrapping_add(1);
            }
        }
    }

    /// Iterate over all prekey private keys: current first, then old ones.
    ///
    /// Used by `init_receiving_session_with_ephemeral` to try all available
    /// prekeys when the current one fails (e.g. sender used a prekey from
    /// before a rotation).
    pub fn all_prekey_private_keys(&self) -> Vec<P::KemPrivateKey> {
        let mut keys = Vec::with_capacity(1 + self.old_prekeys.len());
        if let Some(current) = &self.current_signed_prekey {
            keys.push(current.key_pair.0.clone());
        }
        // Sort old prekeys newest-first (highest key_id = most recent rotation)
        let mut old: Vec<_> = self.old_prekeys.values().collect();
        old.sort_by(|a, b| b.key_id.cmp(&a.key_id));
        for prekey in old {
            keys.push(prekey.key_pair.0.clone());
        }
        keys
    }

    /// Получить signing key для экспорта
    pub fn signing_secret_key(&self) -> Result<&P::SignaturePrivateKey> {
        self.signing_key.as_ref().map(|k| &k.0).ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Signing key not initialized".to_string(),
            ))
        })
    }
}

impl<P: CryptoProvider> Default for KeyManager<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_keypair_zeroize() {
        let mut pair = X25519KeyPair::generate();
        let original_secret = *pair.private_key;
        pair.zeroize();
        let zeroed_secret = *pair.private_key;
        assert_ne!(original_secret, zeroed_secret);
        assert!(zeroed_secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ed25519_keypair_zeroize() {
        let mut pair = Ed25519KeyPair::generate();
        let original_secret = *pair.private_key;
        pair.zeroize();
        let zeroed_secret = *pair.private_key;
        assert_ne!(original_secret, zeroed_secret);
        assert!(zeroed_secret.iter().all(|&b| b == 0));
    }
}
