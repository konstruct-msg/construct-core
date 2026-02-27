// Шифрование приватных ключей мастер-паролем
// PBKDF2 для деривации ключа + ChaCha20-Poly1305 для шифрования

use crate::config::Config;
use crate::storage::models::StoredPrivateKeys;
use crate::utils::error::{ConstructError, Result};
use crate::utils::time::current_timestamp;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::SigningKey;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, Zeroizing};

// Compile-time константы для размеров массивов (должны совпадать с Config::default())
const SALT_LENGTH: usize = 32;
const KEY_LENGTH: usize = 32;

/// Незашифрованные приватные ключи для временного хранения
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct PrivateKeys {
    pub identity_secret: [u8; 32],      // X25519 StaticSecret
    pub signing_key: [u8; 32],          // Ed25519 SigningKey
    pub signed_prekey_secret: [u8; 32], // X25519 prekey secret
}

impl PrivateKeys {
    /// Создать из raw байтов
    pub fn new(
        identity_secret: [u8; 32],
        signing_key: [u8; 32],
        signed_prekey_secret: [u8; 32],
    ) -> Self {
        Self {
            identity_secret,
            signing_key,
            signed_prekey_secret,
        }
    }

    /// Конвертировать в StaticSecret и SigningKey
    pub fn to_keys(&self) -> Result<(StaticSecret, SigningKey, StaticSecret)> {
        let identity = StaticSecret::from(self.identity_secret);

        let signing = SigningKey::from_bytes(&self.signing_key);

        let prekey = StaticSecret::from(self.signed_prekey_secret);

        Ok((identity, signing, prekey))
    }
}

/// Деривировать мастер-ключ из пароля с использованием PBKDF2
///
/// # Arguments
/// * `password` - Пользовательский пароль
/// * `salt` - Соль (32 байта)
///
/// # Returns
/// 256-битный ключ для AES-256-GCM
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    if salt.len() != Config::global().salt_length {
        return Err(ConstructError::ValidationError(format!(
            "Invalid salt length: expected {}, got {}",
            Config::global().salt_length,
            salt.len()
        )));
    }

    if password.is_empty() {
        return Err(ConstructError::ValidationError(
            "Password cannot be empty".to_string(),
        ));
    }

    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);

    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        Config::global().pbkdf2_iterations,
        &mut *key,
    );

    Ok(key)
}

/// Генерировать случайную соль
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Зашифровать приватные ключи с использованием AES-256-GCM
///
/// # Arguments
/// * `keys` - Незашифрованные приватные ключи
/// * `master_key` - 256-битный мастер-ключ (из derive_master_key)
/// * `salt` - Соль, использованная для деривации ключа
/// * `user_id` - ID пользователя
/// * `prekey_signature` - Ed25519 подпись для prekey (не шифруется, хранится отдельно)
///
/// # Returns
/// StoredPrivateKeys с зашифрованными данными
pub fn encrypt_private_keys(
    keys: &PrivateKeys,
    master_key: &[u8; KEY_LENGTH],
    salt: [u8; SALT_LENGTH],
    user_id: String,
    prekey_signature: Vec<u8>,
) -> Result<StoredPrivateKeys> {
    let cipher = ChaCha20Poly1305::new(master_key.into());

    // Шифруем каждый ключ отдельно с разными nonce
    let encrypted_identity = encrypt_data(&cipher, &keys.identity_secret)?;
    let encrypted_prekey = encrypt_data(&cipher, &keys.signed_prekey_secret)?;
    let encrypted_signing = encrypt_data(&cipher, &keys.signing_key)?;

    Ok(StoredPrivateKeys {
        user_id,
        encrypted_identity_private: encrypted_identity,
        encrypted_signed_prekey_private: encrypted_prekey,
        encrypted_signing_key: encrypted_signing,
        prekey_signature,
        salt: salt.to_vec(),
        created_at: current_timestamp(),
    })
}

/// Расшифровать приватные ключи
///
/// # Arguments
/// * `stored` - Зашифрованные ключи из хранилища
/// * `master_key` - 256-битный мастер-ключ
///
/// # Returns
/// PrivateKeys с расшифрованными данными
pub fn decrypt_private_keys(
    stored: &StoredPrivateKeys,
    master_key: &[u8; KEY_LENGTH],
) -> Result<PrivateKeys> {
    let cipher = ChaCha20Poly1305::new(master_key.into());

    // Расшифровываем каждый ключ
    let identity_bytes = decrypt_data(&cipher, &stored.encrypted_identity_private)?;
    let prekey_bytes = decrypt_data(&cipher, &stored.encrypted_signed_prekey_private)?;
    let signing_bytes = decrypt_data(&cipher, &stored.encrypted_signing_key)?;

    // Конвертируем в фиксированные массивы
    let identity_secret = to_array_32(&identity_bytes)?;
    let prekey_secret = to_array_32(&prekey_bytes)?;
    let signing_key = to_array_32(&signing_bytes)?;

    Ok(PrivateKeys::new(
        identity_secret,
        signing_key,
        prekey_secret,
    ))
}

/// Зашифровать данные с использованием AES-256-GCM
fn encrypt_data(cipher: &ChaCha20Poly1305, data: &[u8]) -> Result<Vec<u8>> {
    let nonce_length = Config::global().nonce_length;

    // Генерируем случайный nonce
    let mut nonce_bytes = vec![0u8; nonce_length];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Шифруем
    let ciphertext = cipher.encrypt(nonce, data).map_err(|e| {
        ConstructError::Crypto(crate::error::CryptoError::AeadEncryptionError(
            e.to_string(),
        ))
    })?;

    // Комбинируем nonce + ciphertext
    let mut result = Vec::with_capacity(nonce_length + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Расшифровать данные с использованием AES-256-GCM
fn decrypt_data(cipher: &ChaCha20Poly1305, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let nonce_length = Config::global().nonce_length;

    if data.len() < nonce_length {
        return Err(ConstructError::ValidationError(
            "Invalid ciphertext: too short".to_string(),
        ));
    }

    // Извлекаем nonce и ciphertext
    let (nonce_bytes, ciphertext) = data.split_at(nonce_length);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Расшифровываем
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        ConstructError::Crypto(crate::error::CryptoError::AeadDecryptionError(
            e.to_string(),
        ))
    })?;

    Ok(Zeroizing::new(plaintext))
}

/// Конвертировать Vec<u8> в [u8; 32]
fn to_array_32(vec: &[u8]) -> Result<[u8; 32]> {
    if vec.len() != 32 {
        return Err(ConstructError::ValidationError(format!(
            "Invalid key length: expected 32, got {}",
            vec.len()
        )));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(vec);
    Ok(array)
}

/// Валидация силы пароля
///
/// Минимальные требования:
/// - Длина >= конфигурируемый минимум (по умолчанию 8 символов)
/// - Содержит буквы и цифры
pub fn validate_password(password: &str) -> Result<()> {
    let min_length = Config::global().password_min_length;
    if password.len() < min_length {
        return Err(ConstructError::ValidationError(format!(
            "Password must be at least {} characters long",
            min_length
        )));
    }

    let has_letter = password.chars().any(|c| c.is_alphabetic());
    let has_digit = password.chars().any(|c| c.is_numeric());

    if !has_letter || !has_digit {
        return Err(ConstructError::ValidationError(
            "Password must contain both letters and numbers".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key() {
        let salt = generate_salt();
        let password = "test_password_123";

        let key1 = derive_master_key(password, &salt).unwrap();
        let key2 = derive_master_key(password, &salt).unwrap();

        // Одинаковый пароль и соль должны давать одинаковый ключ
        assert_eq!(&*key1, &*key2);
    }

    #[test]
    fn test_derive_master_key_different_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let password = "test_password_123";

        let key1 = derive_master_key(password, &salt1).unwrap();
        let key2 = derive_master_key(password, &salt2).unwrap();

        // Разные соли должны давать разные ключи
        assert_ne!(&*key1, &*key2);
    }

    #[test]
    fn test_encrypt_decrypt_private_keys() {
        let password = "my_secure_password_123";
        let salt = generate_salt();
        let master_key = derive_master_key(password, &salt).unwrap();

        // Создаем тестовые приватные ключи
        let identity = [1u8; 32];
        let signing = [2u8; 32];
        let prekey = [3u8; 32];

        let keys = PrivateKeys::new(identity, signing, prekey);

        // Шифруем (с тестовой подписью)
        let test_signature = vec![4u8; 64];
        let encrypted = encrypt_private_keys(
            &keys,
            &master_key,
            salt,
            "user123".to_string(),
            test_signature.clone(),
        )
        .unwrap();

        // Проверяем, что данные зашифрованы (не равны оригиналу)
        assert_ne!(encrypted.encrypted_identity_private, identity.to_vec());
        assert_ne!(encrypted.encrypted_signing_key, signing.to_vec());
        assert_ne!(encrypted.encrypted_signed_prekey_private, prekey.to_vec());
        // Подпись не шифруется
        assert_eq!(encrypted.prekey_signature, test_signature);

        // Расшифровываем
        let decrypted = decrypt_private_keys(&encrypted, &master_key).unwrap();

        // Проверяем, что расшифрованные данные совпадают с оригиналом
        assert_eq!(decrypted.identity_secret, identity);
        assert_eq!(decrypted.signing_key, signing);
        assert_eq!(decrypted.signed_prekey_secret, prekey);
    }

    #[test]
    fn test_decrypt_with_wrong_password() {
        let correct_password = "correct_password_123";
        let wrong_password = "wrong_password_456";
        let salt = generate_salt();

        let correct_key = derive_master_key(correct_password, &salt).unwrap();
        let wrong_key = derive_master_key(wrong_password, &salt).unwrap();

        let keys = PrivateKeys::new([1u8; 32], [2u8; 32], [3u8; 32]);

        let test_signature = vec![4u8; 64];
        let encrypted = encrypt_private_keys(
            &keys,
            &correct_key,
            salt,
            "user123".to_string(),
            test_signature,
        )
        .unwrap();

        // Попытка расшифровать неправильным ключом должна провалиться
        let result = decrypt_private_keys(&encrypted, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_password() {
        // Валидные пароли
        assert!(validate_password("password123").is_ok());
        assert!(validate_password("MyPass123").is_ok());
        assert!(validate_password("Test1234").is_ok());

        // Невалидные пароли
        assert!(validate_password("short1").is_err()); // Слишком короткий
        assert!(validate_password("onlyletters").is_err()); // Только буквы
        assert!(validate_password("12345678").is_err()); // Только цифры
        assert!(validate_password("").is_err()); // Пустой
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        // Соли должны быть разными
        assert_ne!(salt1, salt2);

        // Соли должны быть правильной длины
        assert_eq!(salt1.len(), SALT_LENGTH);
        assert_eq!(salt2.len(), SALT_LENGTH);
    }

    #[test]
    fn test_encrypt_data_includes_nonce() {
        let master_key = [0u8; KEY_LENGTH];
        let cipher = ChaCha20Poly1305::new(&master_key.into());
        let data = b"test data";

        let encrypted = encrypt_data(&cipher, data).unwrap();

        // Зашифрованные данные должны быть больше оригинала (nonce + ciphertext + tag)
        assert!(encrypted.len() > data.len());
        let expected_len =
            Config::global().nonce_length + data.len() + Config::global().gcm_tag_length;
        assert_eq!(encrypted.len(), expected_len);
    }
}
