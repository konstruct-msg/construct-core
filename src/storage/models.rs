// Модели данных для хранилища

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Статус сообщения
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,   // Создано, но не отправлено
    Sent,      // Отправлено на сервер
    Delivered, // Доставлено получателю
    Read,      // Прочитано
    Failed,    // Ошибка отправки
}

/// Сообщение в хранилище
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub conversation_id: String, // Группировка по беседе
    pub from: String,
    pub to: String,
    pub encrypted_content: String, // Base64 зашифрованного Double Ratchet сообщения
    pub timestamp: i64,
    pub status: MessageStatus,
}

/// Контакт в хранилище
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContact {
    pub id: String,
    pub username: String,
    pub public_key_bundle: Option<Vec<u8>>, // JSON или Postcard
    pub added_at: i64,
    pub last_message_at: Option<i64>,
}

/// Приватные ключи в хранилище (ЗАШИФРОВАННЫЕ!)
///
/// Implements `Zeroize` so all key material is wiped from memory on drop.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct StoredPrivateKeys {
    pub user_id: String,
    pub encrypted_identity_private: Vec<u8>, // Зашифровано мастер-ключом
    pub encrypted_signed_prekey_private: Vec<u8>,
    pub encrypted_signing_key: Vec<u8>,
    pub prekey_signature: Vec<u8>, // Ed25519 подпись для prekey (не шифруется)
    pub salt: Vec<u8>,             // Для PBKDF2
    pub created_at: i64,
}

/// Сессия Double Ratchet в хранилище (СЕРИАЛИЗОВАННАЯ)
///
/// Implements `Zeroize` so the session bytes (chain keys, ratchet state) are
/// wiped from memory on drop — critical because these bytes carry forward
/// secrecy material.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct StoredSession {
    pub session_id: String,
    pub contact_id: String,
    pub session_data: Vec<u8>, // Postcard сериализация SerializableSession
    pub last_used: i64,
    pub created_at: i64,
}

/// Метаданные приложения
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAppMetadata {
    pub user_id: String,
    pub username: String,
    pub last_sync: i64,
    pub settings: Vec<u8>, // JSON настроек
}

/// Беседа
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub contact_id: String,
    pub last_message_id: Option<String>,
    pub last_message_timestamp: Option<i64>,
    pub unread_count: u32,
}
