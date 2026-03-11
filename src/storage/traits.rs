// Storage traits для платформо-независимого хранилища
//
// Определяет два уровня хранилища:
// 1. SecureStorage - для чувствительных данных (токены, ключи, сессии)
// 2. DataStorage - для обычных данных (сообщения, контакты)

use crate::utils::error::Result;
use std::future::Future;

// Re-export models для удобства
pub use super::models::*;

// ============================================================================
// Conditional Send Bound
// ============================================================================

// For WASM targets, futures can't be Send because JS is single-threaded
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

// For non-WASM targets, require Send for thread safety
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

// ============================================================================
// Secure Storage Trait
// ============================================================================

/// Trait для безопасного хранилища чувствительных данных
///
/// Реализации:
/// - iOS: Keychain (через UniFFI callbacks)
/// - Web: IndexedDB с шифрованием (встроенное)
/// - Desktop: OS-specific secure storage
///
/// Все данные хранятся безопасно и недоступны другим приложениям.
pub trait SecureStorage {
    /// Сохранить токены аутентификации
    ///
    /// # Security
    /// - iOS: Keychain с `.afterFirstUnlock` accessibility
    /// - Web: IndexedDB (browser sandbox)
    fn save_auth_tokens(&self, tokens: &AuthTokens)
        -> impl Future<Output = Result<()>> + MaybeSend;

    /// Загрузить токены аутентификации
    fn load_auth_tokens(&self) -> impl Future<Output = Result<Option<AuthTokens>>> + MaybeSend;

    /// Удалить токены (logout)
    fn clear_auth_tokens(&self) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Сохранить приватные ключи (зашифрованные)
    ///
    /// # Security
    /// - iOS: Keychain с `.whenUnlockedThisDeviceOnly`
    /// - Web: IndexedDB (browser sandbox)
    fn save_private_keys(
        &self,
        keys: &StoredPrivateKeys,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Загрузить приватные ключи
    fn load_private_keys(
        &self,
    ) -> impl Future<Output = Result<Option<StoredPrivateKeys>>> + MaybeSend;

    /// Удалить приватные ключи
    fn clear_private_keys(&self) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Сохранить сессию для контакта
    ///
    /// # Parameters
    /// - `contact_id`: UUID контакта
    /// - `session`: Сериализованная Double Ratchet сессия
    ///
    /// # Security
    /// Сессии содержат chain keys и должны храниться безопасно
    fn save_session(
        &self,
        contact_id: &str,
        session: &StoredSession,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Загрузить сессию для контакта
    fn load_session(
        &self,
        contact_id: &str,
    ) -> impl Future<Output = Result<Option<StoredSession>>> + MaybeSend;

    /// Удалить сессию для контакта
    fn delete_session(&self, contact_id: &str) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Получить список всех contact_id с сохранёнными сессиями
    ///
    /// Используется для pagination при загрузке:
    /// - Загружаем только последние N сессий при старте
    /// - Остальные загружаем lazy on-demand
    fn list_sessions(&self) -> impl Future<Output = Result<Vec<String>>> + MaybeSend;

    /// Очистить все сессии (используется при logout или reset)
    fn clear_all_sessions(&self) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Сохранить метаданные приложения (настройки, последний sync и т.д.)
    fn save_app_metadata(
        &self,
        metadata: &StoredAppMetadata,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Загрузить метаданные приложения
    fn load_app_metadata(
        &self,
    ) -> impl Future<Output = Result<Option<StoredAppMetadata>>> + MaybeSend;
}

// ============================================================================
// Data Storage Trait
// ============================================================================

/// Trait для хранилища обычных данных (сообщения, контакты)
///
/// Реализации:
/// - iOS: Core Data
/// - Web: IndexedDB
/// - Desktop: SQLite или другая БД
///
/// Данные могут быть доступны для поиска, индексации и т.д.
pub trait DataStorage {
    // === Messages ===

    /// Сохранить сообщение
    fn save_message(&self, message: &StoredMessage)
        -> impl Future<Output = Result<()>> + MaybeSend;

    /// Обновить статус сообщения
    fn update_message_status(
        &self,
        message_id: &str,
        status: MessageStatus,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Загрузить сообщения из беседы
    ///
    /// # Parameters
    /// - `conversation_id`: ID беседы (обычно совпадает с contact_id)
    /// - `limit`: Максимальное количество сообщений
    /// - `offset`: Смещение для pagination
    fn load_messages(
        &self,
        conversation_id: &str,
        limit: usize,
        offset: usize,
    ) -> impl Future<Output = Result<Vec<StoredMessage>>> + MaybeSend;

    /// Загрузить сообщение по ID
    fn load_message(
        &self,
        message_id: &str,
    ) -> impl Future<Output = Result<Option<StoredMessage>>> + MaybeSend;

    /// Удалить сообщение
    fn delete_message(&self, message_id: &str) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Удалить все сообщения из беседы
    fn delete_messages_in_conversation(
        &self,
        conversation_id: &str,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Получить количество сообщений в беседе
    fn count_messages(
        &self,
        conversation_id: &str,
    ) -> impl Future<Output = Result<usize>> + MaybeSend;

    // === Contacts ===

    /// Сохранить контакт
    fn save_contact(&self, contact: &StoredContact)
        -> impl Future<Output = Result<()>> + MaybeSend;

    /// Загрузить контакт по ID
    fn load_contact(
        &self,
        contact_id: &str,
    ) -> impl Future<Output = Result<Option<StoredContact>>> + MaybeSend;

    /// Загрузить все контакты
    fn load_contacts(&self) -> impl Future<Output = Result<Vec<StoredContact>>> + MaybeSend;

    /// Обновить время последнего сообщения контакта
    fn update_contact_last_message(
        &self,
        contact_id: &str,
        timestamp: i64,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Удалить контакт
    fn delete_contact(&self, contact_id: &str) -> impl Future<Output = Result<()>> + MaybeSend;

    // === Conversations ===

    /// Сохранить/обновить беседу
    fn save_conversation(
        &self,
        conversation: &Conversation,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Загрузить беседу
    fn load_conversation(
        &self,
        conversation_id: &str,
    ) -> impl Future<Output = Result<Option<Conversation>>> + MaybeSend;

    /// Загрузить все беседы
    fn load_conversations(&self) -> impl Future<Output = Result<Vec<Conversation>>> + MaybeSend;

    /// Обновить непрочитанное количество
    fn update_conversation_unread(
        &self,
        conversation_id: &str,
        count: u32,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Удалить беседу
    fn delete_conversation(
        &self,
        conversation_id: &str,
    ) -> impl Future<Output = Result<()>> + MaybeSend;

    // === Maintenance ===

    /// Очистить все данные (используется при logout или reset)
    fn clear_all(&self) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Экспортировать данные для бэкапа (опционально)
    fn export_data(&self) -> impl Future<Output = Result<Vec<String>>> + MaybeSend {
        async { Err(crate::utils::error::ConstructError::NotImplemented) }
    }

    /// Импортировать данные из бэкапа (опционально)
    fn import_data(&self, _data: &[u8]) -> impl Future<Output = Result<()>> + MaybeSend {
        async { Err(crate::utils::error::ConstructError::NotImplemented) }
    }
}

// ============================================================================
// Auth Tokens Model
// ============================================================================

/// Токены аутентификации (JWT)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(feature = "ios", feature = "mac"), derive(uniffi::Record))]
pub struct AuthTokens {
    /// Access token (JWT, живёт 1 час)
    #[serde(rename = "accessToken")]
    pub access_token: String,

    /// Refresh token (JWT, живёт 30 дней)
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,

    /// Unix timestamp когда истекает access token
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,

    /// User ID (UUID)
    // Note: IndexedDB keyPath настроен на "userId" для соответствия serde rename
    #[serde(rename = "userId")]
    pub user_id: String,
}

impl AuthTokens {
    /// Проверить, истекает ли токен скоро
    ///
    /// # Parameters
    /// - `buffer_seconds`: Буфер в секундах (обычно 300 = 5 минут)
    pub fn is_expiring_soon(&self, buffer_seconds: i64) -> bool {
        let now = crate::utils::time::current_timestamp();
        self.expires_at - now < buffer_seconds
    }

    /// Проверить, истёк ли токен
    pub fn is_expired(&self) -> bool {
        let now = crate::utils::time::current_timestamp();
        self.expires_at <= now
    }
}

// ============================================================================
// Combined Storage Trait
// ============================================================================

/// Комбинированный trait для хранилищ которые реализуют оба интерфейса
///
/// Используется когда одна реализация (например IndexedDB) предоставляет
/// и secure storage и data storage.
pub trait CombinedStorage: SecureStorage + DataStorage {}

// Автоматическая реализация для типов реализующих оба trait
impl<T: SecureStorage + DataStorage> CombinedStorage for T {}

// ============================================================================
// Helper функции
// ============================================================================

/// Создать ID для хранения сессии
pub fn session_storage_key(contact_id: &str) -> String {
    format!("session_{}", contact_id)
}

/// Создать ID для conversation
pub fn conversation_id_from_contact(contact_id: &str) -> String {
    // Обычно conversation_id совпадает с contact_id
    contact_id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_tokens_expiration() {
        let now = crate::utils::time::current_timestamp() as i64;

        // Токен истекает через 2 минуты
        let tokens = AuthTokens {
            access_token: "test".to_string(),
            refresh_token: "test".to_string(),
            expires_at: now + 120, // +2 минуты
            user_id: "test_user".to_string(),
        };

        // Не истекает сейчас
        assert!(!tokens.is_expired());

        // Истекает скоро (буфер 5 минут = 300 сек, токен живёт 120 сек < 300)
        assert!(tokens.is_expiring_soon(300));

        // Не истекает скоро (буфер 1 минута = 60 сек, токен живёт 120 сек > 60)
        assert!(!tokens.is_expiring_soon(60));
    }

    #[test]
    fn test_session_storage_key() {
        assert_eq!(session_storage_key("user123"), "session_user123");
    }

    #[test]
    fn test_conversation_id() {
        assert_eq!(conversation_id_from_contact("contact456"), "contact456");
    }
}
