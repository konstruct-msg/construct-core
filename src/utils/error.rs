// Типы ошибок

use crate::error::CryptoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConstructError {
    /// Криптографическая ошибка
    #[error("Cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    /// Ошибка хранилища
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Ошибка сети
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Ошибка сериализации
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Ошибка валидации
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Ошибка сессии
    #[error("Session error: {0}")]
    SessionError(String),

    /// Не найдено
    #[error("Not found: {0}")]
    NotFound(String),

    /// Неверный ввод
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Внутренняя ошибка
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Функция не реализована
    #[error("Not implemented")]
    NotImplemented,

    /// Ошибка аутентификации
    #[error("Unauthenticated: {0}")]
    Unauthenticated(String),
}

pub type Result<T> = std::result::Result<T, ConstructError>;

// Alias для совместимости
pub type MessengerError = ConstructError;

// Для конвертации String ошибок из callback интерфейсов
impl From<String> for ConstructError {
    fn from(error: String) -> Self {
        ConstructError::StorageError(error)
    }
}

// Для конвертации &str ошибок
impl From<&str> for ConstructError {
    fn from(error: &str) -> Self {
        ConstructError::StorageError(error.to_string())
    }
}
