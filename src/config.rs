//! Централизованная конфигурация для Construct Messenger Core
//!
//! Все константы и настройки приложения должны быть определены здесь,
//! чтобы избежать хардкода по всему проекту.

use std::sync::OnceLock;

/// Глобальная конфигурация приложения (синглтон)
static GLOBAL_CONFIG: OnceLock<Config> = OnceLock::new();

/// Основная структура конфигурации
#[derive(Debug, Clone)]
pub struct Config {
    // ============================================
    // КРИПТОГРАФИЧЕСКИЕ ПАРАМЕТРЫ
    // ============================================
    /// PBKDF2: количество итераций для деривации мастер-ключа из пароля
    pub pbkdf2_iterations: u32,

    /// Длина соли для PBKDF2 (в байтах)
    pub salt_length: usize,

    /// Длина ключа для AES-256 (в байтах)
    pub key_length: usize,

    /// Длина nonce для AES-GCM (в байтах)
    pub nonce_length: usize,

    /// Длина nonce для ChaCha20Poly1305 (в байтах)
    pub chacha_nonce_length: usize,

    /// Размер GCM authentication tag (в байтах)
    pub gcm_tag_length: usize,

    /// Размер публичного ключа X25519 (в байтах)
    pub public_key_size: usize,

    /// Размер Ed25519 подписи (в байтах)
    pub signature_size: usize,

    /// ID классического криптографического набора (Classic Suite)
    pub classic_suite_id: u16,

    // ============================================
    // DOUBLE RATCHET ПАРАМЕТРЫ
    // ============================================
    /// Максимальное количество пропущенных сообщений (DoS защита)
    pub max_skipped_messages: u32,

    /// Максимальный допустимый "прыжок" номера сообщения вперёд за один decrypt.
    /// Предотвращает CPU-exhaustion атаку: без этого лимита сообщение с
    /// msg_num = 1_000_000 заставляет движок вычислить миллион шагов HKDF-цепочки
    /// до срабатывания лимита памяти.
    /// По умолчанию: 2000 (достаточно для любого разумного out-of-order окна)
    pub max_message_jump: u32,

    /// Максимальный возраст пропущенных ключей сообщений (в секундах)
    /// По умолчанию: 7 дней
    pub max_skipped_message_age_seconds: i64,

    // ============================================
    // ВАЛИДАЦИЯ
    // ============================================
    /// Минимальная длина username
    pub username_min_length: usize,

    /// Максимальная длина username
    pub username_max_length: usize,

    /// Минимальная длина пароля
    pub password_min_length: usize,

    /// Длина UUID (стандарт RFC 4122)
    pub uuid_length: usize,

    /// Длина ephemeral public key в сообщениях (X25519)
    pub ephemeral_key_size: usize,

    /// Длина Base64-encoded публичного ключа
    pub base64_public_key_length: usize,

    /// Длина Base64-encoded подписи
    pub base64_signature_length: usize,

    // ============================================
    // ВРЕМЕННЫЕ ПАРАМЕТРЫ
    // ============================================
    /// Максимальное время в будущем для timestamp сообщения (в секундах)
    /// По умолчанию: 5 минут
    pub message_timestamp_future_tolerance_secs: i64,

    /// Максимальное время в прошлом для timestamp сообщения (в секундах)
    /// По умолчанию: 1 час
    pub message_timestamp_past_tolerance_secs: i64,

    /// Период cleanup старых prekeys (в секундах)
    /// По умолчанию: 30 дней
    pub prekey_cleanup_period_secs: i64,

    // ============================================
    // СЕТЕВЫЕ ПАРАМЕТРЫ
    // ============================================
    /// Начальная задержка для exponential backoff при переподключении (в миллисекундах)
    pub websocket_retry_initial_ms: u64,

    /// Максимальная задержка для exponential backoff (в миллисекундах)
    pub websocket_retry_max_ms: u64,

    /// WebSocket OPEN state код
    pub websocket_ready_state_open: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Криптография
            pbkdf2_iterations: 100_000,
            salt_length: 32,
            key_length: 32,
            nonce_length: 12,
            chacha_nonce_length: 12,
            gcm_tag_length: 16,
            public_key_size: 32,
            signature_size: 64,
            classic_suite_id: 1,

            // Double Ratchet
            max_skipped_messages: 1000,
            max_message_jump: 2000,
            max_skipped_message_age_seconds: 7 * 24 * 60 * 60, // 7 days

            // Валидация
            username_min_length: 3,
            username_max_length: 32,
            password_min_length: 8,
            uuid_length: 36,
            ephemeral_key_size: 32,
            base64_public_key_length: 44,
            base64_signature_length: 88,

            // Временные параметры
            message_timestamp_future_tolerance_secs: 300, // 5 minutes
            message_timestamp_past_tolerance_secs: 3600,  // 1 hour
            prekey_cleanup_period_secs: 30 * 24 * 60 * 60, // 30 days

            // Сетевые параметры
            websocket_retry_initial_ms: 1000,
            websocket_retry_max_ms: 30000,
            websocket_ready_state_open: 1,
        }
    }
}

impl Config {
    /// Создать конфигурацию из переменных окружения
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // ✅ SECURITY: Validate environment variables to prevent misconfiguration attacks
        // Ref: SECURITY_AUDIT.md #9 - env vars can weaken security

        // Переопределяем значения из env, если они заданы
        if let Ok(val) = std::env::var("MAX_SKIPPED_MESSAGES") {
            if let Ok(parsed) = val.parse::<u32>() {
                // ✅ Enforce maximum to prevent memory exhaustion DoS
                const MIN_SKIPPED: u32 = 10;
                const MAX_SKIPPED: u32 = 10_000;
                config.max_skipped_messages = parsed.clamp(MIN_SKIPPED, MAX_SKIPPED);
                if !(MIN_SKIPPED..=MAX_SKIPPED).contains(&parsed) {
                    tracing::warn!(
                        parsed,
                        clamped = config.max_skipped_messages,
                        "MAX_SKIPPED_MESSAGES out of safe range [{}-{}], clamped",
                        MIN_SKIPPED,
                        MAX_SKIPPED
                    );
                }
            }
        }

        if let Ok(val) = std::env::var("MAX_SKIPPED_MESSAGE_AGE_SECONDS") {
            if let Ok(parsed) = val.parse::<i64>() {
                // ✅ Enforce minimum to prevent premature key deletion
                const MIN_AGE: i64 = 60; // At least 1 minute
                const MAX_AGE: i64 = 2_592_000; // Max 30 days
                config.max_skipped_message_age_seconds = parsed.clamp(MIN_AGE, MAX_AGE);
                if !(MIN_AGE..=MAX_AGE).contains(&parsed) {
                    tracing::warn!(
                        parsed,
                        clamped = config.max_skipped_message_age_seconds,
                        "MAX_SKIPPED_MESSAGE_AGE_SECONDS out of safe range [{}-{}], clamped",
                        MIN_AGE,
                        MAX_AGE
                    );
                }
            }
        }

        if let Ok(val) = std::env::var("PBKDF2_ITERATIONS") {
            if let Ok(parsed) = val.parse::<u32>() {
                // ✅ Enforce minimum to prevent brute-force attacks
                const MIN_ITERATIONS: u32 = 10_000;
                const MAX_ITERATIONS: u32 = 1_000_000; // Prevent DoS via excessive iterations
                config.pbkdf2_iterations = parsed.clamp(MIN_ITERATIONS, MAX_ITERATIONS);
                if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&parsed) {
                    tracing::warn!(
                        parsed,
                        clamped = config.pbkdf2_iterations,
                        "PBKDF2_ITERATIONS out of safe range [{}-{}], clamped",
                        MIN_ITERATIONS,
                        MAX_ITERATIONS
                    );
                }
            }
        }

        if let Ok(val) = std::env::var("WEBSOCKET_RETRY_MAX_MS") {
            if let Ok(parsed) = val.parse::<u64>() {
                // ✅ Enforce minimum to prevent infinite retry loops
                const MIN_RETRY: u64 = 100; // At least 100ms
                const MAX_RETRY: u64 = 300_000; // Max 5 minutes
                config.websocket_retry_max_ms = parsed.clamp(MIN_RETRY, MAX_RETRY);
                if !(MIN_RETRY..=MAX_RETRY).contains(&parsed) {
                    tracing::warn!(
                        parsed,
                        clamped = config.websocket_retry_max_ms,
                        "WEBSOCKET_RETRY_MAX_MS out of safe range [{}-{}], clamped",
                        MIN_RETRY,
                        MAX_RETRY
                    );
                }
            }
        }

        config
    }

    /// Получить глобальный экземпляр конфигурации
    ///
    /// Автоматически инициализирует конфигурацию со значениями по умолчанию при первом вызове
    pub fn global() -> &'static Config {
        GLOBAL_CONFIG.get_or_init(Config::default)
    }

    /// Инициализировать глобальную конфигурацию со значениями по умолчанию
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если конфигурация уже была инициализирована
    pub fn init() -> Result<(), &'static str> {
        GLOBAL_CONFIG
            .set(Self::default())
            .map_err(|_| "Config already initialized")
    }

    /// Инициализировать глобальную конфигурацию из переменных окружения
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если конфигурация уже была инициализирована
    pub fn init_from_env() -> Result<(), &'static str> {
        GLOBAL_CONFIG
            .set(Self::from_env())
            .map_err(|_| "Config already initialized")
    }

    /// Инициализировать глобальную конфигурацию с кастомным экземпляром
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если конфигурация уже была инициализирована
    pub fn init_with(config: Config) -> Result<(), &'static str> {
        GLOBAL_CONFIG
            .set(config)
            .map_err(|_| "Config already initialized")
    }

    /// Проверить, инициализирована ли глобальная конфигурация
    pub fn is_initialized() -> bool {
        GLOBAL_CONFIG.get().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.pbkdf2_iterations, 100_000);
        assert_eq!(config.max_skipped_messages, 1000);
        assert_eq!(config.username_min_length, 3);
    }

    #[test]
    fn test_config_values() {
        let config = Config::default();

        // Crypto params
        assert_eq!(config.salt_length, 32);
        assert_eq!(config.key_length, 32);
        assert_eq!(config.nonce_length, 12);
        assert_eq!(config.classic_suite_id, 1);

        // Validation
        assert_eq!(config.password_min_length, 8);
        assert_eq!(config.uuid_length, 36);

        // Network
        assert_eq!(config.websocket_retry_initial_ms, 1000);
        assert_eq!(config.websocket_retry_max_ms, 30000);
    }
}
