//! Compatibility configuration API for Rust callers.
//!
//! Protocol code uses the fixed limits directly. `Config` exposes those same values through
//! the existing Rust API; it does not configure the engine.

use crate::limits;
use std::sync::OnceLock;

/// Initialization state of the compatibility API.
static GLOBAL_CONFIG: OnceLock<Config> = OnceLock::new();

/// Основная структура конфигурации
#[derive(Debug, Clone)]
pub struct Config {
    // ============================================
    // КРИПТОГРАФИЧЕСКИЕ ПАРАМЕТРЫ
    // ============================================
    /// Длина nonce для ChaCha20Poly1305 (в байтах)
    pub chacha_nonce_length: usize,

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

    /// Интервал (в DH-ratchet-поворотах) между подмешиваниями свежего
    /// ML-KEM-768 материала в sparse continuous PQ ratchet (`PQ_RATCHET`).
    /// По умолчанию: 16 поворотов — тот же порядок величины, что и у публично
    /// описанного Signal SPQR (2025).
    pub pq_ratchet_interval: u32,

    /// PQR-1: the longest a PQ epoch lasts before the exchange initiator proposes a new one on its
    /// next send, turns or not. The turn count alone never fires in a conversation that does not
    /// change direction. 7 days — the floor Apple PQ3 guarantees.
    pub pq_ratchet_max_age_seconds: u64,

    // ============================================
    // ВРЕМЕННЫЕ ПАРАМЕТРЫ
    // ============================================
    /// Сколько хранится signed prekey после ротации (в секундах), классический и Kyber.
    /// По умолчанию: `SPK_RETENTION_AFTER_ROTATION_SECS` (14 дней).
    pub prekey_cleanup_period_secs: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chacha_nonce_length: limits::CHACHA_NONCE_LENGTH,
            max_skipped_messages: limits::MAX_SKIPPED_MESSAGES,
            max_message_jump: limits::MAX_MESSAGE_JUMP,
            max_skipped_message_age_seconds: limits::MAX_SKIPPED_MESSAGE_AGE_SECONDS,
            pq_ratchet_interval: limits::PQ_RATCHET_INTERVAL,
            pq_ratchet_max_age_seconds: limits::PQ_RATCHET_MAX_AGE_SECONDS,
            prekey_cleanup_period_secs: limits::SPK_RETENTION_AFTER_ROTATION_SECS as i64,
        }
    }
}

impl Config {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.max_skipped_messages, 1000);
        assert_eq!(config.pq_ratchet_interval, 16);
        assert_eq!(config.chacha_nonce_length, 12);
    }
}
