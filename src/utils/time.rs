// Время и таймеры

/// Получить текущее время в секундах с UNIX epoch (u64)
///
/// ✅ SECURITY: Safe fallback to 0 if system clock is before epoch
/// Ref: SECURITY_AUDIT.md #11 - SystemTime::unwrap() panic
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Получить текущий timestamp в секундах с UNIX epoch (i64)
///
/// ✅ SECURITY: Safe fallback to 0 if system clock is before epoch
/// Ref: SECURITY_AUDIT.md #11 - SystemTime::unwrap() panic
pub fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
