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

/// Получить текущее время в миллисекундах с UNIX epoch
///
/// ✅ SECURITY: Safe fallback to 0 if system clock is before epoch
/// Ref: SECURITY_AUDIT.md #11 - SystemTime::unwrap() panic
pub fn current_timestamp_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Получить текущий timestamp в ISO8601 формате с fractional seconds
/// Формат: "2026-01-13T07:22:06.209+00:00"
pub fn current_timestamp_iso8601() -> String {
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}
