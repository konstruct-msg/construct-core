/// Monotonic-safe clock abstraction for the orchestration layer.
///
/// All TTL checks (cooldowns, init-lock timeouts, archive GC, ACK expiry,
/// heal-attempt TTLs) go through this trait instead of calling
/// `SystemTime::now()` directly.  This protects against:
///
/// - **NTP jump backwards** — cooldown resets, flood-protection disabled.
/// - **NTP jump forwards** — all archives/heals/ACKs instantly expire.
/// - **Testability** — `MockClock` lets unit tests control time without sleep.
///
/// Platform code uses `SystemClock`.  Integration tests inject `MockClock`.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// Milliseconds since Unix epoch (wall clock — suitable for persisted
    /// timestamps that must survive app restarts).
    fn now_ms(&self) -> u64;

    /// Seconds since Unix epoch.
    fn now_secs(&self) -> u64 {
        self.now_ms() / 1_000
    }
}

// ── Production implementation ─────────────────────────────────────────────────

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

#[cfg(test)]
pub struct MockClock(std::sync::atomic::AtomicU64);

#[cfg(test)]
impl MockClock {
    pub fn new(initial_ms: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(initial_ms))
    }

    /// Advance the clock by `delta_ms` milliseconds.
    pub fn advance_ms(&self, delta_ms: u64) {
        self.0
            .fetch_add(delta_ms, std::sync::atomic::Ordering::Relaxed);
    }

    /// Set the clock to an absolute value.
    pub fn set_ms(&self, ms: u64) {
        self.0.store(ms, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Convenience: wrap a `MockClock` in an `Arc<dyn Clock>`.
#[cfg(test)]
pub fn mock_clock(initial_ms: u64) -> Arc<dyn Clock> {
    Arc::new(MockClock::new(initial_ms))
}

/// Convenience: create a `SystemClock` wrapped in `Arc<dyn Clock>`.
pub fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}
