/// Platform I/O bridge — callback interface implemented by Swift/Kotlin.
///
/// Rust orchestration logic stays pure (no direct I/O). Instead it calls
/// through this bridge to request platform-specific operations (Keychain,
/// Core Data, logging). UniFFI exposes it as a `callback interface` so that
/// Swift/Kotlin can pass in their own implementations at runtime.
///
/// # Contract
///
/// - `save_to_secure_store` / `load_from_secure_store`: encrypted key-value store
///   (iOS Keychain / Android Keystore).
/// - `persist_record` / `query_record`: structured data store (Core Data / Room).
///   `table` is a logical table name; `json` / `query_json` are JSON-encoded payloads.
/// - `log_event`: platform logging (os_log / Logcat). `level` ∈ {"debug","info","warn","error"}.
pub trait PlatformBridge: Send + Sync {
    /// Persist `data` under `key` in the platform secure store.
    fn save_to_secure_store(&self, key: String, data: Vec<u8>);

    /// Retrieve data previously saved under `key`. Returns `None` if absent.
    fn load_from_secure_store(&self, key: String) -> Option<Vec<u8>>;

    /// Append / upsert a JSON record in the platform data store.
    fn persist_record(&self, table: String, json: String);

    /// Query the platform data store. Returns a JSON-encoded result or `None`.
    fn query_record(&self, table: String, query_json: String) -> Option<String>;

    /// Emit a log entry through the platform logging system.
    fn log_event(&self, level: String, tag: String, message: String);
}

// ─── In-memory mock used in unit tests ───────────────────────────────────────

#[cfg(test)]
pub(crate) mod test_support {
    use super::PlatformBridge;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Thread-safe in-memory implementation of `PlatformBridge` for unit tests.
    #[derive(Default)]
    pub struct MockPlatformBridge {
        secure_store: Mutex<HashMap<String, Vec<u8>>>,
        data_store: Mutex<HashMap<String, Vec<String>>>,
        pub logs: Mutex<Vec<String>>,
    }

    impl PlatformBridge for MockPlatformBridge {
        fn save_to_secure_store(&self, key: String, data: Vec<u8>) {
            self.secure_store.lock().unwrap().insert(key, data);
        }

        fn load_from_secure_store(&self, key: String) -> Option<Vec<u8>> {
            self.secure_store.lock().unwrap().get(&key).cloned()
        }

        fn persist_record(&self, table: String, json: String) {
            self.data_store
                .lock()
                .unwrap()
                .entry(table)
                .or_default()
                .push(json);
        }

        fn query_record(&self, table: String, _query_json: String) -> Option<String> {
            self.data_store
                .lock()
                .unwrap()
                .get(&table)
                .and_then(|rows| rows.last().cloned())
        }

        fn log_event(&self, level: String, tag: String, message: String) {
            self.logs
                .lock()
                .unwrap()
                .push(format!("[{}] {}: {}", level, tag, message));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::MockPlatformBridge, PlatformBridge};

    #[test]
    fn test_secure_store_roundtrip() {
        let bridge = MockPlatformBridge::default();
        let key = "session_alice".to_string();
        let data = b"secret-session-bytes".to_vec();

        bridge.save_to_secure_store(key.clone(), data.clone());
        let loaded = bridge.load_from_secure_store(key);

        assert_eq!(loaded, Some(data));
    }

    #[test]
    fn test_load_missing_key_returns_none() {
        let bridge = MockPlatformBridge::default();
        assert_eq!(bridge.load_from_secure_store("nonexistent".to_string()), None);
    }

    #[test]
    fn test_persist_and_query_record() {
        let bridge = MockPlatformBridge::default();
        bridge.persist_record("ack_store".to_string(), r#"{"id":"msg1"}"#.to_string());
        let result = bridge.query_record("ack_store".to_string(), "{}".to_string());
        assert_eq!(result, Some(r#"{"id":"msg1"}"#.to_string()));
    }

    #[test]
    fn test_log_event() {
        let bridge = MockPlatformBridge::default();
        bridge.log_event("info".to_string(), "Session".to_string(), "Initialized".to_string());
        let logs = bridge.logs.lock().unwrap();
        assert_eq!(logs[0], "[info] Session: Initialized");
    }

    #[test]
    fn test_save_overwrites_previous_value() {
        let bridge = MockPlatformBridge::default();
        let key = "key".to_string();
        bridge.save_to_secure_store(key.clone(), vec![1, 2, 3]);
        bridge.save_to_secure_store(key.clone(), vec![4, 5, 6]);
        assert_eq!(bridge.load_from_secure_store(key), Some(vec![4, 5, 6]));
    }
}
