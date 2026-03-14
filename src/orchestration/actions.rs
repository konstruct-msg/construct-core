/// Action — платформенная операция, которую Rust-ядро просит выполнить Swift/Kotlin.
///
/// Rust принимает события, вычисляет решения и возвращает `Vec<Action>`.
/// Платформенный слой исполняет каждое действие и при необходимости передаёт
/// результат обратно через `IncomingEvent`.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    // ── Cryptographic operations ──────────────────────────────────────────────
    DecryptMessage {
        contact_id: String,
        ciphertext: Vec<u8>,
    },
    EncryptMessage {
        contact_id: String,
        plaintext: Vec<u8>,
    },
    InitSession {
        contact_id: String,
        bundle_json: String,
    },
    ApplyPQContribution {
        contact_id: String,
        kem_ss: Vec<u8>,
    },
    ArchiveSession {
        contact_id: String,
    },

    // ── Persistence ───────────────────────────────────────────────────────────
    SaveSessionToSecureStore {
        key: String,
        data: Vec<u8>,
    },
    LoadSessionFromSecureStore {
        key: String,
    },
    PersistMessage {
        message_json: String,
    },
    MarkMessageDelivered {
        message_id: String,
    },

    // ── Network ───────────────────────────────────────────────────────────────
    FetchPublicKeyBundle {
        user_id: String,
    },
    SendEncryptedMessage {
        to: String,
        payload: Vec<u8>,
    },
    SendReceipt {
        message_id: String,
        status: ReceiptStatus,
    },
    SendEndSession {
        contact_id: String,
    },

    // ── UI ────────────────────────────────────────────────────────────────────
    NotifyNewMessage {
        chat_id: String,
        preview: String,
    },
    NotifySessionCreated {
        contact_id: String,
    },
    NotifyError {
        code: String,
        message: String,
    },

    // ── Scheduling ────────────────────────────────────────────────────────────
    ScheduleTimer {
        timer_id: String,
        delay_ms: u64,
    },
    CancelTimer {
        timer_id: String,
    },
}

/// Delivery / read receipt status.
#[derive(Debug, Clone, PartialEq)]
pub enum ReceiptStatus {
    Sent,
    Delivered,
    Read,
    Failed,
}

/// Event — входящее событие, поступающее в Rust-ядро от платформенного слоя.
///
/// Платформа вызывает `Orchestrator::handle_event(event)` после каждого I/O результата.
#[derive(Debug, Clone)]
pub enum IncomingEvent {
    MessageReceived {
        from: String,
        data: Vec<u8>,
        msg_num: u32,
        /// ML-KEM-768 ciphertext (empty if no PQ contribution in this message).
        kem_ct: Vec<u8>,
        otpk_id: u32,
    },
    SessionInitCompleted {
        contact_id: String,
        session_json: String,
    },
    AckReceived {
        message_id: String,
    },
    /// Result of `LoadSessionFromSecureStore` action.
    SessionLoaded {
        key: String,
        data: Option<Vec<u8>>,
    },
    /// Server returned a key bundle in response to `FetchPublicKeyBundle`.
    KeyBundleFetched {
        user_id: String,
        bundle_json: String,
    },
    NetworkReconnected,
    AppLaunched,
    TimerFired {
        timer_id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_debug() {
        let a = Action::SaveSessionToSecureStore {
            key: "session_bob".to_string(),
            data: vec![1, 2, 3],
        };
        let s = format!("{:?}", a);
        assert!(s.contains("SaveSessionToSecureStore"));
        assert!(s.contains("session_bob"));
    }

    #[test]
    fn test_receipt_status_variants() {
        let statuses = [
            ReceiptStatus::Sent,
            ReceiptStatus::Delivered,
            ReceiptStatus::Read,
            ReceiptStatus::Failed,
        ];
        for s in &statuses {
            let _ = format!("{:?}", s); // must be Debug
        }
    }

    #[test]
    fn test_incoming_event_clone() {
        let ev = IncomingEvent::AckReceived {
            message_id: "abc-123".to_string(),
        };
        let ev2 = ev.clone();
        matches!(ev2, IncomingEvent::AckReceived { .. });
    }
}
