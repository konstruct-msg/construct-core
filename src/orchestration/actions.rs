/// Action — платформенная операция, которую Rust-ядро просит выполнить Swift/Kotlin.
///
/// Rust принимает события, вычисляет решения и возвращает `Vec<Action>`.
/// Платформенный слой исполняет каждое действие и при необходимости передаёт
/// результат обратно через `IncomingEvent`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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

    /// Emitted when a message has been successfully decrypted.
    /// Carries the full plaintext so the platform can persist + display it.
    MessageDecrypted {
        contact_id: String,
        message_id: String,
        plaintext_utf8: String,
    },

    /// Binary payload decrypted from a CALL_SIGNAL envelope (content_type = 12).
    /// Carries raw proto bytes — `WebRTCSignal` serialized with protobuf.
    /// Never saved to Core Data; routed directly to the platform call manager.
    CallSignalDecrypted {
        contact_id: String,
        message_id: String,
        /// Serialised `WebRTCSignal` protobuf bytes.
        proto_bytes: Vec<u8>,
    },

    /// Decryption failed on message 0; the session needs healing.
    /// `role` is either `"Initiator"` (higher userId, wins tie-break) or `"Responder"`.
    SessionHealNeeded {
        contact_id: String,
        role: String,
    },

    /// A `SessionHealNeeded` decision was suppressed by the per-contact cooldown.
    /// The platform must NOT acknowledge the message — leave it unread so the server
    /// re-delivers it after `retry_after_ms` milliseconds when the cooldown clears.
    HealSuppressed {
        contact_id: String,
        retry_after_ms: u64,
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
    /// Persist an ACK deduplication record across app restarts.
    /// The platform must store `(message_id, timestamp)` and load them back
    /// via `ack_mark_processed` on next launch to pre-populate the in-memory cache.
    PersistAck {
        message_id: String,
        timestamp: u64,
    },
    /// Request the platform to delete ACK records older than `cutoff_ts` (unix seconds).
    PruneAckStore {
        cutoff_ts: u64,
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
        /// Server-assigned message UUID.
        message_id: String,
        /// Content-type discriminator (matches proto ContentType enum).
        /// 0 = regular E2EE message; 12 = CALL_SIGNAL.
        content_type: u8,
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

    /// Request platform to query its persistent ACK store for `message_id`.
    /// The platform must respond with `IncomingEvent::AckDbResult`.
    /// While the check is pending the message is held in a buffer and not ACK'd.
    CheckAckInDb {
        message_id: String,
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ReceiptStatus {
    Sent,
    Delivered,
    Read,
    Failed,
}

/// Event — входящее событие, поступающее в Rust-ядро от платформенного слоя.
///
/// Платформа вызывает `Orchestrator::handle_event(event)` после каждого I/O результата.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum IncomingEvent {
    MessageReceived {
        /// Server-assigned message UUID (used for ACK deduplication).
        message_id: String,
        from: String,
        data: Vec<u8>,
        msg_num: u32,
        /// ML-KEM-768 ciphertext (empty if no PQ contribution in this message).
        kem_ct: Vec<u8>,
        otpk_id: u32,
        /// `true` when this is a control message (e.g. END_SESSION).
        is_control: bool,
        /// Content-type from the server envelope (proto ContentType enum value).
        /// 0 = regular E2EE message; 12 = CALL_SIGNAL.
        content_type: u8,
    },
    /// Platform-side outgoing regular message.
    /// Rust orchestrator encrypts `plaintext_utf8` bytes with the Double Ratchet session,
    /// packs a WirePayload (including PQXDH KEM ciphertext for msgNum=0, sourced
    /// internally from `pq_manager`), and returns `Action::SendEncryptedMessage`.
    OutgoingMessage {
        /// Contact (peer) user ID.
        contact_id: String,
        /// Platform-generated message UUID for deduplication / ACK tracking.
        message_id: String,
        /// Raw UTF-8 text of the plaintext message.
        plaintext_utf8: String,
        /// Content-type discriminator (matches proto ContentType enum).
        /// 0 = regular E2EE message.
        content_type: u8,
    },
    /// Platform-side outgoing call signal.
    /// Rust orchestrator encrypts `proto_bytes` with the Double Ratchet session,
    /// packs a WirePayload, and returns `Action::SendEncryptedMessage`.
    OutgoingCallSignal {
        /// Contact (peer) user ID.
        contact_id: String,
        /// Platform-generated message UUID for deduplication / ACK tracking.
        message_id: String,
        /// Serialised `WebRTCSignal` protobuf bytes — encrypted opaquely by Rust.
        proto_bytes: Vec<u8>,
    },
    SessionInitCompleted {
        contact_id: String,
        /// CFE binary session bytes. May be empty if the session is already in the
        /// orchestrator (e.g. immediately after `initReceivingSession`).
        session_data: Vec<u8>,
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
    /// Platform's response to `Action::CheckAckInDb`.
    /// If `is_processed` is `true`, the buffered message is discarded as a duplicate.
    /// If `false`, the message is re-routed as if freshly received.
    AckDbResult {
        message_id: String,
        is_processed: bool,
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
