/// Action — платформенная операция, которую Rust-ядро просит выполнить Swift/Kotlin.
///
/// Rust принимает события, вычисляет решения и возвращает `Vec<Action>`.
/// Платформенный слой исполняет каждое действие и при необходимости передаёт
/// результат обратно через `IncomingEvent`.
/// Which durable slot a `SaveToSecureStore` payload belongs in.
///
/// The core names *what* the bytes are; the platform names *where* they go. Until 2026-08-26 the
/// action carried a formatted string (`"session_<id>"`, `"archive_<id>"`, `"pq_deferred_<id>"`, …)
/// and the platform parsed it back apart — so the naming rule for a store the core does not own
/// was written six times: `session_key()` here, twice more inline in `orchestrator.rs`, once in
/// reverse in `handle_session_loaded`, and twice again on the iOS side, which stripped the prefix
/// only to rebuild the identical string two layers down. A rule written six times is a rule that
/// can change in five places and hold in the sixth.
///
/// A variant here is also the only way a new slot can be added: the platform's `switch` stops
/// compiling until it says what to do with it. The string form had an `else` branch that logged
/// "unhandled storage key" at debug level and returned success, which is where `kyber_session_state`
/// and `kyber_spk_<id>` have been landing.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SecureStoreSlot {
    /// Double Ratchet state for one contact. Empty payload means delete.
    Session { contact_id: String },
    /// A terminated session, kept for late-arriving messages.
    SessionArchive { contact_id: String },
    /// Deferred ML-KEM contribution for one contact. Empty payload means delete.
    PqDeferred { contact_id: String },
    /// Whole `PQContributionManager` snapshot.
    KyberSessionState,
    /// Secret half of a committed ML-KEM signed prekey.
    ///
    /// Nothing reaches this today: `commit_spk_rotation` is called only from its own tests, and
    /// iOS rotates the Kyber SPK through `PreKeyRotationService` instead. Kept faithful rather
    /// than dropped so that if the emitter ever becomes reachable the platform is forced to
    /// answer for it.
    KyberSignedPrekey { key_id: u32 },
    /// Orchestrator coordination state.
    OrchestratorState,
}

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
    /// Carries the raw plaintext bytes so the platform can parse them (protobuf,
    /// plain UTF-8, or chunked-KNST binary frame) without any lossy conversion.
    MessageDecrypted {
        contact_id: String,
        message_id: String,
        plaintext: Vec<u8>,
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

    /// An `EndSessionNeeded` decision was suppressed by the per-contact cooldown, and the
    /// orchestrator has taken ownership of sending it once the cooldown clears (in
    /// `retry_after_ms`). The platform must NOT acknowledge the message.
    ///
    /// This used to be `return vec![]` — indistinguishable from `Duplicate`'s empty verdict,
    /// so iOS guessed ("dropped, pending redelivery") and the teardown was never sent at all.
    /// Recovery for a message that failed to decrypt at msgNum > 0 runs entirely through the
    /// peer: END_SESSION makes it re-establish and re-send. Suppressing the END_SESSION
    /// suppresses the recovery, and build 585 lost three media messages that way.
    EndSessionSuppressed {
        contact_id: String,
        retry_after_ms: u64,
    },

    /// A message arrived while session init for this contact was already in flight. It is
    /// **queued inside the core** (`pending_queues`) and drained on `SessionInitCompleted` —
    /// nothing is required of the platform, and nothing has been lost.
    ///
    /// Also formerly `return vec![]`. iOS read that as a drop and logged "holding the cursor
    /// for redelivery" over a message the core was safely holding.
    MessageQueuedPendingInit {
        contact_id: String,
        queued_count: u32,
    },

    // ── Persistence ───────────────────────────────────────────────────────────
    /// Write `data` into `slot`. An empty `data` is a delete sentinel for the slots whose doc
    /// says so.
    SaveToSecureStore {
        slot: SecureStoreSlot,
        data: Vec<u8>,
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

    // ── Session health ────────────────────────────────────────────────────────
    /// Platform should encrypt a lightweight heartbeat payload and send it to
    /// `contact_id` using the existing DR session. If encryption fails (no
    /// session), the platform should treat this as a desync signal and trigger
    /// a heal. Using a regular encrypted message with `content_type = HEARTBEAT`
    /// means the server forwards it without modification — no server changes needed.
    SendHeartbeat {
        contact_id: String,
    },

    // ── Multi-device ──────────────────────────────────────────────────────────
    /// Notify all linked devices that the session with `contact_id` was reset.
    /// Each device should independently trigger a heal with that contact.
    /// The platform broadcasts this via the existing "send to own devices" path.
    NotifyLinkedDevicesOfSessionReset {
        contact_id: String,
    },

    /// Rust has archived and removed the session for `contact_id`.
    ///
    /// Platform MUST:
    ///   1. Store `archive_bytes` in the archive store (keyed by `contact_id`).
    ///   2. Delete the hot session Keychain/Keystore entry for `contact_id`.
    ///
    /// Replaces the two-action pattern of `SaveSessionToSecureStore("archive_<id>", bytes)`
    /// + `SaveSessionToSecureStore("session_<id>", [])` with a single semantic action.
    ///   Android can implement the identical behaviour against Android Keystore.
    SessionTerminated {
        contact_id: String,
        archive_bytes: Vec<u8>,
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
    /// Rust orchestrator encrypts `plaintext` bytes with the Double Ratchet session,
    /// packs a WirePayload (including PQXDH KEM ciphertext for msgNum=0, sourced
    /// internally from `pq_manager`), and returns `Action::SendEncryptedMessage`.
    OutgoingMessage {
        /// Contact (peer) user ID.
        contact_id: String,
        /// Platform-generated message UUID for deduplication / ACK tracking.
        message_id: String,
        /// Raw plaintext bytes — may be serialised protobuf, plain UTF-8, or binary.
        plaintext: Vec<u8>,
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
    /// Platform signals that the user opened or closed a specific chat.
    /// When `is_active = true`, the orchestrator schedules a heartbeat timer for
    /// `contact_id`. When `false`, the timer is cancelled.
    ActiveChatChanged {
        contact_id: String,
        is_active: bool,
    },
    /// The platform received a heartbeat message from `contact_id`.
    /// The orchestrator should attempt to decrypt it — if decryption fails,
    /// it triggers heal proactively (before the user sends any message).
    HeartbeatReceived {
        contact_id: String,
        message_id: String,
        /// Encrypted heartbeat payload (wire format, same as regular DR message).
        data: Vec<u8>,
        msg_num: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_debug() {
        let a = Action::SaveToSecureStore {
            slot: SecureStoreSlot::Session {
                contact_id: "bob".to_string(),
            },
            data: vec![1, 2, 3],
        };
        let s = format!("{:?}", a);
        assert!(s.contains("SaveToSecureStore"));
        // The slot names the contact; it does not name a place to put it.
        assert!(s.contains("bob"));
        assert!(
            !s.contains("session_bob"),
            "the core must not format a storage key: {s}"
        );
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
