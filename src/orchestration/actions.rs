//! Action — платформенная операция, которую Rust-ядро просит выполнить Swift/Kotlin.
//!
//! Rust принимает события, вычисляет решения и возвращает `Vec<Action>`.
//! Платформенный слой исполняет каждое действие и при необходимости передаёт
//! результат обратно через `IncomingEvent`.

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

    /// Open a new session with `contact_id` as INITIATOR, over the one held: fetch the bundle and
    /// call `reopen_session_with_bundle`, which replaces the held state only once the new one
    /// exists and keeps it as a previous state. Nothing is sent for it: the handshake header rides
    /// on the next message to the device, whatever it is.
    ///
    /// Raised by the PQXDH v2 upgrade sweep (`Orchestrator::pq_upgrade_candidates`).
    OpenSession {
        contact_id: String,
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
        /// Session state, key records, deferred PQ secrets: what goes here is secret, so it
        /// is `SecretBytes` — zeroed on drop, and a `{:?}` of the action prints its length.
        data: crate::crypto::SecretBytes,
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
    /// The routing verdict for a message already handled: in the ACK cache, confirmed processed
    /// by the platform's DB, or carrying a ratchet position whose key is already used
    /// (`MESSAGE_KEY_CONSUMED`). Terminal: record it as processed, advance past it.
    ///
    /// Before this the verdict was an empty list, and an empty list also means "no decision".
    /// The platform could not tell them apart — a duplicate it had answered "not processed"
    /// for (a control message after a restart has no transcript row) read as a message held
    /// for redelivery, and held the stream cursor on a message that would come back as the
    /// same duplicate every time.
    DuplicateDropped {
        message_id: String,
    },

    // ── Network ───────────────────────────────────────────────────────────────
    /// A message waits for a session with `contact_id` and can open one: the platform calls
    /// `open_receiving(contact_id)`. Nothing is fetched — the key the session opens with comes from
    /// the message's sender certificate. It stays a round trip, rather than an open inside this
    /// event, because the platform's bookkeeping after an open (prekey replenishment, the
    /// handshake controls, the queued sends) still hangs off the open's answer.
    OpenReceiving {
        contact_id: String,
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
    /// We could not read `message_id` from `contact_id`: send `payload` to that device as a
    /// DECRYPTION_ERROR (content type 28) envelope, sealed-sender, and acknowledge the message.
    ///
    /// `payload` is complete — the core built and sealed it to the writer's identity key. It names
    /// the unread message's ratchet key, so the writer can tell whether its current state is the
    /// one that failed (`decryption_error`). One per unread message; a redelivery of the same one
    /// is a duplicate by then and sends nothing.
    SendDecryptionError {
        contact_id: String,
        message_id: String,
        payload: Vec<u8>,
    },

    /// The peer could not read what we sent on the current state with `contact_id`, and the state
    /// is retired (`SessionLifecycleManager::retire_current`). There is no current state until
    /// the next send opens one; what the peer still sends on the retired one decrypts.
    ///
    /// `without_one_time_prekey`: the peer does not hold the one-time prekey it would be given,
    /// so the next open should not use one.
    SessionRetired {
        contact_id: String,
        without_one_time_prekey: bool,
    },

    /// The peer could not read `message_id`: send it again to `contact_id`, as a new message on
    /// whatever state is current — after a `SessionRetired` in the same answer, that resend is what
    /// opens the new one. Asked once per message.
    ResendMessage {
        contact_id: String,
        message_id: String,
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
        /// Content-type from the server envelope (proto ContentType enum value).
        /// 0 = regular E2EE message; 12 = CALL_SIGNAL.
        content_type: u8,
        /// The sender certificate the envelope was sealed with, as unsealed and not yet checked.
        /// `None` for a message that was not sealed. The only thing a first message can open a
        /// session from — see `SenderCertificate::identity_for_opening`.
        #[serde(default)]
        sender_certificate: Option<crate::crypto::sealed_sender::SenderCertificate>,
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
    /// A key bundle the platform fetched to open a session as INITIATOR. Sent only by
    /// construct-tui, whose JSON path (`InitSession`) predates `OpenSession`; see TODO 70.
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
    /// A DECRYPTION_ERROR (content type 28) arrived from `contact_id` — the device its sender
    /// certificate names. `payload` is the envelope's sealed box, opened here with our identity
    /// key. Answered with `SessionRetired` when the error is about our current state, and with
    /// nothing when it is stale.
    DecryptionErrorReceived {
        contact_id: String,
        payload: Vec<u8>,
    },
    /// The platform received a heartbeat message from `contact_id`.
    /// The orchestrator should attempt to decrypt it — if nothing held decrypts it,
    /// the answer is the one any message gets (a receiving open or a decryption error).
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
            data: vec![1, 2, 3].into(),
        };
        let s = format!("{:?}", a);
        assert!(s.contains("SaveToSecureStore"));
        // The slot names the contact; it does not name a place to put it.
        assert!(s.contains("bob"));
        assert!(
            !s.contains("session_bob"),
            "the core must not format a storage key: {s}"
        );
        assert!(
            !s.contains("[1, 2, 3]"),
            "the payload is secret; Debug must not print it: {s}"
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
