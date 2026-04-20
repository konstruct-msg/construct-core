use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum CfeMessageType {
    // Key material (Keychain storage)
    PrivateKeys = 0x01,
    SessionState = 0x02,
    OtpkBundle = 0x03,
    RegistrationBundle = 0x04,
    OrchestratorState = 0x05,
    SpkRotation = 0x06,

    // Event/Action protocol (in-memory)
    InboundEvent = 0x10,
    OutboundActions = 0x11,

    // Post-Quantum (ML-KEM-768)
    KyberPrivateKeys = 0x20,
    KyberSessionState = 0x21,

    // Calls (future)
    CallSignal = 0x30,
    CallKeyMaterial = 0x31,

    // OpenMLS (future)
    MlsWelcome = 0x40,
    MlsCommit = 0x41,
    MlsProposal = 0x42,
    MlsKeyPackage = 0x43,

    // Utilities
    Generic = 0x7F,
}

impl CfeMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => Self::PrivateKeys,
            0x02 => Self::SessionState,
            0x03 => Self::OtpkBundle,
            0x04 => Self::RegistrationBundle,
            0x05 => Self::OrchestratorState,
            0x06 => Self::SpkRotation,
            0x10 => Self::InboundEvent,
            0x11 => Self::OutboundActions,
            0x20 => Self::KyberPrivateKeys,
            0x21 => Self::KyberSessionState,
            0x30 => Self::CallSignal,
            0x31 => Self::CallKeyMaterial,
            0x40 => Self::MlsWelcome,
            0x41 => Self::MlsCommit,
            0x42 => Self::MlsProposal,
            0x43 => Self::MlsKeyPackage,
            0x7F => Self::Generic,
            _ => return None,
        })
    }
}

impl TryFrom<u8> for CfeMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or(())
    }
}

// ============================================================================
// CFE payload schemas (v1)
// ============================================================================

/// A previous signed-prekey retained for backward-compatible session init.
///
/// Stored in `CfePrivateKeysV1.old_spks` so that after app restart the RESPONDER
/// can still decrypt sessions that the INITIATOR opened using an older bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeOldSpkV1 {
    #[serde(rename = "priv")]
    pub spk_priv: ByteBuf,
    #[serde(rename = "sig")]
    pub spk_sig: ByteBuf,
    #[serde(rename = "id")]
    pub spk_id: u32,
    /// Unix timestamp (seconds) when this key was originally created.
    #[serde(rename = "ts")]
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfePrivateKeysV1 {
    #[serde(rename = "suite_id")]
    pub suite_id: u8,

    #[serde(rename = "ik_priv")]
    pub ik_priv: ByteBuf,
    #[serde(rename = "sk_priv")]
    pub sk_priv: ByteBuf,
    #[serde(rename = "spk_priv")]
    pub spk_priv: ByteBuf,
    #[serde(rename = "spk_sig")]
    pub spk_sig: ByteBuf,

    #[serde(rename = "spk_id")]
    pub spk_id: u32,

    #[serde(rename = "ik_pub")]
    pub ik_pub: ByteBuf,
    #[serde(rename = "vk_pub")]
    pub vk_pub: ByteBuf,
    #[serde(rename = "spk_pub")]
    pub spk_pub: ByteBuf,

    /// Previous signed prekeys retained for cross-restart RESPONDER compatibility.
    /// Old entries are pruned to `prekey_cleanup_period_secs` on export.
    #[serde(rename = "old_spks", default, skip_serializing_if = "Vec::is_empty")]
    pub old_spks: Vec<CfeOldSpkV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeSkippedKeyEntryV1 {
    #[serde(rename = "dh_pub")]
    pub dh_pub: ByteBuf,
    #[serde(rename = "n")]
    pub msg_number: u32,
    #[serde(rename = "k")]
    pub key_bytes: ByteBuf,
    #[serde(rename = "ts")]
    pub timestamp: u64,
}

/// Thin CFE wrapper that stores a session as its raw JSON bytes with CRC32 protection.
/// Used for Phase 4 migration — wraps the existing JSON session format so it gets
/// integrity checking without requiring a full session state decomposition.
/// msg_type = SessionState (0x02)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeSessionJsonWrapperV1 {
    #[serde(rename = "cid")]
    pub contact_id: String,
    #[serde(rename = "json", with = "serde_bytes")]
    pub json_bytes: ByteBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeSessionStateV1 {
    #[serde(rename = "ver")]
    pub ver: u8,

    #[serde(rename = "suite_id")]
    pub suite_id: u8,

    #[serde(rename = "contact_id")]
    pub contact_id: String,

    #[serde(rename = "local_uid")]
    pub local_uid: String,

    /// 16 bytes derived shared session ID (hex → raw bytes)
    #[serde(rename = "session_id")]
    pub session_id: ByteBuf,

    #[serde(rename = "rk")]
    pub rk: ByteBuf,
    #[serde(rename = "sck")]
    pub sck: ByteBuf,
    #[serde(rename = "rck")]
    pub rck: ByteBuf,

    #[serde(rename = "scl")]
    pub scl: u32,
    #[serde(rename = "rcl")]
    pub rcl: u32,
    #[serde(rename = "psl")]
    pub psl: u32,

    #[serde(rename = "dh_priv")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dh_priv: Option<ByteBuf>,

    #[serde(rename = "dh_pub")]
    pub dh_pub: ByteBuf,

    #[serde(rename = "rdh_pub")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdh_pub: Option<ByteBuf>,

    /// v2 skipped keys (remote DH pub + msg_number).
    ///
    /// Spec v2.0 describes `skipped` as a flat map, but the core tracks the
    /// full (dh_pub, msg_number) tuple to avoid cross-chain collisions.
    #[serde(rename = "skipped")]
    #[serde(default)]
    pub skipped: Vec<CfeSkippedKeyEntryV1>,

    #[serde(rename = "pq_rk1")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_rk1: Option<ByteBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeOtpkRecordV1 {
    #[serde(rename = "id")]
    pub id: u32,
    #[serde(rename = "priv")]
    pub priv_key: ByteBuf,
    #[serde(rename = "pub")]
    pub pub_key: ByteBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeOtpkBundleV1 {
    #[serde(rename = "records")]
    pub records: Vec<CfeOtpkRecordV1>,
    #[serde(rename = "next_id")]
    pub next_id: u32,
}

// ── PQC / ML-KEM-768 CFE types ────────────────────────────────────────────────

/// One entry in the Kyber session state: a deferred PQ contribution for a
/// specific contact that has been encapsulated/decapsulated but not yet applied
/// to the session root key.
///
/// Wire format is kept lean — the shared secret is 32 bytes, `otpk_id` is u32.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeKyberDeferredEntryV1 {
    /// The contact's stable user ID (UUID string without braces).
    #[serde(rename = "cid")]
    pub contact_id: String,
    /// ML-KEM OTPK identifier that was used for this contribution.
    #[serde(rename = "id")]
    pub otpk_id: u32,
    /// 32-byte ML-KEM-768 shared secret, pending `apply_pq_contribution`.
    #[serde(rename = "ss", with = "serde_bytes")]
    pub shared_secret: ByteBuf,
}

/// Full CFE snapshot of the `PQContributionManager` — all deferred Kyber
/// contributions plus the monotonic OTPK ID counter.
///
/// msg_type = `KyberSessionState` (0x21).
/// Persisted to the secure store whenever a new deferred contribution is added
/// or consumed so that the state survives process restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeKyberSessionStateV1 {
    /// Version field — always 1 for this format.
    #[serde(rename = "ver")]
    pub ver: u8,
    /// All per-contact deferred contributions currently in flight.
    #[serde(rename = "entries")]
    pub entries: Vec<CfeKyberDeferredEntryV1>,
    /// Next OTPK ID to allocate (monotonically increasing across restarts).
    #[serde(rename = "next_id")]
    pub next_otpk_id: u32,
}

// ── Orchestrator State CFE types (0x05) ───────────────────────────────────────

/// A single entry in the ACK deduplication cache snapshot.
/// Only the message ID is stored — timestamps are not needed for in-memory
/// recovery (the platform persistent store handles expiry).
///
/// Part of `CfeOrchestratorStateV1`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeAckRecordV1 {
    /// The stable message UUID that has been processed.
    #[serde(rename = "id")]
    pub message_id: String,
}

/// A serialised session-healing queue entry.
/// Stores the original message so it can be replayed after session re-keying.
///
/// Part of `CfeOrchestratorStateV1`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeHealingRecordV1 {
    /// Contact whose session needs healing.
    #[serde(rename = "cid")]
    pub contact_id: String,
    /// Binary WirePayload waiting for replay.
    #[serde(rename = "msg", with = "serde_bytes")]
    pub message_bytes: Vec<u8>,
    /// Number of healing attempts already made (0-based).
    #[serde(rename = "att")]
    pub attempts: u32,
    /// Number of times an incoming msgNum=0 triggered enqueue for this record.
    /// Used to enforce the `MAX_INCOMING_TRIGGERS` cap across app restarts.
    #[serde(rename = "itr", default)]
    pub incoming_triggers: u32,
    /// Unix timestamp (seconds) when the record was first enqueued.
    #[serde(rename = "at")]
    pub created_at: u64,
}

/// Full CFE snapshot of the orchestrator's transient coordination state.
///
/// msg_type = `OrchestratorState` (0x05).
///
/// Includes:
/// - ACK dedup cache (in-memory processed message IDs)
/// - Session healing queue (messages awaiting replay after re-key)
/// - Session init locks (contacts currently in session-setup)
/// - Archive index + prekey tracker (from `SessionLifecycleManager`)
///
/// Persisted on every state change that modifies ack_store, healing_queue,
/// or init_locks.  On startup, importing this blob restores the in-memory
/// queues without re-processing messages or losing pending heals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeOrchestratorStateV1 {
    /// Schema version — always 1 for this format.
    #[serde(rename = "ver")]
    pub ver: u8,
    /// The local user's stable UUID.
    #[serde(rename = "uid")]
    pub my_user_id: String,
    /// Snapshot of the in-memory ACK dedup cache.
    #[serde(rename = "acks")]
    pub processed_ids: Vec<CfeAckRecordV1>,
    /// Active session-healing queue entries.
    #[serde(rename = "heals")]
    pub healing_records: Vec<CfeHealingRecordV1>,
    /// Contact IDs for which a session-init RPC is currently in flight.
    #[serde(rename = "locks")]
    pub init_locks: Vec<String>,
    /// contactId → archived session CFE binary (latest archive per contact).
    #[serde(rename = "arcs")]
    pub archives: Vec<(String, serde_bytes::ByteBuf)>,
    /// contactId → Unix timestamp of the archive (for GC).
    #[serde(rename = "arc_ts")]
    pub archive_timestamps: Vec<(String, u64)>,
    /// contactId → last seen OTPK ID (reinstall detection).
    #[serde(rename = "ptk")]
    pub prekey_tracker: Vec<(String, u32)>,
}
