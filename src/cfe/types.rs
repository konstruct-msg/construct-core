use crate::crypto::SecretBytes;
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

    // Storage (App data)
    AppSettings = 0x07,
    ContactKeyBundle = 0x08,

    // Event/Action protocol (in-memory)
    InboundEvent = 0x10,
    OutboundActions = 0x11,

    // Post-Quantum
    /// The core's ML-KEM-1024 prekeys (`CfeKyberPrekeysV1`). Reserved since the start and
    /// never written before them.
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
    /// Device-level OpenMLS storage snapshot (all groups + key package
    /// private material). See `group::MlsStore`.
    MlsStore = 0x44,

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
            0x07 => Self::AppSettings,
            0x08 => Self::ContactKeyBundle,
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
            0x44 => Self::MlsStore,
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
// Storage CFE types (0x07-0x0F range)
// ============================================================================

/// App settings stored in metadata
/// msg_type = 0x07
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeAppSettingsV1 {
    #[serde(rename = "ver")]
    pub version: u8,
    #[serde(rename = "notif")]
    pub notifications_enabled: bool,
    #[serde(rename = "theme")]
    pub theme: String,
    #[serde(rename = "typing")]
    pub typing_indicator: bool,
    #[serde(rename = "receipts")]
    pub read_receipts: bool,
    #[serde(rename = "sync")]
    pub last_sync: i64,
}

impl Default for CfeAppSettingsV1 {
    fn default() -> Self {
        Self {
            version: 1,
            notifications_enabled: true,
            theme: "default".to_string(),
            typing_indicator: true,
            read_receipts: true,
            last_sync: 0,
        }
    }
}

/// Contact public key bundle
/// msg_type = 0x08
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeContactKeyBundleV1 {
    #[serde(rename = "ver")]
    pub version: u8,
    #[serde(rename = "keys", with = "serde_bytes")]
    pub key_bundle: Vec<u8>,
}

/// Registration bundle for sharing with contacts
///_msg_type = 0x04
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeRegistrationBundleV1 {
    #[serde(rename = "ver")]
    pub version: u8,
    #[serde(rename = "ik", with = "serde_bytes")]
    pub identity_public: Vec<u8>,
    #[serde(rename = "spk", with = "serde_bytes")]
    pub signed_prekey_public: Vec<u8>,
    #[serde(rename = "sig", with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(rename = "vk", with = "serde_bytes")]
    pub verifying_key: Vec<u8>,
    #[serde(rename = "suite")]
    pub suite_id: u8,
}

impl Default for CfeRegistrationBundleV1 {
    fn default() -> Self {
        Self {
            version: 1,
            identity_public: Vec::new(),
            signed_prekey_public: Vec::new(),
            signature: Vec::new(),
            verifying_key: Vec::new(),
            suite_id: 0,
        }
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
    pub spk_priv: SecretBytes,
    #[serde(rename = "sig")]
    pub spk_sig: ByteBuf,
    #[serde(rename = "id")]
    pub spk_id: u32,
    /// Unix timestamp (seconds) when this key was originally created.
    #[serde(rename = "ts")]
    pub created_at: i64,
    /// When it was rotated out; retention (14 days) counts from here. Absent in records written
    /// before it existed — read as "retired at import".
    #[serde(rename = "rt", default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfePrivateKeysV1 {
    #[serde(rename = "suite_id")]
    pub suite_id: u8,

    #[serde(rename = "ik_priv")]
    pub ik_priv: SecretBytes,
    #[serde(rename = "sk_priv")]
    pub sk_priv: SecretBytes,
    #[serde(rename = "spk_priv")]
    pub spk_priv: SecretBytes,
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
    /// Entries retired longer than `prekey_cleanup_period_secs` (14 days) ago are pruned.
    #[serde(rename = "old_spks", default, skip_serializing_if = "Vec::is_empty")]
    pub old_spks: Vec<CfeOldSpkV1>,

    /// Optional independent hybrid PQ signature private key (Ed25519 + ML-DSA-65).
    /// 2016 bytes when present: [ed25519_seed(32) | mldsa65_seed(32) | mldsa65_pk(1952)].
    /// Owned by the core (persisted in CFE) for centralized crypto key management.
    /// Lazily created; absent for legacy pre-hybrid accounts until first ensure.
    #[serde(rename = "hs_priv", default, skip_serializing_if = "Option::is_none")]
    pub hybrid_sig_priv: Option<SecretBytes>,
    // `kyber_spk` (the ML-KEM-768 signed prekey) was here. The core's ML-KEM-1024 prekeys are
    // their own blob (`KyberPrivateKeys`); a record that still carries the key reads without it.
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeSkippedKeyEntryV1 {
    #[serde(rename = "dh_pub")]
    pub dh_pub: ByteBuf,
    #[serde(rename = "n")]
    pub msg_number: u32,
    #[serde(rename = "k")]
    pub key_bytes: SecretBytes,
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
    #[serde(rename = "json")]
    pub json_bytes: SecretBytes,
}

/// `PrekeyHeader` in a session record: public values only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfePrekeyHeaderV1 {
    #[serde(rename = "otpk")]
    pub one_time_prekey_id: u32,
    #[serde(rename = "kid")]
    pub kyber_prekey_id: u32,
    #[serde(rename = "ct")]
    pub kem_ciphertext: ByteBuf,
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
    pub rk: SecretBytes,
    #[serde(rename = "sck")]
    pub sck: SecretBytes,
    #[serde(rename = "rck")]
    pub rck: SecretBytes,

    #[serde(rename = "scl")]
    pub scl: u32,
    #[serde(rename = "rcl")]
    pub rcl: u32,
    #[serde(rename = "psl")]
    pub psl: u32,

    #[serde(rename = "dh_priv")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dh_priv: Option<SecretBytes>,

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

    // `pq_rk1` (the v1 responder's pre-contribution root key) was here; v1 is gone and the
    // named-map codec ignores the key in older blobs.
    /// INITIATOR, until the peer answers: the handshake header the first flight repeats.
    #[serde(rename = "pkh", default, skip_serializing_if = "Option::is_none")]
    pub prekey_header: Option<CfePrekeyHeaderV1>,

    /// `PqHandshake::as_u8`. Absent on blobs written before PQXDH v2.
    #[serde(rename = "pqh", default, skip_serializing_if = "Option::is_none")]
    pub pq_handshake: Option<u8>,

    /// Unix timestamp of the last DH ratchet step (zero = unknown / legacy session).
    #[serde(rename = "lra")]
    #[serde(default)]
    pub last_ratchet_at: u64,

    /// `PqAuthentication::as_u8` — whose Kyber key the PQ layer came from. Absent (0,
    /// `Unknown`) on blobs written before 2026-09-24.
    #[serde(rename = "pqa")]
    #[serde(default)]
    pub pq_authentication: u8,
    /// A KEM secret has been mixed into the root key. Absent on older blobs: unknown.
    #[serde(rename = "pqap")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_applied: Option<bool>,

    // ── Sparse continuous PQ ratchet (suite_id = PQ_RATCHET) ──────────────────
    // History: a pre-SPQR-redesign layout briefly used flat fields here
    // (`pqt`, `pq_pend_pk`/`sk`/`ct`, `pq_pend_ts`). They were removed rather
    // than deprecated: suite 3 never shipped, so no production blob ever
    // carried data in them, and the msgpack named-map codec ignores the keys
    // if an old dev blob still has them. Do not reuse those key names.
    /// Sparse continuous PQ ratchet (suite 3) sub-state, SPQR-style message-key
    /// mixing design (see `decisions/pq-ratchet-spqr-message-key-mixing.md`).
    /// Present only for suite-3 sessions; absent on pre-feature blobs and
    /// non-suite-3 sessions. Atomic: either the whole PQ state is here or the
    /// session has none — no partial-field combinations to validate.
    #[serde(rename = "pqr")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqr: Option<CfePqRatchetStateV1>,
}

/// One completed PQ-ratchet epoch: id + 32-byte ML-KEM-768 shared secret.
/// Secret is zeroized on drop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfePqEpochSecretV1 {
    #[serde(rename = "e")]
    pub epoch: u32,
    #[serde(rename = "ss")]
    pub secret: SecretBytes,
}

/// Initiator-side in-flight PQ exchange: fresh ML-KEM-768 keypair proposing
/// `epoch`. The secret key is `SecretBytes`: zeroized on drop, redacted in `Debug`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfePqPendingExchangeV1 {
    #[serde(rename = "e")]
    pub epoch: u32,
    #[serde(rename = "pk")]
    pub public: ByteBuf,
    #[serde(rename = "sk")]
    pub secret: SecretBytes,
}

/// Responder-side pending PQ ciphertext plus the *provisional* epoch secret.
/// This may be the only copy of an epoch the initiator already activated —
/// losing it on restore would make that epoch permanently undecryptable,
/// which is why it must be persisted. The secret is `SecretBytes`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfePqPendingCiphertextV1 {
    #[serde(rename = "e")]
    pub epoch: u32,
    /// 8-byte hash of the encapsulation key this ciphertext was built against.
    #[serde(rename = "h")]
    pub ek_hash: ByteBuf,
    #[serde(rename = "c")]
    pub ciphertext: ByteBuf,
    #[serde(rename = "ss")]
    pub secret: SecretBytes,
}

/// Complete sparse-PQ-ratchet sub-state for a suite-3 session — everything a
/// restored session needs to keep mixing, completing in-flight exchanges, and
/// driving the cadence exactly as before serialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfePqRatchetStateV1 {
    /// Whether this side drives the exchange cadence (DR initiator).
    #[serde(rename = "ini")]
    pub is_initiator: bool,
    /// Highest completed epoch — mixed into every outgoing message key.
    #[serde(rename = "cur")]
    pub current_epoch: u32,
    /// Completed epoch secrets (bounded by PQ_EPOCH_RETENTION).
    #[serde(rename = "eps")]
    #[serde(default)]
    pub epoch_secrets: Vec<CfePqEpochSecretV1>,
    #[serde(rename = "pend")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_exchange: Option<CfePqPendingExchangeV1>,
    #[serde(rename = "ct")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_ciphertext: Option<CfePqPendingCiphertextV1>,
    /// Unix timestamp when `pending_exchange` was created (abandonment cutoff).
    #[serde(rename = "ts")]
    #[serde(default)]
    pub pending_since: u64,
    /// DH-ratchet turns since the last exchange started (cadence counter).
    #[serde(rename = "turns")]
    #[serde(default)]
    pub turns_since_mix: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeOtpkRecordV1 {
    #[serde(rename = "id")]
    pub id: u32,
    #[serde(rename = "priv")]
    pub priv_key: SecretBytes,
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

// ── Kyber prekeys (ML-KEM-1024, PQXDH v2) ─────────────────────────────────────

/// One Kyber prekey the core holds: the FIPS 203 seed is the whole secret, the public key is
/// derived from it, and the signatures are re-made on demand — so a pool entry is ~80 bytes, not
/// the ~5 KB a key, its expanded secret and a hybrid signature would take.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeKyberPrekeyV1 {
    #[serde(rename = "id")]
    pub key_id: u32,
    /// Signed `created_at` (unix seconds).
    #[serde(rename = "ts")]
    pub created_at: u64,
    /// 64-byte ML-KEM seed `d ‖ z`.
    #[serde(rename = "seed")]
    pub seed: SecretBytes,
}

/// A Kyber SPK that has been rotated out, kept for first messages still in flight to it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeRetiredKyberSpkV1 {
    #[serde(rename = "k")]
    pub prekey: CfeKyberPrekeyV1,
    /// When it stopped being current (unix seconds); dropped 14 days later.
    #[serde(rename = "rt")]
    pub retired_at: u64,
}

/// All of the core's Kyber prekeys. msg_type = `KyberPrivateKeys` (0x20).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CfeKyberPrekeysV1 {
    #[serde(rename = "spk", default, skip_serializing_if = "Option::is_none")]
    pub spk: Option<CfeKyberPrekeyV1>,
    /// Generated and handed out for upload, not yet confirmed.
    #[serde(rename = "pend", default, skip_serializing_if = "Option::is_none")]
    pub pending_spk: Option<CfeKyberPrekeyV1>,
    #[serde(rename = "old", default)]
    pub retired_spks: Vec<CfeRetiredKyberSpkV1>,
    #[serde(rename = "otpk", default)]
    pub otpks: Vec<CfeKyberPrekeyV1>,
    #[serde(rename = "nspk")]
    pub next_spk_id: u32,
    #[serde(rename = "notpk")]
    pub next_otpk_id: u32,
}

// ── OpenMLS store CFE types (0x44) ────────────────────────────────────────────

/// One key/value pair of the OpenMLS `MemoryStorage` snapshot.
///
/// Part of `CfeMlsStoreV1`. Keys and values are opaque OpenMLS-internal
/// encodings (versioned by openmls itself) — we persist them verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeMlsStoreEntryV1 {
    #[serde(rename = "k")]
    pub key: ByteBuf,
    #[serde(rename = "v")]
    pub value: SecretBytes,
}

/// Device-level OpenMLS storage snapshot: ALL group states, ratchet secrets
/// and key-package private material in one blob.
///
/// msg_type = `MlsStore` (0x44).
///
/// Exported by `group::MlsStore::export_cfe()` after every mutating MLS
/// operation; the host app persists it in the platform secure store and
/// restores via `MlsStore::import_cfe()` (device Ed25519 signer is passed
/// separately — it is never part of the blob).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeMlsStoreV1 {
    /// Schema version — always 1 for this format.
    #[serde(rename = "ver")]
    pub version: u8,
    /// Storage entries, sorted by key for deterministic encoding.
    #[serde(rename = "entries")]
    pub entries: Vec<CfeMlsStoreEntryV1>,
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
    ///
    /// **Always written empty since 2026-07-28** — the durable owner of dedup
    /// state is the platform ACK store, and snapshotting the L1 cache grew this
    /// blob without bound (~42 B per received message, forever). Kept in the
    /// struct so the format is unchanged and pre-existing blobs still decode;
    /// readers must tolerate both empty and populated lists.
    /// See `SessionLifecycleManager::export_orchestrator_state_cfe`.
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
    pub archives: Vec<(String, SecretBytes)>,
    /// contactId → Unix timestamp of the archive (for GC).
    #[serde(rename = "arc_ts")]
    pub archive_timestamps: Vec<(String, u64)>,
    /// contactId → last seen OTPK ID (reinstall detection).
    #[serde(rename = "ptk")]
    pub prekey_tracker: Vec<(String, u32)>,
    // `skd` (devices that had signed a v1 Kyber SPK) and `prd` (devices that had advertised the
    // PQ ratchet) were here; PQXDH v2 refuses every unsigned bundle and makes suite 3 mandatory,
    // so neither ledger has anything left to remember. Old keys are ignored on read.
    /// Device → SHA-256 of its pinned hybrid identity key, sorted by device.
    #[serde(rename = "hip", default, skip_serializing_if = "Vec::is_empty")]
    pub hybrid_identity_pins: Vec<CfeHybridPinV1>,
}

/// A pinned hybrid identity key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfeHybridPinV1 {
    #[serde(rename = "d")]
    pub device_id: String,
    #[serde(rename = "fp")]
    pub fingerprint: ByteBuf,
}
