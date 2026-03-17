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
