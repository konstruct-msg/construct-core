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
