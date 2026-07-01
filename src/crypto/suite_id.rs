//! Suite ID type with validation
//!
//! Suite ID identifies a cryptographic suite (set of primitives: KEM, Signature, AEAD, Hash).
//! This module provides a type-safe wrapper around u16 with validation.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

/// Suite ID type - wraps u16 with validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SuiteID(u16);

/// Error for invalid suite ID
#[derive(Error, Debug)]
#[error("Invalid suite ID: {suite_id}. Supported: 1 (CLASSIC), 2 (PQ_HYBRID), 3 (PQ_RATCHET)")]
pub struct InvalidSuiteId {
    pub suite_id: u16,
}

impl SuiteID {
    /// Classic suite: X25519 + Ed25519 + ChaCha20-Poly1305 + HKDF-SHA256
    pub const CLASSIC: Self = Self(1);

    /// Post-Quantum Hybrid suite: X25519+ML-KEM-768 + Ed25519+ML-DSA-65 + ChaCha20-Poly1305 + HKDF-SHA256
    pub const PQ_HYBRID: Self = Self(2);

    /// Classic X25519 Double Ratchet + sparse continuous ML-KEM-768 ratchet (see
    /// `DoubleRatchetSession::perform_pq_ratchet_step`). Independent of `PQ_HYBRID` —
    /// this is a ratchet-level add-on, not a `CryptoProvider` capability, so it can be
    /// adopted on its own rollout timeline. Only ever chosen when both peers have
    /// already advertised support out of band (prekey bundle capability field).
    pub const PQ_RATCHET: Self = Self(3);

    /// Create a new SuiteID with validation
    ///
    /// # Errors
    /// Returns `InvalidSuiteId` if the suite_id is not supported
    pub fn new(suite_id: u16) -> Result<Self, InvalidSuiteId> {
        match suite_id {
            1 => Ok(Self::CLASSIC),
            2 => Ok(Self::PQ_HYBRID),
            3 => Ok(Self::PQ_RATCHET),
            _ => Err(InvalidSuiteId { suite_id }),
        }
    }

    /// Create SuiteID without validation (use with caution)
    ///
    /// # Safety
    /// Only use this if you're certain the suite_id is valid.
    /// Prefer `new()` for safe construction.
    pub const fn from_u16_unchecked(suite_id: u16) -> Self {
        Self(suite_id)
    }

    /// Get the underlying u16 value
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Check if this is the classic suite
    pub const fn is_classic(self) -> bool {
        self.0 == 1
    }

    /// Check if this is the post-quantum hybrid suite
    pub const fn is_pq_hybrid(self) -> bool {
        self.0 == 2
    }

    /// Check if this session uses the sparse continuous PQ ratchet
    pub const fn is_pq_ratchet(self) -> bool {
        self.0 == 3
    }

    /// Check if the suite ID is supported
    pub const fn is_supported(suite_id: u16) -> bool {
        matches!(suite_id, 1..=3)
    }

    /// Get suite name for logging/debugging
    pub const fn name(self) -> &'static str {
        match self.0 {
            1 => "CLASSIC",
            2 => "PQ_HYBRID",
            3 => "PQ_RATCHET",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for SuiteID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.name())
    }
}

// Serialization: serialize as u16
impl Serialize for SuiteID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

// Deserialization: deserialize from u16 with validation
impl<'de> Deserialize<'de> for SuiteID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        SuiteID::new(value).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

// Conversion from u16 (with validation)
impl TryFrom<u16> for SuiteID {
    type Error = InvalidSuiteId;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        SuiteID::new(value)
    }
}

// Conversion to u16
impl From<SuiteID> for u16 {
    fn from(suite_id: SuiteID) -> Self {
        suite_id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_id_new() {
        assert_eq!(SuiteID::new(1).unwrap(), SuiteID::CLASSIC);
        assert_eq!(SuiteID::new(2).unwrap(), SuiteID::PQ_HYBRID);
        assert_eq!(SuiteID::new(3).unwrap(), SuiteID::PQ_RATCHET);
        assert!(SuiteID::new(0).is_err());
        assert!(SuiteID::new(4).is_err());
        assert!(SuiteID::new(999).is_err());
    }

    #[test]
    fn test_suite_id_pq_ratchet_variant() {
        let suite = SuiteID::new(3).unwrap();
        assert!(suite.is_pq_ratchet());
        assert!(!suite.is_classic());
        assert!(!suite.is_pq_hybrid());
        assert_eq!(suite.name(), "PQ_RATCHET");
        assert!(SuiteID::is_supported(3));
    }

    #[test]
    fn test_suite_id_serialization() {
        let suite = SuiteID::CLASSIC;
        let json = serde_json::to_string(&suite).unwrap();
        assert_eq!(json, "1");

        let deserialized: SuiteID = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, SuiteID::CLASSIC);
    }

    #[test]
    fn test_suite_id_deserialization_invalid() {
        let result: Result<SuiteID, _> = serde_json::from_str("999");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid suite ID"));
    }

    #[test]
    fn test_suite_id_try_from() {
        assert_eq!(SuiteID::try_from(1u16).unwrap(), SuiteID::CLASSIC);
        assert!(SuiteID::try_from(999u16).is_err());
    }

    #[test]
    fn test_suite_id_display() {
        assert_eq!(format!("{}", SuiteID::CLASSIC), "1 (CLASSIC)");
        assert_eq!(format!("{}", SuiteID::PQ_HYBRID), "2 (PQ_HYBRID)");
    }

    #[test]
    fn test_suite_id_is_supported() {
        assert!(SuiteID::is_supported(1));
        assert!(SuiteID::is_supported(2));
        assert!(SuiteID::is_supported(3));
        assert!(!SuiteID::is_supported(0));
        assert!(!SuiteID::is_supported(4));
    }
}
