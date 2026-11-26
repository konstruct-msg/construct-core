//! Parsed prekey bundle carried by the session-opening event.

/// The post-quantum half of a fetched prekey bundle (key-service `DevicePreKeyBundle`), as the
/// server served it. PQXDH v2 decides from it whether a session may be opened at all
/// (`pq_prekey_plan`): every Kyber prekey is signed, Ed25519 and hybrid, over
/// `"KonstruktX3DH-v1" || 0x00 0x11 || created_at (u64 BE) || public`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct KyberBundleKeys {
    /// Kyber signed prekey (ML-KEM-1024), its id (from 1), signed creation time, signatures.
    pub pre_key_id: Option<u32>,
    pub pre_key_public: Option<Vec<u8>>,
    pub pre_key_created_at: Option<u64>,
    pub pre_key_signature: Option<Vec<u8>>,
    pub pre_key_hybrid_signature: Option<Vec<u8>>,
    /// Kyber one-time prekey (id from 1 000 000), when the server had one.
    pub one_time_prekey_id: Option<u32>,
    pub one_time_prekey_public: Option<Vec<u8>>,
    pub one_time_prekey_created_at: Option<u64>,
    pub one_time_prekey_signature: Option<Vec<u8>>,
    pub one_time_prekey_hybrid_signature: Option<Vec<u8>>,
    /// Hybrid identity key (Ed25519 + ML-DSA-65, field 20) and its Ed25519 cross-signature by the
    /// device's identity key (field 21).
    pub hybrid_identity_key: Option<Vec<u8>>,
    pub hybrid_identity_signature: Option<Vec<u8>>,
}

/// A peer device's bundle, parsed: what `IncomingEvent::SessionBundleFetched` carries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionBundle {
    pub x3dh: crate::crypto::handshake::x3dh::X3DHPublicKeyBundle,
    pub kyber: KyberBundleKeys,
    /// Set when the bundle's signed prekey is past the age limit: its age, in seconds. The
    /// answer to `OpenSession` decides from it whether to open at risk or refuse
    /// (`handle_session_bundle_fetched`); `None` is a fresh bundle.
    #[serde(default)]
    pub stale_age_secs: Option<u64>,
}
