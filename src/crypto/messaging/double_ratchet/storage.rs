use super::*;
use crate::crypto::SuiteID;
use crate::crypto::provider::CryptoProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

impl<P: CryptoProvider> DoubleRatchetSession<P> {
    pub fn to_serializable(&self) -> SerializableSession {
        let skipped_keys = self
            .skipped_message_keys
            .iter()
            .map(|((dh_pub, msg_num), key)| SkippedKeyEntry {
                dh_public: dh_pub.clone(),
                msg_number: *msg_num,
                key_bytes: key.as_ref().to_vec(),
                timestamp: self
                    .skipped_key_timestamps
                    .get(&(dh_pub.clone(), *msg_num))
                    .copied()
                    .unwrap_or(0),
            })
            .collect();

        SerializableSession {
            version: 2,
            suite_id: self.suite_id.as_u16(),
            root_key: self.root_key.as_ref().to_vec(),
            sending_chain_key: self.sending_chain_key.as_ref().to_vec(),
            sending_chain_length: self.sending_chain_length,
            receiving_chain_key: self.receiving_chain_key.as_ref().to_vec(),
            receiving_chain_length: self.receiving_chain_length,
            dh_ratchet_private: self
                .dh_ratchet_private
                .as_ref()
                .map(|k| k.as_ref().to_vec()),
            dh_ratchet_public: self.dh_ratchet_public.as_ref().to_vec(),
            remote_dh_public: self.remote_dh_public.as_ref().map(|k| k.as_ref().to_vec()),
            previous_sending_length: self.previous_sending_length,
            skipped_message_keys: Default::default(), // legacy field, no longer written
            skipped_key_timestamps: Default::default(), // legacy field, no longer written
            skipped_keys,
            pre_pq_root_key: self.pre_pq_root_key.as_ref().map(|k| k.as_ref().to_vec()),
            session_id: self.session_id.clone(),
            contact_id: self.contact_id.clone(),
            local_user_id: self.local_user_id.clone(),
            last_ratchet_at: self.last_ratchet_at,
        }
    }

    /// Десериализовать сессию
    pub fn from_serializable(data: SerializableSession) -> Result<Self, String> {
        // Accept both version 1 (legacy) and version 2 (current)
        if data.version != 1 && data.version != 2 {
            return Err(format!(
                "Unsupported session version: {}. Expected 1 or 2.",
                data.version
            ));
        }

        // Валидация suite_id при десериализации
        let suite_id = SuiteID::new(data.suite_id)
            .map_err(|e| format!("Invalid suite_id in serialized session: {}", e))?;

        // Version 1 sessions lose their skipped keys (they had the collision bug anyway)
        let skipped_message_keys = data
            .skipped_keys
            .iter()
            .map(|entry| {
                Self::bytes_to_aead_key(&entry.key_bytes)
                    .map(|k| ((entry.dh_public.clone(), entry.msg_number), k))
            })
            .collect::<Result<_, _>>()?;

        let skipped_key_timestamps = data
            .skipped_keys
            .iter()
            .map(|entry| ((entry.dh_public.clone(), entry.msg_number), entry.timestamp))
            .collect();

        let mut session = Self {
            suite_id,
            root_key: Self::bytes_to_aead_key(&data.root_key)?,
            sending_chain_key: Self::bytes_to_aead_key(&data.sending_chain_key)?,
            sending_chain_length: data.sending_chain_length,
            receiving_chain_key: Self::bytes_to_aead_key(&data.receiving_chain_key)?,
            receiving_chain_length: data.receiving_chain_length,
            dh_ratchet_private: data
                .dh_ratchet_private
                .as_deref()
                .map(|bytes| Self::bytes_to_kem_private_key(bytes))
                .transpose()?,
            dh_ratchet_public: Self::bytes_to_kem_public_key(&data.dh_ratchet_public)?,
            remote_dh_public: data
                .remote_dh_public
                .as_deref()
                .map(|bytes| Self::bytes_to_kem_public_key(bytes))
                .transpose()?,
            previous_sending_length: data.previous_sending_length,
            skipped_message_keys,
            skipped_key_timestamps,
            pre_pq_root_key: data
                .pre_pq_root_key
                .as_deref()
                .map(|bytes| Self::bytes_to_aead_key(bytes))
                .transpose()?,
            session_id: data.session_id.clone(),
            contact_id: data.contact_id.clone(),
            local_user_id: data.local_user_id.clone(),
            last_ratchet_at: data.last_ratchet_at,
        };

        // Evict any stale skipped-message keys that accumulated while the session was
        // inactive.  Without this, a session that was dormant for weeks would still
        // carry expired keys in memory until the next 100-message boundary.
        session.cleanup_old_skipped_keys_default();

        Ok(session)
    }
}

/// A single skipped message key entry, keyed by remote DH public key + message number.
///
/// Using the remote DH public key as part of the index prevents keys from different
/// DH ratchet chains colliding when message numbers repeat after a ratchet step.
/// (Fixes the bug where msg#1 from chain B was incorrectly matched by key#1 from chain A.)
#[derive(Serialize, Deserialize, Default)]
pub struct SkippedKeyEntry {
    /// Remote DH public key (bytes) at the time this key was skipped
    pub dh_public: Vec<u8>,
    /// Message number within that DH chain
    pub msg_number: u32,
    /// The actual message key bytes
    pub key_bytes: Vec<u8>,
    /// Unix timestamp (seconds) when this entry was created
    pub timestamp: u64,
}

/// Serializable session format for storage
///
/// # Security Considerations
///
/// ⚠️ **CRITICAL**: This structure contains sensitive cryptographic material:
/// - `root_key`: Root key for DH ratchet key derivation
/// - `sending_chain_key` / `receiving_chain_key`: Current chain keys
/// - `dh_ratchet_private`: Private DH ratchet key
/// - `skipped_message_keys`: Keys for out-of-order messages
///
/// **SECURITY_AUDIT.md #13**: Sessions stored in plaintext
///
/// ## Defense-in-Depth Strategy:
///
/// 1. **Platform-Level Encryption** (Primary Defense):
///    - iOS: MUST use Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
///    - Web: MUST use IndexedDB (origin-isolated, browser-encrypted)
///    - Never store in UserDefaults, localStorage, or unencrypted files
///
/// 2. **Application-Level Encryption** (Optional, for paranoid mode):
///    - Derive session encryption key from device identity_key
///    - Encrypt SerializableSession before JSON serialization
///    - Note: Creates key management complexity in device-based model
///
/// 3. **Forward Secrecy Preservation**:
///    - Even if serialized session is compromised, past messages remain secure
///    - Only future messages (until next DH ratchet) could be decrypted
///    - Regular session rotation mitigates this window
///
/// ## Current Implementation:
///
/// Relies on platform secure storage (Keychain/IndexedDB encryption).
/// This is acceptable for device-based registration model where:
/// - No master password exists for additional encryption layer
/// - Platform storage provides hardware-backed encryption (iOS Secure Enclave)
/// - Origin isolation prevents cross-app access (Web)
///
/// If additional encryption is needed, implement in `export_session_json()`
/// before JSON conversion, not here (to keep serialization format clean).
#[derive(Serialize, Deserialize)]
pub struct SerializableSession {
    version: u16, // Protocol version for future compatibility
    pub suite_id: u16,
    root_key: Vec<u8>,
    sending_chain_key: Vec<u8>,
    sending_chain_length: u32,
    receiving_chain_key: Vec<u8>,
    receiving_chain_length: u32,
    dh_ratchet_private: Option<Vec<u8>>,
    dh_ratchet_public: Vec<u8>,
    remote_dh_public: Option<Vec<u8>>,
    previous_sending_length: u32,
    /// Legacy field (v1): flat map without DH chain context. Kept for reading old sessions
    /// but no longer written. Old skipped keys are silently dropped on upgrade — they had
    /// the cross-chain collision bug and would have produced wrong decryptions anyway.
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    skipped_message_keys: HashMap<u32, Vec<u8>>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    skipped_key_timestamps: HashMap<u32, u64>,
    /// v2: skipped keys properly namespaced by (remote_dh_public, msg_number)
    #[serde(default)]
    pub(crate) skipped_keys: Vec<SkippedKeyEntry>,
    /// RESPONDER-only: pre-second-ratchet root key for symmetric PQXDH derivation.
    /// Consumed after PQ contribution is applied. Absent for INITIATOR sessions
    /// and for sessions that have already applied their PQ contribution.
    #[serde(default)]
    pre_pq_root_key: Option<Vec<u8>>,
    session_id: String,
    contact_id: String,
    #[serde(default)]
    local_user_id: String,
    /// Unix timestamp of the last DH ratchet step. Zero means unknown (old sessions).
    #[serde(default)]
    last_ratchet_at: u64,
}

impl Drop for SerializableSession {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.sending_chain_key.zeroize();
        self.receiving_chain_key.zeroize();
        if let Some(ref mut k) = self.dh_ratchet_private {
            k.zeroize();
        }
        if let Some(ref mut k) = self.pre_pq_root_key {
            k.zeroize();
        }
        for entry in &mut self.skipped_keys {
            entry.key_bytes.zeroize();
        }
    }
}

impl SerializableSession {
    pub fn to_cfe_v1(&self) -> Result<crate::cfe::CfeSessionStateV1, String> {
        use serde_bytes::ByteBuf;

        let suite_id: u8 = self
            .suite_id
            .try_into()
            .map_err(|_| format!("suite_id out of range: {}", self.suite_id))?;

        let session_id_raw =
            hex::decode(&self.session_id).map_err(|e| format!("invalid session_id hex: {e}"))?;
        if session_id_raw.len() != 16 {
            return Err(format!(
                "invalid session_id length: expected 16, got {}",
                session_id_raw.len()
            ));
        }

        Ok(crate::cfe::CfeSessionStateV1 {
            ver: 1,
            suite_id,
            contact_id: self.contact_id.clone(),
            local_uid: self.local_user_id.clone(),
            session_id: ByteBuf::from(session_id_raw),
            rk: ByteBuf::from(self.root_key.clone()),
            sck: ByteBuf::from(self.sending_chain_key.clone()),
            rck: ByteBuf::from(self.receiving_chain_key.clone()),
            scl: self.sending_chain_length,
            rcl: self.receiving_chain_length,
            psl: self.previous_sending_length,
            dh_priv: self.dh_ratchet_private.clone().map(ByteBuf::from),
            dh_pub: ByteBuf::from(self.dh_ratchet_public.clone()),
            rdh_pub: self.remote_dh_public.clone().map(ByteBuf::from),
            skipped: self
                .skipped_keys
                .iter()
                .map(|e| crate::cfe::CfeSkippedKeyEntryV1 {
                    dh_pub: ByteBuf::from(e.dh_public.clone()),
                    msg_number: e.msg_number,
                    key_bytes: ByteBuf::from(e.key_bytes.clone()),
                    timestamp: e.timestamp,
                })
                .collect(),
            pq_rk1: self.pre_pq_root_key.clone().map(ByteBuf::from),
            last_ratchet_at: self.last_ratchet_at,
        })
    }

    pub fn from_cfe_v1(data: crate::cfe::CfeSessionStateV1) -> Result<Self, String> {
        let suite_id: u16 = data.suite_id as u16;
        let session_id_hex = hex::encode(data.session_id.as_ref());

        Ok(Self {
            version: 2,
            suite_id,
            root_key: data.rk.into_vec(),
            sending_chain_key: data.sck.into_vec(),
            sending_chain_length: data.scl,
            receiving_chain_key: data.rck.into_vec(),
            receiving_chain_length: data.rcl,
            dh_ratchet_private: data.dh_priv.map(|b| b.into_vec()),
            dh_ratchet_public: data.dh_pub.into_vec(),
            remote_dh_public: data.rdh_pub.map(|b| b.into_vec()),
            previous_sending_length: data.psl,
            skipped_message_keys: Default::default(),
            skipped_key_timestamps: Default::default(),
            skipped_keys: data
                .skipped
                .into_iter()
                .map(|e| SkippedKeyEntry {
                    dh_public: e.dh_pub.into_vec(),
                    msg_number: e.msg_number,
                    key_bytes: e.key_bytes.into_vec(),
                    timestamp: e.timestamp,
                })
                .collect(),
            pre_pq_root_key: data.pq_rk1.map(|b| b.into_vec()),
            session_id: session_id_hex,
            contact_id: data.contact_id,
            local_user_id: data.local_uid,
            last_ratchet_at: data.last_ratchet_at,
        })
    }
}
