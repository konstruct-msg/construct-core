use crate::crypto::SuiteID;
use crate::crypto::client_api::ClassicClient;
use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::group::{MemberAddition, MlsError};
pub use crate::orchestration::PlatformBridge;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Generate a cryptographically random 32-byte storage key.
/// Each encrypt/decrypt call gets a unique key stored in MessageKeyStore on the Swift side.
/// Deleting the key permanently prevents decryption of the corresponding local ciphertext copy.
fn gen_storage_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key.to_vec()
}

// Wrapper for Client to make it work with UniFFI
// Note: We use UDL definition, not derive macro
// UniFFI wraps this in Arc automatically, so we only need Mutex here
pub struct ClassicCryptoCore {
    inner: Mutex<ClassicClient<ClassicSuiteProvider>>,
}

// Error type that matches UDL definition (flat errors)
// Note: We use UDL definition, not derive macro
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Initialization failed")]
    InitializationFailed,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session initialization failed: {message}")]
    SessionInitializationFailed { message: String },

    #[error("Encryption failed: {message}")]
    EncryptionFailed { message: String },

    #[error("Decryption failed: {message}")]
    DecryptionFailed { message: String },

    #[error("Invalid key data")]
    InvalidKeyData,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Serialization failed: {message}")]
    SerializationFailed { message: String },

    #[error("MessagePack deserialization failed - check format")]
    MessagePackDeserializationFailed,

    /// Peer's Signed Pre-Key is older than the staleness limit (10 days).
    /// The peer must open their app to trigger SPK rotation before a session can be established.
    #[error("Peer SPK is stale: age_secs={age_secs}")]
    PeerSpkStale { age_secs: u64 },
}

impl From<crate::error::CryptoError> for CryptoError {
    fn from(err: crate::error::CryptoError) -> Self {
        match err {
            crate::error::CryptoError::InvalidKeyData => CryptoError::InvalidKeyData,
            crate::error::CryptoError::InvalidCiphertext => CryptoError::InvalidCiphertext,
            e => CryptoError::SessionInitializationFailed {
                message: e.to_string(),
            },
        }
    }
}

/// Build a `SerializationFailed` that carries the underlying error's detail so an
/// otherwise-opaque CFE/serde failure becomes diagnosable in client logs — e.g. the
/// exact `CfeError` variant (`ChecksumMismatch` vs `LegacyJson` vs `DeserializeFailed`
/// vs `TypeMismatch`). Before this, every distinct cause collapsed into a bare
/// "Serialization failed", which is why the recurring OTPK-import corruption could not
/// be root-caused from logs. `{:?}` (Debug) works for every error type at the call
/// sites (CfeError, serde_json::Error, String).
fn serialization_failed(context: &str, err: impl std::fmt::Debug) -> CryptoError {
    CryptoError::SerializationFailed {
        message: format!("{context}: {err:?}"),
    }
}

// Re-export PoW types from pow module (for UniFFI UDL)
// Note: We use UDL definition, not derive macro
pub use crate::pow::{PowChallenge, PowProgressCallback, PowSolution};

/// Read-only health snapshot of a Double Ratchet session.
///
/// Returned by `ClassicCryptoCore::get_session_health` and
/// `OrchestratorCore::get_session_health`. No session state is mutated.
#[derive(Debug, Clone)]
pub struct SessionHealthReport {
    /// Messages sent in the current sending chain.
    pub messages_sent: u32,
    /// Messages received in the current receiving chain.
    pub messages_received: u32,
    /// Number of out-of-order message keys currently buffered.
    pub skipped_keys_count: u32,
    /// `true` once a Kyber contribution has been mixed into the root key.
    pub is_pq_strengthened: bool,
    /// Unix timestamp of the last DH ratchet step (0 = unknown / legacy session).
    pub last_ratchet_at: u64,
    /// Shared session identifier (hex).
    pub session_id: String,
    /// Whose Kyber key the PQ layer came from.
    pub pq_authentication: PqAuthentication,
    /// How the PQ layer started.
    pub pq_handshake: PqHandshake,
}

pub use crate::crypto::kyber_prekey_auth::{PqAuthentication, PqHandshake};
/// The sender certificate as a platform unsealed it. UDL `dictionary SenderCertificate`.
pub use crate::crypto::sealed_sender::SenderCertificate;

// Registration bundle fields exposed across the UniFFI boundary as raw bytes.
// Mirrors the UDL `RegistrationBundleFields` dictionary — no base64, no JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationBundleFields {
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub suite_id: u16,
}

/// Returned by rotate_signed_prekey() — new SPK data ready for server upload.
#[derive(Debug, Clone)]
pub struct RotatedSpkBundle {
    pub key_id: u32,
    pub public_key: Vec<u8>, // raw X25519 public key bytes (32 bytes)
    pub signature: Vec<u8>,  // raw Ed25519 signature bytes (64 bytes)
}

// Result of decrypting a message: plaintext + per-message storage key.
// The caller (Swift) must store `storage_key` in MessageKeyStore keyed by message_id.
// Deleting the key from MessageKeyStore permanently prevents decryption of the local copy.
#[derive(Debug, Clone)]
pub struct DecryptedMessageResult {
    pub plaintext: Vec<u8>,
    pub storage_key: Vec<u8>, // 32-byte random key — caller must store in MessageKeyStore
}

// Session initialization result with decrypted first message
// Note: We use UDL definition for UniFFI
/// Mirrors the UDL `ReceivingOpenResult`; see `Orchestrator::open_receiving`.
pub struct ReceivingOpenResult {
    pub opened_device: Option<String>,
    pub opener_message_id: Option<String>,
    pub actions: Vec<CfeAction>,
    pub tried_message_ids: Vec<String>,
    pub dropped_message_ids: Vec<String>,
    pub last_error: Option<String>,
    pub kyber_prekeys: Option<Vec<u8>>,
    pub awaiting_server_key: bool,
}

#[derive(Debug, Clone)]
pub struct SessionInitResult {
    pub session_id: String,
    pub decrypted_message: Vec<u8>, // raw plaintext bytes — may be binary or UTF-8
    pub storage_key: Vec<u8>,       // 32-byte random key for the first received message
    /// The Kyber prekeys blob to persist when this init burned a one-time key.
    pub kyber_prekeys: Option<Vec<u8>>,
}

/// Binary key bundle — mirrors the UDL `BinaryKeyBundle` dictionary.
/// Replaces the JSON-encoded `sequence<u8>` that was previously passed to init_session /
/// init_receiving_session. All fields are already `Vec<u8>` / scalar — no encoding step needed.
#[derive(Debug, Clone)]
pub struct BinaryKeyBundle {
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub suite_id: u16,
    pub one_time_prekey_public: Option<Vec<u8>>,
    pub one_time_prekey_id: Option<u32>,
    pub spk_uploaded_at: u64,
    pub spk_rotation_epoch: u32,
    pub kyber_spk_uploaded_at: u64,
    pub kyber_spk_rotation_epoch: u32,
    // PQXDH v2 — see the UDL for what each is and how it is signed.
    pub kyber_pre_key_public: Option<Vec<u8>>,
    pub kyber_pre_key_id: Option<u32>,
    pub kyber_pre_key_created_at: Option<u64>,
    pub kyber_pre_key_signature: Option<Vec<u8>>,
    pub kyber_pre_key_hybrid_signature: Option<Vec<u8>>,
    pub kyber_one_time_prekey_public: Option<Vec<u8>>,
    pub kyber_one_time_prekey_id: Option<u32>,
    pub kyber_one_time_prekey_created_at: Option<u64>,
    pub kyber_one_time_prekey_signature: Option<Vec<u8>>,
    pub kyber_one_time_prekey_hybrid_signature: Option<Vec<u8>>,
    pub hybrid_identity_key: Option<Vec<u8>>,
    pub hybrid_identity_signature: Option<Vec<u8>>,
}

/// Mirrors the UDL `WirePayload` dictionary and `wire_payload::DecodedWirePayload`.
/// The canonical binary layout lives in `wire_payload.rs`; this is just the FFI
/// shuttle so platform SDKs pack/unpack via the core instead of duplicating it.
#[derive(Debug, Clone)]
pub struct WirePayload {
    pub dh_public_key: Vec<u8>,
    pub message_number: u32,
    pub one_time_prekey_id: u32,
    pub kyber_otpk_id: u32,
    pub previous_chain_length: u32,
    pub suite_id: u16,
    pub kem_ciphertext: Option<Vec<u8>>,
    pub sealed_box: Vec<u8>,
    pub pq_message_epoch: u32,
    /// Suite-3 sparse PQ-ratchet field, serialized (empty = none). Opaque to the transport.
    pub pq_ratchet_field: Vec<u8>,
    /// The wire carried `PQXDH_V2_FLAG`.
    pub pqxdh_v2: bool,
    /// The initiator's ML-KEM-1024 identity key, on a first flight.
    pub kem_identity: Option<Vec<u8>>,
    /// The responder's answer to it, until the initiator proves itself.
    pub identity_proof_ciphertext: Option<Vec<u8>>,
}

/// Serialize the optional suite-3 sparse PQ-ratchet field for the FFI/wire boundary.
/// Empty vec = `None`. Opaque bytes as far as the transport (iOS) is concerned.
fn pq_field_to_bytes(
    field: &Option<crate::crypto::messaging::double_ratchet::PqRatchetWireField>,
) -> Vec<u8> {
    match field {
        Some(f) => serde_json::to_vec(f).unwrap_or_default(),
        None => Vec::new(),
    }
}

#[cfg(test)]
/// Inverse of [`pq_field_to_bytes`]. An empty (or unparseable) slice yields `None`.
fn pq_field_from_bytes(
    bytes: &[u8],
) -> Option<crate::crypto::messaging::double_ratchet::PqRatchetWireField> {
    if bytes.is_empty() {
        None
    } else {
        serde_json::from_slice(bytes).ok()
    }
}

/// One ML-KEM-1024 Kyber prekey to upload — mirrors the UDL `KyberPrekeyUpload`.
#[derive(Debug, Clone)]
pub struct KyberPrekeyUpload {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub created_at: u64,
    pub signature: Vec<u8>,
    pub hybrid_signature: Vec<u8>,
}

impl From<crate::crypto::kyber_prekeys::KyberPrekeyUpload> for KyberPrekeyUpload {
    fn from(r: crate::crypto::kyber_prekeys::KyberPrekeyUpload) -> Self {
        Self {
            key_id: r.key_id,
            public_key: r.public_key,
            created_at: r.created_at,
            signature: r.signature,
            hybrid_signature: r.hybrid_signature,
        }
    }
}

/// One-time prekey pair for upload to server
#[derive(Debug, Clone)]
pub struct OtpkPair {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

/// Full OTPK record for persistence (includes private key for Keychain storage)
#[derive(Clone, Serialize, Deserialize)]
pub struct OtpkRecord {
    pub key_id: u32,
    pub private_key: Vec<u8>, // Base64-encoded private key bytes
    pub public_key: Vec<u8>,  // Base64-encoded public key bytes
}

// Private keys for persistence (exported via UDL)
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKeysJson {
    pub identity_secret: String,      // Base64
    pub signing_secret: String,       // Base64
    pub signed_prekey_secret: String, // Base64
    pub prekey_signature: String,     // Base64
    pub suite_id: String,
    // Integrity fields: public keys re-derived on load and compared to catch Keychain corruption.
    // Optional for backward compatibility with keys exported before this field was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_public_check: Option<String>, // Base64 of identity public key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_key_check: Option<String>, // Base64 of Ed25519 verifying key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_prekey_public_check: Option<String>, // Base64 of SPK public key
}

// Invite crypto types (exported via UDL)
// Note: These are UniFFI-compatible wrappers, actual crypto logic is in crypto::invite_crypto
#[derive(Clone)]
pub struct EphemeralKeyPair {
    pub secret_key: Vec<u8>, // 32 bytes
    pub public_key: Vec<u8>, // 32 bytes
}

// Post-quantum KEM types (exported via UDL)
#[derive(Clone)]
pub struct MLKEMEncapsulation {
    pub ciphertext: Vec<u8>,    // ML-KEM-1024: 1568 bytes
    pub shared_secret: Vec<u8>, // 32 bytes
}

// UniFFI interface implementation (exported via UDL, not proc-macros)
impl ClassicCryptoCore {
    /// Typed registration bundle fields — raw bytes across the FFI boundary.
    pub fn get_registration_bundle_fields(&self) -> Result<RegistrationBundleFields, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let bundle = client
            .key_manager()
            .export_registration_bundle()
            .map_err(|_| CryptoError::InitializationFailed)?;
        Ok(RegistrationBundleFields::from(bundle))
    }

    /// Sign BundleData JSON string with Ed25519 signing key
    /// This is used for creating the signature in UploadableKeyBundle
    pub fn sign_bundle_data(&self, bundle_data_json: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        client
            .key_manager()
            .sign(&bundle_data_json)
            .map_err(|_| CryptoError::InitializationFailed)
    }

    /// Export private keys in CFE binary format (MessagePack + header).
    pub fn export_private_keys(&self) -> Result<Vec<u8>, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let payload = client
            .to_private_keys_cfe()
            .map_err(|_| CryptoError::InvalidKeyData)?;
        crate::cfe::encode(crate::cfe::CfeMessageType::PrivateKeys, &payload)
            .map_err(|e| serialization_failed("classic export_private_keys/encode", e))
    }

    /// Import private keys from CFE bytes.
    pub fn import_private_keys(&self, data: Vec<u8>) -> Result<(), CryptoError> {
        let keys = crate::cfe::decode_as::<crate::cfe::CfePrivateKeysV1>(
            &data,
            crate::cfe::CfeMessageType::PrivateKeys,
        )
        .map_err(|e| serialization_failed("classic import_private_keys/decode", e))?;

        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let local_uid = client.local_user_id().to_string();

        let new_client = ClassicClient::<ClassicSuiteProvider>::from_private_keys_cfe(keys)
            .map_err(|_| CryptoError::InitializationFailed)?;

        *client = new_client;
        if !local_uid.is_empty() {
            client.set_local_user_id(local_uid);
        }
        Ok(())
    }

    /// Export session in CFE binary format (MessagePack + header).
    pub fn export_session(&self, contact_id: String) -> Result<Vec<u8>, CryptoError> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let session = client
            .get_session(&contact_id)
            .ok_or(CryptoError::SessionNotFound)?;
        let serializable = session.messaging_session().to_serializable();
        let payload = serializable
            .to_cfe_v1()
            .map_err(|e| serialization_failed("classic export_session/to_cfe_v1", e))?;

        crate::cfe::encode(crate::cfe::CfeMessageType::SessionState, &payload)
            .map_err(|e| serialization_failed("classic export_session/encode", e))
    }

    /// Import session from CFE bytes (with legacy JSON fallback).
    pub fn import_session(&self, contact_id: String, data: Vec<u8>) -> Result<String, CryptoError> {
        use crate::crypto::messaging::double_ratchet::{DoubleRatchetSession, SerializableSession};

        let serializable = match crate::cfe::decode_as::<crate::cfe::CfeSessionStateV1>(
            &data,
            crate::cfe::CfeMessageType::SessionState,
        ) {
            Ok(cfe_state) => SerializableSession::from_cfe_v1(cfe_state)
                .map_err(|e| serialization_failed("classic import_session/from_cfe_v1", e))?,
            Err(crate::cfe::CfeError::LegacyJson) => {
                let s = std::str::from_utf8(&data).map_err(|_| CryptoError::InvalidKeyData)?;
                serde_json::from_str(s)
                    .map_err(|e| serialization_failed("classic import_session/legacy_json", e))?
            }
            Err(e) => return Err(serialization_failed("classic import_session/decode", e)),
        };

        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        serializable
            .verify_identity(&contact_id, client.local_user_id())
            .map_err(|e| serialization_failed("classic import_session/identity", e))?;

        let ratchet = DoubleRatchetSession::<ClassicSuiteProvider>::from_serializable(serializable)
            .map_err(|e| serialization_failed("classic import_session/from_serializable", e))?;

        let session_id = client.import_session(&contact_id, ratchet);
        Ok(session_id)
    }

    /// Get list of all contact IDs with active sessions
    ///
    /// Used for session restore pagination - can load only recent sessions on app startup.
    ///
    /// # Returns
    /// Vector of contact IDs that have active sessions
    pub fn get_all_session_contact_ids(&self) -> Vec<String> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.active_contacts()
    }

    /// Return a read-only health report for the session with `contact_id`.
    ///
    /// Returns `None` if no session exists for that contact.
    /// Does **not** mutate any session state.
    pub fn get_session_health(&self, contact_id: String) -> Option<SessionHealthReport> {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client
            .get_session_health(&contact_id)
            .map(|snap| SessionHealthReport {
                messages_sent: snap.messages_sent,
                messages_received: snap.messages_received,
                skipped_keys_count: snap.skipped_keys_count as u32,
                is_pq_strengthened: snap.is_pq_strengthened,
                last_ratchet_at: snap.last_ratchet_at,
                session_id: snap.session_id,
                pq_authentication: snap.pq_authentication,
                pq_handshake: snap.pq_handshake,
            })
    }

    pub fn init_session(
        &self,
        contact_id: String,
        recipient_bundle: BinaryKeyBundle,
    ) -> Result<String, CryptoError> {
        let public_bundle = binary_bundle_to_x3dh(&recipient_bundle)?;
        let remote_identity = ClassicSuiteProvider::kem_public_key_from_bytes(
            recipient_bundle.identity_public.clone(),
        );
        let one_time_prekey_id = recipient_bundle.one_time_prekey_id.unwrap_or(0);

        tracing::debug!(
            target: "crypto::uniffi",
            contact_id = %contact_id,
            remote_identity_len = recipient_bundle.identity_public.len(),
            "Initializing session (sender side)"
        );

        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let local_bundle = client
            .key_manager()
            .export_registration_bundle()
            .map_err(|_| CryptoError::InitializationFailed)?;

        tracing::debug!(
            target: "crypto::uniffi",
            contact_id = %contact_id,
            local_identity_len = local_bundle.identity_public.len(),
            remote_identity_len = recipient_bundle.identity_public.len(),
            remote_signed_prekey_len = recipient_bundle.signed_prekey_public.len(),
            verifying_key_len = recipient_bundle.verifying_key.len(),
            signature_len = recipient_bundle.signature.len(),
            suite_id = recipient_bundle.suite_id,
            "Initializing session (sender side)"
        );

        client
            .init_session(
                &contact_id,
                &public_bundle,
                &remote_identity,
                one_time_prekey_id,
            )
            .map_err(|e| {
                tracing::error!(
                    target: "crypto::uniffi",
                    contact_id = %contact_id,
                    error = %e,
                    "init_session failed"
                );
                CryptoError::SessionInitializationFailed {
                    message: e.to_string(),
                }
            })?;

        Ok(contact_id)
    }

    /// Deletes a session for a contact, allowing a new one to be created.
    pub fn remove_session(&self, contact_id: String) -> bool {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.remove_session(&contact_id)
    }

    /// Returns the total number of available prekeys (current + archived).
    ///
    /// The Swift layer should call `uploadPreKeys` when this drops below a
    /// threshold (e.g. < 5) to ensure incoming sessions can always be
    /// established.
    pub fn prekeys_available_count(&self) -> u32 {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = client.key_manager().old_prekeys_count();
        // +1 for the current prekey (always present after initialization)
        (old + 1) as u32
    }

    /// Generate `count` fresh one-time prekeys and return (key_id, public_key_bytes) pairs.
    /// Caller MUST upload these to the server via KeyService.uploadPreKeys.
    pub fn generate_one_time_prekeys(&self, count: u32) -> Result<Vec<OtpkPair>, CryptoError> {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pairs = client.generate_one_time_prekeys(count).map_err(|e| {
            tracing::error!(target: "crypto::uniffi", error = %e, "generate_one_time_prekeys failed");
            CryptoError::InitializationFailed
        })?;
        Ok(pairs
            .into_iter()
            .map(|(key_id, public_key)| OtpkPair { key_id, public_key })
            .collect())
    }

    /// How many one-time prekeys are stored locally (not yet consumed).
    pub fn one_time_prekey_count(&self) -> u32 {
        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.one_time_prekey_count() as u32
    }

    /// Export all locally stored OTPKs in CFE binary format.
    pub fn export_one_time_prekeys(&self) -> Result<Vec<u8>, CryptoError> {
        use serde_bytes::ByteBuf;

        let client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let records = client
            .export_one_time_prekeys()
            .into_iter()
            .map(|(id, priv_key, pub_key)| crate::cfe::CfeOtpkRecordV1 {
                id,
                priv_key: crate::crypto::SecretBytes::from(priv_key),
                pub_key: ByteBuf::from(pub_key),
            })
            .collect();

        let next_id = client.key_manager().next_otpk_id();
        let payload = crate::cfe::CfeOtpkBundleV1 { records, next_id };

        crate::cfe::encode(crate::cfe::CfeMessageType::OtpkBundle, &payload)
            .map_err(|e| serialization_failed("classic export_one_time_prekeys/encode", e))
    }

    /// Import OTPKs from CFE bytes.
    pub fn import_one_time_prekeys(&self, data: Vec<u8>) -> Result<(), CryptoError> {
        let bundle = crate::cfe::decode_as::<crate::cfe::CfeOtpkBundleV1>(
            &data,
            crate::cfe::CfeMessageType::OtpkBundle,
        )
        .map_err(|e| serialization_failed("classic import_one_time_prekeys/decode", e))?;

        let keys: Vec<(u32, Vec<u8>, Vec<u8>)> = bundle
            .records
            .iter()
            .map(|r| (r.id, r.priv_key.expose().to_vec(), r.pub_key.to_vec()))
            .collect();

        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        client.import_one_time_prekeys(keys);
        client.key_manager_mut().set_next_otpk_id(bundle.next_id);
        Ok(())
    }

    /// Prune stored OTPK private keys with `key_id < min_keep_id`; returns the number removed.
    /// Call after a successful replace-all upload — the server set is then exactly the new
    /// batch, so older keys can never be referenced by a future bundle fetch.
    pub fn prune_one_time_prekeys_below(&self, min_keep_id: u32) -> u32 {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.prune_one_time_prekeys_below(min_keep_id) as u32
    }

    /// Set the local user ID — must be called after login/registration so AAD binds
    /// the correct sender identity to every encrypted message.
    pub fn set_local_user_id(&self, user_id: String) {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        client.set_local_user_id(user_id);
    }

    /// Rotate the signed pre-key atomically.
    ///
    /// Generates a new X25519 keypair, signs it with the device Ed25519 signing key,
    /// updates internal KeyManager state (old SPK kept for grace period decryption),
    /// and returns the new public key + signature ready for upload to the key server.
    ///
    pub fn rotate_signed_prekey(&self) -> Result<RotatedSpkBundle, CryptoError> {
        let mut client = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Rotate in Rust core — old SPK is moved to history, new one becomes current.
        client
            .key_manager_mut()
            .rotate_signed_prekey()
            .map_err(|_| CryptoError::InitializationFailed)?;

        // Export the new SPK for upload.
        let bundle = client
            .key_manager()
            .export_registration_bundle()
            .map_err(|_| CryptoError::InitializationFailed)?;

        let key_id = client.key_manager().current_signed_prekey_id().unwrap_or(1);

        Ok(RotatedSpkBundle {
            key_id,
            public_key: bundle.signed_prekey_public,
            signature: bundle.signature,
        })
    }
}

/// Create a new CryptoCore instance (exported via UDL)
/// UniFFI automatically wraps this in Arc<>, so we return Arc<ClassicCryptoCore>
pub fn create_crypto_core() -> Result<Arc<ClassicCryptoCore>, CryptoError> {
    // Инициализировать конфигурацию при первом вызове
    let _ = crate::config::Config::init();

    let client = ClassicClient::<ClassicSuiteProvider>::new()
        .map_err(|_| CryptoError::InitializationFailed)?;

    Ok(Arc::new(ClassicCryptoCore {
        inner: Mutex::new(client),
    }))
}

/// Create a CryptoCore instance from existing private keys in CFE binary format.
pub fn create_crypto_core_from_keys(keys: Vec<u8>) -> Result<Arc<ClassicCryptoCore>, CryptoError> {
    let client = client_from_key_record(&keys, "create_crypto_core_from_keys/decode")?;

    Ok(Arc::new(ClassicCryptoCore {
        inner: Mutex::new(client),
    }))
}

/// Create an OrchestratorCore from CFE binary key bytes.
pub fn create_orchestrator_core_from_keys(
    keys_data: Vec<u8>,
    my_user_id: String,
) -> Result<Arc<OrchestratorCore>, CryptoError> {
    let client = client_from_key_record(&keys_data, "create_orchestrator_core_from_keys/decode")?;

    let orchestrator = crate::orchestration::Orchestrator::new(client, my_user_id);
    Ok(Arc::new(OrchestratorCore {
        inner: std::sync::Mutex::new(orchestrator),
    }))
}

// ============================================================================
// The key record without a core object
// ============================================================================
//
// Before a client knows its user id it needs its keys — to make them, register them, sign with
// them — and nothing else. iOS and Android kept a whole `ClassicCryptoCore` alive for that phase
// (the "bootstrap core"), and Android fell back to it for session operations whenever the
// orchestrator was missing: two cores, two ratchet stores, whichever answered first. With these,
// the pre-login phase holds only the key record (`CfePrivateKeysV1` bytes, what
// `create_orchestrator_core_from_keys` takes), and after login there is one core.
//
// Each call restores a client from the record, answers, and drops it; secrets live in
// `SecretBytes` meanwhile. Nothing here keeps state.

impl From<crate::crypto::handshake::x3dh::X3DHPublicKeyBundle> for RegistrationBundleFields {
    fn from(bundle: crate::crypto::handshake::x3dh::X3DHPublicKeyBundle) -> Self {
        Self {
            identity_public: bundle.identity_public,
            signed_prekey_public: bundle.signed_prekey_public,
            signature: bundle.signature,
            verifying_key: bundle.verifying_key,
            suite_id: bundle.suite_id.as_u16(),
        }
    }
}

/// The one way a key record becomes a client — both `create_*_from_keys` and every function below.
fn client_from_key_record(
    keys: &[u8],
    context: &str,
) -> Result<ClassicClient<ClassicSuiteProvider>, CryptoError> {
    let _ = crate::config::Config::init();
    let decoded = crate::cfe::decode_as::<crate::cfe::CfePrivateKeysV1>(
        keys,
        crate::cfe::CfeMessageType::PrivateKeys,
    )
    .map_err(|e| serialization_failed(context, e))?;
    ClassicClient::<ClassicSuiteProvider>::from_private_keys_cfe(decoded)
        .map_err(|_| CryptoError::InitializationFailed)
}

/// Fresh device keys — identity, signing, a signed prekey — as a key record.
/// Equivalent to `create_crypto_core()` followed by `export_private_keys()`.
pub fn generate_private_keys() -> Result<Vec<u8>, CryptoError> {
    let _ = crate::config::Config::init();
    let client = ClassicClient::<ClassicSuiteProvider>::new()
        .map_err(|_| CryptoError::InitializationFailed)?;
    let record = client
        .to_private_keys_cfe()
        .map_err(|_| CryptoError::InvalidKeyData)?;
    crate::cfe::encode(crate::cfe::CfeMessageType::PrivateKeys, &record)
        .map_err(|e| serialization_failed("generate_private_keys/encode", e))
}

/// The public registration bundle of a key record — what `get_registration_bundle_fields`
/// returns on a core built from it.
pub fn registration_bundle_fields_from_keys(
    keys: Vec<u8>,
) -> Result<RegistrationBundleFields, CryptoError> {
    let client = client_from_key_record(&keys, "registration_bundle_fields_from_keys/decode")?;
    client
        .key_manager()
        .export_registration_bundle()
        .map(RegistrationBundleFields::from)
        .map_err(|_| CryptoError::InitializationFailed)
}

/// Ed25519 signature over `bundle_data_json` with the key record's signing key —
/// `sign_bundle_data` on a core built from it.
pub fn sign_bundle_data_with_keys(
    keys: Vec<u8>,
    bundle_data_json: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let client = client_from_key_record(&keys, "sign_bundle_data_with_keys/decode")?;
    client
        .key_manager()
        .sign(&bundle_data_json)
        .map_err(|_| CryptoError::InitializationFailed)
}

// ============================================================================
// Invite Crypto Functions
// ============================================================================

use crate::crypto::invite_crypto;

/// Generate ephemeral X25519 keypair for a single invite
/// Returns a fresh keypair. Secret key should be discarded after invite creation.
pub fn generate_ephemeral_keypair() -> Result<EphemeralKeyPair, CryptoError> {
    let keypair = invite_crypto::generate_ephemeral_keypair()?;
    Ok(EphemeralKeyPair {
        secret_key: keypair.secret_key.into_vec(),
        public_key: keypair.public_key,
    })
}

/// Verify invite signature with Ed25519 verifying key
/// Returns true if signature is valid, false otherwise.
pub fn verify_invite_signature(
    data: String,
    signature: Vec<u8>,
    verifying_key: Vec<u8>,
) -> Result<bool, CryptoError> {
    Ok(invite_crypto::verify_invite_signature(
        &data,
        &signature,
        &verifying_key,
    )?)
}

// ============================================================================
// Account Recovery Bindings (BIP39 + SLIP-0010 Ed25519)
// ============================================================================

use crate::crypto::recovery;

/// Ed25519 keypair derived from a recovery seed (output of mnemonic_to_seed).
pub struct RecoveryKeypair {
    /// 32-byte Ed25519 private key — keep in memory only, never persist.
    pub private_key: Vec<u8>,
    /// 32-byte Ed25519 public key — sent to server during SetRecoveryKey.
    pub public_key: Vec<u8>,
}

/// Generate a BIP39 mnemonic with the given word count (12 or 24).
pub fn generate_mnemonic(word_count: u8) -> Result<String, CryptoError> {
    recovery::generate_mnemonic(word_count).map_err(|_| CryptoError::InitializationFailed)
}

/// Validate BIP39 checksum and word membership.
pub fn validate_mnemonic(mnemonic: String) -> bool {
    recovery::validate_mnemonic(&mnemonic)
}

/// Convert a BIP39 mnemonic to a 64-byte seed via PBKDF2-HMAC-SHA512 (no passphrase).
pub fn mnemonic_to_seed(mnemonic: String) -> Result<Vec<u8>, CryptoError> {
    let seed = recovery::mnemonic_to_seed(&mnemonic).map_err(|_| CryptoError::InvalidKeyData)?;
    Ok(seed.to_vec())
}

/// Derive an Ed25519 recovery keypair from a 64-byte BIP39 seed.
/// Path: m/44'/0'/0'/0'/0' (SLIP-0010, all hardened — required for Ed25519).
pub fn derive_recovery_keypair(seed: Vec<u8>) -> Result<RecoveryKeypair, CryptoError> {
    let kp = recovery::derive_recovery_keypair(&seed).map_err(|_| CryptoError::InvalidKeyData)?;
    Ok(RecoveryKeypair {
        private_key: kp.private_key.to_vec(),
        public_key: kp.public_key.to_vec(),
    })
}

/// Sign a message string with a 32-byte Ed25519 private key. Returns 64 bytes.
/// Used for SetRecoveryKey.setup_signature and RecoverAccount.recovery_signature.
pub fn sign_recovery_challenge(
    private_key: Vec<u8>,
    message: String,
) -> Result<Vec<u8>, CryptoError> {
    let key: [u8; 32] = private_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let sig = recovery::sign_recovery_challenge(&key, &message)
        .map_err(|_| CryptoError::InvalidKeyData)?;
    Ok(sig.to_vec())
}

/// Verify a 64-byte Ed25519 signature over a message using a 32-byte public key.
pub fn verify_recovery_signature(public_key: Vec<u8>, message: String, signature: Vec<u8>) -> bool {
    let Ok(pk): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(sig): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    recovery::verify_recovery_signature(&pk, &message, &sig)
}

// ============================================================================
// Traffic Protection Bindings
// ============================================================================

use crate::traffic_protection::{
    CoverTrafficConfig as RustCoverTrafficConfig, CoverTrafficManager,
    EnergyMetrics as RustEnergyMetrics, TimingConfig as RustTimingConfig,
};

// UniFFI-compatible structs (must match UDL dictionaries)
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    pub enabled: bool,
    pub battery_level_threshold: f32,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
    pub message_size: u64,
    pub coalesce_with_real_messages: bool,
    pub coalesce_window_ms: u64,
}

impl From<CoverTrafficConfig> for RustCoverTrafficConfig {
    fn from(config: CoverTrafficConfig) -> Self {
        Self {
            enabled: config.enabled,
            battery_level_threshold: config.battery_level_threshold,
            min_interval_ms: config.min_interval_ms,
            max_interval_ms: config.max_interval_ms,
            message_size: config.message_size as usize,
            coalesce_with_real_messages: config.coalesce_with_real_messages,
            coalesce_window_ms: config.coalesce_window_ms,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnergyMetrics {
    pub dummies_sent: u64,
    pub coalesced_count: u64,
    pub battery_skipped: u64,
}

impl From<&RustEnergyMetrics> for EnergyMetrics {
    fn from(metrics: &RustEnergyMetrics) -> Self {
        Self {
            dummies_sent: metrics.dummies_sent,
            coalesced_count: metrics.coalesced_count,
            battery_skipped: metrics.battery_skipped,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimingConfig {
    pub heartbeat_interval_sec: u64,
    pub heartbeat_jitter_ms: u64,
    pub max_send_delay_ms: u64,
    pub enabled: bool,
    pub battery_aware: bool,
}

impl From<TimingConfig> for RustTimingConfig {
    fn from(config: TimingConfig) -> Self {
        Self {
            heartbeat_interval_sec: config.heartbeat_interval_sec,
            heartbeat_jitter_ms: config.heartbeat_jitter_ms,
            max_send_delay_ms: config.max_send_delay_ms,
            enabled: config.enabled,
            battery_aware: config.battery_aware,
        }
    }
}

/// Traffic Protection Manager (UniFFI wrapper)
///
/// Manages cover traffic generation with energy-efficient strategies.
pub struct TrafficProtectionManager {
    inner: Mutex<CoverTrafficManager>,
}

impl TrafficProtectionManager {
    /// Create a new TrafficProtectionManager
    pub fn new(config: CoverTrafficConfig) -> Self {
        let rust_config: RustCoverTrafficConfig = config.into();
        Self {
            inner: Mutex::new(CoverTrafficManager::new(rust_config)),
        }
    }

    /// Update battery level (0.0-1.0)
    ///
    /// Should be called from iOS/Android when battery level changes.
    pub fn update_battery_level(&self, level: f32) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .update_battery_level(level);
    }

    /// Record that a real message was sent (for coalescing)
    pub fn record_real_message_sent(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_real_message_sent();
    }

    /// Check if a dummy message should be sent now
    pub fn should_send_dummy(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .should_send_dummy()
    }

    /// Generate a dummy message
    ///
    /// Call this after should_send_dummy() returns true.
    pub fn generate_dummy(&self) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generate_dummy()
    }

    /// Get current energy metrics
    pub fn get_metrics(&self) -> EnergyMetrics {
        let manager = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        manager.metrics().into()
    }

    /// Reset metrics
    pub fn reset_metrics(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reset_metrics();
    }

    /// Get current adaptive interval (for debugging/monitoring)
    pub fn current_interval_ms(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .current_interval_ms()
    }

    /// Check if currently active (enabled and battery sufficient)
    pub fn is_currently_active(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_currently_active()
    }
}

// Namespace functions (exported via UDL)

/// Generate a dummy message of specified size
pub fn generate_dummy_message(size: u64) -> Vec<u8> {
    crate::traffic_protection::generate_dummy_message(size as usize)
}

/// Check if data is a dummy message
pub fn is_dummy_message(data: Vec<u8>) -> bool {
    crate::traffic_protection::is_dummy_message(&data)
}

/// Generate jittered interval in milliseconds
pub fn jittered_interval_ms(base_ms: u64, jitter_ms: u64) -> u64 {
    crate::traffic_protection::jittered_interval(base_ms, jitter_ms).as_millis() as u64
}

/// Generate random send delay in milliseconds
pub fn random_send_delay_ms(max_delay_ms: u64) -> u64 {
    crate::traffic_protection::random_send_delay(max_delay_ms).as_millis() as u64
}

/// Generate heartbeat interval with jitter in milliseconds
pub fn heartbeat_interval_ms(base_interval_sec: u64) -> u64 {
    crate::traffic_protection::heartbeat_interval(base_interval_sec).as_millis() as u64
}

/// Generate battery-aware jittered interval in milliseconds
pub fn battery_aware_jitter_ms(base_ms: u64, max_jitter_ms: u64, battery_level: f32) -> u64 {
    crate::traffic_protection::battery_aware_jitter(base_ms, max_jitter_ms, battery_level)
        .as_millis() as u64
}

/// Get recommended send delay based on priority and battery
pub fn recommended_send_delay_ms(is_high_priority: bool, battery_level: f32) -> u64 {
    crate::traffic_protection::recommended_send_delay(is_high_priority, battery_level).as_millis()
        as u64
}

// ============================================================================
// History transfer — construct-docs/decisions/history-transfer-protocol-in-the-core.md
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HistoryError {
    #[error("malformed")]
    Malformed,
    #[error("truncated")]
    Truncated,
    #[error("unknown_version")]
    UnknownVersion,
    #[error("user_mismatch")]
    UserMismatch,
    #[error("record_order")]
    RecordOrder,
    #[error("envelope_manifest_mismatch")]
    EnvelopeManifestMismatch,
    #[error("v1_refused_for_history")]
    V1RefusedForHistory,
    #[error("identity_mismatch")]
    IdentityMismatch,
    #[error("kem_key_id_mismatch")]
    KemKeyIdMismatch,
    #[error("qr_pin_mismatch")]
    QrPinMismatch,
    #[error("qr_pin_absent")]
    QrPinAbsent,
    #[error("no_hybrid_key")]
    NoHybridKey,
    #[error("signature_invalid")]
    SignatureInvalid,
    #[error("chunk_open_failed")]
    ChunkOpenFailed,
    #[error("local_keys_unavailable")]
    LocalKeysUnavailable,
}

impl From<crate::history::HistoryFailure> for HistoryError {
    fn from(f: crate::history::HistoryFailure) -> Self {
        use crate::history::HistoryFailure as F;
        match f {
            F::Malformed => Self::Malformed,
            F::Truncated => Self::Truncated,
            F::UnknownVersion => Self::UnknownVersion,
            F::UserMismatch => Self::UserMismatch,
            F::RecordOrder => Self::RecordOrder,
            F::EnvelopeManifestMismatch => Self::EnvelopeManifestMismatch,
            F::V1RefusedForHistory => Self::V1RefusedForHistory,
            F::IdentityMismatch => Self::IdentityMismatch,
            F::KemKeyIdMismatch => Self::KemKeyIdMismatch,
            F::QrPinMismatch => Self::QrPinMismatch,
            F::QrPinAbsent => Self::QrPinAbsent,
            F::NoHybridKey => Self::NoHybridKey,
            F::SignatureInvalid => Self::SignatureInvalid,
            F::ChunkOpenFailed => Self::ChunkOpenFailed,
            F::LocalKeysUnavailable => Self::LocalKeysUnavailable,
        }
    }
}

fn history_user_id(user_id: Vec<u8>) -> Result<[u8; 16], HistoryError> {
    user_id.try_into().map_err(|_| HistoryError::Malformed)
}

pub struct HistoryPeerKeys {
    pub identity_public: Vec<u8>,
    pub hybrid_public: Vec<u8>,
    pub kyber_prekey_public: Vec<u8>,
    pub kyber_prekey_id: u32,
}

impl HistoryPeerKeys {
    fn into_core(self) -> Result<crate::history::session::PeerKeys, HistoryError> {
        if self.hybrid_public.is_empty() || self.kyber_prekey_public.is_empty() {
            return Err(HistoryError::NoHybridKey);
        }
        Ok(crate::history::session::PeerKeys {
            identity_public: self
                .identity_public
                .try_into()
                .map_err(|_| HistoryError::Malformed)?,
            hybrid_public: self.hybrid_public,
            kyber_prekey_public: self.kyber_prekey_public,
            kyber_prekey_id: self.kyber_prekey_id,
        })
    }
}

pub struct HistoryKnownKeys {
    pub identity_public: Vec<u8>,
    pub hybrid_public: Vec<u8>,
}

pub enum HistoryPin {
    Fingerprint { fingerprint: Vec<u8> },
    BundleOnly,
    Absent,
}

pub struct HistoryRecordOut {
    pub record_type: u8,
    pub proto: Vec<u8>,
}

pub enum HistoryEvent {
    Record {
        record_type: u8,
        proto: Vec<u8>,
    },
    Skipped {
        record_type: u8,
    },
    MediaStart {
        media_id: String,
        mime_type: String,
        byte_len: u64,
    },
    MediaBytes {
        data: Vec<u8>,
    },
    MediaEnd,
    End,
}

impl From<crate::history::cth1::Event> for HistoryEvent {
    fn from(e: crate::history::cth1::Event) -> Self {
        use crate::history::cth1::Event as E;
        match e {
            E::Record { record_type, proto } => Self::Record { record_type, proto },
            E::Skipped { record_type } => Self::Skipped { record_type },
            E::MediaStart {
                media_id,
                mime_type,
                byte_len,
            } => Self::MediaStart {
                media_id,
                mime_type,
                byte_len,
            },
            E::MediaBytes(data) => Self::MediaBytes { data },
            E::MediaEnd => Self::MediaEnd,
            E::End => Self::End,
        }
    }
}

pub enum HistoryStatus {
    NeedMore,
    AwaitKeys { sender_device_id: String },
    Skipped,
    Done,
}

pub struct HistoryStep {
    pub events: Vec<HistoryEvent>,
    pub status: HistoryStatus,
}

pub struct HistorySender {
    inner: Mutex<crate::history::session::Sender>,
    first_frame: Vec<u8>,
    snapshot_id: Vec<u8>,
}

impl HistorySender {
    fn new(sender: crate::history::session::Sender) -> Self {
        Self {
            first_frame: sender.first_frame().to_vec(),
            snapshot_id: sender.snapshot_id().to_vec(),
            inner: Mutex::new(sender),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, crate::history::session::Sender> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn first_frame(&self) -> Vec<u8> {
        self.first_frame.clone()
    }

    pub fn snapshot_id(&self) -> Vec<u8> {
        self.snapshot_id.clone()
    }

    pub fn accept_reply(&self, reply: Vec<u8>) -> Result<(), HistoryError> {
        Ok(self.lock().accept_reply(&reply)?)
    }

    pub fn push_records(&self, records: Vec<HistoryRecordOut>) -> Result<Vec<u8>, HistoryError> {
        let mut sender = self.lock();
        let mut out = Vec::new();
        for r in &records {
            sender.push_record(r.record_type, &r.proto, &mut out)?;
        }
        Ok(out)
    }

    pub fn begin_media(
        &self,
        media_id: String,
        mime_type: String,
        byte_len: u64,
    ) -> Result<Vec<u8>, HistoryError> {
        let mut out = Vec::new();
        self.lock()
            .begin_media(&media_id, &mime_type, byte_len, &mut out)?;
        Ok(out)
    }

    pub fn push_media(&self, piece: Vec<u8>) -> Result<Vec<u8>, HistoryError> {
        let mut out = Vec::with_capacity(piece.len() + 64);
        self.lock().push_media(&piece, &mut out)?;
        Ok(out)
    }

    pub fn finish(&self) -> Result<Vec<u8>, HistoryError> {
        let mut out = Vec::new();
        self.lock().finish(&mut out)?;
        Ok(out)
    }
}

pub struct HistoryReceiver {
    core: Arc<OrchestratorCore>,
    inner: Mutex<crate::history::session::Receiver>,
}

impl HistoryReceiver {
    fn lock(&self) -> std::sync::MutexGuard<'_, crate::history::session::Receiver> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn need(&self) -> u32 {
        self.lock().need() as u32
    }

    pub fn feed(&self, data: Vec<u8>) -> Result<HistoryStep, HistoryError> {
        use crate::history::session::Status;
        let (events, status) = self.lock().feed(&data)?;
        Ok(HistoryStep {
            events: events.into_iter().map(HistoryEvent::from).collect(),
            status: match status {
                Status::NeedMore => HistoryStatus::NeedMore,
                Status::AwaitKeys { sender_device_id } => HistoryStatus::AwaitKeys {
                    sender_device_id: hex::encode(sender_device_id),
                },
                Status::Skipped => HistoryStatus::Skipped,
                Status::Done => HistoryStatus::Done,
            },
        })
    }

    pub fn accept(
        &self,
        known: HistoryKnownKeys,
        pin: HistoryPin,
    ) -> Result<Option<Vec<u8>>, HistoryError> {
        use crate::history::frames::{KnownKeys, Pin};
        let pin = match pin {
            HistoryPin::Fingerprint { fingerprint } => Pin::Fingerprint(
                fingerprint
                    .try_into()
                    .map_err(|_| HistoryError::QrPinMismatch)?,
            ),
            HistoryPin::BundleOnly => Pin::BundleOnly,
            HistoryPin::Absent => Pin::Absent,
        };
        let known = KnownKeys {
            identity_public: known.identity_public,
            hybrid_public: known.hybrid_public,
        };
        let mut receiver = self.lock();
        let orch = self.core.inner.lock().unwrap_or_else(|p| p.into_inner());
        Ok(receiver.accept(&*orch, &known, &pin)?)
    }

    pub fn end_of_input(&self) -> Result<(), HistoryError> {
        Ok(self.lock().end_of_input()?)
    }
}

pub fn history_reply_len() -> u32 {
    crate::history::frames::REPLY_LEN as u32
}

/// The largest blob whose record — head (at most `MEDIA_HEAD_CAP`) and blob — fits
/// `MAX_RECORD_BYTES`.
pub fn history_max_blob_bytes() -> u64 {
    crate::history::MAX_RECORD_BYTES - crate::history::cth1::MEDIA_HEAD_CAP as u64
}

pub fn history_discovery_tag(user_id_dashed: String, device_id_hex: String) -> String {
    crate::history::discovery::discovery_tag(&user_id_dashed, &device_id_hex)
}

pub fn history_discovery_instance_name(tag: String) -> String {
    crate::history::discovery::discovery_instance_name(&tag)
}

pub fn history_qr_fingerprint(identity_public: Vec<u8>, hybrid_public: Vec<u8>) -> Vec<u8> {
    crate::history::discovery::qr_fingerprint(&identity_public, &hybrid_public).to_vec()
}

// ============================================================================
// MLS Group Chat (RFC 9420) — device-level MlsStore
// ============================================================================

/// UniFFI wrapper around `group::MlsStore` (Mutex for the &self interface,
/// same pattern as OrchestratorCore).
pub struct MlsStore {
    inner: std::sync::Mutex<crate::group::MlsStore>,
}

impl MlsStore {
    fn new(signer_private_key: Vec<u8>, signer_public_key: Vec<u8>) -> Self {
        Self {
            inner: std::sync::Mutex::new(crate::group::MlsStore::new(
                signer_private_key,
                signer_public_key,
            )),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, crate::group::MlsStore> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn generate_key_package(&self) -> Result<Vec<u8>, MlsError> {
        self.lock().generate_key_package()
    }

    pub fn create_group(&self) -> Result<Vec<u8>, MlsError> {
        self.lock().create_group()
    }

    pub fn join_from_welcome(&self, welcome: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        self.lock().join_from_welcome(&welcome)
    }

    pub fn encrypt(&self, group_id: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        self.lock().encrypt(&group_id, &plaintext)
    }

    pub fn decrypt(&self, group_id: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        self.lock().decrypt(&group_id, &ciphertext)
    }

    pub fn add_member(
        &self,
        group_id: Vec<u8>,
        key_package: Vec<u8>,
    ) -> Result<MemberAddition, MlsError> {
        self.lock().add_member(&group_id, &key_package)
    }

    pub fn remove_member(&self, group_id: Vec<u8>, leaf_index: u32) -> Result<Vec<u8>, MlsError> {
        self.lock().remove_member(&group_id, leaf_index)
    }

    pub fn leave_group(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        self.lock().leave_group(&group_id)
    }

    pub fn process_commit(&self, group_id: Vec<u8>, commit: Vec<u8>) -> Result<(), MlsError> {
        self.lock().process_commit(&group_id, &commit)
    }

    pub fn member_count(&self, group_id: Vec<u8>) -> Result<u32, MlsError> {
        self.lock().member_count(&group_id)
    }

    pub fn epoch(&self, group_id: Vec<u8>) -> Result<u64, MlsError> {
        self.lock().epoch(&group_id)
    }

    pub fn export_cfe(&self) -> Result<Vec<u8>, MlsError> {
        self.lock().export_cfe()
    }
}

/// Restore an MlsStore from a CFE blob previously produced by `export_cfe()`, signing with the
/// given keys — reached only through `OrchestratorCore::import_mls_store`.
fn import_mls_store_cfe(
    data: Vec<u8>,
    signer_private_key: Vec<u8>,
    signer_public_key: Vec<u8>,
) -> Result<std::sync::Arc<MlsStore>, MlsError> {
    let store = crate::group::MlsStore::import_cfe(&data, signer_private_key, signer_public_key)?;
    Ok(std::sync::Arc::new(MlsStore {
        inner: std::sync::Mutex::new(store),
    }))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn bundle_fields_to_binary(fields: RegistrationBundleFields) -> BinaryKeyBundle {
        BinaryKeyBundle {
            identity_public: fields.identity_public,
            signed_prekey_public: fields.signed_prekey_public,
            signature: fields.signature,
            verifying_key: fields.verifying_key,
            suite_id: fields.suite_id,
            one_time_prekey_public: None,
            one_time_prekey_id: None,
            spk_uploaded_at: 0,
            spk_rotation_epoch: 0,
            kyber_spk_uploaded_at: 0,
            kyber_spk_rotation_epoch: 0,
            kyber_pre_key_public: None,
            kyber_pre_key_id: None,
            kyber_pre_key_created_at: None,
            kyber_pre_key_signature: None,
            kyber_pre_key_hybrid_signature: None,
            kyber_one_time_prekey_public: None,
            kyber_one_time_prekey_id: None,
            kyber_one_time_prekey_created_at: None,
            kyber_one_time_prekey_signature: None,
            kyber_one_time_prekey_hybrid_signature: None,
            hybrid_identity_key: None,
            hybrid_identity_signature: None,
        }
    }

    /// `core`'s bundle as the key service serves it after PQXDH v2: the X3DH part plus a signed
    /// Kyber SPK (committed here if the core has none) and the hybrid identity key bound to the
    /// Ed25519 identity. PQ is mandatory, so this is what every session needs.
    #[cfg(feature = "post-quantum")]
    fn pq_bundle(core: &OrchestratorCore) -> BinaryKeyBundle {
        let hybrid = core.ensure_hybrid_signature_key().unwrap();
        let spk = match core.current_kyber_spk_upload().unwrap() {
            Some(spk) => spk,
            None => {
                core.begin_kyber_spk_rotation().unwrap();
                assert!(core.commit_kyber_spk_rotation());
                core.current_kyber_spk_upload().unwrap().unwrap()
            }
        };
        let signing = core.inner.lock().unwrap().get_signing_key_bytes().unwrap();
        let binding = ClassicSuiteProvider::sign(
            &ClassicSuiteProvider::signature_private_key_from_bytes(signing),
            &core.build_hybrid_identity_bind_message(hybrid.clone()),
        )
        .unwrap();
        let mut bundle = bundle_fields_to_binary(core.get_registration_bundle_fields().unwrap());
        bundle.kyber_pre_key_id = Some(spk.key_id);
        bundle.kyber_pre_key_public = Some(spk.public_key);
        bundle.kyber_pre_key_created_at = Some(spk.created_at);
        bundle.kyber_pre_key_signature = Some(spk.signature);
        bundle.kyber_pre_key_hybrid_signature = Some(spk.hybrid_signature);
        bundle.hybrid_identity_key = Some(hybrid);
        bundle.hybrid_identity_signature = Some(binding);
        bundle
    }

    /// Test that verifies session_id returned from init_session is the contact_id
    /// This ensures the bug where random UUID was returned is fixed
    #[test]
    fn test_init_session_returns_contact_id() {
        let alice = create_crypto_core().unwrap();
        let bob = create_crypto_core().unwrap();
        alice.set_local_user_id("alice_user".to_string());
        bob.set_local_user_id("bob_user_id_123".to_string());

        // Get Bob's registration bundle and convert it
        let bob_bundle_bytes =
            bundle_fields_to_binary(bob.get_registration_bundle_fields().unwrap());

        // Alice initializes session with Bob
        let contact_id = "bob_user_id_123".to_string();
        let session_id = alice
            .init_session(contact_id.clone(), bob_bundle_bytes)
            .unwrap();

        // CRITICAL: session_id should equal contact_id
        assert_eq!(
            session_id, contact_id,
            "init_session must return contact_id as session_id for Swift compatibility"
        );
    }

    /// Unix seconds for a timestamp `days` in the past (used to fake a stale SPK).
    fn unix_secs_days_ago(days: u64) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(days * 24 * 3600)
    }

    /// Build an `OrchestratorCore` (the core the iOS app actually uses) for a given user id.
    /// Keys are generated via the classic core and re-imported as CFE bytes, matching the
    /// production `create_orchestrator_core_from_keys` path.
    /// An orchestrator core named by the device id its identity key derives to — what a real
    /// device is called, and what a session opened from a sender certificate is filed under.
    fn named_core() -> (std::sync::Arc<OrchestratorCore>, String) {
        let classic = create_crypto_core().unwrap();
        let id = crate::device_id::derive_device_id(
            &classic
                .get_registration_bundle_fields()
                .unwrap()
                .identity_public,
        );
        let keys = classic.export_private_keys().unwrap();
        let core = create_orchestrator_core_from_keys(keys, id.clone()).unwrap();
        // Every device that publishes a bundle holds one; the KEM identity key derives from it.
        core.ensure_hybrid_signature_key().unwrap();
        (core, id)
    }

    /// `sender`'s sender certificate as `server` issues it now, and `recipient` trusting `server`.
    fn certified(
        server: &crate::crypto::sealed_sender::test_support::TestServer,
        sender: &OrchestratorCore,
        recipient: &OrchestratorCore,
    ) -> SenderCertificate {
        recipient.set_trusted_server_keys(vec![server.verifying_key()]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let identity = sender
            .get_registration_bundle_fields()
            .unwrap()
            .identity_public;
        server.certify(&identity, now)
    }

    fn make_orchestrator(user_id: &str) -> std::sync::Arc<OrchestratorCore> {
        let classic = create_crypto_core().unwrap();
        let keys = classic.export_private_keys().unwrap();
        create_orchestrator_core_from_keys(keys, user_id.to_string()).unwrap()
    }

    // ── Operations with the device's own keys ─────────────────────────────────
    // Each is checked against the path it replaces — the secret handed to the crypto function
    // directly — so a platform moving to it changed no byte on the wire. The secrets are read
    // through the inner lock: nothing exported returns them since 2026-09-29.

    fn signing_secret(core: &OrchestratorCore) -> Vec<u8> {
        core.inner.lock().unwrap().get_signing_key_bytes().unwrap()
    }

    fn identity_secret(core: &OrchestratorCore) -> Vec<u8> {
        core.inner.lock().unwrap().get_identity_key_bytes().unwrap()
    }

    #[test]
    fn signing_with_the_device_key_is_the_signature_the_exported_key_made() {
        let (core, _) = named_core();
        let message = b"device-id1700000000".to_vec();
        let signature = core.sign_with_device_key(message.clone()).unwrap();
        let exported = signing_secret(&core);
        let old = crate::crypto::invite_crypto::sign_invite_data(
            std::str::from_utf8(&message).unwrap(),
            &exported,
        )
        .unwrap();
        assert_eq!(signature, old.signature);
        let verifying_key = core.get_registration_bundle_fields().unwrap().verifying_key;
        assert!(
            verify_invite_signature(
                String::from_utf8(message).unwrap(),
                signature,
                verifying_key
            )
            .unwrap()
        );
    }

    #[test]
    fn a_box_sealed_to_this_device_opens_and_one_sealed_to_another_does_not() {
        let (ours, _) = named_core();
        let (theirs, _) = named_core();
        let our_key = ours
            .get_registration_bundle_fields()
            .unwrap()
            .identity_public;
        let sealed = seal_to_device_key(b"metadata".to_vec(), our_key).unwrap();
        assert_eq!(
            ours.open_sealed_to_device(sealed.clone()).unwrap(),
            b"metadata"
        );
        assert_eq!(
            crate::crypto::sealed_sender::open_with_x25519_secret(&sealed, &identity_secret(&ours))
                .unwrap(),
            b"metadata"
        );
        assert!(theirs.open_sealed_to_device(sealed).is_err());
    }

    #[test]
    fn a_copy_tag_is_recognised_by_the_device_it_names_and_by_no_sibling() {
        let (sender, _) = named_core();
        let (target, target_id) = named_core();
        let (sibling, _) = named_core();
        let sender_key = sender
            .get_registration_bundle_fields()
            .unwrap()
            .identity_public;
        let target_key = target
            .get_registration_bundle_fields()
            .unwrap()
            .identity_public;

        let tag = sender
            .device_copy_tag("m1".into(), target_id.clone(), target_key.clone())
            .unwrap();
        let old = crate::crypto::device_copy_tag::device_copy_tag(
            "m1",
            &target_id,
            &identity_secret(&sender),
            &target_key,
        )
        .unwrap();
        assert_eq!(tag, old);
        assert!(target.device_copy_tag_matches(tag.clone(), "m1".into(), sender_key.clone()));
        assert!(!target.device_copy_tag_matches(tag.clone(), "m2".into(), sender_key.clone()));
        // The sibling's id is derived from its own key: a tag for the target is not its copy.
        assert!(!sibling.device_copy_tag_matches(tag, "m1".into(), sender_key));
    }

    /// The receiver's channel key is the schedule the sender computes from public keys alone —
    /// the Swift `TransferCrypto.deriveChannelKey(salt: .file)` it replaces.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn the_history_file_channel_key_is_the_one_the_sender_derives() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let (receiver, _) = named_core();
        core_spk(&receiver);
        let spk = receiver.current_kyber_spk_upload().unwrap().unwrap();
        let identity = receiver
            .get_registration_bundle_fields()
            .unwrap()
            .identity_public;

        // The sender's side: an ephemeral X25519 pair and an encapsulation to the Kyber SPK.
        let eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes().to_vec();
        let peer: [u8; 32] = identity.try_into().unwrap();
        let dh = eph.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        let enc = mlkem1024_encapsulate(spk.public_key.clone()).unwrap();
        let snapshot = vec![7u8; 16];
        let mut ikm = dh.as_bytes().to_vec();
        ikm.extend_from_slice(&enc.shared_secret);
        let mut expected = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"construct_history_file_v1"), &ikm)
            .expand(&snapshot, &mut expected)
            .unwrap();

        let key = receiver
            .history_file_channel_key(
                eph_pub.clone(),
                spk.key_id,
                enc.ciphertext.clone(),
                snapshot,
            )
            .unwrap();
        assert_eq!(key, expected);

        let other_snapshot = receiver
            .history_file_channel_key(eph_pub, spk.key_id, enc.ciphertext, vec![8u8; 16])
            .unwrap();
        assert_ne!(
            other_snapshot, expected,
            "the snapshot id is bound into the key"
        );
    }

    /// The directory entry a device publishes, as `HistoryPeerKeys`.
    #[cfg(feature = "post-quantum")]
    fn history_peer(core: &OrchestratorCore) -> HistoryPeerKeys {
        core_spk(core);
        let spk = core.current_kyber_spk_upload().unwrap().unwrap();
        HistoryPeerKeys {
            identity_public: core
                .get_registration_bundle_fields()
                .unwrap()
                .identity_public,
            hybrid_public: core.hybrid_signature_public_key().unwrap(),
            kyber_prekey_public: spk.public_key,
            kyber_prekey_id: spk.key_id,
        }
    }

    #[cfg(feature = "post-quantum")]
    fn history_known(peer: &HistoryPeerKeys) -> HistoryKnownKeys {
        HistoryKnownKeys {
            identity_public: peer.identity_public.clone(),
            hybrid_public: peer.hybrid_public.clone(),
        }
    }

    /// A platform's read loop: exactly `need()` bytes at a time from `stream`.
    #[cfg(feature = "post-quantum")]
    fn history_pump(
        receiver: &HistoryReceiver,
        stream: &[u8],
        at: &mut usize,
        events: &mut Vec<HistoryEvent>,
    ) -> Result<HistoryStatus, HistoryError> {
        loop {
            let need = receiver.need() as usize;
            if need == 0 || *at + need > stream.len() {
                return Ok(HistoryStatus::NeedMore);
            }
            let step = receiver.feed(stream[*at..*at + need].to_vec())?;
            *at += need;
            events.extend(step.events);
            if !matches!(step.status, HistoryStatus::NeedMore) {
                return Ok(step.status);
            }
        }
    }

    /// Two real cores, the whole nearby exchange through the exported surface: opening, the
    /// directory keys, the reply, a transcript and a blob. What the new device's core signs and
    /// decapsulates with never leaves it.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn two_cores_move_history_over_the_local_network() {
        let (old, old_id) = named_core();
        let (new, _) = named_core();
        let user = vec![0x11; 16];
        let old_peer = history_peer(&old);
        let sender = old
            .history_offer_nearby(user.clone(), history_peer(&new), false, None)
            .unwrap();
        let receiver = new.clone().history_receive(user.clone(), false);

        let (mut events, mut at) = (Vec::new(), 0);
        let opening = sender.first_frame();
        match history_pump(&receiver, &opening, &mut at, &mut events).unwrap() {
            HistoryStatus::AwaitKeys { sender_device_id } => assert_eq!(sender_device_id, old_id),
            _ => panic!("expected AwaitKeys"),
        }
        let reply = receiver
            .accept(history_known(&old_peer), HistoryPin::BundleOnly)
            .unwrap()
            .expect("a nearby reply");
        assert_eq!(reply.len() as u32, history_reply_len());
        sender.accept_reply(reply).unwrap();

        let mut manifest = vec![0x08, 1, 0x12, 16];
        manifest.extend_from_slice(&sender.snapshot_id());
        manifest.extend_from_slice(&[0x1a, 16]);
        manifest.extend_from_slice(&user);
        manifest.extend_from_slice(&[0x68, 3]);
        let blob = vec![0x5a; 150_000];
        let mut stream = sender
            .push_records(vec![
                HistoryRecordOut {
                    record_type: 1,
                    proto: manifest,
                },
                HistoryRecordOut {
                    record_type: 4,
                    proto: vec![0x32, 0],
                },
            ])
            .unwrap();
        stream.extend(
            sender
                .begin_media("m".into(), "image/jpeg".into(), blob.len() as u64)
                .unwrap(),
        );
        stream.extend(sender.push_media(blob.clone()).unwrap());
        stream.extend(sender.finish().unwrap());

        let mut at = 0;
        assert!(matches!(
            history_pump(&receiver, &stream, &mut at, &mut events).unwrap(),
            HistoryStatus::Done
        ));
        receiver.end_of_input().unwrap();
        let received: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                HistoryEvent::MediaBytes { data } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(received, blob);
        assert!(matches!(events.last(), Some(HistoryEvent::End)));
    }

    /// A file for the new device opens there and nowhere else: a third device of the account
    /// fails the recipient check, before any secret is touched.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn a_history_file_opens_only_on_the_device_it_was_made_for() {
        let (old, _) = named_core();
        let (new, _) = named_core();
        let (third, _) = named_core();
        let user = vec![0x22; 16];
        let old_peer = history_peer(&old);
        let sender = old
            .history_offer_file(user.clone(), history_peer(&new))
            .unwrap();
        let mut manifest = vec![0x08, 1, 0x12, 16];
        manifest.extend_from_slice(&sender.snapshot_id());
        manifest.extend_from_slice(&[0x1a, 16]);
        manifest.extend_from_slice(&user);
        manifest.extend_from_slice(&[0x68, 3]);
        let mut file = sender.first_frame();
        file.extend(
            sender
                .push_records(vec![HistoryRecordOut {
                    record_type: 1,
                    proto: manifest,
                }])
                .unwrap(),
        );
        file.extend(sender.finish().unwrap());

        let open = |core: &Arc<OrchestratorCore>| -> Result<usize, HistoryError> {
            history_peer(core);
            let receiver = core.clone().history_receive(user.clone(), true);
            let (mut events, mut at) = (Vec::new(), 0);
            history_pump(&receiver, &file, &mut at, &mut events)?;
            assert!(
                receiver
                    .accept(history_known(&old_peer), HistoryPin::BundleOnly)?
                    .is_none()
            );
            history_pump(&receiver, &file, &mut at, &mut events)?;
            receiver.end_of_input()?;
            Ok(events.len())
        };
        assert_eq!(open(&new), Ok(2), "manifest and End");
        assert_eq!(open(&third), Err(HistoryError::IdentityMismatch));
    }

    #[cfg(feature = "post-quantum")]
    fn core_spk(core: &OrchestratorCore) {
        if core.current_kyber_spk_upload().unwrap().is_none() {
            core.begin_kyber_spk_rotation().unwrap();
            assert!(core.commit_kyber_spk_rotation());
        }
    }

    /// The bundle the core seals opens to this device's keys and id — the same format the
    /// platform sealed from its Keychain copies.
    #[test]
    fn the_own_recovery_bundle_opens_to_this_devices_keys() {
        let (core, id) = named_core();
        let vault_key = sr_generate_vault_key().unwrap();
        let sealed = core
            .seal_own_recovery_bundle(vault_key.clone(), 1_700_000_000)
            .unwrap();
        let key: [u8; 32] = vault_key.try_into().unwrap();
        let opened = crate::crypto::social_recovery::open_recovery_bundle(&key, &sealed).unwrap();
        assert_eq!(opened.device_signing_key, signing_secret(&core));
        assert_eq!(opened.device_identity_key, identity_secret(&core));
        assert_eq!(opened.device_id, id);
        assert_eq!(opened.created_at, 1_700_000_000);
        assert!(core.seal_own_recovery_bundle(vec![0; 31], 0).is_err());
    }

    #[test]
    fn an_mls_store_from_the_core_survives_export_and_import() {
        let (core, _) = named_core();
        let store = core.new_mls_store().unwrap();
        let group = store.create_group().unwrap();
        let blob = store.export_cfe().unwrap();
        let restored = core.import_mls_store(blob).unwrap();
        assert_eq!(restored.member_count(group.clone()).unwrap(), 1);
        assert!(
            restored.encrypt(group, b"x".to_vec()).is_ok(),
            "the restored store signs with the device key it was bound to"
        );
    }

    /// The orchestrator's queued-carrier count for `contact_id`. Read through the inner lock
    /// rather than a new UDL method: the leftover state this test is about is private to the
    /// crate on purpose, and widening the exported surface to observe it would be the opposite
    /// of the point.
    fn pending_for(core: &OrchestratorCore, contact_id: &str) -> usize {
        let orch = core.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.pending_message_count(contact_id)
    }

    fn packed(message_number: u32, kem: Option<&[u8]>) -> Vec<u8> {
        crate::wire_payload::pack(
            &[7u8; 32],
            message_number,
            0,
            0,
            0,
            1,
            kem,
            None,
            None,
            &[0u8; 32],
            0,
            None,
        )
        .unwrap()
    }

    /// `wire_summary` reads the number and the kind from the payload itself. A handshake header
    /// opens at any message number (`decisions/sessions-renew-by-sending.md`), so the kind must
    /// not be derived from the number.
    ///
    /// Mutation: classify by `message_number == 0` — the renewal case (number 9 with a header)
    /// reddens.
    #[test]
    fn wire_summary_reads_number_and_kind_from_the_payload() {
        let first = wire_summary(packed(0, Some(&[5u8; 1568]))).unwrap();
        assert_eq!(
            first,
            WireSummary {
                message_number: 0,
                init_kind: ReceivingInitKind::Handshake
            }
        );

        let renewal = wire_summary(packed(9, Some(&[5u8; 1568]))).unwrap();
        assert_eq!(
            renewal,
            WireSummary {
                message_number: 9,
                init_kind: ReceivingInitKind::Handshake
            }
        );

        let plain = wire_summary(packed(9, None)).unwrap();
        assert_eq!(
            plain,
            WireSummary {
                message_number: 9,
                init_kind: ReceivingInitKind::MidRatchet
            }
        );

        assert!(
            wire_summary(vec![0xFF; 7]).is_err(),
            "a payload that does not parse has no summary"
        );
    }

    /// A message carrying the handshake header from `from`, the shape that opens a receiving
    /// session.
    fn queued_first_message(id: &str, from: &str) -> CfeIncomingEvent {
        CfeIncomingEvent::MessageReceived {
            message_id: id.to_string(),
            from: from.to_string(),
            data: crate::wire_payload::pack(
                &[7u8; 32],
                0,
                0,
                0,
                0,
                1,
                Some(&[5u8; 1568]),
                None,
                None,
                &[0u8; 32], // sealed box — never decrypted here
                0,
                None,
            )
            .unwrap(),
            content_type: 0,
            sender_certificate: None,
        }
    }

    /// Deleting a contact must be expressible **through the exported surface**.
    ///
    /// `forget_contact_state` was implemented, unit-tested at two levels, and absent from the
    /// UDL — so the only deletion a platform could reach was `remove_session`, which drops the
    /// ratchet and leaves the queue, the init lock, the prekey counter and the PQ
    /// contribution behind. iOS shipped that for months: "delete this
    /// contact" removed the session and the next add was steered by the deleted contact's
    /// leftovers.
    ///
    /// The assertion is the *difference* between the two calls, not that either one runs. A test
    /// that only called `forget_contact_state` would pass just as well against `remove_session`
    /// and would not have caught the export gap that produced this.
    #[test]
    fn forget_contact_state_is_reachable_and_outlives_remove_session() {
        let core = make_orchestrator("alice");

        // A backlog carrier lands with no session: queued, and a bundle fetch requested.
        let actions = core
            .handle_event(queued_first_message("backlog-1", "bob"))
            .unwrap();
        assert!(
            actions.iter().any(|a| matches!(
                a,
                CfeAction::OpenReceiving { contact_id } if contact_id == "bob"
            )),
            "a first message with no session must ask for bob's bundle"
        );

        // `remove_session` drops the ratchet only. The queued carrier survives it — which is the
        // whole defect: a re-add is still steered by the forgotten contact's backlog.
        core.remove_session("bob".to_string());
        assert_eq!(
            pending_for(&core, "bob"),
            1,
            "remove_session must NOT be mistaken for a local delete — it leaves the queue"
        );

        // The deletion boundary clears it.
        core.forget_contact_state("bob".to_string());
        assert_eq!(
            pending_for(&core, "bob"),
            0,
            "forget_contact_state must clear what remove_session leaves behind"
        );
    }

    /// The core's Kyber prekeys survive the platform's persistence path: generate (after the
    /// hybrid key exists and the private keys were saved), export both blobs, restore into a new
    /// core, and the restored core decapsulates what was encapsulated to the uploaded keys and
    /// re-signs the current SPK with the same hybrid key.
    #[test]
    fn kyber_prekeys_survive_export_and_restore() {
        let core = make_orchestrator("kyber_owner");
        assert!(
            core.generate_kyber_one_time_prekeys(1).is_err(),
            "no hybrid identity key yet: generation is refused, not silently keyed"
        );
        let hybrid_public = core.ensure_hybrid_signature_key().unwrap();
        let private_keys = core.export_private_keys().unwrap();

        let otpks = core.generate_kyber_one_time_prekeys(2).unwrap();
        let spk = core.begin_kyber_spk_rotation().unwrap();
        assert!(core.commit_kyber_spk_rotation());
        assert_eq!(core.kyber_one_time_prekey_count(), 2);
        let kyber_blob = core.export_kyber_prekeys().unwrap();

        let restored =
            create_orchestrator_core_from_keys(private_keys, "kyber_owner".into()).unwrap();
        restored.import_kyber_prekeys(kyber_blob).unwrap();
        assert_eq!(restored.kyber_one_time_prekey_count(), 2);

        for (id, public) in [
            (otpks[0].key_id, &otpks[0].public_key),
            (otpks[1].key_id, &otpks[1].public_key),
            (0, &spk.public_key),
        ] {
            let enc = crate::crypto::pq_x3dh::mlkem1024_encapsulate(public).unwrap();
            let ss = restored
                .kyber_prekey_decapsulate(id, enc.ciphertext.clone())
                .unwrap();
            assert_eq!(ss, enc.shared_secret.expose(), "key {id}");
        }

        let again = restored.current_kyber_spk_upload().unwrap().unwrap();
        assert_eq!(again.public_key, spk.public_key);
        assert_eq!(again.created_at, spk.created_at);
        assert_eq!(
            crate::crypto::kyber_prekey_auth::check_kyber_prekey_hybrid_signature(
                &hybrid_public,
                &again.public_key,
                again.created_at,
                Some(&again.hybrid_signature)
            ),
            crate::crypto::kyber_prekey_auth::KyberPrekeySignature::Valid,
            "re-signed with the persisted hybrid key"
        );

        assert_eq!(
            restored.prune_kyber_one_time_prekeys_below(otpks[1].key_id),
            1
        );
        assert!(
            restored
                .kyber_prekey_decapsulate(otpks[0].key_id, vec![0; 1568])
                .is_err(),
            "a pruned key is gone"
        );
    }

    /// Strict `init_session` must REJECT a bundle whose SPK is past the 10-day staleness limit.
    /// This is the gate that makes a long-offline peer unreachable — guarded so the degraded
    /// path (below) remains the only way through. See the stale-peer-reachability decision.
    #[test]
    fn test_init_session_rejects_stale_spk() {
        let alice = make_orchestrator("alice_user");
        let bob = make_orchestrator("bob_user");

        let mut bob_bundle = pq_bundle(&bob);
        bob_bundle.spk_uploaded_at = unix_secs_days_ago(31); // > 30d limit

        let err = alice
            .init_session("bob_user".to_string(), bob_bundle)
            .expect_err("init_session must reject a stale SPK bundle");
        assert!(
            matches!(err, CryptoError::PeerSpkStale { .. }),
            "expected PeerSpkStale, got {err:?}"
        );
    }

    /// Degraded `init_session_allowing_stale` must ACCEPT the same stale bundle the strict path
    /// rejects — this is the reachability fix for long-offline peers.
    #[test]
    fn test_init_session_allowing_stale_accepts_stale_spk() {
        let alice = make_orchestrator("alice_user");
        // The initiator's KEM identity key derives from its hybrid key.
        alice.ensure_hybrid_signature_key().unwrap();
        let bob = make_orchestrator("bob_user");

        let mut bob_bundle = pq_bundle(&bob);
        bob_bundle.spk_uploaded_at = unix_secs_days_ago(60); // well past the 30d limit

        let session_id = alice
            .init_session_allowing_stale("bob_user".to_string(), bob_bundle)
            .expect("degraded init must accept a stale SPK bundle");
        assert_eq!(session_id, "bob_user");
    }

    /// Degraded init relaxes ONLY the age check. A PQ bundle (suite_id == 2) that never uploaded a
    /// Kyber SPK (kyber_spk_rotation_epoch == 0) is a correctness failure, not a freshness one, and
    /// must still be refused so we never silently downgrade to classical-only key agreement.
    #[test]
    fn test_init_session_allowing_stale_still_rejects_pq_without_kyber_epoch() {
        let alice = make_orchestrator("alice_user");
        let bob = make_orchestrator("bob_user");

        let mut bob_bundle = pq_bundle(&bob);
        bob_bundle.spk_uploaded_at = unix_secs_days_ago(31);
        bob_bundle.suite_id = 2; // PQ_HYBRID
        bob_bundle.kyber_spk_rotation_epoch = 0; // never uploaded a Kyber SPK

        let err = alice
            .init_session_allowing_stale("bob_user".to_string(), bob_bundle)
            .expect_err("degraded init must still reject a PQ bundle with no Kyber SPK");
        assert!(
            matches!(err, CryptoError::InvalidKeyData),
            "expected InvalidKeyData, got {err:?}"
        );
    }

    /// A session established via the degraded path must be fully functional when the peer still
    /// holds the matching SPK private key: Alice degraded-inits against Bob's (faked-stale) bundle,
    /// encrypts, and Bob opens from the wire payload with Alice's sender certificate. (The lost-SPK
    /// case is exercised by the iOS healing integration tests.)
    #[test]
    fn test_degraded_session_encrypts_and_decrypts() {
        let (alice, _) = named_core();
        let (bob, bob_id) = named_core();
        let server = crate::crypto::sealed_sender::test_support::TestServer::new();

        let mut bob_bundle = pq_bundle(&bob);
        bob_bundle.spk_uploaded_at = unix_secs_days_ago(35); // stale → only degraded init works

        let session = alice
            .init_session_allowing_stale(bob_id, bob_bundle)
            .expect("degraded init should succeed");

        let plaintext = b"reachable while offline".to_vec();
        let wire = alice.encrypt_to_wire(session, plaintext.clone()).unwrap();

        let bob_result = bob
            .init_receiving_session_from_wire_payload(certified(&server, &alice, &bob), wire)
            .expect("Bob should establish receiving session from a degraded-init first message");

        assert_eq!(
            bob_result.decrypted_message, plaintext,
            "degraded-init first message must decrypt when the peer still holds its SPK key"
        );
    }

    /// A DEVICE-SHAPED bundle through the exported API, end to end: classic crypto suite (1), a
    /// real X25519 one-time prekey, the Kyber SPK and a Kyber one-time prekey from the core, fresh
    /// timestamps. PQXDH v2 opens a suite-3 session on the one-time Kyber key; the first message's
    /// components carry the handshake; the responder opens the session from them, burns the key
    /// and hands back the prekeys to persist.
    #[cfg(feature = "post-quantum")]
    /// `reopen_session` is the answer to `OpenSession` with or without a session held, and a
    /// refused reopen leaves the held session in place (the upgrade sweep meeting an old build).
    #[test]
    fn test_reopen_session_replaces_only_once_the_new_one_exists() {
        let alice = make_orchestrator("alice_user_id");
        // The initiator's KEM identity key derives from its hybrid key.
        alice.ensure_hybrid_signature_key().unwrap();
        let bob = make_orchestrator("bob_user_id");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut bundle = pq_bundle(&bob);
        bundle.suite_id = 1;
        bundle.spk_uploaded_at = now;
        bundle.spk_rotation_epoch = 4;
        bundle.kyber_spk_uploaded_at = now;
        bundle.kyber_spk_rotation_epoch = 5;
        let bob_id = || "bob_user_id".to_string();
        let kyber_prekey_in_use = || {
            wire_payload_unpack(alice.encrypt_to_wire(bob_id(), b"x".to_vec()).unwrap())
                .unwrap()
                .kyber_otpk_id
        };

        // Nothing held: an ordinary open.
        alice.reopen_session(bob_id(), bundle.clone()).unwrap();
        let spk_id = kyber_prekey_in_use();

        // A bundle without the hybrid identity key, as an old build serves it: refused, kept.
        let mut old_build = bundle.clone();
        old_build.hybrid_identity_key = None;
        old_build.hybrid_identity_signature = None;
        let err = alice.reopen_session(bob_id(), old_build).unwrap_err();
        assert!(
            matches!(&err, CryptoError::SessionInitializationFailed { message }
                if message.starts_with("PQ_REQUIRED")),
            "{err:?}"
        );
        assert!(alice.has_session(bob_id()));
        assert_eq!(kyber_prekey_in_use(), spk_id);

        // A bundle that yields a v2 session replaces the held one.
        let otpk = bob
            .generate_kyber_one_time_prekeys(1)
            .unwrap()
            .pop()
            .unwrap();
        bundle.kyber_one_time_prekey_id = Some(otpk.key_id);
        bundle.kyber_one_time_prekey_public = Some(otpk.public_key);
        bundle.kyber_one_time_prekey_created_at = Some(otpk.created_at);
        bundle.kyber_one_time_prekey_signature = Some(otpk.signature);
        bundle.kyber_one_time_prekey_hybrid_signature = Some(otpk.hybrid_signature);
        alice.reopen_session(bob_id(), bundle).unwrap();
        assert_eq!(kyber_prekey_in_use(), otpk.key_id);
    }

    #[test]
    fn test_pqxdh_v2_through_the_exported_api() {
        use crate::crypto::SuiteID;

        let (alice, alice_id) = named_core();
        let (bob, bob_id) = named_core();
        let server = crate::crypto::sealed_sender::test_support::TestServer::new();

        let bob_otpk = bob.generate_one_time_prekeys(1).unwrap().pop().unwrap();
        let mut bob_bundle = pq_bundle(&bob);
        let kyber_otpk = bob
            .generate_kyber_one_time_prekeys(1)
            .unwrap()
            .pop()
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        bob_bundle.suite_id = 1; // server bundles advertise the CLASSIC crypto suite
        bob_bundle.one_time_prekey_public = Some(bob_otpk.public_key);
        bob_bundle.one_time_prekey_id = Some(bob_otpk.key_id);
        bob_bundle.kyber_one_time_prekey_public = Some(kyber_otpk.public_key);
        bob_bundle.kyber_one_time_prekey_id = Some(kyber_otpk.key_id);
        bob_bundle.kyber_one_time_prekey_created_at = Some(kyber_otpk.created_at);
        bob_bundle.kyber_one_time_prekey_signature = Some(kyber_otpk.signature);
        bob_bundle.kyber_one_time_prekey_hybrid_signature = Some(kyber_otpk.hybrid_signature);
        bob_bundle.spk_uploaded_at = now;
        bob_bundle.spk_rotation_epoch = 4;
        bob_bundle.kyber_spk_uploaded_at = now;
        bob_bundle.kyber_spk_rotation_epoch = 5;

        alice
            .init_session(bob_id.clone(), bob_bundle)
            .expect("device-shaped init_session should succeed");
        assert_eq!(
            alice.get_session_suite_id(bob_id.clone()),
            SuiteID::PQ_RATCHET.as_u16(),
            "suite 3 is mandatory"
        );

        let wire = alice
            .encrypt_to_wire(bob_id.clone(), b"hello".to_vec())
            .unwrap();
        let header = wire_payload_unpack(wire.clone()).unwrap();
        assert_eq!(header.kyber_otpk_id, kyber_otpk.key_id);
        assert_eq!(header.kem_ciphertext.map(|c| c.len()), Some(1568));
        assert_eq!(header.one_time_prekey_id, bob_otpk.key_id);
        assert_eq!(
            header.kem_identity.map(|k| k.len()),
            Some(1568),
            "the first flight names the initiator's KEM identity key"
        );

        let result = bob
            .init_receiving_session_from_wire_payload(certified(&server, &alice, &bob), wire)
            .unwrap();
        assert_eq!(
            result.session_id, alice_id,
            "filed under the certified device"
        );
        assert_eq!(result.decrypted_message, b"hello");
        assert!(
            result.kyber_prekeys.is_some(),
            "the one-time Kyber key was burned: the platform gets the blob to persist"
        );
        assert_eq!(bob.kyber_one_time_prekey_count(), 0);

        let health = alice.get_session_health(bob_id).unwrap();
        assert_eq!(health.pq_handshake, PqHandshake::InitialV2);
        assert_eq!(health.pq_authentication, PqAuthentication::Authenticated);
        let health = bob.get_session_health(alice_id).unwrap();
        assert_eq!(health.pq_handshake, PqHandshake::InitialV2);

        // Not a payload at all: refused, and no session is left behind.
        let (carol, _) = named_core();
        let err = carol
            .init_receiving_session_from_wire_payload(
                certified(&server, &alice, &carol),
                vec![0u8; 8],
            )
            .unwrap_err();
        assert!(
            matches!(&err, CryptoError::SessionInitializationFailed { message }
                if message.starts_with("wire_payload unpack failed")),
            "{err:?}"
        );
    }

    /// Before the platform has set the server keys, a certificate cannot be checked, and nothing
    /// opens from it — whatever it names.
    #[test]
    fn test_responder_refuses_before_the_server_keys_are_set() {
        let (alice, _) = named_core();
        let (bob, bob_id) = named_core();
        let server = crate::crypto::sealed_sender::test_support::TestServer::new();
        alice.init_session(bob_id.clone(), pq_bundle(&bob)).unwrap();
        let wire = alice.encrypt_to_wire(bob_id, b"hi".to_vec()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cert = server.certify(
            &alice
                .get_registration_bundle_fields()
                .unwrap()
                .identity_public,
            now,
        );
        let err = bob
            .init_receiving_session_from_wire_payload(cert, wire)
            .unwrap_err();
        assert!(
            matches!(&err, CryptoError::SessionInitializationFailed { message }
                if message == "SENDER_CERTIFICATE_REFUSED: NoTrustedKey"),
            "{err:?}"
        );
    }

    /// GUARD (task #12): a session that negotiates `SuiteID::PQ_RATCHET` (3) must round-trip its
    /// FIRST message through the uniffi wire API the apps use — `encrypt_to_wire`, opened from the
    /// payload. The responder rebuilds the exact
    /// AEAD associated data from the suite and the suite-3 tags on the wire; before task #12 it
    /// defaulted the suite to the bundle's crypto suite and failed with
    /// `"All 1 prekey(s) failed. AEAD decryption failed"`. The pure-core
    /// `test_client_negotiates_pq_ratchet_from_bundle_capability` cannot catch this: it hands the
    /// full struct straight across, bypassing this boundary (which is why the bug shipped).
    #[cfg(feature = "post-quantum")]
    #[test]
    fn test_pq_ratchet_first_message_survives_uniffi_wire() {
        use crate::crypto::SuiteID;

        let (alice, _) = named_core();
        let (bob, bob_id) = named_core();
        let server = crate::crypto::sealed_sender::test_support::TestServer::new();

        let session = alice
            .init_session(bob_id.clone(), pq_bundle(&bob))
            .expect("init_session should succeed");

        // Precondition: the sending session must really be suite 3, else this test proves nothing.
        assert_eq!(
            alice.get_session_suite_id(bob_id),
            SuiteID::PQ_RATCHET.as_u16(),
            "setup must negotiate suite 3 (PQ_RATCHET_ENABLED is on in test builds)"
        );

        let plaintext = b"pq ratchet over the wire".to_vec();
        let wire = alice.encrypt_to_wire(session, plaintext.clone()).unwrap();

        let bob_result = bob
            .init_receiving_session_from_wire_payload(certified(&server, &alice, &bob), wire)
            .expect("Bob must establish a receiving session from a suite-3 first message");

        assert_eq!(bob_result.decrypted_message, plaintext);
    }

    /// Variant-2 guard: every field must survive the core's packer → `wire_payload_unpack`, the
    /// one reader the platforms call, instead of each SDK re-implementing the byte layout (the
    /// original wire-drop). If the reader ever loses a field, this fails.
    #[cfg(feature = "post-quantum")]
    #[test]
    fn test_wire_payload_pack_roundtrip_suite3() {
        use crate::crypto::messaging::double_ratchet::PqRatchetWireField;

        let field = PqRatchetWireField::PublicKey {
            epoch: 9,
            key: vec![0x5A; 1184],
        };
        let original = WirePayload {
            dh_public_key: vec![0x11; 32],
            message_number: 7,
            one_time_prekey_id: 42,
            kyber_otpk_id: 3,
            previous_chain_length: 5,
            suite_id: 3,
            kem_ciphertext: Some(vec![0x22; 1088]),
            sealed_box: vec![0x33; 60],
            pq_message_epoch: 9,
            pq_ratchet_field: pq_field_to_bytes(&Some(field.clone())),
            pqxdh_v2: true,
            kem_identity: Some(vec![0x44; 1568]),
            identity_proof_ciphertext: Some(vec![0x55; 1568]),
        };

        let bytes = crate::wire_payload::pack(
            &original.dh_public_key,
            original.message_number,
            original.one_time_prekey_id,
            original.kyber_otpk_id,
            original.previous_chain_length,
            original.suite_id,
            original.kem_ciphertext.as_deref(),
            original.kem_identity.as_deref(),
            original.identity_proof_ciphertext.as_deref(),
            &original.sealed_box,
            original.pq_message_epoch,
            Some(field.clone()),
        )
        .expect("pack must succeed");
        let decoded = wire_payload_unpack(bytes).expect("unpack must succeed");
        assert_eq!(decoded.kem_identity, original.kem_identity);
        assert_eq!(
            decoded.identity_proof_ciphertext,
            original.identity_proof_ciphertext
        );
        assert!(decoded.pqxdh_v2);

        assert_eq!(decoded.suite_id, 3, "suite_id must survive the wire");
        assert_eq!(
            decoded.pq_message_epoch, 9,
            "pq_message_epoch must survive the wire"
        );
        assert_eq!(decoded.dh_public_key, original.dh_public_key);
        assert_eq!(decoded.message_number, 7);
        assert_eq!(decoded.one_time_prekey_id, 42);
        assert_eq!(decoded.kyber_otpk_id, 3);
        assert_eq!(decoded.previous_chain_length, 5);
        assert_eq!(decoded.kem_ciphertext, original.kem_ciphertext);
        assert_eq!(decoded.sealed_box, original.sealed_box);
        // The opaque field bytes must round-trip back to the same enum.
        assert_eq!(
            pq_field_from_bytes(&decoded.pq_ratchet_field),
            Some(field),
            "pq_ratchet_field must survive the wire intact"
        );
    }

    /// Test that encryption fails with proper error when session doesn't exist
    #[test]
    fn test_encrypt_without_session_fails() {
        let alice = make_orchestrator("alice_user_id");

        let result =
            alice.encrypt_to_wire("nonexistent_user".to_string(), b"test message".to_vec());

        assert!(
            result.is_err(),
            "Encryption should fail when session doesn't exist"
        );
        match result {
            Err(CryptoError::EncryptionFailed { .. }) => {} // Expected
            _ => panic!("Should return EncryptionFailed error"),
        }
    }

    /// Simple test using Client API directly (bypassing UniFFI)
    #[test]
    fn test_direct_client_api_e2e() {
        use crate::crypto::client_api::Client;
        use crate::crypto::handshake::x3dh::X3DHProtocol;
        use crate::crypto::messaging::double_ratchet::DoubleRatchetSession;
        use crate::crypto::suites::classic::ClassicSuiteProvider;

        type TestClient = Client<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >;

        // Create Alice and Bob
        let mut alice = TestClient::new().unwrap();
        let mut bob = TestClient::new().unwrap();
        alice.set_local_user_id("alice".to_string());
        bob.set_local_user_id("bob".to_string());

        eprintln!("\n[DIRECT TEST] Creating clients...");

        // Get bundles
        let alice_bundle = alice.key_manager().export_registration_bundle().unwrap();
        let bob_bundle = bob.key_manager().export_registration_bundle().unwrap();

        eprintln!(
            "[DIRECT TEST] Alice identity: {}",
            hex::encode(&alice_bundle.identity_public)
        );
        eprintln!(
            "[DIRECT TEST] Bob identity: {}",
            hex::encode(&bob_bundle.identity_public)
        );

        // Alice creates session with Bob
        let alice_identity_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(alice_bundle.identity_public.clone());
        let bob_identity_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(bob_bundle.identity_public.clone());

        alice
            .init_session("bob", &bob_bundle, &bob_identity_pub, 0)
            .unwrap();
        eprintln!("[DIRECT TEST] Alice created session with Bob");

        // Alice encrypts message
        let plaintext1 = b"Hello Bob!";
        let encrypted1 = alice.encrypt_message("bob", plaintext1).unwrap();
        eprintln!(
            "[DIRECT TEST] Alice encrypted message, dh_key: {}",
            hex::encode(encrypted1.dh_public_key)
        );

        // Bob creates receiving session
        let alice_ephemeral_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(encrypted1.dh_public_key.to_vec());

        let (_session_id, decrypted1) = bob
            .init_receiving_session_with_ephemeral(
                "alice",
                &alice_identity_pub,
                &alice_ephemeral_pub,
                &encrypted1,
                0,
                None,
            )
            .unwrap();

        eprintln!("[DIRECT TEST] Bob received and decrypted!");
        assert_eq!(decrypted1, plaintext1);
        eprintln!("[DIRECT TEST] ✅ Direct Client API test PASSED!");
    }

    #[test]
    fn free_key_functions_match_both_cores() {
        let keys = generate_private_keys().unwrap();
        let classic = create_crypto_core_from_keys(keys.clone()).unwrap();
        let orch = create_orchestrator_core_from_keys(keys.clone(), "alice".to_string()).unwrap();

        let fields = registration_bundle_fields_from_keys(keys.clone()).unwrap();
        for (name, other) in [
            ("classic", classic.get_registration_bundle_fields().unwrap()),
            (
                "orchestrator",
                orch.get_registration_bundle_fields().unwrap(),
            ),
        ] {
            assert_eq!(fields.identity_public, other.identity_public, "{name}");
            assert_eq!(
                fields.signed_prekey_public, other.signed_prekey_public,
                "{name}"
            );
            assert_eq!(fields.signature, other.signature, "{name}");
            assert_eq!(fields.verifying_key, other.verifying_key, "{name}");
            assert_eq!(fields.suite_id, other.suite_id, "{name}");
        }

        // No secret comes out of a record any more (`signing_key_from_keys` and
        // `identity_key_from_keys` went 2026-09-29): the same signature below shows the three
        // hold one signing key, and the same bundle above one identity key.
        // Ed25519 is deterministic: the same key over the same bytes is the same signature.
        let data = b"{\"bundle\":1}".to_vec();
        let sig = sign_bundle_data_with_keys(keys.clone(), data.clone()).unwrap();
        assert_eq!(sig, classic.sign_bundle_data(data.clone()).unwrap());
        assert_eq!(sig, orch.sign_bundle_data(data.clone()).unwrap());
        let vk = ClassicSuiteProvider::signature_public_key_from_bytes(fields.verifying_key);
        ClassicSuiteProvider::verify(&vk, &data, &sig).expect("verifies under the bundle's key");

        // The record a core exports is the record the functions were given.
        assert_eq!(orch.export_private_keys().unwrap(), keys);
    }

    #[test]
    fn generate_private_keys_makes_new_keys_and_bad_records_are_rejected() {
        let a = registration_bundle_fields_from_keys(generate_private_keys().unwrap()).unwrap();
        let b = registration_bundle_fields_from_keys(generate_private_keys().unwrap()).unwrap();
        assert_ne!(a.identity_public, b.identity_public);

        for bad in [vec![], vec![0u8; 40], b"not a key record".to_vec()] {
            assert!(registration_bundle_fields_from_keys(bad.clone()).is_err());
            assert!(sign_bundle_data_with_keys(bad, b"x".to_vec()).is_err());
        }
    }

    /// Every constructor that restores from the private-key record keeps the pre-rotation
    /// signed prekeys. `create_orchestrator_core_from_keys` and `create_crypto_core_from_keys`
    /// passed an empty history, so a responder restarted after a rotation could not open a
    /// session an initiator had started from a cached bundle.
    ///
    /// Mutation: pass `vec![]` for `old_spks` in `from_private_keys_cfe` — this reddens.
    #[test]
    fn restoring_from_the_key_record_keeps_old_spks() {
        let mut client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        client.rotate_prekey().unwrap();
        let record = client.to_private_keys_cfe().unwrap();
        assert!(
            !record.old_spks.is_empty(),
            "the premise: a rotation leaves history"
        );
        let blob = crate::cfe::encode(crate::cfe::CfeMessageType::PrivateKeys, &record).unwrap();

        let decode = |bytes: Vec<u8>| {
            crate::cfe::decode_as::<crate::cfe::CfePrivateKeysV1>(
                &bytes,
                crate::cfe::CfeMessageType::PrivateKeys,
            )
            .unwrap()
        };

        let orch = create_orchestrator_core_from_keys(blob.clone(), "alice".to_string()).unwrap();
        assert_eq!(
            decode(orch.export_private_keys().unwrap()),
            record,
            "create_orchestrator_core_from_keys"
        );

        let core = create_crypto_core_from_keys(blob.clone()).unwrap();
        assert_eq!(
            decode(core.export_private_keys().unwrap()),
            record,
            "create_crypto_core_from_keys"
        );

        let fresh = create_crypto_core().unwrap();
        fresh.import_private_keys(blob).unwrap();
        assert_eq!(
            decode(fresh.export_private_keys().unwrap()),
            record,
            "import_private_keys"
        );
    }
}

// ============================================================================
// Device-Based Authentication (PoW + Device ID)
// ============================================================================

/// Compute Argon2id-based Proof of Work
/// UniFFI wrapper - accepts owned String instead of &str
pub fn compute_pow(challenge: String, difficulty: u32) -> PowSolution {
    crate::pow::compute_pow(&challenge, difficulty)
}

/// Compute PoW with progress callback
/// UniFFI wrapper - accepts owned String instead of &str
pub fn compute_pow_with_progress(
    challenge: String,
    difficulty: u32,
    progress_callback: Option<Box<dyn PowProgressCallback>>,
) -> PowSolution {
    crate::pow::compute_pow_with_progress(&challenge, difficulty, progress_callback)
}

/// Verify PoW solution (server-side)  
/// UniFFI wrapper - accepts owned String and PowSolution
pub fn verify_pow(challenge: String, solution: PowSolution, required_difficulty: u32) -> bool {
    crate::pow::verify_pow(&challenge, &solution, required_difficulty)
}

/// Derive device ID from identity public key
/// UniFFI wrapper - accepts owned Vec<u8> instead of &[u8]
pub fn derive_device_id(identity_public_key: Vec<u8>) -> String {
    crate::device_id::derive_device_id(&identity_public_key)
}

// ── Intake credentials ────────────────────────────────────────────────────────
// What a sealed envelope carries instead of a Privacy Pass token when the recipient has
// vouched for the sender. See `crate::intake` and
// construct-docs/decisions/contact-traffic-is-vouched-not-purchased.md.

/// A fresh 32-byte `intake_key` for this account.
///
/// One per account. Every device of the account must end up holding *this* key rather than
/// generating its own, or half the account's contacts would present a credential the server does
/// not recognise.
pub fn generate_intake_key() -> Vec<u8> {
    crate::intake::generate_intake_key()
}

/// The intake epoch containing `unix_seconds` (one UTC day per epoch).
///
/// Exported rather than left as `t / 86400` on each platform because the epoch is half of what the
/// tag is bound to: a client computing yesterday's epoch attaches a tag the server will not match,
/// and the only symptom is a token charged where none was owed.
pub fn intake_epoch(unix_seconds: u64) -> u64 {
    crate::intake::intake_epoch(unix_seconds)
}

/// The intake tag for one recipient account and one epoch.
///
/// The recipient calls this with its own account id to publish the tag; a sender calls it with the
/// recipient's account id to attach one. Same function both ways — that symmetry is what makes the
/// credential per-recipient rather than per-pair.
///
/// Throws `InvalidKeyData` when `intake_key` is not 32 bytes or the account id is empty. Both are
/// conditions HMAC itself would accept silently, producing a tag that simply never matches.
pub fn intake_tag(
    intake_key: Vec<u8>,
    recipient_account_id: String,
    epoch: u64,
) -> Result<Vec<u8>, CryptoError> {
    crate::intake::intake_tag(&intake_key, &recipient_account_id, epoch)
        .map_err(|_| CryptoError::InvalidKeyData)
}

/// Unpack a received `encrypted_payload` blob into its components.
/// Forwards to [`wire_payload::unpack`]. For reading routing fields only: decrypting takes the
/// whole payload (`OrchestratorCore::decrypt_wire_payload`).
pub fn wire_payload_unpack(data: Vec<u8>) -> Result<WirePayload, CryptoError> {
    let decoded =
        crate::wire_payload::unpack(&data).map_err(|e| CryptoError::SerializationFailed {
            message: format!("wire_payload_unpack: {e}"),
        })?;
    Ok(WirePayload {
        dh_public_key: decoded.dh_public_key,
        message_number: decoded.message_number,
        one_time_prekey_id: decoded.one_time_prekey_id,
        kyber_otpk_id: decoded.kyber_otpk_id,
        previous_chain_length: decoded.previous_chain_length,
        suite_id: decoded.suite_id,
        kem_ciphertext: decoded.kem_ciphertext,
        sealed_box: decoded.sealed_box,
        pq_message_epoch: decoded.pq_message_epoch,
        pq_ratchet_field: pq_field_to_bytes(&decoded.pq_ratchet_field),
        pqxdh_v2: decoded.pqxdh_v2,
        kem_identity: decoded.kem_identity,
        identity_proof_ciphertext: decoded.identity_proof_ciphertext,
    })
}

/// See the UDL `wire_summary`.
#[derive(Debug, Clone, PartialEq)]
pub struct WireSummary {
    pub message_number: u32,
    pub init_kind: ReceivingInitKind,
}

/// One parse of a received payload into what a platform routes on. The classification is the
/// same `receiving_init_kind` the carrier form asks; only the input is the payload itself.
pub fn wire_summary(wire_payload: Vec<u8>) -> Result<WireSummary, CryptoError> {
    let d = crate::wire_payload::unpack(&wire_payload).map_err(|e| {
        CryptoError::SerializationFailed {
            message: format!("wire_summary: {e}"),
        }
    })?;
    let carrier = crate::orchestration::ReceivingInitCarrier {
        message_number: d.message_number,
        one_time_prekey_id: d.one_time_prekey_id,
        kem_ciphertext_bytes: d.kem_ciphertext.as_ref().map_or(0, |k| k.len() as u32),
        pq_message_epoch: d.pq_message_epoch,
    };
    Ok(WireSummary {
        message_number: d.message_number,
        init_kind: crate::orchestration::receiving_init_kind(&carrier).into(),
    })
}

/// Format federated identifier
/// UniFFI wrapper - accepts owned Strings
pub fn format_federated_id(device_id: String, server_hostname: String) -> String {
    crate::device_id::format_federated_id(&device_id, &server_hostname)
}

/// Whether to open a session with a device now.
///
/// Delegates; the reasoning and the run it was written from are in
/// `orchestration::initiation_plan`.
pub fn plan_initiation(context: InitiationContext) -> InitiationDecision {
    crate::orchestration::plan_initiation(&context)
}

/// Compute a Safety Number for two Construct devices.
///
/// Returns a 60-digit string (12 groups of 5, space-separated) that both parties
/// can compare verbally or via QR to verify no MITM has occurred.
pub fn compute_safety_number(my_device_id: String, their_device_id: String) -> Option<String> {
    crate::crypto::recovery::compute_safety_number(&my_device_id, &their_device_id)
}

// ── Post-Quantum KEM Namespace Functions ─────────────────────────────────────

/// Encapsulate to an ML-KEM-1024 public key — history transfer to a peer's Kyber SPK. The
/// handshake never needs this: the core runs its own ML-KEM (PQXDH v2).
pub fn mlkem1024_encapsulate(public_key: Vec<u8>) -> Result<MLKEMEncapsulation, CryptoError> {
    crate::crypto::pq_x3dh::mlkem1024_encapsulate(&public_key)
        .map(|enc| MLKEMEncapsulation {
            ciphertext: enc.ciphertext,
            shared_secret: enc.shared_secret.into_vec(),
        })
        .map_err(|e| CryptoError::EncryptionFailed { message: e })
}

// ── Post-Quantum Signatures (ML-DSA-65 + Hybrid) ────────────────────────────

/// ML-DSA-65 keypair exposed across the FFI boundary.
#[derive(Clone)]
pub struct MLDSAKeyPair {
    /// Secret key: 32-byte signing seed (RustCrypto ml-dsa; expanded key re-derived on sign)
    pub secret_key: Vec<u8>,
    /// Public key: 1952 bytes
    pub public_key: Vec<u8>,
}

/// Hybrid (Ed25519 + ML-DSA-65) signature keypair.
#[derive(Clone)]
pub struct HybridSignatureKeyPair {
    /// Hybrid private key: 2016 bytes
    /// [ed25519_seed (32)] [mldsa65_seed (32)] [mldsa65_pk (1952)]
    pub private_key: Vec<u8>,
    /// Hybrid public key: 1984 bytes
    pub public_key: Vec<u8>,
}

/// Generate an ML-DSA-65 keypair (RustCrypto ml-dsa, seed-based).
#[cfg(feature = "post-quantum")]
pub fn mldsa65_keygen() -> Result<MLDSAKeyPair, CryptoError> {
    use ml_dsa::{B32, Keypair as _, MlDsa65, SigningKey as MlDsaSigningKey};
    use rand_core::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(seed));
    let pk_enc = sk.verifying_key().encode(); // 1952 bytes
    Ok(MLDSAKeyPair {
        // Store the 32-byte signing seed (the expanded 4032-byte key is re-derived
        // on demand at sign time). Matches the hybrid suite + construct-server.
        secret_key: seed.to_vec(),
        public_key: pk_enc.as_slice().to_vec(),
    })
}

#[cfg(not(feature = "post-quantum"))]
pub fn mldsa65_keygen() -> Result<MLDSAKeyPair, CryptoError> {
    Err(CryptoError::InitializationFailed)
}

/// Sign a message with an ML-DSA-65 signing seed (detached signature).
#[cfg(feature = "post-quantum")]
pub fn mldsa65_sign(secret_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    use ml_dsa::{B32, MlDsa65, Signer as _, SigningKey as MlDsaSigningKey};
    let seed: [u8; 32] = secret_key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(seed));
    let sig = sk
        .try_sign(&message)
        .map_err(|_| CryptoError::InvalidKeyData)?;
    Ok(sig.encode().as_slice().to_vec())
}

#[cfg(not(feature = "post-quantum"))]
pub fn mldsa65_sign(_secret_key: Vec<u8>, _message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::InitializationFailed)
}

/// Verify an ML-DSA-65 detached signature.
#[cfg(feature = "post-quantum")]
pub fn mldsa65_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, CryptoError> {
    use ml_dsa::{
        EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as MlDsaSignature, Verifier as _,
        VerifyingKey as MlDsaVerifyingKey,
    };
    let pk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_slice())
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let pk = MlDsaVerifyingKey::<MlDsa65>::decode(&pk_enc);
    let sig_enc = EncodedSignature::<MlDsa65>::try_from(signature.as_slice())
        .map_err(|_| CryptoError::InvalidKeyData)?;
    let Some(sig) = MlDsaSignature::<MlDsa65>::decode(&sig_enc) else {
        return Ok(false);
    };
    Ok(pk.verify(&message, &sig).is_ok())
}

#[cfg(not(feature = "post-quantum"))]
pub fn mldsa65_verify(
    _public_key: Vec<u8>,
    _message: Vec<u8>,
    _signature: Vec<u8>,
) -> Result<bool, CryptoError> {
    Err(CryptoError::InitializationFailed)
}

/// Generate a hybrid (Ed25519 + ML-DSA-65) signature keypair.
#[cfg(feature = "post-quantum")]
pub fn hybrid_signature_keygen() -> Result<HybridSignatureKeyPair, CryptoError> {
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::hybrid::HybridSuiteProvider;
    let (sk, pk) = HybridSuiteProvider::generate_signature_keys()
        .map_err(|_| CryptoError::InitializationFailed)?;
    Ok(HybridSignatureKeyPair {
        private_key: sk.into_vec(),
        public_key: pk,
    })
}

#[cfg(not(feature = "post-quantum"))]
pub fn hybrid_signature_keygen() -> Result<HybridSignatureKeyPair, CryptoError> {
    Err(CryptoError::InitializationFailed)
}

/// Sign a message with a hybrid private key (Ed25519 + ML-DSA-65).
#[cfg(feature = "post-quantum")]
pub fn hybrid_sign(private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::hybrid::HybridSuiteProvider;
    HybridSuiteProvider::sign(&crate::crypto::SecretBytes::new(private_key), &message).map_err(
        |e| CryptoError::EncryptionFailed {
            message: format!("Hybrid sign failed: {e}"),
        },
    )
}

#[cfg(not(feature = "post-quantum"))]
pub fn hybrid_sign(_private_key: Vec<u8>, _message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::InitializationFailed)
}

/// Verify a hybrid signature (both Ed25519 and ML-DSA-65 must be valid).
#[cfg(feature = "post-quantum")]
pub fn hybrid_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, CryptoError> {
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::hybrid::HybridSuiteProvider;
    match HybridSuiteProvider::verify(&public_key, &message, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(not(feature = "post-quantum"))]
pub fn hybrid_verify(
    _public_key: Vec<u8>,
    _message: Vec<u8>,
    _signature: Vec<u8>,
) -> Result<bool, CryptoError> {
    Err(CryptoError::InitializationFailed)
}

/// Derive the hybrid public key from a hybrid private key.
#[cfg(feature = "post-quantum")]
pub fn hybrid_public_key_from_private(private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::hybrid::HybridSuiteProvider;
    HybridSuiteProvider::from_signature_private_to_public(&crate::crypto::SecretBytes::new(
        private_key,
    ))
    .map_err(|_e| CryptoError::InvalidKeyData)
}

#[cfg(not(feature = "post-quantum"))]
pub fn hybrid_public_key_from_private(_private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::InitializationFailed)
}

// ── Orchestration — Phase 0: PlatformBridge ──────────────────────────────────

/// Verify that a `PlatformBridge` implementation correctly round-trips data
/// through its secure store (save → load → compare).
///
/// Called from Swift integration tests to confirm that `PlatformBridgeImpl`
/// (Keychain adapter) is wired up correctly before higher-level phases rely on it.
///
/// Returns `true` if the loaded bytes equal the saved bytes, `false` otherwise.
pub fn test_platform_bridge_roundtrip(
    bridge: Box<dyn PlatformBridge>,
    key: String,
    data: Vec<u8>,
) -> Result<bool, CryptoError> {
    bridge.save_to_secure_store(key.clone(), data.clone());
    let loaded = bridge.load_from_secure_store(key);
    Ok(loaded.as_deref() == Some(data.as_slice()))
}

// ── Orchestration — RustAckStore (Phase 1a) ───────────────────────────────────

pub struct RustAckStore {
    inner: std::sync::Mutex<crate::orchestration::AckStore>,
}

impl Default for RustAckStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RustAckStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(crate::orchestration::AckStore::default()),
        }
    }

    pub fn is_processed(&self, message_id: String) -> AckCheckResult {
        let store = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match store.is_processed(&message_id) {
            crate::orchestration::AckCheckResult::InCache => AckCheckResult::InCache,
            crate::orchestration::AckCheckResult::NeedDbCheck => AckCheckResult::NeedDbCheck,
            crate::orchestration::AckCheckResult::NotProcessed => AckCheckResult::NotProcessed,
        }
    }

    pub fn mark_processed(&self, message_id: String) {
        let mut store = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let _ = store.mark_processed(&message_id);
    }

    pub fn prune_expired(&self) {
        let store = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let _ = store.prune_expired();
    }

    pub fn cache_len(&self) -> u64 {
        let store = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        store.cache_len() as u64
    }
}

/// Mirror of the UDL `DeliveryAudience` enum (must match UDL name exactly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryAudience {
    Recipient,
    OwnReplica,
}

/// Mirror of the UDL `DeliveryTarget` dictionary.
#[derive(Debug, Clone)]
pub struct DeliveryTarget {
    pub device_id: String,
    pub audience: DeliveryAudience,
}

impl From<crate::orchestration::DeliveryAudience> for DeliveryAudience {
    fn from(a: crate::orchestration::DeliveryAudience) -> Self {
        match a {
            crate::orchestration::DeliveryAudience::Recipient => DeliveryAudience::Recipient,
            crate::orchestration::DeliveryAudience::OwnReplica => DeliveryAudience::OwnReplica,
        }
    }
}

/// Who gets a copy of an outgoing message — the one implementation every client asks.
pub fn plan_send(
    recipient_device_ids: Vec<String>,
    own_device_ids: Vec<String>,
    our_device_id: String,
    recipient_is_self: bool,
) -> Vec<DeliveryTarget> {
    crate::orchestration::plan_send(
        &recipient_device_ids,
        &own_device_ids,
        &our_device_id,
        recipient_is_self,
    )
    .into_iter()
    .map(|t| DeliveryTarget {
        device_id: t.device_id,
        audience: t.audience.into(),
    })
    .collect()
}

/// Which of a peer's device sessions an incoming message is tried against, in order.
///
/// See `orchestration::receiving_decrypt_plan` for why this is a core decision and not a client
/// one, and for why attempting a wrong session is safe.
pub fn plan_receiving_decrypt(
    session_device_ids: Vec<String>,
    preferred_device_id: String,
) -> Vec<String> {
    crate::orchestration::plan_receiving_decrypt(&session_device_ids, &preferred_device_id)
}

/// Mirror of the UDL `ReceivingInitKind` enum (must match UDL name exactly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceivingInitKind {
    Handshake,
    MidRatchet,
}

impl From<crate::orchestration::ReceivingInitKind> for ReceivingInitKind {
    fn from(k: crate::orchestration::ReceivingInitKind) -> Self {
        match k {
            crate::orchestration::ReceivingInitKind::Handshake => ReceivingInitKind::Handshake,
            crate::orchestration::ReceivingInitKind::MidRatchet => ReceivingInitKind::MidRatchet,
        }
    }
}

/// Classify a queued message — the one implementation every client asks.
pub fn receiving_init_kind(carrier: ReceivingInitCarrier) -> ReceivingInitKind {
    crate::orchestration::receiving_init_kind(&(&carrier).into()).into()
}

/// Mirror of the UDL `ReceivingInitCarrier` dictionary — the wire-visible shape of a queued
/// message, with no ciphertext: planning must not require holding the body.
#[derive(Debug, Clone)]
pub struct ReceivingInitCarrier {
    pub message_number: u32,
    pub one_time_prekey_id: u32,
    pub kem_ciphertext_bytes: u32,
    pub pq_message_epoch: u32,
}

impl From<&ReceivingInitCarrier> for crate::orchestration::ReceivingInitCarrier {
    fn from(c: &ReceivingInitCarrier) -> Self {
        crate::orchestration::ReceivingInitCarrier {
            message_number: c.message_number,
            one_time_prekey_id: c.one_time_prekey_id,
            kem_ciphertext_bytes: c.kem_ciphertext_bytes,
            pq_message_epoch: c.pq_message_epoch,
        }
    }
}

/// The UDL `InitiationDecision` / `InitiationContext` types, re-exported rather than mirrored.
///
/// The neighbours above define a second copy of an orchestration type and convert between them.
/// That is two carriers of one meaning, and this crate's own rule against it applies to its own
/// FFI layer: a mirror drifts by an added variant that nobody adds on the other side, and the UDL
/// only needs the names to resolve at the crate root — which a re-export does.
pub use crate::orchestration::initiation_plan::{InitiationContext, InitiationDecision};

/// Mirror of the UDL `AckCheckResult` enum (must match UDL name exactly).
pub enum AckCheckResult {
    InCache,
    NeedDbCheck,
    NotProcessed,
}

// `RustHealingQueue` and `HealingAttemptResult` stood here until 2026-09-23.
//
// The object was a **second** `HealingQueue`, constructed by the platform for itself, keyed by
// account and fed a JSON `ChatMessage` — beside the one inside `Orchestrator.lifecycle`, keyed by
// device and holding the wire payload. The platform's was the one that decided whether a heal
// could retry; this one's `attempts` was never incremented at all. Two records of one episode, in
// two identity spaces, with nothing holding them in step. Step 4 of
// `construct-docs/decisions/session-is-one-state-machine.md`.
//
// The orchestrator's own queue followed on 2026-09-27: nothing heals any more — a record keeps its
// previous states, and a message with the handshake header opens
// (`construct-docs/decisions/sessions-renew-by-sending.md`).

// ── Orchestration — OrchestratorCore (Phase 5) ───────────────────────────────

/// Convert a `BinaryKeyBundle` (received from Swift via UniFFI) into the internal
/// `X3DHPublicKeyBundle` used by the crypto layer. This is a zero-copy conversion
/// — all fields are moved from the dictionary struct into the internal type.
fn binary_bundle_to_x3dh(b: &BinaryKeyBundle) -> Result<X3DHPublicKeyBundle, CryptoError> {
    Ok(X3DHPublicKeyBundle {
        identity_public: b.identity_public.clone(),
        signed_prekey_public: b.signed_prekey_public.clone(),
        signature: b.signature.clone(),
        verifying_key: b.verifying_key.clone(),
        suite_id: SuiteID::new(b.suite_id).map_err(|_| CryptoError::InvalidKeyData)?,
        one_time_prekey_public: b.one_time_prekey_public.clone(),
        one_time_prekey_id: b.one_time_prekey_id,
        spk_uploaded_at: b.spk_uploaded_at,
        spk_rotation_epoch: b.spk_rotation_epoch,
        kyber_spk_uploaded_at: b.kyber_spk_uploaded_at,
        kyber_spk_rotation_epoch: b.kyber_spk_rotation_epoch,
    })
}

/// A bundle as the reopen takes it: fresh, and split into the X3DH half and the Kyber half.
/// Shared by `reopen_session` and `CfeIncomingEvent::SessionBundleFetched`, so both refuse the
/// same bundles.
fn parse_bundle_for_reopen(
    b: &BinaryKeyBundle,
) -> Result<crate::orchestration::orchestrator::SessionBundle, CryptoError> {
    check_bundle_freshness(b)?;
    Ok(crate::orchestration::orchestrator::SessionBundle {
        x3dh: binary_bundle_to_x3dh(b)?,
        kyber: kyber_keys_of(b),
    })
}

fn kyber_keys_of(b: &BinaryKeyBundle) -> crate::orchestration::orchestrator::KyberBundleKeys {
    crate::orchestration::orchestrator::KyberBundleKeys {
        pre_key_id: b.kyber_pre_key_id,
        pre_key_public: b.kyber_pre_key_public.clone(),
        pre_key_created_at: b.kyber_pre_key_created_at,
        pre_key_signature: b.kyber_pre_key_signature.clone(),
        pre_key_hybrid_signature: b.kyber_pre_key_hybrid_signature.clone(),
        one_time_prekey_id: b.kyber_one_time_prekey_id,
        one_time_prekey_public: b.kyber_one_time_prekey_public.clone(),
        one_time_prekey_created_at: b.kyber_one_time_prekey_created_at,
        one_time_prekey_signature: b.kyber_one_time_prekey_signature.clone(),
        one_time_prekey_hybrid_signature: b.kyber_one_time_prekey_hybrid_signature.clone(),
        hybrid_identity_key: b.hybrid_identity_key.clone(),
        hybrid_identity_signature: b.hybrid_identity_signature.clone(),
    }
}

/// Check SPK freshness from raw bundle JSON bytes.
///
/// Returns `Err(CryptoError::PeerSpkStale { age_secs })` if the SPK or Kyber SPK is stale
/// (older than `SPK_MAX_AGE_SECS`, 30 days). Returns `Ok(())` if fresh, absent (legacy server),
/// or unparseable. Must stay in lockstep with `crypto::client_api::SPK_MAX_AGE_SECS` (the inner
/// X3DH gate) — both relaxed from 10→30 days in Phase 4 of the stale-peer-reachability work.
fn check_bundle_freshness(bundle: &BinaryKeyBundle) -> Result<(), CryptoError> {
    const SPK_MAX_AGE_SECS: u64 = 30 * 24 * 3600;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if bundle.spk_uploaded_at > 0 {
        let age = now.saturating_sub(bundle.spk_uploaded_at);
        if age > SPK_MAX_AGE_SECS {
            return Err(CryptoError::PeerSpkStale { age_secs: age });
        }
    }

    if bundle.kyber_spk_uploaded_at > 0 {
        let age = now.saturating_sub(bundle.kyber_spk_uploaded_at);
        if age > SPK_MAX_AGE_SECS {
            return Err(CryptoError::PeerSpkStale { age_secs: age });
        }
    }

    // PQ_HYBRID bundles (suite_id == 2) require a non-zero Kyber SPK rotation epoch.
    // epoch == 0 means the Kyber SPK was never uploaded — refuse to use such a bundle
    // rather than silently falling back to classical-only key agreement.
    if bundle.suite_id == 2 && bundle.kyber_spk_rotation_epoch == 0 {
        return Err(CryptoError::InvalidKeyData);
    }

    Ok(())
}

pub struct OrchestratorCore {
    inner: std::sync::Mutex<crate::orchestration::Orchestrator>,
}

impl OrchestratorCore {
    pub fn handle_event(&self, event: CfeIncomingEvent) -> Result<Vec<CfeAction>, CryptoError> {
        let incoming = event.into_incoming_event();
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let actions = orch.handle_event(incoming);
        Ok(actions.into_iter().map(CfeAction::from_action).collect())
    }

    /// Suite ID for the active session with `contact_id`. Returns 0 if no session.
    pub fn get_session_suite_id(&self, contact_id: String) -> u16 {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.get_session_suite_id(&contact_id)
    }

    /// Return a read-only health report for the session with `contact_id`.
    ///
    /// Returns `None` if no session exists for that contact.
    /// Does **not** mutate any session state.
    pub fn get_session_health(&self, contact_id: String) -> Option<SessionHealthReport> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.get_session_health(&contact_id)
            .map(|snap| SessionHealthReport {
                messages_sent: snap.messages_sent,
                messages_received: snap.messages_received,
                skipped_keys_count: snap.skipped_keys_count as u32,
                is_pq_strengthened: snap.is_pq_strengthened,
                last_ratchet_at: snap.last_ratchet_at,
                session_id: snap.session_id,
                pq_authentication: snap.pq_authentication,
                pq_handshake: snap.pq_handshake,
            })
    }

    /// Typed registration bundle fields — raw bytes across the FFI boundary.
    pub fn get_registration_bundle_fields(&self) -> Result<RegistrationBundleFields, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let bundle = orch
            .get_registration_bundle_fields()
            .map_err(|_| CryptoError::InitializationFailed)?;
        Ok(RegistrationBundleFields::from(bundle))
    }

    pub fn ack_is_processed(&self, message_id: String) -> AckCheckResult {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match orch.ack_is_processed(&message_id) {
            crate::orchestration::AckCheckResult::InCache => AckCheckResult::InCache,
            crate::orchestration::AckCheckResult::NeedDbCheck => AckCheckResult::NeedDbCheck,
            crate::orchestration::AckCheckResult::NotProcessed => AckCheckResult::NotProcessed,
        }
    }

    pub fn ack_mark_processed(&self, message_id: String) {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let _ = orch.ack_mark_processed(&message_id);
    }

    // ── Session crypto delegates ──────────────────────────────────────────────

    pub fn export_private_keys(&self) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.export_private_keys_cfe()
            .map_err(|e| serialization_failed("orchestrator export_private_keys", e))
    }

    pub fn sign_bundle_data(&self, bundle_data_json: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.sign_bundle_bytes(&bundle_data_json)
            .map_err(|_| CryptoError::InitializationFailed)
    }

    // ── Hybrid PQ identity signature (owned by core) ──────────────────────────
    /// Ensure (generate if needed) the hybrid sig key. Returns the 1984 B public key.
    pub fn ensure_hybrid_signature_key(&self) -> Result<Vec<u8>, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.ensure_hybrid_signature_key()
            .map_err(|_| CryptoError::InitializationFailed)
    }

    /// Current hybrid public (if ensured), 1984 B.
    pub fn hybrid_signature_public_key(&self) -> Option<Vec<u8>> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.hybrid_signature_public_key()
    }

    /// Sign with the hybrid identity key (must have been ensured). 3373 B sig.
    pub fn sign_hybrid(&self, message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.sign_hybrid(&message)
            .map_err(|_| CryptoError::InitializationFailed)
    }

    // ── Operations with this device's own keys (the secrets stay here) ────────

    pub fn sign_with_device_key(&self, message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.sign_with_device_key(&message)
            .map_err(|_| CryptoError::InitializationFailed)
    }

    pub fn open_sealed_to_device(&self, sealed_box: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.open_sealed_to_device(&sealed_box)
            .map_err(|message| CryptoError::DecryptionFailed { message })
    }

    pub fn device_copy_tag(
        &self,
        base_message_id: String,
        target_device_id: String,
        peer_identity_public: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // InvalidKeyData, as the free function: the only failure is key material of the wrong size.
        orch.device_copy_tag(&base_message_id, &target_device_id, &peer_identity_public)
            .map_err(|_| CryptoError::InvalidKeyData)
    }

    pub fn device_copy_tag_matches(
        &self,
        tag: String,
        base_message_id: String,
        peer_identity_public: Vec<u8>,
    ) -> bool {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.device_copy_tag_matches(&tag, &base_message_id, &peer_identity_public)
    }

    pub fn history_file_channel_key(
        &self,
        sender_eph_pub: Vec<u8>,
        kem_key_id: u32,
        kem_ciphertext: Vec<u8>,
        snapshot_id: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.history_file_channel_key(&sender_eph_pub, kem_key_id, &kem_ciphertext, &snapshot_id)
            .map_err(|message| CryptoError::DecryptionFailed { message })
    }

    pub fn seal_own_recovery_bundle(
        &self,
        vault_key: Vec<u8>,
        created_at: i64,
    ) -> Result<Vec<u8>, CryptoError> {
        let key: [u8; 32] = vault_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyData)?;
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.seal_own_recovery_bundle(&key, created_at)
            .map_err(|message| CryptoError::EncryptionFailed { message })
    }

    pub fn history_offer_nearby(
        &self,
        user_id: Vec<u8>,
        peer: HistoryPeerKeys,
        skip: bool,
        pinned_receiver_identity: Option<Vec<u8>>,
    ) -> Result<Arc<HistorySender>, HistoryError> {
        let user_id = history_user_id(user_id)?;
        let peer = peer.into_core()?;
        let pinned = match pinned_receiver_identity {
            Some(p) => Some(<[u8; 32]>::try_from(p).map_err(|_| HistoryError::Malformed)?),
            None => None,
        };
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let sender = crate::history::session::Sender::nearby(&*orch, user_id, &peer, skip, pinned)?;
        Ok(Arc::new(HistorySender::new(sender)))
    }

    pub fn history_offer_file(
        &self,
        user_id: Vec<u8>,
        peer: HistoryPeerKeys,
    ) -> Result<Arc<HistorySender>, HistoryError> {
        let user_id = history_user_id(user_id)?;
        let peer = peer.into_core()?;
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let sender = crate::history::session::Sender::file(&*orch, user_id, &peer)?;
        Ok(Arc::new(HistorySender::new(sender)))
    }

    pub fn history_receive(
        self: Arc<Self>,
        user_id: Vec<u8>,
        from_file: bool,
    ) -> Arc<HistoryReceiver> {
        use crate::history::session::{Receiver, Source};
        let source = if from_file {
            Source::File
        } else {
            Source::Nearby
        };
        // A malformed id cannot match any stream; the receiver refuses it at the first check
        // that reads it rather than here, so this constructor cannot fail.
        let user_id: [u8; 16] = user_id.try_into().unwrap_or([0; 16]);
        Arc::new(HistoryReceiver {
            core: self,
            inner: Mutex::new(Receiver::new(source, user_id)),
        })
    }

    pub fn new_mls_store(&self) -> Result<Arc<MlsStore>, MlsError> {
        let (private, public) = self.mls_signer()?;
        Ok(Arc::new(MlsStore::new(private, public)))
    }

    pub fn import_mls_store(&self, data: Vec<u8>) -> Result<Arc<MlsStore>, MlsError> {
        let (private, public) = self.mls_signer()?;
        import_mls_store_cfe(data, private, public)
    }

    fn mls_signer(&self) -> Result<(Vec<u8>, Vec<u8>), MlsError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.mls_signer().map_err(MlsError::CryptoError)
    }

    pub fn build_x3dh_sign_message(&self, suite_id: u8, public_key: Vec<u8>) -> Vec<u8> {
        // Pure function, no lock needed. We still go through the type for consistency.
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Drop the guard immediately; build doesn't mutate or read instance state.
        drop(orch);
        crate::orchestration::Orchestrator::build_x3dh_sign_message(suite_id, &public_key)
    }

    pub fn build_hybrid_identity_bind_message(&self, hybrid_public_key: Vec<u8>) -> Vec<u8> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        drop(orch);
        crate::orchestration::Orchestrator::build_hybrid_identity_bind_message(&hybrid_public_key)
    }

    /// Ensure hybrid key + sign the standard X3DH prekey sign message with the hybrid key.
    pub fn sign_hybrid_prekey(
        &self,
        suite_id: u8,
        public_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.sign_hybrid_prekey(suite_id, &public_key)
            .map_err(|_| CryptoError::InitializationFailed)
    }

    /// Import legacy hybrid private key into core ownership (for migration from separate keychain storage).
    pub fn import_hybrid_signature_private_key(
        &self,
        priv_bytes: Vec<u8>,
    ) -> Result<(), CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.import_hybrid_signature_private_key(priv_bytes)
            .map_err(|_| CryptoError::InitializationFailed)
    }

    pub fn export_session(&self, contact_id: String) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.export_session_cfe(&contact_id)
            .map_err(|_| CryptoError::SessionNotFound)
    }

    pub fn import_session(&self, contact_id: String, data: Vec<u8>) -> Result<String, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.import_session_cfe(&contact_id, &data)
            .map_err(|e| serialization_failed("orchestrator import_session", e))
    }

    pub fn get_all_session_contact_ids(&self) -> Vec<String> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.get_all_session_contact_ids()
    }

    pub fn has_session(&self, contact_id: String) -> bool {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.has_active_session(&contact_id)
    }

    pub fn init_session(
        &self,
        contact_id: String,
        recipient_bundle: BinaryKeyBundle,
    ) -> Result<String, CryptoError> {
        check_bundle_freshness(&recipient_bundle)?;
        self.init_session_inner(contact_id, recipient_bundle, false)
    }

    /// Degraded INITIATOR init: skips ONLY the SPK age-staleness reject. All other
    /// validation (`check_bundle_freshness`'s kyber-epoch requirement, the bundle
    /// signature verified inside the X3DH agreement) still applies. See the
    /// `stale-peer-reachability` decision record. The caller flags the session at-risk.
    pub fn init_session_allowing_stale(
        &self,
        contact_id: String,
        recipient_bundle: BinaryKeyBundle,
    ) -> Result<String, CryptoError> {
        // Still refuse a PQ bundle with no Kyber SPK — that is a correctness failure
        // (silent downgrade to classical-only), not a freshness concern.
        if recipient_bundle.suite_id == 2 && recipient_bundle.kyber_spk_rotation_epoch == 0 {
            return Err(CryptoError::InvalidKeyData);
        }
        self.init_session_inner(contact_id, recipient_bundle, true)
    }

    /// The answer to `CfeAction::OpenSession`: open a session, replacing the one held only once
    /// the new one exists. See `Orchestrator::reopen_session_with_bundle`.
    pub fn reopen_session(
        &self,
        contact_id: String,
        recipient_bundle: BinaryKeyBundle,
    ) -> Result<String, CryptoError> {
        if let Err(e) = check_bundle_freshness(&recipient_bundle) {
            // Refused before the orchestrator saw it, so its own refusal path never ran.
            self.inner
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .reopen_refused(&contact_id);
            return Err(e);
        }
        self.open_session_inner(contact_id, recipient_bundle, false, true)
    }

    fn init_session_inner(
        &self,
        contact_id: String,
        recipient_bundle: BinaryKeyBundle,
        allow_stale: bool,
    ) -> Result<String, CryptoError> {
        self.open_session_inner(contact_id, recipient_bundle, allow_stale, false)
    }

    fn open_session_inner(
        &self,
        contact_id: String,
        recipient_bundle: BinaryKeyBundle,
        allow_stale: bool,
        replace: bool,
    ) -> Result<String, CryptoError> {
        let parsed = binary_bundle_to_x3dh(&recipient_bundle);
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let public_bundle = match parsed {
            Ok(bundle) => bundle,
            Err(e) => {
                if replace {
                    orch.reopen_refused(&contact_id);
                }
                return Err(e);
            }
        };
        let open = if replace {
            crate::orchestration::orchestrator::Orchestrator::reopen_session_with_bundle
        } else {
            crate::orchestration::orchestrator::Orchestrator::init_session_with_bundle
        };
        open(
            &mut orch,
            &contact_id,
            public_bundle,
            kyber_keys_of(&recipient_bundle),
            allow_stale,
        )
        .map_err(|e| CryptoError::SessionInitializationFailed { message: e })
    }

    /// Whether any of `devices` is opening a session with us right now. See
    /// `Orchestrator::peer_handshake_held`.
    pub fn peer_handshake_held(&self, devices: Vec<String>) -> bool {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.peer_handshake_held(&devices)
    }

    /// How many messages wait for a session with `contact_id`.
    pub fn pending_message_count(&self, contact_id: String) -> u32 {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.pending_message_count(&contact_id) as u32
    }

    /// The server's certificate-signing keys. See `Orchestrator::set_trusted_server_keys`.
    pub fn set_trusted_server_keys(&self, keys: Vec<Vec<u8>>) {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.set_trusted_server_keys(keys);
    }

    /// Open a receiving session from what the core holds under `device`. See
    /// `Orchestrator::open_receiving`.
    pub fn open_receiving(&self, device: String) -> ReceivingOpenResult {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let open = orch.open_receiving(&device);
        ReceivingOpenResult {
            opened_device: open.opened_device,
            opener_message_id: open.opener_message_id,
            actions: open
                .actions
                .into_iter()
                .map(CfeAction::from_action)
                .collect(),
            tried_message_ids: open.tried_message_ids,
            dropped_message_ids: open.dropped_message_ids,
            last_error: open.last_error,
            kyber_prekeys: orch.take_kyber_prekeys_to_persist(),
            awaiting_server_key: open.awaiting_server_key,
        }
    }

    /// RESPONDER init of one message outside the queue, from the key its sender certificate names.
    /// See `Orchestrator::receiving_from_certificate`.
    pub fn init_receiving_session_from_wire_payload(
        &self,
        sender_certificate: SenderCertificate,
        wire_payload: Vec<u8>,
    ) -> Result<SessionInitResult, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (session_id, plaintext) = orch
            .receiving_from_certificate(&sender_certificate, &wire_payload)
            .map_err(|e| CryptoError::SessionInitializationFailed { message: e })?;
        Ok(SessionInitResult {
            session_id,
            decrypted_message: plaintext,
            storage_key: gen_storage_key(),
            kyber_prekeys: orch.take_kyber_prekeys_to_persist(),
        })
    }

    /// Encrypt for `contact_id` and return the wire payload, handshake header and every other
    /// field included. The platform sends the bytes as they are: a copy rebuilt from components
    /// is how fields went missing on the way (the suite-3 tags; the PN field; the answer to a
    /// KEM identity key — decisions/responder-authenticates-initiator-by-kem.md).
    pub fn encrypt_to_wire(
        &self,
        contact_id: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.encrypt_bytes_for(&contact_id, &plaintext)
            .map_err(|e| CryptoError::EncryptionFailed { message: e })
    }

    /// Decrypt a wire payload from `contact_id` on the states held with it. The counterpart of
    /// `encrypt_to_wire`; the core reads every field from the bytes.
    pub fn decrypt_wire_payload(
        &self,
        contact_id: String,
        wire_payload: Vec<u8>,
    ) -> Result<DecryptedMessageResult, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let plaintext = orch
            .decrypt_bytes_for(&contact_id, &wire_payload)
            .map_err(|e| CryptoError::DecryptionFailed { message: e })?;
        Ok(DecryptedMessageResult {
            plaintext,
            storage_key: gen_storage_key(),
        })
    }

    pub fn remove_session(&self, contact_id: String) -> bool {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.remove_session_by_contact(&contact_id)
    }

    /// The person reset the session with `contact_id`. See `Orchestrator::retire_session`: local,
    /// nothing is sent, the next send opens a new state. Execute the returned save.
    pub fn retire_session(&self, contact_id: String) -> Vec<CfeAction> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.retire_session(&contact_id)
            .into_iter()
            .map(CfeAction::from_action)
            .collect()
    }

    /// Drop every piece of local orchestration state this core holds about `contact_id`.
    ///
    /// `remove_session` is not this. It removes the ratchet and nothing else, so an archive, a
    /// heal record, a prekey counter, a PQ contribution and a cooldown all outlive it — and the
    /// next add for the same device is then steered by state describing a contact the platform
    /// has already forgotten. The platform has no way to reach any of them: they are private to
    /// this crate, which is why "delete the contact" could not be expressed until now.
    ///
    /// Deliberately silent on the wire. This is a local deletion boundary, not a protocol reset;
    /// since 2026-09-27 nothing tells a peer about one (`decisions/sessions-renew-by-sending.md`).
    pub fn forget_contact_state(&self, contact_id: String) {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.forget_contact_state(&contact_id);
    }

    pub fn prekeys_available_count(&self) -> u32 {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.prekeys_available()
    }

    pub fn generate_one_time_prekeys(&self, count: u32) -> Result<Vec<OtpkPair>, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let pairs = orch
            .generate_otpks(count)
            .map_err(|_| CryptoError::InitializationFailed)?;
        Ok(pairs
            .into_iter()
            .map(|(key_id, public_key)| OtpkPair { key_id, public_key })
            .collect())
    }

    pub fn one_time_prekey_count(&self) -> u32 {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.otpk_count()
    }

    pub fn export_one_time_prekeys(&self) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.export_otpks_cfe()
            .map_err(|e| serialization_failed("orchestrator export_one_time_prekeys", e))
    }

    pub fn import_one_time_prekeys(&self, data: Vec<u8>) -> Result<(), CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.import_otpks_cfe(&data)
            .map_err(|e| serialization_failed("orchestrator import_one_time_prekeys", e))
    }

    /// Prune stored OTPK private keys with `key_id < min_keep_id`; returns the number removed.
    /// Call after a successful replace-all upload — the server set is then exactly the new
    /// batch, so older keys can never be referenced by a future bundle fetch.
    pub fn prune_one_time_prekeys_below(&self, min_keep_id: u32) -> u32 {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.prune_otpks_below(min_keep_id)
    }

    pub fn generate_kyber_one_time_prekeys(
        &self,
        count: u32,
    ) -> Result<Vec<KyberPrekeyUpload>, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let records = orch.generate_kyber_one_time_prekeys(count).map_err(|e| {
            tracing::error!(target: "crypto::uniffi", error = %e, "generate_kyber_one_time_prekeys failed");
            CryptoError::InitializationFailed
        })?;
        Ok(records.into_iter().map(KyberPrekeyUpload::from).collect())
    }

    pub fn kyber_one_time_prekey_count(&self) -> u32 {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.kyber_one_time_prekey_count()
    }

    pub fn prune_kyber_one_time_prekeys_below(&self, min_keep_id: u32) -> u32 {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.prune_kyber_one_time_prekeys_below(min_keep_id)
    }

    pub fn begin_kyber_spk_rotation(&self) -> Result<KyberPrekeyUpload, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.begin_kyber_spk_rotation()
            .map(KyberPrekeyUpload::from)
            .map_err(|e| {
                tracing::error!(target: "crypto::uniffi", error = %e, "begin_kyber_spk_rotation failed");
                CryptoError::InitializationFailed
            })
    }

    pub fn commit_kyber_spk_rotation(&self) -> bool {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.commit_kyber_spk_rotation()
    }

    pub fn rollback_kyber_spk_rotation(&self) {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.rollback_kyber_spk_rotation();
    }

    pub fn current_kyber_spk_upload(&self) -> Result<Option<KyberPrekeyUpload>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.current_kyber_spk_upload()
            .map(|r| r.map(KyberPrekeyUpload::from))
            .map_err(|e| {
                tracing::error!(target: "crypto::uniffi", error = %e, "current_kyber_spk_upload failed");
                CryptoError::InitializationFailed
            })
    }

    pub fn kyber_prekey_decapsulate(
        &self,
        key_id: u32,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.kyber_prekey_decapsulate(key_id, &ciphertext)
            .map(crate::crypto::SecretBytes::into_vec)
            .map_err(|e| {
                tracing::warn!(target: "crypto::uniffi", key_id, error = %e, "kyber_prekey_decapsulate failed");
                CryptoError::DecryptionFailed { message: e }
            })
    }

    pub fn export_kyber_prekeys(&self) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.export_kyber_prekeys_cfe()
            .map_err(|e| serialization_failed("orchestrator export_kyber_prekeys", e))
    }

    pub fn import_kyber_prekeys(&self, data: Vec<u8>) -> Result<(), CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.import_kyber_prekeys_cfe(&data)
            .map_err(|e| serialization_failed("orchestrator import_kyber_prekeys", e))
    }

    pub fn set_local_user_id(&self, user_id: String) {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.set_my_user_id(user_id);
    }

    pub fn rotate_signed_prekey(&self) -> Result<RotatedSpkBundle, CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (key_id, public_key, signature) = orch
            .rotate_spk()
            .map_err(|_| CryptoError::InitializationFailed)?;
        Ok(RotatedSpkBundle {
            key_id,
            public_key,
            signature,
        })
    }

    /// Export the full orchestrator coordination state (init locks, prekey tracker, pins)
    /// as a CFE binary blob.
    ///
    /// Persist under `SecureStoreSlot::OrchestratorState` via
    /// `SaveToSecureStore`.  Import at app startup to restore all queues.
    pub fn export_orchestrator_state(&self) -> Result<Vec<u8>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.export_orchestrator_state_cfe()
            .map_err(|e| CryptoError::SessionInitializationFailed { message: e })
    }

    /// Restore the full orchestrator coordination state from a CFE blob produced
    /// by `export_orchestrator_state`.  Call at app start before processing any
    /// messages to avoid duplicate-processing and lost healing records.
    pub fn import_orchestrator_state(&self, data: Vec<u8>) -> Result<(), CryptoError> {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.import_orchestrator_state_cfe(&data)
            .map_err(|e| CryptoError::SessionInitializationFailed { message: e })
    }
}

// ── Typed FFI event bus (CfeIncomingEvent / CfeAction) ───────────────────────
//
// These are the UDL-exposed counterparts of the Rust-internal
// `orchestration::IncomingEvent` and `orchestration::Action` enums.
// They mirror every variant 1:1 so we can convert without heap allocations.

/// Typed platform event — UDL `[Enum] interface CfeIncomingEvent`.
pub enum CfeIncomingEvent {
    MessageReceived {
        message_id: String,
        from: String,
        data: Vec<u8>,
        content_type: u8,
        sender_certificate: Option<SenderCertificate>,
    },
    OutgoingMessage {
        contact_id: String,
        message_id: String,
        plaintext: Vec<u8>,
        content_type: u8,
    },
    OutgoingCallSignal {
        contact_id: String,
        message_id: String,
        proto_bytes: Vec<u8>,
    },
    SessionInitCompleted {
        contact_id: String,
        session_data: Vec<u8>,
    },
    AckReceived {
        message_id: String,
    },
    /// The answer to `CfeAction::OpenSession`: the bundle of that one device.
    SessionBundleFetched {
        contact_id: String,
        bundle: BinaryKeyBundle,
    },
    /// The answer to `CfeAction::OpenSession` when no bundle could be fetched.
    SessionBundleUnavailable {
        contact_id: String,
    },
    NetworkReconnected,
    AppLaunched,
    TimerFired {
        timer_id: String,
    },
    /// Platform ACK DB lookup result — response to `CheckAckInDb` action.
    AckDbResult {
        message_id: String,
        is_processed: bool,
    },
    HeartbeatReceived {
        contact_id: String,
        message_id: String,
        data: Vec<u8>,
    },
    /// A DECRYPTION_ERROR (content type 28) arrived from `contact_id`; `payload` is its sealed box.
    DecryptionErrorReceived {
        contact_id: String,
        payload: Vec<u8>,
    },
}

impl CfeIncomingEvent {
    fn into_incoming_event(self) -> crate::orchestration::IncomingEvent {
        use crate::orchestration::IncomingEvent::*;
        match self {
            Self::MessageReceived {
                message_id,
                from,
                data,
                content_type,
                sender_certificate,
            } => MessageReceived {
                message_id,
                from,
                data,
                content_type,
                sender_certificate,
            },
            Self::OutgoingMessage {
                contact_id,
                message_id,
                plaintext,
                content_type,
            } => OutgoingMessage {
                contact_id,
                message_id,
                plaintext,
                content_type,
            },
            Self::OutgoingCallSignal {
                contact_id,
                message_id,
                proto_bytes,
            } => OutgoingCallSignal {
                contact_id,
                message_id,
                proto_bytes,
            },
            Self::SessionInitCompleted {
                contact_id,
                session_data,
            } => SessionInitCompleted {
                contact_id,
                session_data,
            },
            Self::AckReceived { message_id } => AckReceived { message_id },
            Self::SessionBundleFetched { contact_id, bundle } => SessionBundleFetched {
                contact_id,
                // Refused here or in the core, a bundle ends the same way: the handler's refusal.
                bundle: Box::new(parse_bundle_for_reopen(&bundle).map_err(|e| e.to_string())),
            },
            Self::SessionBundleUnavailable { contact_id } => {
                SessionBundleUnavailable { contact_id }
            }
            Self::NetworkReconnected => NetworkReconnected,
            Self::AppLaunched => AppLaunched,
            Self::TimerFired { timer_id } => TimerFired { timer_id },
            Self::AckDbResult {
                message_id,
                is_processed,
            } => AckDbResult {
                message_id,
                is_processed,
            },
            Self::HeartbeatReceived {
                contact_id,
                message_id,
                data,
            } => HeartbeatReceived {
                contact_id,
                message_id,
                data,
            },
            Self::DecryptionErrorReceived {
                contact_id,
                payload,
            } => DecryptionErrorReceived {
                contact_id,
                payload,
            },
        }
    }
}

/// Typed durable slot — UDL `[Enum] interface CfeSecureStoreSlot`.
///
/// Mirrors `orchestration::SecureStoreSlot`. The core says what the bytes are; the platform
/// decides where they live. See that type for why the string key it replaced was a defect.
pub enum CfeSecureStoreSlot {
    Session { contact_id: String },
    OrchestratorState,
}

impl From<crate::orchestration::SecureStoreSlot> for CfeSecureStoreSlot {
    fn from(slot: crate::orchestration::SecureStoreSlot) -> Self {
        use crate::orchestration::SecureStoreSlot as S;
        match slot {
            S::Session { contact_id } => Self::Session { contact_id },
            S::OrchestratorState => Self::OrchestratorState,
        }
    }
}

/// Typed platform action — UDL `[Enum] interface CfeAction`.
pub enum CfeAction {
    DecryptMessage {
        contact_id: String,
        ciphertext: Vec<u8>,
    },
    EncryptMessage {
        contact_id: String,
        plaintext: Vec<u8>,
    },
    ArchiveSession {
        contact_id: String,
    },
    MessageDecrypted {
        contact_id: String,
        message_id: String,
        plaintext: Vec<u8>,
    },
    SaveToSecureStore {
        slot: CfeSecureStoreSlot,
        data: Vec<u8>,
    },
    PersistAck {
        message_id: String,
        timestamp: u64,
    },
    PruneAckStore {
        cutoff_ts: u64,
    },
    MarkMessageDelivered {
        message_id: String,
    },
    DuplicateDropped {
        message_id: String,
    },
    OpenReceiving {
        contact_id: String,
    },
    SendEncryptedMessage {
        to: String,
        payload: Vec<u8>,
        message_id: String,
        content_type: u8,
    },
    SendReceipt {
        message_id: String,
        status: String,
    },
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
    ScheduleTimer {
        timer_id: String,
        delay_ms: u64,
    },
    CancelTimer {
        timer_id: String,
    },
    CallSignalDecrypted {
        contact_id: String,
        message_id: String,
        proto_bytes: Vec<u8>,
    },
    /// Platform must query its persistent ACK store for `message_id`.
    CheckAckInDb {
        message_id: String,
    },
    /// Open a session with `contact_id` now, as INITIATOR, over the one held: `reopen_session`.
    /// Nothing is announced — the handshake header rides on the next message. The PQXDH v2
    /// upgrade sweep asks this for classical sessions.
    OpenSession {
        contact_id: String,
    },
    /// Message is queued inside the core behind an in-flight session init. Nothing lost,
    /// nothing required of the platform; it is drained when the init completes.
    MessageQueuedPendingInit {
        contact_id: String,
        queued_count: u32,
    },
    /// See `Action::SendDecryptionError`: send `payload` to `contact_id` as a DECRYPTION_ERROR
    /// (content type 28) envelope and acknowledge `message_id`.
    SendDecryptionError {
        contact_id: String,
        message_id: String,
        payload: Vec<u8>,
    },
    /// See `Action::SessionRetired`.
    SessionRetired {
        contact_id: String,
        without_one_time_prekey: bool,
    },
    /// See `Action::ResendMessage`.
    ResendMessage {
        contact_id: String,
        message_id: String,
    },
}

impl CfeAction {
    fn from_action(action: crate::orchestration::Action) -> Self {
        use crate::orchestration::Action::*;
        use crate::orchestration::ReceiptStatus;
        match action {
            DecryptMessage {
                contact_id,
                ciphertext,
            } => Self::DecryptMessage {
                contact_id,
                ciphertext,
            },
            EncryptMessage {
                contact_id,
                plaintext,
            } => Self::EncryptMessage {
                contact_id,
                plaintext,
            },
            ArchiveSession { contact_id } => Self::ArchiveSession { contact_id },
            MessageDecrypted {
                contact_id,
                message_id,
                plaintext,
            } => Self::MessageDecrypted {
                contact_id,
                message_id,
                plaintext,
            },
            SaveToSecureStore { slot, data } => Self::SaveToSecureStore {
                slot: slot.into(),
                data: data.into_vec(),
            },
            PersistAck {
                message_id,
                timestamp,
            } => Self::PersistAck {
                message_id,
                timestamp,
            },
            PruneAckStore { cutoff_ts } => Self::PruneAckStore { cutoff_ts },
            MarkMessageDelivered { message_id } => Self::MarkMessageDelivered { message_id },
            DuplicateDropped { message_id } => Self::DuplicateDropped { message_id },
            OpenReceiving { contact_id } => Self::OpenReceiving { contact_id },
            SendEncryptedMessage {
                to,
                payload,
                message_id,
                content_type,
            } => Self::SendEncryptedMessage {
                to,
                payload,
                message_id,
                content_type,
            },
            SendReceipt { message_id, status } => Self::SendReceipt {
                message_id,
                status: match status {
                    ReceiptStatus::Sent => "sent",
                    ReceiptStatus::Delivered => "delivered",
                    ReceiptStatus::Read => "read",
                    ReceiptStatus::Failed => "failed",
                }
                .to_string(),
            },
            SendDecryptionError {
                contact_id,
                message_id,
                payload,
            } => Self::SendDecryptionError {
                contact_id,
                message_id,
                payload,
            },
            SessionRetired {
                contact_id,
                without_one_time_prekey,
            } => Self::SessionRetired {
                contact_id,
                without_one_time_prekey,
            },
            ResendMessage {
                contact_id,
                message_id,
            } => Self::ResendMessage {
                contact_id,
                message_id,
            },
            NotifyNewMessage { chat_id, preview } => Self::NotifyNewMessage { chat_id, preview },
            NotifySessionCreated { contact_id } => Self::NotifySessionCreated { contact_id },
            NotifyError { code, message } => Self::NotifyError { code, message },
            ScheduleTimer { timer_id, delay_ms } => Self::ScheduleTimer { timer_id, delay_ms },
            CancelTimer { timer_id } => Self::CancelTimer { timer_id },
            CallSignalDecrypted {
                contact_id,
                message_id,
                proto_bytes,
            } => Self::CallSignalDecrypted {
                contact_id,
                message_id,
                proto_bytes,
            },
            CheckAckInDb { message_id } => Self::CheckAckInDb { message_id },
            OpenSession { contact_id } => Self::OpenSession { contact_id },
            MessageQueuedPendingInit {
                contact_id,
                queued_count,
            } => Self::MessageQueuedPendingInit {
                contact_id,
                queued_count,
            },
        }
    }
}

// ── ConstructPrivacyPass UniFFI bindings ──────────────────────────────────────

pub fn pp_blind_token(nonce: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    crate::crypto::privacy_pass::pp_blind_token(nonce).map_err(|e| CryptoError::EncryptionFailed {
        message: e.to_string(),
    })
}

pub fn pp_finalize_token(
    evaluated_bytes: Vec<u8>,
    blind_factor_bytes: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    crate::crypto::privacy_pass::pp_finalize_token(evaluated_bytes, blind_factor_bytes, nonce)
        .map_err(|e| CryptoError::EncryptionFailed {
            message: e.to_string(),
        })
}

pub fn pp_verify_client(
    evaluated_bytes: Vec<u8>,
    nonce: Vec<u8>,
    server_pubkey_bytes: Vec<u8>,
) -> bool {
    crate::crypto::privacy_pass::pp_verify_client(evaluated_bytes, nonce, server_pubkey_bytes)
}

/// Verify a batched DLEQ proof (`IssueTokensResponse.dleq_proof`) against the client-pinned
/// issuer public key `K`. Returns true iff the same `k` links `K = k·G` and every
/// `evaluated[i] = k·blinded[i]`. See `crate::crypto::privacy_pass::pp_verify_dleq`.
pub fn pp_verify_dleq(
    blinded: Vec<Vec<u8>>,
    evaluated: Vec<Vec<u8>>,
    proof: Vec<u8>,
    issuer_public: Vec<u8>,
) -> bool {
    crate::crypto::privacy_pass::pp_verify_dleq(blinded, evaluated, proof, issuer_public)
}

pub fn pp_seal_token_bytes(
    token: Vec<u8>,
    server_encryption_key: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    crate::crypto::privacy_pass::pp_seal_token_bytes(token, server_encryption_key).map_err(|e| {
        CryptoError::EncryptionFailed {
            message: e.to_string(),
        }
    })
}

// ── ConstructSEALED UniFFI bindings ───────────────────────────────────────────

pub fn sealed_seal_sender_cert(
    cert_bytes: Vec<u8>,
    recipient_identity_key: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    crate::crypto::sealed_sender::seal_to_x25519_public(&cert_bytes, &recipient_identity_key)
        .map_err(|e| CryptoError::EncryptionFailed {
            message: e.to_string(),
        })
}

/// Seal a device's own metadata to one of its account's devices.
///
/// Same box and the same implementation as `sealed_seal_sender_cert` — deliberately, because
/// the format is bit-compatible with the CryptoKit code on iOS and a second copy that drifted
/// would produce boxes that open on one platform and not the other. Two names because there
/// are two purposes, and a name that describes one of them is wrong on the other.
///
/// The account has no shared key: every device holds its own X25519 identity pair and nothing
/// is established between them at link time. So a device's metadata is sealed once per sibling
/// and the copies are stored together. That costs a copy per device — units of them — and buys
/// the property a shared key could not: a revoked device stops being sealed to on the next
/// re-seal, rather than keeping the ability to read until someone rotates a key.
pub fn seal_to_device_key(
    plaintext: Vec<u8>,
    device_identity_public: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    crate::crypto::sealed_sender::seal_to_x25519_public(&plaintext, &device_identity_public)
        .map_err(|e| CryptoError::EncryptionFailed {
            message: e.to_string(),
        })
}

#[allow(clippy::too_many_arguments)]
pub fn sealed_verify_sender_cert(
    user_id: String,
    domain: String,
    identity_key: Vec<u8>,
    device_id: String,
    issued_at: i64,
    expires_at: i64,
    signature: Vec<u8>,
    server_verifying_key: Vec<u8>,
) -> bool {
    crate::crypto::sealed_sender::verify_sender_cert(
        &user_id,
        &domain,
        &identity_key,
        &device_id,
        issued_at,
        expires_at,
        &signature,
        &server_verifying_key,
    )
}

// ── Per-device copy tag UniFFI bindings ──────────────────────────────────────

// ── SLIP-39 Social Recovery UniFFI bindings ───────────────────────────────────

pub fn sr_generate_vault_key() -> Result<Vec<u8>, CryptoError> {
    Ok(crate::crypto::social_recovery::generate_vault_key().to_vec())
}

pub fn sr_create_recovery_shares(
    vault_key: Vec<u8>,
    threshold: u8,
    share_count: u8,
) -> Result<Vec<String>, CryptoError> {
    let key: [u8; 32] = vault_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyData)?;
    crate::crypto::social_recovery::create_recovery_shares(&key, threshold, share_count).map_err(
        |e| CryptoError::SessionInitializationFailed {
            message: e.to_string(),
        },
    )
}

pub fn sr_reconstruct_vault_key(mnemonics: Vec<String>) -> Result<Vec<u8>, CryptoError> {
    crate::crypto::social_recovery::reconstruct_vault_key(mnemonics)
        .map(|k| k.to_vec())
        .map_err(|e| CryptoError::DecryptionFailed {
            message: e.to_string(),
        })
}
