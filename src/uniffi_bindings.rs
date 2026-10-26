use crate::crypto::SuiteID;
use crate::crypto::client_api::ClassicClient;
use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::group::{MemberAddition, MlsError};
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

    /// The server asked for more leading zero bits than `pow::MAX_POW_DIFFICULTY`: no search
    /// is started. Registration cannot proceed against that server.
    #[error("PoW difficulty {difficulty} is past the limit {max}")]
    PowDifficultyTooHigh { difficulty: u32, max: u32 },

    /// The bundle's SPK rotation epoch is below the one this device already admitted from the
    /// same peer device: an old bundle served again. Nothing was opened. Per device, kept across
    /// a session reset, cleared by `forget_contact_state` (TODO 176).
    #[error("Peer SPK rotation epoch {received} is below the {known} already admitted")]
    PeerSpkEpochRegressed { received: u32, known: u32 },
}

impl From<crate::pow::PowError> for CryptoError {
    fn from(err: crate::pow::PowError) -> Self {
        match err {
            crate::pow::PowError::DifficultyTooHigh { difficulty, max } => {
                CryptoError::PowDifficultyTooHigh { difficulty, max }
            }
            crate::pow::PowError::Hash(_) => CryptoError::InitializationFailed,
        }
    }
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

/// A first flight opened by `OrchestratorCore::open_first_flight`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstFlightOpened {
    pub certificate: Vec<u8>,
    pub wire_payload: Vec<u8>,
}

/// A session envelope opened by `OrchestratorCore::open_envelope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeOpened {
    /// The device whose pair matched — who wrote it.
    pub contact_id: String,
    /// The session of that pair; pass it on as `MessageReceived::envelope_session`.
    pub session_id: String,
    /// 1 = a ratchet wire payload, 2 = a DECRYPTION_ERROR.
    pub kind: u8,
    pub body: Vec<u8>,
    /// The pair's ratchet state is gone here: a ratchet body will not decrypt, and is answered
    /// with a DECRYPTION_ERROR along the same pair.
    pub retired: bool,
}

/// How late messages arrive, for this process — the measurement PQR-4 waits on. See
/// `orchestration::reorder_stats`. Local diagnostics: never sent anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReorderStats {
    pub decrypted: u64,
    pub previous_epoch: u64,
    pub older_epoch: u64,
    pub max_epoch_lag: u32,
    pub max_skip_depth: u32,
    pub evicted_epoch_failures: u64,
}

impl From<crate::orchestration::ReorderStats> for ReorderStats {
    fn from(s: crate::orchestration::ReorderStats) -> Self {
        Self {
            decrypted: s.decrypted,
            previous_epoch: s.previous_epoch,
            older_epoch: s.older_epoch,
            max_epoch_lag: s.max_epoch_lag,
            max_skip_depth: s.max_skip_depth,
            evicted_epoch_failures: s.evicted_epoch_failures,
        }
    }
}

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

/// UDL `KtInclusionProof`, `KtSignedTreeHead`, `KtVerdict`.
pub use crate::crypto::key_transparency::{KtInclusionProof, KtSignedTreeHead, KtVerdict};
pub use crate::crypto::kyber_prekey_auth::{PqAuthentication, PqHandshake};
/// UDL `enum CertificateVerdict`.
pub use crate::crypto::sealed_sender::CertificateVerdict;
/// The sender certificate as a platform unsealed it. UDL `dictionary SenderCertificate`.
pub use crate::crypto::sealed_sender::SenderCertificate;

/// The verdicts on a bundle's proofs. UDL `dictionary KtVerdicts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtVerdicts {
    pub identity: KtVerdict,
    pub hybrid: Option<KtVerdict>,
}

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
    /// PQ-ratchet sparse PQ-ratchet field, serialized (empty = none). Opaque to the transport.
    pub pq_ratchet_field: Vec<u8>,
    /// The wire carried `PQXDH_V2_FLAG`.
    pub pqxdh_v2: bool,
    /// The initiator's ML-KEM-1024 identity key, on a first flight.
    pub kem_identity: Option<Vec<u8>>,
    /// The responder's answer to it, until the initiator proves itself.
    pub identity_proof_ciphertext: Option<Vec<u8>>,
    /// The key's index in the sender's chain of `pq_message_epoch` (PQR-2).
    pub pq_key_index: u32,
}

/// Serialize the optional PQ-ratchet sparse PQ-ratchet field for the FFI/wire boundary.
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

/// A hybrid recovery key's public half and its signature over one recovery message.
pub struct RecoverySigned {
    /// Ed25519 (32) ‖ ML-DSA-65 (1952).
    pub public_key: Vec<u8>,
    /// Ed25519 (64) ‖ ML-DSA-65 (3309).
    pub signature: Vec<u8>,
}

impl From<recovery::RecoverySigned> for RecoverySigned {
    fn from(s: recovery::RecoverySigned) -> Self {
        Self {
            public_key: s.public_key,
            signature: s.signature,
        }
    }
}

/// The hybrid recovery public key the mnemonic determines (Ed25519 ‖ ML-DSA-65, 1984 bytes).
pub fn recovery_public_key(mnemonic: String) -> Result<Vec<u8>, CryptoError> {
    recovery::recovery_public_key(&mnemonic).map_err(|_| CryptoError::InvalidKeyData)
}

/// The mnemonic's recovery key signing its setup on `account_id`, or the upgrade of the Ed25519
/// key already set there.
pub fn sign_recovery_setup(
    mnemonic: String,
    account_id: String,
    timestamp: i64,
) -> Result<RecoverySigned, CryptoError> {
    recovery::sign_recovery_setup(&mnemonic, &account_id, timestamp)
        .map(Into::into)
        .map_err(|_| CryptoError::InvalidKeyData)
}

/// The mnemonic's recovery key handing its account to the device these keys name.
pub fn sign_recovery_claim(
    mnemonic: String,
    timestamp: i64,
    device_id: String,
    verifying_key: Vec<u8>,
    identity_public: Vec<u8>,
) -> Result<RecoverySigned, CryptoError> {
    recovery::sign_recovery_claim(
        &mnemonic,
        timestamp,
        &device_id,
        &verifying_key,
        &identity_public,
    )
    .map(Into::into)
    .map_err(|_| CryptoError::InvalidKeyData)
}

// ============================================================================
// Timing (the one traffic-shaping export; cover traffic retired in 0.55.0)
// ============================================================================

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
// Device certificates — construct-docs/decisions/devices-of-an-account-sign-each-other.md
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceCertError {
    #[error("keys_malformed")]
    KeysMalformed,
    #[error("binding_invalid")]
    BindingInvalid,
    #[error("evidence_mismatch")]
    EvidenceMismatch,
    #[error("signer_is_subject")]
    SignerIsSubject,
    #[error("signing_failed")]
    SigningFailed,
}

impl From<crate::crypto::device_certificate::CertError> for DeviceCertError {
    fn from(e: crate::crypto::device_certificate::CertError) -> Self {
        use crate::crypto::device_certificate::CertError as E;
        match e {
            E::KeysMalformed => Self::KeysMalformed,
            E::BindingInvalid => Self::BindingInvalid,
            E::EvidenceMismatch => Self::EvidenceMismatch,
            E::SignerIsSubject => Self::SignerIsSubject,
            E::SigningFailed => Self::SigningFailed,
        }
    }
}

/// A device's public keys as its bundle presents them.
pub struct DeviceCertKeys {
    pub identity_public: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub hybrid_public: Vec<u8>,
    pub hybrid_binding: Vec<u8>,
}

impl DeviceCertKeys {
    fn view(&self) -> crate::crypto::device_certificate::DeviceKeys<'_> {
        crate::crypto::device_certificate::DeviceKeys {
            identity_public: &self.identity_public,
            verifying_key: &self.verifying_key,
            hybrid_public: &self.hybrid_public,
            hybrid_binding: &self.hybrid_binding,
        }
    }
}

pub enum DeviceLinkEvidence {
    QrFingerprint { fingerprint: Vec<u8> },
    QrSecret { secret: Vec<u8>, proof: Vec<u8> },
}

pub struct OfferedPeerDevice {
    pub device_id: String,
    pub keys: DeviceCertKeys,
    pub certificate: Option<Vec<u8>>,
}

pub enum PeerDeviceVerdict {
    Pinned,
    FirstOfAccount,
    Vouched { by: String },
    Unvouched,
    KeyChanged,
    Invalid,
}

impl From<crate::crypto::device_certificate::DeviceVerdict> for PeerDeviceVerdict {
    fn from(v: crate::crypto::device_certificate::DeviceVerdict) -> Self {
        use crate::crypto::device_certificate::DeviceVerdict as V;
        match v {
            V::Pinned => Self::Pinned,
            V::FirstOfAccount => Self::FirstOfAccount,
            V::Vouched { by } => Self::Vouched { by },
            V::Unvouched => Self::Unvouched,
            V::KeyChanged => Self::KeyChanged,
            V::Invalid => Self::Invalid,
        }
    }
}

/// Flow A: the secret the old device puts in its link QR. Never sent to the server.
pub fn new_device_link_secret() -> Vec<u8> {
    let mut secret = vec![0u8; crate::crypto::device_certificate::LINK_SECRET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
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

// ============================================================================
// Device-Based Authentication (PoW + Device ID)
// ============================================================================

/// Compute Argon2id-based Proof of Work
/// UniFFI wrapper - accepts owned String instead of &str
pub fn compute_pow(challenge: String, difficulty: u32) -> Result<PowSolution, CryptoError> {
    Ok(crate::pow::compute_pow(&challenge, difficulty)?)
}

/// Compute PoW with progress callback
/// UniFFI wrapper - accepts owned String instead of &str
pub fn compute_pow_with_progress(
    challenge: String,
    difficulty: u32,
    progress_callback: Option<Box<dyn PowProgressCallback>>,
) -> Result<PowSolution, CryptoError> {
    Ok(crate::pow::compute_pow_with_progress(
        &challenge,
        difficulty,
        progress_callback,
    )?)
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
        pq_key_index: decoded.pq_key_index,
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

// ── Media blobs ───────────────────────────────────────────────────────────────

/// See the UDL `SealedMedia`.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedMedia {
    pub key: Vec<u8>,
    pub blob: Vec<u8>,
    pub sha256: Vec<u8>,
}

pub fn seal_media(plaintext: Vec<u8>) -> Result<SealedMedia, CryptoError> {
    let sealed = crate::media::seal_media(&plaintext).map_err(media_error)?;
    Ok(SealedMedia {
        key: sealed.key,
        blob: sealed.blob,
        sha256: sealed.sha256,
    })
}

pub fn open_media(key: Vec<u8>, blob: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    crate::media::open_media(&key, &blob).map_err(media_error)
}

pub fn media_max_plaintext_len() -> u64 {
    crate::media::max_plaintext_len()
}

fn media_error(e: crate::media::MediaError) -> CryptoError {
    use crate::media::MediaError;
    match e {
        MediaError::TooLarge(_) => CryptoError::EncryptionFailed {
            message: e.to_string(),
        },
        MediaError::InvalidKey(_) => CryptoError::InvalidKeyData,
        MediaError::Unauthenticated => CryptoError::DecryptionFailed {
            message: e.to_string(),
        },
        MediaError::MalformedPadding => CryptoError::InvalidCiphertext,
    }
}

// ── KNST frame ────────────────────────────────────────────────────────────────

/// See the UDL `KnstFrame`.
#[derive(Debug, Clone, PartialEq)]
pub struct KnstFrame {
    pub content_type: u8,
    pub message_id: String,
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub plaintext_length: u32,
    pub payload: Vec<u8>,
}

pub fn knst_encode_chunks(
    payload: Vec<u8>,
    content_type: u8,
    message_id: String,
) -> Option<Vec<Vec<u8>>> {
    let id = crate::knst::message_id_bytes(&message_id)?;
    crate::knst::encode_chunks(&payload, content_type, &id)
}

pub fn knst_frame_whole(payload: Vec<u8>, content_type: u8, message_id: String) -> Option<Vec<u8>> {
    let id = crate::knst::message_id_bytes(&message_id)?;
    crate::knst::frame_whole(&payload, content_type, &id)
}

pub fn knst_parse(frame: Vec<u8>) -> Option<KnstFrame> {
    let f = crate::knst::Frame::parse(&frame)?;
    Some(KnstFrame {
        content_type: f.content_type,
        message_id: crate::knst::message_id_string(&f.message_id),
        chunk_index: f.chunk_index,
        total_chunks: f.total_chunks,
        plaintext_length: f.plaintext_length,
        payload: f.payload.to_vec(),
    })
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

/// Sign a message with an ML-DSA-65 signing seed (detached signature).
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

/// Verify an ML-DSA-65 detached signature.
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

/// Generate a hybrid (Ed25519 + ML-DSA-65) signature keypair.
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

/// Sign a message with a hybrid private key (Ed25519 + ML-DSA-65).
pub fn hybrid_sign(private_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::hybrid::HybridSuiteProvider;
    HybridSuiteProvider::sign(&crate::crypto::SecretBytes::new(private_key), &message).map_err(
        |e| CryptoError::EncryptionFailed {
            message: format!("Hybrid sign failed: {e}"),
        },
    )
}

/// Verify a hybrid signature (both Ed25519 and ML-DSA-65 must be valid).
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

/// Derive the hybrid public key from a hybrid private key.
pub fn hybrid_public_key_from_private(private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::hybrid::HybridSuiteProvider;
    HybridSuiteProvider::from_signature_private_to_public(&crate::crypto::SecretBytes::new(
        private_key,
    ))
    .map_err(|_e| CryptoError::InvalidKeyData)
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
/// (older than `client_api::SPK_MAX_AGE_SECS`, 30 days — the same constant the inner X3DH gate
/// applies, so the two cannot drift). Returns `Ok(())` if fresh, absent (legacy server), or
/// unparseable.
fn check_bundle_freshness(bundle: &BinaryKeyBundle) -> Result<(), CryptoError> {
    use crate::crypto::client_api::SPK_MAX_AGE_SECS;
    let now = crate::utils::time::now();

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
    if bundle.suite_id == SuiteID::PQ_HYBRID.as_u16() && bundle.kyber_spk_rotation_epoch == 0 {
        return Err(CryptoError::InvalidKeyData);
    }

    Ok(())
}

// ── Notification extension (decisions/notification-extension-reads-only.md) ─────────────────

/// The orchestrator's own verdict type, not a mirror of it: one enum, two names for nothing.
pub use crate::orchestration::PeekVerdict;

pub trait PeekSessionSource: Send + Sync {
    fn session(&self, device_id: String) -> Option<Vec<u8>>;
}

/// The extension's throwaway view of this device's sessions. It wraps an `Orchestrator` and
/// exposes `peek` alone: no event, no export, no action reaches the platform from it.
pub struct NotificationPeek {
    inner: std::sync::Mutex<crate::orchestration::Orchestrator>,
}

impl NotificationPeek {
    pub fn new(
        key_record: Vec<u8>,
        my_user_id: String,
        orchestrator_state: Option<Vec<u8>>,
    ) -> Result<Self, CryptoError> {
        let _ = crate::config::Config::init();
        let inner = crate::orchestration::Orchestrator::for_peek(
            &key_record,
            my_user_id,
            orchestrator_state.as_deref(),
        )
        .map_err(|e| serialization_failed("NotificationPeek/new", e))?;
        Ok(Self {
            inner: std::sync::Mutex::new(inner),
        })
    }

    pub fn peek(
        &self,
        message_id: String,
        sealed_inner: Vec<u8>,
        sessions: Box<dyn PeekSessionSource>,
    ) -> PeekVerdict {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.peek_sealed(&message_id, &sealed_inner, &mut |device| {
            sessions.session(device.to_string())
        })
    }
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
    /// See `Orchestrator::seal_envelope`.
    pub fn seal_envelope(&self, contact_id: String, wire_payload: Vec<u8>) -> Option<Vec<u8>> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.seal_envelope(&contact_id, &wire_payload)
    }

    /// See `Orchestrator::open_envelope`.
    pub fn open_envelope(&self, envelope: Vec<u8>) -> Option<EnvelopeOpened> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.open_envelope(&envelope).map(|o| EnvelopeOpened {
            contact_id: o.device,
            session_id: o.session_id,
            kind: o.kind as u8,
            body: o.body,
            retired: o.retired,
        })
    }

    /// See `Orchestrator::seal_first_flight`.
    pub fn seal_first_flight(
        &self,
        contact_id: String,
        recipient_identity: Vec<u8>,
        wire_payload: Vec<u8>,
        certificate: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.seal_first_flight(
            &contact_id,
            &recipient_identity,
            &wire_payload,
            &certificate,
        )
        .map_err(|message| CryptoError::EncryptionFailed { message })
    }

    /// See `Orchestrator::open_first_flight`.
    pub fn open_first_flight(&self, sealed: Vec<u8>) -> Result<FirstFlightOpened, CryptoError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.open_first_flight(&sealed)
            .map(|o| FirstFlightOpened {
                certificate: o.certificate,
                wire_payload: o.wire_payload,
            })
            .map_err(|message| CryptoError::DecryptionFailed { message })
    }

    /// How late messages have arrived since the process started (PQR-4).
    pub fn reorder_stats(&self) -> ReorderStats {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.reorder_stats().into()
    }

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

    // ── Device certificates ──────────────────────────────────────────────────

    pub fn issue_device_certificate(
        &self,
        subject: DeviceCertKeys,
        evidence: DeviceLinkEvidence,
    ) -> Result<Vec<u8>, DeviceCertError> {
        use crate::crypto::device_certificate::LinkEvidence;
        let evidence = match &evidence {
            DeviceLinkEvidence::QrFingerprint { fingerprint } => {
                LinkEvidence::QrFingerprint(fingerprint)
            }
            DeviceLinkEvidence::QrSecret { secret, proof } => {
                LinkEvidence::QrSecret { secret, proof }
            }
        };
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Ok(orch.issue_device_certificate(&subject.view(), &evidence)?)
    }

    pub fn device_link_key_proof(&self, secret: Vec<u8>) -> Result<Vec<u8>, DeviceCertError> {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Ok(orch.device_link_key_proof(&secret)?.to_vec())
    }

    pub fn judge_peer_devices(
        &self,
        trusted_device_ids: Vec<String>,
        offered: Vec<OfferedPeerDevice>,
    ) -> Vec<PeerDeviceVerdict> {
        let views: Vec<crate::crypto::device_certificate::OfferedDevice<'_>> = offered
            .iter()
            .map(|d| crate::crypto::device_certificate::OfferedDevice {
                device_id: &d.device_id,
                keys: d.keys.view(),
                certificate: d.certificate.as_deref(),
            })
            .collect();
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.judge_peer_devices(&trusted_device_ids, &views)
            .into_iter()
            .map(Into::into)
            .collect()
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

    /// Asked before every send: an unanswered handshake past its age is retired first
    /// (`Orchestrator::has_session_for_sending`), so the platform opens a new state.
    pub fn has_session(&self, contact_id: String) -> bool {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.has_session_for_sending(&contact_id)
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
        if recipient_bundle.suite_id == SuiteID::PQ_HYBRID.as_u16()
            && recipient_bundle.kyber_spk_rotation_epoch == 0
        {
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
        if let Some(regressed) =
            orch.spk_epoch_regression(&contact_id, public_bundle.spk_rotation_epoch)
        {
            if replace {
                orch.reopen_refused(&contact_id);
            }
            return Err(CryptoError::PeerSpkEpochRegressed {
                received: regressed.received,
                known: regressed.known,
            });
        }
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

    /// Delegations of the server's hybrid keys. See `Orchestrator::admit_server_delegations`.
    pub fn admit_server_delegations(&self, delegations: Vec<Vec<u8>>) -> u32 {
        let mut orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.admit_server_delegations(delegations)
    }

    /// The label for a sender certificate. See `SenderCertificate::verdict`.
    pub fn certificate_verdict(&self, certificate: SenderCertificate) -> CertificateVerdict {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        orch.certificate_verdict(&certificate)
    }

    /// Judge a bundle's KT proofs. See `Orchestrator::verify_kt_proofs`. A hybrid key without its
    /// proof, or the reverse, judges the identity proof alone.
    pub fn verify_kt_proofs(
        &self,
        device_id: String,
        identity_key: Vec<u8>,
        identity_proof: KtInclusionProof,
        hybrid_identity_key: Option<Vec<u8>>,
        hybrid_proof: Option<KtInclusionProof>,
        tree_head: Option<KtSignedTreeHead>,
    ) -> KtVerdicts {
        let orch = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let hybrid = hybrid_identity_key.as_deref().zip(hybrid_proof.as_ref());
        let (identity, hybrid) = orch.verify_kt_proofs(
            &device_id,
            &identity_key,
            &identity_proof,
            hybrid,
            tree_head.as_ref(),
        );
        KtVerdicts { identity, hybrid }
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
    /// is how fields went missing on the way (the PQ-ratchet tags; the PN field; the answer to a
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

    /// Export the full orchestrator coordination state (init locks, pins)
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
        envelope_session: Option<String>,
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
        opened: bool,
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
                envelope_session,
            } => MessageReceived {
                message_id,
                from,
                data,
                content_type,
                sender_certificate: sender_certificate.map(Box::new),
                envelope_session,
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
                opened,
            } => DecryptionErrorReceived {
                contact_id,
                payload,
                opened,
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
    MalformedDropped {
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
    CallSignalDecrypted {
        contact_id: String,
        message_id: String,
        proto_bytes: Vec<u8>,
    },
    ControlFrameDecrypted {
        contact_id: String,
        message_id: String,
        content_type: u8,
        body: Vec<u8>,
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
        enveloped: bool,
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
        match action {
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
            MalformedDropped { message_id } => Self::MalformedDropped { message_id },
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
            SendDecryptionError {
                contact_id,
                message_id,
                payload,
                enveloped,
            } => Self::SendDecryptionError {
                contact_id,
                message_id,
                payload,
                enveloped,
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
            CallSignalDecrypted {
                contact_id,
                message_id,
                proto_bytes,
            } => Self::CallSignalDecrypted {
                contact_id,
                message_id,
                proto_bytes,
            },
            ControlFrameDecrypted {
                contact_id,
                message_id,
                content_type,
                body,
            } => Self::ControlFrameDecrypted {
                contact_id,
                message_id,
                content_type,
                body,
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

#[cfg(test)]
mod tests;
