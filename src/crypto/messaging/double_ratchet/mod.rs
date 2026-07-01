//! Double Ratchet Protocol Implementation
//!
//! Реализация протокола Double Ratchet (Signal Protocol).
//!
//! ## Архитектура
//!
//! Double Ratchet состоит из двух ratchets:
//! 1. **DH Ratchet**: Постоянная ротация DH ключей для forward secrecy
//! 2. **Symmetric Ratchet**: Ротация chain keys для каждого сообщения
//!
//! ## Key Responsibilities
//!
//! - DH Ratcheting: Генерация новых DH пар при каждом "turn" в диалоге
//! - Chain Key Ratcheting: Вывод message keys из chain keys
//! - Skipped Message Keys: Хранение ключей для out-of-order сообщений
//! - DoS Protection: Лимиты на skipped keys
//!
//! ## Dataflow Example
//!
//! ```text
//! Alice                                    Bob
//! -----                                    ---
//! new_initiator_session(root_key, initiator_state, bob_pub)
//!   ↓
//! ephemeral_priv (from X3DH) → first DH ratchet key
//!   ↓
//! DH(ephemeral_priv, bob_identity) → sending_chain
//!   ↓
//! encrypt(msg1) →                      →  Bob receives msg1
//!                                            ↓
//!                                        new_responder_session(root_key, bob_priv, msg1)
//!                                            ↓
//!                                        Extract alice_ephemeral_pub from msg1
//!                                            ↓
//!                                        DH(bob_identity_priv, alice_ephemeral_pub) → receiving_chain
//!                                            ↓
//!                                        decrypt(msg1) ✅
//!                                            ↓
//!                                        Generate new DH pair for reply
//!                                            ↓
//!                                    ←   encrypt(msg2) with new DH key
//! DH Ratchet Step! (Alice sees new DH key)
//!   ↓
//! decrypt(msg2) ✅
//! ```

use crate::crypto::SuiteID;
use crate::crypto::provider::CryptoProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

mod internals;
mod messaging;
mod storage;
#[cfg(test)]
mod tests;

pub use storage::{SerializableSession, SkippedKeyEntry};

/// AD (Associated Data) version byte — increment here when the AD format changes.
/// Both `encrypt` and `decrypt_with_key` must use this constant so a version
/// mismatch surfaces as an AEAD failure rather than a silent format bug.
///
/// History:
///   v1 — original format (before the AD identity bug fix)
///   v2 — after AD bug fix: local_user_id/contact_id are both server UUIDs (36-char)
///   v3 — after session_id derivation v2: HKDF info includes sorted user IDs
const AD_VERSION: u8 = 3;

/// Previous AD version used as a fallback during rolling upgrades.
///
/// `decrypt_with_key` tries v3 first; if AEAD fails it retries with v2 to handle
/// in-flight messages encrypted by peers that haven't yet upgraded.
/// Once all clients are on v3, this constant can be removed.
const AD_VERSION_PREV: u8 = 2;

/// Read-only health snapshot of a `DoubleRatchetSession`.
///
/// Returned by [`DoubleRatchetSession::health_snapshot`] and propagated upwards
/// through [`Session`] / [`Client`] / UniFFI to the Swift layer.
/// No session state is mutated when producing this value.
#[derive(Debug, Clone)]
pub struct DrHealthSnapshot {
    /// Messages sent in the current sending chain.
    pub messages_sent: u32,
    /// Messages received in the current receiving chain.
    pub messages_received: u32,
    /// Number of out-of-order message keys currently buffered.
    pub skipped_keys_count: usize,
    /// `true` once the Kyber OTPK contribution has been mixed into the root key.
    pub is_pq_strengthened: bool,
    /// Unix timestamp of the last DH ratchet step (init counts as first ratchet).
    pub last_ratchet_at: u64,
    /// Shared session identifier (hex).
    pub session_id: String,
}

/// A locally-generated ML-KEM-768 keypair pending completion of a sparse
/// PQ-ratchet exchange (see `DoubleRatchetSession::perform_pq_ratchet_step`).
/// The public half rides on outgoing messages until the peer replies with a
/// ciphertext; the secret half is zeroized on drop or on successful decapsulation.
#[derive(Debug, Clone)]
pub(super) struct PqRatchetKeyPair {
    pub(super) public: Vec<u8>,
    pub(super) secret: Vec<u8>,
}

impl Zeroize for PqRatchetKeyPair {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

/// Wire-level representation of the optional sparse PQ-ratchet field carried on a
/// post-handshake message. Not yet threaded through `EncryptedRatchetMessage` /
/// `wire_payload.rs` (see rollout plan) — for now this is the boundary type
/// between `internals.rs`'s protocol logic and that future wire integration.
#[allow(dead_code)] // constructed/matched by internals.rs, exercised by unit tests today
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqRatchetWireField {
    /// Sender generated a fresh ML-KEM-768 keypair (1184-byte public key) and is
    /// initiating a new PQ-ratchet exchange.
    PublicKey(Vec<u8>),
    /// Sender is completing an exchange the recipient previously initiated
    /// (1088-byte ML-KEM-768 ciphertext).
    Ciphertext(Vec<u8>),
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Derive a shared session identifier from the X3DH root key and the two user IDs.
///
/// Both INITIATOR and RESPONDER hold the same `root_key_x3dh` after the X3DH
/// handshake. Running the same HKDF on that shared secret yields an identical
/// 16-byte `session_id` on both sides **without any extra round-trip**.
///
/// The result is hex-encoded (32 hex chars) so it can be stored in
/// `SerializableSession.session_id` as a plain string without format changes.
///
/// Used as additional context in Associated Data (AD) of every AEAD message,
/// binding ciphertexts to the specific session they were created in.
///
/// ## Cross-user collision defence (v2)
///
/// Including the sorted user IDs in the HKDF `info` field ensures that even
/// if two different user pairs accidentally derived the same X3DH root key
/// (statistically negligible but theoretically possible), their session IDs
/// would still differ.  The IDs are sorted lexicographically so that
/// INITIATOR (`local=A, contact=B`) and RESPONDER (`local=B, contact=A`)
/// produce identical info bytes without a round-trip.
///
/// Format: `"Construct-SessionID-v2\x00" || min_id || "\x00" || max_id`
/// (null bytes are safe delimiters; server UUIDs never contain them)
fn derive_shared_session_id<P: CryptoProvider>(
    root_key_x3dh: &[u8],
    local_user_id: &str,
    contact_id: &str,
) -> Result<String, String> {
    // Sort IDs so INITIATOR (local=A,contact=B) and RESPONDER (local=B,contact=A)
    // produce the same info bytes.
    let (first, second) = if local_user_id <= contact_id {
        (local_user_id, contact_id)
    } else {
        (contact_id, local_user_id)
    };
    // info = domain || \0 || id_a || \0 || id_b
    let mut info = b"Construct-SessionID-v2\x00".to_vec();
    info.extend_from_slice(first.as_bytes());
    info.push(0x00);
    info.extend_from_slice(second.as_bytes());

    // HKDF(salt=root_key_x3dh, ikm=static-label, info=domain+ids, len=16)
    let bytes = P::hkdf_derive_key(root_key_x3dh, b"construct-session-id", &info, 16)
        .map_err(|e| format!("Failed to derive shared session_id: {e}"))?;
    Ok(hex::encode(&bytes))
}

/// Double Ratchet Session
///
/// Хранит состояние Double Ratchet для обмена сообщениями с одним контактом.
///
/// ## State Components
///
/// ### Root Key
/// - Обновляется при каждом DH ratchet step
/// - Источник для derivation chain keys
///
/// ### Chain Keys
/// - `sending_chain_key`: Для шифрования исходящих сообщений
/// - `receiving_chain_key`: Для расшифровки входящих сообщений
/// - Обновляются при каждом сообщении
///
/// ### DH Ratchet Keys
/// - `dh_ratchet_private`: Наш текущий DH private key
/// - `dh_ratchet_public`: Наш текущий DH public key (отправляется в сообщениях)
/// - `remote_dh_public`: Последний известный DH public key собеседника
///
/// ### Skipped Message Keys
/// - Ключи для out-of-order сообщений
/// - Имеют timestamp для cleanup
pub struct DoubleRatchetSession<P: CryptoProvider> {
    suite_id: SuiteID,
    root_key: P::AeadKey,

    sending_chain_key: P::AeadKey,
    sending_chain_length: u32,

    receiving_chain_key: P::AeadKey,
    receiving_chain_length: u32,

    dh_ratchet_private: Option<P::KemPrivateKey>,
    dh_ratchet_public: P::KemPublicKey,
    remote_dh_public: Option<P::KemPublicKey>,

    previous_sending_length: u32,
    skipped_message_keys: HashMap<(Vec<u8>, u32), P::AeadKey>,
    skipped_key_timestamps: HashMap<(Vec<u8>, u32), u64>,

    /// RESPONDER-only: root key after the first DH ratchet, before the second.
    /// Used by `apply_pq_contribution` to apply PQ at a point where both sides
    /// have the same root key (RK1), ensuring symmetric PQXDH derivation.
    /// Consumed (set to None) after PQ is applied.
    pre_pq_root_key: Option<P::AeadKey>,

    /// Sparse continuous PQ ratchet (suite_id = `PQ_RATCHET`) — see
    /// `internals::perform_pq_ratchet_step`. Number of DH-ratchet turns since the
    /// last ML-KEM-768 mix-in. Only consulted when `suite_id.is_pq_ratchet()`.
    pq_turns_since_mix: u32,

    /// Our locally-generated ML-KEM-768 keypair, `Some` while we're waiting for the
    /// peer's ciphertext reply to complete a PQ-ratchet exchange we initiated.
    pending_pq_ratchet_keypair: Option<PqRatchetKeyPair>,

    /// A ciphertext we derived (as the encapsulating peer) that we keep re-attaching
    /// to outgoing messages until the peer's next DH-ratchet turn implicitly
    /// acknowledges receipt (see `perform_pq_ratchet_step`).
    pending_pq_ciphertext_to_send: Option<Vec<u8>>,

    /// Unix timestamp when `pending_pq_ratchet_keypair`/`pending_pq_ciphertext_to_send`
    /// was first set — bounds how long we keep resending before giving up on a peer
    /// that's gone silent (reuses `max_skipped_message_age_seconds` as the cutoff).
    pq_pending_since: u64,

    session_id: String,
    contact_id: String,
    local_user_id: String,

    /// Unix timestamp of the last DH ratchet step (or session creation).
    /// Updated by `perform_dh_ratchet` and set in `new_initiator_session` / `new_responder_session`.
    last_ratchet_at: u64,
}

/// Snapshot of mutable session fields captured before a DH ratchet in `decrypt()`.
/// If AEAD decryption fails, the snapshot is restored to prevent permanent session corruption.
struct DecryptSnapshot<P: CryptoProvider> {
    root_key: P::AeadKey,
    sending_chain_key: P::AeadKey,
    sending_chain_length: u32,
    receiving_chain_key: P::AeadKey,
    receiving_chain_length: u32,
    dh_ratchet_private: Option<P::KemPrivateKey>,
    dh_ratchet_public: P::KemPublicKey,
    remote_dh_public: Option<P::KemPublicKey>,
    previous_sending_length: u32,
    skipped_message_keys: HashMap<(Vec<u8>, u32), P::AeadKey>,
    skipped_key_timestamps: HashMap<(Vec<u8>, u32), u64>,
    pq_turns_since_mix: u32,
    pending_pq_ratchet_keypair: Option<PqRatchetKeyPair>,
    pending_pq_ciphertext_to_send: Option<Vec<u8>>,
    pq_pending_since: u64,
}

impl<P: CryptoProvider> Clone for DecryptSnapshot<P> {
    fn clone(&self) -> Self {
        Self {
            root_key: self.root_key.clone(),
            sending_chain_key: self.sending_chain_key.clone(),
            sending_chain_length: self.sending_chain_length,
            receiving_chain_key: self.receiving_chain_key.clone(),
            receiving_chain_length: self.receiving_chain_length,
            dh_ratchet_private: self.dh_ratchet_private.clone(),
            dh_ratchet_public: self.dh_ratchet_public.clone(),
            remote_dh_public: self.remote_dh_public.clone(),
            previous_sending_length: self.previous_sending_length,
            skipped_message_keys: self.skipped_message_keys.clone(),
            skipped_key_timestamps: self.skipped_key_timestamps.clone(),
            pq_turns_since_mix: self.pq_turns_since_mix,
            pending_pq_ratchet_keypair: self.pending_pq_ratchet_keypair.clone(),
            pending_pq_ciphertext_to_send: self.pending_pq_ciphertext_to_send.clone(),
            pq_pending_since: self.pq_pending_since,
        }
    }
}

/// Encrypted message in wire format
///
/// Содержит всё необходимое для расшифровки:
/// - DH public key для ratcheting
/// - Message number для key derivation
/// - Ciphertext с authentication tag
/// - Nonce для AEAD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRatchetMessage {
    pub dh_public_key: [u8; 32],
    pub message_number: u32,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub previous_chain_length: u32,
    pub suite_id: u16,
    /// PQ ratchet field for SuiteID::PQ_RATCHET=3 (sparse continuous). None for other suites.
    /// Present only on messages carrying a PQ exchange (pub or ct). Resent until acked by ratchet advance.
    pub pq_ratchet_field: Option<PqRatchetWireField>,
}

impl<P: CryptoProvider> Drop for DoubleRatchetSession<P> {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.sending_chain_key.zeroize();
        self.receiving_chain_key.zeroize();
        if let Some(k) = self.dh_ratchet_private.as_mut() {
            k.zeroize();
        }
        if let Some(k) = self.pre_pq_root_key.as_mut() {
            k.zeroize();
        }
        if let Some(kp) = self.pending_pq_ratchet_keypair.as_mut() {
            kp.zeroize();
        }
        for key in self.skipped_message_keys.values_mut() {
            key.zeroize();
        }
    }
}
