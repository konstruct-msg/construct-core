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
            prekey_header: self
                .prekey_header
                .as_ref()
                .map(|h| SerializablePrekeyHeader {
                    one_time_prekey_id: h.one_time_prekey_id,
                    kyber_prekey_id: h.kyber_prekey_id,
                    kem_ciphertext: h.kem_ciphertext.clone(),
                    kem_identity: h.kem_identity.clone(),
                }),
            pq_handshake: Some(self.pq_handshake.as_u8()),
            session_id: self.session_id.clone(),
            contact_id: self.contact_id.clone(),
            local_user_id: self.local_user_id.clone(),
            last_ratchet_at: self.last_ratchet_at,
            pq_authentication: self.pq_authentication.as_u8(),
            pq_applied: self.pq_applied,
            identity_proof_awaiting: self.identity_proof == IdentityProof::AwaitingAnswer,
            identity_proof_ciphertext: match &self.identity_proof {
                IdentityProof::Answered { ciphertext } => Some(ciphertext.clone()),
                _ => None,
            },
            pq_ratchet: if self.suite_id.is_pq_ratchet() {
                Some(SerializablePqRatchetState {
                    is_initiator: self.is_pq_initiator,
                    current_epoch: self.current_pq_epoch,
                    chains: self
                        .pq_chains
                        .iter()
                        .map(SerializablePqEpochChains::from)
                        .collect(),
                    skipped: {
                        let mut skipped: Vec<_> = self
                            .pq_skipped_keys
                            .iter()
                            .map(|(&(epoch, index), key)| SerializablePqSkippedKey {
                                epoch,
                                index,
                                key: key.clone(),
                                at: self
                                    .pq_skipped_key_timestamps
                                    .get(&(epoch, index))
                                    .copied()
                                    .unwrap_or(0),
                            })
                            .collect();
                        skipped.sort_by_key(|s| (s.epoch, s.index));
                        skipped
                    },
                    pending_exchange: self.pending_pq_exchange.as_ref().map(|ex| {
                        SerializablePqPendingExchange {
                            epoch: ex.epoch,
                            public: ex.keypair.public.clone(),
                            secret: ex.keypair.secret.clone(),
                        }
                    }),
                    pending_ciphertext: self.pending_pq_ciphertext.as_ref().map(|p| {
                        SerializablePqPendingCiphertext {
                            epoch: p.epoch,
                            ek_hash: p.ek_hash.to_vec(),
                            ciphertext: p.ciphertext.clone(),
                            chains: SerializablePqEpochChains::from(&p.chains),
                        }
                    }),
                    pending_since: self.pq_pending_since,
                    turns_since_mix: self.pq_turns_since_mix,
                })
            } else {
                None
            },
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
            prekey_header: data.prekey_header.as_ref().map(|h| PrekeyHeader {
                one_time_prekey_id: h.one_time_prekey_id,
                kyber_prekey_id: h.kyber_prekey_id,
                kem_ciphertext: h.kem_ciphertext.clone(),
                kem_identity: h.kem_identity.clone(),
            }),
            pq_handshake: data
                .pq_handshake
                .map(PqHandshake::from_u8)
                .unwrap_or_else(|| PqHandshake::legacy(data.pq_applied)),
            // PQ ratchet state is restored below from `data.pq_ratchet` after
            // validation; defaults here cover non-PQ-ratchet sessions and blobs
            // whose PQ state fails validation (degrade-not-fail).
            pq_turns_since_mix: 0,
            is_pq_initiator: false,
            current_pq_epoch: 0,
            pq_chains: Vec::new(),
            pq_skipped_keys: HashMap::new(),
            pq_skipped_key_timestamps: HashMap::new(),
            pending_pq_exchange: None,
            pending_pq_ciphertext: None,
            pq_pending_since: 0,
            session_id: data.session_id.clone(),
            contact_id: data.contact_id.clone(),
            local_user_id: data.local_user_id.clone(),
            last_ratchet_at: data.last_ratchet_at,
            pq_authentication: PqAuthentication::from_u8(data.pq_authentication),
            pq_applied: data.pq_applied,
            // Both set is not a state the ratchet produces; the answer wins, since dropping it
            // would leave the initiator unable to read the reply.
            identity_proof: match (
                &data.identity_proof_ciphertext,
                data.identity_proof_awaiting,
            ) {
                (Some(ciphertext), _) => IdentityProof::Answered {
                    ciphertext: ciphertext.clone(),
                },
                (None, true) => IdentityProof::AwaitingAnswer,
                (None, false) => IdentityProof::None,
            },
        };

        session.restore_pq_ratchet_state(&data);

        // Evict any stale skipped-message keys that accumulated while the session was
        // inactive.  Without this, a session that was dormant for weeks would still
        // carry expired keys in memory until the next 100-message boundary.
        session.cleanup_old_skipped_keys_default();

        Ok(session)
    }

    /// Restore the sparse-PQ-ratchet sub-state from a serialized session.
    ///
    /// Degrade-not-fail: a structurally invalid PQ state (corrupted blob) is
    /// dropped with a warning instead of failing the whole session restore —
    /// losing one feature's state beats losing the session. The degraded
    /// session still decrypts epoch-0 traffic; peer messages tagged with a PQ
    /// epoch then fail loudly at decrypt ("epoch secret unavailable") rather
    /// than silently skipping the mix.
    fn restore_pq_ratchet_state(&mut self, data: &SerializableSession) {
        if !self.suite_id.is_pq_ratchet() {
            if data.pq_ratchet.is_some() {
                tracing::warn!(
                    target: "crypto::double_ratchet",
                    "ignoring PQ ratchet state on a non-PQ-ratchet session blob"
                );
            }
            return;
        }
        let Some(pq) = &data.pq_ratchet else {
            tracing::warn!(
                target: "crypto::double_ratchet",
                "PQ-ratchet session blob without PQ ratchet state (pre-persistence \
                 build?) — PQ state reset; peer messages tagged with an epoch \
                 will not decrypt"
            );
            return;
        };
        if let Err(e) = validate_pq_ratchet_state(pq) {
            tracing::warn!(
                target: "crypto::double_ratchet",
                "dropping invalid persisted PQ ratchet state: {e}"
            );
            return;
        }

        self.is_pq_initiator = pq.is_initiator;
        self.current_pq_epoch = pq.current_epoch;
        self.pq_chains = pq.chains.iter().map(PqEpochChains::from).collect();
        for s in &pq.skipped {
            self.pq_skipped_keys
                .insert((s.epoch, s.index), s.key.clone());
            self.pq_skipped_key_timestamps
                .insert((s.epoch, s.index), s.at);
        }
        self.pending_pq_exchange = pq.pending_exchange.as_ref().map(|ex| PendingPqExchange {
            epoch: ex.epoch,
            keypair: PqRatchetKeyPair {
                public: ex.public.clone(),
                secret: ex.secret.clone(),
            },
        });
        self.pending_pq_ciphertext = pq.pending_ciphertext.as_ref().map(|p| {
            let mut ek_hash = [0u8; 8];
            ek_hash.copy_from_slice(&p.ek_hash); // length validated above
            PendingPqCiphertext {
                epoch: p.epoch,
                ek_hash,
                ciphertext: p.ciphertext.clone(),
                chains: PqEpochChains::from(&p.chains),
            }
        });
        self.pq_pending_since = pq.pending_since;
        self.pq_turns_since_mix = pq.turns_since_mix;
    }
}

/// ML-KEM-768 material sizes (bytes) — used to validate restored PQ state.
const MLKEM768_PUBLIC_LEN: usize = 1184;
const MLKEM768_SECRET_LEN: usize = 2400;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// A PQ chain key and a key it yields are 32 bytes (`pq_chain_step`).
const PQ_CHAIN_KEY_LEN: usize = 32;

/// Structural validation of a persisted PQ ratchet state. These are invariants
/// the runtime state machine maintains by construction; a blob violating them
/// is corrupted (or from an incompatible future format) and must not be
/// applied, since bad epoch secrets produce undecryptable messages anyway.
fn validate_pq_ratchet_state(pq: &SerializablePqRatchetState) -> Result<(), String> {
    if pq.chains.len() > PQ_CHAIN_RETENTION {
        return Err(format!(
            "{} epochs' chains exceed retention bound {PQ_CHAIN_RETENTION}",
            pq.chains.len()
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for chains in &pq.chains {
        let epoch = chains.epoch;
        if epoch == 0 || epoch > pq.current_epoch {
            return Err(format!(
                "epoch chains id {epoch} outside (0, current={}]",
                pq.current_epoch
            ));
        }
        validate_pq_epoch_chains(chains)?;
        // Only the current epoch still sends.
        if chains.send.is_some() && epoch != pq.current_epoch {
            return Err(format!(
                "epoch {epoch} keeps a send chain behind current {}",
                pq.current_epoch
            ));
        }
        if !seen.insert(epoch) {
            return Err(format!("duplicate epoch chains id {epoch}"));
        }
    }
    if pq.current_epoch > 0
        && !pq
            .chains
            .iter()
            .any(|c| c.epoch == pq.current_epoch && c.send.is_some())
    {
        return Err(format!(
            "current epoch {} has no send chain",
            pq.current_epoch
        ));
    }
    if pq.skipped.len() > crate::config::Config::global().max_skipped_messages as usize {
        return Err(format!(
            "{} skipped PQ keys exceed the skipped-key bound",
            pq.skipped.len()
        ));
    }
    if let Some(bad) = pq.skipped.iter().find(|s| s.key.len() != PQ_CHAIN_KEY_LEN) {
        return Err(format!(
            "skipped PQ key {}/{} is {} bytes",
            bad.epoch,
            bad.index,
            bad.key.len()
        ));
    }
    if let Some(ex) = &pq.pending_exchange {
        // The initiator only ever proposes current + 1 (single exchange in flight).
        if ex.epoch != pq.current_epoch.saturating_add(1) {
            return Err(format!(
                "pending exchange epoch {} != current {} + 1",
                ex.epoch, pq.current_epoch
            ));
        }
        if ex.public.len() != MLKEM768_PUBLIC_LEN || ex.secret.len() != MLKEM768_SECRET_LEN {
            return Err(format!(
                "pending exchange key sizes {}/{} invalid",
                ex.public.len(),
                ex.secret.len()
            ));
        }
    }
    if let Some(ct) = &pq.pending_ciphertext {
        // Provisional epochs are strictly ahead of the promoted one.
        if ct.epoch <= pq.current_epoch {
            return Err(format!(
                "pending ciphertext epoch {} not ahead of current {}",
                ct.epoch, pq.current_epoch
            ));
        }
        if ct.ek_hash.len() != 8 {
            return Err(format!("ek_hash is {} bytes, expected 8", ct.ek_hash.len()));
        }
        if ct.ciphertext.len() != MLKEM768_CIPHERTEXT_LEN {
            return Err(format!(
                "pending ciphertext is {} bytes",
                ct.ciphertext.len()
            ));
        }
        if ct.chains.epoch != ct.epoch {
            return Err(format!(
                "pending ciphertext epoch {} carries chains of epoch {}",
                ct.epoch, ct.chains.epoch
            ));
        }
        validate_pq_epoch_chains(&ct.chains)?;
    }
    // A pending exchange and a pending ciphertext are mutually exclusive by
    // the single-initiator discipline (initiator holds only exchanges,
    // responder only ciphertexts).
    if pq.pending_exchange.is_some() && pq.pending_ciphertext.is_some() {
        return Err("both pending exchange and pending ciphertext present".to_string());
    }
    Ok(())
}

fn validate_pq_epoch_chains(chains: &SerializablePqEpochChains) -> Result<(), String> {
    let lengths = std::iter::once(&chains.recv).chain(chains.send.as_ref());
    for chain in lengths {
        if chain.key.len() != PQ_CHAIN_KEY_LEN {
            return Err(format!(
                "epoch {} chain key is {} bytes",
                chains.epoch,
                chain.key.len()
            ));
        }
    }
    Ok(())
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SerializablePrekeyHeader {
    one_time_prekey_id: u32,
    kyber_prekey_id: u32,
    kem_ciphertext: Vec<u8>,
    #[serde(default)]
    kem_identity: Vec<u8>,
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
    /// INITIATOR: the handshake header the first flight repeats (`PrekeyHeader`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prekey_header: Option<SerializablePrekeyHeader>,
    /// `PqHandshake::as_u8`; absent on sessions recorded before it (derived from `pq_applied`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pq_handshake: Option<u8>,
    session_id: String,
    contact_id: String,
    #[serde(default)]
    local_user_id: String,
    /// Unix timestamp of the last DH ratchet step. Zero means unknown (old sessions).
    #[serde(default)]
    last_ratchet_at: u64,
    /// `PqAuthentication::as_u8`; 0 (`Unknown`) for sessions recorded before it existed.
    #[serde(default)]
    pq_authentication: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pq_applied: Option<bool>,
    /// `IdentityProof::AwaitingAnswer` (initiator).
    #[serde(default)]
    identity_proof_awaiting: bool,
    /// `IdentityProof::Answered` (responder): the ciphertext carried until the initiator proves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_proof_ciphertext: Option<Vec<u8>>,
    /// Sparse continuous PQ ratchet (suite 4) sub-state — epoch chains, per-message
    /// keys (PQR-2). Present only for PQ-ratchet sessions. Mirrors
    /// `CfeSessionStateV1.pqr` 1:1; see that type for field-level docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pq_ratchet: Option<SerializablePqRatchetState>,
}

/// JSON-side mirror of `CfePqRatchetStateV2` (see `cfe/types.rs` for the field
/// semantics and why `pending_ciphertext` must be persisted). Secrets are
/// zeroized on drop.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SerializablePqRatchetState {
    pub(crate) is_initiator: bool,
    pub(crate) current_epoch: u32,
    #[serde(default)]
    pub(crate) chains: Vec<SerializablePqEpochChains>,
    #[serde(default)]
    pub(crate) skipped: Vec<SerializablePqSkippedKey>,
    #[serde(default)]
    pub(crate) pending_exchange: Option<SerializablePqPendingExchange>,
    #[serde(default)]
    pub(crate) pending_ciphertext: Option<SerializablePqPendingCiphertext>,
    #[serde(default)]
    pub(crate) pending_since: u64,
    #[serde(default)]
    pub(crate) turns_since_mix: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SerializablePqChain {
    pub(crate) index: u32,
    pub(crate) key: Vec<u8>,
}

impl Drop for SerializablePqChain {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SerializablePqEpochChains {
    pub(crate) epoch: u32,
    #[serde(default)]
    pub(crate) send: Option<SerializablePqChain>,
    pub(crate) recv: SerializablePqChain,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SerializablePqSkippedKey {
    pub(crate) epoch: u32,
    pub(crate) index: u32,
    pub(crate) key: Vec<u8>,
    pub(crate) at: u64,
}

impl Drop for SerializablePqSkippedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl From<&PqEpochChains> for SerializablePqEpochChains {
    fn from(c: &PqEpochChains) -> Self {
        let chain = |ch: &PqChain| SerializablePqChain {
            index: ch.index,
            key: ch.key.clone(),
        };
        Self {
            epoch: c.epoch,
            send: c.send.as_ref().map(chain),
            recv: chain(&c.recv),
        }
    }
}

impl From<&SerializablePqEpochChains> for PqEpochChains {
    fn from(c: &SerializablePqEpochChains) -> Self {
        let chain = |ch: &SerializablePqChain| PqChain {
            index: ch.index,
            key: ch.key.clone(),
        };
        Self {
            epoch: c.epoch,
            send: c.send.as_ref().map(chain),
            recv: chain(&c.recv),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SerializablePqPendingExchange {
    pub(crate) epoch: u32,
    pub(crate) public: Vec<u8>,
    pub(crate) secret: Vec<u8>,
}

impl Drop for SerializablePqPendingExchange {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SerializablePqPendingCiphertext {
    pub(crate) epoch: u32,
    pub(crate) ek_hash: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) chains: SerializablePqEpochChains,
}

impl Drop for SerializableSession {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.sending_chain_key.zeroize();
        self.receiving_chain_key.zeroize();
        if let Some(ref mut k) = self.dh_ratchet_private {
            k.zeroize();
        }
        for entry in &mut self.skipped_keys {
            entry.key_bytes.zeroize();
        }
    }
}

/// First 8 characters of an identifier, for diagnostics that must not carry the whole value.
/// Indexed by `char_indices` rather than by byte, so a non-ASCII id cannot panic the error path.
///
/// Shared across the module rather than re-written per call site: a second truncation helper is a
/// second answer to "how much of an identifier may a log carry", and the two would drift.
pub(super) fn id_prefix(id: &str) -> &str {
    let end = id.char_indices().nth(8).map_or(id.len(), |(i, _)| i);
    &id[..end]
}

impl SerializableSession {
    /// Check that this record is the session the caller believes it is loading.
    ///
    /// The identity of a session — who it is with, and who we were when it was made — is
    /// written *inside* the record (`contact_id` / `local_uid` in `CfeSessionStateV1`), but
    /// every import path also takes a `contact_id` argument and, until 2026-08-26, silently let
    /// the argument win. A blob stored under one name and loaded under another was imported
    /// without complaint: the caller's name went into the AD, the record's ratchet state went
    /// behind it, and nothing compared the two. That does not fail at import. It fails later,
    /// as a permanent AEAD error on a session healthy by every other measure — which is how
    /// per-device sessions spent months unable to open, the sender addressing a device as
    /// `<uuid>:<hex>` while the receiver's own `local_user_id` stayed a bare UUID.
    ///
    /// `try_aead_decrypt` already carries a comment predicting exactly this mismatch. It could
    /// only report it after the fact, from the far side of a failed decrypt; this reports it at
    /// the moment the wrong name is applied, which is the moment someone can act on it.
    ///
    /// An empty field on either side means "this predates the field", not "this belongs to
    /// someone else": `local_user_id` carries `#[serde(default)]` for legacy JSON blobs, and
    /// the core's own id is empty until `set_local_user_id` runs. Those are skipped with a
    /// warning — rejecting them would discard live ratchet state to enforce a comparison that
    /// cannot conclude anything. `contact_id` has no default and is always compared.
    ///
    /// Diagnostics carry an 8-character prefix and a length, never the whole identifier: a
    /// mismatch is precisely the case where both ids would otherwise be written to a log.
    pub fn verify_identity(
        &self,
        expected_contact_id: &str,
        expected_local_user_id: &str,
    ) -> Result<(), String> {
        if self.contact_id != expected_contact_id {
            return Err(format!(
                "session identity mismatch: record is for contact {}… ({} chars), loaded as {}… ({} chars)",
                id_prefix(&self.contact_id),
                self.contact_id.len(),
                id_prefix(expected_contact_id),
                expected_contact_id.len(),
            ));
        }

        if self.local_user_id.is_empty() || expected_local_user_id.is_empty() {
            tracing::warn!(
                target: "crypto::double_ratchet",
                record_local_uid_len = %self.local_user_id.len(),
                expected_local_uid_len = %expected_local_user_id.len(),
                "session identity: local_user_id unverifiable (empty on one side) — importing anyway"
            );
            return Ok(());
        }

        if self.local_user_id != expected_local_user_id {
            return Err(format!(
                "session identity mismatch: record was made by {}… ({} chars), importing as {}… ({} chars)",
                id_prefix(&self.local_user_id),
                self.local_user_id.len(),
                id_prefix(expected_local_user_id),
                expected_local_user_id.len(),
            ));
        }

        Ok(())
    }

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
            rk: crate::crypto::SecretBytes::from(self.root_key.clone()),
            sck: crate::crypto::SecretBytes::from(self.sending_chain_key.clone()),
            rck: crate::crypto::SecretBytes::from(self.receiving_chain_key.clone()),
            scl: self.sending_chain_length,
            rcl: self.receiving_chain_length,
            psl: self.previous_sending_length,
            dh_priv: self
                .dh_ratchet_private
                .clone()
                .map(crate::crypto::SecretBytes::from),
            dh_pub: ByteBuf::from(self.dh_ratchet_public.clone()),
            rdh_pub: self.remote_dh_public.clone().map(ByteBuf::from),
            skipped: self
                .skipped_keys
                .iter()
                .map(|e| crate::cfe::CfeSkippedKeyEntryV1 {
                    dh_pub: ByteBuf::from(e.dh_public.clone()),
                    msg_number: e.msg_number,
                    key_bytes: crate::crypto::SecretBytes::from(e.key_bytes.clone()),
                    timestamp: e.timestamp,
                })
                .collect(),
            prekey_header: self
                .prekey_header
                .as_ref()
                .map(|h| crate::cfe::CfePrekeyHeaderV1 {
                    one_time_prekey_id: h.one_time_prekey_id,
                    kyber_prekey_id: h.kyber_prekey_id,
                    kem_ciphertext: ByteBuf::from(h.kem_ciphertext.clone()),
                    kem_identity: ByteBuf::from(h.kem_identity.clone()),
                }),
            pq_handshake: self.pq_handshake,
            last_ratchet_at: self.last_ratchet_at,
            pq_authentication: self.pq_authentication,
            pq_applied: self.pq_applied,
            identity_proof_awaiting: self.identity_proof_awaiting,
            identity_proof_ciphertext: self.identity_proof_ciphertext.clone().map(ByteBuf::from),
            pqr: self
                .pq_ratchet
                .as_ref()
                .map(|pq| crate::cfe::CfePqRatchetStateV2 {
                    is_initiator: pq.is_initiator,
                    current_epoch: pq.current_epoch,
                    chains: pq.chains.iter().map(cfe_epoch_chains).collect(),
                    skipped: pq
                        .skipped
                        .iter()
                        .map(|s| crate::cfe::CfePqSkippedKeyV2 {
                            epoch: s.epoch,
                            index: s.index,
                            key: crate::crypto::SecretBytes::from(s.key.clone()),
                            at: s.at,
                        })
                        .collect(),
                    pending_exchange: pq.pending_exchange.as_ref().map(|ex| {
                        crate::cfe::CfePqPendingExchangeV1 {
                            epoch: ex.epoch,
                            public: ByteBuf::from(ex.public.clone()),
                            secret: crate::crypto::SecretBytes::from(ex.secret.clone()),
                        }
                    }),
                    pending_ciphertext: pq.pending_ciphertext.as_ref().map(|p| {
                        crate::cfe::CfePqPendingCiphertextV2 {
                            epoch: p.epoch,
                            ek_hash: ByteBuf::from(p.ek_hash.clone()),
                            ciphertext: ByteBuf::from(p.ciphertext.clone()),
                            chains: cfe_epoch_chains(&p.chains),
                        }
                    }),
                    pending_since: pq.pending_since,
                    turns_since_mix: pq.turns_since_mix,
                }),
            // The ratchet knows only itself; the record's previous states are the lifecycle
            // manager's, which attaches them (`SessionLifecycleManager::export_session_bytes_for`).
            previous: Vec::new(),
            retired: None,
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
            prekey_header: data.prekey_header.map(|h| SerializablePrekeyHeader {
                one_time_prekey_id: h.one_time_prekey_id,
                kyber_prekey_id: h.kyber_prekey_id,
                kem_ciphertext: h.kem_ciphertext.into_vec(),
                kem_identity: h.kem_identity.into_vec(),
            }),
            pq_handshake: data.pq_handshake,
            session_id: session_id_hex,
            contact_id: data.contact_id,
            local_user_id: data.local_uid,
            last_ratchet_at: data.last_ratchet_at,
            pq_authentication: data.pq_authentication,
            pq_applied: data.pq_applied,
            identity_proof_awaiting: data.identity_proof_awaiting,
            identity_proof_ciphertext: data.identity_proof_ciphertext.map(|b| b.into_vec()),
            // Secrets leave `SecretBytes` here: `SerializableSession` still holds plain `Vec`s.
            pq_ratchet: data.pqr.map(|pq| SerializablePqRatchetState {
                is_initiator: pq.is_initiator,
                current_epoch: pq.current_epoch,
                chains: pq.chains.iter().map(serializable_epoch_chains).collect(),
                skipped: pq
                    .skipped
                    .iter()
                    .map(|s| SerializablePqSkippedKey {
                        epoch: s.epoch,
                        index: s.index,
                        key: s.key.expose().to_vec(),
                        at: s.at,
                    })
                    .collect(),
                pending_exchange: pq.pending_exchange.as_ref().map(|ex| {
                    SerializablePqPendingExchange {
                        epoch: ex.epoch,
                        public: ex.public.to_vec(),
                        secret: ex.secret.expose().to_vec(),
                    }
                }),
                pending_ciphertext: pq.pending_ciphertext.as_ref().map(|p| {
                    SerializablePqPendingCiphertext {
                        epoch: p.epoch,
                        ek_hash: p.ek_hash.to_vec(),
                        ciphertext: p.ciphertext.to_vec(),
                        chains: serializable_epoch_chains(&p.chains),
                    }
                }),
                pending_since: pq.pending_since,
                turns_since_mix: pq.turns_since_mix,
            }),
        })
    }
}

fn cfe_epoch_chains(c: &SerializablePqEpochChains) -> crate::cfe::CfePqEpochChainsV2 {
    let chain = |ch: &SerializablePqChain| crate::cfe::CfePqChainV2 {
        index: ch.index,
        key: crate::crypto::SecretBytes::from(ch.key.clone()),
    };
    crate::cfe::CfePqEpochChainsV2 {
        epoch: c.epoch,
        send: c.send.as_ref().map(chain),
        recv: chain(&c.recv),
    }
}

fn serializable_epoch_chains(c: &crate::cfe::CfePqEpochChainsV2) -> SerializablePqEpochChains {
    let chain = |ch: &crate::cfe::CfePqChainV2| SerializablePqChain {
        index: ch.index,
        key: ch.key.expose().to_vec(),
    };
    SerializablePqEpochChains {
        epoch: c.epoch,
        send: c.send.as_ref().map(chain),
        recv: chain(&c.recv),
    }
}
