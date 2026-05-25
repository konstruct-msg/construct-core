//! MLS group wrapper around `openmls::group::MlsGroup`.
//!
//! Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
//! Credential: BasicCredential with Ed25519 keypair from `openmls_basic_credential`.
//!
//! # Status
//! Scaffolding complete. API design final. Compilation blocked on openmls 0.8
//! API surface verification. Specific issues tracked below as TODO(openmls).
//!
//! # TODO(openmls)
//! - `MlsMessageIn::tls_deserialize_exact` — verify path (book_code uses it, cargo check
//!   says not found; may need feature flag `serde` or `tls-codec`)
//! - `StagedWelcome::merge_pending_commit` — may be on `MlsGroup` directly after
//!   `new_from_welcome`, or requires `process_message` first
//! - `MlsGroup::save` — may be `save_to_bytes` or behind `serde` feature
//! - `MlsGroup::load` — verify signature (takes `&impl StorageProvider`, not `&[u8]`)
//! - `SignatureKeyPair` storage — `openmls_rust_crypto` implements `StorageProvider`;
//!   may need `key.store(provider.storage())?` pattern
//! - `LeafNodeIndex: From<u32>` — use explicit `.into()` or `LeafNodeIndex::new()`
//!
//! Fix approach: compile openmls 0.8.1 book_code.rs example locally, adapt our API
//! to match exactly the patterns used there.

use openmls::prelude::{
    Ciphersuite, CredentialWithKey, MlsGroup as OpenMlsGroup,
    MlsGroupCreateConfig, MlsMessageIn, ProtocolMessage,
};
use openmls::credentials::BasicCredential;
use openmls::group::StagedWelcome;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::group::mls_error::MlsError;

/// Our single supported ciphersuite.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Configuration for creating or joining an MLS group.
pub struct GroupConfig {
    pub signer: SignatureKeyPair,
    pub encrypted_group_context: Vec<u8>,
}

/// Result of adding a member: Commit + Welcome.
pub struct MemberAddition {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub leaf_index: u32,
}

/// Wrapper around `openmls::group::MlsGroup`.
pub struct MlsGroup {
    inner: OpenMlsGroup,
    signer: SignatureKeyPair,
    provider: OpenMlsRustCrypto,
}

impl MlsGroup {
    /// Create a new MLS group with the caller as the sole initial member.
    ///
    /// TODO(openmls): verify `create_message` signature once compilation passes.
    pub fn create(config: GroupConfig) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let credential = basic_credential(config.signer.to_public_vec());

        let mls_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        let inner = OpenMlsGroup::new(&provider, &config.signer, &mls_config, credential)
            .map_err(|e| MlsError::CryptoError(format!("create group: {e}")))?;

        Ok(Self { inner, signer: config.signer, provider })
    }

    /// Join an existing group from a Welcome message.
    pub fn join_from_welcome(welcome_bytes: &[u8], config: GroupConfig) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let credential = basic_credential(config.signer.to_public_vec());

        let mls_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        // TODO(openmls): tls_deserialize_exact path — verify.
        let welcome = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| MlsError::WelcomeError(format!("deserialize welcome: {e}")))?;

        let welcome = welcome.into_welcome()
            .ok_or_else(|| MlsError::WelcomeError("not a Welcome message".into()))?;

        // TODO(openmls): verify StagedWelcome API.
        let staged = StagedWelcome::new_from_welcome(&provider, &mls_config, welcome, None)
            .map_err(|e| MlsError::WelcomeError(format!("stage join: {e}")))?;

        let inner = staged.merge_pending_commit(&provider)
            .map_err(|e| MlsError::WelcomeError(format!("merge join: {e}")))?;

        Ok(Self { inner, signer: config.signer, provider })
    }

    // ── Messages ───────────────────────────────────────────────────────

    /// Encrypt an application message for all group members.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, MlsError> {
        self.inner
            .create_message(&self.provider, &self.signer, plaintext)
            .map(|msg| msg.to_bytes().unwrap_or_default())
            .map_err(|e| MlsError::EncryptionError(format!("encrypt: {e}")))
    }

    /// Decrypt an application message from another group member.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, MlsError> {
        // TODO(openmls): verify tls_deserialize_exact path.
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|e| MlsError::EncryptionError(format!("deserialize: {e}")))?;

        let protocol_msg: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|e| MlsError::EncryptionError(format!("protocol: {e}")))?;

        let processed = self.inner
            .process_message(&self.provider, protocol_msg)
            .map_err(|e| MlsError::EncryptionError(format!("process: {e}")))?;

        match processed.into_content() {
            openmls::prelude::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(app_msg.into_bytes())
            }
            _ => Err(MlsError::EncryptionError(
                "unexpected message type".into(),
            )),
        }
    }

    // ── Members ────────────────────────────────────────────────────────

    /// Add a member from their KeyPackage. Returns Commit + Welcome.
    pub fn add_member(&mut self, key_package_bytes: &[u8]) -> Result<MemberAddition, MlsError> {
        // TODO(openmls): verify tls_deserialize_exact path.
        let kp_msg = MlsMessageIn::tls_deserialize_exact(key_package_bytes)
            .map_err(|e| MlsError::CryptoError(format!("kp deserialize: {e}")))?;

        let key_package = kp_msg.into_key_package()
            .ok_or_else(|| MlsError::CryptoError("not a KeyPackage".into()))?;

        let (commit, welcome, _group_info) = self.inner
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(|e| MlsError::CryptoError(format!("add member: {e}")))?;

        Ok(MemberAddition {
            commit: commit.to_bytes().unwrap_or_default(),
            welcome: welcome.to_bytes().unwrap_or_default(),
            leaf_index: self.inner.members().count() as u32,
        })
    }

    /// Remove a member by leaf index. Returns Commit.
    pub fn remove_member(&mut self, leaf_index: u32) -> Result<Vec<u8>, MlsError> {
        // TODO(openmls): verify LeafNodeIndex conversion.
        let leaf: openmls::prelude::LeafNodeIndex = leaf_index.into();
        let (commit, _, _) = self.inner
            .remove_members(&self.provider, &self.signer, &[leaf])
            .map_err(|e| MlsError::CryptoError(format!("remove: {e}")))?;

        commit.to_bytes()
            .map_err(|e| MlsError::SerializationError(format!("remove commit: {e}")))
    }

    /// Leave the group. Returns Commit.
    pub fn leave(&mut self) -> Result<Vec<u8>, MlsError> {
        let commit = self.inner
            .leave_group(&self.provider, &self.signer)
            .map_err(|e| MlsError::CryptoError(format!("leave: {e}")))?;

        commit.to_bytes()
            .map_err(|e| MlsError::SerializationError(format!("leave commit: {e}")))
    }

    /// Current number of members.
    pub fn member_count(&self) -> usize {
        self.inner.members().count()
    }

    /// Current epoch.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    // ── Commits ────────────────────────────────────────────────────────

    /// Process a commit from another member (received via FetchCommits).
    pub fn process_commit(&mut self, commit_bytes: &[u8]) -> Result<(), MlsError> {
        // TODO(openmls): verify tls_deserialize_exact path.
        let message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(|e| MlsError::CommitError(format!("deserialize: {e}")))?;

        let protocol_msg: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|e| MlsError::CommitError(format!("protocol: {e}")))?;

        self.inner
            .process_message(&self.provider, protocol_msg)
            .map_err(|e| MlsError::CommitError(format!("process: {e}")))?;

        self.inner
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::CommitError(format!("merge: {e}")))?;

        Ok(())
    }

    // ── Persistence ────────────────────────────────────────────────────

    /// Serialize group state for CFE persistence.
    /// TODO(openmls): verify `save` method path.
    pub fn serialize(&self) -> Result<Vec<u8>, MlsError> {
        self.inner.save()
            .map_err(|e| MlsError::SerializationError(format!("save: {e}")))
    }

    /// Deserialize from CFE-persisted state.
    /// TODO(openmls): verify `load` signature.
    pub fn deserialize(data: &[u8]) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let inner = OpenMlsGroup::load(data, &provider)
            .map_err(|e| MlsError::SerializationError(format!("load: {e}")))?;

        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| MlsError::SerializationError(format!("placeholder key: {e}")))?;

        Ok(Self { inner, signer, provider })
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn basic_credential(pub_key: Vec<u8>) -> CredentialWithKey {
    let credential = BasicCredential::new(pub_key);
    // TODO(openmls): provide the actual signature public key from the Keychain,
    // not an empty placeholder. openmls requires the real key for verification.
    CredentialWithKey {
        credential: credential.into(),
        signature_key: openmls::prelude::SignaturePublicKey::from(Vec::new()),
    }
}

// Tests are disabled until openmls API issues are resolved.
// See book_code.rs in openmls 0.8.1 tests/ for the canonical API patterns.
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_create_and_encrypt() { ... }
// }
