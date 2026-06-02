//! MLS group wrapper around `openmls::group::MlsGroup`.
//!
//! Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
//! Credential: BasicCredential with Ed25519 keypair from `openmls_basic_credential`.

use openmls::credentials::BasicCredential;
use openmls::group::StagedWelcome;
use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::{
    Ciphersuite, CredentialWithKey, MlsGroup as OpenMlsGroup, MlsGroupCreateConfig,
    MlsGroupJoinConfig, MlsMessageIn, ProtocolMessage,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::group::mls_error::MlsError;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub struct GroupConfig {
    pub signer_private_key: Vec<u8>,
    pub signer_public_key: Vec<u8>,
    pub encrypted_group_context: Vec<u8>,
}

pub struct MemberAddition {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub leaf_index: u32,
}

pub struct MlsGroup {
    inner: OpenMlsGroup,
    signer: SignatureKeyPair,
    provider: OpenMlsRustCrypto,
}

fn make_signer(config: &GroupConfig) -> SignatureKeyPair {
    SignatureKeyPair::from_raw(
        CIPHERSUITE.signature_algorithm(),
        config.signer_private_key.clone(),
        config.signer_public_key.clone(),
    )
}

impl MlsGroup {
    // ── Lifecycle ──────────────────────────────────────────────────────

    /// Create a new MLS group. Called from UniFFI as `MlsGroup(config:)`.
    pub fn new(config: GroupConfig) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = make_signer(&config);
        let cwk = make_credential(&signer);

        let mls_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        let inner = OpenMlsGroup::new(&provider, &signer, &mls_config, cwk)
            .map_err(|e| MlsError::CryptoError(format!("create group: {e}")))?;

        Ok(Self {
            inner,
            signer,
            provider,
        })
    }

    /// Join a group from a Welcome message.
    pub fn from_welcome(welcome_bytes: &[u8], config: GroupConfig) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = make_signer(&config);
        let cwk = make_credential(&signer);

        let mls_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let welcome = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| MlsError::WelcomeError(format!("deserialize welcome: {e}")))?;

        let welcome = match welcome.extract() {
            openmls::prelude::MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::WelcomeError("not a Welcome message".into())),
        };

        let staged = StagedWelcome::new_from_welcome(&provider, &mls_config, welcome, None)
            .map_err(|e| MlsError::WelcomeError(format!("stage join: {e}")))?;

        let inner = staged
            .into_group(&provider)
            .map_err(|e| MlsError::WelcomeError(format!("join group: {e}")))?;

        Ok(Self {
            inner,
            signer,
            provider,
        })
    }

    // ── Messages ───────────────────────────────────────────────────────

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, MlsError> {
        self.inner
            .create_message(&self.provider, &self.signer, plaintext)
            .map(|msg| msg.to_bytes().unwrap_or_default())
            .map_err(|e| MlsError::EncryptionError(format!("encrypt: {e}")))
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, MlsError> {
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|e| MlsError::EncryptionError(format!("deserialize: {e}")))?;

        let proto: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|e| MlsError::EncryptionError(format!("protocol: {e}")))?;

        let processed = self
            .inner
            .process_message(&self.provider, proto)
            .map_err(|e| MlsError::EncryptionError(format!("process: {e}")))?;

        match processed.into_content() {
            openmls::prelude::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(app_msg.into_bytes())
            }
            _ => Err(MlsError::EncryptionError("unexpected message type".into())),
        }
    }

    // ── Members ────────────────────────────────────────────────────────

    pub fn add_member(&mut self, key_package_bytes: &[u8]) -> Result<MemberAddition, MlsError> {
        let kp_msg = MlsMessageIn::tls_deserialize_exact(key_package_bytes)
            .map_err(|e| MlsError::CryptoError(format!("kp deserialize: {e}")))?;

        let key_package = kp_msg
            .into_keypackage()
            .ok_or_else(|| MlsError::CryptoError("not a KeyPackage".into()))?;

        let (commit, welcome, _group_info) = self
            .inner
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(|e| MlsError::CryptoError(format!("add member: {e}")))?;

        Ok(MemberAddition {
            commit: commit.to_bytes().unwrap_or_default(),
            welcome: welcome.to_bytes().unwrap_or_default(),
            leaf_index: self.inner.members().count() as u32,
        })
    }

    pub fn remove_member(&mut self, leaf_index: u32) -> Result<Vec<u8>, MlsError> {
        let leaf = openmls::prelude::LeafNodeIndex::new(leaf_index);
        let (commit, _, _) = self
            .inner
            .remove_members(&self.provider, &self.signer, &[leaf])
            .map_err(|e| MlsError::CryptoError(format!("remove: {e}")))?;

        commit
            .to_bytes()
            .map_err(|e| MlsError::SerializationError(format!("remove commit: {e}")))
    }

    pub fn leave_group(&mut self) -> Result<Vec<u8>, MlsError> {
        let commit = self
            .inner
            .leave_group(&self.provider, &self.signer)
            .map_err(|e| MlsError::CryptoError(format!("leave: {e}")))?;

        commit
            .to_bytes()
            .map_err(|e| MlsError::SerializationError(format!("leave commit: {e}")))
    }

    pub fn member_count(&self) -> u32 {
        self.inner.members().count() as u32
    }
    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    // ── Commits ────────────────────────────────────────────────────────

    pub fn process_commit(&mut self, commit_bytes: &[u8]) -> Result<(), MlsError> {
        let message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(|e| MlsError::CommitError(format!("deserialize: {e}")))?;

        let proto: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|e| MlsError::CommitError(format!("protocol: {e}")))?;

        self.inner
            .process_message(&self.provider, proto)
            .map_err(|e| MlsError::CommitError(format!("process: {e}")))?;

        self.inner
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::CommitError(format!("merge: {e}")))?;

        Ok(())
    }

    // ── Persistence (TODO: implement via StorageProvider) ──────────────

    pub fn serialize(&self) -> Result<Vec<u8>, MlsError> {
        Err(MlsError::SerializationError(
            "TODO: openmls persistence".into(),
        ))
    }

    pub fn deserialize(_data: &[u8]) -> Result<Self, MlsError> {
        Err(MlsError::SerializationError(
            "TODO: openmls persistence".into(),
        ))
    }
}

fn make_credential(signer: &SignatureKeyPair) -> CredentialWithKey {
    let pub_key = signer.to_public_vec();
    let credential = BasicCredential::new(pub_key.clone());
    CredentialWithKey {
        credential: credential.into(),
        signature_key: openmls::prelude::SignaturePublicKey::from(pub_key),
    }
}
