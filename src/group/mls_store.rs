//! Device-level MLS store: one long-lived OpenMLS storage per device.
//!
//! OpenMLS persists *everything* through the provider's `StorageProvider`
//! during every operation: group state, ratchet secrets, and — critically —
//! the private init/encryption keys of generated KeyPackages (keyed by the
//! package's hash reference, written by `KeyPackageBuilder::build`). A Welcome
//! can only be decrypted by the storage that generated the KeyPackage it
//! addresses, so per-group throwaway providers (the previous `MlsGroup`
//! wrapper) could create groups but never join one.
//!
//! `MlsStore` therefore owns ONE `OpenMlsRustCrypto` provider for the device:
//!   - `generate_key_package()` writes private material into it,
//!   - `join_from_welcome()` finds that material in it,
//!   - every group is loaded from it by group id (`MlsGroup::load`),
//!   - `export_cfe()` / `import_cfe()` snapshot the whole storage as a
//!     versioned CFE blob (`CfeMlsStoreV1`, msg_type 0x44) that the host app
//!     persists in its secure store, exactly like the other key-state blobs.
//!
//! The Ed25519 signer is NOT part of the blob — it is the device identity
//! key, owned by the platform key store, and is passed back in on import.

use std::collections::HashMap;

use openmls::credentials::BasicCredential;
use openmls::group::StagedWelcome;
use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::{
    Ciphersuite, CredentialWithKey, GroupId, KeyPackage, MlsGroup as OpenMlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageIn, MlsMessageOut, OpenMlsProvider,
    ProtocolMessage,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_bytes::ByteBuf;

use crate::cfe::{self, CfeMessageType, CfeMlsStoreEntryV1, CfeMlsStoreV1};
use crate::group::mls_error::MlsError;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Result of adding a member to a group: broadcast `commit` to current
/// members (via SubmitCommit), send `welcome` to the new member.
pub struct MemberAddition {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    /// Member count after the addition (informational).
    pub member_count: u32,
}

pub struct MlsStore {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    /// Working copies of loaded groups. OpenMLS writes every mutation through
    /// the provider storage, so these are caches, not the source of truth.
    groups: HashMap<Vec<u8>, OpenMlsGroup>,
}

/// Load a group from storage into the working cache (no-op if cached).
/// Free-standing so callers can split-borrow `provider`/`signer` alongside.
fn load_group<'a>(
    provider: &OpenMlsRustCrypto,
    groups: &'a mut HashMap<Vec<u8>, OpenMlsGroup>,
    group_id: &[u8],
) -> Result<&'a mut OpenMlsGroup, MlsError> {
    if !groups.contains_key(group_id) {
        let gid = GroupId::from_slice(group_id);
        let group = OpenMlsGroup::load(provider.storage(), &gid)
            .map_err(|e| MlsError::SerializationError(format!("load group: {e:?}")))?
            .ok_or(MlsError::NotAMember)?;
        groups.insert(group_id.to_vec(), group);
    }
    Ok(groups.get_mut(group_id).expect("just inserted"))
}

impl MlsStore {
    // ── Lifecycle ──────────────────────────────────────────────────────

    /// A fresh store bound to the device's Ed25519 identity keypair.
    pub fn new(signer_private_key: Vec<u8>, signer_public_key: Vec<u8>) -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            signer: SignatureKeyPair::from_raw(
                CIPHERSUITE.signature_algorithm(),
                signer_private_key,
                signer_public_key,
            ),
            groups: HashMap::new(),
        }
    }

    fn credential(&self) -> CredentialWithKey {
        let pub_key = self.signer.to_public_vec();
        CredentialWithKey {
            credential: BasicCredential::new(pub_key.clone()).into(),
            signature_key: openmls::prelude::SignaturePublicKey::from(pub_key),
        }
    }

    // ── Key packages ───────────────────────────────────────────────────

    /// Generate a KeyPackage for publishing to the server (PublishKeyPackage).
    /// The private init/encryption keys are written into this store — the
    /// caller MUST persist the exported CFE blob before uploading the package,
    /// or an inviter's Welcome will reference keys we no longer hold.
    pub fn generate_key_package(&self) -> Result<Vec<u8>, MlsError> {
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential())
            .map_err(|e| MlsError::CryptoError(format!("key package: {e}")))?;

        MlsMessageOut::from(bundle.key_package().clone())
            .to_bytes()
            .map_err(|e| MlsError::SerializationError(format!("key package encode: {e}")))
    }

    // ── Group lifecycle ────────────────────────────────────────────────

    /// Create a new group with this device as the sole member. Returns the
    /// group id (used as the handle for every other group operation).
    pub fn create_group(&mut self) -> Result<Vec<u8>, MlsError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        let group = OpenMlsGroup::new(&self.provider, &self.signer, &config, self.credential())
            .map_err(|e| MlsError::CryptoError(format!("create group: {e}")))?;

        let group_id = group.group_id().as_slice().to_vec();
        self.groups.insert(group_id.clone(), group);
        Ok(group_id)
    }

    /// Join a group from a Welcome message. The KeyPackage the Welcome
    /// addresses must have been generated by THIS store (its private keys
    /// live here). Returns the joined group's id.
    pub fn join_from_welcome(&mut self, welcome_bytes: &[u8]) -> Result<Vec<u8>, MlsError> {
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| MlsError::WelcomeError(format!("deserialize welcome: {e}")))?;

        let welcome = match message.extract() {
            openmls::prelude::MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::WelcomeError("not a Welcome message".into())),
        };

        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|e| MlsError::WelcomeError(format!("stage join: {e}")))?;

        let group = staged
            .into_group(&self.provider)
            .map_err(|e| MlsError::WelcomeError(format!("join group: {e}")))?;

        let group_id = group.group_id().as_slice().to_vec();
        self.groups.insert(group_id.clone(), group);
        Ok(group_id)
    }

    // ── Messages ───────────────────────────────────────────────────────

    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, MlsError> {
        let group = load_group(&self.provider, &mut self.groups, group_id)?;
        group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| MlsError::EncryptionError(format!("encrypt: {e}")))?
            .to_bytes()
            .map_err(|e| MlsError::SerializationError(format!("message encode: {e}")))
    }

    pub fn decrypt(&mut self, group_id: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, MlsError> {
        let proto = parse_protocol_message(ciphertext)
            .map_err(|e| MlsError::EncryptionError(format!("deserialize: {e}")))?;

        let group = load_group(&self.provider, &mut self.groups, group_id)?;
        let processed = group
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

    /// Add a member by their published KeyPackage. Merges the commit locally:
    /// call this only when you are about to SubmitCommit — a server rejection
    /// after the local merge forks the epoch.
    pub fn add_member(
        &mut self,
        group_id: &[u8],
        key_package_bytes: &[u8],
    ) -> Result<MemberAddition, MlsError> {
        let kp_msg = MlsMessageIn::tls_deserialize_exact(key_package_bytes)
            .map_err(|e| MlsError::CryptoError(format!("kp deserialize: {e}")))?;
        let key_package = kp_msg
            .into_keypackage()
            .ok_or_else(|| MlsError::CryptoError("not a KeyPackage".into()))?;

        let group = load_group(&self.provider, &mut self.groups, group_id)?;
        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(|e| MlsError::CryptoError(format!("add member: {e}")))?;

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::CommitError(format!("merge add: {e}")))?;

        Ok(MemberAddition {
            commit: commit
                .to_bytes()
                .map_err(|e| MlsError::SerializationError(format!("add commit: {e}")))?,
            welcome: welcome
                .to_bytes()
                .map_err(|e| MlsError::SerializationError(format!("welcome encode: {e}")))?,
            member_count: group.members().count() as u32,
        })
    }

    /// Remove a member by leaf index. Merges the commit locally (same
    /// SubmitCommit caveat as `add_member`).
    pub fn remove_member(&mut self, group_id: &[u8], leaf_index: u32) -> Result<Vec<u8>, MlsError> {
        let leaf = openmls::prelude::LeafNodeIndex::new(leaf_index);
        let group = load_group(&self.provider, &mut self.groups, group_id)?;

        let (commit, _, _) = group
            .remove_members(&self.provider, &self.signer, &[leaf])
            .map_err(|e| MlsError::CryptoError(format!("remove: {e}")))?;

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::CommitError(format!("merge remove: {e}")))?;

        commit
            .to_bytes()
            .map_err(|e| MlsError::SerializationError(format!("remove commit: {e}")))
    }

    /// Propose leaving. The returned message must be broadcast; another
    /// member's commit actually removes us.
    pub fn leave_group(&mut self, group_id: &[u8]) -> Result<Vec<u8>, MlsError> {
        let group = load_group(&self.provider, &mut self.groups, group_id)?;
        group
            .leave_group(&self.provider, &self.signer)
            .map_err(|e| MlsError::CryptoError(format!("leave: {e}")))?
            .to_bytes()
            .map_err(|e| MlsError::SerializationError(format!("leave commit: {e}")))
    }

    pub fn member_count(&mut self, group_id: &[u8]) -> Result<u32, MlsError> {
        Ok(load_group(&self.provider, &mut self.groups, group_id)?
            .members()
            .count() as u32)
    }

    pub fn epoch(&mut self, group_id: &[u8]) -> Result<u64, MlsError> {
        Ok(load_group(&self.provider, &mut self.groups, group_id)?
            .epoch()
            .as_u64())
    }

    // ── Commits from other members ─────────────────────────────────────

    /// Process and merge a commit produced by another member.
    pub fn process_commit(&mut self, group_id: &[u8], commit_bytes: &[u8]) -> Result<(), MlsError> {
        let proto = parse_protocol_message(commit_bytes)
            .map_err(|e| MlsError::CommitError(format!("deserialize: {e}")))?;

        let group = load_group(&self.provider, &mut self.groups, group_id)?;
        let processed = group
            .process_message(&self.provider, proto)
            .map_err(|e| MlsError::CommitError(format!("process: {e}")))?;

        match processed.into_content() {
            openmls::prelude::ProcessedMessageContent::StagedCommitMessage(staged) => {
                group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(|e| MlsError::CommitError(format!("merge: {e}")))?;
                Ok(())
            }
            _ => Err(MlsError::CommitError("not a commit".into())),
        }
    }

    // ── Persistence (CFE) ──────────────────────────────────────────────

    /// Snapshot the entire MLS storage (all groups + key package private
    /// material) as a CFE blob. Call after every mutating operation and
    /// persist in the platform secure store.
    pub fn export_cfe(&self) -> Result<Vec<u8>, MlsError> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| MlsError::SerializationError("storage lock poisoned".into()))?;

        let mut entries: Vec<CfeMlsStoreEntryV1> = values
            .iter()
            .map(|(k, v)| CfeMlsStoreEntryV1 {
                key: ByteBuf::from(k.clone()),
                value: ByteBuf::from(v.clone()),
            })
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));

        let payload = CfeMlsStoreV1 {
            version: 1,
            entries,
        };
        cfe::encode(CfeMessageType::MlsStore, &payload)
            .map_err(|e| MlsError::SerializationError(format!("cfe encode: {e}")))
    }

    /// Restore a store from a CFE blob + the device Ed25519 identity keypair
    /// (the signer is never part of the blob). Groups load lazily by id.
    pub fn import_cfe(
        data: &[u8],
        signer_private_key: Vec<u8>,
        signer_public_key: Vec<u8>,
    ) -> Result<Self, MlsError> {
        let payload: CfeMlsStoreV1 = cfe::decode_as(data, CfeMessageType::MlsStore)
            .map_err(|e| MlsError::SerializationError(format!("cfe decode: {e}")))?;

        let store = Self::new(signer_private_key, signer_public_key);
        {
            let mut values = store
                .provider
                .storage()
                .values
                .write()
                .map_err(|_| MlsError::SerializationError("storage lock poisoned".into()))?;
            for entry in payload.entries {
                values.insert(entry.key.into_vec(), entry.value.into_vec());
            }
        }
        Ok(store)
    }
}

fn parse_protocol_message(bytes: &[u8]) -> Result<ProtocolMessage, String> {
    let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| e.to_string())?;
    message
        .try_into_protocol_message()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> MlsStore {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("keygen");
        MlsStore::new(signer.private().to_vec(), signer.to_public_vec())
    }

    /// Full two-party flow: Bob publishes a key package, Alice creates a
    /// group and adds him, Bob joins from the Welcome, messages flow both
    /// ways. This is the flow the old per-group-provider wrapper could not
    /// support (join always failed: fresh storage had no KP private keys).
    #[test]
    fn test_create_add_join_message_roundtrip() {
        let mut alice = make_store();
        let mut bob = make_store();

        let bob_kp = bob.generate_key_package().expect("bob kp");

        let group_id = alice.create_group().expect("create");
        assert_eq!(alice.member_count(&group_id).expect("count"), 1);
        assert_eq!(alice.epoch(&group_id).expect("epoch"), 0);

        let addition = alice.add_member(&group_id, &bob_kp).expect("add bob");
        assert_eq!(addition.member_count, 2);
        // The inviter's commit is merged locally — epoch must advance.
        assert_eq!(alice.epoch(&group_id).expect("epoch"), 1);

        let bob_group_id = bob.join_from_welcome(&addition.welcome).expect("join");
        assert_eq!(bob_group_id, group_id);
        assert_eq!(bob.member_count(&group_id).expect("count"), 2);
        assert_eq!(bob.epoch(&group_id).expect("epoch"), 1);

        let ct = alice.encrypt(&group_id, b"hello bob").expect("encrypt");
        assert_eq!(bob.decrypt(&group_id, &ct).expect("decrypt"), b"hello bob");

        let ct = bob.encrypt(&group_id, b"hello alice").expect("encrypt");
        assert_eq!(
            alice.decrypt(&group_id, &ct).expect("decrypt"),
            b"hello alice"
        );
    }

    /// The store must survive a CFE export/import round-trip mid-ratchet:
    /// restored stores decrypt new messages and keep committing.
    #[test]
    fn test_store_survives_cfe_roundtrip() {
        let alice_signer =
            SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("keygen");
        let bob_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("keygen");
        let mut alice = MlsStore::new(
            alice_signer.private().to_vec(),
            alice_signer.to_public_vec(),
        );
        let bob = MlsStore::new(bob_signer.private().to_vec(), bob_signer.to_public_vec());

        let bob_kp = bob.generate_key_package().expect("bob kp");

        // Bob persists after generating the key package (the private init key
        // must survive until the Welcome arrives — possibly days later).
        let bob_blob = bob.export_cfe().expect("bob export");
        let mut bob = MlsStore::import_cfe(
            &bob_blob,
            bob_signer.private().to_vec(),
            bob_signer.to_public_vec(),
        )
        .expect("bob import");

        let group_id = alice.create_group().expect("create");
        let addition = alice.add_member(&group_id, &bob_kp).expect("add bob");
        bob.join_from_welcome(&addition.welcome).expect("join");

        let ct = alice
            .encrypt(&group_id, b"before restart")
            .expect("encrypt");
        assert_eq!(
            bob.decrypt(&group_id, &ct).expect("decrypt"),
            b"before restart"
        );

        // Both sides "restart".
        let alice_blob = alice.export_cfe().expect("alice export");
        let bob_blob = bob.export_cfe().expect("bob export");
        let mut alice = MlsStore::import_cfe(
            &alice_blob,
            alice_signer.private().to_vec(),
            alice_signer.to_public_vec(),
        )
        .expect("alice import");
        let mut bob = MlsStore::import_cfe(
            &bob_blob,
            bob_signer.private().to_vec(),
            bob_signer.to_public_vec(),
        )
        .expect("bob import");

        assert_eq!(alice.member_count(&group_id).expect("count"), 2);
        assert_eq!(bob.member_count(&group_id).expect("count"), 2);
        assert_eq!(alice.epoch(&group_id).expect("epoch"), 1);

        // Ratchet continuity in both directions after restore.
        let ct = alice.encrypt(&group_id, b"after restart").expect("encrypt");
        assert_eq!(
            bob.decrypt(&group_id, &ct).expect("decrypt"),
            b"after restart"
        );
        let ct = bob.encrypt(&group_id, b"ack").expect("encrypt");
        assert_eq!(alice.decrypt(&group_id, &ct).expect("decrypt"), b"ack");

        // Restored stores can still commit: add a third member.
        let mut carol = make_store();
        let carol_kp = carol.generate_key_package().expect("carol kp");
        let addition = alice.add_member(&group_id, &carol_kp).expect("add carol");
        assert_eq!(addition.member_count, 3);
        bob.process_commit(&group_id, &addition.commit)
            .expect("bob merges");
        carol.join_from_welcome(&addition.welcome).expect("join");

        let ct = carol.encrypt(&group_id, b"hi all").expect("encrypt");
        assert_eq!(alice.decrypt(&group_id, &ct).expect("decrypt"), b"hi all");
        assert_eq!(bob.decrypt(&group_id, &ct).expect("decrypt"), b"hi all");
    }

    #[test]
    fn test_import_rejects_garbage_and_wrong_type() {
        assert!(MlsStore::import_cfe(b"not a cfe blob", vec![0u8; 32], vec![0u8; 32]).is_err());

        // A valid CFE envelope of a different msg_type must be rejected.
        let other = cfe::encode(
            CfeMessageType::Generic,
            &CfeMlsStoreV1 {
                version: 1,
                entries: vec![],
            },
        )
        .expect("encode");
        assert!(MlsStore::import_cfe(&other, vec![0u8; 32], vec![0u8; 32]).is_err());
    }

    #[test]
    fn test_unknown_group_id_is_not_a_member() {
        let mut store = make_store();
        let err = store.epoch(b"no-such-group").expect_err("must fail");
        assert!(matches!(err, MlsError::NotAMember));
    }
}
