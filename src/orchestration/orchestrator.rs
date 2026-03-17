/// Orchestrator — top-level facade (Phase 5).
///
/// Single entry point for all platform events. Swift / Kotlin call ONE function:
///
/// ```swift
/// let actions = orchestrator.handleEvent(event)
/// // execute each action, then feed results back as new events
/// ```
///
/// The `Orchestrator` holds the full orchestration state:
/// - `SessionLifecycleManager` (sessions, archives, ACK, healing, PQ)
/// - `MessageRouter` (routing decisions)
/// - Coordinator state: init locks, cooldowns, prewarm tracking
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::client_api::ClassicClient;
use crate::crypto::provider::CryptoProvider;
use crate::crypto::suites::classic::ClassicSuiteProvider;
use crate::orchestration::actions::{Action, IncomingEvent};
use crate::orchestration::message_router::{IncomingMessage, MessageRouter, Role, RoutingDecision};
use crate::orchestration::session_lifecycle::SessionLifecycleManager;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum time between successive END_SESSION sends to the same contact (ms).
const END_SESSION_COOLDOWN_MS: u64 = 5_000;

/// Minimum time between prewarm attempts for the same contact (ms).
#[allow(dead_code)]
const PREWARM_COOLDOWN_MS: u64 = 30_000;

// ── Orchestrator ──────────────────────────────────────────────────────────────

pub struct Orchestrator {
    lifecycle: SessionLifecycleManager,
    router: MessageRouter,
    /// Contacts whose session initialisation is currently in progress.
    init_locks: HashSet<String>,
    /// contactId → Unix ms of last END_SESSION / prewarm (anti-loop cooldown).
    cooldowns: HashMap<String, u64>,
    /// Contacts that have been pre-warmed (lower userId prewarms on first contact).
    #[allow(dead_code)]
    prewarm_done: HashSet<String>,
}

impl Orchestrator {
    /// Create a new orchestrator for the given local user.
    ///
    /// `client` is a freshly constructed (or key-restored) `ClassicClient`.
    pub fn new(client: ClassicClient<ClassicSuiteProvider>, my_user_id: String) -> Self {
        Self {
            lifecycle: SessionLifecycleManager::new(client, my_user_id),
            router: MessageRouter::new(),
            init_locks: HashSet::new(),
            cooldowns: HashMap::new(),
            prewarm_done: HashSet::new(),
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Unified event handler — the **only** method Swift / Kotlin need to call.
    ///
    /// Returns a list of `Action`s that the platform must execute in order.
    /// After executing I/O actions (network, storage), the platform feeds
    /// results back via further `handle_event` calls.
    pub fn handle_event(&mut self, event: IncomingEvent) -> Vec<Action> {
        match event {
            IncomingEvent::MessageReceived {
                message_id,
                from,
                data,
                msg_num,
                kem_ct,
                otpk_id,
                is_control,
            } => self.handle_message_received(
                message_id, from, data, msg_num, kem_ct, otpk_id, is_control,
            ),
            IncomingEvent::SessionInitCompleted {
                contact_id,
                session_json,
            } => self.handle_session_init_completed(contact_id, session_json),
            IncomingEvent::AckReceived { message_id } => self.handle_ack_received(message_id),
            IncomingEvent::SessionLoaded { key, data } => self.handle_session_loaded(key, data),
            IncomingEvent::KeyBundleFetched {
                user_id,
                bundle_json,
            } => self.handle_key_bundle_fetched(user_id, bundle_json),
            IncomingEvent::NetworkReconnected => self.handle_network_reconnected(),
            IncomingEvent::AppLaunched => self.handle_app_launched(),
            IncomingEvent::TimerFired { timer_id } => self.handle_timer_fired(timer_id),
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn my_user_id(&self) -> &str {
        self.lifecycle.my_user_id()
    }

    pub fn has_active_session(&self, contact_id: &str) -> bool {
        self.lifecycle.has_active_session(contact_id)
    }

    pub fn pending_message_count(&self, contact_id: &str) -> usize {
        self.router.pending_count(contact_id)
    }

    pub fn ack_is_processed(&self, message_id: &str) -> crate::orchestration::AckCheckResult {
        self.lifecycle.ack_store.is_processed(message_id)
    }

    pub fn ack_mark_processed(&mut self, message_id: &str) -> Vec<crate::orchestration::Action> {
        self.lifecycle.ack_store.mark_processed(message_id)
    }

    pub fn export_state_json(&self) -> Result<String, String> {
        self.lifecycle.export_state_json()
    }

    // ── Session-crypto delegates ──────────────────────────────────────────────

    pub fn get_all_session_contact_ids(&self) -> Vec<String> {
        self.lifecycle.client.active_contacts()
    }

    pub fn init_session_with_bundle(
        &mut self,
        contact_id: &str,
        recipient_bundle: &[u8],
    ) -> Result<String, String> {
        use crate::crypto::handshake::x3dh::X3DHPublicKeyBundle;
        use crate::crypto::SuiteID;

        #[derive(serde::Deserialize)]
        struct KeyBundle {
            identity_public: Vec<u8>,
            signed_prekey_public: Vec<u8>,
            signature: Vec<u8>,
            verifying_key: Vec<u8>,
            suite_id: u16,
            #[serde(default)]
            one_time_prekey_public: Option<Vec<u8>>,
            #[serde(default)]
            one_time_prekey_id: Option<u32>,
            #[serde(default)]
            spk_uploaded_at: Option<u64>,
            #[serde(default)]
            spk_rotation_epoch: Option<u32>,
            #[serde(default)]
            kyber_spk_uploaded_at: Option<u64>,
            #[serde(default)]
            kyber_spk_rotation_epoch: Option<u32>,
        }

        let bundle_str = std::str::from_utf8(recipient_bundle)
            .map_err(|_| "invalid UTF-8 in bundle".to_string())?;
        let key_bundle: KeyBundle =
            serde_json::from_str(bundle_str).map_err(|_| "invalid key bundle JSON".to_string())?;

        let public_bundle = X3DHPublicKeyBundle {
            identity_public: key_bundle.identity_public.clone(),
            signed_prekey_public: key_bundle.signed_prekey_public.clone(),
            signature: key_bundle.signature.clone(),
            verifying_key: key_bundle.verifying_key.clone(),
            suite_id: SuiteID::new(key_bundle.suite_id)
                .map_err(|_| "invalid suite_id".to_string())?,
            one_time_prekey_public: key_bundle.one_time_prekey_public.clone(),
            one_time_prekey_id: key_bundle.one_time_prekey_id,
            spk_uploaded_at: key_bundle.spk_uploaded_at.unwrap_or(0),
            spk_rotation_epoch: key_bundle.spk_rotation_epoch.unwrap_or(0),
            kyber_spk_uploaded_at: key_bundle.kyber_spk_uploaded_at.unwrap_or(0),
            kyber_spk_rotation_epoch: key_bundle.kyber_spk_rotation_epoch.unwrap_or(0),
        };

        let remote_identity =
            ClassicSuiteProvider::kem_public_key_from_bytes(key_bundle.identity_public.clone());
        let one_time_prekey_id = key_bundle.one_time_prekey_id.unwrap_or(0);

        tracing::debug!(
            target: "crypto::orchestrator",
            contact_id = %contact_id,
            one_time_prekey_id = one_time_prekey_id,
            has_otpk_public = key_bundle.one_time_prekey_public.is_some(),
            "init_session_with_bundle: storing pending OTPK id"
        );

        self.lifecycle
            .client
            .init_session(
                contact_id,
                &public_bundle,
                &remote_identity,
                one_time_prekey_id,
            )
            .map_err(|e| e.to_string())?;

        Ok(contact_id.to_string())
    }

    pub fn init_receiving_session_with_msg(
        &mut self,
        contact_id: &str,
        recipient_bundle: &[u8],
        first_message: &[u8],
    ) -> Result<(String, Vec<u8>), String> {
        use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;

        #[derive(serde::Deserialize)]
        struct KeyBundle {
            identity_public: Vec<u8>,
            suite_id: u16,
        }

        #[derive(serde::Deserialize)]
        struct FirstMsg {
            ephemeral_public_key: Vec<u8>,
            message_number: u32,
            content: String,
            #[serde(default)]
            one_time_prekey_id: u32,
        }

        let bundle_str = std::str::from_utf8(recipient_bundle)
            .map_err(|_| "invalid UTF-8 in bundle".to_string())?;
        let key_bundle: KeyBundle =
            serde_json::from_str(bundle_str).map_err(|_| "invalid key bundle JSON".to_string())?;

        let msg_str = std::str::from_utf8(first_message)
            .map_err(|_| "invalid UTF-8 in first message".to_string())?;
        let first_msg: FirstMsg =
            serde_json::from_str(msg_str).map_err(|_| "invalid first message JSON".to_string())?;

        use base64::Engine as _;
        let sealed_box = base64::engine::general_purpose::STANDARD
            .decode(&first_msg.content)
            .map_err(|_| "invalid base64 content".to_string())?;

        if sealed_box.len() < 12 {
            return Err("sealed_box too short".to_string());
        }
        let nonce = sealed_box[..12].to_vec();
        let ciphertext = sealed_box[12..].to_vec();

        let dh_public_key: [u8; 32] = first_msg
            .ephemeral_public_key
            .clone()
            .try_into()
            .map_err(|_| "ephemeral_public_key must be 32 bytes".to_string())?;

        let encrypted_first_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number: first_msg.message_number,
            ciphertext,
            nonce,
            previous_chain_length: 0,
            suite_id: key_bundle.suite_id,
        };

        let remote_identity =
            ClassicSuiteProvider::kem_public_key_from_bytes(key_bundle.identity_public.clone());
        let remote_ephemeral =
            ClassicSuiteProvider::kem_public_key_from_bytes(first_msg.ephemeral_public_key.clone());

        let (_session_id, plaintext) = self
            .lifecycle
            .client
            .init_receiving_session_with_ephemeral(
                contact_id,
                &remote_identity,
                &remote_ephemeral,
                &encrypted_first_message,
                first_msg.one_time_prekey_id,
            )
            .map_err(|e| e.to_string())?;

        Ok((contact_id.to_string(), plaintext))
    }

    pub fn export_session_json_for(&self, contact_id: &str) -> Result<String, String> {
        self.lifecycle.export_session_json_for(contact_id)
    }

    pub fn import_session_json(&mut self, contact_id: &str, json: &str) -> Result<String, String> {
        self.lifecycle.import_session_json(contact_id, json)
    }

    pub fn remove_session_by_contact(&mut self, contact_id: &str) -> bool {
        self.lifecycle.client.remove_session(contact_id)
    }

    pub fn export_private_keys_json_str(&self) -> Result<String, String> {
        use base64::Engine as _;
        let km = self.lifecycle.client.key_manager();
        let identity_secret = km.identity_secret_key().map_err(|e| e.to_string())?;
        let signing_secret = km.signing_secret_key().map_err(|e| e.to_string())?;
        let prekey = km.current_signed_prekey().map_err(|e| e.to_string())?;

        let identity_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(identity_secret).to_vec();
        let signing_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(signing_secret).to_vec();
        let prekey_secret_bytes: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(&prekey.key_pair.0).to_vec();

        use crate::crypto::provider::CryptoProvider as _;
        use crate::crypto::suites::classic::ClassicSuiteProvider;
        use base64::engine::general_purpose::STANDARD;

        // Re-derive public keys for integrity verification on next load.
        let identity_pub_check =
            ClassicSuiteProvider::from_private_key_to_public_key(&identity_bytes)
                .ok()
                .map(|b| STANDARD.encode(&b));
        let verifying_key_check =
            ClassicSuiteProvider::from_signature_private_to_public(&signing_bytes)
                .ok()
                .map(|b| STANDARD.encode(&b));
        let spk_pub_check =
            ClassicSuiteProvider::from_private_key_to_public_key(&prekey_secret_bytes)
                .ok()
                .map(|b| STANDARD.encode(&b));

        let mut json = serde_json::json!({
            "identity_secret": STANDARD.encode(&identity_bytes),
            "signing_secret": STANDARD.encode(&signing_bytes),
            "signed_prekey_secret": STANDARD.encode(&prekey_secret_bytes),
            "prekey_signature": STANDARD.encode(&prekey.signature),
            "suite_id": "1"
        });
        if let Some(v) = identity_pub_check {
            json["identity_public_check"] = serde_json::Value::String(v);
        }
        if let Some(v) = verifying_key_check {
            json["verifying_key_check"] = serde_json::Value::String(v);
        }
        if let Some(v) = spk_pub_check {
            json["signed_prekey_public_check"] = serde_json::Value::String(v);
        }
        serde_json::to_string(&json).map_err(|e| e.to_string())
    }

    pub fn export_registration_bundle_json_str(&self) -> Result<String, String> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let bundle = self
            .lifecycle
            .client
            .key_manager()
            .export_registration_bundle()
            .map_err(|e| e.to_string())?;

        let json = serde_json::json!({
            "identity_public": STANDARD.encode(&bundle.identity_public),
            "signed_prekey_public": STANDARD.encode(&bundle.signed_prekey_public),
            "signature": STANDARD.encode(&bundle.signature),
            "verifying_key": STANDARD.encode(&bundle.verifying_key),
            "suite_id": bundle.suite_id.as_u16().to_string()
        });
        serde_json::to_string(&json).map_err(|e| e.to_string())
    }

    pub fn sign_bundle_bytes(&self, data: &[u8]) -> Result<String, String> {
        use base64::Engine as _;
        let signature = self
            .lifecycle
            .client
            .key_manager()
            .sign(data)
            .map_err(|e| e.to_string())?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&signature))
    }

    pub fn set_my_user_id(&mut self, user_id: String) {
        self.lifecycle.set_my_user_id(user_id);
    }

    pub fn prekeys_available(&self) -> u32 {
        let old = self.lifecycle.client.key_manager().old_prekeys_count();
        (old + 1) as u32
    }

    /// Returns `(key_id, public_key_bytes)` pairs for the new OTPKs.
    pub fn generate_otpks(&mut self, count: u32) -> Result<Vec<(u32, Vec<u8>)>, String> {
        self.lifecycle
            .client
            .generate_one_time_prekeys(count)
            .map_err(|e| e.to_string())
    }

    pub fn otpk_count(&self) -> u32 {
        self.lifecycle.client.one_time_prekey_count() as u32
    }

    pub fn export_otpks_json(&self) -> Result<String, String> {
        #[derive(serde::Serialize)]
        struct OtpkRecord {
            key_id: u32,
            private_key: Vec<u8>,
            public_key: Vec<u8>,
        }
        let records: Vec<OtpkRecord> = self
            .lifecycle
            .client
            .export_one_time_prekeys()
            .into_iter()
            .map(|(key_id, private_key, public_key)| OtpkRecord {
                key_id,
                private_key,
                public_key,
            })
            .collect();
        serde_json::to_string(&records).map_err(|e| e.to_string())
    }

    pub fn import_otpks_json(&mut self, json: &str) -> Result<(), String> {
        #[derive(serde::Deserialize)]
        struct OtpkRecord {
            key_id: u32,
            private_key: Vec<u8>,
            public_key: Vec<u8>,
        }
        let records: Vec<OtpkRecord> = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let keys: Vec<(u32, Vec<u8>, Vec<u8>)> = records
            .into_iter()
            .map(|r| (r.key_id, r.private_key, r.public_key))
            .collect();
        self.lifecycle.client.import_one_time_prekeys(keys);
        Ok(())
    }

    pub fn export_private_keys_cfe(&self) -> Result<Vec<u8>, String> {
        use crate::crypto::provider::CryptoProvider as _;
        use crate::crypto::suites::classic::ClassicSuiteProvider;
        use serde_bytes::ByteBuf;

        let km = self.lifecycle.client.key_manager();
        let identity_secret = km.identity_secret_key().map_err(|e| e.to_string())?;
        let signing_secret = km.signing_secret_key().map_err(|e| e.to_string())?;
        let prekey = km.current_signed_prekey().map_err(|e| e.to_string())?;

        let ik_priv: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(identity_secret).to_vec();
        let sk_priv: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(signing_secret).to_vec();
        let spk_priv: Vec<u8> = <_ as AsRef<[u8]>>::as_ref(&prekey.key_pair.0).to_vec();
        let spk_sig: Vec<u8> = prekey.signature.clone();

        let ik_pub = ClassicSuiteProvider::from_private_key_to_public_key(&ik_priv)
            .map_err(|e| e.to_string())?;
        let vk_pub = ClassicSuiteProvider::from_signature_private_to_public(&sk_priv)
            .map_err(|e| e.to_string())?;
        let spk_pub = ClassicSuiteProvider::from_private_key_to_public_key(&spk_priv)
            .map_err(|e| e.to_string())?;

        let spk_id = km.current_signed_prekey_id().unwrap_or(0);

        let payload = crate::cfe::CfePrivateKeysV1 {
            suite_id: 1,
            ik_priv: ByteBuf::from(ik_priv),
            sk_priv: ByteBuf::from(sk_priv),
            spk_priv: ByteBuf::from(spk_priv),
            spk_sig: ByteBuf::from(spk_sig),
            spk_id,
            ik_pub: ByteBuf::from(ik_pub),
            vk_pub: ByteBuf::from(vk_pub),
            spk_pub: ByteBuf::from(spk_pub),
        };

        crate::cfe::encode(crate::cfe::CfeMessageType::PrivateKeys, &payload)
            .map_err(|e| e.to_string())
    }

    pub fn export_otpks_cfe(&self) -> Result<Vec<u8>, String> {
        use serde_bytes::ByteBuf;

        let records: Vec<crate::cfe::CfeOtpkRecordV1> = self
            .lifecycle
            .client
            .export_one_time_prekeys()
            .into_iter()
            .map(|(id, priv_key, pub_key)| crate::cfe::CfeOtpkRecordV1 {
                id,
                priv_key: ByteBuf::from(priv_key),
                pub_key: ByteBuf::from(pub_key),
            })
            .collect();

        let next_id = self.lifecycle.client.key_manager().next_otpk_id();
        let payload = crate::cfe::CfeOtpkBundleV1 { records, next_id };

        crate::cfe::encode(crate::cfe::CfeMessageType::OtpkBundle, &payload)
            .map_err(|e| e.to_string())
    }

    pub fn import_otpks_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        let bundle = match crate::cfe::decode_as::<crate::cfe::CfeOtpkBundleV1>(
            data,
            crate::cfe::CfeMessageType::OtpkBundle,
        ) {
            Ok(b) => b,
            Err(crate::cfe::CfeError::LegacyJson) => {
                let s = std::str::from_utf8(data).map_err(|e| e.to_string())?;
                crate::cfe::migrate_otpk_bundle_json_str(s).map_err(|e| e.to_string())?
            }
            Err(e) => return Err(e.to_string()),
        };

        let keys: Vec<(u32, Vec<u8>, Vec<u8>)> = bundle
            .records
            .iter()
            .map(|r| (r.id, r.priv_key.to_vec(), r.pub_key.to_vec()))
            .collect();

        self.lifecycle.client.import_one_time_prekeys(keys);
        self.lifecycle
            .client
            .key_manager_mut()
            .set_next_otpk_id(bundle.next_id);
        Ok(())
    }

    /// Export a session as a CFE binary blob (MessagePack + CRC32 header).
    /// Falls back gracefully from JSON if needed by the caller.
    pub fn export_session_cfe(&self, contact_id: &str) -> Result<Vec<u8>, String> {
        use serde_bytes::ByteBuf;

        let json = self
            .lifecycle
            .export_session_json_for(contact_id)
            .map_err(|e| e.to_string())?;

        let payload = crate::cfe::CfeSessionJsonWrapperV1 {
            contact_id: contact_id.to_string(),
            json_bytes: ByteBuf::from(json.into_bytes()),
        };
        crate::cfe::encode(crate::cfe::CfeMessageType::SessionState, &payload)
            .map_err(|e| e.to_string())
    }

    /// Import a session from a CFE binary blob, or fall back to raw JSON.
    /// Returns the session ID string on success.
    pub fn import_session_cfe(&mut self, contact_id: &str, data: &[u8]) -> Result<String, String> {
        let json = match crate::cfe::decode_as::<crate::cfe::CfeSessionJsonWrapperV1>(
            data,
            crate::cfe::CfeMessageType::SessionState,
        ) {
            Ok(s) => String::from_utf8(s.json_bytes.into_vec()).map_err(|e| e.to_string())?,
            Err(crate::cfe::CfeError::LegacyJson) => std::str::from_utf8(data)
                .map_err(|e| e.to_string())?
                .to_string(),
            Err(e) => return Err(e.to_string()),
        };
        self.lifecycle
            .import_session_json(contact_id, &json)
            .map_err(|e| e.to_string())
    }
    pub fn rotate_spk(&mut self) -> Result<(u32, String, String), String> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        self.lifecycle
            .client
            .key_manager_mut()
            .rotate_signed_prekey()
            .map_err(|e| e.to_string())?;

        let bundle = self
            .lifecycle
            .client
            .key_manager()
            .export_registration_bundle()
            .map_err(|e| e.to_string())?;

        let key_id = self
            .lifecycle
            .client
            .key_manager()
            .current_signed_prekey_id()
            .unwrap_or(1);

        Ok((
            key_id,
            STANDARD.encode(&bundle.signed_prekey_public),
            STANDARD.encode(&bundle.signature),
        ))
    }

    pub fn apply_pq_contribution_delegate(
        &mut self,
        contact_id: &str,
        kem_shared_secret: &[u8],
    ) -> Result<(), String> {
        self.lifecycle
            .client
            .apply_pq_contribution_to_session(contact_id, kem_shared_secret)
            .map_err(|e| e.to_string())
    }

    /// Register a KEM shared secret as a deferred contribution for `contact_id`.
    ///
    /// Call this AFTER performing ML-KEM encapsulation (INITIATOR) or
    /// decapsulation (RESPONDER) so that the shared secret is stored in the
    /// `PQContributionManager` and included in `export_kyber_session_state_cfe`
    /// snapshots.
    ///
    /// Returns a `SaveSessionToSecureStore` action that the platform **must**
    /// execute to persist the per-entry deferred secret for crash-safety.
    pub fn register_pq_deferred(
        &mut self,
        contact_id: &str,
        otpk_id: u32,
        shared_secret: &[u8],
    ) -> Vec<crate::orchestration::Action> {
        let persist_action =
            self.lifecycle
                .pq_manager
                .register_shared_secret(contact_id, otpk_id, shared_secret);
        vec![persist_action]
    }

    /// Export the `PQContributionManager` state as a CFE binary blob.
    ///
    /// Persist the returned bytes under `"kyber_session_state"` in the platform
    /// secure store after any encapsulate / decapsulate / consume operation.
    pub fn export_kyber_session_state_cfe(&self) -> Result<Vec<u8>, String> {
        self.lifecycle.export_kyber_session_state_cfe()
    }

    /// Restore the `PQContributionManager` state from a previously exported CFE blob.
    pub fn import_kyber_session_state_cfe(&mut self, data: &[u8]) -> Result<(), String> {
        self.lifecycle.import_kyber_session_state_cfe(data)
    }

    /// Returns `(ephemeral_public_key, message_number, content_b64, one_time_prekey_id)`.
    pub fn encrypt_message_for(
        &mut self,
        contact_id: &str,
        plaintext: &str,
    ) -> Result<(Vec<u8>, u32, String, u32), String> {
        use base64::Engine as _;
        let encrypted = self
            .lifecycle
            .client
            .encrypt_message(contact_id, plaintext.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut sealed_box = Vec::new();
        sealed_box.extend_from_slice(&encrypted.nonce);
        sealed_box.extend_from_slice(&encrypted.ciphertext);

        let one_time_prekey_id = if encrypted.message_number == 0 {
            self.lifecycle.client.take_pending_otpk_id(contact_id)
        } else {
            0
        };

        Ok((
            encrypted.dh_public_key.to_vec(),
            encrypted.message_number,
            base64::engine::general_purpose::STANDARD.encode(&sealed_box),
            one_time_prekey_id,
        ))
    }

    pub fn decrypt_message_for(
        &mut self,
        contact_id: &str,
        ephemeral_public_key: Vec<u8>,
        message_number: u32,
        content: &str,
    ) -> Result<String, String> {
        use crate::crypto::messaging::double_ratchet::EncryptedRatchetMessage;
        use base64::Engine as _;

        let sealed_box = base64::engine::general_purpose::STANDARD
            .decode(content)
            .map_err(|_| "invalid base64 content".to_string())?;

        if sealed_box.len() < 12 {
            return Err("sealed_box too short".to_string());
        }
        let nonce = sealed_box[..12].to_vec();
        let ciphertext = sealed_box[12..].to_vec();

        let dh_public_key: [u8; 32] = ephemeral_public_key
            .try_into()
            .map_err(|_| "ephemeral_public_key must be 32 bytes".to_string())?;

        let encrypted_message = EncryptedRatchetMessage {
            dh_public_key,
            message_number,
            ciphertext,
            nonce,
            previous_chain_length: 0,
            suite_id: crate::config::Config::global().classic_suite_id,
        };

        let plaintext = self
            .lifecycle
            .client
            .decrypt_message(contact_id, &encrypted_message)
            .map_err(|e| e.to_string())?;

        String::from_utf8(plaintext).map_err(|e| format!("UTF-8 conversion failed: {}", e))
    }

    // ── Event handlers ────────────────────────────────────────────────────────

    fn handle_message_received(
        &mut self,
        message_id: String,
        from: String,
        data: Vec<u8>,
        msg_num: u32,
        kem_ct: Vec<u8>,
        _otpk_id: u32,
        is_control: bool,
    ) -> Vec<Action> {
        let wire_json = match String::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                return vec![Action::NotifyError {
                    code: "INVALID_UTF8".to_string(),
                    message: "message data is not valid UTF-8".to_string(),
                }]
            }
        };

        let incoming = IncomingMessage {
            contact_id: from.clone(),
            wire_json,
            message_id,
            msg_number: msg_num,
            is_control,
        };

        // Store KEM ciphertext for PQ decapsulation if non-empty.
        // The platform must call back with `mlkem768_decapsulate` result.
        let mut actions = Vec::new();
        if !kem_ct.is_empty() {
            actions.push(Action::ApplyPQContribution {
                contact_id: from.clone(),
                kem_ss: kem_ct, // platform decapsulates, feeds ss back
            });
        }

        let decision = self.router.route_message(&mut self.lifecycle, &incoming);
        actions.extend(self.decision_to_actions(decision, &from));
        actions
    }

    fn handle_session_init_completed(
        &mut self,
        contact_id: String,
        session_json: String,
    ) -> Vec<Action> {
        self.init_locks.remove(&contact_id);

        // Import the newly created session.
        self.lifecycle.load_archive_json(&contact_id, session_json);

        // Save the session to secure store.
        let mut actions = vec![];
        if let Ok(json) = self.lifecycle.export_state_json() {
            actions.push(Action::SaveSessionToSecureStore {
                key: crate::orchestration::session_lifecycle::session_key(&contact_id),
                data: json.into_bytes(),
            });
        }

        // Drain the pending queue.
        let drained = self.router.drain_pending(&contact_id, &mut self.lifecycle);
        for decision in drained {
            actions.extend(self.decision_to_actions(decision, &contact_id));
        }

        actions.push(Action::NotifySessionCreated {
            contact_id: contact_id.clone(),
        });

        actions
    }

    fn handle_ack_received(&mut self, message_id: String) -> Vec<Action> {
        vec![Action::MarkMessageDelivered { message_id }]
    }

    fn handle_session_loaded(&mut self, key: String, data: Option<Vec<u8>>) -> Vec<Action> {
        // key format: "session_<contact_id>" or "archive_<contact_id>"
        let contact_id = key
            .strip_prefix("session_")
            .or_else(|| key.strip_prefix("archive_"))
            .unwrap_or(&key)
            .to_string();

        if let Some(bytes) = data {
            if let Ok(json) = String::from_utf8(bytes) {
                self.lifecycle.load_archive_json(&contact_id, json);
            }
        }
        vec![]
    }

    fn handle_key_bundle_fetched(&mut self, user_id: String, _bundle_json: String) -> Vec<Action> {
        // Session init is done by the platform using ClassicCryptoCore.init_session.
        // The result comes back via SessionInitCompleted.
        // Here we just clear the init lock if we were waiting.
        vec![Action::InitSession {
            contact_id: user_id,
            bundle_json: _bundle_json,
        }]
    }

    fn handle_network_reconnected(&mut self) -> Vec<Action> {
        // Schedule a GC sweep after reconnect.
        vec![Action::ScheduleTimer {
            timer_id: "gc_sweep".to_string(),
            delay_ms: 1_000,
        }]
    }

    fn handle_app_launched(&mut self) -> Vec<Action> {
        // Schedule a GC and prewarm sweep on launch.
        vec![
            Action::ScheduleTimer {
                timer_id: "gc_sweep".to_string(),
                delay_ms: 5_000,
            },
            Action::ScheduleTimer {
                timer_id: "prewarm_sweep".to_string(),
                delay_ms: 2_000,
            },
        ]
    }

    fn handle_timer_fired(&mut self, timer_id: String) -> Vec<Action> {
        match timer_id.as_str() {
            "gc_sweep" => {
                let mut actions = self.lifecycle.gc_old_archives();
                actions.extend(self.lifecycle.ack_store.prune_expired());
                actions.extend(self.lifecycle.healing_queue.prune_expired());
                actions
            }
            _ => vec![],
        }
    }

    // ── Decision → Actions ────────────────────────────────────────────────────

    fn decision_to_actions(&mut self, decision: RoutingDecision, _contact_id: &str) -> Vec<Action> {
        match decision {
            RoutingDecision::Decrypted {
                plaintext,
                actions,
                contact_id: cid,
                message_id: mid,
            } => {
                let mut all = actions;
                let plaintext_str = String::from_utf8_lossy(&plaintext).into_owned();
                all.push(Action::MessageDecrypted {
                    contact_id: cid.clone(),
                    message_id: mid,
                    plaintext_utf8: plaintext_str.clone(),
                });
                all.push(Action::NotifyNewMessage {
                    chat_id: cid,
                    preview: preview(&plaintext),
                });
                all
            }
            RoutingDecision::NeedSessionInit {
                contact_id: cid, ..
            } => {
                if self.init_locks.contains(&cid) {
                    return vec![];
                }
                self.init_locks.insert(cid.clone());
                vec![Action::FetchPublicKeyBundle { user_id: cid }]
            }
            RoutingDecision::SessionHealNeeded {
                contact_id: cid,
                role,
            } => {
                if self.on_cooldown(&cid) {
                    return vec![];
                }
                self.set_cooldown(cid.clone());
                let role_str = match role {
                    Role::Initiator => "Initiator",
                    Role::Responder => "Responder",
                };
                vec![Action::SessionHealNeeded {
                    contact_id: cid,
                    role: role_str.to_string(),
                }]
            }
            RoutingDecision::EndSessionNeeded {
                contact_id: cid,
                reason: _,
            } => {
                if self.on_cooldown(&cid) {
                    return vec![];
                }
                self.set_cooldown(cid.clone());
                vec![Action::SendEndSession { contact_id: cid }]
            }
            RoutingDecision::Duplicate { .. } => vec![],
            RoutingDecision::QueueFull { contact_id: cid } => {
                vec![Action::NotifyError {
                    code: "QUEUE_FULL".to_string(),
                    message: format!("Message queue full for {}", cid),
                }]
            }
            RoutingDecision::EndSessionReceived {
                contact_id: _,
                actions,
            } => actions,
            RoutingDecision::Error { message } => {
                vec![Action::NotifyError {
                    code: "ROUTING_ERROR".to_string(),
                    message,
                }]
            }
        }
    }

    // ── Cooldown helpers ──────────────────────────────────────────────────────

    fn on_cooldown(&self, contact_id: &str) -> bool {
        self.cooldowns
            .get(contact_id)
            .is_some_and(|&last_ms| unix_ms().saturating_sub(last_ms) < END_SESSION_COOLDOWN_MS)
    }

    fn set_cooldown(&mut self, contact_id: String) {
        self.cooldowns.insert(contact_id, unix_ms());
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[allow(dead_code)]
fn unix_now() -> u64 {
    unix_ms() / 1_000
}

#[allow(dead_code)]
fn derive_message_id(data: &[u8], msg_num: u32) -> String {
    // Cheap deterministic ID: sha2 not available without feature, use a hash of
    // the first 16 bytes + message number. Good enough for deduplication.
    let prefix: u64 = data.iter().take(16).enumerate().fold(0u64, |acc, (i, &b)| {
        acc.wrapping_add((b as u64).wrapping_shl(i as u32 % 64))
    });
    format!("{}_{}", prefix, msg_num)
}

fn preview(plaintext: &[u8]) -> String {
    let s = String::from_utf8_lossy(plaintext);
    let chars: String = s.chars().take(50).collect();
    chars
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_api::ClassicClient;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    fn make_orchestrator(user_id: &str) -> Orchestrator {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        Orchestrator::new(client, user_id.to_string())
    }

    #[test]
    fn test_new_orchestrator() {
        let o = make_orchestrator("alice");
        assert_eq!(o.my_user_id(), "alice");
        assert!(!o.has_active_session("bob"));
        assert_eq!(o.pending_message_count("bob"), 0);
    }

    #[test]
    fn test_message_received_no_session_fetches_bundle() {
        let mut o = make_orchestrator("alice");
        let wire = r#"{"dh_public_key":[0],"message_number":0,"ciphertext":[],"nonce":[],"previous_chain_length":0,"suite_id":1}"#;
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            message_id: "msg-001".to_string(),
            from: "bob".to_string(),
            data: wire.as_bytes().to_vec(),
            msg_num: 0,
            kem_ct: vec![],
            otpk_id: 0,
            is_control: false,
        });
        // Should ask to fetch bundle (no active session → NeedSessionInit).
        let fetches: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::FetchPublicKeyBundle { .. }))
            .collect();
        assert!(!fetches.is_empty(), "expected FetchPublicKeyBundle action");
    }

    #[test]
    fn test_message_received_pq_ciphertext_produces_apply_action() {
        let mut o = make_orchestrator("alice");
        let wire = r#"{"dh_public_key":[0],"message_number":0,"ciphertext":[],"nonce":[],"previous_chain_length":0,"suite_id":1}"#;
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            message_id: "msg-002".to_string(),
            from: "bob".to_string(),
            data: wire.as_bytes().to_vec(),
            msg_num: 0,
            kem_ct: vec![1, 2, 3],
            otpk_id: 42,
            is_control: false,
        });
        let pq_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::ApplyPQContribution { .. }))
            .collect();
        assert!(
            !pq_actions.is_empty(),
            "expected ApplyPQContribution action"
        );
    }

    #[test]
    fn test_app_launched_schedules_timers() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::AppLaunched);
        let timers: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::ScheduleTimer { .. }))
            .collect();
        assert_eq!(timers.len(), 2);
    }

    #[test]
    fn test_network_reconnected_schedules_gc() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::NetworkReconnected);
        assert!(actions.iter().any(
            |a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id == "gc_sweep")
        ));
    }

    #[test]
    fn test_timer_gc_sweep_returns_actions() {
        let mut o = make_orchestrator("alice");
        // gc_sweep on empty state should return empty (no expired records).
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "gc_sweep".to_string(),
        });
        // May return prune actions even on empty store; just check no panic.
        let _ = actions;
    }

    #[test]
    fn test_ack_received_produces_mark_delivered() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::AckReceived {
            message_id: "msg-xyz".to_string(),
        });
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], Action::MarkMessageDelivered { message_id } if message_id == "msg-xyz")
        );
    }

    #[test]
    fn test_session_init_completed_clears_lock() {
        let mut o = make_orchestrator("alice");
        o.init_locks.insert("bob".to_string());
        let actions = o.handle_event(IncomingEvent::SessionInitCompleted {
            contact_id: "bob".to_string(),
            session_json: "{}".to_string(), // minimal, will fail to import gracefully
        });
        assert!(!o.init_locks.contains("bob"));
        // Should include NotifySessionCreated.
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::NotifySessionCreated { .. })));
    }

    #[test]
    fn test_cooldown_deduplicates_end_session() {
        let mut o = make_orchestrator("alice");
        o.set_cooldown("bob".to_string());
        assert!(o.on_cooldown("bob"));
    }

    #[test]
    fn test_no_cooldown_initially() {
        let o = make_orchestrator("alice");
        assert!(!o.on_cooldown("bob"));
    }
}
