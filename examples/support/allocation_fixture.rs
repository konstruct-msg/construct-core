//! Synthetic, public-API-only fixtures for TODO 296. No production behavior changes.

use construct_core::cfe::{self, CfeMessageType, CfeSessionStateV1};
use construct_core::crypto::client_api::ClassicClient;
use construct_core::crypto::messaging::double_ratchet::{
    DoubleRatchetSession, SerializableSession,
};
use construct_core::crypto::sealed_sender::{SenderCertificate, build_cert_sign_payload};
use construct_core::crypto::suites::classic::ClassicSuiteProvider;
use construct_core::orchestration::orchestrator::{KyberBundleKeys, Orchestrator};
use construct_core::orchestration::{Action, IncomingEvent, SecureStoreSlot};
use construct_core::wire_payload;
use ed25519_dalek::{Signer, SigningKey};
use std::hint::black_box;

pub type Ratchet = DoubleRatchetSession<ClassicSuiteProvider>;

pub struct Pair {
    pub alice: Orchestrator,
    pub bob: Orchestrator,
    pub alice_id: String,
    pub bob_id: String,
    pub late: Vec<Vec<u8>>,
}

fn device() -> (Orchestrator, String) {
    let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
    let mut core = Orchestrator::new(client, "pending".into());
    core.ensure_hybrid_signature_key().unwrap();
    core.begin_kyber_spk_rotation().unwrap();
    assert!(core.commit_kyber_spk_rotation());
    let id = construct_core::device_id::derive_device_id(
        &core
            .get_registration_bundle_fields()
            .unwrap()
            .identity_public,
    );
    core.set_my_user_id(id.clone());
    (core, id)
}

impl Pair {
    pub fn new() -> Self {
        let (alice, alice_id) = device();
        let (bob, bob_id) = device();
        let mut pair = Self {
            alice,
            bob,
            alice_id,
            bob_id,
            late: Vec::new(),
        };
        pair.reopen();
        pair
    }

    pub fn reopen(&mut self) {
        let x3dh = self.bob.get_registration_bundle_fields().unwrap();
        let hybrid = self.bob.hybrid_signature_public_key().unwrap();
        let bind = Orchestrator::build_hybrid_identity_bind_message(&hybrid);
        let binding = self.bob.sign_with_device_key(&bind).unwrap();
        let spk = self.bob.current_kyber_spk_upload().unwrap().unwrap();
        let kyber = KyberBundleKeys {
            pre_key_id: Some(spk.key_id),
            pre_key_public: Some(spk.public_key),
            pre_key_created_at: Some(spk.created_at),
            pre_key_signature: Some(spk.signature),
            pre_key_hybrid_signature: Some(spk.hybrid_signature),
            hybrid_identity_key: Some(hybrid),
            hybrid_identity_signature: Some(binding),
            ..Default::default()
        };
        self.alice
            .reopen_session_with_bundle(&self.bob_id, x3dh, kyber, false)
            .unwrap();
        let first = self
            .alice
            .encrypt_bytes_for(&self.bob_id, b"opening")
            .unwrap();
        let identity = self
            .alice
            .get_registration_bundle_fields()
            .unwrap()
            .identity_public;
        // Exercise the real receiving-open path: it retains the held state on replacement.
        let server = SigningKey::from_bytes(&[7; 32]);
        self.bob
            .set_trusted_server_keys(vec![server.verifying_key().to_bytes().to_vec()]);
        let now = construct_core::utils::time::current_timestamp();
        let signed = build_cert_sign_payload(
            "fixture",
            "bench.invalid",
            &identity,
            &self.alice_id,
            now,
            now + 86400,
        );
        let certificate = SenderCertificate {
            user_id: "fixture".into(),
            domain: "bench.invalid".into(),
            identity_key: identity,
            device_id: self.alice_id.clone(),
            issued_at: now,
            expires_at: now + 86400,
            signature: server.sign(&signed).to_bytes().to_vec(),
            server_kid: Vec::new(),
            server_signature_hybrid: Vec::new(),
        };
        let id = format!(
            "open-{}",
            self.alice
                .get_session_health(&self.bob_id)
                .unwrap()
                .session_id
        );
        let _queued = self.bob.handle_event(IncomingEvent::MessageReceived {
            message_id: id.clone(),
            from: self.alice_id.clone(),
            data: first,
            content_type: 0,
            sender_certificate: Some(Box::new(certificate)),
            envelope_session: None,
        });
        let opened = self.bob.open_receiving(&self.alice_id);
        assert_eq!(
            opened.opened_device.as_deref(),
            Some(self.alice_id.as_str()),
            "opening failed: {:?}",
            opened.last_error
        );
        validate_actions(&opened.actions, b"opening", &id);
        // Complete identity proof and a real sparse PQ exchange (default turn interval = 16).
        for _ in 0..20 {
            let reply = self
                .bob
                .encrypt_bytes_for(&self.alice_id, b"reply")
                .unwrap();
            assert_eq!(
                self.alice.decrypt_bytes_for(&self.bob_id, &reply).unwrap(),
                b"reply"
            );
            let proof = self
                .alice
                .encrypt_bytes_for(&self.bob_id, b"proof")
                .unwrap();
            assert_eq!(
                self.bob.decrypt_bytes_for(&self.alice_id, &proof).unwrap(),
                b"proof"
            );
        }
        assert!(
            self.bob
                .get_session_health(&self.alice_id)
                .unwrap()
                .pq_epoch
                > 0
        );
    }

    pub fn with_history(skipped: usize, previous: usize) -> Self {
        let mut pair = Self::new();
        for state in 0..=previous {
            if state > 0 {
                pair.reopen();
            }
            for i in 0..skipped {
                let wire = pair.alice.encrypt_bytes_for(&pair.bob_id, b"late").unwrap();
                if i == 0 {
                    pair.late.push(wire);
                }
            }
            let wire = pair
                .alice
                .encrypt_bytes_for(&pair.bob_id, b"after-gap")
                .unwrap();
            assert_eq!(
                pair.bob.decrypt_bytes_for(&pair.alice_id, &wire).unwrap(),
                b"after-gap"
            );
        }
        let health = pair.bob.get_session_health(&pair.alice_id).unwrap();
        assert_eq!(health.skipped_keys_count, skipped);
        assert_eq!(health.pq_skipped_keys_count, skipped);
        let cfe = decode_session(&pair.bob, &pair.alice_id);
        assert_eq!(cfe.previous.len(), previous);
        assert!(
            cfe.previous
                .iter()
                .all(|s| s.state.skipped.len() == skipped)
        );
        pair
    }

    pub fn event(&mut self, plaintext: &[u8], id: &str) -> IncomingEvent {
        IncomingEvent::MessageReceived {
            message_id: id.into(),
            from: self.alice_id.clone(),
            data: self
                .alice
                .encrypt_bytes_for(&self.bob_id, plaintext)
                .unwrap(),
            content_type: 0,
            sender_certificate: None,
            envelope_session: None,
        }
    }
}

pub fn decode_session(core: &Orchestrator, peer: &str) -> CfeSessionStateV1 {
    cfe::decode_as(
        &core.export_session_cfe(peer).unwrap(),
        CfeMessageType::SessionState,
    )
    .unwrap()
}

pub fn ratchet_from(cfe: CfeSessionStateV1) -> Ratchet {
    Ratchet::from_serializable(SerializableSession::from_cfe_v1(cfe).unwrap()).unwrap()
}

/// All setup copies and imports happen outside the measured operation.
pub struct ReaderSnapshot {
    keys: Vec<u8>,
    kyber: Vec<u8>,
    coordination: Vec<u8>,
    session: Vec<u8>,
    local: String,
    peer: String,
}

impl ReaderSnapshot {
    pub fn new(core: &Orchestrator, local: &str, peer: &str) -> Self {
        Self {
            keys: core.export_private_keys_cfe().unwrap(),
            kyber: core.export_kyber_prekeys_cfe().unwrap(),
            coordination: core.export_orchestrator_state_cfe().unwrap(),
            session: core.export_session_cfe(peer).unwrap(),
            local: local.into(),
            peer: peer.into(),
        }
    }

    pub fn restore(&self) -> Orchestrator {
        let keys = cfe::decode_as(&self.keys, CfeMessageType::PrivateKeys).unwrap();
        let client = ClassicClient::<ClassicSuiteProvider>::from_private_keys_cfe(keys).unwrap();
        let mut core = Orchestrator::new(client, self.local.clone());
        core.import_kyber_prekeys_cfe(&self.kyber).unwrap();
        core.import_orchestrator_state_cfe(&self.coordination)
            .unwrap();
        core.import_session_cfe(&self.peer, &self.session).unwrap();
        core
    }
}

pub fn validate_actions(actions: &[Action], plaintext: &[u8], id: &str) {
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, Action::MessageDecrypted { .. }))
            .count(),
        1,
        "unexpected receive actions: {actions:?}"
    );
    assert!(actions.iter().any(|a| matches!(a, Action::MessageDecrypted { message_id, plaintext: p, .. } if message_id == id && p == plaintext)));
    assert!(actions.iter().any(|a| matches!(a, Action::SaveToSecureStore { slot: SecureStoreSlot::Session { .. }, data } if !data.is_empty())));
    assert!(!actions.iter().any(|a| matches!(
        a,
        Action::DuplicateDropped { .. } | Action::NotifyError { .. } | Action::CheckAckInDb { .. }
    )));
}

pub fn verify_restore(pair: &Pair) {
    let mut alice = ReaderSnapshot::new(&pair.alice, &pair.alice_id, &pair.bob_id).restore();
    let mut bob = ReaderSnapshot::new(&pair.bob, &pair.bob_id, &pair.alice_id).restore();
    let original = decode_session(&pair.bob, &pair.alice_id);
    let restored = decode_session(&bob, &pair.alice_id);
    assert_eq!(restored.previous.len(), original.previous.len());
    assert_eq!(restored.skipped.len(), original.skipped.len());
    let wire = alice.encrypt_bytes_for(&pair.bob_id, b"roundtrip").unwrap();
    assert_eq!(
        bob.decrypt_bytes_for(&pair.alice_id, &wire).unwrap(),
        b"roundtrip"
    );
    let wire = bob.encrypt_bytes_for(&pair.alice_id, b"reverse").unwrap();
    assert_eq!(
        alice.decrypt_bytes_for(&pair.bob_id, &wire).unwrap(),
        b"reverse"
    );
    // Verify each retained state independently, without changing another trial's ratchet.
    for wire in pair.late.iter().rev() {
        let mut bob = ReaderSnapshot::new(&pair.bob, &pair.bob_id, &pair.alice_id).restore();
        assert_eq!(
            bob.decrypt_bytes_for(&pair.alice_id, wire).unwrap(),
            b"late"
        );
    }
}

/// Reproduce an observed baseline limitation separately from independent restore checks.
pub fn delayed_sequence(pair: &Pair) -> Result<(), String> {
    let mut bob = ReaderSnapshot::new(&pair.bob, &pair.bob_id, &pair.alice_id).restore();
    for (index, wire) in pair.late.iter().rev().enumerate() {
        let plaintext = bob
            .decrypt_bytes_for(&pair.alice_id, wire)
            .map_err(|e| format!("delayed index {index}: {e}"))?;
        if plaintext != b"late" {
            return Err("unexpected delayed plaintext".into());
        }
    }
    Ok(())
}

pub fn parse_stage(wire: &[u8], passes: usize, split: bool) {
    for _ in 1..passes {
        drop(black_box(wire_payload::unpack(black_box(wire)).unwrap()));
    }
    let decoded = wire_payload::unpack(black_box(wire)).unwrap();
    if split {
        let nonce = decoded.sealed_box[..12].to_vec();
        let ciphertext = decoded.sealed_box[12..].to_vec();
        drop(black_box((nonce, ciphertext)));
    }
    drop(black_box(decoded));
}

pub const CASES: &[(usize, usize)] = &[(0, 0), (100, 0), (500, 0), (900, 0), (0, 3), (500, 3)];
