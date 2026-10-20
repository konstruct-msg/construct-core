//! The UniFFI surface's tests, out of line: `uniffi_bindings.rs` is the binding, this is
//! what pins it. Moved here from the middle of that file in 0.54.2 (TODO 201).

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
    let bob_bundle_bytes = bundle_fields_to_binary(bob.get_registration_bundle_fields().unwrap());

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

fn history_known(peer: &HistoryPeerKeys) -> HistoryKnownKeys {
    HistoryKnownKeys {
        identity_public: peer.identity_public.clone(),
        hybrid_public: peer.hybrid_public.clone(),
    }
}

/// A platform's read loop: exactly `need()` bytes at a time from `stream`.
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
            0,
            None,
        )
        .unwrap(),
        content_type: 0,
        sender_certificate: None,
        envelope_session: None,
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

    let restored = create_orchestrator_core_from_keys(private_keys, "kyber_owner".into()).unwrap();
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
/// timestamps. PQXDH v2 opens a PQ-ratchet session on the one-time Kyber key; the first message's
/// components carry the handshake; the responder opens the session from them, burns the key
/// and hands back the prekeys to persist.
/// A replayed bundle is a typed refusal over the FFI, with both epochs in it, and the held
/// session stays (TODO 176).
///
/// Mutation: map the orchestrator's refusal to `SessionInitializationFailed` instead — the
/// client is back to parsing text.
#[test]
fn a_replayed_bundle_is_a_typed_refusal_with_both_epochs() {
    let alice = make_orchestrator("alice_user_id");
    alice.ensure_hybrid_signature_key().unwrap();
    let bob = make_orchestrator("bob_user_id");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut bundle = pq_bundle(&bob);
    bundle.suite_id = 1;
    bundle.spk_uploaded_at = now;
    bundle.kyber_spk_uploaded_at = now;
    bundle.kyber_spk_rotation_epoch = 5;
    bundle.spk_rotation_epoch = 9;
    alice
        .init_session("bob_user_id".to_string(), bundle.clone())
        .unwrap();

    bundle.spk_rotation_epoch = 8;
    let err = alice
        .reopen_session("bob_user_id".to_string(), bundle.clone())
        .unwrap_err();
    assert!(
        matches!(
            err,
            CryptoError::PeerSpkEpochRegressed {
                received: 8,
                known: 9
            }
        ),
        "{err:?}"
    );
    assert!(alice.has_session("bob_user_id".to_string()));

    bundle.spk_rotation_epoch = 9;
    alice
        .reopen_session("bob_user_id".to_string(), bundle)
        .unwrap();
}

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
        "the PQ-ratchet suite is mandatory"
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
        .init_receiving_session_from_wire_payload(certified(&server, &alice, &carol), vec![0u8; 8])
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
/// AEAD associated data from the suite and the PQ-ratchet tags on the wire; before task #12 it
/// defaulted the suite to the bundle's crypto suite and failed with
/// `"All 1 prekey(s) failed. AEAD decryption failed"`. The pure-core
/// `test_client_negotiates_pq_ratchet_from_bundle_capability` cannot catch this: it hands the
/// full struct straight across, bypassing this boundary (which is why the bug shipped).
#[test]
fn test_pq_ratchet_first_message_survives_uniffi_wire() {
    use crate::crypto::SuiteID;

    let (alice, _) = named_core();
    let (bob, bob_id) = named_core();
    let server = crate::crypto::sealed_sender::test_support::TestServer::new();

    let session = alice
        .init_session(bob_id.clone(), pq_bundle(&bob))
        .expect("init_session should succeed");

    // Precondition: the sending session must really be the PQ-ratchet suite, else this test proves nothing.
    assert_eq!(
        alice.get_session_suite_id(bob_id),
        SuiteID::PQ_RATCHET.as_u16(),
        "setup must negotiate the PQ-ratchet suite (PQ_RATCHET_ENABLED is on in test builds)"
    );

    let plaintext = b"pq ratchet over the wire".to_vec();
    let wire = alice.encrypt_to_wire(session, plaintext.clone()).unwrap();

    let bob_result = bob
        .init_receiving_session_from_wire_payload(certified(&server, &alice, &bob), wire)
        .expect("Bob must establish a receiving session from a PQ-ratchet first message");

    assert_eq!(bob_result.decrypted_message, plaintext);
}

/// Variant-2 guard: every field must survive the core's packer → `wire_payload_unpack`, the
/// one reader the platforms call, instead of each SDK re-implementing the byte layout (the
/// original wire-drop). If the reader ever loses a field, this fails.
#[test]
fn test_wire_payload_pack_roundtrip_pq_ratchet() {
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
        suite_id: 4,
        kem_ciphertext: Some(vec![0x22; 1088]),
        sealed_box: vec![0x33; 60],
        pq_message_epoch: 9,
        pq_ratchet_field: pq_field_to_bytes(&Some(field.clone())),
        pqxdh_v2: true,
        kem_identity: Some(vec![0x44; 1568]),
        identity_proof_ciphertext: Some(vec![0x55; 1568]),
        pq_key_index: 300,
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
        original.pq_key_index,
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

    assert_eq!(decoded.suite_id, 4, "suite_id must survive the wire");
    assert_eq!(
        decoded.pq_key_index, 300,
        "a two-byte key index must survive the wire"
    );
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

    let result = alice.encrypt_to_wire("nonexistent_user".to_string(), b"test message".to_vec());

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
