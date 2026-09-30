//! `construct-docs/decisions/local-store-in-the-core.md`

use std::sync::{Arc, Mutex};

use construct_store::{
    Change, Chat, Contact, Insert, Message, PeerDevice, Reaction, Store, StoreError, StoreObserver,
    Table,
};

const KEY: [u8; 32] = [7; 32];

fn contact(id: &str, name: &str) -> Contact {
    Contact {
        id: id.into(),
        display_name: name.into(),
        is_contact: true,
        ..Default::default()
    }
}

fn chat(id: &str, peer: &str, time: Option<i64>, pinned: bool) -> Chat {
    Chat {
        id: id.into(),
        peer_id: peer.into(),
        last_message_time: time,
        is_pinned: pinned,
        ..Default::default()
    }
}

fn message(id: &str, chat: &str, order_key: &str, body: &[u8]) -> Message {
    Message {
        id: id.into(),
        chat_id: chat.into(),
        from_user_id: "a".into(),
        to_user_id: "b".into(),
        timestamp: 1_000,
        order_key: order_key.into(),
        body: body.to_vec(),
        ..Default::default()
    }
}

/// A contact with one chat, ready for messages.
fn with_chat(store: &Store) {
    store.upsert_contact(&contact("peer", "Bob")).unwrap();
    store
        .upsert_chat(&chat("c1", "peer", Some(1), false))
        .unwrap();
}

// MARK: - Encryption

/// Mutation: drop the `PRAGMA key` — the file is plain SQLite and this reddens.
#[test]
fn nothing_on_disk_is_in_the_clear() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    {
        let store = Store::open(&path, &KEY).unwrap();
        store
            .upsert_contact(&contact("peer", "Alice-Unmistakable"))
            .unwrap();
        store
            .upsert_chat(&chat("c1", "peer", Some(1), false))
            .unwrap();
        store
            .insert_message(
                &message("m1", "c1", "k1", b"body-Unmistakable"),
                Some("text-Unmistakable"),
            )
            .unwrap();
    }
    let mut bytes = std::fs::read(&path).unwrap();
    for sidecar in ["-wal", "-shm"] {
        if let Ok(more) = std::fs::read(format!("{}{sidecar}", path.display())) {
            bytes.extend(more);
        }
    }
    assert!(!bytes.starts_with(b"SQLite format 3"));
    for marker in [
        &b"Unmistakable"[..],
        b"Alice",
        b"contacts",
        b"message_search",
    ] {
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker),
            "{:?} readable on disk",
            String::from_utf8_lossy(marker)
        );
    }
}

/// A wrong key is an error, never an empty store: minting one over the account's would orphan it.
#[test]
fn another_key_does_not_open_the_store_and_the_right_one_still_does() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    Store::open(&path, &KEY)
        .unwrap()
        .upsert_contact(&contact("peer", "Bob"))
        .unwrap();

    assert!(matches!(
        Store::open(&path, &[8; 32]),
        Err(StoreError::WrongKey)
    ));
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.contact("peer").unwrap().unwrap().display_name, "Bob");
}

#[test]
fn a_key_of_the_wrong_length_is_refused() {
    assert!(matches!(
        Store::open_in_memory(&[1; 16]),
        Err(StoreError::KeyLength {
            expected: 32,
            got: 16
        })
    ));
}

// MARK: - Messages

#[test]
fn a_repeated_delivery_is_reported_not_duplicated() {
    let store = Store::open_in_memory(&KEY).unwrap();
    with_chat(&store);
    let m = message("m1", "c1", "k1", b"hi");
    assert_eq!(
        store.insert_message(&m, Some("hi there")).unwrap(),
        Insert::Inserted
    );
    assert_eq!(
        store.insert_message(&m, Some("hi there")).unwrap(),
        Insert::AlreadyPresent
    );
    assert_eq!(store.messages_before("c1", None, 10).unwrap().len(), 1);
}

/// Pages are `(order_key, id)` order — total, so equal keys never swap between reads.
#[test]
fn pages_run_back_through_the_transcript_oldest_first() {
    let store = Store::open_in_memory(&KEY).unwrap();
    with_chat(&store);
    for (id, key) in [
        ("m1", "k1"),
        ("m2", "k2"),
        ("m3b", "k3"),
        ("m3a", "k3"),
        ("m4", "k4"),
    ] {
        store
            .insert_message(&message(id, "c1", key, b"x"), None)
            .unwrap();
    }
    let ids = |page: Vec<Message>| page.into_iter().map(|m| m.id).collect::<Vec<_>>();

    let newest = store.messages_before("c1", None, 3).unwrap();
    assert_eq!(ids(newest.clone()), ["m3a", "m3b", "m4"]);
    let oldest = &newest[0];
    let earlier = store
        .messages_before("c1", Some((&oldest.order_key, &oldest.id)), 3)
        .unwrap();
    assert_eq!(ids(earlier), ["m1", "m2"]);
}

#[test]
fn delivery_status_and_edits_are_written_once() {
    let store = Store::open_in_memory(&KEY).unwrap();
    with_chat(&store);
    store
        .insert_message(&message("m1", "c1", "k1", b"old"), Some("old words"))
        .unwrap();

    assert!(store.set_delivery_status("m1", 2).unwrap());
    assert!(
        !store.set_delivery_status("m1", 2).unwrap(),
        "no change, no event"
    );
    assert!(
        store
            .edit_message("m1", b"new", Some("fresh words"), 5)
            .unwrap()
    );

    let m = store.message("m1").unwrap().unwrap();
    assert_eq!(
        (
            m.body.as_slice(),
            m.is_edited,
            m.edited_at,
            m.delivery_status
        ),
        (&b"new"[..], true, Some(5), 2)
    );
    assert!(
        store.search("old words", 10).unwrap().is_empty(),
        "an edit replaces what is findable"
    );
    assert_eq!(store.search("fresh", 10).unwrap().len(), 1);
}

// MARK: - Search

#[test]
fn search_finds_text_in_any_script_and_treats_the_query_as_text() {
    let store = Store::open_in_memory(&KEY).unwrap();
    with_chat(&store);
    store
        .insert_message(
            &message("en", "c1", "k1", b""),
            Some("Meet me at the station"),
        )
        .unwrap();
    store
        .insert_message(
            &message("ru", "c1", "k2", b""),
            Some("Встретимся на вокзале"),
        )
        .unwrap();
    store
        .insert_message(&message("ja", "c1", "k3", b""), Some("駅で会いましょう"))
        .unwrap();
    store
        .insert_message(&message("q", "c1", "k4", b""), Some("say \"OR\" loudly"))
        .unwrap();

    let found = |q: &str| {
        store
            .search(q, 10)
            .unwrap()
            .into_iter()
            .map(|h| h.message_id)
            .collect::<Vec<_>>()
    };
    assert_eq!(found("STATION"), ["en"]);
    assert_eq!(found("вокзал"), ["ru"]);
    assert_eq!(found("会いまし"), ["ja"], "no word boundaries needed");
    assert_eq!(found("\"OR\" lou"), ["q"], "quotes and operators are text");
    assert!(found("me OR vokzal").is_empty());
}

/// Mutation: drop the delete trigger — deleted text stays findable and this reddens.
#[test]
fn what_is_deleted_is_no_longer_found() {
    let store = Store::open_in_memory(&KEY).unwrap();
    with_chat(&store);
    store.upsert_contact(&contact("p2", "Carol")).unwrap();
    store
        .upsert_chat(&chat("c2", "p2", Some(2), false))
        .unwrap();
    store
        .insert_message(&message("m1", "c1", "k1", b""), Some("secret one"))
        .unwrap();
    store
        .insert_message(&message("m2", "c1", "k2", b""), Some("secret two"))
        .unwrap();
    store
        .insert_message(&message("m3", "c2", "k1", b""), Some("secret three"))
        .unwrap();

    store.delete_message("m1").unwrap();
    assert_eq!(store.search("secret", 10).unwrap().len(), 2);
    store.delete_chat("c1").unwrap();
    assert_eq!(store.search("secret", 10).unwrap().len(), 1);
    store.delete_contact("p2").unwrap();
    assert!(store.search("secret", 10).unwrap().is_empty());
    assert!(
        store.message("m3").unwrap().is_none(),
        "the contact took its chat and messages"
    );
}

// MARK: - Lists

#[test]
fn the_chat_list_is_pinned_then_recent_then_empty() {
    let store = Store::open_in_memory(&KEY).unwrap();
    for p in ["p1", "p2", "p3", "p4"] {
        store.upsert_contact(&contact(p, p)).unwrap();
    }
    store
        .upsert_chat(&chat("old", "p1", Some(10), false))
        .unwrap();
    store
        .upsert_chat(&chat("new", "p2", Some(20), false))
        .unwrap();
    store
        .upsert_chat(&chat("empty", "p3", None, false))
        .unwrap();
    store
        .upsert_chat(&chat("pinned", "p4", Some(1), true))
        .unwrap();

    let order = store
        .chats()
        .unwrap()
        .into_iter()
        .map(|c| c.id)
        .collect::<Vec<_>>();
    assert_eq!(order, ["pinned", "new", "old", "empty"]);
}

#[test]
fn contacts_are_listed_by_the_name_shown_for_them() {
    let store = Store::open_in_memory(&KEY).unwrap();
    store.upsert_contact(&contact("1", "zed")).unwrap();
    store
        .upsert_contact(&Contact {
            local_alias: Some("Amy".into()),
            ..contact("2", "yuki")
        })
        .unwrap();
    store
        .upsert_contact(&Contact {
            is_contact: false,
            ..contact("3", "aaa")
        })
        .unwrap();
    let ids = store
        .contacts()
        .unwrap()
        .into_iter()
        .map(|c| c.id)
        .collect::<Vec<_>>();
    assert_eq!(ids, ["2", "1"]);
}

#[test]
fn a_reaction_is_one_per_person_per_message() {
    let store = Store::open_in_memory(&KEY).unwrap();
    let r = |emoji: &str, at: i64| Reaction {
        target_message_id: "m1".into(),
        reactor_user_id: "bob".into(),
        emoji: emoji.into(),
        timestamp_ms: at,
        received_at: None,
    };
    store.upsert_reaction(&r("👍", 1)).unwrap();
    store.upsert_reaction(&r("❤️", 2)).unwrap();
    assert_eq!(store.reactions("m1").unwrap(), [r("❤️", 2)]);
    store.delete_reaction("m1", "bob").unwrap();
    assert!(store.reactions("m1").unwrap().is_empty());
}

// MARK: - Peer devices

#[test]
fn a_device_keeps_its_first_account_and_an_empty_list_forgets_nothing() {
    let store = Store::open_in_memory(&KEY).unwrap();
    let d = |id: &str, account: &str| PeerDevice {
        device_id: id.into(),
        account_id: account.into(),
        identity_key: vec![1],
        first_seen_at: 1,
    };
    assert_eq!(
        store.record_peer_device(&d("d1", "alice")).unwrap(),
        Insert::Inserted
    );
    assert_eq!(
        store.record_peer_device(&d("d1", "mallory")).unwrap(),
        Insert::AlreadyPresent
    );
    store.record_peer_device(&d("d2", "alice")).unwrap();

    assert!(store.retain_peer_devices("alice", &[]).unwrap().is_empty());
    assert_eq!(store.peer_devices("alice").unwrap().len(), 2);
    assert_eq!(
        store.retain_peer_devices("alice", &["d2".into()]).unwrap(),
        ["d1"]
    );
    assert_eq!(store.peer_devices("alice").unwrap(), [d("d2", "alice")]);
    assert!(store.peer_devices("mallory").unwrap().is_empty());
}

/// Oldest first, so a single-device peer's device stays first; one bundle answer records several
/// devices in the same millisecond, and the id orders those the same way on every run.
#[test]
fn an_accounts_devices_come_oldest_first_and_ties_break_by_id() {
    let store = Store::open_in_memory(&KEY).unwrap();
    let d = |id: &str, account: &str, at: i64| PeerDevice {
        device_id: id.into(),
        account_id: account.into(),
        identity_key: vec![1],
        first_seen_at: at,
    };
    store.record_peer_device(&d("c", "alice", 5)).unwrap();
    store
        .record_peer_device(&d("zz-first", "alice", 1))
        .unwrap();
    store.record_peer_device(&d("b", "alice", 5)).unwrap();
    store.record_peer_device(&d("a", "bob", 9)).unwrap();

    let ids = |v: Vec<PeerDevice>| v.into_iter().map(|d| d.device_id).collect::<Vec<_>>();
    assert_eq!(
        ids(store.peer_devices("alice").unwrap()),
        ["zz-first", "b", "c"]
    );
    assert_eq!(
        ids(store.all_peer_devices().unwrap()),
        ["zz-first", "b", "c", "a"]
    );
}

#[test]
fn a_device_is_found_by_id_under_the_account_it_was_first_recorded_for() {
    let store = Store::open_in_memory(&KEY).unwrap();
    let d = |account: &str| PeerDevice {
        device_id: "d1".into(),
        account_id: account.into(),
        identity_key: vec![7],
        first_seen_at: 3,
    };
    assert_eq!(store.peer_device("d1").unwrap(), None);
    store.record_peer_device(&d("alice")).unwrap();
    store.record_peer_device(&d("mallory")).unwrap();
    assert_eq!(store.peer_device("d1").unwrap(), Some(d("alice")));
}

// MARK: - Observer, wipe, schema

struct Recorder {
    store: Mutex<Option<Arc<Store>>>,
    seen: Mutex<Vec<Change>>,
}

impl StoreObserver for Recorder {
    fn on_change(&self, change: Change) {
        // Reading inside the callback: it runs after the lock is released, so this must not
        // deadlock.
        if let Some(store) = self.store.lock().unwrap().as_ref() {
            store.chats().unwrap();
        }
        self.seen.lock().unwrap().push(change);
    }
}

#[test]
fn writes_are_announced_after_they_commit() {
    let store = Arc::new(Store::open_in_memory(&KEY).unwrap());
    let recorder = Arc::new(Recorder {
        store: Mutex::new(Some(store.clone())),
        seen: Mutex::new(Vec::new()),
    });
    store.set_observer(Some(recorder.clone()));

    with_chat(&store);
    store
        .insert_message(&message("m1", "c1", "k1", b""), None)
        .unwrap();
    store
        .insert_message(&message("m1", "c1", "k1", b""), None)
        .unwrap();

    let seen = recorder.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            Change {
                table: Table::Contacts,
                ids: vec!["peer".into()]
            },
            Change {
                table: Table::Chats,
                ids: vec!["c1".into()]
            },
            Change {
                table: Table::Messages,
                ids: vec!["m1".into()]
            },
        ],
        "a repeat is not a change"
    );
    *recorder.store.lock().unwrap() = None;
}

#[test]
fn wipe_leaves_no_file_behind() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let store = Store::open(&path, &KEY).unwrap();
    with_chat(&store);
    store.wipe().unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn a_store_from_a_newer_build_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    drop(Store::open(&path, &KEY).unwrap());
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", "07".repeat(32)))
            .unwrap();
        conn.pragma_update(None, "user_version", Store::schema_version() + 1)
            .unwrap();
    }
    assert!(matches!(
        Store::open(&path, &KEY),
        Err(StoreError::SchemaTooNew { .. })
    ));
}

// MARK: - Server message ids

/// A receipt or decryption error names the server's id of a sealed copy; the store answers with
/// ours, in any case, until the ids are older than the server's queue.
#[test]
fn a_server_id_maps_back_to_our_message_until_it_is_forgotten() {
    let store = Store::open_in_memory(&KEY).unwrap();
    store
        .record_server_message_id("E474825E-AAAA", "8B403CE9-BBBB", 100)
        .unwrap();
    store
        .record_server_message_id("f00d-0001", "8b403ce9-bbbb", 200)
        .unwrap();

    assert_eq!(
        store.local_message_id("e474825e-aaaa").unwrap().as_deref(),
        Some("8b403ce9-bbbb")
    );
    assert_eq!(
        store.local_message_id("F00D-0001").unwrap().as_deref(),
        Some("8b403ce9-bbbb")
    );
    assert_eq!(store.local_message_id("unknown").unwrap(), None);

    assert_eq!(store.forget_server_message_ids_before(150).unwrap(), 1);
    assert_eq!(store.local_message_id("e474825e-aaaa").unwrap(), None);
    assert!(store.local_message_id("f00d-0001").unwrap().is_some());
}
