//! The local store as iOS, macOS and Android see it: the UniFFI surface over `construct-store`.
//! The store's own behaviour is `store/tests/store_test.rs`; this checks the crossing.
#![cfg(any(feature = "ios", feature = "mac", feature = "android"))]

use std::sync::{Arc, Mutex};

use construct_core::{
    LocalChat, LocalContact, LocalInsert, LocalMessage, LocalOwnProfile, LocalPeerDevice,
    LocalStore, LocalStoreChange, LocalStoreError, LocalStoreObserver, LocalStoreTable,
};

const KEY: [u8; 32] = [3; 32];

fn contact(id: &str) -> LocalContact {
    LocalContact {
        id: id.into(),
        username: String::new(),
        display_name: "Bob".into(),
        local_alias: None,
        avatar: None,
        known_identity_key: None,
        account_address: None,
        is_contact: true,
        is_blocked: false,
        is_sharing_with_me: false,
        am_i_sharing_with: false,
        shared_with_me_at: None,
        added_at: None,
        kt_status: 0,
        security_notice: 0,
        profile_edited_at_ms: 0,
        pending_avatar_ref: None,
        pending_avatar_since: None,
    }
}

fn message(id: &str, order_key: &str) -> LocalMessage {
    LocalMessage {
        id: id.into(),
        chat_id: "c1".into(),
        from_user_id: "a".into(),
        to_user_id: "b".into(),
        is_sent_by_me: true,
        timestamp: 1,
        order_key: order_key.into(),
        body: vec![1, 2, 3],
        content_type: 0,
        delivery_status: 0,
        retry_count: 0,
        suite_id: 0,
        is_edited: false,
        edited_at: None,
        reply_to_message_id: None,
        reply_to_content: None,
        transcript_text: None,
        transcript_language: None,
        transcript_generated_at: None,
    }
}

struct Seen(Arc<Mutex<Vec<(String, Vec<String>)>>>);

impl LocalStoreObserver for Seen {
    fn on_change(&self, change: LocalStoreChange) {
        let table = match change.table {
            LocalStoreTable::Contacts => "contacts",
            LocalStoreTable::Chats => "chats",
            LocalStoreTable::Messages => "messages",
            LocalStoreTable::OwnProfile => "own_profile",
            _ => "other",
        };
        self.0.lock().unwrap().push((table.into(), change.ids));
    }
}

#[test]
fn a_client_writes_reads_pages_and_hears_about_it() {
    let store = LocalStore::in_memory(KEY.to_vec()).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    store.set_observer(Some(Box::new(Seen(seen.clone()))));

    store.upsert_contact(contact("peer")).unwrap();
    store
        .upsert_chat(LocalChat {
            id: "c1".into(),
            peer_id: "peer".into(),
            last_message_text: None,
            last_message_time: Some(1),
            is_pinned: false,
            unread_count: 0,
        })
        .unwrap();
    assert!(matches!(
        store
            .insert_message(message("m1", "k1"), Some("hello there".into()))
            .unwrap(),
        LocalInsert::Inserted
    ));
    assert!(matches!(
        store.insert_message(message("m1", "k1"), None).unwrap(),
        LocalInsert::AlreadyPresent
    ));
    store.insert_message(message("m2", "k2"), None).unwrap();

    let newest = store.messages_before("c1".into(), None, None, 1).unwrap();
    assert_eq!(
        newest.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        ["m2"]
    );
    let earlier = store
        .messages_before("c1".into(), Some("k2".into()), Some("m2".into()), 5)
        .unwrap();
    assert_eq!(
        earlier.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        ["m1"]
    );
    assert_eq!(earlier[0].body, [1, 2, 3]);
    assert_eq!(store.search("hello".into(), 5).unwrap()[0].message_id, "m1");

    assert_eq!(
        seen.lock()
            .unwrap()
            .iter()
            .map(|(t, _)| t.as_str())
            .collect::<Vec<_>>(),
        ["contacts", "chats", "messages", "messages"]
    );
}

/// After a wipe the object is closed, not a fresh store — and the file is gone.
#[test]
fn a_wiped_store_answers_closed_and_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local.db");
    let store = LocalStore::new(path.to_string_lossy().into(), KEY.to_vec()).unwrap();
    store.upsert_contact(contact("peer")).unwrap();

    store.wipe().unwrap();
    assert!(matches!(store.contacts(), Err(LocalStoreError::Closed)));
    assert!(matches!(store.wipe(), Err(LocalStoreError::Closed)));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn a_wrong_key_is_its_own_error() {
    let dir = tempfile::tempdir().unwrap();
    let path: String = dir.path().join("local.db").to_string_lossy().into();
    LocalStore::new(path.clone(), KEY.to_vec())
        .unwrap()
        .upsert_contact(contact("peer"))
        .unwrap();
    assert!(matches!(
        LocalStore::new(path, vec![4; 32]),
        Err(LocalStoreError::WrongKey)
    ));
    assert!(matches!(
        LocalStore::in_memory(vec![0; 8]),
        Err(LocalStoreError::KeyLength)
    ));
}

#[test]
fn a_peer_device_is_found_by_id_and_listed() {
    let store = LocalStore::in_memory(KEY.to_vec()).unwrap();
    let device = |id: &str, at: i64| LocalPeerDevice {
        device_id: id.into(),
        account_id: "alice".into(),
        identity_key: vec![9; 32],
        first_seen_at: at,
    };
    store.record_peer_device(device("later", 2)).unwrap();
    store.record_peer_device(device("earlier", 1)).unwrap();

    assert_eq!(
        store
            .peer_device("later".into())
            .unwrap()
            .map(|d| d.first_seen_at),
        Some(2)
    );
    assert!(store.peer_device("none".into()).unwrap().is_none());
    let ids = |v: Vec<LocalPeerDevice>| v.into_iter().map(|d| d.device_id).collect::<Vec<_>>();
    assert_eq!(
        ids(store.peer_devices("alice".into()).unwrap()),
        ["earlier", "later"]
    );
    assert_eq!(ids(store.all_peer_devices().unwrap()), ["earlier", "later"]);
}

#[test]
fn a_server_message_id_maps_back_across_the_crossing() {
    let store = LocalStore::in_memory(KEY.to_vec()).unwrap();
    store
        .record_server_message_id("SERVER-1".into(), "Local-1".into(), 10)
        .unwrap();
    assert_eq!(
        store
            .local_message_id("server-1".into())
            .unwrap()
            .as_deref(),
        Some("local-1")
    );
    assert_eq!(store.forget_server_message_ids_before(11).unwrap(), 1);
    assert_eq!(store.local_message_id("server-1".into()).unwrap(), None);
}

/// A narrow write and our own profile cross the boundary with their optionals intact, and are
/// announced under their tables.
#[test]
fn contact_writes_and_our_profile_cross_the_boundary() {
    let store = LocalStore::in_memory(KEY.to_vec()).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    store.set_observer(Some(Box::new(Seen(seen.clone()))));

    store.upsert_contact(contact("peer")).unwrap();
    assert!(
        store
            .set_contact_alias("peer".into(), Some("B".into()))
            .unwrap()
    );
    assert_eq!(
        store
            .contact("peer".into())
            .unwrap()
            .unwrap()
            .local_alias
            .as_deref(),
        Some("B")
    );
    assert!(store.set_contact_alias("peer".into(), None).unwrap());
    assert_eq!(
        store.contact("peer".into()).unwrap().unwrap().local_alias,
        None
    );
    assert!(!store.set_contact_blocked("nobody".into(), true).unwrap());

    store
        .set_own_profile(LocalOwnProfile {
            account_id: "me".into(),
            username: "max".into(),
            display_name: "Max".into(),
            avatar: Some(vec![1]),
            profile_edited_at_ms: 5,
        })
        .unwrap();
    let me = store.own_profile().unwrap().unwrap();
    assert_eq!(
        (me.display_name.as_str(), me.avatar),
        ("Max", Some(vec![1]))
    );

    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.last().unwrap(),
        &("own_profile".to_string(), vec!["me".to_string()])
    );
    assert_eq!(seen.iter().filter(|(t, _)| t == "contacts").count(), 3);
}
