//! `construct-docs/decisions/local-store-in-the-core.md`

use std::sync::{Arc, Mutex};

use construct_store::{
    Change, Chat, Contact, IdentityKeyPin, Insert, Message, OwnProfile, PeerDevice, Reaction,
    Store, StoreError, StoreObserver, Table,
    delivery::{self, ArchiveOutcome, DELIVERED, FAILED, QUEUED, SENDING, SENT},
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

// MARK: - Contact writes and our own profile (schema 2)

#[derive(Default)]
struct Changes {
    changes: Mutex<Vec<Change>>,
}

impl StoreObserver for Changes {
    fn on_change(&self, change: Change) {
        self.changes.lock().unwrap().push(change);
    }
}

fn full_contact(id: &str) -> Contact {
    Contact {
        id: id.into(),
        username: "ada".into(),
        display_name: "Ada".into(),
        local_alias: Some("A".into()),
        avatar: Some(vec![1, 2, 3]),
        known_identity_key: Some(vec![9; 32]),
        account_address: Some(vec![8; 32]),
        is_contact: true,
        is_blocked: false,
        is_sharing_with_me: true,
        am_i_sharing_with: true,
        shared_with_me_at: Some(10),
        added_at: Some(20),
        kt_status: 1,
        security_notice: 0,
        profile_edited_at_ms: 30,
        pending_avatar_ref: Some(vec![7]),
        pending_avatar_since: Some(40),
    }
}

/// Every field round-trips, the three schema-2 ones included. Mutation: drop one from
/// `CONTACT_COLUMNS`/`contact_row` or from the upsert — the row reads back different.
#[test]
fn a_contact_reads_back_as_written() {
    let store = Store::open_in_memory(&KEY).unwrap();
    store.upsert_contact(&full_contact("a")).unwrap();
    assert_eq!(store.contact("a").unwrap(), Some(full_contact("a")));
}

/// A write names its fields and leaves the rest. Mutation: implement a setter as read, change,
/// `upsert_contact` — a concurrent writer of another field is undone; here, a setter that
/// rewrites more than its fields changes the row beyond the one field.
#[test]
fn each_contact_write_changes_only_its_fields() {
    let store = Store::open_in_memory(&KEY).unwrap();
    store.upsert_contact(&full_contact("a")).unwrap();
    let mut expected = full_contact("a");

    assert!(store.set_contact_blocked("a", true).unwrap());
    expected.is_blocked = true;
    assert!(store.set_contact_alias("a", None).unwrap());
    expected.local_alias = None;
    assert!(store.set_sharing_with("a", false).unwrap());
    expected.am_i_sharing_with = false;
    assert!(store.set_identity_key("a", Some(&[5; 32])).unwrap());
    expected.known_identity_key = Some(vec![5; 32]);
    assert!(store.set_kt_status("a", 2).unwrap());
    expected.kt_status = 2;
    assert!(store.set_account_address("a", None).unwrap());
    expected.account_address = None;
    assert!(store.set_security_notice("a", 1).unwrap());
    expected.security_notice = 1;
    assert!(store.set_contact_names("a", "ada2", "Ada Two").unwrap());
    expected.username = "ada2".into();
    expected.display_name = "Ada Two".into();
    assert!(
        store
            .set_contact_avatar("a", Some(&[4]), None, None)
            .unwrap()
    );
    expected.avatar = Some(vec![4]);
    expected.pending_avatar_ref = None;
    expected.pending_avatar_since = None;

    assert_eq!(store.contact("a").unwrap(), Some(expected));
}

/// A shared profile turns sharing on and writes the name and both times.
#[test]
fn a_shared_profile_is_applied_whole() {
    let store = Store::open_in_memory(&KEY).unwrap();
    let mut c = contact("a", "");
    c.is_sharing_with_me = false;
    store.upsert_contact(&c).unwrap();
    assert!(store.apply_shared_profile("a", "Ada", 100, 200).unwrap());
    let read = store.contact("a").unwrap().unwrap();
    assert!(read.is_sharing_with_me);
    assert_eq!(read.display_name, "Ada");
    assert_eq!(read.shared_with_me_at, Some(100));
    assert_eq!(read.profile_edited_at_ms, 200);
}

/// Marking a contact keeps the date it was first added. Mutation: drop the `COALESCE`.
#[test]
fn marking_a_contact_keeps_when_it_was_added() {
    let store = Store::open_in_memory(&KEY).unwrap();
    let mut c = contact("a", "Ada");
    c.is_contact = false;
    c.added_at = Some(5);
    store.upsert_contact(&c).unwrap();
    store
        .upsert_contact(&Contact {
            id: "b".into(),
            ..Default::default()
        })
        .unwrap();

    assert!(store.mark_contact("a", 99).unwrap());
    assert!(store.mark_contact("b", 99).unwrap());
    let a = store.contact("a").unwrap().unwrap();
    assert!(a.is_contact);
    assert_eq!(a.added_at, Some(5));
    assert_eq!(store.contact("b").unwrap().unwrap().added_at, Some(99));
}

/// A write to a row that does not exist reports it, creates nothing and announces nothing.
/// Mutation: notify unconditionally — observers rebuild for a row that is not there.
#[test]
fn a_write_to_no_row_is_reported_and_silent() {
    let store = Store::open_in_memory(&KEY).unwrap();
    let seen = Arc::new(Changes::default());
    store.set_observer(Some(seen.clone()));
    assert!(!store.set_contact_blocked("nobody", true).unwrap());
    assert_eq!(store.contact("nobody").unwrap(), None);
    assert!(seen.changes.lock().unwrap().is_empty());
}

/// Every write names its table and row. Mutation: drop the notify in `update_contact`.
#[test]
fn contact_writes_are_announced() {
    let store = Store::open_in_memory(&KEY).unwrap();
    store.upsert_contact(&full_contact("a")).unwrap();
    let seen = Arc::new(Changes::default());
    store.set_observer(Some(seen.clone()));
    store.set_contact_alias("a", Some("B")).unwrap();
    assert_eq!(
        *seen.changes.lock().unwrap(),
        vec![Change {
            table: Table::Contacts,
            ids: vec!["a".into()]
        }]
    );
}

/// The list of contacts is people marked as contacts; every row is everyone we hold a row for.
#[test]
fn every_row_includes_people_who_are_not_contacts() {
    let store = Store::open_in_memory(&KEY).unwrap();
    store.upsert_contact(&contact("b", "Bea")).unwrap();
    let mut stranger = contact("a", "Al");
    stranger.is_contact = false;
    store.upsert_contact(&stranger).unwrap();

    let ids = |rows: Vec<Contact>| rows.into_iter().map(|c| c.id).collect::<Vec<_>>();
    assert_eq!(ids(store.contacts().unwrap()), vec!["b"]);
    assert_eq!(ids(store.every_contact().unwrap()), vec!["a", "b"]);
}

/// The narrow reads answer from the field they are named for.
#[test]
fn pins_pending_avatars_and_sharing_are_found_by_their_field() {
    let store = Store::open_in_memory(&KEY).unwrap();
    store.upsert_contact(&full_contact("a")).unwrap();
    store.upsert_contact(&contact("b", "Bea")).unwrap();

    assert_eq!(
        store.identity_key_pins().unwrap(),
        vec![IdentityKeyPin {
            contact_id: "a".into(),
            key: vec![9; 32]
        }]
    );
    let pending = store.contacts_with_pending_avatar().unwrap();
    assert_eq!(
        pending.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        vec!["a"]
    );
    assert_eq!(store.sharing_with().unwrap(), vec!["a"]);
}

/// Our profile is one row, not a contact. Mutation: drop the `one = 1` key — a second set adds a
/// row and the read takes either.
#[test]
fn our_profile_is_one_row_and_not_a_contact() {
    let store = Store::open_in_memory(&KEY).unwrap();
    assert_eq!(store.own_profile().unwrap(), None);
    let seen = Arc::new(Changes::default());
    store.set_observer(Some(seen.clone()));

    let mut me = OwnProfile {
        account_id: "me".into(),
        username: "max".into(),
        display_name: "Max".into(),
        avatar: None,
        profile_edited_at_ms: 1,
    };
    store.set_own_profile(&me).unwrap();
    me.display_name = "Maxim".into();
    me.profile_edited_at_ms = 2;
    store.set_own_profile(&me).unwrap();

    assert_eq!(store.own_profile().unwrap(), Some(me));
    assert!(store.every_contact().unwrap().is_empty());
    assert_eq!(
        seen.changes.lock().unwrap().last(),
        Some(&Change {
            table: Table::OwnProfile,
            ids: vec!["me".into()]
        })
    );
}

// MARK: - Chat writes (schema 3)

fn store_with_peer(peer: &str) -> Store {
    let store = Store::open_in_memory(&KEY).unwrap();
    store.upsert_contact(&contact(peer, peer)).unwrap();
    store
}

/// One chat per peer, however it is asked for. Mutation: make `chats_by_peer` not unique — the
/// second insert adds a chat and `chat_for_peer` answers with either.
#[test]
fn a_peer_has_one_chat() {
    let store = store_with_peer("p");
    assert_eq!(
        store.insert_chat(&chat("c1", "p", None, false)).unwrap(),
        Insert::Inserted
    );
    assert_eq!(
        store.insert_chat(&chat("c2", "p", Some(5), false)).unwrap(),
        Insert::AlreadyPresent
    );
    assert_eq!(
        store.insert_chat(&chat("c1", "p", Some(5), false)).unwrap(),
        Insert::AlreadyPresent,
        "an insert never replaces"
    );
    assert_eq!(
        store.chat_for_peer("p").unwrap(),
        Some(chat("c1", "p", None, false))
    );
    assert!(store.upsert_chat(&chat("c3", "p", None, false)).is_err());
    assert_eq!(store.chats().unwrap().len(), 1);
    assert_eq!(store.chat_for_peer("nobody").unwrap(), None);
}

/// Messages arrive out of order; the preview only moves forward. Mutation: drop the time
/// condition from `advance_chat_preview` — the late older message replaces the newer preview.
#[test]
fn the_preview_moves_forward_unless_set() {
    let store = store_with_peer("p");
    store.upsert_chat(&chat("c", "p", None, false)).unwrap();
    let preview = |s: &Store| {
        let c = s.chat("c").unwrap().unwrap();
        (c.last_message_text, c.last_message_time)
    };

    assert!(store.advance_chat_preview("c", "first", 10).unwrap());
    assert!(store.advance_chat_preview("c", "newer", 20).unwrap());
    assert!(!store.advance_chat_preview("c", "late", 15).unwrap());
    assert_eq!(preview(&store), (Some("newer".into()), Some(20)));
    assert!(store.advance_chat_preview("c", "edited", 20).unwrap());
    assert_eq!(preview(&store), (Some("edited".into()), Some(20)));

    assert!(store.set_chat_preview("c", Some("left"), Some(3)).unwrap());
    assert_eq!(preview(&store), (Some("left".into()), Some(3)));
    assert!(store.set_chat_preview("c", None, None).unwrap());
    assert_eq!(preview(&store), (None, None));
}

/// Every arriving message counts, from whichever thread. Mutation: implement the increment as a
/// read and a write back — increments are lost and the total falls short.
#[test]
fn unread_counts_every_increment() {
    let store = Arc::new(store_with_peer("p"));
    store.upsert_chat(&chat("c", "p", None, false)).unwrap();
    let threads = (0..8)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || {
                for _ in 0..50 {
                    assert!(store.increment_unread("c").unwrap());
                }
            })
        })
        .collect::<Vec<_>>();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(store.chat("c").unwrap().unwrap().unread_count, 400);
    assert!(store.set_unread("c", 0).unwrap());
    assert_eq!(store.chat("c").unwrap().unwrap().unread_count, 0);
}

/// Each chat write changes its fields and nothing else, announces its chat, and reports a missing
/// one without announcing it. Mutation: write `is_pinned` from `set_unread`, or notify
/// unconditionally in `update_chat`.
#[test]
fn each_chat_write_changes_only_its_fields() {
    let store = store_with_peer("p");
    let mut expected = Chat {
        id: "c".into(),
        peer_id: "p".into(),
        last_message_text: Some("hi".into()),
        last_message_time: Some(7),
        is_pinned: false,
        unread_count: 3,
    };
    store.upsert_chat(&expected).unwrap();
    assert_eq!(store.chat("c").unwrap(), Some(expected.clone()));
    let seen = Arc::new(Changes::default());
    store.set_observer(Some(seen.clone()));

    assert!(store.set_chat_pinned("c", true).unwrap());
    expected.is_pinned = true;
    assert!(store.set_unread("c", 5).unwrap());
    expected.unread_count = 5;
    assert!(store.increment_unread("c").unwrap());
    expected.unread_count = 6;
    assert_eq!(store.chat("c").unwrap(), Some(expected));

    for missing in [
        store.set_chat_pinned("nobody", true).unwrap(),
        store.increment_unread("nobody").unwrap(),
        store.advance_chat_preview("nobody", "x", 1).unwrap(),
        store.set_chat_preview("nobody", None, None).unwrap(),
    ] {
        assert!(!missing);
    }
    let changes = seen.changes.lock().unwrap();
    assert_eq!(changes.len(), 3);
    assert!(
        changes
            .iter()
            .all(|c| c.table == Table::Chats && c.ids == ["c"])
    );
}

// MARK: - Messages domain (0.37.0)

/// A store with one chat `c` and messages `m1…m{n}`, ours, keyed `k1…k{n}`.
fn with_messages(n: usize) -> Store {
    let store = store_with_peer("p");
    store.upsert_chat(&chat("c", "p", None, false)).unwrap();
    for i in 1..=n {
        let mut m = message(&format!("m{i}"), "c", &format!("k{i}"), b"x");
        m.is_sent_by_me = true;
        store.insert_message(&m, None).unwrap();
    }
    store
}

fn status(store: &Store, id: &str) -> i16 {
    store.message(id).unwrap().unwrap().delivery_status
}

/// A transport failure is ignorance, not a negative result: the attempt statuses move among
/// themselves, and none overwrites evidence. Mutation: drop the rank condition in
/// `set_delivery_status` — a queued write demotes a delivered message.
#[test]
fn ignorance_never_overwrites_evidence() {
    let store = with_messages(1);
    for (write, lands) in [
        (QUEUED, true),
        (FAILED, true),
        (SENDING, true),
        (SENT, true),
        (QUEUED, false),
        (FAILED, false),
        (DELIVERED, true),
        (SENT, false),
        (QUEUED, false),
        (DELIVERED, false),
    ] {
        assert_eq!(
            store.set_delivery_status("m1", write).unwrap(),
            lands,
            "write {write}"
        );
    }
    assert_eq!(status(&store, "m1"), DELIVERED);
    assert!(!store.set_delivery_status("nothing", SENT).unwrap());
}

/// The SQL rank and the Rust rank are one rule: every pair of statuses lands exactly when the
/// Rust rule says it may. Mutation: rank `DELIVERED` 1 in `RANK_OF_STORED_STATUS` — a sent
/// write then replaces a delivered one.
#[test]
fn the_status_rule_is_one_rule() {
    let all = [SENDING, SENT, DELIVERED, QUEUED, FAILED];
    for from in all {
        for to in all {
            let store = with_messages(1);
            // From `SENDING` every status is reachable: it ranks lowest.
            store.set_delivery_status("m1", from).unwrap();
            assert_eq!(status(&store, "m1"), from);
            let lands = store.set_delivery_status("m1", to).unwrap();
            let rule = from != to && delivery::evidence_rank(to) >= delivery::evidence_rank(from);
            assert_eq!(lands, rule, "{from} → {to}");
        }
    }
}

/// A session archive keeps what the peer confirmed, queues the rest while attempts last, and
/// gives up after — the one write allowed to lower `SENT`. Mutation: return `Resend` for
/// `DELIVERED` in `after_session_archive`.
#[test]
fn a_session_archive_keeps_the_confirmed_and_requeues_the_rest() {
    let store = with_messages(3);
    store.set_delivery_status("m1", DELIVERED).unwrap();
    store.set_delivery_status("m2", SENT).unwrap();
    store.set_delivery_status("m3", SENT).unwrap();
    store.set_retry_count("m3", 3).unwrap();

    assert_eq!(
        store.apply_session_archive("m1", 3).unwrap(),
        Some(ArchiveOutcome::Keep)
    );
    assert_eq!(
        store.apply_session_archive("m2", 3).unwrap(),
        Some(ArchiveOutcome::Resend)
    );
    assert_eq!(
        store.apply_session_archive("m3", 3).unwrap(),
        Some(ArchiveOutcome::GiveUp)
    );
    assert_eq!(
        [
            status(&store, "m1"),
            status(&store, "m2"),
            status(&store, "m3")
        ],
        [DELIVERED, QUEUED, FAILED]
    );
    assert_eq!(store.apply_session_archive("nothing", 3).unwrap(), None);
}

/// Every attempt counts, from whichever thread. Mutation: read, add and write back.
#[test]
fn retries_count_every_attempt() {
    let store = Arc::new(with_messages(1));
    let threads = (0..8)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    assert!(store.increment_retry_count("m1").unwrap().is_some());
                }
            })
        })
        .collect::<Vec<_>>();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(store.message("m1").unwrap().unwrap().retry_count, 200);
    assert_eq!(store.increment_retry_count("nothing").unwrap(), None);
}

/// Each message write changes its fields and nothing else, and announces its message once.
/// Mutation: write `retry_count` from `set_order_key`, or announce a write that changed nothing.
#[test]
fn each_message_write_changes_only_its_fields() {
    let store = with_messages(1);
    let mut expected = store.message("m1").unwrap().unwrap();
    let seen = Arc::new(Changes::default());
    store.set_observer(Some(seen.clone()));

    // The count first: a later write that touched it would show.
    assert!(store.set_retry_count("m1", 2).unwrap());
    expected.retry_count = 2;
    assert!(store.set_order_key("m1", "server-7").unwrap());
    expected.order_key = "server-7".into();
    assert!(
        store
            .set_transcript("m1", Some("hello"), Some("en"), Some(9))
            .unwrap()
    );
    expected.transcript_text = Some("hello".into());
    expected.transcript_language = Some("en".into());
    expected.transcript_generated_at = Some(9);
    assert_eq!(store.message("m1").unwrap(), Some(expected.clone()));

    // The same values again: nothing changed, nothing announced.
    assert!(!store.set_order_key("m1", "server-7").unwrap());
    assert!(!store.set_retry_count("m1", 2).unwrap());
    assert!(
        !store
            .set_transcript("m1", Some("hello"), Some("en"), Some(9))
            .unwrap()
    );
    assert!(store.set_transcript("m1", None, None, None).unwrap());
    expected.transcript_text = None;
    expected.transcript_language = None;
    expected.transcript_generated_at = None;
    assert_eq!(store.message("m1").unwrap(), Some(expected));

    let changes = seen.changes.lock().unwrap();
    assert_eq!(changes.len(), 4);
    assert!(
        changes
            .iter()
            .all(|c| c.table == Table::Messages && c.ids == ["m1"])
    );
}

/// The window a transcript holds is read again forwards from its first row, that row included.
/// Mutation: `>` for `>=` in `messages_from` — the first row is lost.
#[test]
fn a_window_reads_forward_from_its_first_row() {
    let store = with_messages(5);
    let page = store.messages_from("c", ("k2", "m2"), 10).unwrap();
    assert_eq!(
        page.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        ["m2", "m3", "m4", "m5"]
    );
    let short = store.messages_from("c", ("k2", "m2"), 2).unwrap();
    assert_eq!(
        short.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        ["m2", "m3"]
    );
}

/// What waits to be sent: our queued messages, and failed ones with attempts left. Mutation:
/// drop `retry_count < ceiling` — a message out of attempts is sent forever.
#[test]
fn pending_sends_are_ours_queued_or_failed_with_attempts_left() {
    let store = with_messages(5);
    store.set_delivery_status("m1", QUEUED).unwrap();
    store.set_delivery_status("m2", FAILED).unwrap();
    store.set_delivery_status("m3", FAILED).unwrap();
    store.set_retry_count("m3", 3).unwrap();
    store.set_delivery_status("m4", SENT).unwrap();
    let mut theirs = message("t1", "c", "k0", b"x");
    theirs.delivery_status = QUEUED;
    store.insert_message(&theirs, None).unwrap();

    let ids = |v: Vec<Message>| v.into_iter().map(|m| m.id).collect::<Vec<_>>();
    assert_eq!(
        ids(store.pending_sends(Some("c"), 3, 50).unwrap()),
        ["m1", "m2"]
    );
    assert_eq!(ids(store.pending_sends(None, 3, 50).unwrap()), ["m1", "m2"]);
    assert!(
        store
            .pending_sends(Some("other"), 3, 50)
            .unwrap()
            .is_empty()
    );
}

/// A history snapshot reads every message of every chat a page at a time, and the count agrees.
/// Mutation: page with `>=` — every page after the first repeats a row.
#[test]
fn export_pages_run_through_every_chat_once() {
    let store = with_messages(3);
    store.upsert_contact(&contact("q", "q")).unwrap();
    store.upsert_chat(&chat("d", "q", None, false)).unwrap();
    store
        .insert_message(&message("n1", "d", "k2a", b"x"), None)
        .unwrap();

    let mut seen = Vec::new();
    let mut after: Option<(String, String)> = None;
    // Bounded: a page that repeats a row would otherwise loop forever instead of failing.
    for _ in 0..10 {
        let page = store
            .all_messages_after(after.as_ref().map(|(k, i)| (k.as_str(), i.as_str())), 2)
            .unwrap();
        let Some(last) = page.last() else { break };
        after = Some((last.order_key.clone(), last.id.clone()));
        seen.extend(page.into_iter().map(|m| m.id));
    }
    assert_eq!(seen, ["m1", "m2", "n1", "m3"]);
    assert_eq!(store.message_count().unwrap(), 4);
}

/// Only a reaction whose message never came is forgotten — and only once it has waited past the
/// cutoff; a reaction on a message the store holds is kept however old, as is one with no receipt
/// time. Mutation: drop the case-insensitive `NOT EXISTS` — the reaction on `M2-UPPER` expires; drop
/// both — every old reaction expires. (The exact one is for the index, not for the answer.)
#[test]
fn only_reactions_whose_message_never_came_expire() {
    let store = with_messages(1); // holds "m1"
    let mut upper = message("M2-UPPER", "c", "k2", b"x");
    upper.is_sent_by_me = true;
    store.insert_message(&upper, None).unwrap();
    let reaction = |target: &str, who: &str, received: Option<i64>| Reaction {
        target_message_id: target.into(),
        reactor_user_id: who.into(),
        emoji: "👍".into(),
        timestamp_ms: 1,
        received_at: received,
    };
    store
        .upsert_reaction(&reaction("m1", "old-on-held", Some(100)))
        .unwrap();
    store
        .upsert_reaction(&reaction("m2-upper", "old-on-held-other-case", Some(100)))
        .unwrap();
    store
        .upsert_reaction(&reaction("gone", "old-orphan", Some(100)))
        .unwrap();
    store
        .upsert_reaction(&reaction("gone", "new-orphan", Some(900)))
        .unwrap();
    store
        .upsert_reaction(&reaction("gone", "ours", None))
        .unwrap();

    assert_eq!(store.expire_reactions(500).unwrap(), 1);
    let mut who = store
        .all_reactions()
        .unwrap()
        .into_iter()
        .map(|r| r.reactor_user_id)
        .collect::<Vec<_>>();
    who.sort();
    assert_eq!(
        who,
        [
            "new-orphan",
            "old-on-held",
            "old-on-held-other-case",
            "ours"
        ]
    );
    assert_eq!(store.expire_reactions(500).unwrap(), 0);
}

/// A chat's reactions in one read, its messages only. Mutation: drop `m.chat_id = ?1` — another
/// chat's reaction comes along.
#[test]
fn a_chats_reactions_come_in_one_read() {
    let store = with_messages(2); // chat "c": m1, m2
    store.upsert_contact(&contact("q", "q")).unwrap();
    store.upsert_chat(&chat("d", "q", None, false)).unwrap();
    store
        .insert_message(&message("n1", "d", "k1", b"x"), None)
        .unwrap();
    let reaction = |target: &str, who: &str, at: i64| Reaction {
        target_message_id: target.into(),
        reactor_user_id: who.into(),
        emoji: "🔥".into(),
        timestamp_ms: at,
        received_at: None,
    };
    store.upsert_reaction(&reaction("m2", "b", 2)).unwrap();
    store.upsert_reaction(&reaction("m1", "a", 5)).unwrap();
    store.upsert_reaction(&reaction("m1", "z", 1)).unwrap();
    store
        .upsert_reaction(&reaction("n1", "other-chat", 1))
        .unwrap();

    let got = store
        .reactions_in_chat("c")
        .unwrap()
        .into_iter()
        .map(|r| (r.target_message_id, r.reactor_user_id))
        .collect::<Vec<_>>();
    let pairs = |v: &[(&str, &str)]| {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect::<Vec<_>>()
    };
    assert_eq!(got, pairs(&[("m1", "z"), ("m1", "a"), ("m2", "b")]));
}

/// Counted per chat. Mutation: count every message.
#[test]
fn messages_are_counted_per_chat() {
    let store = with_messages(3);
    store.upsert_contact(&contact("q", "q")).unwrap();
    store.upsert_chat(&chat("d", "q", None, false)).unwrap();
    store
        .insert_message(&message("n1", "d", "k1", b"x"), None)
        .unwrap();
    assert_eq!(store.chat_message_count("c").unwrap(), 3);
    assert_eq!(store.chat_message_count("d").unwrap(), 1);
    assert_eq!(store.chat_message_count("none").unwrap(), 0);
}

/// A body read late replaces what is stored and what is findable, and does not mark the message
/// edited — it says what it said all along. Mutation: route `set_message_body` through the edit
/// branch — the message reads as edited.
#[test]
fn a_body_read_late_is_not_an_edit() {
    let store = with_messages(1);
    store
        .insert_message(&message("u1", "c", "k9", b""), None)
        .unwrap();
    assert!(
        store
            .set_message_body("u1", b"recovered", Some("recovered words"))
            .unwrap()
    );
    let m = store.message("u1").unwrap().unwrap();
    assert_eq!(
        (m.body.as_slice(), m.is_edited, m.edited_at),
        (&b"recovered"[..], false, None)
    );
    assert_eq!(
        store.search("recovered", 10).unwrap().len(),
        1,
        "now findable"
    );
    assert!(!store.set_message_body("nothing", b"x", None).unwrap());

    // An edit still marks the message, through the same path.
    assert!(
        store
            .edit_message("u1", b"edited", Some("edited"), 7)
            .unwrap()
    );
    let m = store.message("u1").unwrap().unwrap();
    assert_eq!((m.is_edited, m.edited_at), (true, Some(7)));
    assert!(
        store.search("recovered", 10).unwrap().is_empty(),
        "the old text is no longer findable"
    );
}
