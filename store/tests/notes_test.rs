//! Notes: what a person keeps for themselves, on this device (construct-docs todo 279,
//! decisions/notes-stay-on-the-device.md).

use std::sync::{Arc, Mutex};

use construct_store::{Change, Insert, MediaEntry, MediaKind, Note, Store, StoreObserver, Table};

const KEY: [u8; 32] = [7; 32];

fn text_body(text: &str) -> Vec<u8> {
    let mut body = b"CTM1".to_vec();
    body.push(construct_store::payload::kind::TEXT);
    body.extend_from_slice(text.as_bytes());
    body
}

fn note(id: &str, text: &str, created_at: i64) -> Note {
    Note {
        id: id.into(),
        body: text_body(text),
        created_at,
        ..Default::default()
    }
}

fn entry(item: u32, media_id: &str, kind: MediaKind) -> MediaEntry {
    MediaEntry {
        item,
        media_id: media_id.into(),
        kind,
        byte_size: 10,
    }
}

fn add(store: &Store, id: &str, text: &str, at: i64, media: &[MediaEntry]) {
    let outcome = store.insert_note(&note(id, text, at), Some(text), media);
    assert_eq!(outcome.unwrap(), Insert::Inserted);
}

fn ids(notes: &[Note]) -> Vec<&str> {
    notes.iter().map(|n| n.id.as_str()).collect()
}

/// Every field comes back, and survives a reopen. Mutation: drop a column from the insert.
#[test]
fn a_note_is_kept_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("construct.db");
    let kept = Note {
        id: "n1".into(),
        body: text_body("milk"),
        created_at: 100,
        edited_at: Some(150),
        is_pinned: true,
        source_name: Some("Bob".into()),
        source_at: Some(90),
    };
    {
        let store = Store::open(&path, &KEY).unwrap();
        store.insert_note(&kept, Some("milk"), &[]).unwrap();
    }
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.note("n1").unwrap(), Some(kept));
    assert_eq!(store.note("n2").unwrap(), None);
}

/// A note already here is left as it is, its files too: a move that runs again changes nothing.
/// Mutation: replace on conflict, or write the parts anyway.
#[test]
fn a_note_already_here_is_not_written_over() {
    let store = Store::open_in_memory(&KEY).unwrap();
    add(&store, "n1", "milk", 1, &[entry(0, "m1", MediaKind::Photo)]);
    let again = store.insert_note(&note("n1", "other", 2), Some("other"), &[]);
    assert_eq!(again.unwrap(), Insert::AlreadyPresent);
    assert_eq!(store.note("n1").unwrap().unwrap().body, text_body("milk"));
    assert_eq!(store.notes_media().unwrap().len(), 1);
    assert_eq!(ids(&store.search_notes("milk", 10).unwrap()), ["n1"]);
    assert!(store.search_notes("other", 10).unwrap().is_empty());
}

/// Pinned first, each part newest first, in pages that neither repeat nor skip — also between two
/// notes of one moment. Mutations: drop the pin, the time or the id from the order or the cursor.
#[test]
fn notes_come_pinned_first_then_newest_in_pages() {
    let store = Store::open_in_memory(&KEY).unwrap();
    add(&store, "old-pinned", "a", 1, &[]);
    add(&store, "new", "b", 9, &[]);
    add(&store, "tie-a", "c", 5, &[]);
    add(&store, "tie-b", "d", 5, &[]);
    add(&store, "new-pinned", "e", 3, &[]);
    assert!(store.set_note_pinned("old-pinned", true).unwrap());
    assert!(store.set_note_pinned("new-pinned", true).unwrap());
    assert!(!store.set_note_pinned("gone", true).unwrap());

    let all = ["new-pinned", "old-pinned", "new", "tie-b", "tie-a"];
    assert_eq!(ids(&store.notes(None, 10).unwrap()), all);
    let mut seen: Vec<Note> = Vec::new();
    loop {
        let before = seen
            .last()
            .map(|n| (n.is_pinned, n.created_at, n.id.as_str()));
        let page = store.notes(before, 1).unwrap();
        let Some(next) = page.into_iter().next() else {
            break;
        };
        seen.push(next);
    }
    assert_eq!(ids(&seen), all);

    assert!(store.set_note_pinned("old-pinned", false).unwrap());
    assert_eq!(
        ids(&store.notes(None, 10).unwrap()),
        ["new-pinned", "new", "tie-b", "tie-a", "old-pinned"]
    );
}

/// An edit changes what a note says, holds and finds, and nothing else; the files it let go are
/// named. Mutations: keep the old text in the search, keep the old files, touch the pin.
#[test]
fn an_edit_changes_what_it_says_and_names_the_files_it_lets_go() {
    let store = Store::open_in_memory(&KEY).unwrap();
    let mut first = note("n1", "buy milk", 1);
    first.is_pinned = true;
    first.source_name = Some("Bob".into());
    store
        .insert_note(
            &first,
            Some("buy milk"),
            &[
                entry(0, "m1", MediaKind::Photo),
                entry(1, "m2", MediaKind::File),
            ],
        )
        .unwrap();

    let released = store
        .edit_note(
            "n1",
            &text_body("buy bread"),
            Some("buy bread"),
            &[entry(0, "m2", MediaKind::File)],
            7,
        )
        .unwrap();
    assert_eq!(released, Some(vec!["m1".to_string()]));
    let edited = store.note("n1").unwrap().unwrap();
    assert_eq!(
        edited,
        Note {
            body: text_body("buy bread"),
            edited_at: Some(7),
            ..first
        }
    );
    assert!(store.search_notes("milk", 10).unwrap().is_empty());
    assert_eq!(ids(&store.search_notes("bread", 10).unwrap()), ["n1"]);
    let held = store.notes_media().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!((held[0].media_id.as_str(), held[0].item), ("m2", 0));

    let gone = store.edit_note("n2", &text_body("x"), Some("x"), &[], 8);
    assert_eq!(gone.unwrap(), None);
    assert!(store.note("n2").unwrap().is_none());
}

/// A deleted note leaves the list and the search, and a file another note holds is not let go.
/// Mutations: leave the search row; release a file still held; release it twice.
#[test]
fn a_deleted_note_lets_go_only_of_files_no_note_holds() {
    let store = Store::open_in_memory(&KEY).unwrap();
    add(
        &store,
        "n1",
        "first note",
        1,
        &[
            entry(0, "shared", MediaKind::Photo),
            entry(1, "own", MediaKind::Voice),
        ],
    );
    add(
        &store,
        "n2",
        "second note",
        2,
        &[entry(0, "shared", MediaKind::Photo)],
    );
    add(&store, "n3", "third note", 3, &[]);

    let released = store.delete_notes(&["n1".into(), "gone".into()]).unwrap();
    assert_eq!(released, ["own"]);
    assert_eq!(ids(&store.notes(None, 10).unwrap()), ["n3", "n2"]);
    assert_eq!(ids(&store.search_notes("note", 10).unwrap()), ["n3", "n2"]);

    add(
        &store,
        "n4",
        "fourth",
        4,
        &[entry(0, "shared", MediaKind::Photo)],
    );
    let released = store.delete_notes(&["n2".into(), "n4".into()]).unwrap();
    assert_eq!(released, ["shared"]);
    assert!(store.notes_media().unwrap().is_empty());
}

/// Search is a phrase, not FTS syntax, and finds what a message search would not: the two indexes
/// are apart. Mutation: search `message_search`.
#[test]
fn notes_are_searched_as_phrases_apart_from_messages() {
    let store = Store::open_in_memory(&KEY).unwrap();
    add(&store, "n1", "купить \"молоко\" OR хлеб", 1, &[]);
    add(&store, "n2", "другое", 2, &[]);
    assert_eq!(ids(&store.search_notes("\"молоко\"", 10).unwrap()), ["n1"]);
    assert_eq!(ids(&store.search_notes("OR хлеб", 10).unwrap()), ["n1"]);
    assert!(store.search_notes("ОЛ", 10).unwrap().is_empty());
    assert!(store.search("молоко", 10).unwrap().is_empty());
    // A note with nothing to find is found by nothing, and still listed.
    store.insert_note(&note("n3", "", 3), None, &[]).unwrap();
    assert_eq!(store.notes(None, 10).unwrap().len(), 3);
}

/// Each change is told once, by id, and one that changed nothing is not. Mutation: notify anyway.
#[test]
fn a_change_to_notes_is_told_once() {
    #[derive(Default)]
    struct Heard(Mutex<Vec<Change>>);
    impl StoreObserver for Heard {
        fn on_change(&self, change: Change) {
            self.0.lock().unwrap().push(change);
        }
    }
    let store = Store::open_in_memory(&KEY).unwrap();
    let heard = Arc::new(Heard::default());
    store.set_observer(Some(heard.clone()));
    add(&store, "n1", "milk", 1, &[]);
    store
        .insert_note(&note("n1", "again", 1), None, &[])
        .unwrap();
    store.set_note_pinned("n1", true).unwrap();
    store.set_note_pinned("gone", true).unwrap();
    store
        .edit_note("n1", &text_body("x"), None, &[], 2)
        .unwrap();
    store
        .edit_note("gone", &text_body("x"), None, &[], 2)
        .unwrap();
    store.delete_notes(&["n1".into(), "gone".into()]).unwrap();
    store.delete_notes(&["n1".into()]).unwrap();
    let heard = heard.0.lock().unwrap();
    assert_eq!(heard.len(), 4);
    for change in heard.iter() {
        assert_eq!(
            (change.table, change.ids.clone()),
            (Table::Notes, vec!["n1".to_string()])
        );
    }
}
