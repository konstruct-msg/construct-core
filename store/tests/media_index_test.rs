//! The media index: which media each message holds, for the chat gallery and the storage screen
//! (construct-docs todo 327, decisions/chat-media-gallery-storage-backup.md).

use construct_store::{Chat, Contact, MediaEntry, MediaKind, Message, Store};

const KEY: [u8; 32] = [7; 32];

fn album_body() -> Vec<u8> {
    let mut body = b"CTM1".to_vec();
    body.push(construct_store::payload::kind::MEDIA_ALBUM);
    body.extend_from_slice(&[0x0a, 0x01, 0x00]);
    body
}

fn text_body(text: &str) -> Vec<u8> {
    let mut body = b"CTM1".to_vec();
    body.push(construct_store::payload::kind::TEXT);
    body.extend_from_slice(text.as_bytes());
    body
}

fn message(id: &str, chat: &str, order_key: &str, timestamp: i64, body: Vec<u8>) -> Message {
    Message {
        id: id.into(),
        chat_id: chat.into(),
        from_user_id: "a".into(),
        to_user_id: "b".into(),
        timestamp,
        order_key: order_key.into(),
        body,
        ..Default::default()
    }
}

fn entry(item: u32, media_id: &str, kind: MediaKind, byte_size: i64) -> MediaEntry {
    MediaEntry {
        item,
        media_id: media_id.into(),
        kind,
        byte_size,
    }
}

/// Two people, a chat each.
fn store() -> Store {
    let store = Store::open_in_memory(&KEY).unwrap();
    for (peer, chat) in [("bob", "c1"), ("carol", "c2")] {
        store
            .upsert_contact(&Contact {
                id: peer.into(),
                display_name: peer.into(),
                is_contact: true,
                ..Default::default()
            })
            .unwrap();
        store
            .upsert_chat(&Chat {
                id: chat.into(),
                peer_id: peer.into(),
                ..Default::default()
            })
            .unwrap();
    }
    store
}

/// c1: an album of three (k1), a text (k2), a voice note (k3); c2: one photo.
fn with_media(store: &Store) {
    store
        .insert_message(&message("album", "c1", "k1", 100, album_body()), None)
        .unwrap();
    store
        .insert_message(
            &message("text", "c1", "k2", 200, text_body("hi")),
            Some("hi"),
        )
        .unwrap();
    store
        .insert_message(&message("voice", "c1", "k3", 300, vec![1, 2, 3]), None)
        .unwrap();
    store
        .insert_message(&message("other", "c2", "k1", 100, album_body()), None)
        .unwrap();
    let album = [
        entry(0, "p0", MediaKind::Photo, 10),
        entry(1, "v1", MediaKind::Video, 20),
        entry(2, "p2", MediaKind::Photo, 30),
    ];
    assert!(store.set_message_media("album", &album).unwrap());
    assert!(
        store
            .set_message_media("voice", &[entry(0, "a0", MediaKind::Voice, 5)])
            .unwrap()
    );
    assert!(
        store
            .set_message_media("other", &[entry(0, "o0", MediaKind::Photo, 7)])
            .unwrap()
    );
}

fn ids(page: &[construct_store::ChatMedia]) -> Vec<&str> {
    page.iter().map(|m| m.media_id.as_str()).collect()
}

/// A chat's media, newest first, only its own; a kind filter keeps that kind.
/// Mutations: drop the chat filter, the kind filter, or the DESC order — each reddens.
#[test]
fn a_chats_media_comes_newest_first_and_only_its_own() {
    let store = store();
    with_media(&store);

    let all = store.chat_media("c1", &[], None, 50).unwrap();
    assert_eq!(ids(&all), ["a0", "p2", "v1", "p0"]);
    assert_eq!(all[0].kind, MediaKind::Voice);
    assert_eq!(all[0].timestamp, 300);
    assert_eq!(all[1].byte_size, 30);

    let photos = store
        .chat_media("c1", &[MediaKind::Photo], None, 50)
        .unwrap();
    assert_eq!(ids(&photos), ["p2", "p0"]);
    let visual = store
        .chat_media("c1", &[MediaKind::Photo, MediaKind::Video], None, 50)
        .unwrap();
    assert_eq!(ids(&visual), ["p2", "v1", "p0"]);

    assert_eq!(ids(&store.chat_media("c2", &[], None, 50).unwrap()), ["o0"]);
}

/// A page that stops inside an album continues with the rest of it, nothing skipped or repeated.
/// Mutation: page by `(order_key, id)` without the item — the album's last items are lost.
#[test]
fn a_page_cut_inside_an_album_continues_where_it_stopped() {
    let store = store();
    with_media(&store);

    let mut seen = Vec::new();
    let mut before: Option<(String, String, u32)> = None;
    loop {
        let cursor = before
            .as_ref()
            .map(|(k, id, item)| (k.as_str(), id.as_str(), *item));
        let page = store.chat_media("c1", &[], cursor, 2).unwrap();
        if page.is_empty() {
            break;
        }
        seen.extend(page.iter().map(|m| m.media_id.clone()));
        let last = page.last().unwrap();
        before = Some((last.order_key.clone(), last.message_id.clone(), last.item));
    }
    assert_eq!(seen, ["a0", "p2", "v1", "p0"]);
}

/// Re-indexing a message replaces its entries; a message that is not there is refused.
/// Mutation: drop the DELETE before the inserts — the dropped item stays.
#[test]
fn indexing_again_replaces_and_a_missing_message_is_refused() {
    let store = store();
    with_media(&store);

    assert!(
        store
            .set_message_media("album", &[entry(0, "p0", MediaKind::Photo, 10)])
            .unwrap()
    );
    assert_eq!(
        ids(&store
            .chat_media("c1", &[MediaKind::Photo, MediaKind::Video], None, 50)
            .unwrap()),
        ["p0"]
    );

    assert!(
        !store
            .set_message_media("nobody", &[entry(0, "x", MediaKind::File, 1)])
            .unwrap()
    );
    assert!(store.media_owners(&["x".to_string()]).unwrap().is_empty());
}

fn content_body() -> Vec<u8> {
    let mut body = b"CTM1".to_vec();
    body.push(construct_store::payload::kind::MESSAGE_CONTENT);
    body.extend_from_slice(&[0x52, 0x00]);
    body
}

/// What a build before the index wrote — or a crash caught between insert and index — is listed
/// until indexed, with no entries too. Both kinds media is stored under are listed: an album iOS
/// sends, and a message content (everything received, everything Android writes); a plain text
/// and a profile never are.
/// Mutations: drop the `media_indexed` check, the album prefix, or the message-content prefix —
/// each reddens.
#[test]
fn a_message_that_may_hold_media_is_listed_until_it_is_indexed() {
    let store = store();
    store
        .insert_message(&message("a1", "c1", "k1", 1, album_body()), None)
        .unwrap();
    store
        .insert_message(&message("mc", "c1", "k2", 2, content_body()), None)
        .unwrap();
    store
        .insert_message(
            &message("t", "c1", "k3", 3, text_body("hello")),
            Some("hello"),
        )
        .unwrap();
    let mut profile = b"CTM1".to_vec();
    profile.push(construct_store::payload::kind::PROFILE);
    store
        .insert_message(&message("p", "c1", "k4", 4, profile), None)
        .unwrap();
    store
        .insert_message(&message("a2", "c1", "k5", 5, album_body()), None)
        .unwrap();

    assert_eq!(
        store.unindexed_media_messages(10).unwrap(),
        ["a1", "mc", "a2"]
    );
    assert_eq!(store.unindexed_media_messages(1).unwrap(), ["a1"]);

    store.set_message_media("a1", &[]).unwrap();
    assert_eq!(store.unindexed_media_messages(10).unwrap(), ["mc", "a2"]);
    store
        .set_message_media("mc", &[entry(0, "v", MediaKind::Voice, 1)])
        .unwrap();
    store
        .set_message_media("a2", &[entry(0, "m", MediaKind::Photo, 1)])
        .unwrap();
    assert!(store.unindexed_media_messages(10).unwrap().is_empty());
}

/// A media id maps to the chat and message holding it; one two messages share is listed twice;
/// an unknown id is left out.
#[test]
fn a_media_id_maps_to_its_chat() {
    let store = store();
    with_media(&store);
    store
        .insert_message(&message("fwd", "c2", "k2", 400, album_body()), None)
        .unwrap();
    store
        .set_message_media("fwd", &[entry(0, "p0", MediaKind::Photo, 10)])
        .unwrap();

    let owners = store
        .media_owners(&["p0".into(), "a0".into(), "unknown".into()])
        .unwrap();
    let pairs: Vec<(&str, &str, &str)> = owners
        .iter()
        .map(|o| {
            (
                o.media_id.as_str(),
                o.chat_id.as_str(),
                o.message_id.as_str(),
            )
        })
        .collect();
    assert_eq!(
        pairs,
        [
            ("a0", "c1", "voice"),
            ("p0", "c1", "album"),
            ("p0", "c2", "fwd")
        ]
    );
}

/// A deleted message, chat or contact takes its index with it.
/// Mutation: drop `ON DELETE CASCADE` on `media` — the owners outlive the message.
#[test]
fn what_is_deleted_leaves_no_index_behind() {
    let store = store();
    with_media(&store);

    store.delete_message("voice").unwrap();
    assert!(store.media_owners(&["a0".into()]).unwrap().is_empty());
    store.delete_chat("c1").unwrap();
    assert!(
        store
            .media_owners(&["p0".into(), "v1".into()])
            .unwrap()
            .is_empty()
    );
    store.delete_contact("carol").unwrap();
    assert!(store.media_owners(&["o0".into()]).unwrap().is_empty());
}

/// Only messages before the time: what "remove media older than…" removes.
/// Mutation: `<=` for `<`, or drop the chat filter — each reddens.
#[test]
fn media_older_than_a_time_is_only_that_chats_and_strictly_older() {
    let store = store();
    with_media(&store);

    let old = store.chat_media_older_than("c1", 300).unwrap();
    assert_eq!(ids(&old), ["p0", "v1", "p2"]);
    assert!(store.chat_media_older_than("c1", 100).unwrap().is_empty());
    assert_eq!(
        ids(&store.chat_media_older_than("c2", 1_000).unwrap()),
        ["o0"]
    );
}

/// Off unless the chat turned it on; a chat that is not there reads off and cannot be set.
/// Mutation: `DEFAULT 1` on the column — this reddens.
#[test]
fn saving_media_to_photos_is_off_until_a_chat_turns_it_on() {
    let store = store();
    assert!(!store.chat_auto_save_media("c1").unwrap());
    assert!(store.set_chat_auto_save_media("c1", true).unwrap());
    assert!(store.chat_auto_save_media("c1").unwrap());
    assert!(!store.chat_auto_save_media("c2").unwrap());
    assert!(!store.set_chat_auto_save_media("nobody", true).unwrap());
    assert!(!store.chat_auto_save_media("nobody").unwrap());
    assert!(store.set_chat_auto_save_media("c1", false).unwrap());
    assert!(!store.chat_auto_save_media("c1").unwrap());
}
