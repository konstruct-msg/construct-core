//! The schema, as numbered steps. `PRAGMA user_version` is the step a store has reached; a store
//! ahead of this build is refused rather than opened, since an older schema would lose what the
//! newer one wrote.
//!
//! Version 1 carries what the iOS Core Data model 12 holds, minus what whole-database encryption
//! makes pointless: a message body is one blob, not ciphertext plus a key kept elsewhere plus a
//! clear fallback column (`encryptedContent` / `contentKeyRef` / `decryptedContent`).

use rusqlite::Connection;

use crate::error::{Result, StoreError};

const STEPS: &[&str] = &[
    // 1 — the model of iOS Core Data model 12.
    r#"
    CREATE TABLE contacts (
        id                 TEXT PRIMARY KEY NOT NULL,   -- account UUID
        username           TEXT NOT NULL DEFAULT '',
        display_name       TEXT NOT NULL DEFAULT '',
        local_alias        TEXT,
        avatar             BLOB,
        public_key         TEXT,
        known_identity_key BLOB,
        account_address    BLOB,
        is_contact         INTEGER NOT NULL DEFAULT 0,
        is_blocked         INTEGER NOT NULL DEFAULT 0,
        is_sharing_with_me INTEGER NOT NULL DEFAULT 0,
        am_i_sharing_with  INTEGER NOT NULL DEFAULT 0,
        shared_with_me_at  INTEGER,
        added_at           INTEGER,
        kt_status          INTEGER NOT NULL DEFAULT 0,
        hybrid_capable     INTEGER NOT NULL DEFAULT 0,
        security_notice    INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE chats (
        id                TEXT PRIMARY KEY NOT NULL,
        peer_id           TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
        last_message_text TEXT,
        last_message_time INTEGER,
        session_id        TEXT,
        is_pinned         INTEGER NOT NULL DEFAULT 0,
        is_muted          INTEGER NOT NULL DEFAULT 0,
        unread_count      INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX chats_by_peer ON chats(peer_id);

    CREATE TABLE messages (
        id                    TEXT PRIMARY KEY NOT NULL,
        chat_id               TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
        from_user_id          TEXT NOT NULL,
        to_user_id            TEXT NOT NULL,
        is_sent_by_me         INTEGER NOT NULL,
        timestamp             INTEGER NOT NULL,
        -- The transcript order: server-assigned where the server placed the message, local
        -- otherwise (`ServerMessageOrder` on iOS). Total — ties broken by id in queries.
        order_key             TEXT NOT NULL,
        body                  BLOB NOT NULL,           -- the local payload (CTM1 on iOS)
        content_type          INTEGER NOT NULL DEFAULT 0,
        delivery_status       INTEGER NOT NULL DEFAULT 0,
        retry_count           INTEGER NOT NULL DEFAULT 0,
        suite_id              INTEGER NOT NULL DEFAULT 0,
        is_edited             INTEGER NOT NULL DEFAULT 0,
        edited_at             INTEGER,
        reply_to_message_id   TEXT,
        reply_to_content      TEXT,
        transcript_text       TEXT,
        transcript_language   TEXT,
        transcript_generated_at INTEGER
    );
    CREATE INDEX messages_in_order ON messages(chat_id, order_key, id);

    -- Search over what a message says, fed by the client (it knows which part of a body is
    -- text). Contentless: the text lives only in the index. Trigram, because a word tokenizer
    -- does not segment Japanese; the cost is that a query needs three characters.
    CREATE VIRTUAL TABLE message_search USING fts5(
        text, content = '', contentless_delete = 1, tokenize = 'trigram'
    );
    -- Every way a message goes — itself, its chat, its contact (cascades fire triggers) — takes
    -- its search entry with it. Nothing a person deleted stays findable.
    CREATE TRIGGER messages_leave_search AFTER DELETE ON messages BEGIN
        DELETE FROM message_search WHERE rowid = old.rowid;
    END;

    CREATE TABLE reactions (
        target_message_id TEXT NOT NULL,
        reactor_user_id   TEXT NOT NULL,
        emoji             TEXT NOT NULL,
        timestamp_ms      INTEGER NOT NULL DEFAULT 0,
        received_at       INTEGER,
        PRIMARY KEY (target_message_id, reactor_user_id)
    );

    CREATE TABLE calls (
        id               TEXT PRIMARY KEY NOT NULL,
        peer_user_id     TEXT NOT NULL,
        peer_name        TEXT NOT NULL DEFAULT '',
        direction        INTEGER NOT NULL DEFAULT 0,
        status           INTEGER NOT NULL DEFAULT 0,
        started_at       INTEGER,
        ended_at         INTEGER,
        duration_seconds INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE processed_messages (
        message_id   TEXT PRIMARY KEY NOT NULL,
        sender_id    TEXT NOT NULL,
        processed_at INTEGER NOT NULL
    );

    CREATE TABLE healing_messages (
        message_id      TEXT PRIMARY KEY NOT NULL,
        sender_id       TEXT NOT NULL,
        received_at     INTEGER NOT NULL,
        message_data    BLOB NOT NULL,
        heal_attempts   INTEGER NOT NULL DEFAULT 0,
        last_attempt_at INTEGER
    );

    CREATE TABLE peer_devices (
        device_id     TEXT PRIMARY KEY NOT NULL,   -- 32 hex, hash of the identity key
        account_id    TEXT NOT NULL,
        identity_key  BLOB NOT NULL,
        first_seen_at INTEGER NOT NULL
    );
    CREATE INDEX peer_devices_by_account ON peer_devices(account_id);

    -- The server's id of each sealed copy we sent, and the message it carries. On the sealed path
    -- the server assigns the id the recipient sees, so a receipt or a decryption error names that
    -- one; kept as long as the server keeps a queue (30 days), since nothing older can be named.
    CREATE TABLE server_message_ids (
        server_id   TEXT PRIMARY KEY NOT NULL,   -- lowercase
        local_id    TEXT NOT NULL,               -- lowercase
        recorded_at INTEGER NOT NULL             -- ms since the epoch
    );
    CREATE INDEX server_message_ids_by_age ON server_message_ids(recorded_at);

    -- Small state that is not a row of anything: stream cursors, owner, flags.
    CREATE TABLE kv (
        key   TEXT PRIMARY KEY NOT NULL,
        value BLOB NOT NULL
    );
    "#,
    // 2 — iOS Core Data model 15, and our own profile out of the contacts table.
    //
    // A contact gains what model 15 added for profiles: when the peer last edited theirs (a newer
    // edit wins), and an avatar announced but not yet downloaded. `public_key` and
    // `hybrid_capable` go: nothing on any client writes them (the core pins the hybrid key per
    // device since PQXDH v2).
    //
    // Our own profile was a row of `contacts` on iOS, told apart by `id != me` in two places. It
    // is not a contact — no chat, no pin, no block — so it is a table of one row.
    r#"
    ALTER TABLE contacts ADD COLUMN profile_edited_at_ms INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE contacts ADD COLUMN pending_avatar_ref   BLOB;
    ALTER TABLE contacts ADD COLUMN pending_avatar_since INTEGER;
    ALTER TABLE contacts DROP COLUMN public_key;
    ALTER TABLE contacts DROP COLUMN hybrid_capable;

    CREATE TABLE own_profile (
        one                  INTEGER PRIMARY KEY NOT NULL CHECK (one = 1),
        account_id           TEXT NOT NULL,
        username             TEXT NOT NULL DEFAULT '',
        display_name         TEXT NOT NULL DEFAULT '',
        avatar               BLOB,
        profile_edited_at_ms INTEGER NOT NULL DEFAULT 0
    );
    "#,
    // 3 — one chat per peer, and the chat columns no client reads or writes.
    //
    // iOS keeps one chat per person by convention only: `Chat.findOrCreate` looks up by peer and
    // merges duplicates when it meets them. Here the index says it. No store with rows exists
    // outside tests yet, so nothing is merged; the iOS import merges duplicates before writing.
    //
    // `session_id` was never written by any client; `is_muted` had a setter nobody called and no
    // reader. A mute comes back with the feature that reads it.
    r#"
    DROP INDEX chats_by_peer;
    CREATE UNIQUE INDEX chats_by_peer ON chats(peer_id);
    ALTER TABLE chats DROP COLUMN session_id;
    ALTER TABLE chats DROP COLUMN is_muted;
    "#,
];

pub(crate) const VERSION: i64 = STEPS.len() as i64;

pub(crate) fn run(conn: &mut Connection) -> Result<()> {
    let found: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found > VERSION {
        return Err(StoreError::SchemaTooNew {
            found,
            supported: VERSION,
        });
    }
    for (index, step) in STEPS.iter().enumerate().skip(found as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(step)?;
        tx.pragma_update(None, "user_version", index as i64 + 1)?;
        tx.commit()?;
    }
    Ok(())
}
