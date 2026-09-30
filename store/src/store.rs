use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use rusqlite::{Connection, ErrorCode, OptionalExtension, Row, params};
use zeroize::Zeroizing;

use crate::KEY_LEN;
use crate::error::{Result, StoreError};
use crate::migrations;
use crate::model::{
    CallRecord, Chat, Contact, DeliveryStatus, Message, PeerDevice, Reaction, SearchHit,
};
use crate::observer::{Change, StoreObserver, Table};

/// Whether a write added a row or found it there already. Deliveries repeat — a stream replay, a
/// history import over live mail — and the caller decides what a repeat means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    Inserted,
    AlreadyPresent,
}

/// One open store. `Sync`: the connection sits behind a mutex, so a client may share one `Store`
/// across threads (UniFFI hands it out as an `Arc`).
pub struct Store {
    conn: Mutex<Connection>,
    path: Option<PathBuf>,
    observer: RwLock<Option<Arc<dyn StoreObserver>>>,
}

impl Store {
    /// Open — creating if absent — the store at `path` under `key`. A store the key does not open
    /// is [`StoreError::WrongKey`], never a fresh empty store: minting one over it would orphan
    /// the account's history.
    pub fn open(path: impl AsRef<Path>, key: &[u8]) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        Self::prepare(conn, key, Some(path))
    }

    /// A store that lives only in memory, under the same encryption code path. Tests, previews.
    pub fn open_in_memory(key: &[u8]) -> Result<Self> {
        Self::prepare(Connection::open_in_memory()?, key, None)
    }

    fn prepare(mut conn: Connection, key: &[u8], path: Option<PathBuf>) -> Result<Self> {
        if key.len() != KEY_LEN {
            return Err(StoreError::KeyLength {
                expected: KEY_LEN,
                got: key.len(),
            });
        }
        // Raw key: `x'…'` skips SQLCipher's PBKDF2 — the key is already 256 random bits.
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex(key).as_str()));
        conn.execute_batch(&pragma)?;
        // The first read is where a wrong key shows: SQLCipher decrypts page 1 there.
        match conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        }) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::NotADatabase => {
                return Err(StoreError::WrongKey);
            }
            Err(e) => return Err(e.into()),
        }
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        migrations::run(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path,
            observer: RwLock::new(None),
        })
    }

    /// The schema version this build writes.
    pub fn schema_version() -> i64 {
        migrations::VERSION
    }

    pub fn set_observer(&self, observer: Option<Arc<dyn StoreObserver>>) {
        *self.observer.write().unwrap_or_else(|e| e.into_inner()) = observer;
    }

    /// Close the store and delete its files. The platform deletes the key; without it anything
    /// this misses is ciphertext nobody can open.
    pub fn wipe(self) -> Result<()> {
        let Self { conn, path, .. } = self;
        let conn = conn.into_inner().unwrap_or_else(|e| e.into_inner());
        conn.close().map_err(|(_, e)| e)?;
        if let Some(path) = path {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let file = PathBuf::from(format!("{}{suffix}", path.display()));
                match std::fs::remove_file(&file) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// After the write committed and the lock is released, so an observer may read the store.
    fn notify(&self, table: Table, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        let observer = self
            .observer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(observer) = observer {
            observer.on_change(Change { table, ids });
        }
    }

    // MARK: - Contacts

    pub fn upsert_contact(&self, c: &Contact) -> Result<()> {
        self.lock().execute(
            "INSERT INTO contacts (id, username, display_name, local_alias, avatar, public_key,
                 known_identity_key, account_address, is_contact, is_blocked, is_sharing_with_me,
                 am_i_sharing_with, shared_with_me_at, added_at, kt_status, hybrid_capable,
                 security_notice)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(id) DO UPDATE SET
                 username = excluded.username, display_name = excluded.display_name,
                 local_alias = excluded.local_alias, avatar = excluded.avatar,
                 public_key = excluded.public_key, known_identity_key = excluded.known_identity_key,
                 account_address = excluded.account_address, is_contact = excluded.is_contact,
                 is_blocked = excluded.is_blocked, is_sharing_with_me = excluded.is_sharing_with_me,
                 am_i_sharing_with = excluded.am_i_sharing_with,
                 shared_with_me_at = excluded.shared_with_me_at, added_at = excluded.added_at,
                 kt_status = excluded.kt_status, hybrid_capable = excluded.hybrid_capable,
                 security_notice = excluded.security_notice",
            params![
                c.id,
                c.username,
                c.display_name,
                c.local_alias,
                c.avatar,
                c.public_key,
                c.known_identity_key,
                c.account_address,
                c.is_contact,
                c.is_blocked,
                c.is_sharing_with_me,
                c.am_i_sharing_with,
                c.shared_with_me_at,
                c.added_at,
                c.kt_status,
                c.hybrid_capable,
                c.security_notice
            ],
        )?;
        self.notify(Table::Contacts, vec![c.id.clone()]);
        Ok(())
    }

    pub fn contact(&self, id: &str) -> Result<Option<Contact>> {
        Ok(self
            .lock()
            .query_row(
                &format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE id = ?1"),
                [id],
                contact_row,
            )
            .optional()?)
    }

    /// People marked as contacts, by the name shown for them.
    pub fn contacts(&self) -> Result<Vec<Contact>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts WHERE is_contact = 1
             ORDER BY COALESCE(local_alias, display_name) COLLATE NOCASE, id"
        ))?;
        let rows = stmt
            .query_map([], contact_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Removes the contact with its chats and their messages.
    pub fn delete_contact(&self, id: &str) -> Result<()> {
        let removed = self
            .lock()
            .execute("DELETE FROM contacts WHERE id = ?1", [id])?;
        if removed > 0 {
            self.notify(Table::Contacts, vec![id.to_string()]);
        }
        Ok(())
    }

    // MARK: - Chats

    pub fn upsert_chat(&self, c: &Chat) -> Result<()> {
        self.lock().execute(
            "INSERT INTO chats (id, peer_id, last_message_text, last_message_time, session_id,
                 is_pinned, is_muted, unread_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                 peer_id = excluded.peer_id, last_message_text = excluded.last_message_text,
                 last_message_time = excluded.last_message_time, session_id = excluded.session_id,
                 is_pinned = excluded.is_pinned, is_muted = excluded.is_muted,
                 unread_count = excluded.unread_count",
            params![
                c.id,
                c.peer_id,
                c.last_message_text,
                c.last_message_time,
                c.session_id,
                c.is_pinned,
                c.is_muted,
                c.unread_count
            ],
        )?;
        self.notify(Table::Chats, vec![c.id.clone()]);
        Ok(())
    }

    pub fn chat(&self, id: &str) -> Result<Option<Chat>> {
        Ok(self
            .lock()
            .query_row(
                &format!("SELECT {CHAT_COLUMNS} FROM chats WHERE id = ?1"),
                [id],
                chat_row,
            )
            .optional()?)
    }

    /// The chat list: pinned first, then the most recent; a chat with no message last.
    pub fn chats(&self) -> Result<Vec<Chat>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHAT_COLUMNS} FROM chats
             ORDER BY is_pinned DESC, last_message_time IS NULL, last_message_time DESC, id"
        ))?;
        let rows = stmt
            .query_map([], chat_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Removes the chat and its messages; their search entries go with them (trigger).
    pub fn delete_chat(&self, id: &str) -> Result<()> {
        let removed = self
            .lock()
            .execute("DELETE FROM chats WHERE id = ?1", [id])?;
        if removed > 0 {
            self.notify(Table::Chats, vec![id.to_string()]);
        }
        Ok(())
    }

    // MARK: - Messages

    /// Add a message unless one with its id is there. `search_text` — what the message says, as
    /// the client extracted it from the body — goes into the full-text index; `None` for bodies
    /// with nothing to find (media, control).
    pub fn insert_message(&self, m: &Message, search_text: Option<&str>) -> Result<Insert> {
        let inserted = {
            let mut conn = self.lock();
            let tx = conn.transaction()?;
            let added = tx.execute(
                &format!(
                    "INSERT OR IGNORE INTO messages ({MESSAGE_COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)"
                ),
                params![
                    m.id, m.chat_id, m.from_user_id, m.to_user_id, m.is_sent_by_me, m.timestamp,
                    m.order_key, m.body, m.content_type, m.delivery_status, m.retry_count,
                    m.suite_id, m.is_edited, m.edited_at, m.reply_to_message_id,
                    m.reply_to_content, m.transcript_text, m.transcript_language,
                    m.transcript_generated_at
                ],
            )?;
            if added > 0
                && let Some(text) = search_text.filter(|t| !t.is_empty())
            {
                tx.execute(
                    "INSERT INTO message_search (rowid, text)
                     SELECT rowid, ?2 FROM messages WHERE id = ?1",
                    params![m.id, text],
                )?;
            }
            tx.commit()?;
            added > 0
        };
        if inserted {
            self.notify(Table::Messages, vec![m.id.clone()]);
            Ok(Insert::Inserted)
        } else {
            Ok(Insert::AlreadyPresent)
        }
    }

    /// An edit: the body and its search text replaced, the message marked edited.
    pub fn edit_message(
        &self,
        id: &str,
        body: &[u8],
        search_text: Option<&str>,
        edited_at: i64,
    ) -> Result<bool> {
        let changed = {
            let mut conn = self.lock();
            let tx = conn.transaction()?;
            let changed = tx.execute(
                "UPDATE messages SET body = ?2, is_edited = 1, edited_at = ?3 WHERE id = ?1",
                params![id, body, edited_at],
            )?;
            if changed > 0 {
                tx.execute(
                    "DELETE FROM message_search WHERE rowid = (SELECT rowid FROM messages WHERE id = ?1)",
                    [id],
                )?;
                if let Some(text) = search_text.filter(|t| !t.is_empty()) {
                    tx.execute(
                        "INSERT INTO message_search (rowid, text)
                         SELECT rowid, ?2 FROM messages WHERE id = ?1",
                        params![id, text],
                    )?;
                }
            }
            tx.commit()?;
            changed > 0
        };
        if changed {
            self.notify(Table::Messages, vec![id.to_string()]);
        }
        Ok(changed)
    }

    pub fn set_delivery_status(&self, id: &str, status: DeliveryStatus) -> Result<bool> {
        let changed = self.lock().execute(
            "UPDATE messages SET delivery_status = ?2 WHERE id = ?1 AND delivery_status != ?2",
            params![id, status],
        )? > 0;
        if changed {
            self.notify(Table::Messages, vec![id.to_string()]);
        }
        Ok(changed)
    }

    pub fn message(&self, id: &str) -> Result<Option<Message>> {
        Ok(self
            .lock()
            .query_row(
                &format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE id = ?1"),
                [id],
                message_row,
            )
            .optional()?)
    }

    /// Up to `limit` messages of a chat just before `before` — `(order_key, id)` of the oldest
    /// message the client holds, `None` for the newest page — oldest first.
    pub fn messages_before(
        &self,
        chat_id: &str,
        before: Option<(&str, &str)>,
        limit: u32,
    ) -> Result<Vec<Message>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages
             WHERE chat_id = ?1 AND (?2 IS NULL OR (order_key, id) < (?2, ?3))
             ORDER BY order_key DESC, id DESC LIMIT ?4"
        ))?;
        let (key, id) = before.unzip();
        let mut rows = stmt
            .query_map(params![chat_id, key, id, limit], message_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.reverse();
        Ok(rows)
    }

    pub fn delete_message(&self, id: &str) -> Result<()> {
        let removed = self
            .lock()
            .execute("DELETE FROM messages WHERE id = ?1", [id])?;
        if removed > 0 {
            self.notify(Table::Messages, vec![id.to_string()]);
        }
        Ok(())
    }

    /// Messages whose text contains `query`, newest first. The query is matched as one phrase,
    /// never parsed as FTS syntax — a user's quote or `OR` is text, not an operator. Fewer than
    /// three characters find nothing (trigram index).
    pub fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>> {
        let phrase = format!("\"{}\"", query.replace('"', "\"\""));
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT m.id, m.chat_id, m.timestamp FROM message_search s
             JOIN messages m ON m.rowid = s.rowid
             WHERE message_search MATCH ?1
             ORDER BY m.timestamp DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![phrase, limit], |row| {
                Ok(SearchHit {
                    message_id: row.get(0)?,
                    chat_id: row.get(1)?,
                    timestamp: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // MARK: - Reactions

    /// One reaction per person per message; a new one replaces theirs.
    pub fn upsert_reaction(&self, r: &Reaction) -> Result<()> {
        self.lock().execute(
            "INSERT INTO reactions (target_message_id, reactor_user_id, emoji, timestamp_ms, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(target_message_id, reactor_user_id) DO UPDATE SET
                 emoji = excluded.emoji, timestamp_ms = excluded.timestamp_ms,
                 received_at = excluded.received_at",
            params![r.target_message_id, r.reactor_user_id, r.emoji, r.timestamp_ms, r.received_at],
        )?;
        self.notify(Table::Reactions, vec![r.target_message_id.clone()]);
        Ok(())
    }

    pub fn reactions(&self, target_message_id: &str) -> Result<Vec<Reaction>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT target_message_id, reactor_user_id, emoji, timestamp_ms, received_at
             FROM reactions WHERE target_message_id = ?1 ORDER BY timestamp_ms, reactor_user_id",
        )?;
        let rows = stmt
            .query_map([target_message_id], |row| {
                Ok(Reaction {
                    target_message_id: row.get(0)?,
                    reactor_user_id: row.get(1)?,
                    emoji: row.get(2)?,
                    timestamp_ms: row.get(3)?,
                    received_at: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn delete_reaction(&self, target_message_id: &str, reactor_user_id: &str) -> Result<()> {
        let removed = self.lock().execute(
            "DELETE FROM reactions WHERE target_message_id = ?1 AND reactor_user_id = ?2",
            [target_message_id, reactor_user_id],
        )?;
        if removed > 0 {
            self.notify(Table::Reactions, vec![target_message_id.to_string()]);
        }
        Ok(())
    }

    // MARK: - Calls

    pub fn upsert_call(&self, c: &CallRecord) -> Result<()> {
        self.lock().execute(
            "INSERT INTO calls (id, peer_user_id, peer_name, direction, status, started_at, ended_at, duration_seconds)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                 peer_user_id = excluded.peer_user_id, peer_name = excluded.peer_name,
                 direction = excluded.direction, status = excluded.status,
                 started_at = excluded.started_at, ended_at = excluded.ended_at,
                 duration_seconds = excluded.duration_seconds",
            params![
                c.id, c.peer_user_id, c.peer_name, c.direction, c.status, c.started_at,
                c.ended_at, c.duration_seconds
            ],
        )?;
        self.notify(Table::Calls, vec![c.id.clone()]);
        Ok(())
    }

    /// The call log, newest first.
    pub fn calls(&self, limit: u32) -> Result<Vec<CallRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, peer_user_id, peer_name, direction, status, started_at, ended_at, duration_seconds
             FROM calls ORDER BY started_at IS NULL, started_at DESC, id LIMIT ?1",
        )?;
        let rows = stmt
            .query_map([limit], |row| {
                Ok(CallRecord {
                    id: row.get(0)?,
                    peer_user_id: row.get(1)?,
                    peer_name: row.get(2)?,
                    direction: row.get(3)?,
                    status: row.get(4)?,
                    started_at: row.get(5)?,
                    ended_at: row.get(6)?,
                    duration_seconds: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // MARK: - Peer devices

    /// Record a device of an account. An id already known keeps its first account: a server that
    /// later names another account for the same device is not believed (iOS
    /// `SessionAddressing.recordDevices`, "PEER_DEVICE_REHOMED").
    pub fn record_peer_device(&self, d: &PeerDevice) -> Result<Insert> {
        let added = self.lock().execute(
            "INSERT OR IGNORE INTO peer_devices (device_id, account_id, identity_key, first_seen_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![d.device_id, d.account_id, d.identity_key, d.first_seen_at],
        )?;
        if added > 0 {
            self.notify(Table::PeerDevices, vec![d.device_id.clone()]);
            Ok(Insert::Inserted)
        } else {
            Ok(Insert::AlreadyPresent)
        }
    }

    pub fn peer_devices(&self, account_id: &str) -> Result<Vec<PeerDevice>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT device_id, account_id, identity_key, first_seen_at FROM peer_devices
             WHERE account_id = ?1 ORDER BY device_id",
        )?;
        let rows = stmt
            .query_map([account_id], |row| {
                Ok(PeerDevice {
                    device_id: row.get(0)?,
                    account_id: row.get(1)?,
                    identity_key: row.get(2)?,
                    first_seen_at: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Forget an account's devices the server no longer lists. An empty `active` forgets nothing:
    /// it cannot be told from a server that does not send the list (iOS `reconcileDevices`).
    pub fn retain_peer_devices(&self, account_id: &str, active: &[String]) -> Result<Vec<String>> {
        if active.is_empty() {
            return Ok(Vec::new());
        }
        let removed = {
            let mut conn = self.lock();
            let tx = conn.transaction()?;
            let stale: Vec<String> = {
                let mut stmt =
                    tx.prepare("SELECT device_id FROM peer_devices WHERE account_id = ?1")?;
                stmt.query_map([account_id], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
                    .into_iter()
                    .filter(|id| !active.contains(id))
                    .collect()
            };
            for id in &stale {
                tx.execute("DELETE FROM peer_devices WHERE device_id = ?1", [id])?;
            }
            tx.commit()?;
            stale
        };
        self.notify(Table::PeerDevices, removed.clone());
        Ok(removed)
    }

    // MARK: - Small state

    pub fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.lock().execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .lock()
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn remove(&self, key: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM kv WHERE key = ?1", [key])?;
        Ok(())
    }
}

// MARK: - Rows

const CONTACT_COLUMNS: &str = "id, username, display_name, local_alias, avatar, public_key,
    known_identity_key, account_address, is_contact, is_blocked, is_sharing_with_me,
    am_i_sharing_with, shared_with_me_at, added_at, kt_status, hybrid_capable, security_notice";

fn contact_row(row: &Row<'_>) -> rusqlite::Result<Contact> {
    Ok(Contact {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        local_alias: row.get(3)?,
        avatar: row.get(4)?,
        public_key: row.get(5)?,
        known_identity_key: row.get(6)?,
        account_address: row.get(7)?,
        is_contact: row.get(8)?,
        is_blocked: row.get(9)?,
        is_sharing_with_me: row.get(10)?,
        am_i_sharing_with: row.get(11)?,
        shared_with_me_at: row.get(12)?,
        added_at: row.get(13)?,
        kt_status: row.get(14)?,
        hybrid_capable: row.get(15)?,
        security_notice: row.get(16)?,
    })
}

const CHAT_COLUMNS: &str = "id, peer_id, last_message_text, last_message_time, session_id, is_pinned, is_muted, unread_count";

fn chat_row(row: &Row<'_>) -> rusqlite::Result<Chat> {
    Ok(Chat {
        id: row.get(0)?,
        peer_id: row.get(1)?,
        last_message_text: row.get(2)?,
        last_message_time: row.get(3)?,
        session_id: row.get(4)?,
        is_pinned: row.get(5)?,
        is_muted: row.get(6)?,
        unread_count: row.get(7)?,
    })
}

const MESSAGE_COLUMNS: &str = "id, chat_id, from_user_id, to_user_id, is_sent_by_me, timestamp,
    order_key, body, content_type, delivery_status, retry_count, suite_id, is_edited, edited_at,
    reply_to_message_id, reply_to_content, transcript_text, transcript_language,
    transcript_generated_at";

fn message_row(row: &Row<'_>) -> rusqlite::Result<Message> {
    Ok(Message {
        id: row.get(0)?,
        chat_id: row.get(1)?,
        from_user_id: row.get(2)?,
        to_user_id: row.get(3)?,
        is_sent_by_me: row.get(4)?,
        timestamp: row.get(5)?,
        order_key: row.get(6)?,
        body: row.get(7)?,
        content_type: row.get(8)?,
        delivery_status: row.get(9)?,
        retry_count: row.get(10)?,
        suite_id: row.get(11)?,
        is_edited: row.get(12)?,
        edited_at: row.get(13)?,
        reply_to_message_id: row.get(14)?,
        reply_to_content: row.get(15)?,
        transcript_text: row.get(16)?,
        transcript_language: row.get(17)?,
        transcript_generated_at: row.get(18)?,
    })
}

/// The key as hex, in a buffer wiped on drop.
fn hex(bytes: &[u8]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}
