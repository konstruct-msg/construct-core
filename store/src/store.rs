use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use rusqlite::{Connection, ErrorCode, OptionalExtension, Row, ToSql, params};
use zeroize::Zeroizing;

use crate::KEY_LEN;
use crate::error::{Result, StoreError};
use crate::migrations;
use crate::model::{
    CallRecord, Chat, Contact, DeliveryStatus, IdentityKeyPin, Message, OwnProfile, PeerDevice,
    Reaction, SearchHit, delivery,
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
            "INSERT INTO contacts (id, username, display_name, local_alias, avatar,
                 known_identity_key, account_address, is_contact, is_blocked, is_sharing_with_me,
                 am_i_sharing_with, shared_with_me_at, added_at, kt_status, security_notice,
                 profile_edited_at_ms, pending_avatar_ref, pending_avatar_since)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
             ON CONFLICT(id) DO UPDATE SET
                 username = excluded.username, display_name = excluded.display_name,
                 local_alias = excluded.local_alias, avatar = excluded.avatar,
                 known_identity_key = excluded.known_identity_key,
                 account_address = excluded.account_address, is_contact = excluded.is_contact,
                 is_blocked = excluded.is_blocked, is_sharing_with_me = excluded.is_sharing_with_me,
                 am_i_sharing_with = excluded.am_i_sharing_with,
                 shared_with_me_at = excluded.shared_with_me_at, added_at = excluded.added_at,
                 kt_status = excluded.kt_status, security_notice = excluded.security_notice,
                 profile_edited_at_ms = excluded.profile_edited_at_ms,
                 pending_avatar_ref = excluded.pending_avatar_ref,
                 pending_avatar_since = excluded.pending_avatar_since",
            params![
                c.id,
                c.username,
                c.display_name,
                c.local_alias,
                c.avatar,
                c.known_identity_key,
                c.account_address,
                c.is_contact,
                c.is_blocked,
                c.is_sharing_with_me,
                c.am_i_sharing_with,
                c.shared_with_me_at,
                c.added_at,
                c.kt_status,
                c.security_notice,
                c.profile_edited_at_ms,
                c.pending_avatar_ref,
                c.pending_avatar_since
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

    /// Every row, contacts or not (a peer we hold a key for, a blocked stranger), by id.
    pub fn every_contact(&self) -> Result<Vec<Contact>> {
        self.contacts_where("1", [])
    }

    /// The people we share our profile with, by id.
    pub fn sharing_with(&self) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT id FROM contacts WHERE am_i_sharing_with = 1 ORDER BY id")?;
        let ids = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    /// Rows with an avatar announced and not yet downloaded, by id.
    pub fn contacts_with_pending_avatar(&self) -> Result<Vec<Contact>> {
        self.contacts_where("pending_avatar_ref IS NOT NULL", [])
    }

    /// Every pinned identity key, by contact id.
    pub fn identity_key_pins(&self) -> Result<Vec<IdentityKeyPin>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, known_identity_key FROM contacts
             WHERE known_identity_key IS NOT NULL ORDER BY id",
        )?;
        let pins = stmt
            .query_map([], |row| {
                Ok(IdentityKeyPin {
                    contact_id: row.get(0)?,
                    key: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(pins)
    }

    // Each write below changes the named fields of one existing row and nothing else, in one
    // statement, so two writers of different fields never undo each other — which a read, a
    // change and an `upsert_contact` of the whole row would. `false`: no such row.

    /// A contact from now on; `added_at` is kept if it was set.
    pub fn mark_contact(&self, id: &str, added_at: i64) -> Result<bool> {
        self.update_contact(
            id,
            "is_contact = 1, added_at = COALESCE(added_at, ?1)",
            &[&added_at],
        )
    }

    pub fn set_contact_blocked(&self, id: &str, blocked: bool) -> Result<bool> {
        self.update_contact(id, "is_blocked = ?1", &[&blocked])
    }

    /// The name we gave them; `None` shows theirs again.
    pub fn set_contact_alias(&self, id: &str, alias: Option<&str>) -> Result<bool> {
        self.update_contact(id, "local_alias = ?1", &[&alias])
    }

    /// Whether we share our profile with them.
    pub fn set_sharing_with(&self, id: &str, sharing: bool) -> Result<bool> {
        self.update_contact(id, "am_i_sharing_with = ?1", &[&sharing])
    }

    pub fn set_identity_key(&self, id: &str, key: Option<&[u8]>) -> Result<bool> {
        self.update_contact(id, "known_identity_key = ?1", &[&key])
    }

    pub fn set_kt_status(&self, id: &str, status: i16) -> Result<bool> {
        self.update_contact(id, "kt_status = ?1", &[&status])
    }

    pub fn set_account_address(&self, id: &str, address: Option<&[u8]>) -> Result<bool> {
        self.update_contact(id, "account_address = ?1", &[&address])
    }

    pub fn set_security_notice(&self, id: &str, notice: i16) -> Result<bool> {
        self.update_contact(id, "security_notice = ?1", &[&notice])
    }

    /// The names the server knows them by, as the client resolved them.
    pub fn set_contact_names(&self, id: &str, username: &str, display_name: &str) -> Result<bool> {
        self.update_contact(
            id,
            "username = ?1, display_name = ?2",
            &[&username, &display_name],
        )
    }

    /// A profile they shared with us. Which name and times to write is the client's decision —
    /// whether this edit is newer, whether the name is a generated one.
    pub fn apply_shared_profile(
        &self,
        id: &str,
        display_name: &str,
        shared_with_me_at: i64,
        profile_edited_at_ms: i64,
    ) -> Result<bool> {
        self.update_contact(
            id,
            "is_sharing_with_me = 1, display_name = ?1, shared_with_me_at = ?2,
             profile_edited_at_ms = ?3",
            &[&display_name, &shared_with_me_at, &profile_edited_at_ms],
        )
    }

    /// The avatar, and the one still to download — set together, since a downloaded avatar ends
    /// the wait for it and an announced one replaces what was shown.
    pub fn set_contact_avatar(
        &self,
        id: &str,
        avatar: Option<&[u8]>,
        pending_ref: Option<&[u8]>,
        pending_since: Option<i64>,
    ) -> Result<bool> {
        self.update_contact(
            id,
            "avatar = ?1, pending_avatar_ref = ?2, pending_avatar_since = ?3",
            &[&avatar, &pending_ref, &pending_since],
        )
    }

    fn update_contact(&self, id: &str, set: &str, values: &[&dyn ToSql]) -> Result<bool> {
        let mut args = values.to_vec();
        args.push(&id);
        let sql = format!("UPDATE contacts SET {set} WHERE id = ?{}", args.len());
        let changed = self.lock().execute(&sql, args.as_slice())? > 0;
        if changed {
            self.notify(Table::Contacts, vec![id.to_string()]);
        }
        Ok(changed)
    }

    fn contacts_where<P: rusqlite::Params>(&self, filter: &str, args: P) -> Result<Vec<Contact>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts WHERE {filter} ORDER BY id"
        ))?;
        let rows = stmt
            .query_map(args, contact_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // MARK: - Own profile

    pub fn own_profile(&self) -> Result<Option<OwnProfile>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT account_id, username, display_name, avatar, profile_edited_at_ms
                 FROM own_profile WHERE one = 1",
                [],
                |row| {
                    Ok(OwnProfile {
                        account_id: row.get(0)?,
                        username: row.get(1)?,
                        display_name: row.get(2)?,
                        avatar: row.get(3)?,
                        profile_edited_at_ms: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// Replaces our profile — there is one.
    pub fn set_own_profile(&self, p: &OwnProfile) -> Result<()> {
        self.lock().execute(
            "INSERT INTO own_profile (one, account_id, username, display_name, avatar,
                 profile_edited_at_ms)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(one) DO UPDATE SET
                 account_id = excluded.account_id, username = excluded.username,
                 display_name = excluded.display_name, avatar = excluded.avatar,
                 profile_edited_at_ms = excluded.profile_edited_at_ms",
            params![
                p.account_id,
                p.username,
                p.display_name,
                p.avatar,
                p.profile_edited_at_ms
            ],
        )?;
        self.notify(Table::OwnProfile, vec![p.account_id.clone()]);
        Ok(())
    }

    // MARK: - Chats

    /// The whole row, replacing one with the same id. A second chat for a peer that has one is
    /// refused (`Sqlite` constraint error): one chat per peer.
    pub fn upsert_chat(&self, c: &Chat) -> Result<()> {
        self.lock().execute(
            "INSERT INTO chats (id, peer_id, last_message_text, last_message_time, is_pinned,
                 unread_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                 peer_id = excluded.peer_id, last_message_text = excluded.last_message_text,
                 last_message_time = excluded.last_message_time, is_pinned = excluded.is_pinned,
                 unread_count = excluded.unread_count",
            params![
                c.id,
                c.peer_id,
                c.last_message_text,
                c.last_message_time,
                c.is_pinned,
                c.unread_count
            ],
        )?;
        self.notify(Table::Chats, vec![c.id.clone()]);
        Ok(())
    }

    /// Adds the chat unless its id or its peer already has one; the chat to use then is
    /// `chat_for_peer`. Two writers opening a chat with the same person at once get one chat.
    pub fn insert_chat(&self, c: &Chat) -> Result<Insert> {
        let added = self.lock().execute(
            "INSERT INTO chats (id, peer_id, last_message_text, last_message_time, is_pinned,
                 unread_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT DO NOTHING",
            params![
                c.id,
                c.peer_id,
                c.last_message_text,
                c.last_message_time,
                c.is_pinned,
                c.unread_count
            ],
        )?;
        if added > 0 {
            self.notify(Table::Chats, vec![c.id.clone()]);
            Ok(Insert::Inserted)
        } else {
            Ok(Insert::AlreadyPresent)
        }
    }

    pub fn chat_for_peer(&self, peer_id: &str) -> Result<Option<Chat>> {
        Ok(self
            .lock()
            .query_row(
                &format!("SELECT {CHAT_COLUMNS} FROM chats WHERE peer_id = ?1"),
                [peer_id],
                chat_row,
            )
            .optional()?)
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

    // Each write below changes the named fields of one existing chat in one statement, like the
    // contact writes. The preview and the unread count are written by every arriving message, from
    // whichever thread received it: a read, a change and a write back would lose one of two.

    /// Moves the preview to a message unless the one shown is newer — messages arrive out of
    /// order, and an older one must not replace a newer preview. An equal time moves it (a
    /// message edited in place). `false`: no such chat, or the preview shown is newer.
    pub fn advance_chat_preview(&self, id: &str, text: &str, time: i64) -> Result<bool> {
        self.update_chat(
            id,
            "last_message_text = ?1, last_message_time = ?2",
            "AND (last_message_time IS NULL OR last_message_time <= ?2)",
            &[&text, &time],
        )
    }

    /// Sets the preview whatever it was: recomputed from the messages left after a deletion,
    /// which moves it back; both `None` when none are left.
    pub fn set_chat_preview(
        &self,
        id: &str,
        text: Option<&str>,
        time: Option<i64>,
    ) -> Result<bool> {
        self.update_chat(
            id,
            "last_message_text = ?1, last_message_time = ?2",
            "",
            &[&text, &time],
        )
    }

    /// One more unread message.
    pub fn increment_unread(&self, id: &str) -> Result<bool> {
        self.update_chat(id, "unread_count = unread_count + 1", "", &[])
    }

    /// Zero when the chat is read.
    pub fn set_unread(&self, id: &str, count: i32) -> Result<bool> {
        self.update_chat(id, "unread_count = ?1", "", &[&count])
    }

    pub fn set_chat_pinned(&self, id: &str, pinned: bool) -> Result<bool> {
        self.update_chat(id, "is_pinned = ?1", "", &[&pinned])
    }

    fn update_message(
        &self,
        id: &str,
        set: &str,
        and: &str,
        values: &[&dyn ToSql],
    ) -> Result<bool> {
        let mut args = values.to_vec();
        args.push(&id);
        let sql = format!("UPDATE messages SET {set} WHERE id = ?{} {and}", args.len());
        let changed = self.lock().execute(&sql, args.as_slice())? > 0;
        if changed {
            self.notify(Table::Messages, vec![id.to_string()]);
        }
        Ok(changed)
    }

    fn update_chat(&self, id: &str, set: &str, and: &str, values: &[&dyn ToSql]) -> Result<bool> {
        let mut args = values.to_vec();
        args.push(&id);
        let sql = format!("UPDATE chats SET {set} WHERE id = ?{} {and}", args.len());
        let changed = self.lock().execute(&sql, args.as_slice())? > 0;
        if changed {
            self.notify(Table::Chats, vec![id.to_string()]);
        }
        Ok(changed)
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
        self.replace_body(id, body, search_text, Some(edited_at))
    }

    /// The body and its search text replaced, the message **not** marked edited: what it said all
    /// along, read late — a message stored undecryptable whose sender sent it again under the same
    /// id. False when there is no such message.
    pub fn set_message_body(
        &self,
        id: &str,
        body: &[u8],
        search_text: Option<&str>,
    ) -> Result<bool> {
        self.replace_body(id, body, search_text, None)
    }

    /// One path for both: the body and the full-text row in one transaction, `edited_at` marking
    /// an edit when given.
    fn replace_body(
        &self,
        id: &str,
        body: &[u8],
        search_text: Option<&str>,
        edited_at: Option<i64>,
    ) -> Result<bool> {
        let changed = {
            let mut conn = self.lock();
            let tx = conn.transaction()?;
            let changed = match edited_at {
                Some(at) => tx.execute(
                    "UPDATE messages SET body = ?2, is_edited = 1, edited_at = ?3 WHERE id = ?1",
                    params![id, body, at],
                )?,
                None => tx.execute(
                    "UPDATE messages SET body = ?2 WHERE id = ?1",
                    params![id, body],
                )?,
            };
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

    /// Write `status` unless the stored one is stronger evidence (`delivery::evidence_rank`): a
    /// slower writer arriving with a weaker fact is refused, and that is the normal outcome, not
    /// an error. False also when nothing changed or there is no such message. Until 0.37.0 this
    /// wrote any status; the rule was the iOS app's.
    pub fn set_delivery_status(&self, id: &str, status: DeliveryStatus) -> Result<bool> {
        self.update_message(
            id,
            "delivery_status = ?1",
            &format!(
                "AND delivery_status != ?1 AND {} <= ?2",
                RANK_OF_STORED_STATUS
            ),
            &[&status, &delivery::evidence_rank(status)],
        )
    }

    /// The session an outgoing message was encrypted under was archived: keep it (the peer
    /// confirmed), queue it again, or give up when `max_retries` is spent. This is the one write
    /// that may lower the evidence — `SENT` stops meaning anything once the peer can no longer
    /// decrypt — and `Keep` is the branch that protects `DELIVERED`. `None` when there is no
    /// such message.
    pub fn apply_session_archive(
        &self,
        id: &str,
        max_retries: i16,
    ) -> Result<Option<delivery::ArchiveOutcome>> {
        let (outcome, changed) = {
            let mut conn = self.lock();
            let tx = conn.transaction()?;
            let Some((status, retry_count)) = tx
                .query_row(
                    "SELECT delivery_status, retry_count FROM messages WHERE id = ?1",
                    [id],
                    |row| Ok((row.get::<_, DeliveryStatus>(0)?, row.get::<_, i16>(1)?)),
                )
                .optional()?
            else {
                return Ok(None);
            };
            let outcome = delivery::after_session_archive(status, retry_count, max_retries);
            let target = match outcome {
                delivery::ArchiveOutcome::Keep => None,
                delivery::ArchiveOutcome::Resend => Some(delivery::QUEUED),
                delivery::ArchiveOutcome::GiveUp => Some(delivery::FAILED),
            };
            let changed = match target {
                Some(t) if t != status => {
                    tx.execute(
                        "UPDATE messages SET delivery_status = ?2 WHERE id = ?1",
                        params![id, t],
                    )? > 0
                }
                _ => false,
            };
            tx.commit()?;
            (outcome, changed)
        };
        if changed {
            self.notify(Table::Messages, vec![id.to_string()]);
        }
        Ok(Some(outcome))
    }

    /// Each write below changes its named fields of one message in one statement, is announced
    /// after it commits, and reports false when there is no such message or nothing changed.
    pub fn set_retry_count(&self, id: &str, count: i16) -> Result<bool> {
        self.update_message(id, "retry_count = ?1", "AND retry_count != ?1", &[&count])
    }

    /// One more attempt, counted in the store rather than read, changed and written back — two
    /// retries at once would otherwise count as one. The new count, or `None` for no message.
    pub fn increment_retry_count(&self, id: &str) -> Result<Option<i16>> {
        let count = self
            .lock()
            .query_row(
                "UPDATE messages SET retry_count = retry_count + 1 WHERE id = ?1
                 RETURNING retry_count",
                [id],
                |row| row.get::<_, i16>(0),
            )
            .optional()?;
        if count.is_some() {
            self.notify(Table::Messages, vec![id.to_string()]);
        }
        Ok(count)
    }

    /// The server's order for a message we placed optimistically.
    pub fn set_order_key(&self, id: &str, order_key: &str) -> Result<bool> {
        self.update_message(id, "order_key = ?1", "AND order_key != ?1", &[&order_key])
    }

    /// A voice or video note's transcript; all `None` clears it.
    pub fn set_transcript(
        &self,
        id: &str,
        text: Option<&str>,
        language: Option<&str>,
        generated_at: Option<i64>,
    ) -> Result<bool> {
        self.update_message(
            id,
            "transcript_text = ?1, transcript_language = ?2, transcript_generated_at = ?3",
            "AND (transcript_text IS NOT ?1 OR transcript_language IS NOT ?2
                  OR transcript_generated_at IS NOT ?3)",
            &[&text, &language, &generated_at],
        )
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

    /// Up to `limit` messages of a chat from `from` — `(order_key, id)`, included — onwards,
    /// oldest first: the window a transcript already holds, read again forwards.
    pub fn messages_from(
        &self,
        chat_id: &str,
        from: (&str, &str),
        limit: u32,
    ) -> Result<Vec<Message>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages
             WHERE chat_id = ?1 AND (order_key, id) >= (?2, ?3)
             ORDER BY order_key, id LIMIT ?4"
        ))?;
        let rows = stmt
            .query_map(params![chat_id, from.0, from.1, limit], message_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Our messages waiting to be sent: queued, or failed with attempts left under
    /// `retry_ceiling`; in one chat, or in every chat for `None`. Transcript order.
    pub fn pending_sends(
        &self,
        chat_id: Option<&str>,
        retry_ceiling: i16,
        limit: u32,
    ) -> Result<Vec<Message>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages
             WHERE is_sent_by_me = 1 AND (?1 IS NULL OR chat_id = ?1)
               AND (delivery_status = ?2 OR (delivery_status = ?3 AND retry_count < ?4))
             ORDER BY order_key, id LIMIT ?5"
        ))?;
        let rows = stmt
            .query_map(
                params![
                    chat_id,
                    delivery::QUEUED,
                    delivery::FAILED,
                    retry_ceiling,
                    limit
                ],
                message_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn message_count(&self) -> Result<u64> {
        Ok(self
            .lock()
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))?)
    }

    /// Every message of every chat after `after` — `(order_key, id)`, `None` for the start — in
    /// `(order_key, id)` order, a page at a time: what a history snapshot reads.
    pub fn all_messages_after(
        &self,
        after: Option<(&str, &str)>,
        limit: u32,
    ) -> Result<Vec<Message>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages
             WHERE ?1 IS NULL OR (order_key, id) > (?1, ?2)
             ORDER BY order_key, id LIMIT ?3"
        ))?;
        let (key, id) = after.unzip();
        let rows = stmt
            .query_map(params![key, id, limit], message_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
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

    /// Every reaction, oldest first: what a history snapshot reads.
    pub fn all_reactions(&self) -> Result<Vec<Reaction>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT target_message_id, reactor_user_id, emoji, timestamp_ms, received_at
             FROM reactions ORDER BY timestamp_ms, target_message_id, reactor_user_id",
        )?;
        let rows = stmt
            .query_map([], |row| {
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

    /// Forget reactions received at or before `cutoff` (ms); one with no receipt time — ours, or
    /// from a history snapshot — is kept. How many went.
    pub fn expire_reactions(&self, cutoff: i64) -> Result<u32> {
        let targets = {
            let mut conn = self.lock();
            let tx = conn.transaction()?;
            let targets = {
                let mut stmt = tx.prepare(
                    "DELETE FROM reactions WHERE received_at IS NOT NULL AND received_at <= ?1
                     RETURNING target_message_id",
                )?;
                stmt.query_map([cutoff], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            tx.commit()?;
            targets
        };
        let removed = targets.len() as u32;
        if !targets.is_empty() {
            let mut ids = targets;
            ids.sort();
            ids.dedup();
            self.notify(Table::Reactions, ids);
        }
        Ok(removed)
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

    /// An account's devices, oldest first. The device a single-device peer has always had stays
    /// first, and the order is the same on every run: devices recorded from one bundle answer
    /// share a millisecond, so `device_id` breaks the tie rather than the table's row order.
    pub fn peer_devices(&self, account_id: &str) -> Result<Vec<PeerDevice>> {
        self.select_peer_devices(
            "WHERE account_id = ?1 ORDER BY first_seen_at, device_id",
            [account_id],
        )
    }

    /// One device by id, whichever account it was recorded for.
    pub fn peer_device(&self, device_id: &str) -> Result<Option<PeerDevice>> {
        Ok(self
            .select_peer_devices("WHERE device_id = ?1", [device_id])?
            .pop())
    }

    /// Every recorded device of every account, in the per-account order above.
    pub fn all_peer_devices(&self) -> Result<Vec<PeerDevice>> {
        self.select_peer_devices("ORDER BY account_id, first_seen_at, device_id", [])
    }

    fn select_peer_devices<P: rusqlite::Params>(
        &self,
        clause: &str,
        params: P,
    ) -> Result<Vec<PeerDevice>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT device_id, account_id, identity_key, first_seen_at FROM peer_devices {clause}"
        ))?;
        let rows = stmt
            .query_map(params, |row| {
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

    // MARK: - Server message ids

    /// Remember that the server named our message `local_id` as `server_id`. Ids compare
    /// case-insensitively (UUID text), so both are kept lowercase. A server id recorded again
    /// takes the new message: the server never reuses one, so that is a correction.
    pub fn record_server_message_id(
        &self,
        server_id: &str,
        local_id: &str,
        recorded_at: i64,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO server_message_ids (server_id, local_id, recorded_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(server_id) DO UPDATE SET local_id = excluded.local_id,
                                                  recorded_at = excluded.recorded_at",
            params![
                server_id.to_ascii_lowercase(),
                local_id.to_ascii_lowercase(),
                recorded_at
            ],
        )?;
        Ok(())
    }

    /// Our message id for a server id, if we sent under it.
    pub fn local_message_id(&self, server_id: &str) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT local_id FROM server_message_ids WHERE server_id = ?1",
                [server_id.to_ascii_lowercase()],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Forget ids recorded before `cutoff` (ms); returns how many.
    pub fn forget_server_message_ids_before(&self, cutoff: i64) -> Result<u64> {
        Ok(self.lock().execute(
            "DELETE FROM server_message_ids WHERE recorded_at < ?1",
            [cutoff],
        )? as u64)
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

const CONTACT_COLUMNS: &str = "id, username, display_name, local_alias, avatar,
    known_identity_key, account_address, is_contact, is_blocked, is_sharing_with_me,
    am_i_sharing_with, shared_with_me_at, added_at, kt_status, security_notice,
    profile_edited_at_ms, pending_avatar_ref, pending_avatar_since";

fn contact_row(row: &Row<'_>) -> rusqlite::Result<Contact> {
    Ok(Contact {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        local_alias: row.get(3)?,
        avatar: row.get(4)?,
        known_identity_key: row.get(5)?,
        account_address: row.get(6)?,
        is_contact: row.get(7)?,
        is_blocked: row.get(8)?,
        is_sharing_with_me: row.get(9)?,
        am_i_sharing_with: row.get(10)?,
        shared_with_me_at: row.get(11)?,
        added_at: row.get(12)?,
        kt_status: row.get(13)?,
        security_notice: row.get(14)?,
        profile_edited_at_ms: row.get(15)?,
        pending_avatar_ref: row.get(16)?,
        pending_avatar_since: row.get(17)?,
    })
}

const CHAT_COLUMNS: &str =
    "id, peer_id, last_message_text, last_message_time, is_pinned, unread_count";

fn chat_row(row: &Row<'_>) -> rusqlite::Result<Chat> {
    Ok(Chat {
        id: row.get(0)?,
        peer_id: row.get(1)?,
        last_message_text: row.get(2)?,
        last_message_time: row.get(3)?,
        is_pinned: row.get(4)?,
        unread_count: row.get(5)?,
    })
}

/// `delivery::evidence_rank` of the stored status, in SQL — kept beside the Rust one and checked
/// against it by `the_status_rule_is_one_rule`.
const RANK_OF_STORED_STATUS: &str = "(CASE delivery_status WHEN 2 THEN 2 WHEN 1 THEN 1 ELSE 0 END)";

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
