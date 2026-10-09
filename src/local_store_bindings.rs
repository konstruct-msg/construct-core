//! `construct-store` over UniFFI, in this library's one component — a component of its own would
//! be a second Swift module every app target has to wire up. Field-for-field conversions only; the
//! store decides everything (`construct-docs/decisions/local-store-in-the-core.md`).
//!
//! The Tauri desktops and the TUI use `construct_store` directly and never see this file.

use std::sync::{Arc, RwLock};

use construct_store as store;

#[derive(Debug, thiserror::Error)]
pub enum LocalStoreError {
    #[error("the key does not open this store")]
    WrongKey,
    #[error("the store key must be 32 bytes")]
    KeyLength,
    #[error("the store was written by a newer build")]
    SchemaTooNew,
    #[error("the store was wiped")]
    Closed,
    /// SQLite or file errors, with the detail in the message.
    #[error("{0}")]
    Storage(String),
}

impl From<store::StoreError> for LocalStoreError {
    fn from(e: store::StoreError) -> Self {
        match e {
            store::StoreError::WrongKey => Self::WrongKey,
            store::StoreError::KeyLength { .. } => Self::KeyLength,
            store::StoreError::SchemaTooNew { .. } => Self::SchemaTooNew,
            other => Self::Storage(other.to_string()),
        }
    }
}

type Result<T> = std::result::Result<T, LocalStoreError>;

pub enum LocalStoreTable {
    Contacts,
    Chats,
    Messages,
    Reactions,
    Calls,
    PeerDevices,
    OwnProfile,
}

impl From<store::Table> for LocalStoreTable {
    fn from(t: store::Table) -> Self {
        match t {
            store::Table::Contacts => Self::Contacts,
            store::Table::Chats => Self::Chats,
            store::Table::Messages => Self::Messages,
            store::Table::Reactions => Self::Reactions,
            store::Table::Calls => Self::Calls,
            store::Table::PeerDevices => Self::PeerDevices,
            store::Table::OwnProfile => Self::OwnProfile,
        }
    }
}

pub enum LocalInsert {
    Inserted,
    AlreadyPresent,
}

impl From<store::Insert> for LocalInsert {
    fn from(i: store::Insert) -> Self {
        match i {
            store::Insert::Inserted => Self::Inserted,
            store::Insert::AlreadyPresent => Self::AlreadyPresent,
        }
    }
}

pub enum LocalArchiveOutcome {
    Keep,
    Resend,
    GiveUp,
}

impl From<store::delivery::ArchiveOutcome> for LocalArchiveOutcome {
    fn from(o: store::delivery::ArchiveOutcome) -> Self {
        match o {
            store::delivery::ArchiveOutcome::Keep => Self::Keep,
            store::delivery::ArchiveOutcome::Resend => Self::Resend,
            store::delivery::ArchiveOutcome::GiveUp => Self::GiveUp,
        }
    }
}

pub struct LocalStoreChange {
    pub table: LocalStoreTable,
    pub ids: Vec<String>,
}

pub trait LocalStoreObserver: Send + Sync {
    fn on_change(&self, change: LocalStoreChange);
}

struct ObserverBridge(Box<dyn LocalStoreObserver>);

impl store::StoreObserver for ObserverBridge {
    fn on_change(&self, change: store::Change) {
        self.0.on_change(LocalStoreChange {
            table: change.table.into(),
            ids: change.ids,
        });
    }
}

/// Declares a record twice — as UniFFI sees it and as the store does — with conversions both ways.
macro_rules! mirror {
    ($local:ident <=> $inner:path { $($field:ident: $ty:ty),* $(,)? }) => {
        pub struct $local { $(pub $field: $ty),* }
        impl From<$inner> for $local {
            fn from(v: $inner) -> Self { Self { $($field: v.$field),* } }
        }
        impl From<$local> for $inner {
            fn from(v: $local) -> Self { Self { $($field: v.$field),* } }
        }
    };
}

mirror!(LocalContact <=> store::Contact {
    id: String, username: String, display_name: String, local_alias: Option<String>,
    avatar: Option<Vec<u8>>, known_identity_key: Option<Vec<u8>>,
    account_address: Option<Vec<u8>>, is_contact: bool, is_blocked: bool,
    is_sharing_with_me: bool, am_i_sharing_with: bool, shared_with_me_at: Option<i64>,
    added_at: Option<i64>, kt_status: i16, security_notice: i16, profile_edited_at_ms: i64,
    pending_avatar_ref: Option<Vec<u8>>, pending_avatar_since: Option<i64>,
});

mirror!(LocalOwnProfile <=> store::OwnProfile {
    account_id: String, username: String, display_name: String, avatar: Option<Vec<u8>>,
    profile_edited_at_ms: i64,
});

mirror!(LocalIdentityKeyPin <=> store::IdentityKeyPin {
    contact_id: String, key: Vec<u8>,
});

mirror!(LocalChat <=> store::Chat {
    id: String, peer_id: String, last_message_text: Option<String>,
    last_message_time: Option<i64>, is_pinned: bool, unread_count: i32,
});

mirror!(LocalMessage <=> store::Message {
    id: String, chat_id: String, from_user_id: String, to_user_id: String,
    is_sent_by_me: bool, timestamp: i64, order_key: String, body: Vec<u8>, content_type: i16,
    delivery_status: i16, retry_count: i16, suite_id: i16, is_edited: bool,
    edited_at: Option<i64>, reply_to_message_id: Option<String>,
    reply_to_content: Option<String>, transcript_text: Option<String>,
    transcript_language: Option<String>, transcript_generated_at: Option<i64>,
});

mirror!(LocalReaction <=> store::Reaction {
    target_message_id: String, reactor_user_id: String, emoji: String, timestamp_ms: i64,
    received_at: Option<i64>,
});

mirror!(LocalCall <=> store::CallRecord {
    id: String, peer_user_id: String, peer_name: String, direction: i16, status: i16,
    started_at: Option<i64>, ended_at: Option<i64>, duration_seconds: i32,
});

mirror!(LocalPeerDevice <=> store::PeerDevice {
    device_id: String, account_id: String, identity_key: Vec<u8>, first_seen_at: i64,
});

mirror!(LocalSearchHit <=> store::SearchHit {
    message_id: String, chat_id: String, timestamp: i64,
});

/// The store, closable: `wipe` takes it out, and every call after is `Closed`.
pub struct LocalStore {
    inner: RwLock<Option<store::Store>>,
}

fn all<T, U: From<T>>(rows: Vec<T>) -> Vec<U> {
    rows.into_iter().map(U::from).collect()
}

impl LocalStore {
    pub fn new(path: String, key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            inner: RwLock::new(Some(store::Store::open(path, &key)?)),
        })
    }

    pub fn in_memory(key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            inner: RwLock::new(Some(store::Store::open_in_memory(&key)?)),
        })
    }

    fn with<T>(
        &self,
        f: impl FnOnce(&store::Store) -> std::result::Result<T, store::StoreError>,
    ) -> Result<T> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let store = guard.as_ref().ok_or(LocalStoreError::Closed)?;
        Ok(f(store)?)
    }

    pub fn set_observer(&self, observer: Option<Box<dyn LocalStoreObserver>>) {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        if let Some(store) = guard.as_ref() {
            store.set_observer(
                observer.map(|o| Arc::new(ObserverBridge(o)) as Arc<dyn store::StoreObserver>),
            );
        }
    }

    pub fn wipe(&self) -> Result<()> {
        let taken = self.inner.write().unwrap_or_else(|e| e.into_inner()).take();
        match taken {
            Some(store) => Ok(store.wipe()?),
            None => Err(LocalStoreError::Closed),
        }
    }

    pub fn upsert_contact(&self, contact: LocalContact) -> Result<()> {
        self.with(|s| s.upsert_contact(&contact.into()))
    }
    pub fn contact(&self, id: String) -> Result<Option<LocalContact>> {
        Ok(self.with(|s| s.contact(&id))?.map(Into::into))
    }
    pub fn contacts(&self) -> Result<Vec<LocalContact>> {
        Ok(all(self.with(|s| s.contacts())?))
    }
    pub fn delete_contact(&self, id: String) -> Result<()> {
        self.with(|s| s.delete_contact(&id))
    }
    pub fn every_contact(&self) -> Result<Vec<LocalContact>> {
        Ok(all(self.with(|s| s.every_contact())?))
    }
    pub fn sharing_with(&self) -> Result<Vec<String>> {
        self.with(|s| s.sharing_with())
    }
    pub fn contacts_with_pending_avatar(&self) -> Result<Vec<LocalContact>> {
        Ok(all(self.with(|s| s.contacts_with_pending_avatar())?))
    }
    pub fn identity_key_pins(&self) -> Result<Vec<LocalIdentityKeyPin>> {
        Ok(all(self.with(|s| s.identity_key_pins())?))
    }
    pub fn mark_contact(&self, id: String, added_at: i64) -> Result<bool> {
        self.with(|s| s.mark_contact(&id, added_at))
    }
    pub fn set_contact_blocked(&self, id: String, blocked: bool) -> Result<bool> {
        self.with(|s| s.set_contact_blocked(&id, blocked))
    }
    pub fn set_contact_alias(&self, id: String, alias: Option<String>) -> Result<bool> {
        self.with(|s| s.set_contact_alias(&id, alias.as_deref()))
    }
    pub fn set_sharing_with(&self, id: String, sharing: bool) -> Result<bool> {
        self.with(|s| s.set_sharing_with(&id, sharing))
    }
    pub fn set_identity_key(&self, id: String, key: Option<Vec<u8>>) -> Result<bool> {
        self.with(|s| s.set_identity_key(&id, key.as_deref()))
    }
    pub fn set_kt_status(&self, id: String, status: i16) -> Result<bool> {
        self.with(|s| s.set_kt_status(&id, status))
    }
    pub fn set_account_address(&self, id: String, address: Option<Vec<u8>>) -> Result<bool> {
        self.with(|s| s.set_account_address(&id, address.as_deref()))
    }
    pub fn set_security_notice(&self, id: String, notice: i16) -> Result<bool> {
        self.with(|s| s.set_security_notice(&id, notice))
    }
    pub fn set_contact_names(
        &self,
        id: String,
        username: String,
        display_name: String,
    ) -> Result<bool> {
        self.with(|s| s.set_contact_names(&id, &username, &display_name))
    }
    pub fn apply_shared_profile(
        &self,
        id: String,
        display_name: String,
        shared_with_me_at: i64,
        profile_edited_at_ms: i64,
    ) -> Result<bool> {
        self.with(|s| {
            s.apply_shared_profile(&id, &display_name, shared_with_me_at, profile_edited_at_ms)
        })
    }
    pub fn set_contact_avatar(
        &self,
        id: String,
        avatar: Option<Vec<u8>>,
        pending_ref: Option<Vec<u8>>,
        pending_since: Option<i64>,
    ) -> Result<bool> {
        self.with(|s| {
            s.set_contact_avatar(
                &id,
                avatar.as_deref(),
                pending_ref.as_deref(),
                pending_since,
            )
        })
    }

    pub fn own_profile(&self) -> Result<Option<LocalOwnProfile>> {
        Ok(self.with(|s| s.own_profile())?.map(Into::into))
    }
    pub fn set_own_profile(&self, profile: LocalOwnProfile) -> Result<()> {
        self.with(|s| s.set_own_profile(&profile.into()))
    }

    pub fn upsert_chat(&self, chat: LocalChat) -> Result<()> {
        self.with(|s| s.upsert_chat(&chat.into()))
    }
    pub fn insert_chat(&self, chat: LocalChat) -> Result<LocalInsert> {
        Ok(self.with(|s| s.insert_chat(&chat.into()))?.into())
    }
    pub fn chat(&self, id: String) -> Result<Option<LocalChat>> {
        Ok(self.with(|s| s.chat(&id))?.map(Into::into))
    }
    pub fn chat_for_peer(&self, peer_id: String) -> Result<Option<LocalChat>> {
        Ok(self.with(|s| s.chat_for_peer(&peer_id))?.map(Into::into))
    }
    pub fn advance_chat_preview(&self, id: String, text: String, time: i64) -> Result<bool> {
        self.with(|s| s.advance_chat_preview(&id, &text, time))
    }
    pub fn set_chat_preview(
        &self,
        id: String,
        text: Option<String>,
        time: Option<i64>,
    ) -> Result<bool> {
        self.with(|s| s.set_chat_preview(&id, text.as_deref(), time))
    }
    pub fn increment_unread(&self, id: String) -> Result<bool> {
        self.with(|s| s.increment_unread(&id))
    }
    pub fn set_unread(&self, id: String, count: i32) -> Result<bool> {
        self.with(|s| s.set_unread(&id, count))
    }
    pub fn set_chat_pinned(&self, id: String, pinned: bool) -> Result<bool> {
        self.with(|s| s.set_chat_pinned(&id, pinned))
    }
    pub fn chats(&self) -> Result<Vec<LocalChat>> {
        Ok(all(self.with(|s| s.chats())?))
    }
    pub fn delete_chat(&self, id: String) -> Result<()> {
        self.with(|s| s.delete_chat(&id))
    }

    pub fn insert_message(
        &self,
        message: LocalMessage,
        search_text: Option<String>,
    ) -> Result<LocalInsert> {
        Ok(self
            .with(|s| s.insert_message(&message.into(), search_text.as_deref()))?
            .into())
    }
    pub fn edit_message(
        &self,
        id: String,
        body: Vec<u8>,
        search_text: Option<String>,
        edited_at: i64,
    ) -> Result<bool> {
        self.with(|s| s.edit_message(&id, &body, search_text.as_deref(), edited_at))
    }
    pub fn set_message_body(
        &self,
        id: String,
        body: Vec<u8>,
        search_text: Option<String>,
    ) -> Result<bool> {
        self.with(|s| s.set_message_body(&id, &body, search_text.as_deref()))
    }
    pub fn set_delivery_status(&self, id: String, status: i16) -> Result<bool> {
        self.with(|s| s.set_delivery_status(&id, status))
    }
    pub fn apply_session_archive(
        &self,
        id: String,
        max_retries: i16,
    ) -> Result<Option<LocalArchiveOutcome>> {
        Ok(self
            .with(|s| s.apply_session_archive(&id, max_retries))?
            .map(Into::into))
    }
    pub fn set_retry_count(&self, id: String, count: i16) -> Result<bool> {
        self.with(|s| s.set_retry_count(&id, count))
    }
    pub fn increment_retry_count(&self, id: String) -> Result<Option<i16>> {
        self.with(|s| s.increment_retry_count(&id))
    }
    pub fn set_order_key(&self, id: String, order_key: String) -> Result<bool> {
        self.with(|s| s.set_order_key(&id, &order_key))
    }
    pub fn set_transcript(
        &self,
        id: String,
        text: Option<String>,
        language: Option<String>,
        generated_at: Option<i64>,
    ) -> Result<bool> {
        self.with(|s| s.set_transcript(&id, text.as_deref(), language.as_deref(), generated_at))
    }
    pub fn message(&self, id: String) -> Result<Option<LocalMessage>> {
        Ok(self.with(|s| s.message(&id))?.map(Into::into))
    }
    pub fn messages_before(
        &self,
        chat_id: String,
        before_order_key: Option<String>,
        before_id: Option<String>,
        limit: u32,
    ) -> Result<Vec<LocalMessage>> {
        let before = before_order_key.as_deref().zip(before_id.as_deref());
        Ok(all(
            self.with(|s| s.messages_before(&chat_id, before, limit))?
        ))
    }
    pub fn messages_from(
        &self,
        chat_id: String,
        from_order_key: String,
        from_id: String,
        limit: u32,
    ) -> Result<Vec<LocalMessage>> {
        Ok(all(self.with(|s| {
            s.messages_from(&chat_id, (&from_order_key, &from_id), limit)
        })?))
    }
    pub fn pending_sends(
        &self,
        chat_id: Option<String>,
        retry_ceiling: i16,
        limit: u32,
    ) -> Result<Vec<LocalMessage>> {
        Ok(all(self.with(|s| {
            s.pending_sends(chat_id.as_deref(), retry_ceiling, limit)
        })?))
    }
    pub fn message_count(&self) -> Result<u64> {
        self.with(|s| s.message_count())
    }
    pub fn all_messages_after(
        &self,
        after_order_key: Option<String>,
        after_id: Option<String>,
        limit: u32,
    ) -> Result<Vec<LocalMessage>> {
        let after = after_order_key.as_deref().zip(after_id.as_deref());
        Ok(all(self.with(|s| s.all_messages_after(after, limit))?))
    }
    pub fn delete_message(&self, id: String) -> Result<()> {
        self.with(|s| s.delete_message(&id))
    }
    pub fn search(&self, query: String, limit: u32) -> Result<Vec<LocalSearchHit>> {
        Ok(all(self.with(|s| s.search(&query, limit))?))
    }

    pub fn upsert_reaction(&self, reaction: LocalReaction) -> Result<()> {
        self.with(|s| s.upsert_reaction(&reaction.into()))
    }
    pub fn reactions(&self, target_message_id: String) -> Result<Vec<LocalReaction>> {
        Ok(all(self.with(|s| s.reactions(&target_message_id))?))
    }
    pub fn delete_reaction(
        &self,
        target_message_id: String,
        reactor_user_id: String,
    ) -> Result<()> {
        self.with(|s| s.delete_reaction(&target_message_id, &reactor_user_id))
    }

    pub fn all_reactions(&self) -> Result<Vec<LocalReaction>> {
        Ok(all(self.with(|s| s.all_reactions())?))
    }
    pub fn expire_reactions(&self, cutoff: i64) -> Result<u32> {
        self.with(|s| s.expire_reactions(cutoff))
    }

    pub fn upsert_call(&self, call: LocalCall) -> Result<()> {
        self.with(|s| s.upsert_call(&call.into()))
    }
    pub fn calls(&self, limit: u32) -> Result<Vec<LocalCall>> {
        Ok(all(self.with(|s| s.calls(limit))?))
    }

    pub fn record_peer_device(&self, device: LocalPeerDevice) -> Result<LocalInsert> {
        Ok(self.with(|s| s.record_peer_device(&device.into()))?.into())
    }
    pub fn peer_devices(&self, account_id: String) -> Result<Vec<LocalPeerDevice>> {
        Ok(all(self.with(|s| s.peer_devices(&account_id))?))
    }
    pub fn peer_device(&self, device_id: String) -> Result<Option<LocalPeerDevice>> {
        Ok(self.with(|s| s.peer_device(&device_id))?.map(Into::into))
    }
    pub fn all_peer_devices(&self) -> Result<Vec<LocalPeerDevice>> {
        Ok(all(self.with(|s| s.all_peer_devices())?))
    }
    pub fn retain_peer_devices(
        &self,
        account_id: String,
        active: Vec<String>,
    ) -> Result<Vec<String>> {
        self.with(|s| s.retain_peer_devices(&account_id, &active))
    }

    pub fn record_server_message_id(
        &self,
        server_id: String,
        local_id: String,
        recorded_at: i64,
    ) -> Result<()> {
        self.with(|s| s.record_server_message_id(&server_id, &local_id, recorded_at))
    }
    pub fn local_message_id(&self, server_id: String) -> Result<Option<String>> {
        self.with(|s| s.local_message_id(&server_id))
    }
    pub fn forget_server_message_ids_before(&self, cutoff: i64) -> Result<u64> {
        self.with(|s| s.forget_server_message_ids_before(cutoff))
    }

    pub fn put(&self, key: String, value: Vec<u8>) -> Result<()> {
        self.with(|s| s.put(&key, &value))
    }
    pub fn get(&self, key: String) -> Result<Option<Vec<u8>>> {
        self.with(|s| s.get(&key))
    }
    pub fn remove(&self, key: String) -> Result<()> {
        self.with(|s| s.remove(&key))
    }
}
