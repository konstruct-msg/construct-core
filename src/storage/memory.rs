// In-memory storage для тестов и non-WASM платформ
//
// # Security note
// This implementation stores all data in plain heap memory protected only by
// the process address space.  It is intentionally designed for:
//   - Unit / integration tests
//   - Non-sensitive in-process caching layers
//
// Do NOT use MemoryStorage as the sole backing store for production key material.
// `StoredPrivateKeys` and `StoredSession` implement `Zeroize`, so their heap
// allocations are wiped on drop, but the data remains readable for the lifetime
// of the `Arc<Mutex<...>>` wrapper.  Platform storage (Keychain, Keystore,
// IndexedDB with encryption) must be used for all real deployments.

use crate::storage::models::*;
use crate::storage::traits::{AuthTokens, DataStorage, SecureStorage};
use crate::utils::error::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// In-memory хранилище (для тестов)
#[derive(Clone)]
pub struct MemoryStorage {
    // SecureStorage data
    auth_tokens: Arc<Mutex<Option<AuthTokens>>>,
    private_keys: Arc<Mutex<Option<StoredPrivateKeys>>>,
    sessions: Arc<Mutex<HashMap<String, StoredSession>>>,
    app_metadata: Arc<Mutex<Option<StoredAppMetadata>>>,

    // DataStorage data
    contacts: Arc<Mutex<HashMap<String, StoredContact>>>,
    messages: Arc<Mutex<Vec<StoredMessage>>>,
    conversations: Arc<Mutex<HashMap<String, Conversation>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            auth_tokens: Arc::new(Mutex::new(None)),
            private_keys: Arc::new(Mutex::new(None)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            app_metadata: Arc::new(Mutex::new(None)),
            contacts: Arc::new(Mutex::new(HashMap::new())),
            messages: Arc::new(Mutex::new(Vec::new())),
            conversations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return `limit` contact IDs sorted by `last_used` DESC (most recent first).
    ///
    /// Use this for LRU-prefetch at startup instead of loading all sessions.
    /// Platform storage implementations (Keychain, SQLite, IndexedDB) should
    /// apply the same ordering natively for efficiency.
    pub fn list_recent_sessions(&self, limit: usize) -> Vec<String> {
        let lock = self.sessions.lock().unwrap();
        let mut entries: Vec<(i64, String)> = lock
            .values()
            .map(|s| (s.last_used, s.contact_id.clone()))
            .collect();
        entries.sort_by(|a, b| b.0.cmp(&a.0));
        entries.into_iter().take(limit).map(|(_, id)| id).collect()
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SecureStorage Implementation
// ============================================================================

impl SecureStorage for MemoryStorage {
    async fn save_auth_tokens(&self, tokens: &AuthTokens) -> Result<()> {
        let mut lock = self.auth_tokens.lock().unwrap();
        *lock = Some(tokens.clone());
        Ok(())
    }

    async fn load_auth_tokens(&self) -> Result<Option<AuthTokens>> {
        let lock = self.auth_tokens.lock().unwrap();
        Ok(lock.clone())
    }

    async fn clear_auth_tokens(&self) -> Result<()> {
        let mut lock = self.auth_tokens.lock().unwrap();
        *lock = None;
        Ok(())
    }

    async fn save_private_keys(&self, keys: &StoredPrivateKeys) -> Result<()> {
        let mut lock = self.private_keys.lock().unwrap();
        *lock = Some(keys.clone());
        Ok(())
    }

    async fn load_private_keys(&self) -> Result<Option<StoredPrivateKeys>> {
        let lock = self.private_keys.lock().unwrap();
        Ok(lock.clone())
    }

    async fn clear_private_keys(&self) -> Result<()> {
        let mut lock = self.private_keys.lock().unwrap();
        *lock = None;
        Ok(())
    }

    async fn save_session(&self, contact_id: &str, session: &StoredSession) -> Result<()> {
        let mut lock = self.sessions.lock().unwrap();
        lock.insert(contact_id.to_string(), session.clone());
        Ok(())
    }

    async fn load_session(&self, contact_id: &str) -> Result<Option<StoredSession>> {
        let lock = self.sessions.lock().unwrap();
        Ok(lock.get(contact_id).cloned())
    }

    async fn delete_session(&self, contact_id: &str) -> Result<()> {
        let mut lock = self.sessions.lock().unwrap();
        lock.remove(contact_id);
        Ok(())
    }

    async fn list_sessions(&self) -> Result<Vec<String>> {
        let lock = self.sessions.lock().unwrap();
        Ok(lock.keys().cloned().collect())
    }

    async fn clear_all_sessions(&self) -> Result<()> {
        let mut lock = self.sessions.lock().unwrap();
        lock.clear();
        Ok(())
    }

    async fn save_app_metadata(&self, metadata: &StoredAppMetadata) -> Result<()> {
        let mut lock = self.app_metadata.lock().unwrap();
        *lock = Some(metadata.clone());
        Ok(())
    }

    async fn load_app_metadata(&self) -> Result<Option<StoredAppMetadata>> {
        let lock = self.app_metadata.lock().unwrap();
        Ok(lock.clone())
    }
}

// ============================================================================
// DataStorage Implementation
// ============================================================================

impl DataStorage for MemoryStorage {
    async fn save_message(&self, message: &StoredMessage) -> Result<()> {
        let mut lock = self.messages.lock().unwrap();
        lock.push(message.clone());
        Ok(())
    }

    async fn update_message_status(&self, message_id: &str, status: MessageStatus) -> Result<()> {
        let mut lock = self.messages.lock().unwrap();
        if let Some(msg) = lock.iter_mut().find(|m| m.id == message_id) {
            msg.status = status;
        }
        Ok(())
    }

    async fn load_messages(
        &self,
        conversation_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredMessage>> {
        let lock = self.messages.lock().unwrap();
        let mut messages: Vec<StoredMessage> = lock
            .iter()
            .filter(|m| m.conversation_id == conversation_id)
            .cloned()
            .collect();

        messages.sort_by_key(|m| m.timestamp);

        Ok(messages.into_iter().skip(offset).take(limit).collect())
    }

    async fn load_message(&self, message_id: &str) -> Result<Option<StoredMessage>> {
        let lock = self.messages.lock().unwrap();
        Ok(lock.iter().find(|m| m.id == message_id).cloned())
    }

    async fn delete_message(&self, message_id: &str) -> Result<()> {
        let mut lock = self.messages.lock().unwrap();
        lock.retain(|m| m.id != message_id);
        Ok(())
    }

    async fn delete_messages_in_conversation(&self, conversation_id: &str) -> Result<()> {
        let mut lock = self.messages.lock().unwrap();
        lock.retain(|m| m.conversation_id != conversation_id);
        Ok(())
    }

    async fn count_messages(&self, conversation_id: &str) -> Result<usize> {
        let lock = self.messages.lock().unwrap();
        Ok(lock
            .iter()
            .filter(|m| m.conversation_id == conversation_id)
            .count())
    }

    async fn save_contact(&self, contact: &StoredContact) -> Result<()> {
        let mut lock = self.contacts.lock().unwrap();
        lock.insert(contact.id.clone(), contact.clone());
        Ok(())
    }

    async fn load_contact(&self, contact_id: &str) -> Result<Option<StoredContact>> {
        let lock = self.contacts.lock().unwrap();
        Ok(lock.get(contact_id).cloned())
    }

    async fn load_contacts(&self) -> Result<Vec<StoredContact>> {
        let lock = self.contacts.lock().unwrap();
        Ok(lock.values().cloned().collect())
    }

    async fn update_contact_last_message(&self, contact_id: &str, timestamp: i64) -> Result<()> {
        let mut lock = self.contacts.lock().unwrap();
        if let Some(contact) = lock.get_mut(contact_id) {
            contact.last_message_at = Some(timestamp);
        }
        Ok(())
    }

    async fn delete_contact(&self, contact_id: &str) -> Result<()> {
        let mut lock = self.contacts.lock().unwrap();
        lock.remove(contact_id);
        Ok(())
    }

    async fn save_conversation(&self, conversation: &Conversation) -> Result<()> {
        let mut lock = self.conversations.lock().unwrap();
        lock.insert(conversation.id.clone(), conversation.clone());
        Ok(())
    }

    async fn load_conversation(&self, conversation_id: &str) -> Result<Option<Conversation>> {
        let lock = self.conversations.lock().unwrap();
        Ok(lock.get(conversation_id).cloned())
    }

    async fn load_conversations(&self) -> Result<Vec<Conversation>> {
        let lock = self.conversations.lock().unwrap();
        Ok(lock.values().cloned().collect())
    }

    async fn update_conversation_unread(&self, conversation_id: &str, count: u32) -> Result<()> {
        let mut lock = self.conversations.lock().unwrap();
        if let Some(conv) = lock.get_mut(conversation_id) {
            conv.unread_count = count;
        }
        Ok(())
    }

    async fn delete_conversation(&self, conversation_id: &str) -> Result<()> {
        let mut lock = self.conversations.lock().unwrap();
        lock.remove(conversation_id);
        Ok(())
    }

    async fn clear_all(&self) -> Result<()> {
        {
            let mut lock = self.messages.lock().unwrap();
            lock.clear();
        }
        {
            let mut lock = self.contacts.lock().unwrap();
            lock.clear();
        }
        {
            let mut lock = self.conversations.lock().unwrap();
            lock.clear();
        }
        Ok(())
    }
}

// Tests удалены - будут добавлены позже после финализации моделей
