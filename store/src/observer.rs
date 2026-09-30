/// What changed. Clients rebuild their observable models from these (SwiftUI `@Observable`,
/// Kotlin `Flow`, Tauri events, a TUI redraw) — the replacement for Core Data's
/// `@FetchRequest` and fetched-results controllers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    Contacts,
    Chats,
    Messages,
    Reactions,
    Calls,
    PeerDevices,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub table: Table,
    /// The rows written or deleted, by id (for reactions, the target message id).
    pub ids: Vec<String>,
}

/// Told after every committed write. Called on the writing thread, after the transaction —
/// never with the store's lock held, so an observer may read the store.
pub trait StoreObserver: Send + Sync {
    fn on_change(&self, change: Change);
}
