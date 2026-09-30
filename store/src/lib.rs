//! The local store every Construct client keeps.
//!
//! One schema, one set of queries, one full-text index, encrypted whole with SQLCipher — for iOS
//! and macOS and Android through the core's UniFFI surface, for the Tauri desktops and the TUI as
//! a plain dependency. Before this each client kept its own: Core Data on Apple, Room on Android,
//! `construct-tui/src/storage.rs`. Five clients would have meant five implementations of one
//! model, each drifting on its own (`construct-docs/decisions/local-store-in-the-core.md`).
//!
//! **Encryption.** SQLCipher 4: every page AES-256 with an HMAC-SHA512, so rows, indexes, the
//! full-text index and the journal are all ciphertext on disk. The key is 32 random bytes the
//! platform keeps in its key store (Keychain, Android Keystore, Secret Service, DPAPI) and passes
//! to [`Store::open`]; it is used raw, not stretched — it is already uniformly random.
//!
//! **I/O lives here, not in `construct-core`.** The core stays pure (its `AGENTS.md`: side
//! effects are the platform's). This crate is one of those platform-side effects, written once.
//!
//! **Times** are Unix milliseconds. **Ids** are the strings the clients already use: account
//! UUIDs for users and chats, message ids, 32-hex device ids for peer devices.

mod error;
mod migrations;
mod model;
mod observer;
mod store;

pub use error::StoreError;
pub use model::{
    CallRecord, Chat, Contact, DeliveryStatus, Message, PeerDevice, Reaction, SearchHit,
};
pub use observer::{Change, StoreObserver, Table};
pub use store::{Insert, Store};

/// Length of the store key, in bytes.
pub const KEY_LEN: usize = 32;
