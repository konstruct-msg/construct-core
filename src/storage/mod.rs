// Storage models — the shapes `master_key` persists. Where they are stored is the platform's
// business (see `Action::SaveToSecureStore`); the storage traits and in-memory store that used
// to sit here had no implementor and no caller, and were removed.

pub mod models;

pub use models::*;
