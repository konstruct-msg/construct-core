use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    /// The key does not open this database — or the file is not a database. SQLCipher cannot tell
    /// the two apart, and neither can this; the caller must not treat it as "empty".
    #[error("the key does not open this store")]
    WrongKey,
    #[error("store key must be {expected} bytes, got {got}")]
    KeyLength { expected: usize, got: usize },
    /// A store written by a newer build: opening it with an older schema would lose data.
    #[error("store schema {found} is newer than this build's {supported}")]
    SchemaTooNew { found: i64, supported: i64 },
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;
