/// Errors that can occur during MLS group operations.
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// Cryptographic operation failed (wrong key, corrupted data, etc.)
    #[error("MLS crypto error: {0}")]
    CryptoError(String),

    /// The local epoch is behind the server; pull commits via FetchCommits.
    #[error("epoch mismatch — pull pending commits first")]
    EpochMismatch,

    /// The caller is not a member of this group.
    #[error("not a member of this group")]
    NotAMember,

    /// The group state could not be serialized or deserialized.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// The Welcome message could not be processed (invalid, expired, or wrong keys).
    #[error("welcome error: {0}")]
    WelcomeError(String),

    /// A commit could not be applied (stale epoch, invalid signature, etc.).
    #[error("commit error: {0}")]
    CommitError(String),

    /// Message encryption or decryption failed.
    #[error("encryption/decryption error: {0}")]
    EncryptionError(String),
}

// UniFFI requires Error enums to impl std::error::Error + Send + Sync.
// thiserror derives Error automatically.
