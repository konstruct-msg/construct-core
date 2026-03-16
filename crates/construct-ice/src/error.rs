use thiserror::Error;

/// All errors produced by construct-ice.
#[derive(Debug, Error)]
pub enum Error {
    // ── Handshake ───────────────────────────────────────────────────────────
    /// The handshake did not complete within the allowed time.
    #[error("handshake timeout")]
    HandshakeTimeout,

    /// The server's public key is malformed or invalid.
    #[error("invalid server public key: {0}")]
    InvalidServerPublicKey(String),

    /// HMAC verification failed during the handshake mark/MAC check.
    #[error("handshake HMAC verification failed")]
    HandshakeMacMismatch,

    /// The server rejected the handshake (e.g. closed the connection).
    #[error("server rejected handshake")]
    HandshakeRejected,

    /// The ntor AUTH tag does not match — possible MITM attack.
    #[error("ntor AUTH tag verification failed — possible MITM")]
    NtorAuthMismatch,

    /// Clock skew between client and server exceeds the allowed tolerance.
    #[error("clock skew too large between client and server")]
    ClockSkew,

    /// The provided node ID is malformed.
    #[error("invalid node ID: {0}")]
    InvalidNodeId(String),

    /// The bridge line / cert string could not be parsed.
    #[error("invalid bridge line: {0}")]
    InvalidBridgeLine(String),

    // ── Elligator2 ──────────────────────────────────────────────────────────
    /// The Curve25519 point has no Elligator2 representative (~50% of keys).
    #[error("point has no Elligator2 representative (retry required)")]
    NoElligatorRepresentative,

    // ── Framing ─────────────────────────────────────────────────────────────
    /// Frame decryption / MAC verification failed — data may have been tampered with.
    #[error("frame MAC verification failed — possible tampering")]
    FrameMacMismatch,

    /// A frame exceeds the maximum allowed size.
    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge {
        /// Actual frame size in bytes.
        size: usize,
        /// Maximum allowed frame size.
        max: usize,
    },

    /// The stream ended before a complete message could be read.
    #[error("unexpected end of stream")]
    UnexpectedEof,

    // ── Key derivation ───────────────────────────────────────────────────────
    /// HKDF expansion failed (should never happen with valid inputs).
    #[error("HKDF expand failed")]
    KdfError,

    // ── Nonce ────────────────────────────────────────────────────────────────
    /// The nonce counter has been exhausted — connection must be reset.
    /// This would require sending ~2^64 frames (~18 exabytes), so it should
    /// never happen in practice. Returned instead of panicking.
    #[error("nonce counter exhausted — connection must be reset")]
    NonceExhausted,

    // ── I/O ─────────────────────────────────────────────────────────────────
    /// Underlying I/O error from the TCP stream.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
