//! obfs4 handshake: client and server state machines.
//!
//! See obfs4 spec §4 for full protocol details.

pub mod client;
pub mod server;

use std::time::Duration;

use crate::crypto::kdf::SessionKeys;

// ── Handshake Constants (obfs4 spec §4) ─────────────────────────────────────

/// Default handshake timeout. Prevents DPI probers from holding connections
/// open indefinitely and distinguishing the server from normal HTTPS.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum total size of a handshake request or response, including padding.
pub const MAX_HANDSHAKE_LENGTH: usize = 8192;

/// Length of the HMAC-SHA256-128 mark (M_C / M_S).
pub const MARK_LEN: usize = 16;

/// Length of the HMAC-SHA256-128 MAC (MAC_C / MAC_S).
pub const MAC_LEN: usize = 16;

/// Size of an Elligator2 representative on the wire.
pub const REPR_LEN: usize = 32;

/// Length of the ntor AUTH tag.
pub const AUTH_LEN: usize = 32;

/// Non-padding data in a client handshake: repr + mark + mac.
pub const CLIENT_HANDSHAKE_LEN: usize = REPR_LEN + MARK_LEN + MAC_LEN; // 64

/// Non-padding data in a server handshake: repr + auth + mark + mac.
pub const SERVER_HANDSHAKE_LEN: usize = REPR_LEN + AUTH_LEN + MARK_LEN + MAC_LEN; // 96

/// Length of a TYPE_PRNG_SEED frame (unpadded): header(2) + tag(16) + type(1) + payload_len(2) + seed(24).
pub const INLINE_SEED_FRAME_LEN: usize = 45;

/// Minimum client padding so that smallest request equals smallest response.
/// (SERVER_HANDSHAKE_LEN + INLINE_SEED_FRAME_LEN) - CLIENT_HANDSHAKE_LEN = 77
/// But spec says 85 — matches "ServerMinPadLength = InlineSeedFrameLength" variant.
pub const CLIENT_MIN_PAD: usize = 85;

/// Maximum client padding.
pub const CLIENT_MAX_PAD: usize = MAX_HANDSHAKE_LENGTH - CLIENT_HANDSHAKE_LEN; // 8128

/// Minimum server padding (0 if using inline seed frame optimization).
pub const SERVER_MIN_PAD: usize = 0;

/// Maximum server padding.
pub const SERVER_MAX_PAD: usize = MAX_HANDSHAKE_LENGTH - SERVER_HANDSHAKE_LEN; // 8096

/// Result of a completed handshake — session keys ready for framing.
pub(crate) struct HandshakeResult {
    pub session_keys: SessionKeys,
    /// Trailing bytes received after the handshake MAC (e.g. inline PRNG seed frame).
    /// Empty if no excess data was buffered.
    pub trailing: Vec<u8>,
}
