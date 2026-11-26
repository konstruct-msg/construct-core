//! Fixed limits shared by the prekey and Double Ratchet paths. No runtime configuration.

/// ChaCha20-Poly1305 nonce length used by the Double Ratchet (bytes).
pub(crate) const CHACHA_NONCE_LENGTH: usize = 12;

/// Maximum skipped keys held per session, separately for the classical and PQ chains.
pub(crate) const MAX_SKIPPED_MESSAGES: u32 = 1_000;

/// Maximum number of chain steps a single decrypt may skip.
pub(crate) const MAX_MESSAGE_JUMP: u32 = 2_000;

/// When a skipped message key is too old to keep.
pub(crate) const MAX_SKIPPED_MESSAGE_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;

/// How many DH ratchet turns trigger a fresh sparse PQ exchange.
pub(crate) const PQ_RATCHET_INTERVAL: u32 = 16;

/// When the initiator proposes a new PQ epoch even without enough DH turns (PQR-1).
pub(crate) const PQ_RATCHET_MAX_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Age beyond which a peer's signed prekey is stale.
///
/// 30 days is about four client rotation cycles. For classic bundles this separates a clean
/// open from the degraded path (see `stale-peer-reachability`); it does not bypass signature
/// verification. Kyber prekeys have a signed age and do not get the degraded override.
pub const SPK_MAX_AGE_SECS: u64 = 30 * 24 * 3600;

/// How long a rotated-out signed prekey — classic or Kyber — is kept for first messages still in
/// flight to it: the server's queue TTL (7 days) plus as much again. One constant for both, so the
/// two cannot drift apart. Counted from rotation, not creation: a key rotated out on day 30 of its
/// life still has its full window.
pub const SPK_RETENTION_AFTER_ROTATION_SECS: u64 = 14 * 24 * 3600;

/// How long the server keeps an undelivered message: construct-server `MESSAGE_TTL_DAYS` (7, the
/// default and the production value, checked 2026-10-01). Changing it there means re-checking the
/// inequality below.
pub const QUEUE_TTL_SECS: u64 = 7 * 24 * 3600;

/// The oldest unanswered handshake an initiator still writes first flights on. Past it the session
/// is retired and the next send opens a new one from a fresh bundle
/// (construct-docs `decisions/first-flight-sealed-whole.md`).
///
/// Since construct-core 0.27 a first flight is sealed under its handshake's ML-KEM secret, so a
/// recipient that no longer holds the prekey cannot tell who wrote it and cannot answer. The prekey
/// a handshake used is held at least `SPK_RETENTION_AFTER_ROTATION_SECS` from the moment its bundle
/// was served; a first flight written at the handshake's age `a` may wait `QUEUE_TTL_SECS` in the
/// queue. Every first flight opens while `a + queue ≤ retention`.
pub const MAX_UNANSWERED_HANDSHAKE_AGE_SECS: u64 = 7 * 24 * 3600;

const _: () = assert!(
    MAX_UNANSWERED_HANDSHAKE_AGE_SECS + QUEUE_TTL_SECS <= SPK_RETENTION_AFTER_ROTATION_SECS,
    "a first flight could outlive the prekey it was sealed to"
);
