//! Device key fingerprint shared by linking and history transfer.

use sha2::{Digest, Sha256};

/// What a link QR pins: `SHA256(identity_pub ‖ hybrid_pub)`.
/// The 32-byte fingerprint fits in the QR where the full hybrid public key would not.
pub fn qr_fingerprint(identity_public: &[u8], hybrid_public: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(identity_public)
        .chain_update(hybrid_public)
        .finalize()
        .into()
}
