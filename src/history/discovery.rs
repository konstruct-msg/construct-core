//! The two values two devices must compute alike before any byte of history moves: the name the
//! new device is advertised under on the local network, and the fingerprint the link QR pins.

use sha2::{Digest, Sha256};

/// `hex(SHA256("cth1:" ‖ dashed account UUID ‖ 32-hex device id)[0..16])`. The preimage is frozen
/// (spec K13): no colon between the two ids — the UUID is 36 characters and the device id 32, so
/// the concatenation is unambiguous. Scope, not an authenticator.
pub fn discovery_tag(user_id_dashed: &str, new_device_id_hex: &str) -> String {
    let digest = Sha256::new()
        .chain_update(b"cth1:")
        .chain_update(user_id_dashed.as_bytes())
        .chain_update(new_device_id_hex.as_bytes())
        .finalize();
    hex::encode(&digest[..16])
}

/// The Bonjour instance name for a tag: `hex(SHA256("ctt1_instance:" ‖ tag)[0..16])`.
pub fn discovery_instance_name(tag: &str) -> String {
    let digest = Sha256::new()
        .chain_update(b"ctt1_instance:")
        .chain_update(tag.as_bytes())
        .finalize();
    hex::encode(&digest[..16])
}

/// What a Flow A link QR carries for the offering device: `SHA256(identity_pub ‖ hybrid_pub)`,
/// 32 bytes — a 1984-byte hybrid key does not fit a scannable code.
pub fn qr_fingerprint(identity_public: &[u8], hybrid_public: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(identity_public)
        .chain_update(hybrid_public)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::vectors;

    #[test]
    fn the_discovery_tag_and_instance_name_are_the_vectors() {
        let v = vectors::named("discovery_tag");
        let preimage = v["preimage_utf8"].as_str().unwrap();
        let rest = preimage.strip_prefix("cth1:").unwrap();
        let (user, device) = rest.split_at(36);
        let tag = discovery_tag(user, device);
        assert_eq!(tag, v["tag"].as_str().unwrap());
        assert_eq!(
            discovery_instance_name(&tag),
            v["instance_name"].as_str().unwrap()
        );
    }

    #[test]
    fn the_qr_fingerprint_is_the_vector() {
        let v = vectors::named("qr_fp");
        let preimage = vectors::hex_field(&v, "preimage");
        let (identity, hybrid) = preimage.split_at(32);
        assert_eq!(
            hex::encode(qr_fingerprint(identity, hybrid)),
            v["fp"].as_str().unwrap()
        );
    }
}
