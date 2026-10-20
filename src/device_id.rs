// Device ID generation from identity public key
// Deterministic, collision-resistant identifier for device-based authentication

use sha2::{Digest, Sha256};

/// Derive a unique device ID from an identity public key
///
/// # Arguments
/// * `identity_public_key` - Ed25519 public key (32 bytes)
///
/// # Returns
/// * Hex-encoded device ID (32 characters = 16 bytes)
///
/// # Algorithm
/// ```text
/// device_id = hex(SHA256(identity_public_key)[0..16])
/// ```
///
/// # Properties
/// - Deterministic: Same key always produces same device_id
/// - Collision-resistant: SHA256 provides 128-bit security
/// - Compact: 32 hex characters (vs 44 for base64)
/// - URL-safe: Only [0-9a-f] characters
///
/// # Example
/// ```
/// use construct_core::device_id::derive_device_id;
/// let public_key = [0u8; 32]; // Ed25519 public key
/// let device_id = derive_device_id(&public_key);
/// assert_eq!(device_id.len(), 32); // 16 bytes * 2 hex chars
/// ```
pub fn derive_device_id(identity_public_key: &[u8]) -> String {
    // Encode as lowercase hex (32 characters)
    hex::encode(derive_device_id_bytes(identity_public_key))
}

/// The 16 raw bytes behind `derive_device_id`: `SHA256(identity_public)[0..16]`. 128 bits is
/// enough — 2^64 devices for a 50 % collision chance — and it is what the history-transfer
/// frames carry in binary.
pub fn derive_device_id_bytes(identity_public_key: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(identity_public_key);
    let hash = hasher.finalize();
    hash[0..16].try_into().expect("16 of 32 bytes")
}

/// Format device ID for federated identifier
///
/// # Arguments
/// * `device_id` - Raw device ID (32 hex characters)
/// * `server_hostname` - Server hostname (e.g., "ams.konstruct.cc")
///
/// # Returns
/// * Federated identifier: `device_id@server_hostname`
///
/// # Example
/// ```
/// use construct_core::device_id::format_federated_id;
/// let device_id = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
/// let hostname = "ams.konstruct.cc";
/// let federated = format_federated_id(&device_id, hostname);
/// assert_eq!(federated, "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6@ams.konstruct.cc");
/// ```
pub fn format_federated_id(device_id: &str, server_hostname: &str) -> String {
    format!("{}@{}", device_id, server_hostname)
}

/// Parse federated identifier into components
///
/// # Arguments
/// * `federated_id` - Full federated ID (e.g., "device_id@hostname")
///
/// # Returns
/// * `Some((device_id, hostname))` if valid format
/// * `None` if invalid (no @ separator)
///
/// # Example
/// ```
/// use construct_core::device_id::parse_federated_id;
/// let result = parse_federated_id("abc123@server.com");
/// assert_eq!(result, Some(("abc123".to_string(), "server.com".to_string())));
/// ```
pub fn parse_federated_id(federated_id: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = federated_id.split('@').collect();

    if parts.len() != 2 {
        return None;
    }

    Some((parts[0].to_string(), parts[1].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hex_id_is_the_raw_bytes_encoded() {
        let pk = [0x5au8; 32];
        assert_eq!(
            derive_device_id(&pk),
            hex::encode(derive_device_id_bytes(&pk))
        );
    }

    #[test]
    fn test_derive_device_id_deterministic() {
        let public_key = [42u8; 32]; // Arbitrary test key

        let device_id1 = derive_device_id(&public_key);
        let device_id2 = derive_device_id(&public_key);

        // Same key should produce same device_id
        assert_eq!(device_id1, device_id2);
    }

    #[test]
    fn test_derive_device_id_format() {
        let public_key = [0u8; 32];
        let device_id = derive_device_id(&public_key);

        // Should be 32 hex characters (16 bytes * 2)
        assert_eq!(device_id.len(), 32);

        // Should only contain hex characters
        assert!(device_id.chars().all(|c| c.is_ascii_hexdigit()));

        // Should be lowercase
        assert_eq!(device_id, device_id.to_lowercase());
    }

    #[test]
    fn test_derive_device_id_different_keys() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let id1 = derive_device_id(&key1);
        let id2 = derive_device_id(&key2);

        // Different keys should produce different device_ids
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_derive_device_id_known_value() {
        // Test with known SHA256 output for all zeros
        // SHA256(32 zeros) = 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
        // First 16 bytes: 66687aadf862bd776c8fc18b8e9f8e20

        let public_key = [0u8; 32];
        let device_id = derive_device_id(&public_key);

        assert_eq!(device_id, "66687aadf862bd776c8fc18b8e9f8e20");
    }

    #[test]
    fn test_format_federated_id() {
        let device_id = "abc123def456";
        let hostname = "ams.konstruct.cc";

        let federated = format_federated_id(device_id, hostname);

        assert_eq!(federated, "abc123def456@ams.konstruct.cc");
    }

    #[test]
    fn test_parse_federated_id_valid() {
        let federated = "device123@server.example.com";

        let result = parse_federated_id(federated);

        assert_eq!(
            result,
            Some(("device123".to_string(), "server.example.com".to_string()))
        );
    }

    #[test]
    fn test_parse_federated_id_invalid() {
        // No @ separator
        assert_eq!(parse_federated_id("device123"), None);

        // Multiple @ separators
        assert_eq!(parse_federated_id("device@host@extra"), None);

        // Empty string
        assert_eq!(parse_federated_id(""), None);
    }

    #[test]
    fn test_roundtrip_federated_id() {
        let device_id = "abc123def456";
        let hostname = "ams.konstruct.cc";

        let federated = format_federated_id(device_id, hostname);
        let (parsed_id, parsed_host) = parse_federated_id(&federated).unwrap();

        assert_eq!(parsed_id, device_id);
        assert_eq!(parsed_host, hostname);
    }
}
