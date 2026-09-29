//! The device's Ed25519 and X25519 secrets do not cross the FFI.
//!
//! A platform asks the core for the operation — `sign_with_device_key`, `open_sealed_to_device`,
//! `device_copy_tag`, `new_mls_store`, `history_file_channel_key`, `seal_own_recovery_bundle` —
//! never for the key. Until 2026-09-29 the UDL exported the keys themselves
//! (`get_signing_key_bytes`, `get_identity_key_bytes`, `signing_key_from_keys`, …) and eight
//! functions that took them back as arguments, and both platforms used them: iOS kept raw
//! Keychain copies of both keys and a second, CryptoKit implementation of the sealed box.
//!
//! This reads the UDL rather than the Rust because the UDL is the boundary; a Rust function the
//! UDL does not name is not reachable from Swift or Kotlin.

/// Names that give a device secret out, or take one in. Checked as whole identifiers.
const FORBIDDEN: &[&str] = &[
    // getters
    "get_signing_key_bytes",
    "get_identity_key_bytes",
    "signing_key_from_keys",
    "identity_key_from_keys",
    // arguments / fields carrying a device secret
    "identity_secret_key",
    "our_identity_priv",
    "our_identity_private",
    "signer_private_key",
    "device_signing_key",
    "device_identity_key",
];

#[test]
fn no_device_secret_crosses_the_udl() {
    let udl = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/construct_core.udl"
    ))
    .expect("read the UDL");

    let hits: Vec<(usize, &str, &str)> = udl
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .flat_map(|(i, line)| {
            line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|word| FORBIDDEN.contains(word))
                .map(move |word| (i + 1, word, line.trim()))
        })
        .collect();

    assert!(
        hits.is_empty(),
        "ask the core for the operation, not for the device key: {hits:?}"
    );
}
