//! The tag that says which device a copy is for, without saying it to anyone else.
//!
//! ## What it is for
//!
//! Delivery is per **account**, not per device: `messaging-service` writes the same envelope to
//! every one of the recipient's per-device streams. So when one message produces several
//! ciphertexts — one per target device — every device receives all of them and must recognise
//! which one is its own.
//!
//! Recognising a foreign copy has to be cheap, because the alternative is not a few wasted
//! decrypts: a copy with `message_number == 0` that opens under no session takes the recovery
//! path, which fetches a key bundle over the network and initialises a receiving session. On a
//! device's own echo that is session churn caused by a message it wrote itself.
//!
//! ## What it must not be
//!
//! Until 2026-08-17 the iOS tag was `device_id[0..8]` — the device id in plain hex, stable for the
//! life of the device. The relay, which routes every copy, could read which device each was for
//! and group an account's traffic by device. That is precisely the metadata the routing design
//! refused to add when it declined to put the *sender's* device on the wire.
//!
//! ## What it is
//!
//! A per-message value keyed by a secret only the two devices hold:
//!
//! ```text
//! secret = HKDF-SHA256(ikm = X25519(our identity private, peer identity public),
//!                      salt = "ConstructSSTAG-v1", info = "") → 32 bytes
//! tag    = HMAC-SHA256(secret, base_message_id ‖ 0x00 ‖ target_device_id)[0..8], lowercase hex
//! ```
//!
//! X25519 is symmetric in the pair, so the sender derives it against the target device's bundle
//! key and the receiver derives the same value against each candidate peer's bundle key. The relay
//! holds both public keys — it serves the bundles — and still cannot compute the secret, so the tag
//! is an unlinkable 16 hex characters that changes with every message.
//!
//! **The target device id is in the MAC input, and has to be.** The pair secret alone is symmetric:
//! A and B derive the same value, so a tag keyed on it says "this concerns A and B" and not which
//! of the two it is for. Delivery hands the sender its own copy back, so A would read its own echo
//! as addressed to itself and try to open a message it had just encrypted. Binding the target makes
//! the tag directional while leaving it opaque — the relay cannot compute either direction.
//!
//! ## Why the name is not `sender_sync`
//!
//! It arrived as the `-ss-` suffix on SENDER_SYNC copies, and the iOS type is still called
//! `SenderSyncDeviceTag`. The mechanism is not specific to that content type: any message
//! addressed to one device of a multi-device account needs it, which is every message once
//! sessions are addressed per device. Naming it after its first caller would have to be undone.
//!
//! ## Provenance
//!
//! Ported from `ConstructMessenger/Services/Messaging/SenderSyncDeviceTag.swift` (2026-08-25),
//! byte-compatible by construction — see the conformance vectors. The Swift original is the
//! second implementation this repository has had to keep in agreement by hand; this module exists
//! so there is not a third on Android.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::CryptoError;

type HmacSha256 = Hmac<Sha256>;

/// HKDF salt. Shared with no other use — a secret derived here must not open anything else.
const PAIR_SECRET_SALT: &[u8] = b"ConstructSSTAG-v1";

/// Bytes of MAC kept, before hex encoding.
const TAG_BYTES: usize = 8;

/// Hex characters in a tag: 16.
pub const TAG_HEX_LEN: usize = TAG_BYTES * 2;

/// Hex characters in the form this replaced (`device_id[0..8]`), still read from senders at or
/// below 0.18.0. The two forms are told apart by length alone, which is why the new one is not
/// also 8.
pub const LEGACY_TAG_HEX_LEN: usize = 8;

fn as_key32(bytes: &[u8], what: &str) -> Result<[u8; 32], CryptoError> {
    bytes.try_into().map_err(|_| {
        CryptoError::InvalidInputError(format!("{what} must be 32 bytes, got {}", bytes.len()))
    })
}

/// The secret shared by two devices.
///
/// Static-static X25519: no ephemeral, because both sides must derive the same value without
/// exchanging anything. That makes it stable for the lifetime of the two identity keys — which is
/// wanted here, since the per-message variation comes from the message id below, not the key.
///
/// Not exported across the FFI on purpose: a caller that holds the secret can be asked to keep it,
/// and derived key material with a lifetime is a thing to invalidate when a device is revoked. One
/// X25519 per call is ~50µs and an account has units of devices.
fn pair_secret(
    our_identity_private: &[u8],
    peer_identity_public: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let our_priv = StaticSecret::from(as_key32(our_identity_private, "identity private key")?);
    let peer_pub = PublicKey::from(as_key32(peer_identity_public, "peer identity public key")?);

    // No contributory-behaviour check, matching the Swift original and `sealed_sender`: a
    // low-order peer key yields an all-zero shared secret rather than an error. It costs nothing
    // here — a peer who supplies one can only make its own copies unrecognisable, and the tag is
    // an optimisation, not an authorisation.
    let shared = our_priv.diffie_hellman(&peer_pub);

    let hk = Hkdf::<Sha256>::new(Some(PAIR_SECRET_SALT), shared.as_bytes());
    let mut secret = [0u8; 32];
    hk.expand(&[], &mut secret)
        .expect("HKDF-SHA256 with 32-byte output always succeeds");
    Ok(secret)
}

/// The MAC input: `base_message_id ‖ 0x00 ‖ target_device_id`.
///
/// The NUL separator is unambiguous because neither a message id nor a device id contains one.
fn mac_input(base_message_id: &str, target_device_id: &str) -> Vec<u8> {
    let mut input = Vec::with_capacity(base_message_id.len() + 1 + target_device_id.len());
    input.extend_from_slice(base_message_id.as_bytes());
    input.push(0x00);
    input.extend_from_slice(target_device_id.as_bytes());
    input
}

/// The tag a copy for `target_device_id` travels under.
///
/// `base_message_id` is the id **without** any per-device or per-chunk suffix, so every chunk of
/// one message carries the same tag and the receiver can recompute it from whichever chunk it sees
/// first.
pub fn device_copy_tag(
    base_message_id: &str,
    target_device_id: &str,
    our_identity_private: &[u8],
    peer_identity_public: &[u8],
) -> Result<String, CryptoError> {
    let secret = pair_secret(our_identity_private, peer_identity_public)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&secret)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(&mac_input(base_message_id, target_device_id));
    Ok(hex::encode(&mac.finalize().into_bytes()[..TAG_BYTES]))
}

/// Whether `tag` was written **for `our_device_id`** by the device behind `peer_identity_public`.
///
/// Not constant-time on purpose: both operands are ours, a mismatch means only "this copy is for
/// another of my devices", and there is no remote party whose timing could learn anything.
///
/// Returns `false` rather than an error for a tag of the wrong length or unusable key material.
/// Every caller of this asks "is this copy foreign?", and the answer to an undecidable question
/// there must be "not foreign": wrongly opening a copy costs failed decrypts, wrongly discarding
/// one loses a message from the transcript, silently.
pub fn device_copy_tag_matches(
    tag: &str,
    base_message_id: &str,
    our_device_id: &str,
    our_identity_private: &[u8],
    peer_identity_public: &[u8],
) -> bool {
    // No length pre-check. It was written and removed the same hour: the comparison below already
    // rejects every wrong-length tag, since the expected value is always TAG_HEX_LEN characters,
    // so the guard had no outcome a test could reach — removing it left all nine tests green. A
    // guard that cannot fail is the defect class this repository keeps paying for, in miniature.
    match device_copy_tag(
        base_message_id,
        our_device_id,
        our_identity_private,
        peer_identity_public,
    ) {
        Ok(expected) => expected == tag,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic keypair from a seed, so vectors are reproducible.
    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::from([seed; 32]);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    #[test]
    fn pair_secret_is_symmetric() {
        let (a_priv, a_pub) = keypair(1);
        let (b_priv, b_pub) = keypair(2);
        assert_eq!(
            pair_secret(&a_priv, &b_pub).unwrap(),
            pair_secret(&b_priv, &a_pub).unwrap()
        );
    }

    #[test]
    fn tag_is_sixteen_hex_characters() {
        let (a_priv, _) = keypair(1);
        let (_, b_pub) = keypair(2);
        let tag = device_copy_tag("msg", "device-b", &a_priv, &b_pub).unwrap();
        assert_eq!(tag.len(), TAG_HEX_LEN);
        assert!(
            tag.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn tag_differs_per_message() {
        let (a_priv, _) = keypair(1);
        let (_, b_pub) = keypair(2);
        let one = device_copy_tag("msg-1", "device-b", &a_priv, &b_pub).unwrap();
        let two = device_copy_tag("msg-2", "device-b", &a_priv, &b_pub).unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn tag_is_directional() {
        // The pair secret alone is symmetric, so without the target in the MAC input a device
        // would read its own echo as addressed to itself.
        let (a_priv, _) = keypair(1);
        let (_, b_pub) = keypair(2);
        let for_a = device_copy_tag("msg", "device-a", &a_priv, &b_pub).unwrap();
        let for_b = device_copy_tag("msg", "device-b", &a_priv, &b_pub).unwrap();
        assert_ne!(for_a, for_b);
    }

    #[test]
    fn a_copy_for_b_is_foreign_on_a_and_ours_on_b() {
        let (a_priv, a_pub) = keypair(1);
        let (b_priv, b_pub) = keypair(2);
        let tag = device_copy_tag("msg", "device-b", &a_priv, &b_pub).unwrap();

        assert!(device_copy_tag_matches(
            &tag, "msg", "device-b", &b_priv, &a_pub
        ));
        assert!(!device_copy_tag_matches(
            &tag, "msg", "device-a", &a_priv, &b_pub
        ));
    }

    #[test]
    fn tag_reveals_nothing_about_the_device_id() {
        let (a_priv, _) = keypair(1);
        let (_, b_pub) = keypair(2);
        let device = "6f5e37acb3ed60ab6f5e37acb3ed60ab";
        let tag = device_copy_tag("msg", device, &a_priv, &b_pub).unwrap();
        assert!(!device.contains(&tag));
        assert!(!tag.is_empty() && !device.starts_with(&tag));
    }

    #[test]
    fn a_wrong_length_tag_never_matches() {
        let (a_priv, a_pub) = keypair(1);
        let (b_priv, b_pub) = keypair(2);
        let tag = device_copy_tag("msg", "device-b", &a_priv, &b_pub).unwrap();
        let _ = b_pub;
        assert!(!device_copy_tag_matches(
            &tag[..8],
            "msg",
            "device-b",
            &b_priv,
            &a_pub
        ));
    }

    #[test]
    fn malformed_key_material_is_rejected_not_guessed() {
        let (_, b_pub) = keypair(2);
        assert!(device_copy_tag("msg", "device-b", &[0u8; 31], &b_pub).is_err());
        assert!(!device_copy_tag_matches(
            "0123456789abcdef",
            "msg",
            "device-b",
            &[0u8; 31],
            &b_pub
        ));
    }

    /// Pinned vectors — the contract with every other implementation.
    ///
    /// **These values were not taken from this code.** They were produced by the iOS CryptoKit
    /// implementation this module replaces (`SenderSyncDeviceTag.swift`) and then asserted here,
    /// which is what makes the port verified rather than claimed. A test that pinned this
    /// module's own output would agree with itself no matter what it computed.
    ///
    /// Mirrored in `construct-protos/conformance/knst_device_copy_tag.json` so Swift and Kotlin
    /// assert against the same bytes. Changing any value here is a wire change: every client must
    /// land it in the same release.
    #[test]
    fn pinned_vectors() {
        let (a_priv, a_pub) = keypair(1);
        let (b_priv, b_pub) = keypair(2);

        assert_eq!(
            hex::encode(a_pub),
            "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"
        );
        assert_eq!(
            hex::encode(b_pub),
            "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59"
        );

        const PAIR_SECRET: &str =
            "7af783d487a32aa296b82c9198ca34a848a3ae2cf9323389d968e65d1ab99e45";
        assert_eq!(
            hex::encode(pair_secret(&a_priv, &b_pub).unwrap()),
            PAIR_SECRET
        );
        assert_eq!(
            hex::encode(pair_secret(&b_priv, &a_pub).unwrap()),
            PAIR_SECRET,
            "symmetry is part of the contract, not an implementation detail"
        );

        assert_eq!(
            device_copy_tag(
                "1aa6abac-0000-4000-8000-000000000001",
                "6f5e37acb3ed60ab6f5e37acb3ed60ab",
                &a_priv,
                &b_pub,
            )
            .unwrap(),
            "13819e444aa59d15"
        );
    }
}
