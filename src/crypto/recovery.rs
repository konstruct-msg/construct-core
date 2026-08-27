//! Account recovery: BIP39 mnemonics + SLIP-0010 Ed25519 HD key derivation.
//!
//! # API (matches ACCOUNT_RECOVERY_CLIENT_SPEC.md v1.1)
//!
//! ```text
//! generate_mnemonic(word_count)          → mnemonic string
//! validate_mnemonic(mnemonic)            → bool
//! mnemonic_to_seed(mnemonic)             → [u8; 64]
//! derive_recovery_keypair(seed)          → RecoveryKeypair
//! sign_recovery_challenge(key, message)  → [u8; 64]
//! verify_recovery_signature(key, msg, sig) → bool
//! ```
//!
//! # Derivation path
//! Spec says `m/44'/0'/0'/0/0` (BIP44). For Ed25519, SLIP-0010 requires
//! ALL indices to be hardened (non-hardened child derivation is undefined).
//! We use `m/44'/0'/0'/0'/0'` and the server must match this convention.

use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::utils::error::{ConstructError, Result};

// ── Public types ──────────────────────────────────────────────────────────────

/// Ed25519 keypair derived from a recovery seed.
#[derive(Clone)]
pub struct RecoveryKeypair {
    /// 32-byte Ed25519 private key — keep in memory only, never persist.
    pub private_key: [u8; 32],
    /// 32-byte Ed25519 public key — sent to server in SetRecoveryKey.
    pub public_key: [u8; 32],
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a BIP39 mnemonic with the given word count (12 or 24).
pub fn generate_mnemonic(word_count: u8) -> Result<String> {
    let mnemonic = Mnemonic::generate(word_count as usize)
        .map_err(|e| ConstructError::InternalError(format!("BIP39 generate failed: {e}")))?;
    Ok(mnemonic.to_string())
}

/// Validate BIP39 checksum and word membership.
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    mnemonic.parse::<Mnemonic>().is_ok()
}

/// Convert a BIP39 mnemonic to a 64-byte seed via PBKDF2-HMAC-SHA512
/// (2048 rounds, no passphrase). This is the BIP39 standard derivation.
pub fn mnemonic_to_seed(mnemonic: &str) -> Result<[u8; 64]> {
    let m: Mnemonic = mnemonic
        .parse()
        .map_err(|e| ConstructError::InternalError(format!("Invalid mnemonic: {e}")))?;
    Ok(m.to_seed(""))
}

/// Derive an Ed25519 recovery keypair from a 64-byte BIP39 seed.
///
/// Derivation: SLIP-0010, path m/44'/0'/0'/0'/0' (all hardened — required for Ed25519).
pub fn derive_recovery_keypair(seed: &[u8]) -> Result<RecoveryKeypair> {
    if seed.len() < 16 {
        return Err(ConstructError::InternalError(format!(
            "Seed too short: {} bytes (need ≥ 16)",
            seed.len()
        )));
    }

    // SLIP-0010 master key from seed
    let (mut key, mut chain) = slip10_master_key(seed);

    // m/44'/0'/0'/0'/0' — all five components hardened
    for index in [44u32, 0, 0, 0, 0] {
        let (k, c) = slip10_hardened_child(&key, &chain, index);
        key = k;
        chain = c;
    }

    let signing_key = SigningKey::from_bytes(&key);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    Ok(RecoveryKeypair {
        private_key: key,
        public_key: verifying_key.to_bytes(),
    })
}

/// Sign a message string with a 32-byte Ed25519 private key.
/// Returns a 64-byte detached signature.
pub fn sign_recovery_challenge(private_key: &[u8; 32], message: &str) -> Result<[u8; 64]> {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature: Signature = signing_key.sign(message.as_bytes());
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature over a message using a 32-byte public key.
pub fn verify_recovery_signature(
    public_key: &[u8; 32],
    message: &str,
    signature: &[u8; 64],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(message.as_bytes(), &sig).is_ok()
}

/// Compute a short fingerprint of a public key for UI display.
/// Format: first 8 bytes of SHA-256(pubkey) as "A1B2 C3D4 E5F6 G7H8".
pub fn compute_key_fingerprint(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    hash[..8]
        .chunks(2)
        .map(|pair| format!("{:02X}{:02X}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Compute a Safety Number for two Construct devices, or `None` when either id cannot be read.
///
/// Both parties derive the same 60-digit string from their device IDs.
/// Device IDs are cryptographic commitments to identity keys (HKDF of Ed25519 pubkey),
/// so substituting a MITM key changes the Safety Number.
///
/// Algorithm:
/// 1. Canonicalize: sort device IDs lexicographically so both sides get the same order.
/// 2. Iterative SHA-512: 1024 rounds of hash(prev_hash || input) — hardens brute-force.
/// 3. Format: first 24 bytes → 12 groups of 5 decimal digits, zero-padded. Each group is a
///    big-endian u16, so the range that actually occurs is **00000–65535** — the leading digit is
///    never 7, 8 or 9. The number carries 192 bits, not the ~199 that twelve free 0–99999 groups
///    would suggest.
///
/// Display format: "12345 67890 11111 22222 ..."
///
/// # Why this is fallible
///
/// It returned `String` until 2026-08-27, decoding with `hex::decode(..).unwrap_or_default()` —
/// which turns "I could not read this id" into "the id is empty", and an empty id is a *valid*
/// input that yields a real-looking 60-digit number. So `"abc"`, `"zzzz"` and `""` all produced
/// **the same** safety number against a given peer.
///
/// That is a verification bypass, not a formatting wart: two people whose ids failed to decode
/// would be shown matching numbers and would conclude the session is verified. This value exists
/// for exactly one purpose — to differ when a key was substituted — so any input it cannot read
/// must produce no number at all. A safety number that means "something went wrong" and a safety
/// number that means "you are talking to who you think" must not be the same string.
///
/// Not reachable from iOS today (`derive_device_id` always yields 32 valid hex chars), but this is
/// exported over UniFFI and takes whatever the caller passes, and it is now the only
/// implementation.
pub fn compute_safety_number(my_device_id: &str, their_device_id: &str) -> Option<String> {
    // Empty is rejected too. It decodes fine, which is the trap: it is the value an unreadable id
    // used to collapse into, and two devices that both supplied nothing would match each other.
    if my_device_id.is_empty() || their_device_id.is_empty() {
        return None;
    }
    let my_bytes = hex::decode(my_device_id).ok()?;
    let their_bytes = hex::decode(their_device_id).ok()?;

    let (first, second) = if my_device_id < their_device_id {
        (my_bytes.as_slice(), their_bytes.as_slice())
    } else {
        (their_bytes.as_slice(), my_bytes.as_slice())
    };

    let mut input = Vec::with_capacity(first.len() + second.len());
    input.extend_from_slice(first);
    input.extend_from_slice(second);

    let mut hash = Sha512::digest(&input).to_vec();
    for _ in 1..1024 {
        let mut h = Sha512::new();
        h.update(&hash);
        h.update(&input);
        hash = h.finalize().to_vec();
    }

    // `% 100_000` is **inert today** and is kept as a width guard, not as a reduction: a
    // big-endian u16 is at most 65535, so the modulus never fires and the displayed range is
    // 00000–65535, not 00000–99999 as the doc above used to imply. It earns its place only
    // against a future `chunks(3)`, where it is what keeps `{:05}` from printing six digits and
    // breaking the 71-character format every client parses.
    //
    // Found by mutation on 2026-08-27: changing it to `% 99_999` reddened nothing, which is the
    // correct outcome for an operation that cannot execute — not a missing test.
    // `test_safety_number_group_range` pins the range that actually occurs.
    Some(
        hash[..24]
            .chunks(2)
            .map(|pair| {
                format!(
                    "{:05}",
                    (u32::from(pair[0]) * 256 + u32::from(pair[1])) % 100_000
                )
            })
            .collect::<Vec<_>>()
            .join(" "),
    )
}

// ── SLIP-0010 internals ───────────────────────────────────────────────────────

/// SLIP-0010 master key: HMAC-SHA512(Key="ed25519 seed", Data=seed)
/// Returns (master_key[32], chain_code[32]).
fn slip10_master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let result = hmac_sha512(b"ed25519 seed", seed);
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain.copy_from_slice(&result[32..]);
    (key, chain)
}

/// SLIP-0010 hardened child: HMAC-SHA512(Key=chain, Data=0x00||parent_key||ser32(index|0x80000000))
/// Returns (child_key[32], child_chain[32]).
fn slip10_hardened_child(
    parent_key: &[u8; 32],
    parent_chain: &[u8; 32],
    index: u32,
) -> ([u8; 32], [u8; 32]) {
    let hardened = index | 0x8000_0000;
    let mut data = [0u8; 37]; // 1 + 32 + 4
    data[0] = 0x00;
    data[1..33].copy_from_slice(parent_key);
    data[33..37].copy_from_slice(&hardened.to_be_bytes());

    let result = hmac_sha512(parent_chain, &data);
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain.copy_from_slice(&result[32..]);
    (key, chain)
}

fn hmac_sha512(secret: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac =
        <Hmac<Sha512>>::new_from_slice(secret).expect("HMAC-SHA512 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_generate_12_words() {
        let m = generate_mnemonic(12).unwrap();
        assert_eq!(m.split_whitespace().count(), 12);
        assert!(validate_mnemonic(&m));
    }

    #[test]
    fn test_generate_24_words() {
        let m = generate_mnemonic(24).unwrap();
        assert_eq!(m.split_whitespace().count(), 24);
    }

    #[test]
    fn test_validate_rejects_garbage() {
        assert!(!validate_mnemonic("not valid words at all hey there"));
        assert!(!validate_mnemonic(""));
    }

    #[test]
    fn test_mnemonic_to_seed_length() {
        let seed = mnemonic_to_seed(TEST_PHRASE).unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_derivation_deterministic() {
        let seed = mnemonic_to_seed(TEST_PHRASE).unwrap();
        let kp1 = derive_recovery_keypair(&seed).unwrap();
        let kp2 = derive_recovery_keypair(&seed).unwrap();
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.private_key, kp2.private_key);
    }

    #[test]
    fn test_different_mnemonics_different_keys() {
        let s1 = mnemonic_to_seed(TEST_PHRASE).unwrap();
        let s2 = mnemonic_to_seed("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong").unwrap();
        let kp1 = derive_recovery_keypair(&s1).unwrap();
        let kp2 = derive_recovery_keypair(&s2).unwrap();
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = mnemonic_to_seed(TEST_PHRASE).unwrap();
        let kp = derive_recovery_keypair(&seed).unwrap();
        let challenge = "CONSTRUCT_RECOVERY_SETUP:user123:1741200000";
        let sig = sign_recovery_challenge(&kp.private_key, challenge).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify_recovery_signature(&kp.public_key, challenge, &sig));
        // Wrong message → invalid
        assert!(!verify_recovery_signature(
            &kp.public_key,
            "wrong_message",
            &sig
        ));
    }

    #[test]
    fn test_fingerprint_format() {
        let seed = mnemonic_to_seed(TEST_PHRASE).unwrap();
        let kp = derive_recovery_keypair(&seed).unwrap();
        let fp = compute_key_fingerprint(&kp.public_key);
        // Format: "XXXX XXXX XXXX XXXX" = 4 groups of 4 hex chars separated by spaces
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.chars().filter(|c| *c == ' ').count(), 3);
    }

    #[test]
    fn test_safety_number_format() {
        let id_a = "deadbeefcafe1234deadbeefcafe1234";
        let id_b = "1234cafe5678abcd1234cafe5678abcd";
        let sn = compute_safety_number(id_a, id_b).expect("valid ids must produce a number");
        // 12 groups of 5 digits with spaces: "DDDDD DDDDD ..." = 12*5 + 11 spaces = 71 chars
        assert_eq!(sn.len(), 71);
        assert_eq!(sn.chars().filter(|c| *c == ' ').count(), 11);
        // Every group is numeric and ≤ 99999
        for group in sn.split(' ') {
            let n: u32 = group.parse().expect("group should be numeric");
            assert!(n < 100_000);
        }
    }

    #[test]
    fn test_safety_number_symmetric() {
        let id_a = "deadbeefcafe1234deadbeefcafe1234";
        let id_b = "1234cafe5678abcd1234cafe5678abcd";
        // Both orderings must produce the same Safety Number
        assert_eq!(
            compute_safety_number(id_a, id_b),
            compute_safety_number(id_b, id_a)
        );
        assert!(compute_safety_number(id_a, id_b).is_some());
    }

    #[test]
    fn test_safety_number_different_ids_differ() {
        let id_a = "deadbeefcafe1234deadbeefcafe1234";
        let id_b = "1234cafe5678abcd1234cafe5678abcd";
        let id_c = "ffffffffffffffffffffffffffffffff";
        assert_ne!(
            compute_safety_number(id_a, id_b),
            compute_safety_number(id_a, id_c)
        );
    }

    /// An id this function cannot read must produce **no number**, not a number.
    ///
    /// The old body decoded with `unwrap_or_default()`, so an unreadable id became an empty one —
    /// and an empty id is valid input that yields a real-looking 60-digit string. Every broken id
    /// therefore collapsed onto the *same* value, which is a matching safety number shown to two
    /// people who have verified nothing.
    ///
    /// Mutation: restore `unwrap_or_default()` — the first two assertions redden.
    #[test]
    fn test_safety_number_declines_an_unreadable_id() {
        let good = "deadbeefcafe1234deadbeefcafe1234";

        assert_eq!(compute_safety_number("abc", good), None, "odd length is not hex");
        assert_eq!(compute_safety_number("zzzz", good), None, "not hex at all");
        assert_eq!(compute_safety_number(good, "abc"), None, "either side, not just the first");

        // The trap the old code fell into: empty decodes cleanly, so it has to be refused by name.
        //
        // Mutation: drop the `is_empty` guard — this reddens, and it is the assertion that stops
        // two devices which both supplied nothing from matching each other.
        assert_eq!(compute_safety_number("", good), None);
        assert_eq!(compute_safety_number(good, ""), None);
        assert_eq!(compute_safety_number("", ""), None);
    }

    /// The range a group can actually take. The formatting suggests 00000–99999; a big-endian u16
    /// gives 00000–65535, and the modulus in the formatter never fires.
    ///
    /// Worth pinning because it is a claim about the value's entropy — anyone reasoning about how
    /// hard this is to collide reads the digit count, and the digit count overstates it.
    ///
    /// Mutation: widen the chunks to 3 bytes — the modulus starts firing, the group count drops,
    /// and this reddens along with the pinned values.
    #[test]
    fn test_safety_number_group_range() {
        let sn = compute_safety_number(
            "deadbeefcafe1234deadbeefcafe1234",
            "1234cafe5678abcd1234cafe5678abcd",
        )
        .unwrap();
        let groups: Vec<u32> = sn.split(' ').map(|g| g.parse().unwrap()).collect();
        assert_eq!(groups.len(), 12);
        for g in groups {
            assert!(g <= 65_535, "{g} is above the u16 range a group is built from");
        }
    }

    /// The value itself, pinned here as well as in `construct-protos/conformance/
    /// knst_safety_number.json`.
    ///
    /// The properties above (length, symmetry, distinctness) all survive a change to the round
    /// count, the group width or the digest — every one of those produces a different number for
    /// every input while keeping the shape perfect. Only a pinned value catches them, and it must
    /// be pinned *here* too: with the check living only in the iOS conformance test, a change to
    /// this function is green in its own repo and red in another one.
    ///
    /// Mutation: change `1..1024` to `1..1023`, or `% 100_000` to `% 99_999` — this reddens and
    /// nothing else in this file does.
    #[test]
    fn test_safety_number_pins_its_value() {
        assert_eq!(
            compute_safety_number(
                "deadbeefcafe1234deadbeefcafe1234",
                "1234cafe5678abcd1234cafe5678abcd"
            )
            .as_deref(),
            Some("29923 11327 33797 39770 55644 15437 29152 58888 63756 22781 21915 47107"),
            "a change here is a change every client must make in the same release"
        );
        // The sort, over a pair that orders the other way round.
        assert_eq!(
            compute_safety_number(
                "ffffffffffffffffffffffffffffffff",
                "0f0e0d0c0b0a09080706050403020100"
            )
            .as_deref(),
            Some("64486 46034 27606 61533 65387 50416 61186 59737 40043 64512 57578 59097")
        );
    }

    /// The property the refusal protects: no two *different* inputs may share a number, including
    /// the broken ones. Before the fix every unreadable id produced the value of the empty id.
    ///
    /// Mutation: restore `unwrap_or_default()` — `"abc"` and `"zzzz"` then both produce
    /// `Some(<the empty-id number>)` and this reddens on the first pair.
    #[test]
    fn test_no_two_unreadable_ids_share_a_number() {
        let good = "deadbeefcafe1234deadbeefcafe1234";
        let broken = ["abc", "zzzz", "", "nothex!!", "0x1234"];
        for id in broken {
            assert_eq!(
                compute_safety_number(id, good),
                None,
                "{id} produced a number it has no business producing"
            );
        }
        // And the one shape that must still work is unaffected.
        assert!(compute_safety_number(good, "1234cafe5678abcd1234cafe5678abcd").is_some());
    }
}

