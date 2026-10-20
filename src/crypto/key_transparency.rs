// Key Transparency — Certificate Transparency-style binary Merkle tree
//
// Implements RFC 6962 §2 Merkle Tree Hash (MTH) for append-only key logs.
//
// Leaf hash  : H(0x00 || device_id_bytes || identity_key_bytes)
// Node hash  : H(0x01 || left_hash || right_hash)
//
// Every device registration appends a leaf to the log. The server signs a
// Signed Tree Head (STH) = Ed25519(tree_size || root_hash). Clients verify:
//   1. Inclusion proof: the identity key they received is in the log.
//   2. Consistency proof: the log has only grown since last check (no rewrite).

use sha2::{Digest, Sha256};

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = vec![0x01u8];
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    sha256(&input)
}

// ────────────────────────────────────────────────────────────────────────────
// RFC 6962 §2.1  Merkle Tree Hash (MTH)
// ────────────────────────────────────────────────────────────────────────────

/// The most hashes an inclusion proof can carry: one per level of a tree of at most 2^64
/// leaves. A consistency proof carries at most two per level. A longer proof is not a proof,
/// and bounding it here bounds the recursion below on a server-supplied length.
pub const MAX_PROOF_DEPTH: usize = 64;

/// Largest power of 2 strictly less than `n` (n >= 2); 0 for `n < 2`.
/// This is the RFC 6962 split point: left subtree has `k` leaves, right has `n-k`.
///
/// Closed form on purpose: the loop `while k < n { k <<= 1 }` it replaced shifted `k` to 0 for
/// `n > 2^63` and never ended — `tree_size` is the server's number (TODO 193, 2026-10-20).
fn split(n: usize) -> usize {
    if n < 2 {
        return 0;
    }
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Compute the Merkle Tree Hash for a slice of leaf hashes.
/// MTH([]) = SHA-256("") (empty tree)
/// MTH([d0]) = d0  — callers pass pre-hashed leaves (output of `leaf_hash`).
#[cfg(test)]
fn merkle_tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256(b""),
        1 => leaves[0],
        n => {
            let k = split(n);
            let left = merkle_tree_hash(&leaves[..k]);
            let right = merkle_tree_hash(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RFC 6962 §2.1.3  Merkle Inclusion Proof
// ────────────────────────────────────────────────────────────────────────────

/// Verify an inclusion proof (RFC 6962 §2.1.3).
///
/// - `leaf_hash`   : SHA-256(domain || device_id || key) as 32 bytes
/// - `proof`       : sibling hashes on path from leaf to root, leaf-to-root order
/// - `leaf_index`  : 0-based index of the leaf
/// - `tree_size`   : total number of leaves at the time of proof
/// - `root_hash`   : expected Merkle root
fn verify_inclusion_inner(
    leaf_hash: &[u8; 32],
    proof: &[[u8; 32]],
    leaf_index: u64,
    tree_size: u64,
    root_hash: &[u8; 32],
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size || proof.len() > MAX_PROOF_DEPTH {
        return false;
    }
    // A size this machine cannot index is not a tree this machine can check.
    let (Ok(index), Ok(size)) = (usize::try_from(leaf_index), usize::try_from(tree_size)) else {
        return false;
    };
    inclusion_reconstruct(leaf_hash, proof, index, size) == Some(*root_hash)
}

/// Recursively reconstruct the root hash from an inclusion proof.
/// Proof elements are in leaf-to-root order; we consume from the end (root side)
/// to preserve the tree-structure semantics at each recursion level.
fn inclusion_reconstruct(
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
    index: usize,
    size: usize,
) -> Option<[u8; 32]> {
    if proof.is_empty() {
        // Base case: single-element subtree, leaf IS the root
        return if size == 1 && index == 0 {
            Some(*leaf)
        } else {
            None
        };
    }
    if size < 2 {
        // A one-leaf tree has no siblings: a proof with hashes left over is not its proof.
        return None;
    }
    let k = split(size);
    let sibling = proof[proof.len() - 1];
    let inner = &proof[..proof.len() - 1];
    if index < k {
        // Leaf is in left subtree; the last proof element is the right subtree hash
        let left = inclusion_reconstruct(leaf, inner, index, k)?;
        Some(node_hash(&left, &sibling))
    } else {
        // Leaf is in right subtree; the last proof element is the left subtree hash
        let right = inclusion_reconstruct(leaf, inner, index - k, size - k)?;
        Some(node_hash(&sibling, &right))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RFC 6962 §2.1.4  Merkle Consistency Proof
// ────────────────────────────────────────────────────────────────────────────

/// Verify a consistency proof showing that the old tree of `old_size` leaves
/// is a prefix of the new tree of `new_size` leaves.
#[cfg(test)]
fn verify_consistency_inner(
    old_root: &[u8; 32],
    old_size: u64,
    new_root: &[u8; 32],
    new_size: u64,
    proof: &[[u8; 32]],
) -> bool {
    if old_size > new_size || proof.len() > 2 * MAX_PROOF_DEPTH {
        return false;
    }
    if old_size == new_size {
        return old_root == new_root && proof.is_empty();
    }
    if old_size == 0 {
        return proof.is_empty();
    }
    let (Ok(old_size), Ok(new_size)) = (usize::try_from(old_size), usize::try_from(new_size))
    else {
        return false;
    };
    match consistency_reconstruct(old_root, old_size, new_size, true, proof) {
        Some((r_old, r_new)) => r_old == *old_root && r_new == *new_root,
        None => false,
    }
}

/// Recursively reconstruct (old_subtree_root, new_subtree_root) from a
/// consistency proof generated by `subproof`.
///
/// `b=true`  at the outermost call (RFC 6962 SUBPROOF with b=true).
/// `b=false` in right-subtree recursions (produces an extra "anchor" element).
/// `old_root_hint` is the overall old root, used ONLY when `b=true` and
/// `old_size == k` (meaning the old tree exactly fills the left half and no
/// proof element encodes it — the caller already knows it).
#[cfg(test)]
fn consistency_reconstruct(
    old_root_hint: &[u8; 32],
    old_size: usize,
    new_size: usize,
    b: bool,
    proof: &[[u8; 32]],
) -> Option<([u8; 32], [u8; 32])> {
    if old_size == new_size {
        return if b {
            // b=true base: proof must be empty; the subtree hash is known externally
            if proof.is_empty() {
                Some((*old_root_hint, *old_root_hint))
            } else {
                None
            }
        } else {
            // b=false base: proof = [MTH(D)] — the subtree hash is provided explicitly
            if proof.len() == 1 {
                Some((proof[0], proof[0]))
            } else {
                None
            }
        };
    }

    let k = split(new_size);
    if old_size <= k {
        if proof.is_empty() {
            return None;
        }
        let right_hash = proof[proof.len() - 1];
        let inner = &proof[..proof.len() - 1];

        if old_size == k && b {
            // Old tree exactly fills the left half; inner proof is empty and the
            // old subtree root is old_root_hint (not encoded in the proof).
            return if inner.is_empty() {
                Some((*old_root_hint, node_hash(old_root_hint, &right_hash)))
            } else {
                None
            };
        }

        let (old_left, new_left) = consistency_reconstruct(old_root_hint, old_size, k, b, inner)?;
        Some((old_left, node_hash(&new_left, &right_hash)))
    } else {
        // old_size > k: old tree spans into the right half.
        if proof.is_empty() {
            return None;
        }
        let left_hash = proof[proof.len() - 1];
        let inner = &proof[..proof.len() - 1];
        // Right-subtree recursion always uses b=false.
        let (old_right, new_right) =
            consistency_reconstruct(old_root_hint, old_size - k, new_size - k, false, inner)?;
        Some((
            node_hash(&left_hash, &old_right),
            node_hash(&left_hash, &new_right),
        ))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// A bundle's proofs, judged — what a client asks (decisions/server-keys-rooted-offline-and-hybrid.md)
// ────────────────────────────────────────────────────────────────────────────

/// Leaf domain of a device's X25519 identity key.
pub const LEAF_IDENTITY: u8 = 0x00;
/// Leaf domain of a device's hybrid (Ed25519 ‖ ML-DSA-65) identity key.
pub const LEAF_HYBRID: u8 = 0x02;

/// `SHA-256(domain ‖ device_id ‖ key)` — the leaf key-service appends.
pub fn leaf_hash(domain: u8, device_id: &str, key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([domain]);
    h.update(device_id.as_bytes());
    h.update(key);
    h.finalize().into()
}

/// What the Ed25519 tree-head signature covers: `"ConstructKT-v1" ‖ BE64(size) ‖ root`.
pub fn tree_head_signable(tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut buf = b"ConstructKT-v1".to_vec();
    buf.extend_from_slice(&tree_size.to_be_bytes());
    buf.extend_from_slice(root);
    buf
}

/// An inclusion proof as a bundle carries it. UDL `dictionary KtInclusionProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtInclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub root_hash: Vec<u8>,
    pub proof_hashes: Vec<Vec<u8>>,
    /// Ed25519 over `tree_head_signable` — the head before delegated keys.
    pub tree_head_signature: Vec<u8>,
}

/// The tree head a bundle's proofs are relative to, signed by a delegated key. UDL
/// `dictionary KtSignedTreeHead`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtSignedTreeHead {
    pub tree_size: u64,
    pub root_hash: Vec<u8>,
    pub kid: Vec<u8>,
    pub signature: Vec<u8>,
}

/// What a client concludes from one proof. UDL `enum KtVerdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtVerdict {
    Verified,
    /// No key to check the head with yet — not evidence of anything.
    Unavailable,
    MalformedProof,
    /// The key is not where the proof says, or the proof is not of the signed head.
    InclusionProofInvalid,
    SignatureInvalid,
}

/// Judge one proof of `key` under `device_id` (leaf `domain`), and the head it is relative to.
///
/// The head is judged as a certificate is (`SenderCertificate::check_signature`): with roots
/// pinned, a delegated `head` decides alone and must name this proof's size and root; without
/// one the Ed25519 head signature decides until `HYBRID_REQUIRED`; without roots, Ed25519.
pub fn verify_proof(
    domain: u8,
    device_id: &str,
    key: &[u8],
    proof: &KtInclusionProof,
    head: Option<&KtSignedTreeHead>,
    trust: &crate::crypto::sealed_sender::ServerTrust,
    now_secs: i64,
) -> KtVerdict {
    let Ok(root) = <[u8; 32]>::try_from(proof.root_hash.as_slice()) else {
        return KtVerdict::MalformedProof;
    };
    let Ok(hashes) = proof
        .proof_hashes
        .iter()
        .map(|h| <[u8; 32]>::try_from(h.as_slice()))
        .collect::<Result<Vec<_>, _>>()
    else {
        return KtVerdict::MalformedProof;
    };
    if proof.tree_size == 0 || proof.leaf_index >= proof.tree_size {
        return KtVerdict::MalformedProof;
    }
    let leaf = leaf_hash(domain, device_id, key);
    if !verify_inclusion_inner(&leaf, &hashes, proof.leaf_index, proof.tree_size, &root) {
        return KtVerdict::InclusionProofInvalid;
    }

    #[cfg(feature = "post-quantum")]
    if trust.ring.has_roots() {
        use crate::crypto::server_trust::{
            HYBRID_REQUIRED, Kid, Purpose, TrustError, kt_head_body,
        };
        if let Some(head) = head {
            if head.tree_size != proof.tree_size || head.root_hash != proof.root_hash {
                return KtVerdict::InclusionProofInvalid;
            }
            let Ok(kid) = Kid::try_from(head.kid.as_slice()) else {
                return KtVerdict::MalformedProof;
            };
            let body = kt_head_body(head.tree_size, &root);
            return match trust.ring.verify(
                Purpose::KtHead,
                &kid,
                &body,
                &head.signature,
                now_secs,
                now_secs,
            ) {
                Ok(()) => KtVerdict::Verified,
                Err(TrustError::UnknownKey) => KtVerdict::Unavailable,
                Err(_) => KtVerdict::SignatureInvalid,
            };
        }
        if HYBRID_REQUIRED {
            return KtVerdict::SignatureInvalid;
        }
    }
    #[cfg(not(feature = "post-quantum"))]
    let _ = (head, now_secs);

    if trust.legacy_keys.is_empty() {
        return KtVerdict::Unavailable;
    }
    let signable = tree_head_signable(proof.tree_size, &root);
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&proof.tree_head_signature) else {
        return KtVerdict::SignatureInvalid;
    };
    let signed = trust.legacy_keys.iter().any(|k| {
        <[u8; 32]>::try_from(k.as_slice())
            .ok()
            .and_then(|k| ed25519_dalek::VerifyingKey::from_bytes(&k).ok())
            .is_some_and(|vk| ed25519_dalek::Verifier::verify(&vk, &signable, &sig).is_ok())
    });
    if signed {
        KtVerdict::Verified
    } else {
        KtVerdict::SignatureInvalid
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Proof generators (the key service builds proofs; here they only exercise the verifiers)
// ────────────────────────────────────────────────────────────────────────────

/// Inclusion proof for the leaf at `index`, leaf-to-root order.
#[cfg(test)]
fn generate_inclusion_proof_inner(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n == 1 {
        return vec![];
    }
    let k = split(n);
    if index < k {
        let mut proof = generate_inclusion_proof_inner(&leaves[..k], index);
        proof.push(merkle_tree_hash(&leaves[k..]));
        proof
    } else {
        let mut proof = generate_inclusion_proof_inner(&leaves[k..], index - k);
        proof.push(merkle_tree_hash(&leaves[..k]));
        proof
    }
}

#[cfg(test)]
fn generate_consistency_proof_inner(leaves: &[[u8; 32]], old_size: usize) -> Vec<[u8; 32]> {
    subproof(leaves, old_size, true)
}

/// RFC 6962 §2.1.4 SUBPROOF(m, D[n], b):
/// - `b=true`  for the outermost call (old root is known externally)
/// - `b=false` in right-subtree recursions (adds an explicit anchor hash)
#[cfg(test)]
fn subproof(leaves: &[[u8; 32]], old_size: usize, b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if old_size == n {
        return if b {
            vec![] // old root known externally, nothing to add
        } else {
            vec![merkle_tree_hash(leaves)] // caller needs the explicit hash
        };
    }
    let k = split(n);
    if old_size <= k {
        let mut proof = subproof(&leaves[..k], old_size, b);
        proof.push(merkle_tree_hash(&leaves[k..]));
        proof
    } else {
        let mut proof = subproof(&leaves[k..], old_size - k, false); // b=false for right subtree
        proof.push(merkle_tree_hash(&leaves[..k]));
        proof
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaf(device_id: &str, key: &[u8]) -> [u8; 32] {
        leaf_hash(LEAF_IDENTITY, device_id, key)
    }

    #[test]
    fn test_leaf_hash_deterministic() {
        let h1 = make_leaf("device-1", &[1u8; 32]);
        let h2 = make_leaf("device-1", &[1u8; 32]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_leaf_hash_differs_by_device() {
        let h1 = make_leaf("device-1", &[1u8; 32]);
        let h2 = make_leaf("device-2", &[1u8; 32]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_leaf_hash_differs_by_key() {
        let h1 = make_leaf("device-1", &[1u8; 32]);
        let h2 = make_leaf("device-1", &[2u8; 32]);
        assert_ne!(h1, h2);
    }

    fn make_leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = i as u8;
                key[1] = (i >> 8) as u8;
                make_leaf(&format!("device-{}", i), &key)
            })
            .collect()
    }

    // ── Audit 2026-10-20: the server's numbers bound the work (TODO 193) ────────

    /// `split` in closed form agrees with its loop definition wherever the loop terminates.
    #[test]
    fn split_matches_the_loop_definition() {
        fn by_loop(n: usize) -> usize {
            let mut k = 1usize;
            while k < n {
                k <<= 1;
            }
            k >> 1
        }
        for n in 2..=4096usize {
            assert_eq!(split(n), by_loop(n), "n={n}");
        }
        for n in [1usize << 40, (1 << 40) + 1, (1 << 62) + 7, 1 << 63] {
            assert_eq!(split(n), by_loop(n), "n={n}");
        }
        assert_eq!(split(0), 0);
        assert_eq!(split(1), 0);
        assert_eq!(split((1usize << 63) + 1), 1 << 63);
        assert_eq!(split(usize::MAX), 1 << 63);
    }

    /// A proof against a tree past 2^63 leaves is refused at once.
    ///
    /// Mutation: restore the loop in `split` — this test never finishes.
    #[test]
    fn a_tree_size_past_two_to_the_63_is_refused_at_once() {
        let leaf = [1u8; 32];
        let root = [2u8; 32];
        let started = std::time::Instant::now();
        for size in [u64::MAX, (1u64 << 63) + 1, 1u64 << 63] {
            assert!(!verify_inclusion_inner(&leaf, &[[3u8; 32]], 0, size, &root));
            assert!(!verify_inclusion_inner(
                &leaf,
                &[[3u8; 32]],
                size - 1,
                size,
                &root
            ));
            assert!(!verify_consistency_inner(
                &leaf,
                1,
                &root,
                size,
                &[[3u8; 32]]
            ));
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// A proof deeper than a 2^64-leaf tree, or with hashes left over for a one-leaf tree, is
    /// not a proof.
    #[test]
    fn an_overlong_proof_is_refused() {
        let leaf = [1u8; 32];
        let too_deep = vec![[3u8; 32]; MAX_PROOF_DEPTH + 1];
        assert!(!verify_inclusion_inner(
            &leaf,
            &too_deep,
            0,
            u64::MAX / 2,
            &leaf
        ));
        assert!(verify_inclusion_inner(&leaf, &[], 0, 1, &leaf));
        assert!(!verify_inclusion_inner(&leaf, &[[3u8; 32]], 0, 1, &leaf));
        let too_long = vec![[3u8; 32]; 2 * MAX_PROOF_DEPTH + 1];
        assert!(!verify_consistency_inner(&leaf, 1, &leaf, 4, &too_long));
    }

    #[test]
    fn test_single_leaf_inclusion() {
        let leaves = make_leaves(1);
        let root = merkle_tree_hash(&leaves);
        let proof = generate_inclusion_proof_inner(&leaves, 0);
        assert!(proof.is_empty());
        assert!(verify_inclusion_inner(&leaves[0], &proof, 0, 1, &root));
    }

    #[test]
    fn test_inclusion_various_tree_sizes() {
        for n in [2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let leaves = make_leaves(n);
            let root = merkle_tree_hash(&leaves);
            for i in 0..n {
                let proof = generate_inclusion_proof_inner(&leaves, i);
                assert!(
                    verify_inclusion_inner(&leaves[i], &proof, i as u64, n as u64, &root),
                    "inclusion failed n={} i={}",
                    n,
                    i
                );
            }
        }
    }

    #[test]
    fn test_inclusion_wrong_leaf_fails() {
        let leaves = make_leaves(4);
        let root = merkle_tree_hash(&leaves);
        let proof = generate_inclusion_proof_inner(&leaves, 0);
        // Try verifying with the wrong leaf
        assert!(!verify_inclusion_inner(&leaves[1], &proof, 0, 4, &root));
    }

    #[test]
    fn test_inclusion_wrong_root_fails() {
        let leaves = make_leaves(4);
        let proof = generate_inclusion_proof_inner(&leaves, 0);
        let bad_root = [0xaau8; 32];
        assert!(!verify_inclusion_inner(&leaves[0], &proof, 0, 4, &bad_root));
    }

    #[test]
    fn test_consistency_trivial() {
        let leaves = make_leaves(4);
        let root = merkle_tree_hash(&leaves);
        // Same tree = trivially consistent
        assert!(verify_consistency_inner(&root, 4, &root, 4, &[]));
    }

    #[test]
    fn test_consistency_grow() {
        for old_n in 1..=8usize {
            for new_n in old_n..=16usize {
                let leaves = make_leaves(new_n);
                let old_root = merkle_tree_hash(&leaves[..old_n]);
                let new_root = merkle_tree_hash(&leaves);
                let proof = generate_consistency_proof_inner(&leaves, old_n);
                assert!(
                    verify_consistency_inner(
                        &old_root,
                        old_n as u64,
                        &new_root,
                        new_n as u64,
                        &proof
                    ),
                    "consistency failed old={} new={}",
                    old_n,
                    new_n
                );
            }
        }
    }

    #[test]
    fn test_consistency_tampered_old_root_fails() {
        let leaves = make_leaves(8);
        let old_root = merkle_tree_hash(&leaves[..4]);
        let new_root = merkle_tree_hash(&leaves);
        let proof = generate_consistency_proof_inner(&leaves, 4);
        let bad_old = [0xbbu8; 32];
        assert!(!verify_consistency_inner(&bad_old, 4, &new_root, 8, &proof));
        // Correct old root but wrong new root
        let bad_new = [0xccu8; 32];
        assert!(!verify_consistency_inner(&old_root, 4, &bad_new, 8, &proof));
    }

    #[test]
    fn test_tree_head_signable_length() {
        let bytes = tree_head_signable(42, &[0xaau8; 32]);
        // "ConstructKT-v1" (14) + 8 + 32 = 54
        assert_eq!(bytes.len(), 54);
        assert!(bytes.starts_with(b"ConstructKT-v1"));
    }

    // ── verify_proof: a bundle's proofs, judged (decisions/server-keys-rooted-offline-and-hybrid.md) ──

    mod bundle_proofs {
        use super::super::*;
        use crate::crypto::sealed_sender::ServerTrust;
        use ed25519_dalek::{Signer, SigningKey};

        const NOW: i64 = 1_800_000_000;
        const DEVICE: &str = "6f5e37ac00000000000000000000000a";
        const KEY: [u8; 32] = [7; 32];
        const HYBRID_KEY: [u8; 4] = [8; 4];

        /// A tree of 6 leaves with the device's identity leaf at 2 and its hybrid leaf at 5, the
        /// Ed25519 head signed by `ed`.
        fn tree(ed: &SigningKey) -> (KtInclusionProof, KtInclusionProof, [u8; 32]) {
            let mut leaves: Vec<[u8; 32]> = (0..6u8).map(|i| sha256(&[i])).collect();
            leaves[2] = leaf_hash(LEAF_IDENTITY, DEVICE, &KEY);
            leaves[5] = leaf_hash(LEAF_HYBRID, DEVICE, &HYBRID_KEY);
            let root = merkle_tree_hash(&leaves);
            let sig = ed.sign(&tree_head_signable(6, &root)).to_bytes().to_vec();
            let proof = |i: usize| KtInclusionProof {
                leaf_index: i as u64,
                tree_size: 6,
                root_hash: root.to_vec(),
                proof_hashes: generate_inclusion_proof_inner(&leaves, i)
                    .into_iter()
                    .map(|h| h.to_vec())
                    .collect(),
                tree_head_signature: sig.clone(),
            };
            (proof(2), proof(5), root)
        }

        fn legacy(ed: &SigningKey) -> ServerTrust {
            ServerTrust::with_legacy_keys(vec![ed.verifying_key().to_bytes().to_vec()])
        }

        #[test]
        fn a_leaf_under_a_signed_head_is_verified() {
            let ed = SigningKey::from_bytes(&[9; 32]);
            let (id, hy, _) = tree(&ed);
            let t = legacy(&ed);
            assert_eq!(
                verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &id, None, &t, NOW),
                KtVerdict::Verified
            );
            assert_eq!(
                verify_proof(LEAF_HYBRID, DEVICE, &HYBRID_KEY, &hy, None, &t, NOW),
                KtVerdict::Verified
            );
        }

        /// Mutation: hash the leaf without its domain byte, or skip the reconstruction — a line reddens.
        #[test]
        fn another_key_or_the_wrong_leaf_kind_is_not_in_the_tree() {
            let ed = SigningKey::from_bytes(&[9; 32]);
            let (id, hy, _) = tree(&ed);
            let t = legacy(&ed);
            assert_eq!(
                verify_proof(LEAF_IDENTITY, DEVICE, &[6; 32], &id, None, &t, NOW),
                KtVerdict::InclusionProofInvalid
            );
            assert_eq!(
                verify_proof(LEAF_IDENTITY, DEVICE, &HYBRID_KEY, &hy, None, &t, NOW),
                KtVerdict::InclusionProofInvalid
            );
        }

        #[test]
        fn a_head_signed_by_another_key_or_no_key_at_all() {
            let ed = SigningKey::from_bytes(&[9; 32]);
            let (id, _, _) = tree(&ed);
            let other = legacy(&SigningKey::from_bytes(&[10; 32]));
            assert_eq!(
                verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &id, None, &other, NOW),
                KtVerdict::SignatureInvalid
            );
            assert_eq!(
                verify_proof(
                    LEAF_IDENTITY,
                    DEVICE,
                    &KEY,
                    &id,
                    None,
                    &ServerTrust::default(),
                    NOW
                ),
                KtVerdict::Unavailable
            );
            let mut short = id.clone();
            short.root_hash.pop();
            assert_eq!(
                verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &short, None, &legacy(&ed), NOW),
                KtVerdict::MalformedProof
            );
        }

        #[cfg(feature = "post-quantum")]
        mod delegated_head {
            use super::*;
            use crate::crypto::server_trust::{
                Purpose, ServerKeyRing, issue_delegation, kid_of, kt_head_body, sign_as_server,
            };
            use crate::crypto::suites::hybrid::hybrid_signature_keypair_from_seeds;

            fn rooted(ed: &SigningKey) -> (ServerTrust, (crate::crypto::SecretBytes, Vec<u8>)) {
                let (root_sk, root_pk) = hybrid_signature_keypair_from_seeds(&[1; 32], &[2; 32]);
                let key = hybrid_signature_keypair_from_seeds(&[3; 32], &[4; 32]);
                let d = issue_delegation(&root_sk, Purpose::KtHead, NOW - 10, NOW + 10, &key.1)
                    .unwrap();
                let mut ring = ServerKeyRing::new(vec![root_pk]);
                ring.admit(&d.encode()).unwrap();
                (
                    ServerTrust {
                        legacy_keys: vec![ed.verifying_key().to_bytes().to_vec()],
                        ring,
                    },
                    key,
                )
            }

            fn head(
                key: &(crate::crypto::SecretBytes, Vec<u8>),
                size: u64,
                root: &[u8; 32],
            ) -> KtSignedTreeHead {
                KtSignedTreeHead {
                    tree_size: size,
                    root_hash: root.to_vec(),
                    kid: kid_of(&key.1).to_vec(),
                    signature: sign_as_server(
                        Purpose::KtHead,
                        &key.0,
                        &key.1,
                        &kt_head_body(size, root),
                    )
                    .unwrap(),
                }
            }

            #[test]
            fn a_delegated_head_verifies_the_proof() {
                let ed = SigningKey::from_bytes(&[9; 32]);
                let (id, _, root) = tree(&ed);
                let (t, key) = rooted(&ed);
                let h = head(&key, 6, &root);
                assert_eq!(
                    verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &id, Some(&h), &t, NOW),
                    KtVerdict::Verified
                );
            }

            /// A delegated head that fails is not rescued by a good Ed25519 head beside it.
            #[test]
            fn a_spoiled_delegated_head_does_not_fall_back() {
                let ed = SigningKey::from_bytes(&[9; 32]);
                let (id, _, root) = tree(&ed);
                let (t, key) = rooted(&ed);
                let mut h = head(&key, 6, &root);
                h.signature[70] ^= 1;
                assert_eq!(
                    verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &id, Some(&h), &t, NOW),
                    KtVerdict::SignatureInvalid
                );
            }

            /// The head must be the one the proof is relative to.
            #[test]
            fn a_head_of_another_tree_does_not_vouch_for_this_proof() {
                let ed = SigningKey::from_bytes(&[9; 32]);
                let (id, _, root) = tree(&ed);
                let (t, key) = rooted(&ed);
                let h = head(&key, 7, &root);
                assert_eq!(
                    verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &id, Some(&h), &t, NOW),
                    KtVerdict::InclusionProofInvalid
                );
                let h = head(&key, 6, &[0; 32]);
                assert_eq!(
                    verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &id, Some(&h), &t, NOW),
                    KtVerdict::InclusionProofInvalid
                );
            }

            #[test]
            fn an_unknown_head_key_or_a_lapsed_one() {
                let ed = SigningKey::from_bytes(&[9; 32]);
                let (id, _, root) = tree(&ed);
                let (t, key) = rooted(&ed);
                let mut h = head(&key, 6, &root);
                h.kid = vec![0; 16];
                assert_eq!(
                    verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &id, Some(&h), &t, NOW),
                    KtVerdict::Unavailable
                );
                let h = head(&key, 6, &root);
                assert_eq!(
                    verify_proof(LEAF_IDENTITY, DEVICE, &KEY, &id, Some(&h), &t, NOW + 11),
                    KtVerdict::SignatureInvalid
                );
            }
        }
    }
}
