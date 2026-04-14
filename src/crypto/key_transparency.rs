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

fn leaf_hash_raw(device_id: &[u8], identity_key: &[u8]) -> [u8; 32] {
    let mut input = vec![0x00u8];
    input.extend_from_slice(device_id);
    input.extend_from_slice(identity_key);
    sha256(&input)
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = vec![0x01u8];
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    sha256(&input)
}

fn hex_to_bytes32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn bytes32_to_hex(b: &[u8; 32]) -> String {
    b.iter().map(|byte| format!("{:02x}", byte)).collect()
}

// ────────────────────────────────────────────────────────────────────────────
// RFC 6962 §2.1  Merkle Tree Hash (MTH)
// ────────────────────────────────────────────────────────────────────────────

/// Largest power of 2 strictly less than `n` (n >= 2).
/// This is the RFC 6962 split point: left subtree has `k` leaves, right has `n-k`.
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

/// Compute the Merkle Tree Hash for a slice of leaf hashes.
/// MTH([]) = SHA-256("") (empty tree)
/// MTH([d0]) = d0  — callers pass pre-hashed leaves (output of `leaf_hash_raw`).
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
/// - `leaf_hash`   : SHA-256(0x00 || device_id || identity_key) as 32 bytes
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
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }
    inclusion_reconstruct(leaf_hash, proof, leaf_index as usize, tree_size as usize)
        == Some(*root_hash)
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
fn verify_consistency_inner(
    old_root: &[u8; 32],
    old_size: u64,
    new_root: &[u8; 32],
    new_size: u64,
    proof: &[[u8; 32]],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return old_root == new_root && proof.is_empty();
    }
    if old_size == 0 {
        return proof.is_empty();
    }
    match consistency_reconstruct(old_root, old_size as usize, new_size as usize, true, proof) {
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
// Public API (called from UniFFI bindings and server-side code)
// ────────────────────────────────────────────────────────────────────────────

/// Hash a single leaf: H(0x00 || device_id_utf8 || identity_key_raw_bytes).
///
/// `identity_key_b64` is the standard Base64-encoded identity public key as
/// stored in the database / transmitted in bundles.
///
/// Returns a lowercase hex string (64 chars).
pub fn kt_hash_leaf(device_id: &str, identity_key_b64: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let key_bytes = B64.decode(identity_key_b64).unwrap_or_default();
    let hash = leaf_hash_raw(device_id.as_bytes(), &key_bytes);
    bytes32_to_hex(&hash)
}

/// Compute Merkle root for a list of leaf hashes (hex strings).
/// Used by the server to build the current tree root from stored leaves.
pub fn kt_compute_root(leaf_hashes_hex: Vec<String>) -> String {
    let leaves: Vec<[u8; 32]> = leaf_hashes_hex
        .iter()
        .filter_map(|h| hex_to_bytes32(h))
        .collect();
    let root = merkle_tree_hash(&leaves);
    bytes32_to_hex(&root)
}

/// Verify an inclusion proof (hex-encoded inputs).
///
/// Returns `true` iff `leaf_hash` is at `leaf_index` in a tree of `tree_size`
/// leaves with root `root_hash`.
pub fn kt_verify_inclusion(
    leaf_hash_hex: &str,
    proof_hexes: Vec<String>,
    leaf_index: u64,
    tree_size: u64,
    root_hash_hex: &str,
) -> bool {
    let leaf = match hex_to_bytes32(leaf_hash_hex) {
        Some(h) => h,
        None => return false,
    };
    let root = match hex_to_bytes32(root_hash_hex) {
        Some(h) => h,
        None => return false,
    };
    let proof: Vec<[u8; 32]> = proof_hexes
        .iter()
        .filter_map(|h| hex_to_bytes32(h))
        .collect();
    if proof.len() != proof_hexes.len() {
        return false; // any invalid hex in proof → reject
    }
    verify_inclusion_inner(&leaf, &proof, leaf_index, tree_size, &root)
}

/// Verify a consistency proof showing the old tree is a prefix of the new tree.
///
/// Returns `true` iff old_root matches a subtree of new_root for the given sizes.
pub fn kt_verify_consistency(
    old_root_hex: &str,
    old_size: u64,
    new_root_hex: &str,
    new_size: u64,
    proof_hexes: Vec<String>,
) -> bool {
    let old_root = match hex_to_bytes32(old_root_hex) {
        Some(h) => h,
        None => return false,
    };
    let new_root = match hex_to_bytes32(new_root_hex) {
        Some(h) => h,
        None => return false,
    };
    let proof: Vec<[u8; 32]> = proof_hexes
        .iter()
        .filter_map(|h| hex_to_bytes32(h))
        .collect();
    if proof.len() != proof_hexes.len() {
        return false;
    }
    verify_consistency_inner(&old_root, old_size, &new_root, new_size, &proof)
}

// ────────────────────────────────────────────────────────────────────────────
// Signed Tree Head helpers (used server-side; included here for test parity)
// ────────────────────────────────────────────────────────────────────────────

/// Canonical bytes for signing a tree head:
/// `"ConstructKT-v1" || tree_size (8 bytes BE) || root_hash (32 bytes)`
pub fn kt_tree_head_signable(tree_size: u64, root_hash_hex: &str) -> Vec<u8> {
    let root = hex_to_bytes32(root_hash_hex).unwrap_or([0u8; 32]);
    let mut buf = b"ConstructKT-v1".to_vec();
    buf.extend_from_slice(&tree_size.to_be_bytes());
    buf.extend_from_slice(&root);
    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Server-side proof generator (used in key-service, not in UniFFI)
// ────────────────────────────────────────────────────────────────────────────

/// Generate an inclusion proof for leaf at `leaf_index` in a tree of `leaves`.
/// Returns (proof_hashes, root_hash) as hex strings.
pub fn kt_generate_inclusion_proof(
    leaf_hashes_hex: &[String],
    leaf_index: usize,
) -> Option<(Vec<String>, String)> {
    let leaves: Vec<[u8; 32]> = leaf_hashes_hex
        .iter()
        .filter_map(|h| hex_to_bytes32(h))
        .collect();
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }
    let proof = generate_inclusion_proof_inner(&leaves, leaf_index);
    let root = merkle_tree_hash(&leaves);
    Some((
        proof.iter().map(bytes32_to_hex).collect(),
        bytes32_to_hex(&root),
    ))
}

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

/// Generate a consistency proof between tree of `old_size` and full `leaves`.
/// Returns proof_hashes as hex strings.
pub fn kt_generate_consistency_proof(
    leaf_hashes_hex: &[String],
    old_size: usize,
) -> Option<Vec<String>> {
    let leaves: Vec<[u8; 32]> = leaf_hashes_hex
        .iter()
        .filter_map(|h| hex_to_bytes32(h))
        .collect();
    if old_size == 0 || old_size > leaves.len() {
        return None;
    }
    let proof = generate_consistency_proof_inner(&leaves, old_size);
    Some(proof.iter().map(bytes32_to_hex).collect())
}

fn generate_consistency_proof_inner(leaves: &[[u8; 32]], old_size: usize) -> Vec<[u8; 32]> {
    subproof(leaves, old_size, true)
}

/// RFC 6962 §2.1.4 SUBPROOF(m, D[n], b):
/// - `b=true`  for the outermost call (old root is known externally)
/// - `b=false` in right-subtree recursions (adds an explicit anchor hash)
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
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    fn make_leaf(device_id: &str, key: &[u8]) -> String {
        let key_b64 = B64.encode(key);
        kt_hash_leaf(device_id, &key_b64)
    }

    #[test]
    fn test_leaf_hash_format() {
        let h = make_leaf("abc123", &[0u8; 32]);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
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

    fn make_leaves(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = i as u8;
                key[1] = (i >> 8) as u8;
                make_leaf(&format!("device-{}", i), &key)
            })
            .collect()
    }

    #[test]
    fn test_single_leaf_inclusion() {
        let leaves = make_leaves(1);
        let root = kt_compute_root(leaves.clone());
        let (proof, proof_root) = kt_generate_inclusion_proof(&leaves, 0).unwrap();
        assert_eq!(root, proof_root);
        assert!(kt_verify_inclusion(&leaves[0], proof, 0, 1, &root));
    }

    #[test]
    fn test_inclusion_various_tree_sizes() {
        for n in [2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let leaves = make_leaves(n);
            let root = kt_compute_root(leaves.clone());
            for i in 0..n {
                let (proof, proof_root) = kt_generate_inclusion_proof(&leaves, i).unwrap();
                assert_eq!(root, proof_root, "root mismatch n={} i={}", n, i);
                assert!(
                    kt_verify_inclusion(&leaves[i], proof, i as u64, n as u64, &root),
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
        let root = kt_compute_root(leaves.clone());
        let (proof, _) = kt_generate_inclusion_proof(&leaves, 0).unwrap();
        // Try verifying with the wrong leaf
        assert!(!kt_verify_inclusion(&leaves[1], proof, 0, 4, &root));
    }

    #[test]
    fn test_inclusion_wrong_root_fails() {
        let leaves = make_leaves(4);
        let _root = kt_compute_root(leaves.clone()); // ensure root computes without panic
        let (proof, _) = kt_generate_inclusion_proof(&leaves, 0).unwrap();
        let bad_root = "a".repeat(64);
        assert!(!kt_verify_inclusion(&leaves[0], proof, 0, 4, &bad_root));
    }

    #[test]
    fn test_consistency_trivial() {
        let leaves = make_leaves(4);
        let root = kt_compute_root(leaves.clone());
        // Same tree = trivially consistent
        assert!(kt_verify_consistency(&root, 4, &root, 4, vec![]));
    }

    #[test]
    fn test_consistency_grow() {
        for old_n in 1..=8usize {
            for new_n in old_n..=16usize {
                let leaves = make_leaves(new_n);
                let old_root = kt_compute_root(leaves[..old_n].to_vec());
                let new_root = kt_compute_root(leaves.clone());
                let proof = kt_generate_consistency_proof(&leaves, old_n).unwrap();
                assert!(
                    kt_verify_consistency(&old_root, old_n as u64, &new_root, new_n as u64, proof),
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
        let old_root = kt_compute_root(leaves[..4].to_vec());
        let new_root = kt_compute_root(leaves.clone());
        let proof = kt_generate_consistency_proof(&leaves, 4).unwrap();
        let bad_old = "b".repeat(64);
        assert!(!kt_verify_consistency(&bad_old, 4, &new_root, 8, proof));
        // Correct old root but wrong new root
        let bad_new = "c".repeat(64);
        let proof2 = kt_generate_consistency_proof(&leaves, 4).unwrap();
        assert!(!kt_verify_consistency(&old_root, 4, &bad_new, 8, proof2));
    }

    #[test]
    fn test_tree_head_signable_length() {
        let root = "a".repeat(64);
        let bytes = kt_tree_head_signable(42, &root);
        // "ConstructKT-v1" (14) + 8 + 32 = 54
        assert_eq!(bytes.len(), 54);
        assert!(bytes.starts_with(b"ConstructKT-v1"));
    }
}
