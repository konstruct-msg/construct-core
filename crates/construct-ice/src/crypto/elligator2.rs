//! Elligator2 encoding/decoding for Curve25519 public keys.
//!
//! Elligator2 maps Curve25519 points to uniformly random 32-byte strings,
//! making public keys indistinguishable from random noise.
//!
//! Only ~50% of Curve25519 points have an Elligator2 representative.
//! Use [`keypair::EphemeralKeypair`] which retries until a representable
//! key is found.
//!
//! ## Reference
//! - Spec: <https://elligator.cr.yp.to/elligator-20130828.pdf>
//! - obfs4 usage: <https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt>

use curve25519_elligator2::elligator2::MapToPointVariant;
use curve25519_elligator2::elligator2::Randomized;
use curve25519_elligator2::montgomery::MontgomeryPoint;
use rand::{CryptoRng, RngCore};

// ── Public API ───────────────────────────────────────────────────────────────

/// Compute an Elligator2 representative from a private key.
///
/// Uses the Randomized variant which matches the Go obfs4 reference
/// implementation and provides stronger indistinguishability guarantees
/// (no computational distinguisher in the representative).
///
/// Returns `None` if the private key's public point has no representative
/// (~50% of keys). In that case, generate a new keypair and retry.
///
/// The `tweak` byte controls the high bits of the representative for extra
/// randomization (any random byte is fine).
pub fn representative_from_privkey_tweaked(privkey: &[u8; 32], tweak: u8) -> Option<[u8; 32]> {
    Randomized::to_representative(privkey, tweak).into()
}

/// Generate a random tweak byte for Elligator2 encoding.
pub fn random_tweak<R: RngCore + CryptoRng>(rng: &mut R) -> u8 {
    let mut b = [0u8; 1];
    rng.fill_bytes(&mut b);
    b[0]
}

/// Decode a uniform 32-byte representative back to a Curve25519 public key.
///
/// This is the inverse of the representative computation: given a representative
/// produced from a private key, it recovers the corresponding public key.
pub fn pubkey_from_representative(representative: &[u8; 32]) -> MontgomeryPoint {
    // from_representative::<Randomized> masks the top 2 bits before decoding,
    // so it succeeds for any 32-byte input and must never return None.
    // The old fallback to map_to_point was dead code but dangerous: if it ever
    // triggered it would return a completely different point, silently breaking DH.
    MontgomeryPoint::from_representative::<Randomized>(representative)
        .expect("Elligator2 Randomized decode always succeeds for any 32-byte input")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn encode_decode_round_trip() {
        let mut found = 0;
        for _ in 0..256 {
            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            let tweak = random_tweak(&mut OsRng);

            if let Some(repr) = representative_from_privkey_tweaked(&secret, tweak) {
                let decoded = pubkey_from_representative(&repr);
                // DH must agree: peer doing DH with decoded pubkey must get
                // same result as peer doing DH with the "real" pubkey.
                // The dirty pubkey differs from standard mul_base_clamped by a
                // low-order component, which is killed by clamping in DH.
                let mut peer = [0u8; 32];
                OsRng.fill_bytes(&mut peer);
                let dh_from_decoded = decoded.mul_clamped(peer);
                let standard_pub = MontgomeryPoint::mul_base_clamped(secret);
                let dh_from_standard = standard_pub.mul_clamped(peer);
                assert_eq!(
                    dh_from_decoded.to_bytes(),
                    dh_from_standard.to_bytes(),
                    "DH mismatch: dirty and standard pubkeys must agree on DH"
                );
                found += 1;
            }
        }
        // ~50% should be representable
        assert!(found > 50, "too few representable points: {found}/256");
    }

    #[test]
    fn decode_any_bytes_succeeds() {
        // Every 32-byte string should decode without panic
        for i in 0u8..=255 {
            let repr = [i; 32];
            let _ = pubkey_from_representative(&repr);
        }
    }
}

#[cfg(test)]
mod go_reference_tests {
    use super::*;

    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Test vectors from Go obfs4 reference (gitlab.com/yawning/obfs4)
    /// using edwards25519-extra/elligator2.MontgomeryFlavor
    /// Format: (privkey, dirty_pubkey, representative, dh_shared_with_fixed_peer)
    const GO_VECTORS: &[(&str, &str, &str, &str)] = &[
        (
            "07102132435c6d7e8f98a9bacbe4f50617203142536c7d8e9fa8b9cadbf40516",
            "276dca70899bf3dc12a90a25b42c77c8b43419d27361d452e565a2f514af547b",
            "1f951cd36fa4a5a5e9e309dd3a229b8d97903399fbce97b52db759a424976110",
            "8fc2795f8c9d28ad275429e249481e23b461c2ce3abaf531e2b6ce553d1f8c04",
        ),
        (
            "0b1c2d3e4f5061728394a5b6c7e8f90a1b2c3d4e5f60718293a4b5c6d7f8091a",
            "78229a8773105ac4b8ea5266f340b3818fe94b46748a01eef68e4485e771344d",
            "73fc82fa7ac2e9a242dce50b1d6d3e2890f8cef2bfe7e24da5c09813d051292d",
            "8c04504e4bcd31069fe42de6a5534ae2c03943da369059e9d49a75519d1f3b1f",
        ),
        (
            "091e2f3c4d5263708196a7b4c5eafb08192e3f4c5d62738091a6b7c4d5fa0b18",
            "3e9cbc3cda79fd048dcac74d612fc65ef2e817f29e0072bf083a585558f0e605",
            "ff7c23872b63fea261799d46000f94026c86c00ecb85240f8eac414a5936df0c",
            "76550fcaa817039458d7d2543719fee231e984535a67cc2805772d5d84c2a51a",
        ),
        (
            "081f2e3d4c5362718097a6b5c4ebfa09182f3e4d5c63728190a7b6c5d4fb0a19",
            "f222ce310ac58879b3045a7c8b68191d58edd4f16fedf0dbdd2d292cb311e606",
            "06c9bacbe8b8ea4ade0fba293c74a8a22024991c6067e0ec5b587215a9fe5738",
            "d963ec91a8c38899cda534a68c2f05410700db752d6ffdbd5ec58cc11377975d",
        ),
        (
            "0d1a2b38495667748592a3b0c1eeff0c1d2a3b485966778495a2b3c0d1fe0f1c",
            "c5bf86037ae1aff54935d7ea0ac77fe736f783518d06a5bf4910802038506a46",
            "43dc4f51899c479700e00b2e65a3df9db31d351b19e0d29fdf50f4bedf74ea33",
            "f06af6b9a8d55472179692375592bbd1efeb0b1d21bf1cc2c35c99cc08257249",
        ),
        (
            "0c1b2a39485766758493a2b1c0effe0d1c2b3a495867768594a3b2c1d0ff0e1d",
            "d8e19c7c739e7f8a395f3fe4f1f153a849b975f4a1cbe8f7ca7e7363d9faa250",
            "5c022575b420d87b35ec05bf5e1d9e64daeffa689a82750e65ccd9ab43d47d38",
            "d47942fa0c4851799d795dde08212fdf3734fe49614d99dc37de9e07c9e3a255",
        ),
        (
            "11063724554a7b68998ebfacddf2e31001362754457a6b9889beafdccde21300",
            "be892e6b8286027aff4643636964af19718cf2333759a4600cdae989345d494b",
            "1f08a902c07758cfa22360a608c0cc612771676da17ff8fbf419ae51caa6872f",
            "1fa47669311e59480bf862497cd8b6884b92ace6e96dcbb26bfa9dd7c2289e7a",
        ),
        (
            "17003122534c7d6e9f88b9aadbf4e51607302152437c6d9e8fb8a9dacbe41506",
            "7f3afd731adfccdf12735b37e92f6b7611daffad1e9fe1e90dda872b458e3545",
            "fa6d3872297e2ce360d6b41edd9fdb6d0434f7f1f4664777194db8b279f5e223",
            "6cc4732959987a2c4c43624d396d727adf85897dc3047e722225c2da57358155",
        ),
        (
            "15023320514e7f6c9d8abba8d9f6e71405322350417e6f9c8dbaabd8c9e61704",
            "dc09139f05bcb1a6d1ecd99e300a0d0ba9af68c3800f58016f9448bdaabcaa2f",
            "ef8f6ee6211a19be9a05126a7672ecd3745e76294f5d97ca63d8ff18a0e9c514",
            "9d3552c6fa8749e33654a24f92322f511d4938ffce40fa23cdb32fec13764a30",
        ),
        (
            "1a0d3c2f5e4170639285b4a7d6f9e81b0a3d2c5f4e71609382b5a4d7c6e9180b",
            "ebdc7fd75a6f34a55291b70fe171048b84719592b249bbfefeb544d1ee11365d",
            "8d3ee385c4e43962a2d61d2960dd9703f71c196aa0bda539d9b9f42155a76f1d",
            "dfef3b268518811b1abf822577ecaaa51949fd592c8e391d66da14a5da71dc7a",
        ),
    ];

    // Fixed peer secret used in Go to compute DH shared secrets
    const PEER_SECRET: &str = "deadbeefcafebabe0123456789abcdeffedcba98765432100011223344556677";

    #[test]
    fn go_reference_representative_from_privkey() {
        for (i, &(priv_hex, _pub_hex, repr_hex, _shared_hex)) in GO_VECTORS.iter().enumerate() {
            let privkey = hex_to_32(priv_hex);
            let expected_repr = hex_to_32(repr_hex);

            let repr = representative_from_privkey_tweaked(&privkey, 0);
            assert!(repr.is_some(), "vector {i}: should be representable");
            assert_eq!(
                repr.unwrap(),
                expected_repr,
                "vector {i}: representative mismatch"
            );
        }
    }

    #[test]
    fn go_reference_representative_to_pubkey() {
        for (i, &(_priv_hex, pub_hex, repr_hex, _shared_hex)) in GO_VECTORS.iter().enumerate() {
            let expected_pub = hex_to_32(pub_hex);
            let repr = hex_to_32(repr_hex);

            let recovered = pubkey_from_representative(&repr);
            assert_eq!(
                recovered.to_bytes(),
                expected_pub,
                "vector {i}: pubkey_from_representative mismatch\n  expected: {pub_hex}\n  got:      {:?}",
                hex::encode(recovered.to_bytes())
            );
        }
    }

    #[test]
    fn go_reference_dh_shared_secret() {
        let peer = hex_to_32(PEER_SECRET);
        for (i, &(_priv_hex, pub_hex, repr_hex, shared_hex)) in GO_VECTORS.iter().enumerate() {
            let expected_pub = hex_to_32(pub_hex);
            let expected_shared = hex_to_32(shared_hex);
            let repr = hex_to_32(repr_hex);

            // Recover pubkey from representative, do DH with fixed peer
            let recovered_pub = pubkey_from_representative(&repr);
            assert_eq!(
                recovered_pub.to_bytes(),
                expected_pub,
                "vector {i}: pubkey mismatch"
            );

            let shared = recovered_pub.mul_clamped(peer);
            assert_eq!(
                shared.to_bytes(),
                expected_shared,
                "vector {i}: DH shared secret mismatch"
            );
        }
    }

    #[test]
    fn go_reference_full_pipeline() {
        // Test the full pipeline: privkey -> representative -> pubkey -> DH
        // The Go "dirty" scalar mult adds a low-order point which is killed
        // by clamping in DH. We verify: representative_from_privkey -> pubkey_from_representative
        // matches Go's expected pubkey, and DH produces the same shared secret.
        let peer = hex_to_32(PEER_SECRET);
        for (i, &(priv_hex, pub_hex, repr_hex, shared_hex)) in GO_VECTORS.iter().enumerate() {
            let privkey = hex_to_32(priv_hex);
            let expected_pub = hex_to_32(pub_hex);
            let expected_repr = hex_to_32(repr_hex);
            let expected_shared = hex_to_32(shared_hex);

            // Step 1: privkey -> representative (must match Go)
            let repr = representative_from_privkey_tweaked(&privkey, 0).unwrap();
            assert_eq!(repr, expected_repr, "vector {i}: repr mismatch");

            // Step 2: representative -> pubkey (must match Go's dirty pubkey)
            let pub_point = pubkey_from_representative(&repr);
            assert_eq!(
                pub_point.to_bytes(),
                expected_pub,
                "vector {i}: pubkey mismatch"
            );

            // Step 3: DH with pubkey (must match Go's shared secret)
            let shared = pub_point.mul_clamped(peer);
            assert_eq!(
                shared.to_bytes(),
                expected_shared,
                "vector {i}: DH mismatch"
            );
        }
    }
}
