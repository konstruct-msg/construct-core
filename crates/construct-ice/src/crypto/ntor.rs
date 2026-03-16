//! ntor handshake key exchange for obfs4.
//!
//! Based on the Tor ntor handshake (proposal 216) adapted for obfs4.
//! Derives a shared KEY_SEED and an authentication tag AUTH from a
//! double Diffie-Hellman exchange.
//!
//! ## Protocol
//!
//! Client has: ephemeral keypair (X, x), server static pubkey B, NODEID
//! Server has: static keypair (B, b), ephemeral keypair (Y, y)
//!
//! ```text
//! secret_input = x25519(x, Y) || x25519(x, B) || ID || B || X || Y || PROTOID
//! KEY_SEED = HMAC-SHA256(secret_input, t_key)
//! verify   = HMAC-SHA256(secret_input, t_verify)
//! auth_input = verify || ID || B || Y || X || PROTOID || "Server"
//! AUTH = HMAC-SHA256(auth_input, t_mac)
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::keypair::{EphemeralKeypair, NodeId, StaticKeypair};
use curve25519_elligator2::montgomery::MontgomeryPoint;

type HmacSha256 = Hmac<Sha256>;

// ── ntor Protocol Constants ─────────────────────────────────────────────────

const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:key_verify";
const SERVER_STR: &[u8] = b"Server";

/// Result of ntor key exchange.
pub struct NtorResult {
    /// 256-bit shared secret for key derivation.
    pub key_seed: [u8; 32],
    /// 256-bit authentication tag (server → client proof).
    pub auth: [u8; 32],
}

// ── Client Side ─────────────────────────────────────────────────────────────

/// Client-side ntor: compute KEY_SEED and expected AUTH tag.
///
/// # Arguments
/// * `epk` — client's ephemeral keypair (X, x)
/// * `server_pubkey` — server's static public key B
/// * `node_id` — server's 20-byte Node ID
/// * `server_epk_point` — server's ephemeral public key Y (decoded from Elligator2)
pub fn client_ntor(
    epk: &EphemeralKeypair,
    server_pubkey: &MontgomeryPoint,
    node_id: &NodeId,
    server_epk_point: &MontgomeryPoint,
) -> NtorResult {
    // DH: x25519(x, Y) and x25519(x, B)
    let xy = epk.diffie_hellman(server_epk_point);
    let xb = epk.diffie_hellman(server_pubkey);

    compute_ntor(
        &xy,
        &xb,
        node_id,
        server_pubkey,
        &epk.public,
        server_epk_point,
    )
}

// ── Server Side ─────────────────────────────────────────────────────────────

/// Server-side ntor: compute KEY_SEED and AUTH tag to send to client.
///
/// # Arguments
/// * `static_kp` — server's static keypair (B, b)
/// * `server_epk` — server's ephemeral keypair (Y, y)
/// * `client_point` — client's public key X (decoded from Elligator2)
pub fn server_ntor(
    static_kp: &StaticKeypair,
    server_epk: &EphemeralKeypair,
    client_point: &MontgomeryPoint,
) -> NtorResult {
    // DH: x25519(y, X) and x25519(b, X)
    let yx = server_epk.diffie_hellman(client_point);
    let bx = static_kp.diffie_hellman(client_point);

    compute_ntor(
        &yx,
        &bx,
        &static_kp.node_id,
        &static_kp.public,
        client_point,
        &server_epk.public,
    )
}

// ── Shared Computation ──────────────────────────────────────────────────────

fn compute_ntor(
    dh_ephemeral: &[u8; 32], // x25519(x,Y) or x25519(y,X)
    dh_static: &[u8; 32],    // x25519(x,B) or x25519(b,X)
    node_id: &NodeId,
    server_pubkey: &MontgomeryPoint,
    client_pubkey: &MontgomeryPoint,     // X
    server_epk_pubkey: &MontgomeryPoint, // Y
) -> NtorResult {
    // secret_input = EXP(Y,x) || EXP(B,x) || ID || B || X || Y || PROTOID
    let mut secret_input = Vec::with_capacity(32 + 32 + 20 + 32 + 32 + 32 + PROTOID.len());
    secret_input.extend_from_slice(dh_ephemeral);
    secret_input.extend_from_slice(dh_static);
    secret_input.extend_from_slice(node_id);
    secret_input.extend_from_slice(server_pubkey.as_bytes());
    secret_input.extend_from_slice(client_pubkey.as_bytes());
    secret_input.extend_from_slice(server_epk_pubkey.as_bytes());
    secret_input.extend_from_slice(PROTOID);

    // KEY_SEED = HMAC-SHA256(key=t_key, msg=secret_input)
    let key_seed = hmac_sha256(T_KEY, &secret_input);

    // verify = HMAC-SHA256(key=t_verify, msg=secret_input)
    let verify = hmac_sha256(T_VERIFY, &secret_input);

    // auth_input = verify || ID || B || Y || X || PROTOID || "Server"
    let mut auth_input =
        Vec::with_capacity(32 + 20 + 32 + 32 + 32 + PROTOID.len() + SERVER_STR.len());
    auth_input.extend_from_slice(&verify);
    auth_input.extend_from_slice(node_id);
    auth_input.extend_from_slice(server_pubkey.as_bytes());
    auth_input.extend_from_slice(server_epk_pubkey.as_bytes());
    auth_input.extend_from_slice(client_pubkey.as_bytes());
    auth_input.extend_from_slice(PROTOID);
    auth_input.extend_from_slice(SERVER_STR);

    // AUTH = HMAC-SHA256(key=t_mac, msg=auth_input)
    let auth = hmac_sha256(T_MAC, &auth_input);

    NtorResult { key_seed, auth }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length ok");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn client_server_ntor_agree() {
        let server_static = StaticKeypair::generate(&mut OsRng);
        let client_epk = EphemeralKeypair::generate(&mut OsRng);
        let server_epk = EphemeralKeypair::generate(&mut OsRng);

        let client_result = client_ntor(
            &client_epk,
            &server_static.public,
            &server_static.node_id,
            &server_epk.public,
        );

        let server_result = server_ntor(&server_static, &server_epk, &client_epk.public);

        assert_eq!(
            client_result.key_seed, server_result.key_seed,
            "KEY_SEED mismatch"
        );
        assert_eq!(client_result.auth, server_result.auth, "AUTH mismatch");
    }

    #[test]
    fn different_server_gives_different_keys() {
        let server1 = StaticKeypair::generate(&mut OsRng);
        let server2 = StaticKeypair::generate(&mut OsRng);
        let client_epk = EphemeralKeypair::generate(&mut OsRng);
        let server_epk = EphemeralKeypair::generate(&mut OsRng);

        let r1 = client_ntor(
            &client_epk,
            &server1.public,
            &server1.node_id,
            &server_epk.public,
        );
        let r2 = client_ntor(
            &client_epk,
            &server2.public,
            &server2.node_id,
            &server_epk.public,
        );

        assert_ne!(r1.key_seed, r2.key_seed);
    }

    /// Cross-reference test with Go obfs4 implementation.
    /// Values generated using Go x25519+ntor with dirty Elligator2 pubkeys.
    #[test]
    fn go_reference_ntor_vectors() {
        fn h(s: &str) -> [u8; 32] {
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }
        fn h20(s: &str) -> [u8; 20] {
            let mut out = [0u8; 20];
            for i in 0..20 {
                out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }

        // Fixed test values from Go
        let client_priv = h("07102132435c6d7e8f98a9bacbe4f50617203142536c7d8e9fa8b9cadbf40516");
        let server_static_priv =
            h("a8abababababababababababababababababababababababababababababababab");
        let server_eph_priv = h("0b1c2d3e4f5061728394a5b6c7e8f90a1b2c3d4e5f60718293a4b5c6d7f8091a");
        let node_id = h20("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

        // Dirty pubkeys (from Go Elligator2)
        let client_dirty_pub = MontgomeryPoint(h(
            "276dca70899bf3dc12a90a25b42c77c8b43419d27361d452e565a2f514af547b",
        ));
        let server_dirty_eph = MontgomeryPoint(h(
            "78229a8773105ac4b8ea5266f340b3818fe94b46748a01eef68e4485e771344d",
        ));
        // Server static pub (standard X25519)
        let server_static_pub = MontgomeryPoint::mul_base_clamped(server_static_priv);
        assert_eq!(
            hex::encode(server_static_pub.to_bytes()),
            "e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859"
        );

        // Client-side DH
        let xy = server_dirty_eph.mul_clamped(client_priv);
        let xb = server_static_pub.mul_clamped(client_priv);

        // Verify DH values match Go
        assert_eq!(
            hex::encode(xy.to_bytes()),
            "3f275b8273197f1155410218a26a238df58bca173468ada4ba8ee9e43f473e74"
        );
        assert_eq!(
            hex::encode(xb.to_bytes()),
            "c7be57c2b73b7e585f6920922b2267ea7b4024f7e5082ea1fb602d833df72832"
        );

        // Server-side DH (verify agreement)
        let yx = client_dirty_pub.mul_clamped(server_eph_priv);
        let bx = client_dirty_pub.mul_clamped(server_static_priv);
        assert_eq!(xy.to_bytes(), yx.to_bytes(), "xy != yx");
        assert_eq!(xb.to_bytes(), bx.to_bytes(), "xb != bx");

        let result = compute_ntor(
            &xy.to_bytes(),
            &xb.to_bytes(),
            &node_id,
            &server_static_pub,
            &client_dirty_pub,
            &server_dirty_eph,
        );

        // Expected from Go
        assert_eq!(
            hex::encode(result.key_seed),
            "86ff4ea92c7c913fd2fa3df39c4153175ea8060e94df06fd6fa0fff66de6376e",
            "KEY_SEED mismatch with Go reference"
        );
        assert_eq!(
            hex::encode(result.auth),
            "408f252b603b71ff9902937a9c39344ba2788ebf8b482cde26fb8a8c5ce7c74f",
            "AUTH mismatch with Go reference"
        );
    }
}
