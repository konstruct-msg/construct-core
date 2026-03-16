//! Ephemeral Curve25519 keypairs with Elligator2 representatives.
//!
//! Only ~50% of Curve25519 keys have an Elligator2 representative.
//! This module handles the retry loop transparently.

use curve25519_elligator2::montgomery::MontgomeryPoint;
use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use super::elligator2;

/// Maximum number of keypair generation attempts before giving up.
/// In practice, succeeds within 2-3 attempts on average.
const MAX_RETRIES: usize = 64;

/// 20-byte server Node ID (part of obfs4 server identity alongside public key B).
pub type NodeId = [u8; 20];

/// Static server identity keypair — loaded from config, long-lived.
#[derive(ZeroizeOnDrop)]
pub struct StaticKeypair {
    /// Server's Curve25519 public key.
    #[zeroize(skip)]
    pub public: MontgomeryPoint,
    /// Server's Curve25519 secret key (32 bytes).
    pub secret: [u8; 32],
    /// Server's Node ID (20 bytes) — distributed to clients out-of-band.
    #[zeroize(skip)]
    pub node_id: NodeId,
}

/// Ephemeral keypair guaranteed to have an Elligator2 representative.
/// Used in the handshake — the representative is sent on the wire.
#[derive(ZeroizeOnDrop)]
pub struct EphemeralKeypair {
    /// Curve25519 public key (derived from representative, not scalar mult).
    #[zeroize(skip)]
    pub public: MontgomeryPoint,
    /// Curve25519 secret key (32 bytes).
    pub secret: [u8; 32],
    /// Elligator2 representative — always valid, guaranteed by construction.
    #[zeroize(skip)]
    pub representative: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate an ephemeral keypair that has an Elligator2 representative.
    ///
    /// Retries up to [`MAX_RETRIES`] times. Average: 2 attempts.
    ///
    /// # Panics
    /// Panics if no representable key found after MAX_RETRIES (probability ~2^-64).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        for _ in 0..MAX_RETRIES {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);

            let tweak = elligator2::random_tweak(rng);

            if let Some(representative) =
                elligator2::representative_from_privkey_tweaked(&secret, tweak)
            {
                // Derive public key from representative to guarantee it matches
                // what peers will recover. The dirty scalar mult adds a low-order
                // point that from_representative accounts for.
                let public = elligator2::pubkey_from_representative(&representative);
                return EphemeralKeypair {
                    public,
                    secret,
                    representative,
                };
            }
        }
        panic!("Failed to generate Elligator2-representable keypair after {MAX_RETRIES} retries");
    }

    /// Perform X25519 DH with a peer's public key.
    pub fn diffie_hellman(&self, peer_public: &MontgomeryPoint) -> [u8; 32] {
        peer_public.mul_clamped(self.secret).to_bytes()
    }
}

impl StaticKeypair {
    /// Generate a new static keypair with a random Node ID (for server identity).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let public = MontgomeryPoint::mul_base_clamped(secret);

        let mut node_id = [0u8; 20];
        rng.fill_bytes(&mut node_id);

        StaticKeypair {
            public,
            secret,
            node_id,
        }
    }

    /// Load keypair from raw secret bytes and node ID.
    pub fn from_secret(secret: [u8; 32], node_id: NodeId) -> Self {
        let public = MontgomeryPoint::mul_base_clamped(secret);
        StaticKeypair {
            public,
            secret,
            node_id,
        }
    }

    /// Perform X25519 DH with a peer's public key using the static secret.
    pub fn diffie_hellman(&self, peer_public: &MontgomeryPoint) -> [u8; 32] {
        peer_public.mul_clamped(self.secret).to_bytes()
    }

    /// The identity key material: `B || NODEID` (52 bytes).
    /// Used as HMAC key in the handshake.
    pub fn identity_bytes(&self) -> [u8; 52] {
        let mut out = [0u8; 52];
        out[..32].copy_from_slice(self.public.as_bytes());
        out[32..].copy_from_slice(&self.node_id);
        out
    }

    /// Encode the bridge credential in Go obfs4proxy-compatible format.
    ///
    /// Format: `base64(nodeID[20] || pubKey[32])` with trailing `==` stripped.
    /// This matches the `cert=` field in a standard obfs4 bridge line:
    /// `Bridge obfs4 <IP>:<port> <fingerprint> cert=<this>,iat-mode=0`
    ///
    /// Note: the HMAC key used in the handshake (`identity_bytes()`) uses
    /// `pubKey || nodeID` order — that is a separate, internal value.
    pub fn bridge_cert(&self) -> String {
        use base64::Engine;
        let mut raw = Vec::with_capacity(52);
        raw.extend_from_slice(&self.node_id); // nodeID first — Go order
        raw.extend_from_slice(self.public.as_bytes());
        // Strip trailing '=' padding to match Go's certSuffix trimming
        base64::engine::general_purpose::STANDARD
            .encode(&raw)
            .trim_end_matches('=')
            .to_owned()
    }

    /// Parse a bridge cert string back to (public key, node ID).
    ///
    /// Accepts both padded (`==`) and unpadded (Go-style) base64.
    /// Format: `base64(nodeID[20] || pubKey[32])`.
    pub fn parse_bridge_cert(cert: &str) -> crate::Result<([u8; 32], NodeId)> {
        use base64::Engine;
        // Re-add padding if stripped (Go style: always 52 bytes → trailing "==")
        let padded = match cert.len() % 4 {
            2 => format!("{cert}=="),
            3 => format!("{cert}="),
            _ => cert.to_owned(),
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&padded)
            .map_err(|e| crate::Error::InvalidServerPublicKey(e.to_string()))?;
        if bytes.len() != 52 {
            return Err(crate::Error::InvalidServerPublicKey(format!(
                "expected 52 bytes, got {}",
                bytes.len()
            )));
        }
        // nodeID first (bytes 0..20), then pubKey (bytes 20..52)
        let mut node_id = [0u8; 20];
        let mut pubkey = [0u8; 32];
        node_id.copy_from_slice(&bytes[..20]);
        pubkey.copy_from_slice(&bytes[20..]);
        Ok((pubkey, node_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn ephemeral_keypair_has_representative() {
        let epk = EphemeralKeypair::generate(&mut OsRng);
        // Decode the representative back to a point
        let decoded = elligator2::pubkey_from_representative(&epk.representative);
        assert_eq!(epk.public, decoded);
    }

    #[test]
    fn static_keypair_roundtrip() {
        let sk = StaticKeypair::generate(&mut OsRng);
        let sk2 = StaticKeypair::from_secret(sk.secret, sk.node_id);
        assert_eq!(sk.public, sk2.public);
    }

    #[test]
    fn bridge_cert_roundtrip() {
        let sk = StaticKeypair::generate(&mut OsRng);
        let cert = sk.bridge_cert();

        // Go-compatible: no trailing '='
        assert!(!cert.ends_with('='), "cert should not have padding");
        // 52 bytes → 70 base64 chars (without padding)
        assert_eq!(cert.len(), 70, "cert length should be 70 (Go-compatible)");

        let (pubkey, node_id) = StaticKeypair::parse_bridge_cert(&cert).unwrap();
        assert_eq!(pubkey, sk.public.to_bytes());
        assert_eq!(node_id, sk.node_id);
    }

    #[test]
    fn bridge_cert_accepts_padded_and_unpadded() {
        let sk = StaticKeypair::generate(&mut OsRng);
        let cert_no_pad = sk.bridge_cert();
        let cert_padded = format!("{cert_no_pad}==");

        // Both forms should parse correctly
        let (pub1, id1) = StaticKeypair::parse_bridge_cert(&cert_no_pad).unwrap();
        let (pub2, id2) = StaticKeypair::parse_bridge_cert(&cert_padded).unwrap();
        assert_eq!(pub1, pub2);
        assert_eq!(id1, id2);
    }

    #[test]
    fn dh_agreement() {
        let a = EphemeralKeypair::generate(&mut OsRng);
        let b = EphemeralKeypair::generate(&mut OsRng);
        let shared_ab = a.diffie_hellman(&b.public);
        let shared_ba = b.diffie_hellman(&a.public);
        assert_eq!(shared_ab, shared_ba);
    }
}
