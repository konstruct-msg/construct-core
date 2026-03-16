//! SipHash-2-4 OFB mode for frame length obfuscation.
//!
//! obfs4 obfuscates the 2-byte frame length field by XORing with a mask
//! derived from SipHash-2-4 in OFB (Output Feedback) mode.
//!
//! ```text
//! IV[0] = from KDF (8 bytes)
//! IV[n] = SipHash-2-4(K, IV[n-1])
//! Mask[n] = first 2 bytes of IV[n]
//! obfuscated_length = length ^ Mask[n]
//! ```

use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// SipHash-2-4 OFB state for frame length masking.
pub struct LengthObfuscator {
    key0: u64,
    key1: u64,
    iv: u64,
}

impl LengthObfuscator {
    /// Create a new obfuscator from the 16-byte SipHash key and 8-byte OFB IV from KDF.
    pub fn new(siphash_key: &[u8; 16], siphash_iv: &[u8; 8]) -> Self {
        let key0 = u64::from_le_bytes(siphash_key[0..8].try_into().unwrap());
        let key1 = u64::from_le_bytes(siphash_key[8..16].try_into().unwrap());
        let iv = u64::from_le_bytes(*siphash_iv);
        LengthObfuscator { key0, key1, iv }
    }

    /// Advance the OFB state and return the next 2-byte mask.
    fn next_mask(&mut self) -> [u8; 2] {
        let mut h = SipHasher24::new_with_keys(self.key0, self.key1);
        h.write_u64(self.iv);
        self.iv = h.finish();
        let bytes = self.iv.to_le_bytes();
        [bytes[0], bytes[1]]
    }

    /// Obfuscate (XOR) a 2-byte frame length for transmission.
    pub fn mask_length(&mut self, length: u16) -> [u8; 2] {
        let mask = self.next_mask();
        let len_bytes = length.to_be_bytes(); // Big-endian per spec
        [len_bytes[0] ^ mask[0], len_bytes[1] ^ mask[1]]
    }

    /// De-obfuscate a received 2-byte frame length.
    pub fn unmask_length(&mut self, obfuscated: &[u8; 2]) -> u16 {
        let mask = self.next_mask();
        let unmasked = [obfuscated[0] ^ mask[0], obfuscated[1] ^ mask[1]];
        u16::from_be_bytes(unmasked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_unmask_roundtrip() {
        let key = [0x01u8; 16];
        let iv = [0x02u8; 8];

        let mut enc = LengthObfuscator::new(&key, &iv);
        let mut dec = LengthObfuscator::new(&key, &iv);

        for length in [0u16, 1, 100, 1448, 65535] {
            let masked = enc.mask_length(length);
            let recovered = dec.unmask_length(&masked);
            assert_eq!(length, recovered, "round-trip failed for length {length}");
        }
    }

    #[test]
    fn masked_looks_different_from_plaintext() {
        let key = [0xab_u8; 16];
        let iv = [0xcd_u8; 8];
        let mut obf = LengthObfuscator::new(&key, &iv);

        let masked = obf.mask_length(100);
        let plain = 100u16.to_be_bytes();
        // Very unlikely to be identical (would need mask = [0,0])
        assert_ne!(masked, plain);
    }

    #[test]
    fn deterministic_sequence() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 8];

        let mut a = LengthObfuscator::new(&key, &iv);
        let mut b = LengthObfuscator::new(&key, &iv);

        for _ in 0..100 {
            assert_eq!(a.mask_length(42), b.mask_length(42));
        }
    }
}
