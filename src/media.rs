//! Media blobs — the encrypted file a media message points to.
//!
//! Until 0.33 each client sealed media itself (CryptoKit on iOS, `javax.crypto` on Android) as
//! the file exactly as it was: `nonce(12) ‖ ct ‖ tag(16)`. The server, and anyone watching the
//! upload, saw the size to the byte — enough to tell a voice note from a photo from a short video,
//! and to recognise a known file outright. Two clients writing the same format by hand is also the
//! thing `AGENTS.md` forbids; so the format is here, and the size is padded.
//!
//! ```text
//! v1 blob   : nonce(12) ‖ AES-256-GCM(key, nonce, ad = "konstruct-media-v1", P) ‖ tag(16)
//! P         : len(u64 BE) ‖ file ‖ 0x00 … 0x00
//! |blob|    : max(Padmé(28 + 8 + |file|), 4096), clamped to MEDIA_MAX_BLOB_LEN
//! legacy    : nonce(12) ‖ AES-256-GCM(key, nonce, no ad, file) ‖ tag(16)
//! ```
//!
//! **Padmé** (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication
//! with PURBs", PETS 2019) keeps only the top ⌊log₂ log₂ L⌋ + 1 significant bits of the length.
//! The overhead is at most 12 % and falls with size — about 3 % from 64 KiB up — while what a
//! length reveals falls from log L bits to log log L. Power-of-two buckets leak less still but
//! double a video for one byte over the line.
//!
//! **The version is told apart by the AEAD, not by a marker.** A v1 blob is opened with the v1
//! associated data and a legacy blob without any; a blob of one kind can never authenticate as the
//! other, so trying v1 and then legacy is exact, and the server sees no version byte. A client
//! that predates v1 fails to open a v1 blob — loudly, with an authentication error — instead of
//! handing a document on with a tail of zeros.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Length of a media key, in bytes.
pub const MEDIA_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const LEN_PREFIX: usize = 8;
const V1_AD: &[u8] = b"konstruct-media-v1";

/// The largest blob the media service takes: the `max_file_size_bytes` it advertises in
/// `/.well-known/construct-server` (decimal 100 MB — the service itself allows 100 MiB, and the
/// smaller of the two is the one a client can rely on).
pub const MEDIA_MAX_BLOB_LEN: u64 = 100_000_000;

/// No blob is smaller than this. Below it Padmé's buckets are a few bytes apart, and a small file
/// — an avatar, a short voice note — would be told apart by size as well as ever.
pub const MEDIA_MIN_BLOB_LEN: u64 = 4096;

const V1_OVERHEAD: u64 = (NONCE_LEN + TAG_LEN + LEN_PREFIX) as u64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MediaError {
    #[error("media file is {0} bytes; the largest that fits a blob is {max}", max = max_plaintext_len())]
    TooLarge(u64),
    #[error("media key must be {MEDIA_KEY_LEN} bytes, got {0}")]
    InvalidKey(usize),
    #[error("media blob does not open with this key")]
    Unauthenticated,
    #[error("media blob opened but its padding is malformed")]
    MalformedPadding,
}

/// A sealed media file: the blob to upload, the key the message carries, and the SHA-256 of the
/// blob the message carries beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMedia {
    pub key: Vec<u8>,
    pub blob: Vec<u8>,
    pub sha256: Vec<u8>,
}

/// The largest file `seal_media` accepts.
pub const fn max_plaintext_len() -> u64 {
    MEDIA_MAX_BLOB_LEN - V1_OVERHEAD
}

/// Padmé: `len` rounded up so that only its top ⌊log₂ ⌊log₂ len⌋⌋ + 1 bits may be set.
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - len.leading_zeros(); // ⌊log₂ len⌋, ≥ 1
    let s = 32 - e.leading_zeros(); // ⌊log₂ e⌋ + 1
    let mask = (1u64 << (e - s)) - 1;
    (len + mask) & !mask
}

/// The size of the v1 blob for a file of `plaintext_len` bytes — what the server will see.
pub fn blob_len(plaintext_len: u64) -> Result<u64, MediaError> {
    if plaintext_len > max_plaintext_len() {
        return Err(MediaError::TooLarge(plaintext_len));
    }
    let raw = plaintext_len + V1_OVERHEAD;
    Ok(padme(raw).clamp(MEDIA_MIN_BLOB_LEN, MEDIA_MAX_BLOB_LEN))
}

/// Seal `plaintext` under a fresh key as a v1 blob.
pub fn seal_media(plaintext: &[u8]) -> Result<SealedMedia, MediaError> {
    let mut key = [0u8; MEDIA_KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let sealed = seal_with(&key, &nonce, plaintext)?;
    Ok(sealed)
}

fn seal_with(
    key: &[u8; MEDIA_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<SealedMedia, MediaError> {
    let total = blob_len(plaintext.len() as u64)? as usize;
    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    blob.extend_from_slice(plaintext);
    blob.resize(total - TAG_LEN, 0);

    let cipher = Aes256Gcm::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), V1_AD, &mut blob[NONCE_LEN..])
        // Only fails past GCM's 64 GiB message limit, which MEDIA_MAX_BLOB_LEN is far below.
        .expect("a media blob is within the AES-GCM message limit");
    blob.extend_from_slice(&tag);
    debug_assert_eq!(blob.len(), total);

    let sha256 = Sha256::digest(&blob).to_vec();
    Ok(SealedMedia {
        key: key.to_vec(),
        blob,
        sha256,
    })
}

/// Open a media blob of either format.
pub fn open_media(key: &[u8], blob: &[u8]) -> Result<Vec<u8>, MediaError> {
    if key.len() != MEDIA_KEY_LEN {
        return Err(MediaError::InvalidKey(key.len()));
    }
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(MediaError::Unauthenticated);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| MediaError::InvalidKey(key.len()))?;
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let tag = Tag::from_slice(&blob[blob.len() - TAG_LEN..]);
    let body = &blob[NONCE_LEN..blob.len() - TAG_LEN];

    let mut buf = body.to_vec();
    if cipher
        .decrypt_in_place_detached(nonce, V1_AD, &mut buf, tag)
        .is_ok()
    {
        return unpad(buf);
    }

    // Not v1. The buffer is rewritten from the blob rather than trusted to be untouched by the
    // failed attempt.
    buf.copy_from_slice(body);
    cipher
        .decrypt_in_place_detached(nonce, b"", &mut buf, tag)
        .map_err(|_| MediaError::Unauthenticated)?;
    Ok(buf)
}

/// `len ‖ file ‖ zeros` → `file`. The padding is authenticated already; it is still required to be
/// exactly what `seal_media` writes, so there is one encoding of each file and not many.
fn unpad(mut padded: Vec<u8>) -> Result<Vec<u8>, MediaError> {
    if padded.len() < LEN_PREFIX {
        return Err(MediaError::MalformedPadding);
    }
    let mut prefix = [0u8; LEN_PREFIX];
    prefix.copy_from_slice(&padded[..LEN_PREFIX]);
    let len = u64::from_be_bytes(prefix);
    let end = usize::try_from(len)
        .ok()
        .and_then(|l| l.checked_add(LEN_PREFIX))
        .filter(|&end| end <= padded.len())
        .ok_or(MediaError::MalformedPadding)?;
    if padded[end..].iter().any(|&b| b != 0) {
        return Err(MediaError::MalformedPadding);
    }
    padded.truncate(end);
    padded.drain(..LEN_PREFIX);
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const NONCE: [u8; 12] = [9; 12];

    fn legacy_seal(key: &[u8; 32], nonce: &[u8; 12], file: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(key.into());
        let mut buf = file.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), b"", &mut buf)
            .unwrap();
        [nonce.as_slice(), &buf, &tag].concat()
    }

    #[test]
    fn padme_matches_the_paper() {
        // Values from the PURBs paper's definition, worked by hand.
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(7), 7); // e=2, s=2: no bits dropped
        assert_eq!(padme(9), 10); // e=3, s=2: one bit
        assert_eq!(padme(1000), 1024); // e=9, s=4: five bits
        assert_eq!(padme(1025), 1088); // e=10, s=4: six bits
        assert_eq!(padme(1_000_000), 1_015_808); // e=19, s=5: fourteen bits
    }

    #[test]
    fn padme_overhead_stays_under_twelve_percent_and_never_shrinks() {
        let mut len = 2u64;
        while len < 1 << 40 {
            for l in [len, len + 1, len * 3 / 2] {
                let p = padme(l);
                assert!(p >= l, "{l} → {p}");
                assert!((p - l) * 100 <= l * 12, "{l} → {p}");
            }
            len *= 2;
        }
    }

    #[test]
    fn blob_len_is_a_bucket_with_a_floor_and_a_ceiling() {
        assert_eq!(blob_len(0).unwrap(), MEDIA_MIN_BLOB_LEN);
        assert_eq!(blob_len(1000).unwrap(), MEDIA_MIN_BLOB_LEN);
        assert_eq!(blob_len(1_000_000).unwrap(), padme(1_000_036));
        assert_eq!(blob_len(max_plaintext_len()).unwrap(), MEDIA_MAX_BLOB_LEN);
        // Just under the ceiling Padmé would round past it; the service would refuse that.
        assert_eq!(blob_len(99_000_000).unwrap(), MEDIA_MAX_BLOB_LEN);
        assert_eq!(
            blob_len(max_plaintext_len() + 1),
            Err(MediaError::TooLarge(max_plaintext_len() + 1))
        );
    }

    #[test]
    fn files_of_nearby_sizes_share_a_blob_size() {
        let a = seal_with(&KEY, &NONCE, &vec![1u8; 1_000_000]).unwrap();
        let b = seal_with(&KEY, &NONCE, &vec![1u8; 1_010_000]).unwrap();
        assert_eq!(a.blob.len(), b.blob.len());
    }

    #[test]
    fn v1_round_trips_at_every_boundary() {
        for len in [0usize, 1, 4060, 4061, 4096, 65_536, 1_000_000] {
            let file: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let sealed = seal_media(&file).unwrap();
            assert_eq!(sealed.blob.len() as u64, blob_len(len as u64).unwrap());
            assert_eq!(sealed.sha256, Sha256::digest(&sealed.blob).to_vec());
            assert_eq!(
                open_media(&sealed.key, &sealed.blob).unwrap(),
                file,
                "{len}"
            );
        }
    }

    #[test]
    fn a_file_ending_in_zeros_keeps_them() {
        let file = [1, 2, 0, 0, 0];
        let sealed = seal_media(&file).unwrap();
        assert_eq!(open_media(&sealed.key, &sealed.blob).unwrap(), file);
    }

    #[test]
    fn legacy_blobs_still_open() {
        let file = b"a photo sent before 0.33";
        let blob = legacy_seal(&KEY, &NONCE, file);
        assert_eq!(open_media(&KEY, &blob).unwrap(), file);
    }

    /// What both platforms' pre-0.33 code wrote for this key, nonce and file — CryptoKit's
    /// `combined` form on iOS, `MediaCrypto.seal` on Android. A platform test seals the same input
    /// with its own AES-GCM and compares against these bytes.
    const LEGACY_VECTOR: &str =
        "0909090909090909090909094ceaeae7ca82b402d45b2c4d098ff3e8d8546682abc9e5f8ab";

    #[test]
    fn legacy_vector() {
        assert_eq!(
            hex::encode(legacy_seal(&KEY, &NONCE, b"konstruct")),
            LEGACY_VECTOR
        );
        let blob = hex::decode(LEGACY_VECTOR).unwrap();
        assert_eq!(open_media(&KEY, &blob).unwrap(), b"konstruct");
    }

    /// The v1 blob for the same input: 4096 bytes (the floor), pinned by its SHA-256. A change to
    /// the layout, the associated data or the bucket function changes this.
    #[test]
    fn v1_vector() {
        let sealed = seal_with(&KEY, &NONCE, b"konstruct").unwrap();
        assert_eq!(sealed.blob.len(), 4096);
        assert_eq!(
            hex::encode(&sealed.sha256),
            "813616d433cb4c87fb1ba7e2fe54c3be82f6c8dd5f5e8d2f1aff7195ce55ed49"
        );
    }

    #[test]
    fn a_v1_blob_does_not_open_as_legacy() {
        // What a client that predates v1 does with one: it must fail, not return the padding.
        let sealed = seal_with(&KEY, &NONCE, b"konstruct").unwrap();
        let cipher = Aes256Gcm::new((&KEY).into());
        let mut body = sealed.blob[12..sealed.blob.len() - 16].to_vec();
        let tag = Tag::from_slice(&sealed.blob[sealed.blob.len() - 16..]);
        assert!(
            cipher
                .decrypt_in_place_detached(Nonce::from_slice(&NONCE), b"", &mut body, tag)
                .is_err()
        );
    }

    #[test]
    fn the_wrong_key_or_a_flipped_bit_is_refused() {
        let sealed = seal_media(b"konstruct").unwrap();
        assert_eq!(
            open_media(&[0u8; 32], &sealed.blob),
            Err(MediaError::Unauthenticated)
        );
        for i in [0, 12, sealed.blob.len() / 2, sealed.blob.len() - 1] {
            let mut blob = sealed.blob.clone();
            blob[i] ^= 1;
            assert_eq!(
                open_media(&sealed.key, &blob),
                Err(MediaError::Unauthenticated),
                "byte {i}"
            );
        }
        assert_eq!(
            open_media(&sealed.key, &sealed.blob[..sealed.blob.len() - 1]),
            Err(MediaError::Unauthenticated)
        );
    }

    #[test]
    fn bad_inputs_are_refused_without_panicking() {
        assert_eq!(
            open_media(&[0; 31], &[0; 64]),
            Err(MediaError::InvalidKey(31))
        );
        assert_eq!(open_media(&KEY, &[0; 27]), Err(MediaError::Unauthenticated));
        assert_eq!(open_media(&KEY, &[]), Err(MediaError::Unauthenticated));
    }

    /// A v1 plaintext that authenticates but was not written by `seal_media` — a length past the
    /// end, or a non-zero tail — is refused rather than truncated or read past.
    #[test]
    fn malformed_padding_is_refused() {
        let seal_raw = |p: &[u8]| {
            let cipher = Aes256Gcm::new((&KEY).into());
            let mut buf = p.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&NONCE), V1_AD, &mut buf)
                .unwrap();
            [NONCE.as_slice(), &buf, &tag].concat()
        };
        let mut long = 100u64.to_be_bytes().to_vec();
        long.extend_from_slice(&[0; 10]);
        assert_eq!(
            open_media(&KEY, &seal_raw(&long)),
            Err(MediaError::MalformedPadding)
        );

        let mut huge = u64::MAX.to_be_bytes().to_vec();
        huge.extend_from_slice(&[0; 10]);
        assert_eq!(
            open_media(&KEY, &seal_raw(&huge)),
            Err(MediaError::MalformedPadding)
        );

        let mut dirty = 2u64.to_be_bytes().to_vec();
        dirty.extend_from_slice(&[5, 6, 0, 1]);
        assert_eq!(
            open_media(&KEY, &seal_raw(&dirty)),
            Err(MediaError::MalformedPadding)
        );

        assert_eq!(
            open_media(&KEY, &seal_raw(&[0; 7])),
            Err(MediaError::MalformedPadding)
        );
    }
}
