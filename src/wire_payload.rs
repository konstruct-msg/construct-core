//! Wire payload format for encrypted messages sent over gRPC.
//!
//! This module implements the binary framing used by both iOS and Android clients.
//! Centralising it in the Rust core ensures byte-perfect interop and avoids
//! duplicating the format in each platform SDK.
//!
//! # Layout (little-endian)
//! ```text
//! [4 bytes]  message_number        (u32 LE)
//! [32 bytes] dh_public_key         (X25519 ephemeral public key)
//! [4 bytes]  one_time_prekey_id    (u32 LE; 0 = no OTPK used)
//! [4 bytes]  kyber_otpk_id         (u32 LE; 0 = Kyber SPK used; >0 = Kyber OTPK ID)
//! [2 bytes]  kem_ciphertext_len    (u16 LE; 0 = no PQC)
//! [4 bytes]  previous_chain_length (u32 LE; DR PN field for out-of-order recovery)
//! [2 bytes]  suite_id              (u16 LE; crypto-suite identifier)
//! [N bytes]  kem_ciphertext        (present only when kem_ciphertext_len > 0)
//! [rest]     sealed_box            (nonce || ciphertext || auth_tag)
//! ```
//!
//! The server stores and forwards the payload opaquely without inspecting its contents.

const MSG_NUM_SIZE: usize = 4;
const DH_KEY_SIZE: usize = 32;
const OTPK_ID_SIZE: usize = 4;
const KYBER_OTPK_ID_SIZE: usize = 4;
const KEM_LEN_SIZE: usize = 2;
const PREV_CHAIN_LEN_SIZE: usize = 4;
const SUITE_ID_SIZE: usize = 2;
/// Fixed header size (no KEM ciphertext): 52 bytes.
pub const HEADER_SIZE: usize = MSG_NUM_SIZE
    + DH_KEY_SIZE
    + OTPK_ID_SIZE
    + KYBER_OTPK_ID_SIZE
    + KEM_LEN_SIZE
    + PREV_CHAIN_LEN_SIZE
    + SUITE_ID_SIZE;

#[derive(Debug, Clone)]
pub struct DecodedWirePayload {
    pub message_number: u32,
    /// 32-byte X25519 ephemeral public key.
    pub dh_public_key: Vec<u8>,
    pub one_time_prekey_id: u32,
    pub kyber_otpk_id: u32,
    /// Double Ratchet PN field: number of messages in the previous sending chain.
    /// Required for correct out-of-order message recovery.
    pub previous_chain_length: u32,
    /// Crypto-suite identifier (matches `EncryptedRatchetMessage.suite_id`).
    pub suite_id: u16,
    /// ML-KEM-768 ciphertext (1088 bytes) for PQXDH first messages; `None` otherwise.
    pub kem_ciphertext: Option<Vec<u8>>,
    /// `nonce || ciphertext || auth_tag` — the ChaCha20-Poly1305 sealed box.
    pub sealed_box: Vec<u8>,
    /// Suite 3 only: PQ epoch whose secret was mixed into this message's key
    /// (0 = pure DR key). Always 0 for other suites.
    pub pq_message_epoch: u32,
    /// Sparse PQ ratchet field (EK proposal or CT completion) for Suite 3 sessions.
    /// Only parsed/produced when suite_id == 3; additive after kem block.
    pub pq_ratchet_field: Option<crate::crypto::messaging::double_ratchet::PqRatchetWireField>,
}

/// Pack encrypted message components into a single binary blob.
///
/// # Parameters
/// - `dh_public_key`          — 32-byte ephemeral X25519 public key
/// - `message_number`         — Double Ratchet message counter
/// - `one_time_prekey_id`     — OTPK id (0 = fallback 3-DH / not a first message)
/// - `kyber_otpk_id`          — Kyber OTPK id (0 = Kyber SPK used)
/// - `previous_chain_length`  — DR PN field (messages in the previous sending chain)
/// - `suite_id`               — Crypto-suite identifier
/// - `kem_ciphertext`         — ML-KEM-768 encapsulation ciphertext, only for first messages
/// - `sealed_box`             — `nonce || ciphertext || auth_tag`
/// - `pq_message_epoch`       — Suite 3 only: PQ epoch mixed into this message's key (0 otherwise)
/// - `pq_ratchet_field`       — Suite 3 only: optional EK/CT exchange field
///
/// # Suite-3 PQ section layout (between kem_ciphertext and sealed_box)
/// ```text
/// [4 bytes] pq_message_epoch (u32 LE)          — always present for suite 3
/// [1 byte]  field type: 0 = none, 1 = EK, 2 = CT
/// type 1:   [4B field epoch][2B len][len bytes EK]
/// type 2:   [4B field epoch][8B ek_hash][2B len][len bytes CT]
/// ```
#[allow(clippy::too_many_arguments)]
pub fn pack(
    dh_public_key: &[u8],
    message_number: u32,
    one_time_prekey_id: u32,
    kyber_otpk_id: u32,
    previous_chain_length: u32,
    suite_id: u16,
    kem_ciphertext: Option<&[u8]>,
    sealed_box: &[u8],
    pq_message_epoch: u32,
    pq_ratchet_field: Option<crate::crypto::messaging::double_ratchet::PqRatchetWireField>,
) -> Result<Vec<u8>, WirePayloadError> {
    use crate::crypto::messaging::double_ratchet::PqRatchetWireField;

    if dh_public_key.len() != DH_KEY_SIZE {
        return Err(WirePayloadError::InvalidDhPublicKey(dh_public_key.len()));
    }
    let kem_len = kem_ciphertext.map_or(0, |k| k.len());
    if kem_len > u16::MAX as usize {
        return Err(WirePayloadError::KemTooLarge(kem_len));
    }

    // Suite-3 PQ section (see layout above). Empty for other suites.
    let pq_bytes: Vec<u8> = if suite_id == 3 {
        let mut b = Vec::with_capacity(5);
        b.extend_from_slice(&pq_message_epoch.to_le_bytes());
        match pq_ratchet_field {
            None => b.push(0u8),
            Some(PqRatchetWireField::PublicKey { epoch, key }) => {
                if key.len() > u16::MAX as usize {
                    return Err(WirePayloadError::PqFieldTooLarge(key.len()));
                }
                b.push(1u8);
                b.extend_from_slice(&epoch.to_le_bytes());
                b.extend_from_slice(&(key.len() as u16).to_le_bytes());
                b.extend_from_slice(&key);
            }
            Some(PqRatchetWireField::Ciphertext { epoch, ek_hash, ct }) => {
                if ct.len() > u16::MAX as usize {
                    return Err(WirePayloadError::PqFieldTooLarge(ct.len()));
                }
                b.push(2u8);
                b.extend_from_slice(&epoch.to_le_bytes());
                b.extend_from_slice(&ek_hash);
                b.extend_from_slice(&(ct.len() as u16).to_le_bytes());
                b.extend_from_slice(&ct);
            }
        }
        b
    } else {
        vec![]
    };

    let mut payload = Vec::with_capacity(HEADER_SIZE + kem_len + pq_bytes.len() + sealed_box.len());

    payload.extend_from_slice(&message_number.to_le_bytes());
    payload.extend_from_slice(dh_public_key);
    payload.extend_from_slice(&one_time_prekey_id.to_le_bytes());
    payload.extend_from_slice(&kyber_otpk_id.to_le_bytes());
    payload.extend_from_slice(&(kem_len as u16).to_le_bytes());
    payload.extend_from_slice(&previous_chain_length.to_le_bytes());
    payload.extend_from_slice(&suite_id.to_le_bytes());
    if let Some(kem) = kem_ciphertext {
        payload.extend_from_slice(kem);
    }
    payload.extend_from_slice(&pq_bytes);
    payload.extend_from_slice(sealed_box);

    Ok(payload)
}

/// Unpack a received binary blob into its components.
pub fn unpack(data: &[u8]) -> Result<DecodedWirePayload, WirePayloadError> {
    if data.len() <= HEADER_SIZE {
        return Err(WirePayloadError::TooShort(data.len()));
    }

    let message_number = u32::from_le_bytes(data[0..4].try_into().unwrap());

    let dh_public_key = data[MSG_NUM_SIZE..MSG_NUM_SIZE + DH_KEY_SIZE].to_vec();

    let otpk_offset = MSG_NUM_SIZE + DH_KEY_SIZE;
    let one_time_prekey_id = u32::from_le_bytes(
        data[otpk_offset..otpk_offset + OTPK_ID_SIZE]
            .try_into()
            .unwrap(),
    );

    let kyber_offset = otpk_offset + OTPK_ID_SIZE;
    let kyber_otpk_id = u32::from_le_bytes(
        data[kyber_offset..kyber_offset + KYBER_OTPK_ID_SIZE]
            .try_into()
            .unwrap(),
    );

    let kem_len_offset = kyber_offset + KYBER_OTPK_ID_SIZE;
    let kem_len = u16::from_le_bytes(
        data[kem_len_offset..kem_len_offset + KEM_LEN_SIZE]
            .try_into()
            .unwrap(),
    ) as usize;

    let prev_chain_offset = kem_len_offset + KEM_LEN_SIZE;
    let previous_chain_length = u32::from_le_bytes(
        data[prev_chain_offset..prev_chain_offset + PREV_CHAIN_LEN_SIZE]
            .try_into()
            .unwrap(),
    );

    let suite_id_offset = prev_chain_offset + PREV_CHAIN_LEN_SIZE;
    let suite_id = u16::from_le_bytes(
        data[suite_id_offset..suite_id_offset + SUITE_ID_SIZE]
            .try_into()
            .unwrap(),
    );

    let sealed_box_start = HEADER_SIZE + kem_len;
    if data.len() <= sealed_box_start {
        return Err(WirePayloadError::TooShort(data.len()));
    }

    let kem_ciphertext = if kem_len > 0 {
        Some(data[HEADER_SIZE..sealed_box_start].to_vec())
    } else {
        None
    };

    // Suite-3 PQ section (strict — suite 3 messages are only produced by code
    // that always writes it; a malformed section is a hard error, not a fallback):
    // [4B pq_message_epoch][1B type][type-specific payload]. See pack()'s doc.
    let mut cursor = sealed_box_start;
    let mut pq_message_epoch = 0u32;
    let mut pq_ratchet_field = None;
    if suite_id == 3 {
        use crate::crypto::messaging::double_ratchet::PqRatchetWireField;

        if data.len() < cursor + 5 {
            return Err(WirePayloadError::TooShort(data.len()));
        }
        pq_message_epoch = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap());
        let typ = data[cursor + 4];
        cursor += 5;
        match typ {
            0 => {}
            1 => {
                if data.len() < cursor + 6 {
                    return Err(WirePayloadError::TooShort(data.len()));
                }
                let epoch = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap());
                let len =
                    u16::from_le_bytes(data[cursor + 4..cursor + 6].try_into().unwrap()) as usize;
                cursor += 6;
                if data.len() < cursor + len {
                    return Err(WirePayloadError::TooShort(data.len()));
                }
                pq_ratchet_field = Some(PqRatchetWireField::PublicKey {
                    epoch,
                    key: data[cursor..cursor + len].to_vec(),
                });
                cursor += len;
            }
            2 => {
                if data.len() < cursor + 14 {
                    return Err(WirePayloadError::TooShort(data.len()));
                }
                let epoch = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap());
                let mut ek_hash = [0u8; 8];
                ek_hash.copy_from_slice(&data[cursor + 4..cursor + 12]);
                let len =
                    u16::from_le_bytes(data[cursor + 12..cursor + 14].try_into().unwrap()) as usize;
                cursor += 14;
                if data.len() < cursor + len {
                    return Err(WirePayloadError::TooShort(data.len()));
                }
                pq_ratchet_field = Some(PqRatchetWireField::Ciphertext {
                    epoch,
                    ek_hash,
                    ct: data[cursor..cursor + len].to_vec(),
                });
                cursor += len;
            }
            other => return Err(WirePayloadError::InvalidPqFieldType(other)),
        }
    }

    if data.len() <= cursor {
        return Err(WirePayloadError::TooShort(data.len()));
    }
    let sealed_box = data[cursor..].to_vec();

    Ok(DecodedWirePayload {
        message_number,
        dh_public_key,
        one_time_prekey_id,
        kyber_otpk_id,
        previous_chain_length,
        suite_id,
        kem_ciphertext,
        sealed_box,
        pq_message_epoch,
        pq_ratchet_field,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum WirePayloadError {
    #[error("DH public key must be 32 bytes, got {0}")]
    InvalidDhPublicKey(usize),
    #[error("KEM ciphertext too large: {0} bytes (max 65535)")]
    KemTooLarge(usize),
    #[error("PQ ratchet field too large: {0} bytes (max 65535)")]
    PqFieldTooLarge(usize),
    #[error("Invalid PQ ratchet field type: {0}")]
    InvalidPqFieldType(u8),
    #[error("Payload too short: {0} bytes")]
    TooShort(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sealed_box(n: u8) -> Vec<u8> {
        // 12-byte nonce + 32-byte ciphertext + 16-byte tag = 60 bytes
        vec![n; 60]
    }

    #[test]
    fn round_trip_no_pqc() {
        let dh_key = vec![0xAA; 32];
        let sealed = make_sealed_box(0xBB);
        let packed = pack(&dh_key, 7, 42, 0, 3, 1, None, &sealed, 0, None).unwrap();
        assert_eq!(packed.len(), HEADER_SIZE + sealed.len());

        let decoded = unpack(&packed).unwrap();
        assert_eq!(decoded.message_number, 7);
        assert_eq!(decoded.dh_public_key, dh_key);
        assert_eq!(decoded.one_time_prekey_id, 42);
        assert_eq!(decoded.kyber_otpk_id, 0);
        assert_eq!(decoded.previous_chain_length, 3);
        assert_eq!(decoded.suite_id, 1);
        assert!(decoded.kem_ciphertext.is_none());
        assert_eq!(decoded.pq_message_epoch, 0);
        assert!(decoded.pq_ratchet_field.is_none());
        assert_eq!(decoded.sealed_box, sealed);
    }

    #[test]
    fn round_trip_with_pqc() {
        let dh_key = vec![0x11; 32];
        let kem_ct = vec![0x22; 1088]; // ML-KEM-768 ciphertext size
        let sealed = make_sealed_box(0x33);
        let packed = pack(&dh_key, 0, 99, 5, 0, 1, Some(&kem_ct), &sealed, 0, None).unwrap();
        assert_eq!(packed.len(), HEADER_SIZE + kem_ct.len() + sealed.len());

        let decoded = unpack(&packed).unwrap();
        assert_eq!(decoded.message_number, 0);
        assert_eq!(decoded.one_time_prekey_id, 99);
        assert_eq!(decoded.kyber_otpk_id, 5);
        assert_eq!(decoded.previous_chain_length, 0);
        assert_eq!(decoded.suite_id, 1);
        assert_eq!(decoded.kem_ciphertext.as_deref(), Some(kem_ct.as_slice()));
        assert_eq!(decoded.sealed_box, sealed);
    }

    #[test]
    fn too_short_returns_error() {
        assert!(unpack(&[0u8; 10]).is_err());
    }

    #[test]
    fn invalid_dh_key_size() {
        let err = pack(
            &[0u8; 16],
            0,
            0,
            0,
            0,
            1,
            None,
            &make_sealed_box(0),
            0,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, WirePayloadError::InvalidDhPublicKey(16)));
    }

    #[test]
    fn round_trip_suite3_no_field() {
        let dh_key = vec![0x11; 32];
        let sealed = make_sealed_box(0x44);
        let packed = pack(&dh_key, 3, 0, 0, 1, 3, None, &sealed, 7, None).unwrap();
        // header + 5-byte PQ section (epoch + type 0)
        assert_eq!(packed.len(), HEADER_SIZE + 5 + sealed.len());

        let decoded = unpack(&packed).unwrap();
        assert_eq!(decoded.suite_id, 3);
        assert_eq!(decoded.pq_message_epoch, 7);
        assert!(decoded.pq_ratchet_field.is_none());
        assert_eq!(decoded.sealed_box, sealed);
    }

    #[test]
    fn round_trip_suite3_public_key_field() {
        use crate::crypto::messaging::double_ratchet::PqRatchetWireField;
        let dh_key = vec![0x11; 32];
        let sealed = make_sealed_box(0x55);
        let ek = vec![0x66; 1184];
        let field = PqRatchetWireField::PublicKey {
            epoch: 8,
            key: ek.clone(),
        };
        let packed = pack(&dh_key, 3, 0, 0, 1, 3, None, &sealed, 7, Some(field)).unwrap();

        let decoded = unpack(&packed).unwrap();
        assert_eq!(decoded.pq_message_epoch, 7);
        match decoded.pq_ratchet_field {
            Some(PqRatchetWireField::PublicKey { epoch, key }) => {
                assert_eq!(epoch, 8);
                assert_eq!(key, ek);
            }
            other => panic!("expected PublicKey field, got {other:?}"),
        }
        assert_eq!(decoded.sealed_box, sealed);
    }

    #[test]
    fn round_trip_suite3_ciphertext_field() {
        use crate::crypto::messaging::double_ratchet::PqRatchetWireField;
        let dh_key = vec![0x11; 32];
        let sealed = make_sealed_box(0x77);
        let ct = vec![0x88; 1088];
        let ek_hash = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let field = PqRatchetWireField::Ciphertext {
            epoch: 8,
            ek_hash,
            ct: ct.clone(),
        };
        let packed = pack(&dh_key, 3, 0, 0, 1, 3, None, &sealed, 8, Some(field)).unwrap();

        let decoded = unpack(&packed).unwrap();
        assert_eq!(decoded.pq_message_epoch, 8);
        match decoded.pq_ratchet_field {
            Some(PqRatchetWireField::Ciphertext {
                epoch,
                ek_hash: h,
                ct: c,
            }) => {
                assert_eq!(epoch, 8);
                assert_eq!(h, ek_hash);
                assert_eq!(c, ct);
            }
            other => panic!("expected Ciphertext field, got {other:?}"),
        }
        assert_eq!(decoded.sealed_box, sealed);
    }

    #[test]
    fn suite3_truncated_pq_section_errors() {
        let dh_key = vec![0x11; 32];
        let sealed = make_sealed_box(0x44);
        let packed = pack(&dh_key, 3, 0, 0, 1, 3, None, &sealed, 7, None).unwrap();
        // Cut into the 5-byte PQ section: parsing must fail loudly, not misparse.
        let truncated = &packed[..HEADER_SIZE + 2];
        assert!(matches!(
            unpack(truncated),
            Err(WirePayloadError::TooShort(_))
        ));
    }

    /// Verify byte-level layout after format update (52-byte header).
    /// msgNum=1, dh=0x01×32, otpkId=2, kyberOtpkId=0, PN=5, suiteId=1, no PQC, sealed=0xAA×60
    #[test]
    fn known_byte_vector() {
        let dh_key = vec![0x01; 32];
        let sealed = vec![0xAA; 60];
        let packed = pack(&dh_key, 1, 2, 0, 5, 1, None, &sealed, 0, None).unwrap();

        // message_number = 1 LE → [01 00 00 00]
        assert_eq!(&packed[0..4], &[0x01, 0x00, 0x00, 0x00]);
        // dh_public_key = [01; 32]
        assert_eq!(&packed[4..36], vec![0x01u8; 32].as_slice());
        // otpk_id = 2 LE → [02 00 00 00]
        assert_eq!(&packed[36..40], &[0x02, 0x00, 0x00, 0x00]);
        // kyber_otpk_id = 0 LE → [00 00 00 00]
        assert_eq!(&packed[40..44], &[0x00, 0x00, 0x00, 0x00]);
        // kem_len = 0 LE → [00 00]
        assert_eq!(&packed[44..46], &[0x00, 0x00]);
        // previous_chain_length = 5 LE → [05 00 00 00]
        assert_eq!(&packed[46..50], &[0x05, 0x00, 0x00, 0x00]);
        // suite_id = 1 LE → [01 00]
        assert_eq!(&packed[50..52], &[0x01, 0x00]);
        // sealed box starts at 52
        assert_eq!(&packed[52..], vec![0xAAu8; 60].as_slice());
    }
}
