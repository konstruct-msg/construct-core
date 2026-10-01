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
//! [2 bytes]  suite_id              (u16 LE; crypto-suite identifier; bit 0x0100 = PQXDH v2)
//! [N bytes]  kem_ciphertext        (present only when kem_ciphertext_len > 0)
//! [2+N]      kem_identity          (u16 LE len + key; only with KEM_IDENTITY_FLAG)
//! [2+N]      identity_proof_ct     (u16 LE len + ciphertext; only with IDENTITY_PROOF_FLAG)
//! [..]       PQ-ratchet section    (suite 4 only; see `pack`)
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
/// Set in the wire `suite_id` of every message that carries a PQXDH v2 handshake (a KEM
/// ciphertext): the initiator's first flight. The low byte stays the ratchet suite; `unpack`
/// strips the bit, so everything past the wire sees the suite the AEAD authenticated.
///
/// Why a bit when there is no compatibility to keep: an older core would otherwise derive a
/// classical key, fail the AEAD and read the result as corruption (heal). `0x0101`/`0x0103` is a
/// suite id it rejects outright.
pub const PQXDH_V2_FLAG: u16 = 0x0100;
/// Set with `PQXDH_V2_FLAG` on every first-flight message: the initiator's ML-KEM-1024 identity
/// key follows the KEM ciphertext. Mandatory — a first flight without it is refused by the
/// responder (decisions/responder-authenticates-initiator-by-kem.md).
pub const KEM_IDENTITY_FLAG: u16 = 0x0200;
/// Set on a responder's messages until the initiator proves itself: the ML-KEM-1024 answer to the
/// initiator's identity key follows.
pub const IDENTITY_PROOF_FLAG: u16 = 0x0400;
/// Every bit the wire uses above the ratchet suite; stripped by `unpack`.
const WIRE_FLAGS: u16 = PQXDH_V2_FLAG | KEM_IDENTITY_FLAG | IDENTITY_PROOF_FLAG;
/// Size of the KEM identity key and of the answer to it (ML-KEM-1024).
const KEM_IDENTITY_OBJECT_SIZE: usize = 1568;

/// Fixed header size (no KEM ciphertext): 52 bytes.
pub const HEADER_SIZE: usize = MSG_NUM_SIZE
    + DH_KEY_SIZE
    + OTPK_ID_SIZE
    + KYBER_OTPK_ID_SIZE
    + KEM_LEN_SIZE
    + PREV_CHAIN_LEN_SIZE
    + SUITE_ID_SIZE;

/// Where the Kyber prekey id and the KEM ciphertext length sit in the fixed header — read by the
/// first-flight box (`crypto::sealed_sender::first_flight`), which lifts the ciphertext out.
pub(crate) const KYBER_PREKEY_ID_OFFSET: usize = MSG_NUM_SIZE + DH_KEY_SIZE + OTPK_ID_SIZE;
pub(crate) const KEM_LEN_OFFSET: usize = KYBER_PREKEY_ID_OFFSET + KYBER_OTPK_ID_SIZE;

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
    /// ML-KEM-1024 ciphertext (1568 bytes) on the initiator's first flight; `None` otherwise.
    pub kem_ciphertext: Option<Vec<u8>>,
    /// The wire `suite_id` carried `PQXDH_V2_FLAG` (stripped from `suite_id` above).
    pub pqxdh_v2: bool,
    /// The initiator's ML-KEM-1024 identity key (1568 bytes), first flight only.
    pub kem_identity: Option<Vec<u8>>,
    /// The responder's ML-KEM-1024 answer to the initiator's identity key (1568 bytes).
    pub identity_proof_ciphertext: Option<Vec<u8>>,
    /// `nonce || ciphertext || auth_tag` — the ChaCha20-Poly1305 sealed box.
    pub sealed_box: Vec<u8>,
    /// PQ-ratchet suite only: the PQ epoch whose chain keyed this message
    /// (0 = pure DR key). Always 0 for other suites.
    pub pq_message_epoch: u32,
    /// PQ-ratchet suite only: the index of this message's key in the sender's chain of
    /// `pq_message_epoch`. Always 0 for other suites and for epoch 0.
    pub pq_key_index: u32,
    /// Sparse PQ ratchet field (EK proposal or CT completion) for PQ-ratchet sessions.
    /// Only parsed/produced for `SuiteID::PQ_RATCHET`; additive after kem block.
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
/// - `kem_ciphertext`         — ML-KEM-1024 encapsulation ciphertext, only for first messages
/// - `kem_identity`           — the initiator's ML-KEM-1024 identity key, with `kem_ciphertext`
/// - `identity_proof_ct`      — the responder's answer to it, until the initiator proves itself
/// - `sealed_box`             — `nonce || ciphertext || auth_tag`
/// - `pq_message_epoch`       — PQ-ratchet suite only: the epoch keying this message (0 otherwise)
/// - `pq_key_index`           — PQ-ratchet suite only: the key's index in that epoch's chain
/// - `pq_ratchet_field`       — PQ-ratchet suite only: optional EK/CT exchange field
///
/// # PQ-ratchet section layout (suite 4; between kem_ciphertext and sealed_box)
/// ```text
/// [4 bytes] pq_message_epoch (u32 LE)          — always present
/// [1–5 B]   pq_key_index (LEB128, minimal)     — always present; 1 byte below 128
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
    kem_identity: Option<&[u8]>,
    identity_proof_ct: Option<&[u8]>,
    sealed_box: &[u8],
    pq_message_epoch: u32,
    pq_key_index: u32,
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

    if kem_identity.is_some() && kem_len == 0 {
        return Err(WirePayloadError::KemIdentityWithoutHandshake);
    }
    for object in [kem_identity, identity_proof_ct].into_iter().flatten() {
        if object.len() != KEM_IDENTITY_OBJECT_SIZE {
            return Err(WirePayloadError::KemIdentityObjectSize(object.len()));
        }
    }

    // PQ-ratchet section (see layout above). Empty for other suites.
    // The flags are the wire's business: derived from what is present, never taken from the caller.
    let suite_id = suite_id & !WIRE_FLAGS;
    let mut wire_suite_id = suite_id;
    if kem_len > 0 {
        wire_suite_id |= PQXDH_V2_FLAG;
    }
    if kem_identity.is_some() {
        wire_suite_id |= KEM_IDENTITY_FLAG;
    }
    if identity_proof_ct.is_some() {
        wire_suite_id |= IDENTITY_PROOF_FLAG;
    }

    let pq_bytes: Vec<u8> = if suite_id == PQ_RATCHET_SUITE {
        let mut b = Vec::with_capacity(10);
        b.extend_from_slice(&pq_message_epoch.to_le_bytes());
        write_leb128(&mut b, pq_key_index);
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
    payload.extend_from_slice(&wire_suite_id.to_le_bytes());
    if let Some(kem) = kem_ciphertext {
        payload.extend_from_slice(kem);
    }
    for object in [kem_identity, identity_proof_ct].into_iter().flatten() {
        payload.extend_from_slice(&(object.len() as u16).to_le_bytes());
        payload.extend_from_slice(object);
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
    let wire_suite_id = u16::from_le_bytes(
        data[suite_id_offset..suite_id_offset + SUITE_ID_SIZE]
            .try_into()
            .unwrap(),
    );
    let pqxdh_v2 = wire_suite_id & PQXDH_V2_FLAG != 0;
    let has_kem_identity = wire_suite_id & KEM_IDENTITY_FLAG != 0;
    let has_identity_proof = wire_suite_id & IDENTITY_PROOF_FLAG != 0;
    let suite_id = wire_suite_id & !WIRE_FLAGS;
    if pqxdh_v2 && kem_len == 0 {
        return Err(WirePayloadError::PqxdhFlagWithoutCiphertext);
    }
    if has_kem_identity && !pqxdh_v2 {
        return Err(WirePayloadError::KemIdentityWithoutHandshake);
    }

    let sealed_box_start = HEADER_SIZE + kem_len;
    if data.len() <= sealed_box_start {
        return Err(WirePayloadError::TooShort(data.len()));
    }

    let kem_ciphertext = if kem_len > 0 {
        Some(data[HEADER_SIZE..sealed_box_start].to_vec())
    } else {
        None
    };

    let mut cursor = sealed_box_start;
    let mut kem_identity_object = |present: bool| -> Result<Option<Vec<u8>>, WirePayloadError> {
        if !present {
            return Ok(None);
        }
        if data.len() < cursor + 2 {
            return Err(WirePayloadError::TooShort(data.len()));
        }
        let len = u16::from_le_bytes(data[cursor..cursor + 2].try_into().unwrap()) as usize;
        if len != KEM_IDENTITY_OBJECT_SIZE {
            return Err(WirePayloadError::KemIdentityObjectSize(len));
        }
        cursor += 2;
        if data.len() < cursor + len {
            return Err(WirePayloadError::TooShort(data.len()));
        }
        let object = data[cursor..cursor + len].to_vec();
        cursor += len;
        Ok(Some(object))
    };
    let kem_identity = kem_identity_object(has_kem_identity)?;
    let identity_proof_ciphertext = kem_identity_object(has_identity_proof)?;

    // PQ-ratchet section (strict — these messages are only produced by code that always writes
    // it; a malformed section is a hard error, not a fallback):
    // [4B pq_message_epoch][LEB128 pq_key_index][1B type][type-specific payload].
    // See pack()'s doc. Suite 3, which had no index, is refused outright rather than read as a
    // message whose section is shorter by the index.
    if suite_id == crate::crypto::SuiteID::RETIRED_PQ_RATCHET_V1 {
        return Err(WirePayloadError::RetiredSuite(suite_id));
    }
    let mut pq_message_epoch = 0u32;
    let mut pq_key_index = 0u32;
    let mut pq_ratchet_field = None;
    if suite_id == PQ_RATCHET_SUITE {
        use crate::crypto::messaging::double_ratchet::PqRatchetWireField;

        if data.len() < cursor + 4 {
            return Err(WirePayloadError::TooShort(data.len()));
        }
        pq_message_epoch = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        pq_key_index = read_leb128(data, &mut cursor)?;
        if pq_message_epoch == 0 && pq_key_index != 0 {
            return Err(WirePayloadError::PqKeyIndexWithoutEpoch(pq_key_index));
        }
        if data.len() < cursor + 1 {
            return Err(WirePayloadError::TooShort(data.len()));
        }
        let typ = data[cursor];
        cursor += 1;
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
        pqxdh_v2,
        kem_identity,
        identity_proof_ciphertext,
        sealed_box,
        pq_message_epoch,
        pq_key_index,
        pq_ratchet_field,
    })
}

/// The PQ-ratchet suite, as the wire carries it.
const PQ_RATCHET_SUITE: u16 = crate::crypto::SuiteID::PQ_RATCHET.as_u16();

/// Unsigned LEB128: seven bits per byte, low first, high bit = more follows.
fn write_leb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Reads a `u32` written by `write_leb128`, and only that: at most five bytes, no bits beyond
/// 32, and no trailing zero group. The value is bound in the AD, but its bytes are not — a
/// second encoding of the same number would let a relay alter a message without breaking it.
fn read_leb128(data: &[u8], cursor: &mut usize) -> Result<u32, WirePayloadError> {
    let mut value: u32 = 0;
    for i in 0..5 {
        let Some(&byte) = data.get(*cursor + i) else {
            return Err(WirePayloadError::TooShort(data.len()));
        };
        let group = u32::from(byte & 0x7f);
        if i == 4 && group > 0x0f {
            return Err(WirePayloadError::NonCanonicalKeyIndex);
        }
        value |= group << (7 * i);
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                return Err(WirePayloadError::NonCanonicalKeyIndex);
            }
            *cursor += i + 1;
            return Ok(value);
        }
    }
    Err(WirePayloadError::NonCanonicalKeyIndex)
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
    #[error("PQXDH v2 flag set without a KEM ciphertext")]
    PqxdhFlagWithoutCiphertext,
    #[error("a KEM identity key outside a handshake header")]
    KemIdentityWithoutHandshake,
    #[error("KEM identity key or answer of {0} bytes (expected 1568)")]
    KemIdentityObjectSize(usize),
    #[error("suite {0} is retired: this build reads only the per-message PQ ratchet (suite 4)")]
    RetiredSuite(u16),
    #[error("PQ key index {0} on a message with no PQ epoch")]
    PqKeyIndexWithoutEpoch(u32),
    #[error("PQ key index is not minimal LEB128")]
    NonCanonicalKeyIndex,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sealed_box(n: u8) -> Vec<u8> {
        // 12-byte nonce + 32-byte ciphertext + 16-byte tag = 60 bytes
        vec![n; 60]
    }

    /// PQXDH v2: a KEM ciphertext sets the flag on the wire and nowhere else; `unpack` strips it
    /// back off. A caller cannot set it without a ciphertext, and the wire cannot carry it
    /// without one.
    #[test]
    fn the_pqxdh_v2_flag_follows_the_ciphertext() {
        let dh_key = vec![0xAA; 32];
        let sealed = make_sealed_box(0xBB);
        let kem = vec![0x44; 1568];

        let packed = pack(
            &dh_key,
            0,
            0,
            1_000_001,
            0,
            4,
            Some(&kem),
            None,
            None,
            &sealed,
            0,
            0,
            None,
        )
        .unwrap();
        let wire_suite =
            u16::from_le_bytes(packed[HEADER_SIZE - 2..HEADER_SIZE].try_into().unwrap());
        assert_eq!(
            wire_suite,
            4 | PQXDH_V2_FLAG,
            "an older core sees suite 0x0104 and refuses"
        );
        let decoded = unpack(&packed).unwrap();
        assert!(decoded.pqxdh_v2);
        assert_eq!(
            decoded.suite_id, 4,
            "stripped: the AEAD authenticated the PQ-ratchet suite"
        );
        assert_eq!(decoded.kem_ciphertext.as_deref(), Some(kem.as_slice()));

        let plain = pack(
            &dh_key,
            1,
            0,
            0,
            0,
            4 | PQXDH_V2_FLAG,
            None,
            None,
            None,
            &sealed,
            0,
            0,
            None,
        )
        .unwrap();
        let decoded = unpack(&plain).unwrap();
        assert!(!decoded.pqxdh_v2, "the caller's bit is not the wire's");
        assert_eq!(decoded.suite_id, 4);

        let mut forged = plain.clone();
        forged[HEADER_SIZE - 2..HEADER_SIZE].copy_from_slice(&(4 | PQXDH_V2_FLAG).to_le_bytes());
        assert!(matches!(
            unpack(&forged),
            Err(WirePayloadError::PqxdhFlagWithoutCiphertext)
        ));
    }

    /// The KEM identity key rides only in a handshake header, the answer to it on any message.
    /// Both survive the round trip ahead of the PQ-ratchet section, their flags follow presence, and
    /// a key outside a handshake or an object of the wrong size is refused both ways.
    #[test]
    fn the_kem_identity_and_its_answer_round_trip() {
        use crate::crypto::messaging::double_ratchet::PqRatchetWireField;
        let dh_key = vec![0xAA; 32];
        let sealed = make_sealed_box(0xBB);
        let (kem, ikk, answer) = (vec![0x44; 1568], vec![0x55; 1568], vec![0x66; 1568]);
        let field = PqRatchetWireField::PublicKey {
            epoch: 2,
            key: vec![7; 1184],
        };
        let suite_of =
            |p: &[u8]| u16::from_le_bytes(p[HEADER_SIZE - 2..HEADER_SIZE].try_into().unwrap());

        let first = pack(
            &dh_key,
            0,
            0,
            1,
            0,
            4,
            Some(&kem),
            Some(&ikk),
            None,
            &sealed,
            0,
            0,
            Some(field.clone()),
        )
        .unwrap();
        assert_eq!(suite_of(&first), 4 | PQXDH_V2_FLAG | KEM_IDENTITY_FLAG);
        let d = unpack(&first).unwrap();
        assert_eq!(d.suite_id, 4);
        assert_eq!(d.kem_identity.as_deref(), Some(ikk.as_slice()));
        assert_eq!(d.identity_proof_ciphertext, None);
        assert_eq!(d.pq_ratchet_field, Some(field));
        assert_eq!(d.sealed_box, sealed);

        let reply = pack(
            &dh_key,
            1,
            0,
            0,
            0,
            4,
            None,
            None,
            Some(&answer),
            &sealed,
            0,
            0,
            None,
        )
        .unwrap();
        assert_eq!(suite_of(&reply), 4 | IDENTITY_PROOF_FLAG);
        let d = unpack(&reply).unwrap();
        assert!(!d.pqxdh_v2);
        assert_eq!(
            d.identity_proof_ciphertext.as_deref(),
            Some(answer.as_slice())
        );
        assert_eq!(d.sealed_box, sealed);

        assert!(matches!(
            pack(
                &dh_key,
                1,
                0,
                0,
                0,
                4,
                None,
                Some(&ikk),
                None,
                &sealed,
                0,
                0,
                None
            ),
            Err(WirePayloadError::KemIdentityWithoutHandshake)
        ));
        let mut forged = reply.clone();
        forged[HEADER_SIZE - 2..HEADER_SIZE]
            .copy_from_slice(&(3 | KEM_IDENTITY_FLAG).to_le_bytes());
        assert!(matches!(
            unpack(&forged),
            Err(WirePayloadError::KemIdentityWithoutHandshake)
        ));
        assert!(matches!(
            pack(
                &dh_key,
                1,
                0,
                0,
                0,
                4,
                None,
                None,
                Some(&[0u8; 100]),
                &sealed,
                0,
                0,
                None
            ),
            Err(WirePayloadError::KemIdentityObjectSize(100))
        ));
    }

    #[test]
    fn round_trip_no_pqc() {
        let dh_key = vec![0xAA; 32];
        let sealed = make_sealed_box(0xBB);
        let packed = pack(
            &dh_key, 7, 42, 0, 3, 1, None, None, None, &sealed, 0, 0, None,
        )
        .unwrap();
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
        let packed = pack(
            &dh_key,
            0,
            99,
            5,
            0,
            1,
            Some(&kem_ct),
            None,
            None,
            &sealed,
            0,
            0,
            None,
        )
        .unwrap();
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
            None,
            None,
            &make_sealed_box(0),
            0,
            0,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, WirePayloadError::InvalidDhPublicKey(16)));
    }

    #[test]
    fn round_trip_pq_ratchet_no_field() {
        let dh_key = vec![0x11; 32];
        let sealed = make_sealed_box(0x44);
        let packed = pack(
            &dh_key, 3, 0, 0, 1, 4, None, None, None, &sealed, 7, 0, None,
        )
        .unwrap();
        // header + 6-byte PQ section (epoch + index 0 in one LEB128 byte + type 0)
        assert_eq!(packed.len(), HEADER_SIZE + 6 + sealed.len());

        let decoded = unpack(&packed).unwrap();
        assert_eq!(decoded.suite_id, 4);
        assert_eq!(decoded.pq_message_epoch, 7);
        assert!(decoded.pq_ratchet_field.is_none());
        assert_eq!(decoded.sealed_box, sealed);
    }

    #[test]
    fn round_trip_pq_ratchet_public_key_field() {
        use crate::crypto::messaging::double_ratchet::PqRatchetWireField;
        let dh_key = vec![0x11; 32];
        let sealed = make_sealed_box(0x55);
        let ek = vec![0x66; 1184];
        let field = PqRatchetWireField::PublicKey {
            epoch: 8,
            key: ek.clone(),
        };
        let packed = pack(
            &dh_key,
            3,
            0,
            0,
            1,
            4,
            None,
            None,
            None,
            &sealed,
            7,
            0,
            Some(field),
        )
        .unwrap();

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
    fn round_trip_pq_ratchet_ciphertext_field() {
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
        let packed = pack(
            &dh_key,
            3,
            0,
            0,
            1,
            4,
            None,
            None,
            None,
            &sealed,
            8,
            0,
            Some(field),
        )
        .unwrap();

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
    fn pq_ratchet_truncated_section_errors() {
        let dh_key = vec![0x11; 32];
        let sealed = make_sealed_box(0x44);
        let packed = pack(
            &dh_key, 3, 0, 0, 1, 4, None, None, None, &sealed, 7, 0, None,
        )
        .unwrap();
        // Cut into the 6-byte PQ section: parsing must fail loudly, not misparse.
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
        let packed = pack(
            &dh_key, 1, 2, 0, 5, 1, None, None, None, &sealed, 0, 0, None,
        )
        .unwrap();

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

    /// PQR-2: the key index is LEB128 — one byte below 128, two below 16 384 — and only its
    /// minimal form is read: the AD binds the value, not its bytes, so a second encoding of the
    /// same number would let a relay change a message without breaking it.
    #[test]
    fn the_key_index_is_minimal_leb128() {
        for (value, bytes) in [
            (0u32, vec![0x00]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x01]),
            (16_383, vec![0xff, 0x7f]),
            (16_384, vec![0x80, 0x80, 0x01]),
            (u32::MAX, vec![0xff, 0xff, 0xff, 0xff, 0x0f]),
        ] {
            let mut out = Vec::new();
            write_leb128(&mut out, value);
            assert_eq!(out, bytes, "{value}");
            let mut cursor = 0;
            assert_eq!(read_leb128(&out, &mut cursor).unwrap(), value);
            assert_eq!(cursor, bytes.len());
        }
        for bad in [
            vec![0x80, 0x00],                   // 0 in two bytes
            vec![0xff, 0x80, 0x00],             // 127 padded
            vec![0xff, 0xff, 0xff, 0xff, 0x1f], // beyond 32 bits
            vec![0x80, 0x80, 0x80, 0x80, 0x80], // six bytes
        ] {
            let mut cursor = 0;
            assert!(
                matches!(
                    read_leb128(&bad, &mut cursor),
                    Err(WirePayloadError::NonCanonicalKeyIndex)
                ),
                "{bad:02x?}"
            );
        }
    }

    /// Suite 3 had no key index, so its section read as suite 4 would shift every later byte.
    /// It is refused by name instead; and an index without an epoch is malformed.
    #[test]
    fn suite_3_is_refused_and_an_index_needs_an_epoch() {
        let dh_key = vec![0x11; 32];
        let sealed = make_sealed_box(0x44);
        let mut packed = pack(
            &dh_key, 3, 0, 0, 1, 1, None, None, None, &sealed, 0, 0, None,
        )
        .unwrap();
        packed[HEADER_SIZE - 2..HEADER_SIZE].copy_from_slice(&3u16.to_le_bytes());
        assert!(matches!(
            unpack(&packed),
            Err(WirePayloadError::RetiredSuite(3))
        ));

        let mut packed = pack(
            &dh_key, 3, 0, 0, 1, 4, None, None, None, &sealed, 0, 0, None,
        )
        .unwrap();
        packed[HEADER_SIZE + 4] = 0x05; // index 5 on epoch 0
        assert!(matches!(
            unpack(&packed),
            Err(WirePayloadError::PqKeyIndexWithoutEpoch(5))
        ));
    }
}
