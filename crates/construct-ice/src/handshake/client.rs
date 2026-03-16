//! Client-side obfs4 handshake.
//!
//! ## Wire format (client → server)
//! ```text
//! clientRequest = X'[32] || P_C[85..8128] || M_C[16] || MAC_C[16]
//! ```
//! - `X'` — ephemeral Curve25519 public key encoded via Elligator2
//! - `P_C` — random padding, length in [CLIENT_MIN_PAD..CLIENT_MAX_PAD]
//! - `M_C` — mark: `HMAC-SHA256-128(B||NODEID, X')`
//! - `MAC_C` — `HMAC-SHA256-128(B||NODEID, X' || P_C || M_C || E)`
//!
//! ## Wire format (server → client)
//! ```text
//! serverResponse = Y'[32] || AUTH[32] || P_S || M_S[16] || MAC_S[16]
//! ```

use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    Error, Result,
    crypto::{
        elligator2,
        kdf::{SessionKeys, handshake_hmac_key},
        keypair::{EphemeralKeypair, NodeId},
        ntor,
    },
    handshake::{
        AUTH_LEN, CLIENT_MAX_PAD, CLIENT_MIN_PAD, HandshakeResult, MAC_LEN, MARK_LEN,
        MAX_HANDSHAKE_LENGTH, REPR_LEN, SERVER_HANDSHAKE_LEN,
    },
};

type HmacSha256 = Hmac<Sha256>;

/// Perform the client side of the obfs4 handshake.
///
/// # Arguments
/// * `stream` — underlying TCP stream
/// * `server_pubkey` — server's static Curve25519 public key B (32 bytes)
/// * `node_id` — server's 20-byte Node ID
/// * `rng` — cryptographic RNG
pub(crate) async fn client_handshake<S, R>(
    mut stream: S,
    server_pubkey: &[u8; 32],
    node_id: &NodeId,
    rng: &mut R,
) -> Result<(S, HandshakeResult)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: RngCore + CryptoRng,
{
    let server_point = curve25519_elligator2::montgomery::MontgomeryPoint(*server_pubkey);
    let hmac_key = handshake_hmac_key(server_pubkey, node_id);

    // 1. Generate ephemeral keypair (guaranteed Elligator2-representable)
    let epk = EphemeralKeypair::generate(rng);

    // 2. Compute mark: M_C = HMAC-SHA256-128(B||NODEID, X')
    let mark = hmac_128(&hmac_key, &epk.representative);

    // 3. Build random padding P_C
    let pad_len =
        CLIENT_MIN_PAD + ((rng.next_u32() as usize) % (CLIENT_MAX_PAD - CLIENT_MIN_PAD + 1));
    let mut padding = vec![0u8; pad_len];
    rng.fill_bytes(&mut padding);

    // 4. Compute MAC_C = HMAC-SHA256-128(B||NODEID, X' || P_C || M_C || E)
    let epoch = epoch_hours_str();
    let mac = {
        let mut h = HmacSha256::new_from_slice(&hmac_key).expect("hmac key len ok");
        h.update(&epk.representative);
        h.update(&padding);
        h.update(&mark);
        h.update(epoch.as_bytes());
        truncate_128(h.finalize().into_bytes().as_slice())
    };

    // 5. Send: X' || P_C || M_C || MAC_C
    let total_len = REPR_LEN + pad_len + MARK_LEN + MAC_LEN;
    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&epk.representative);
    msg.extend_from_slice(&padding);
    msg.extend_from_slice(&mark);
    msg.extend_from_slice(&mac);
    stream.write_all(&msg).await?;
    stream.flush().await?;

    // 6. Read server response (up to MAX_HANDSHAKE_LENGTH bytes)
    //    Format: Y'[32] || AUTH[32] || P_S || M_S[16] || MAC_S[16]
    let mut resp_buf = vec![0u8; MAX_HANDSHAKE_LENGTH];
    let mut resp_len = 0usize;

    // We need at least SERVER_HANDSHAKE_LEN bytes
    while resp_len < SERVER_HANDSHAKE_LEN {
        let n = stream.read(&mut resp_buf[resp_len..]).await?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        resp_len += n;
    }

    // Extract Y' (first 32 bytes) and AUTH (next 32 bytes)
    let server_repr: [u8; REPR_LEN] = resp_buf[..REPR_LEN].try_into().unwrap();
    let server_auth: [u8; AUTH_LEN] = resp_buf[REPR_LEN..REPR_LEN + AUTH_LEN].try_into().unwrap();

    // Compute expected server mark: M_S = HMAC-SHA256-128(B||NODEID, Y')
    let expected_mark = hmac_128(&hmac_key, &server_repr);

    // Read more data if needed and scan for M_S in the response
    let mark_pos = loop {
        if let Some(pos) = find_mark(&resp_buf[REPR_LEN + AUTH_LEN..resp_len], &expected_mark) {
            break REPR_LEN + AUTH_LEN + pos;
        }
        if resp_len >= MAX_HANDSHAKE_LENGTH {
            return Err(Error::HandshakeMacMismatch);
        }
        let n = stream.read(&mut resp_buf[resp_len..]).await?;
        if n == 0 {
            return Err(Error::HandshakeMacMismatch);
        }
        resp_len += n;
    };

    // Mark found at mark_pos. MAC_S follows immediately after.
    let mac_start = mark_pos + MARK_LEN;
    // Ensure we have the full MAC
    while resp_len < mac_start + MAC_LEN {
        let n = stream.read(&mut resp_buf[resp_len..]).await?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        resp_len += n;
    }

    let received_mac: [u8; MAC_LEN] = resp_buf[mac_start..mac_start + MAC_LEN].try_into().unwrap();

    // Verify MAC_S = HMAC-SHA256-128(B||NODEID, Y' || AUTH || P_S || M_S || E')
    // We use the same epoch as the server used (which we don't know exactly),
    // so try E-1, E, E+1
    let mac_verified = verify_mac_with_skew(
        &hmac_key,
        &resp_buf[..mac_start], // Y' || AUTH || P_S || M_S
        &received_mac,
    );
    if !mac_verified {
        return Err(Error::HandshakeMacMismatch);
    }

    // 7. Decode Y from Y' and complete ntor handshake
    let server_epk_point = elligator2::pubkey_from_representative(&server_repr);

    let ntor_result = ntor::client_ntor(&epk, &server_point, node_id, &server_epk_point);

    // 8. Verify AUTH
    if ntor_result.auth.ct_eq(&server_auth).unwrap_u8() != 1 {
        return Err(Error::NtorAuthMismatch);
    }

    // 9. Derive session keys from KEY_SEED
    let session_keys = SessionKeys::derive(&ntor_result.key_seed)?;

    // 10. Return any trailing bytes that arrived after the handshake MAC.
    //     This can include inline frames (e.g. PRNG seed) sent by the server
    //     immediately after the handshake response.
    let consumed = mac_start + MAC_LEN;
    let trailing = if resp_len > consumed {
        resp_buf[consumed..resp_len].to_vec()
    } else {
        Vec::new()
    };

    Ok((
        stream,
        HandshakeResult {
            session_keys,
            trailing,
        },
    ))
}

/// Compute HMAC-SHA256-128 (truncated to 16 bytes).
fn hmac_128(key: &[u8], msg: &[u8]) -> [u8; MARK_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key ok");
    mac.update(msg);
    truncate_128(mac.finalize().into_bytes().as_slice())
}

fn truncate_128(full: &[u8]) -> [u8; 16] {
    full[..16].try_into().unwrap()
}

fn epoch_hours_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (secs / 3600).to_string()
}

/// Scan `data` for the 16-byte `mark`, return offset if found.
///
/// Uses constant-time comparison for each window AND a full scan
/// (no early exit) so that the total execution time does not reveal
/// the mark position (i.e. the padding length).
fn find_mark(data: &[u8], mark: &[u8; MARK_LEN]) -> Option<usize> {
    let mut found: Option<usize> = None;
    for (i, w) in data.windows(MARK_LEN).enumerate() {
        if w.ct_eq(mark).unwrap_u8() == 1 {
            found = found.or(Some(i));
        }
    }
    found
}

/// Verify MAC with clock skew tolerance: try E-1, E, E+1.
fn verify_mac_with_skew(hmac_key: &[u8], prefix: &[u8], received_mac: &[u8; MAC_LEN]) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let epoch = secs / 3600;

    for offset in [0i64, -1, 1] {
        let e = ((epoch as i64) + offset) as u64;
        let e_str = e.to_string();

        let mut h = HmacSha256::new_from_slice(hmac_key).expect("hmac key ok");
        h.update(prefix);
        h.update(e_str.as_bytes());
        let expected = truncate_128(h.finalize().into_bytes().as_slice());

        if received_mac.ct_eq(&expected).unwrap_u8() == 1 {
            return true;
        }
    }
    false
}
