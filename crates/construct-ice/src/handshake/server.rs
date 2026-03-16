//! Server-side obfs4 handshake.
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
        kdf::SessionKeys,
        keypair::{EphemeralKeypair, StaticKeypair},
        ntor,
    },
    handshake::{
        AUTH_LEN, CLIENT_MIN_PAD, HandshakeResult, MAC_LEN, MARK_LEN, MAX_HANDSHAKE_LENGTH,
        REPR_LEN, SERVER_MAX_PAD, SERVER_MIN_PAD,
    },
    replay_filter::ReplayFilter,
};

type HmacSha256 = Hmac<Sha256>;

/// Perform the server side of the obfs4 handshake.
///
/// Reads the client's message, verifies MAC, checks replay filter,
/// performs ntor DH, responds with server's ephemeral key + AUTH tag,
/// derives session keys.
pub(crate) async fn server_handshake<S, R>(
    mut stream: S,
    static_keypair: &StaticKeypair,
    rng: &mut R,
    replay_filter: &std::sync::Mutex<ReplayFilter>,
) -> Result<(S, HandshakeResult)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: RngCore + CryptoRng,
{
    let hmac_key = static_keypair.identity_bytes();

    // 1. Read client message (up to MAX_HANDSHAKE_LENGTH)
    let mut buf = vec![0u8; MAX_HANDSHAKE_LENGTH];
    let mut buf_len = 0usize;

    // We need at least REPR_LEN bytes for X'
    while buf_len < REPR_LEN {
        let n = stream.read(&mut buf[buf_len..]).await?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        buf_len += n;
    }

    // Extract X' (first 32 bytes)
    let client_repr: [u8; REPR_LEN] = buf[..REPR_LEN].try_into().unwrap();

    // 2. Compute expected client mark: M_C = HMAC-SHA256-128(B||NODEID, X')
    let expected_mark = hmac_128(&hmac_key, &client_repr);

    // 3. Scan for M_C in the remaining data
    let mark_pos = loop {
        if let Some(pos) = find_mark(&buf[REPR_LEN..buf_len], &expected_mark) {
            break REPR_LEN + pos;
        }
        if buf_len >= MAX_HANDSHAKE_LENGTH {
            // Anti-probing: delay before dropping
            random_delay(rng).await;
            return Err(Error::HandshakeMacMismatch);
        }
        let n = stream.read(&mut buf[buf_len..]).await?;
        if n == 0 {
            random_delay(rng).await;
            return Err(Error::HandshakeMacMismatch);
        }
        buf_len += n;
    };

    // 4. Read MAC_C which follows the mark
    let mac_start = mark_pos + MARK_LEN;

    // 4b. Verify minimum client padding (anti-probing: real clients always
    // send at least CLIENT_MIN_PAD bytes of padding between X' and M_C).
    let pad_len = mark_pos - REPR_LEN;
    if pad_len < CLIENT_MIN_PAD {
        random_delay(rng).await;
        return Err(Error::HandshakeMacMismatch);
    }

    while buf_len < mac_start + MAC_LEN {
        let n = stream.read(&mut buf[buf_len..]).await?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        buf_len += n;
    }

    let received_mac: [u8; MAC_LEN] = buf[mac_start..mac_start + MAC_LEN].try_into().unwrap();

    // 5. Verify MAC_C with clock skew tolerance (E-1, E, E+1)
    let (mac_valid, epoch_str) = verify_mac_with_skew(
        &hmac_key,
        &buf[..mac_start], // X' || P_C || M_C
        &received_mac,
    );
    if !mac_valid {
        random_delay(rng).await;
        return Err(Error::HandshakeMacMismatch);
    }

    // 5b. Replay check — reject replayed handshakes (active probing defence).
    // Guard must be dropped before any .await — extract the bool first.
    let is_replay = {
        let mut filter = replay_filter.lock().expect("replay filter mutex poisoned");
        filter.test_and_set(received_mac)
    };
    if is_replay {
        random_delay(rng).await;
        return Err(Error::HandshakeMacMismatch);
    }

    // 6. Decode X from X' (Elligator2 reverse map)
    let client_point = elligator2::pubkey_from_representative(&client_repr);

    // 7. Generate server ephemeral keypair Y, y
    let server_epk = EphemeralKeypair::generate(rng);

    // 8. Complete ntor handshake (server side)
    let ntor_result = ntor::server_ntor(static_keypair, &server_epk, &client_point);

    // 9. Derive session keys
    let session_keys = SessionKeys::derive(&ntor_result.key_seed)?;

    // 10. Build server response: Y' || AUTH || P_S || M_S || MAC_S
    let server_mark = hmac_128(&hmac_key, &server_epk.representative);

    let pad_range = SERVER_MAX_PAD - SERVER_MIN_PAD + 1;
    let pad_len = SERVER_MIN_PAD + ((rng.next_u32() as usize) % pad_range);
    let mut padding = vec![0u8; pad_len];
    rng.fill_bytes(&mut padding);

    // MAC_S = HMAC-SHA256-128(B||NODEID, Y' || AUTH || P_S || M_S || E')
    let server_mac = {
        let mut h = HmacSha256::new_from_slice(&hmac_key).expect("hmac key ok");
        h.update(&server_epk.representative);
        h.update(&ntor_result.auth);
        h.update(&padding);
        h.update(&server_mark);
        h.update(epoch_str.as_bytes());
        truncate_128(h.finalize().into_bytes().as_slice())
    };

    let resp_len = REPR_LEN + AUTH_LEN + pad_len + MARK_LEN + MAC_LEN;
    let mut response = Vec::with_capacity(resp_len);
    response.extend_from_slice(&server_epk.representative);
    response.extend_from_slice(&ntor_result.auth);
    response.extend_from_slice(&padding);
    response.extend_from_slice(&server_mark);
    response.extend_from_slice(&server_mac);

    // 10b. Timing jitter: delay 1-50ms before responding.
    // Mimics TLS certificate lookup latency so DPI cannot distinguish
    // "instant obfs4 response" from a real HTTPS server.
    {
        let jitter_ms = 1 + (rng.next_u32() % 50) as u64;
        tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
    }

    stream.write_all(&response).await?;
    stream.flush().await?;

    Ok((
        stream,
        HandshakeResult {
            session_keys,
            trailing: Vec::new(),
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
/// Returns (valid, epoch_string_that_matched).
fn verify_mac_with_skew(
    hmac_key: &[u8],
    prefix: &[u8],
    received_mac: &[u8; MAC_LEN],
) -> (bool, String) {
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
            return (true, e_str);
        }
    }
    (false, String::new())
}

/// Anti-probing: sleep a random duration (0..5000ms) before closing connection.
async fn random_delay<R: RngCore>(rng: &mut R) {
    let ms = (rng.next_u32() % 5000) as u64;
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}
