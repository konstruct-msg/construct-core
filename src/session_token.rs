//! What a client reads in its own access token: PASETO v4.public, as construct-server issues it.
//!
//! `v4.public.` + base64url(nonce (32) ‖ claims JSON ‖ signature (64)) + an optional `.footer`. The
//! nonce is the server's own addition to the format. The signature is not checked: the token came
//! from the server over an authenticated channel and only the server decides by it.
//!
//! Read once here: iOS and Android each parsed it, and construct-client still read a JWT, which
//! the server stopped issuing on 2026-06-29 — so a device linked there had no start cursor and
//! asked for the whole mailbox (construct-docs todo 338).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

const PREFIX: &str = "v4.public.";
const NONCE: usize = 32;
const SIGNATURE: usize = 64;

/// The claims a client has a use for. Each is absent when the token does not carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// `sub`: the account.
    pub user_id: Option<String>,
    /// `iat`, Unix seconds.
    pub issued_at: Option<i64>,
}

/// The claims of `token`; `None` when it is not a v4.public token.
pub fn claims(token: &str) -> Option<Claims> {
    let payload = token.strip_prefix(PREFIX)?.split('.').next()?;
    let payload = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let end = payload.len().checked_sub(SIGNATURE)?;
    let message = payload.get(NONCE..end)?;
    // JSON by rule 6's exception: the token's payload is the server's format, read, never kept.
    let json: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(message).ok()?;
    Some(Claims {
        user_id: json
            .get("sub")
            .and_then(|sub| sub.as_str())
            .filter(|sub| !sub.is_empty())
            .map(str::to_owned),
        issued_at: json.get("iat").and_then(serde_json::Value::as_i64),
    })
}

/// Where a newly linked device's stream starts: the moment its token was issued. What the mailbox
/// held before is sealed to keys this device never had. `None` when the token does not say.
pub fn start_cursor(access_token: &str) -> Option<String> {
    let issued_at = claims(access_token)?.issued_at.filter(|iat| *iat > 0)?;
    Some(format!("{}-0", issued_at.checked_mul(1000)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_of(message: &[u8]) -> String {
        let payload = [&[0xAA; 32][..], message, &[0xBB; 64]].concat();
        format!("v4.public.{}", URL_SAFE_NO_PAD.encode(payload))
    }

    const CLAIMS: &[u8] =
        br#"{"sub":"u-1","jti":"j","exp":1792783600,"iat":1792780000,"iss":"s","device_id":"d"}"#;

    /// Mutations that redden it: any of the two lengths; seconds taken for milliseconds.
    #[test]
    fn a_token_names_its_account_and_where_the_stream_starts() {
        let token = token_of(CLAIMS);
        for token in [
            token.clone(),
            format!("{token}.Zm9vdGVy"),
            format!("{token}=="),
        ] {
            assert_eq!(
                claims(&token),
                Some(Claims {
                    user_id: Some("u-1".into()),
                    issued_at: Some(1_792_780_000)
                })
            );
            assert_eq!(start_cursor(&token).as_deref(), Some("1792780000000-0"));
        }
    }

    /// What construct-client still read. Mutation that reddens it: drop the prefix check.
    #[test]
    fn another_format_is_no_token() {
        let jwt = format!("h.{}.s", URL_SAFE_NO_PAD.encode(CLAIMS));
        let v3 = token_of(CLAIMS).replace("v4.public.", "v3.public.");
        for token in ["", "v4.public.", "v4.public.!!!", &jwt, &v3] {
            assert_eq!(claims(token), None, "{token}");
        }
        for short in [0, 32, 64, 96] {
            let token = format!("v4.public.{}", URL_SAFE_NO_PAD.encode(vec![1u8; short]));
            assert_eq!(claims(&token), None, "{short}");
        }
        assert_eq!(claims(&token_of(b"[1]")), None);
    }

    /// Mutations that redden it: drop the sign check, the overflow check, the empty-account check.
    #[test]
    fn a_claim_that_says_nothing_is_absent() {
        let read = |message: &str| claims(&token_of(message.as_bytes())).unwrap();
        assert_eq!(read(r#"{"sub":""}"#).user_id, None);
        assert_eq!(read(r#"{"sub":7,"iat":"x"}"#).issued_at, None);
        for iat in ["0", "-5", "9223372036854775807", "null"] {
            let token = token_of(format!(r#"{{"sub":"u","iat":{iat}}}"#).as_bytes());
            assert_eq!(start_cursor(&token), None, "{iat}");
        }
    }
}
