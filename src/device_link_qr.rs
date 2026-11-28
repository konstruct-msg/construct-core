//! The two QR codes that link a device, as text.
//!
//! - Flow A, shown by a device of the account: `konstruct://link?token=…&fp=<hex>&s=<hex>` — `fp`
//!   is [`qr_fingerprint`] of the showing device, `s` the secret the new device proves its keys
//!   under (construct-docs `decisions/devices-of-an-account-sign-each-other.md`); it never goes to
//!   the server.
//! - Flow B, shown by the new device:
//!   `konstruct://link-to-me?id=<device id>&pubkey=<base64>&fp=<hex>&name=…&platform=…` — `fp`
//!   names the new device's keys, the hybrid one included; the account's device vouches for exactly
//!   those.
//!
//! Written and read here once: the codes were built and parsed in Swift, Kotlin and Rust, and a
//! device named "Mac & iPad" cut its own query on iOS while the others read it (construct-ios
//! #354). Hex and base64 are the code's text boundary; nothing else here is text.

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::crypto::device_fingerprint::qr_fingerprint;
use crate::device_id::derive_device_id;

const OFFER: &str = "konstruct://link?";
const JOIN_REQUEST: &str = "konstruct://link-to-me?";

/// What a scanned code is. No `Debug`: an offer lets its reader into the account.
#[derive(Clone, PartialEq, Eq)]
pub enum LinkQr {
    /// Flow A. `fingerprint` and `secret` are absent from a code older than device certificates:
    /// the device links, unvouched.
    Offer {
        token: String,
        fingerprint: Option<[u8; 32]>,
        secret: Option<[u8; 32]>,
    },
    /// Flow B. Without `fingerprint` the device is let in, unvouched.
    JoinRequest {
        device_id: String,
        identity_public: [u8; 32],
        fingerprint: Option<[u8; 32]>,
        name: String,
        platform: String,
    },
}

/// The Flow A code. `fingerprint`: [`qr_fingerprint`] of this device, once it holds a hybrid key.
pub fn offer(token: &str, fingerprint: Option<&[u8; 32]>, secret: &[u8; 32]) -> String {
    let fp = fingerprint
        .map(|fp| format!("&fp={}", hex::encode(fp)))
        .unwrap_or_default();
    format!(
        "{OFFER}token={}{fp}&s={}",
        escape(token),
        hex::encode(secret)
    )
}

/// The Flow B code of the device that holds these keys: its id and fingerprint follow from them.
pub fn join_request(
    identity_public: &[u8; 32],
    hybrid_public: &[u8],
    name: &str,
    platform: &str,
) -> String {
    format!(
        "{JOIN_REQUEST}id={}&pubkey={}&fp={}&name={}&platform={}",
        derive_device_id(identity_public),
        escape(&STANDARD.encode(identity_public)),
        hex::encode(qr_fingerprint(identity_public, hybrid_public)),
        escape(name),
        escape(platform),
    )
}

/// The code in `text`; `None` when it is not one. A fingerprint or secret of any shape but 64 hex
/// characters reads as absent, never as a shorter key. A join request whose id is not its key's is
/// not one of ours.
pub fn read(text: &str) -> Option<LinkQr> {
    let text = text.trim();
    if let Some(query) = text.strip_prefix(OFFER) {
        return Some(LinkQr::Offer {
            token: value(query, "token").filter(|t| !t.is_empty())?,
            fingerprint: value(query, "fp").and_then(hex32),
            secret: value(query, "s").and_then(hex32),
        });
    }
    let query = text.strip_prefix(JOIN_REQUEST)?;
    let identity_public: [u8; 32] = STANDARD
        .decode(value(query, "pubkey")?)
        .ok()?
        .try_into()
        .ok()?;
    let device_id = value(query, "id").filter(|id| *id == derive_device_id(&identity_public))?;
    Some(LinkQr::JoinRequest {
        device_id,
        identity_public,
        fingerprint: value(query, "fp").and_then(hex32),
        name: value(query, "name")?,
        platform: value(query, "platform")?,
    })
}

/// The first value of `name`, percent-decoded once; `+` is itself.
fn value(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|item| item.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| unescape(value))
}

fn hex32(value: String) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

/// Everything but RFC 3986 unreserved ASCII, percent-encoded as UTF-8.
fn escape(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A `%` that begins no escape is itself.
fn unescape(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let mut rest = value.as_bytes();
    while let [first, tail @ ..] = rest {
        let escaped = (*first == b'%')
            .then(|| hex::decode(tail.get(..2)?).ok())
            .flatten();
        match escaped {
            Some(byte) => {
                out.extend(byte);
                rest = &tail[2..];
            }
            None => {
                out.push(*first);
                rest = tail;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0";
    const FP: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn fp() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    fn secret() -> [u8; 32] {
        std::array::from_fn(|i| 0xff - i as u8)
    }

    /// A key whose base64 holds every character that must be escaped.
    fn identity() -> [u8; 32] {
        std::array::from_fn(|i| [0xfb, 0xff, 0xbf][i % 3])
    }

    type Key = [u8; 32];
    type Offered = (String, Option<Key>, Option<Key>);
    type Requested = (String, Key, Option<Key>, String, String);

    fn offered(text: &str) -> Option<Offered> {
        match read(text)? {
            LinkQr::Offer {
                token,
                fingerprint,
                secret,
            } => Some((token, fingerprint, secret)),
            LinkQr::JoinRequest { .. } => None,
        }
    }

    fn requested(text: &str) -> Option<Requested> {
        match read(text)? {
            LinkQr::JoinRequest {
                device_id,
                identity_public,
                fingerprint,
                name,
                platform,
            } => Some((device_id, identity_public, fingerprint, name, platform)),
            LinkQr::Offer { .. } => None,
        }
    }

    /// The bytes iOS and Android have shown since construct-ios #354. Mutations that redden it: any
    /// field renamed, dropped or moved.
    #[test]
    fn an_offer_is_the_text_the_released_clients_show() {
        assert_eq!(
            offer("tok-_12", Some(&fp()), &secret()),
            format!("konstruct://link?token=tok-_12&fp={FP}&s={SECRET}")
        );
        assert_eq!(
            offer("t", None, &secret()),
            format!("konstruct://link?token=t&s={SECRET}")
        );
    }

    #[test]
    fn a_join_request_is_the_text_the_released_clients_show() {
        let hybrid = [7u8; 64];
        let id = derive_device_id(&identity());
        let print = hex::encode(qr_fingerprint(&identity(), &hybrid));
        assert_eq!(
            join_request(&identity(), &hybrid, "Max's Mac М", "android"),
            format!(
                "konstruct://link-to-me?id={id}&pubkey={}%2B%2F8%3D&fp={print}&name=Max%27s%20Mac%20%D0%9C&platform=android",
                "%2B%2F%2B%2F".repeat(10)
            )
        );
    }

    /// Mutation that reddens it: take the last.
    #[test]
    fn the_first_of_two_values_counts() {
        assert_eq!(offered("konstruct://link?token=a&token=b").unwrap().0, "a");
    }

    #[test]
    fn an_offer_reads_back() {
        let text = offer("tok", Some(&fp()), &secret());
        assert_eq!(
            offered(&format!("  {text}\n")),
            Some(("tok".into(), Some(fp()), Some(secret())))
        );
    }

    /// Mutations that redden it: decode `+` as a space (the key breaks); decode twice ("100%25").
    #[test]
    fn a_name_survives_the_trip() {
        for name in ["Pixel & Co", "a+b=c 100%", "100%25", "Максим’s", ""] {
            let text = join_request(&identity(), &[7; 64], name, "ios");
            assert_eq!(
                requested(&text),
                Some((
                    derive_device_id(&identity()),
                    identity(),
                    Some(qr_fingerprint(&identity(), &[7; 64])),
                    name.into(),
                    "ios".into()
                ))
            );
        }
    }

    /// A code written without escapes, as iOS wrote it before #354, still reads.
    #[test]
    fn an_unescaped_key_reads() {
        let id = derive_device_id(&identity());
        let key = STANDARD.encode(identity());
        let text = format!("konstruct://link-to-me?id={id}&pubkey={key}&name=5%&platform=ios");
        let (_, got, fingerprint, name, _) = requested(&text).unwrap();
        assert_eq!((got, fingerprint, name.as_str()), (identity(), None, "5%"));
    }

    /// Mutations that redden it: take a shorter key; read non-hex as zero.
    #[test]
    fn a_value_of_another_shape_is_absent() {
        for s in [&SECRET[2..], "zz", &SECRET.replace('f', "g"), ""] {
            let (_, fingerprint, secret) =
                offered(&format!("konstruct://link?token=t&fp={s}&s={s}")).unwrap();
            assert_eq!((fingerprint, secret), (None, None), "{s}");
        }
        assert_eq!(
            offered("konstruct://link?token=t"),
            Some(("t".into(), None, None))
        );
    }

    #[test]
    fn what_is_not_a_code_is_none() {
        let id = derive_device_id(&identity());
        let key = escape(&STANDARD.encode(identity()));
        let short = escape(&STANDARD.encode([1u8; 31]));
        for text in [
            "konstruct://add?invite=x".to_string(),
            format!("konstruct://link?fp={FP}"),
            "konstruct://link?token=".to_string(),
            format!("konstruct://link-to-me?id={id}&name=a&platform=ios"),
            format!("konstruct://link-to-me?id={id}&pubkey=%%%&name=a&platform=ios"),
            format!("konstruct://link-to-me?id={id}&pubkey={short}&name=a&platform=ios"),
            format!("konstruct://link-to-me?pubkey={key}&name=a&platform=ios"),
            format!("konstruct://link-to-me?id={id}&pubkey={key}&platform=ios"),
            format!("konstruct://link-to-me?id={id}&pubkey={key}&name=a"),
        ] {
            assert!(read(&text).is_none(), "{text}");
        }
    }

    /// The approver pins this key under this id. Mutation that reddens it: take any id.
    #[test]
    fn an_id_that_is_not_the_keys_own_is_refused() {
        let text = join_request(&identity(), &[7; 64], "a", "ios");
        let other = derive_device_id(&[1; 32]);
        let swapped = text.replace(&derive_device_id(&identity()), &other);
        assert!(read(&text).is_some());
        assert!(read(&swapped).is_none());
    }
}
