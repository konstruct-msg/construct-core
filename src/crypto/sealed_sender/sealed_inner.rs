//! Which way a `SealedInner` (construct-protos `core/envelope.proto`) is opened.
//!
//! A sealed delivery carries its writer in one of three fields, and which one is set is the
//! choice of route. Until 2026-10-11 that choice was the platform's. The iOS app read the fields
//! with its generated code and called the core per field, and Android would have had to make the
//! same choice again. It is read here, by field number, with the wire reader the history
//! protocol uses (`history::wire`), so the crate holds no second copy of the schema.

use crate::history::wire::{self, Value};

/// `SealedInner.sender_cert_ciphertext`.
const SENDER_CERT_CIPHERTEXT: u32 = 3;
/// `SealedInner.session_envelope`.
const SESSION_ENVELOPE: u32 = 21;
/// `SealedInner.first_flight`.
const FIRST_FLIGHT: u32 = 22;

/// The route a sealed delivery takes, with the bytes that route opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedRoute<'a> {
    /// A session envelope: the writer is found by the envelope book's tag
    /// (`decisions/sealed-envelope-keyed-by-the-session.md`).
    SessionEnvelope(&'a [u8]),
    /// A session's first flight, sealed whole to this device.
    FirstFlight(&'a [u8]),
    /// A sender certificate sealed to this device's identity key, with the payload beside it.
    SenderCertificate,
}

/// The route of `sealed_inner`, or `None` when it is not well-formed or names no writer.
///
/// The order is the one senders follow: a session envelope when one is set, then a first
/// flight, then a certificate. A field repeated on the wire counts by its last occurrence, as
/// protobuf decoders read it.
pub fn sealed_route(sealed_inner: &[u8]) -> Option<SealedRoute<'_>> {
    let mut envelope: &[u8] = &[];
    let mut first_flight: &[u8] = &[];
    let mut certificate: &[u8] = &[];
    for field in wire::fields(sealed_inner) {
        match field.ok()? {
            (SESSION_ENVELOPE, Value::Bytes(b)) => envelope = b,
            (FIRST_FLIGHT, Value::Bytes(b)) => first_flight = b,
            (SENDER_CERT_CIPHERTEXT, Value::Bytes(b)) => certificate = b,
            _ => {}
        }
    }
    if !envelope.is_empty() {
        Some(SealedRoute::SessionEnvelope(envelope))
    } else if !first_flight.is_empty() {
        Some(SealedRoute::FirstFlight(first_flight))
    } else if !certificate.is_empty() {
        Some(SealedRoute::SenderCertificate)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(number: u32, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        wire::write_varint(u64::from(number) << 3 | 2, &mut out);
        wire::write_varint(bytes.len() as u64, &mut out);
        out.extend_from_slice(bytes);
        out
    }

    fn varint_field(number: u32, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        wire::write_varint(u64::from(number) << 3, &mut out);
        wire::write_varint(value, &mut out);
        out
    }

    #[test]
    fn a_session_envelope_wins_over_the_other_fields() {
        let inner = [
            field(1, b"recipient"),
            field(SENDER_CERT_CIPHERTEXT, b"cert"),
            varint_field(5, 14),
            field(SESSION_ENVELOPE, b"env"),
        ]
        .concat();
        assert_eq!(
            sealed_route(&inner),
            Some(SealedRoute::SessionEnvelope(b"env"))
        );
    }

    #[test]
    fn a_first_flight_is_its_own_route() {
        let inner = [field(FIRST_FLIGHT, b"ff"), field(SESSION_ENVELOPE, b"")].concat();
        assert_eq!(sealed_route(&inner), Some(SealedRoute::FirstFlight(b"ff")));
    }

    #[test]
    fn a_certificate_alone_is_the_certificate_route() {
        let inner = [field(SENDER_CERT_CIPHERTEXT, b"cert"), field(4, b"payload")].concat();
        assert_eq!(sealed_route(&inner), Some(SealedRoute::SenderCertificate));
    }

    #[test]
    fn the_last_occurrence_of_a_field_counts() {
        let inner = [
            field(SESSION_ENVELOPE, b"first"),
            field(SESSION_ENVELOPE, b"last"),
        ]
        .concat();
        assert_eq!(
            sealed_route(&inner),
            Some(SealedRoute::SessionEnvelope(b"last"))
        );
    }

    #[test]
    fn nothing_naming_a_writer_or_garbage_is_no_route() {
        assert_eq!(sealed_route(&field(1, b"recipient")), None);
        assert_eq!(sealed_route(&[]), None);
        assert_eq!(sealed_route(&[0xff, 0xff]), None);
    }
}
