//! Whether the server's refusal of this device erases it.
//!
//! The server says why it refused a device with a number in the trailing metadata key
//! `construct-device-refusal` of an `UNAUTHENTICATED` status (construct-protos `DeviceRefusal`):
//! 1 removed — its row was deactivated, from another device of the account or by its own sign-out
//! elsewhere, and is never reactivated; 2 not found — an unapproved join request answers that too,
//! and so would a server that lost rows. The status text is for people; no client reads it.
//!
//! Only `Removed` erases, and only over a direct TLS connection to our server, before and after the
//! call: through VEIL the client speaks plaintext gRPC to the relay, and a relay that could forge
//! this answer could erase the device (construct-docs `decisions/sign-out-wipes-the-device.md`).
//! iOS and Android decided so; construct-client erased on the text "Device is inactive", with no
//! number and no path check — a relay could wipe a desktop (todo 292). One rule now.

/// gRPC `UNAUTHENTICATED`: the only status that carries a refusal.
pub const UNAUTHENTICATED: u32 = 16;

/// The metadata key the number travels in.
pub const METADATA_KEY: &str = "construct-device-refusal";

/// Why the server refused this device, as the number says (`DeviceRefusal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No number, an unknown one, or not a refusal at all.
    Unspecified,
    /// 1: the device's row was deactivated.
    Removed,
    /// 2: no such device — or a join request still waiting.
    NotFound,
}

/// The refusal a status carries: its gRPC code and the first value of `construct-device-refusal`,
/// if any. Only `UNAUTHENTICATED` carries one; surrounding whitespace in the value is ignored.
pub fn refusal(status_code: u32, trailer: Option<&str>) -> Refusal {
    if status_code != UNAUTHENTICATED {
        return Refusal::Unspecified;
    }
    match trailer.map(str::trim).and_then(|v| v.parse::<u32>().ok()) {
        Some(1) => Refusal::Removed,
        Some(2) => Refusal::NotFound,
        _ => Refusal::Unspecified,
    }
}

/// Whether `refusal` erases this device: `Removed`, received over direct TLS both before and after
/// the call (`over_direct_tls`).
pub fn erases_device(refusal: Refusal, over_direct_tls: bool) -> bool {
    over_direct_tls && refusal == Refusal::Removed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The number decides, on UNAUTHENTICATED only. Mutations that redden it: drop the status
    /// check; map 2 to `Removed`; read anything but the number.
    #[test]
    fn the_refusal_is_read_from_its_number() {
        assert_eq!(refusal(16, Some("1")), Refusal::Removed);
        assert_eq!(refusal(16, Some(" 1 ")), Refusal::Removed, "Android trims");
        assert_eq!(refusal(16, Some("2")), Refusal::NotFound);
        assert_eq!(
            refusal(7, Some("1")),
            Refusal::Unspecified,
            "PERMISSION_DENIED carries none"
        );
        assert_eq!(
            refusal(16, Some("7")),
            Refusal::Unspecified,
            "an unknown number"
        );
        assert_eq!(refusal(16, None), Refusal::Unspecified);
    }

    /// The text alone is no reason: what construct-client read before todo 292.
    #[test]
    fn the_text_alone_is_no_reason() {
        assert_eq!(
            refusal(16, Some("Device is inactive")),
            Refusal::Unspecified
        );
        assert_eq!(refusal(16, Some("removed")), Refusal::Unspecified);
    }

    /// Mutations that redden it: drop the path check (a relay erases the device); erase on
    /// `NotFound` (a join request erases the device mid-link).
    #[test]
    fn only_removed_over_direct_tls_erases() {
        assert!(erases_device(Refusal::Removed, true));
        assert!(
            !erases_device(Refusal::Removed, false),
            "through VEIL: a relay could forge it"
        );
        assert!(
            !erases_device(Refusal::NotFound, true),
            "a waiting join request"
        );
        assert!(!erases_device(Refusal::Unspecified, true));
    }
}
