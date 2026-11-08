//! What to do when a peer's bundle is refused as stale (`CryptoError::PeerSpkStale`).
//!
//! A signed prekey past `SPK_MAX_AGE_SECS` is refused for a clean open. Just past it, the peer
//! may have rotated already and the key server not yet be serving the new key: a refetch after a
//! short wait opens clean. Well past it, the peer has been away and no wait helps, so the open
//! goes degraded at once (`init_session_allowing_stale`, `stale-peer-reachability`).
//!
//! Until 0.65 the boundary lived in the iOS app as `30.25` days, a copy of this crate's 30 days
//! plus six hours, and Android had no stale path at all (todo/253). The wait itself — how long and
//! how often to refetch — is the platform's: it is about its network, not about the session.

use crate::crypto::client_api::SPK_MAX_AGE_SECS;

/// How long past the age limit a peer's rotation may still be on its way to the key server.
pub const SPK_ROTATION_GRACE_SECS: u64 = 6 * 3600;

/// The answer to a stale bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleSpkPlan {
    /// The peer may have rotated already: refetch the bundle after a short wait, and open
    /// degraded only if it is still stale.
    WaitForRotation,
    /// The peer has been away longer than any rotation takes to propagate: open degraded now.
    OpenDegraded,
}

/// Decide for a bundle refused with an SPK `age_secs` old.
pub fn plan_stale_spk(age_secs: u64) -> StaleSpkPlan {
    if age_secs > SPK_MAX_AGE_SECS + SPK_ROTATION_GRACE_SECS {
        StaleSpkPlan::OpenDegraded
    } else {
        StaleSpkPlan::WaitForRotation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600;

    /// Just past the limit, the rotation may be in flight. Mutation: degrade from the limit itself
    /// — this reddens.
    #[test]
    fn just_past_the_limit_is_worth_a_refetch() {
        assert_eq!(
            plan_stale_spk(SPK_MAX_AGE_SECS + 1),
            StaleSpkPlan::WaitForRotation
        );
        assert_eq!(
            plan_stale_spk(SPK_MAX_AGE_SECS + SPK_ROTATION_GRACE_SECS),
            StaleSpkPlan::WaitForRotation
        );
    }

    /// Past the grace, nothing is on its way. Mutation: always wait — this reddens.
    #[test]
    fn past_the_grace_opens_degraded_at_once() {
        assert_eq!(
            plan_stale_spk(SPK_MAX_AGE_SECS + SPK_ROTATION_GRACE_SECS + 1),
            StaleSpkPlan::OpenDegraded
        );
        assert_eq!(plan_stale_spk(45 * DAY), StaleSpkPlan::OpenDegraded);
    }

    /// The boundary the iOS app kept as 30.25 days.
    #[test]
    fn the_boundary_is_thirty_days_and_six_hours() {
        assert_eq!(
            SPK_MAX_AGE_SECS + SPK_ROTATION_GRACE_SECS,
            30 * DAY + 6 * 3600
        );
    }
}
