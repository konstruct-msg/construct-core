//! What state a ratchet is in, and what may happen to it next.
//!
//! # Why this exists
//!
//! A session is a ratchet between **two devices**, and until 2026-09 its phase was not written
//! down anywhere: it was inferred from three maps in `Orchestrator` and five timers on the iOS
//! side. Every one of them was a slice of one lifecycle cut along a different seam, and the seams
//! did not line up — the shape the END_SESSION storms kept coming out of.
//! See `construct-docs/decisions/session-is-one-state-machine.md`.
//!
//! # What left on 2026-09-27
//!
//! Half of what this machine held was there because a session could be opened only from a
//! message numbered 0, and a record held one state: the SESSION_RESET_INIT confirm window and its
//! re-sends, the hold behind it, the heal and its cooldown, the tie-break turn and the reopen
//! quiet. A record now keeps its previous states and any message carrying the handshake header
//! opens (`decisions/sessions-renew-by-sending.md`), so two sides opening at once converge by
//! themselves and nothing has to be waited for, announced or ordered.
//!
//! The teardown window went the same day, with END_SESSION (variant B): a decryption error names
//! the state it is about, so a stale one is recognised exactly and needs no cooldown, retry budget,
//! debt or quiet. What is left is the lock on an init in flight.

use std::collections::HashMap;
use std::sync::Arc;

use crate::orchestration::clock::Clock;

/// How long `Opening` may last before the machine stops believing it (ms).
///
/// An init that never completes — the bundle fetch died with the network — would otherwise hold
/// every later message behind a lock nothing releases.
pub const OPENING_TTL_MS: u64 = 30_000;

/// What the machine believes about one ratchet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// No session being opened.
    Absent,
    /// We are opening a session by sending: the bundle is being fetched and the init run. Nothing
    /// else may start a second one — two inits spend two of the peer's one-time pre-keys for one
    /// state that will be used.
    Opening { since_ms: u64 },
}

/// What a client of the machine wants to happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Something needs a session with this device and there is none.
    WantToOpen,
    /// The init finished, either way. A failed init leaves no session, and a successful one is
    /// visible in the lifecycle manager.
    OpenFinished,
    /// The open this `Opening` was granted for was refused; the state held before it, if any, is
    /// still held, unchanged.
    OpenFailed,
    /// Everything about this device is being forgotten (contact deleted, account wiped).
    Forget,
}

/// What the caller must do about it. One effect per event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Go ahead: open the session.
    Open,
    /// An init is already in flight. The message waits behind it rather than starting a second.
    WaitForOpen,
    /// Nothing to do.
    Nothing,
}

/// One phase per device, and the transitions between them.
///
/// Keyed by `CryptoDeviceId`, like everything below the seam. An account has no phase: two
/// devices of one person are two ratchets.
pub struct SessionMachine {
    phases: HashMap<String, Phase>,
    clock: Arc<dyn Clock>,
}

impl SessionMachine {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            phases: HashMap::new(),
            clock,
        }
    }

    /// The phase of this ratchet **now** — with the time-out already applied, so a caller cannot
    /// read a phase the machine would not act on.
    pub fn phase(&self, device_id: &str) -> Phase {
        let now = self.clock.now_ms();
        match self.phases.get(device_id) {
            Some(Phase::Opening { since_ms }) if now.saturating_sub(*since_ms) < OPENING_TTL_MS => {
                Phase::Opening {
                    since_ms: *since_ms,
                }
            }
            _ => Phase::Absent,
        }
    }

    /// Feed the machine an event, get the one thing to do about it.
    pub fn handle(&mut self, device_id: &str, event: Event) -> Effect {
        let now = self.clock.now_ms();
        match event {
            Event::WantToOpen => {
                if matches!(self.phase(device_id), Phase::Opening { .. }) {
                    return Effect::WaitForOpen;
                }
                // Opening while the peer opens is not a contradiction: both states are kept and
                // the first message either side reads settles on one.
                self.phases
                    .insert(device_id.to_string(), Phase::Opening { since_ms: now });
                Effect::Open
            }
            Event::OpenFinished | Event::OpenFailed | Event::Forget => {
                self.phases.remove(device_id);
                Effect::Nothing
            }
        }
    }

    /// Devices the machine currently holds a live `Opening` for — what the persisted
    /// coordination state carries across a restart, and all it carries.
    pub fn opening_device_ids(&self) -> Vec<String> {
        self.phases
            .keys()
            .filter(|id| matches!(self.phase(id), Phase::Opening { .. }))
            .cloned()
            .collect()
    }

    /// Restore `Opening` for the devices a previous run left mid-init, **as of now**: the stored
    /// set carries ids and not timestamps, and dating them to the restore is what makes the TTL
    /// still bound them.
    pub fn restore_opening(&mut self, device_ids: impl IntoIterator<Item = String>) {
        let now = self.clock.now_ms();
        self.phases.clear();
        for id in device_ids {
            self.phases.insert(id, Phase::Opening { since_ms: now });
        }
    }

    /// Drop expired openings. Memory hygiene, not policy.
    pub fn prune_expired(&mut self) {
        let now = self.clock.now_ms();
        self.phases.retain(|_, phase| match phase {
            Phase::Opening { since_ms } => now.saturating_sub(*since_ms) < OPENING_TTL_MS,
            Phase::Absent => false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestration::clock::MockClock;

    /// Most of these tests only need "somebody opened it"; the ones that care name the role.
    fn machine(start: u64) -> (SessionMachine, Arc<MockClock>) {
        let clock = Arc::new(MockClock::new(start));
        (SessionMachine::new(clock.clone()), clock)
    }

    // ── Opening ───────────────────────────────────────────────────────────────

    /// The first caller opens; the second waits behind it. Two inits spend two of the peer's
    /// one-time pre-keys and the second replaces the first's session, which orphans every carrier
    /// already on the wire — the 2026-07-31 divergence.
    ///
    /// Mutation: return `Open` for both — this reddens.
    #[test]
    fn a_second_open_waits_behind_the_first() {
        let (mut m, _) = machine(1_000);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::WaitForOpen);
    }

    /// An init that never finished must not hold every later message forever. The network can
    /// take the bundle fetch with it, and nothing else would release the phase.
    #[test]
    fn an_abandoned_open_stops_blocking_after_its_ttl() {
        let (mut m, clock) = machine(1_000);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
        clock.advance_ms(OPENING_TTL_MS + 1);
        assert_eq!(m.phase("dev"), Phase::Absent);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
    }

    /// A finished init releases the in-flight lock. For a responder that is the whole of it: the
    /// peer already holds the ratchet its own carrier built, so nothing was announced and nothing
    /// is awaited.
    #[test]
    fn a_finished_open_releases_the_in_flight_lock() {
        let (mut m, _) = machine(1_000);
        m.handle("dev", Event::WantToOpen);
        m.handle("dev", Event::OpenFinished);
        assert_eq!(m.phase("dev"), Phase::Absent);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
    }

    /// A refused reopen ends the `Opening` it was granted and nothing else.
    #[test]
    fn a_refused_open_ends_its_opening() {
        let (mut m, _) = machine(1_000);
        m.handle("dev", Event::WantToOpen);
        m.handle("dev", Event::OpenFailed);
        assert_eq!(m.phase("dev"), Phase::Absent);
    }

    #[test]
    fn devices_do_not_share_a_phase() {
        let (mut m, _) = machine(1_000);
        assert_eq!(m.handle("dev-a", Event::WantToOpen), Effect::Open);
        assert_eq!(m.handle("dev-b", Event::WantToOpen), Effect::Open);
        assert_eq!(m.handle("dev-a", Event::WantToOpen), Effect::WaitForOpen);
    }

    #[test]
    fn forgetting_a_device_ends_its_opening() {
        let (mut m, _) = machine(1_000);
        m.handle("dev", Event::WantToOpen);
        m.handle("dev", Event::Forget);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
    }

    // ── Restart ───────────────────────────────────────────────────────────────

    /// What crosses a restart is the set of ids, and the TTL is re-dated to the restore — so a
    /// device that was mid-init when the app died is blocked for at most one more window rather
    /// than by a timestamp from another process's clock.
    #[test]
    fn restored_openings_are_bounded_from_the_restore() {
        let (mut m, clock) = machine(1_000);
        m.restore_opening(["dev".to_string()]);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::WaitForOpen);
        clock.advance_ms(OPENING_TTL_MS + 1);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
    }

    /// Only live openings are carried out; an expired one is not worth a line in the store.
    #[test]
    fn only_live_openings_are_exported() {
        let (mut m, clock) = machine(1_000);
        m.handle("live", Event::WantToOpen);
        m.handle("stale", Event::WantToOpen);
        clock.advance_ms(OPENING_TTL_MS + 1);
        m.handle("live", Event::WantToOpen); // re-dates it
        assert_eq!(m.opening_device_ids(), vec!["live".to_string()]);
    }
}
