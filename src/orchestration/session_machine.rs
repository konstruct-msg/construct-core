//! What state a ratchet is in, and what may happen to it next.
//!
//! # Why this exists
//!
//! A session is a ratchet between **two devices**, and until now its phase was not written down
//! anywhere: it was inferred from three maps in `Orchestrator` (`init_locks`, `cooldowns`,
//! `pending_end_sessions`) and from five timers on the iOS side (outbound END_SESSION cooldown,
//! inbound grace, re-init debounce, tie-break watchdog, responder fallback). Every one of them
//! is a slice of one lifecycle — *a session dies, a session is born* — cut along a different
//! seam, and the seams do not line up. That is the shape the END_SESSION storms kept coming out
//! of: each window was individually reasonable and nothing owned the sequence.
//!
//! See `construct-docs/decisions/session-is-one-state-machine.md`. This module is step 2, and
//! step 2 is the teardown/reopen half: the core's own three maps become one machine, keyed by
//! device, with one timer.
//!
//! # What is deliberately not here yet
//!
//! The decision names five states; this has three. `Established { epoch }` and
//! `Healing { attempts, replacing_epoch }` arrive with the consumers that need them — the
//! confirm gate (step 3) and the healing queue (step 4). A state nobody asks about is a state
//! nobody maintains, and the epoch in particular has exactly one reader today
//! (`SessionEpoch` on the client), which has not moved yet. "Session exists" is still answered
//! by `SessionLifecycleManager::has_session`, which is where the ratchet actually lives.

use std::collections::HashMap;
use std::sync::Arc;

use crate::orchestration::clock::Clock;

/// Minimum time between successive END_SESSION sends to the same device (ms).
///
/// The number is unchanged from the `cooldowns` map it replaces. It is here rather than in
/// `Orchestrator` because it is a property of `TearingDown`, not of the caller.
pub const END_SESSION_COOLDOWN_MS: u64 = 5_000;

/// How long `Opening` may last before the machine stops believing it (ms).
///
/// An init that never completes — the bundle fetch died with the network — would otherwise hold
/// every later message behind a lock nothing releases. Unchanged from `INIT_LOCK_TTL_MS`.
pub const OPENING_TTL_MS: u64 = 30_000;

/// What the machine believes about one ratchet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// No session, and nothing in flight for one.
    Absent,
    /// A session is being opened. Nothing else may start a second one: two inits spend two of
    /// the peer's one-time pre-keys and the second replaces the first, so the carriers already
    /// dispatched reference a ratchet we no longer hold.
    Opening { since_ms: u64 },
    /// A teardown has gone out and the peer has not yet acted on it. Inside this phase another
    /// teardown is not sent — it is **owed**, which is not the same as dropped.
    TearingDown { since_ms: u64, owed: bool },
}

/// What a client of the machine wants to happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Something needs a session with this device and there is none.
    WantToOpen,
    /// The init finished, either way. The machine does not care which: a failed init leaves no
    /// session, and a successful one is visible in the lifecycle manager.
    OpenFinished,
    /// This ratchet cannot decrypt and the peer must be told to rebuild it.
    WantToTearDown,
    /// This ratchet cannot decrypt and we intend to heal rather than tear down.
    WantToHeal,
    /// The timer the machine asked for has fired.
    Timeout,
    /// Everything about this device is being forgotten (contact deleted, account wiped).
    Forget,
}

/// What the caller must do about it. One effect per event: a machine that answers with a list is
/// a machine the caller can reorder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Go ahead: open the session.
    Open,
    /// An init is already in flight. The message waits behind it rather than starting a second.
    WaitForOpen,
    /// Go ahead: send the teardown.
    TearDown,
    /// Too soon. Tell the caller when to come back; the teardown is remembered and paid then.
    DeferTearDown { retry_after_ms: u64 },
    /// Go ahead: heal.
    Heal,
    /// Too soon, and unlike a teardown a heal is **not** owed — the condition that produced it
    /// (a message that will not open) survives, and the peer re-delivers.
    DeferHeal { retry_after_ms: u64 },
    /// Nothing to do.
    Nothing,
}

/// One phase per device, and the transitions between them.
///
/// Keyed by `CryptoDeviceId`, like everything below the seam. An account has no phase: two
/// devices of one person are two ratchets, and a teardown of one is not a teardown of the other.
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

    /// The phase of this ratchet **now** — with the time-outs already applied, so a caller
    /// cannot read a phase the machine would not act on.
    pub fn phase(&self, device_id: &str) -> Phase {
        let now = self.clock.now_ms();
        match self.phases.get(device_id) {
            Some(Phase::Opening { since_ms }) if now.saturating_sub(*since_ms) < OPENING_TTL_MS => {
                Phase::Opening {
                    since_ms: *since_ms,
                }
            }
            Some(Phase::TearingDown { since_ms, owed })
                if now.saturating_sub(*since_ms) < END_SESSION_COOLDOWN_MS =>
            {
                Phase::TearingDown {
                    since_ms: *since_ms,
                    owed: *owed,
                }
            }
            // An expired `Opening` or a `TearingDown` whose window has passed is `Absent` as far
            // as any decision is concerned. The entry is left in place so `Timeout` can still
            // find an owed teardown; `handle` is what removes it.
            _ => Phase::Absent,
        }
    }

    /// Feed the machine an event, get the one thing to do about it.
    pub fn handle(&mut self, device_id: &str, event: Event) -> Effect {
        let now = self.clock.now_ms();
        match event {
            Event::WantToOpen => match self.phase(device_id) {
                Phase::Opening { .. } => Effect::WaitForOpen,
                // Opening during a teardown is not a contradiction: the teardown asked the peer
                // to rebuild, and rebuilding is what this is. The cooldown governs how often we
                // *ask*, not whether we may answer.
                _ => {
                    self.phases
                        .insert(device_id.to_string(), Phase::Opening { since_ms: now });
                    Effect::Open
                }
            },

            Event::OpenFinished => {
                if matches!(self.phase(device_id), Phase::Opening { .. }) {
                    self.phases.remove(device_id);
                }
                // A session that now exists settles any debt against the one it replaced. Paying
                // it afterwards would tear down the session that fixed the problem — the
                // crossing-teardown defect, arriving by its own timer.
                self.forget_owed_teardown(device_id);
                Effect::Nothing
            }

            Event::WantToTearDown => match self.phase(device_id) {
                Phase::TearingDown { since_ms, .. } => {
                    let remaining = Self::remaining(now, since_ms, END_SESSION_COOLDOWN_MS);
                    self.phases.insert(
                        device_id.to_string(),
                        Phase::TearingDown {
                            since_ms,
                            owed: true,
                        },
                    );
                    Effect::DeferTearDown {
                        retry_after_ms: remaining,
                    }
                }
                _ => {
                    self.phases.insert(
                        device_id.to_string(),
                        Phase::TearingDown {
                            since_ms: now,
                            owed: false,
                        },
                    );
                    Effect::TearDown
                }
            },

            Event::WantToHeal => match self.phase(device_id) {
                Phase::TearingDown { since_ms, .. } => Effect::DeferHeal {
                    retry_after_ms: Self::remaining(now, since_ms, END_SESSION_COOLDOWN_MS),
                },
                _ => {
                    // A heal shares the window with a teardown deliberately: both ask the peer to
                    // rebuild, and two of them inside one window is the storm this cools.
                    self.phases.insert(
                        device_id.to_string(),
                        Phase::TearingDown {
                            since_ms: now,
                            owed: false,
                        },
                    );
                    Effect::Heal
                }
            },

            Event::Timeout => {
                let owed = matches!(
                    self.phases.get(device_id),
                    Some(Phase::TearingDown { owed: true, .. })
                );
                // The window has passed either way, so the phase goes whatever the debt was.
                if matches!(self.phases.get(device_id), Some(Phase::TearingDown { .. })) {
                    self.phases.remove(device_id);
                }
                if owed {
                    // Paid exactly once, and as a fresh teardown — which re-enters the cooldown,
                    // so N suppressions inside one window still produce one send.
                    self.phases.insert(
                        device_id.to_string(),
                        Phase::TearingDown {
                            since_ms: now,
                            owed: false,
                        },
                    );
                    Effect::TearDown
                } else {
                    Effect::Nothing
                }
            }

            Event::Forget => {
                self.phases.remove(device_id);
                Effect::Nothing
            }
        }
    }

    /// Whether a teardown is owed to this device — the debt the cooldown deferred.
    pub fn owes_teardown(&self, device_id: &str) -> bool {
        matches!(
            self.phases.get(device_id),
            Some(Phase::TearingDown { owed: true, .. })
        )
    }

    fn forget_owed_teardown(&mut self, device_id: &str) {
        if let Some(Phase::TearingDown {
            since_ms,
            owed: true,
        }) = self.phases.get(device_id)
        {
            let since_ms = *since_ms;
            self.phases.insert(
                device_id.to_string(),
                Phase::TearingDown {
                    since_ms,
                    owed: false,
                },
            );
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

    /// Restore `Opening` for the devices a previous run left mid-init.
    ///
    /// Restored **as of now**, not as of when they were acquired: the stored set carries ids and
    /// not timestamps, and dating them to the restore is what makes the TTL still bound them.
    pub fn restore_opening(&mut self, device_ids: impl IntoIterator<Item = String>) {
        let now = self.clock.now_ms();
        self.phases
            .retain(|_, phase| !matches!(phase, Phase::Opening { .. }));
        for id in device_ids {
            self.phases.insert(id, Phase::Opening { since_ms: now });
        }
    }

    /// Milliseconds left in a window that started at `since_ms`, plus a small margin so a timer
    /// armed for it lands *after* the window rather than on its edge.
    fn remaining(now: u64, since_ms: u64, window: u64) -> u64 {
        window.saturating_sub(now.saturating_sub(since_ms)) + 100
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestration::clock::MockClock;

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

    #[test]
    fn a_finished_open_releases_the_phase() {
        let (mut m, _) = machine(1_000);
        m.handle("dev", Event::WantToOpen);
        m.handle("dev", Event::OpenFinished);
        assert_eq!(m.phase("dev"), Phase::Absent);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
    }

    // ── Tearing down ──────────────────────────────────────────────────────────

    /// The first teardown goes; the second inside the window is deferred and **owed**. Dropping
    /// it is what lost three media messages in build 585: a message that failed to decrypt above
    /// msgNum 0 is bound to a ratchet nobody holds, and only the peer rebuilding recovers it.
    #[test]
    fn a_second_teardown_in_the_window_is_owed_not_dropped() {
        let (mut m, _) = machine(1_000);
        assert_eq!(m.handle("dev", Event::WantToTearDown), Effect::TearDown);
        match m.handle("dev", Event::WantToTearDown) {
            Effect::DeferTearDown { retry_after_ms } => {
                assert!(retry_after_ms > 0 && retry_after_ms <= END_SESSION_COOLDOWN_MS + 100)
            }
            other => panic!("expected a deferral, got {other:?}"),
        }
        assert!(m.owes_teardown("dev"));
    }

    /// N suppressions inside one window are one teardown afterwards, not N. The debt is a flag,
    /// not a queue — that is the whole reason the cooldown still does its job.
    #[test]
    fn many_suppressions_pay_one_teardown() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown);
        for _ in 0..5 {
            m.handle("dev", Event::WantToTearDown);
        }
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::TearDown);
        // And the payment re-enters the window, so the next timer finds nothing owed.
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }

    /// A debt paid after the session was rebuilt destroys the session that fixed the problem.
    /// This is the crossing teardown, arriving by its own timer.
    ///
    /// Mutation: drop `forget_owed_teardown` from `OpenFinished` — this reddens.
    #[test]
    fn an_owed_teardown_is_void_once_the_session_is_rebuilt() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown);
        m.handle("dev", Event::WantToTearDown);
        assert!(m.owes_teardown("dev"));

        m.handle("dev", Event::WantToOpen);
        m.handle("dev", Event::OpenFinished);

        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }

    /// A timer for a device with no debt sends nothing. Timers outlive their reason.
    #[test]
    fn a_timeout_with_no_debt_does_nothing() {
        let (mut m, _) = machine(1_000);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }

    // ── Healing shares the window ─────────────────────────────────────────────

    /// A heal and a teardown ask the peer for the same thing, so they share one window. Two of
    /// them inside it is the storm the cooldown exists for.
    #[test]
    fn a_heal_inside_a_teardown_window_is_deferred() {
        let (mut m, _) = machine(1_000);
        m.handle("dev", Event::WantToTearDown);
        match m.handle("dev", Event::WantToHeal) {
            Effect::DeferHeal { retry_after_ms } => assert!(retry_after_ms > 0),
            other => panic!("expected a deferral, got {other:?}"),
        }
    }

    /// Unlike a teardown, a deferred heal is not owed: the message that could not be opened is
    /// still undelivered, so the peer re-delivers and the decision is taken again with fresher
    /// facts. Owing it would heal against a condition that may have resolved.
    #[test]
    fn a_deferred_heal_leaves_no_debt() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown);
        m.handle("dev", Event::WantToHeal);
        assert!(!m.owes_teardown("dev"));
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }

    // ── One device is not its sibling ─────────────────────────────────────────

    /// The key is the device. A teardown of one device of an account says nothing about the
    /// other's ratchet, and the account-shaped version of this map is what let one device's reset
    /// archive its sibling's session.
    #[test]
    fn devices_do_not_share_a_phase() {
        let (mut m, _) = machine(1_000);
        assert_eq!(m.handle("dev-a", Event::WantToTearDown), Effect::TearDown);
        assert_eq!(m.handle("dev-b", Event::WantToTearDown), Effect::TearDown);
        assert_eq!(m.handle("dev-a", Event::WantToOpen), Effect::Open);
        assert_eq!(m.handle("dev-b", Event::WantToOpen), Effect::Open);
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

    /// Forgetting a contact forgets its phase — including a debt, which would otherwise be paid
    /// to a device the user has deleted.
    #[test]
    fn forgetting_a_device_forgets_its_debt() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown);
        m.handle("dev", Event::WantToTearDown);
        m.handle("dev", Event::Forget);
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }
}
