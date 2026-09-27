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
//! themselves and nothing has to be waited for, announced or ordered. What is left is the lock on
//! an init in flight and the teardown window.

use std::collections::HashMap;
use std::sync::Arc;

use crate::orchestration::clock::Clock;

/// Minimum time between successive END_SESSION sends to the same device (ms).
///
/// One number where there were two: the core's `cooldowns` map said 5 s and the iOS
/// coordinator's `endSessionSentAt` said 30 s, for the same envelope to the same device. 30 s is
/// the one that was chosen against observed storms; the 5 s cadence survives where it was
/// earned, as the evidence retry below.
pub const END_SESSION_COOLDOWN_MS: u64 = 30_000;

/// How soon a teardown may be repeated when there is **evidence** the last one did not land (ms).
///
/// There is no acknowledgement for END_SESSION; nothing says the peer applied it. The opposite is
/// observable — a message arriving on a ratchet we already destroyed is proof they did not
/// (device 2026-08-11 07:19:03: messageNumber 3 and 4 both skipped, and the peer's own log has no
/// END_SESSION in that window at all).
pub const END_SESSION_EVIDENCE_RETRY_MS: u64 = 3_000;

/// How many evidence-driven repeats a device gets before the ordinary window returns.
///
/// Bounded on purpose: evidence buys a few fast retries and not an open channel.
pub const END_SESSION_MAX_UNACKED_RETRIES: u32 = 3;

/// How long a spent retry budget is remembered (ms).
///
/// The budget must outlive the window it was spent in — otherwise every window hands out a fresh
/// allowance and the bound is per window rather than per storm. A device quiet for two windows is
/// not in a storm, and its next divergence is a new one.
pub const UNACKED_BUDGET_TTL_MS: u64 = END_SESSION_COOLDOWN_MS * 2;

/// How long `Opening` may last before the machine stops believing it (ms).
///
/// An init that never completes — the bundle fetch died with the network — would otherwise hold
/// every later message behind a lock nothing releases.
pub const OPENING_TTL_MS: u64 = 30_000;

/// How long the peer's own teardown keeps ours quiet (ms).
///
/// The same number as `END_SESSION_COOLDOWN_MS`: both answer one question — may an END_SESSION
/// envelope go to this device now.
pub const PEER_TEARDOWN_QUIET_MS: u64 = END_SESSION_COOLDOWN_MS;

/// What the machine believes about one ratchet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// No session being opened, and no teardown window.
    Absent,
    /// We are opening a session by sending: the bundle is being fetched and the init run. Nothing
    /// else may start a second one — two inits spend two of the peer's one-time pre-keys for one
    /// state that will be used.
    Opening { since_ms: u64 },
    /// A teardown has gone out and the peer has not yet acted on it. Inside this phase another
    /// teardown is not sent — it is **owed**, which is not the same as dropped.
    ///
    /// `unacked` counts the teardowns sent on evidence that the previous one never arrived. It is
    /// spent, not measured: only an evidence-driven send consumes it, and a session that comes
    /// back returns it whole.
    ///
    /// `peer_asked` records who started this. **A teardown is owed only when we are the only side
    /// that knows.** If the peer sent it, they know — a blind repeat back at them says nothing and
    /// doubles the storm.
    TearingDown {
        since_ms: u64,
        owed: bool,
        unacked: u32,
        peer_asked: bool,
        /// Which session the debt condemns — the core's `session_id` of the ratchet that was
        /// held when the teardown was owed, set by `condemn`, meaningful only while `owed`.
        /// Without it the alarm could only ask "is there a session?", and the broken ratchet the
        /// debt exists to tear down *is* a session (device logs 2026-09-24).
        condemned: Option<String>,
    },
}

/// Why a teardown is being asked for — which is what decides how soon it may go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TearDownCause {
    /// This ratchet will not open, and nothing more is known. The storm-prone ask, and the only
    /// one the peer's own teardown silences.
    Blind,
    /// A message arrived on a ratchet we no longer hold — proof our last teardown never landed.
    /// Buys the short window, while the budget lasts.
    Unacknowledged,
    /// The teardown carries a reason the peer cannot work out for itself — today, that the
    /// one-time pre-key it chose could not be reproduced. Held to the ordinary window but never
    /// silenced.
    Explained,
}

/// What a client of the machine wants to happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Something needs a session with this device and there is none.
    WantToOpen,
    /// The init finished, either way. A failed init leaves no session, and a successful one is
    /// visible in the lifecycle manager.
    OpenFinished,
    /// The reopen this `Opening` was granted for was refused, and the session held before it is
    /// still held, unchanged. Ends the `Opening` and nothing else: a teardown record is not this
    /// refusal's to settle.
    OpenFailed,
    /// This ratchet cannot decrypt and the peer must be told to rebuild it.
    WantToTearDown { cause: TearDownCause },
    /// The **peer** tore this ratchet down and we have applied it. Opens the same window a
    /// teardown of ours opens, without a debt.
    PeerToreDown,
    /// The timer the machine asked for has fired.
    Timeout,
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
    /// Go ahead: send the teardown.
    TearDown,
    /// Too soon. Tell the caller when to come back; the teardown is remembered and paid then.
    DeferTearDown { retry_after_ms: u64 },
    /// Do not send, and do not come back: the peer tore this ratchet down itself, so a blind
    /// teardown carries nothing.
    TearDownNotNeeded,
    /// Nothing to do.
    Nothing,
}

/// What the machine has stored about a teardown, with the budget rule already applied.
#[derive(Debug, Clone)]
struct TearDownRecord {
    since_ms: u64,
    owed: bool,
    unacked: u32,
    peer_asked: bool,
    condemned: Option<String>,
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
            Some(Phase::TearingDown {
                since_ms,
                owed,
                unacked,
                peer_asked,
                condemned,
            }) if now.saturating_sub(*since_ms)
                < if *peer_asked {
                    PEER_TEARDOWN_QUIET_MS
                } else {
                    END_SESSION_COOLDOWN_MS
                } =>
            {
                Phase::TearingDown {
                    since_ms: *since_ms,
                    owed: *owed,
                    unacked: *unacked,
                    peer_asked: *peer_asked,
                    condemned: condemned.clone(),
                }
            }
            // An expired `Opening` or a `TearingDown` whose window has passed is `Absent` as far
            // as any decision is concerned. The entry is left in place so `Timeout` can still
            // find an owed teardown and so the retry budget outlives its window.
            _ => Phase::Absent,
        }
    }

    /// The stored teardown record, whatever its window says — the budget is per storm, not per
    /// window (`UNACKED_BUDGET_TTL_MS`).
    fn teardown_record(&self, device_id: &str, now: u64) -> Option<TearDownRecord> {
        match self.phases.get(device_id) {
            Some(Phase::TearingDown {
                since_ms,
                owed,
                unacked,
                peer_asked,
                condemned,
            }) => {
                let forgotten = now.saturating_sub(*since_ms) >= UNACKED_BUDGET_TTL_MS;
                Some(TearDownRecord {
                    since_ms: *since_ms,
                    owed: *owed,
                    unacked: if forgotten { 0 } else { *unacked },
                    peer_asked: *peer_asked,
                    condemned: condemned.clone(),
                })
            }
            _ => None,
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
                // Opening during a teardown is not a contradiction: the teardown asked the peer
                // to rebuild, and rebuilding is what this is. Nor is opening while the peer opens:
                // both states are kept and the first message either side reads settles on one.
                self.phases
                    .insert(device_id.to_string(), Phase::Opening { since_ms: now });
                Effect::Open
            }

            Event::OpenFinished => {
                // The whole record goes, not just the `Opening`: a session that exists again
                // settles the debt against the one it replaced *and* returns the retry budget.
                self.phases.remove(device_id);
                Effect::Nothing
            }

            Event::OpenFailed => {
                if matches!(self.phases.get(device_id), Some(Phase::Opening { .. })) {
                    self.phases.remove(device_id);
                }
                Effect::Nothing
            }

            Event::WantToTearDown { cause } => {
                let evidence = cause == TearDownCause::Unacknowledged;
                let record = match self.teardown_record(device_id, now) {
                    Some(record) => record,
                    None => {
                        self.phases.insert(
                            device_id.to_string(),
                            Phase::TearingDown {
                                since_ms: now,
                                owed: false,
                                unacked: u32::from(evidence),
                                peer_asked: false,
                                condemned: None,
                            },
                        );
                        return Effect::TearDown;
                    }
                };
                let elapsed = now.saturating_sub(record.since_ms);
                // The peer tore this down itself and is still inside its quiet: a blind ask says
                // nothing they do not know. Answered, not postponed.
                if record.peer_asked
                    && cause == TearDownCause::Blind
                    && elapsed < PEER_TEARDOWN_QUIET_MS
                {
                    return Effect::TearDownNotNeeded;
                }
                let on_evidence = evidence && record.unacked < END_SESSION_MAX_UNACKED_RETRIES;
                let window = if on_evidence {
                    END_SESSION_EVIDENCE_RETRY_MS
                } else {
                    END_SESSION_COOLDOWN_MS
                };
                if elapsed >= window {
                    self.phases.insert(
                        device_id.to_string(),
                        Phase::TearingDown {
                            since_ms: now,
                            owed: false,
                            unacked: record.unacked + u32::from(evidence),
                            peer_asked: false,
                            condemned: None,
                        },
                    );
                    return Effect::TearDown;
                }
                self.phases.insert(
                    device_id.to_string(),
                    Phase::TearingDown {
                        since_ms: record.since_ms,
                        owed: true,
                        unacked: record.unacked,
                        peer_asked: record.peer_asked,
                        condemned: record.condemned,
                    },
                );
                Effect::DeferTearDown {
                    retry_after_ms: Self::remaining(now, record.since_ms, window),
                }
            }

            Event::PeerToreDown => {
                // Restarts the quiet whoever opened the phase; the retry budget carries, and any
                // debt is discharged — the peer has said what our deferred teardown would have.
                let unacked = self
                    .teardown_record(device_id, now)
                    .map_or(0, |record| record.unacked);
                self.phases.insert(
                    device_id.to_string(),
                    Phase::TearingDown {
                        since_ms: now,
                        owed: false,
                        unacked,
                        peer_asked: true,
                        condemned: None,
                    },
                );
                Effect::Nothing
            }

            Event::Timeout => {
                if let Some(Phase::Opening { since_ms }) = self.phases.get(device_id).cloned() {
                    // Only owed: not to leak the entry.
                    if now.saturating_sub(since_ms) >= OPENING_TTL_MS {
                        self.phases.remove(device_id);
                    }
                    return Effect::Nothing;
                }
                let Some(record) = self.teardown_record(device_id, now) else {
                    return Effect::Nothing;
                };
                if record.owed {
                    // Paid exactly once, and as a fresh teardown — which re-enters the cooldown,
                    // so N suppressions inside one window still produce one send.
                    self.phases.insert(
                        device_id.to_string(),
                        Phase::TearingDown {
                            since_ms: now,
                            owed: false,
                            unacked: record.unacked,
                            peer_asked: false,
                            condemned: None,
                        },
                    );
                    Effect::TearDown
                } else {
                    self.phases.remove(device_id);
                    Effect::Nothing
                }
            }

            Event::Forget => {
                self.phases.remove(device_id);
                Effect::Nothing
            }
        }
    }

    /// Name the session an owed teardown condemns. A no-op unless a debt is owed.
    pub fn condemn(&mut self, device_id: &str, session: Option<String>) {
        if let Some(Phase::TearingDown {
            owed: true,
            condemned,
            ..
        }) = self.phases.get_mut(device_id)
        {
            *condemned = session;
        }
    }

    /// The session an owed teardown condemns, if one is owed and it was named.
    pub fn condemned(&self, device_id: &str) -> Option<String> {
        match self.phases.get(device_id) {
            Some(Phase::TearingDown {
                owed: true,
                condemned,
                ..
            }) => condemned.clone(),
            _ => None,
        }
    }

    /// Whether a teardown is owed to this device — the debt the cooldown deferred.
    pub fn owes_teardown(&self, device_id: &str) -> bool {
        matches!(
            self.phases.get(device_id),
            Some(Phase::TearingDown { owed: true, .. })
        )
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
        self.phases
            .retain(|_, phase| !matches!(phase, Phase::Opening { .. }));
        for id in device_ids {
            self.phases.insert(id, Phase::Opening { since_ms: now });
        }
    }

    /// Drop teardown records nothing will ask about again. Memory hygiene, not policy.
    pub fn prune_expired(&mut self) {
        let now = self.clock.now_ms();
        self.phases.retain(|_, phase| match phase {
            Phase::TearingDown {
                since_ms,
                owed: false,
                ..
            } => now.saturating_sub(*since_ms) < UNACKED_BUDGET_TTL_MS,
            _ => true,
        });
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

    /// And touches nothing else. A teardown debt condemns a ratchet a refusal did not replace.
    ///
    /// Mutation: remove the phase whatever it is — this reddens.
    #[test]
    fn a_refused_reopen_leaves_a_teardown_record_alone() {
        let (mut m, _) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        let before = m.phase("dev");
        assert!(matches!(before, Phase::TearingDown { .. }));
        m.handle("dev", Event::OpenFailed);
        assert_eq!(m.phase("dev"), before);
    }

    // ── Reopening after the peer's teardown ───────────────────────────────────

    /// A session established during the quiet ends it. Nothing here re-opens over a working
    /// session — that is the peer's rebuild having arrived, which is what the quiet was for.
    #[test]
    fn a_session_arriving_during_the_quiet_ends_it() {
        let (mut m, _) = machine(1_000);
        m.handle("dev", Event::PeerToreDown);
        m.handle("dev", Event::OpenFinished);
        assert_eq!(m.phase("dev"), Phase::Absent);
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
    }

    /// Our own teardown holds nothing back. We are the side that asked the peer to rebuild, so
    /// there is no crossing init to wait for — and the message that provoked the teardown is
    /// waiting on exactly this session.
    ///
    /// Mutation: drop `peer_asked: true` from the arm — this reddens.
    #[test]
    fn our_own_teardown_does_not_hold_the_reopen() {
        let (mut m, _) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        assert_eq!(m.handle("dev", Event::WantToOpen), Effect::Open);
    }

    // ── Whose turn it is to rebuild ───────────────────────────────────────────

    // `the_turn_outlasts_the_windows_inside_it` stood here until 2026-09-23. Every line of it
    // compared two constants, which is a `const _: () = assert!(...)` written as a test — the
    // module has those, and clippy rejects the runtime spelling (`assertions_on_constants`). The
    // relation that matters, `PEER_TEARDOWN_QUIET_MS < RESPONDER_OVERRIDE_MS`, is checked where
    // the constants are declared and so cannot be broken by an edit that skips the test suite.

    // ── Tearing down ──────────────────────────────────────────────────────────

    /// The first teardown goes; the second inside the window is deferred and **owed**. Dropping
    /// it is what lost three media messages in build 585: a message that failed to decrypt above
    /// msgNum 0 is bound to a ratchet nobody holds, and only the peer rebuilding recovers it.
    #[test]
    fn a_second_teardown_in_the_window_is_owed_not_dropped() {
        let (mut m, _) = machine(1_000);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Blind
                }
            ),
            Effect::TearDown
        );
        match m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        ) {
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
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        for _ in 0..5 {
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Blind,
                },
            );
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
    /// Mutation: leave the `TearingDown` record in place on `OpenFinished` — this reddens.
    #[test]
    fn an_owed_teardown_is_void_once_the_session_is_rebuilt() {
        let (mut m, clock) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        assert!(m.owes_teardown("dev"));

        m.handle("dev", Event::WantToOpen);
        m.handle("dev", Event::OpenFinished);

        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert!(!m.owes_teardown("dev"), "the rebuild settled it");
        // The alarm finds the rebuild's own unacknowledged announcement instead — the cooldown
        // and the SRI retry are both 30 s, so they come due together. What must not happen is the
        // teardown: paying it here destroys the session that fixed the problem.
        assert_ne!(m.handle("dev", Event::Timeout), Effect::TearDown);
    }

    /// A timer for a device with no debt sends nothing. Timers outlive their reason.
    #[test]
    fn a_timeout_with_no_debt_does_nothing() {
        let (mut m, _) = machine(1_000);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }

    // ── One device is not its sibling ─────────────────────────────────────────

    /// The key is the device. A teardown of one device of an account says nothing about the
    /// other's ratchet, and the account-shaped version of this map is what let one device's reset
    /// archive its sibling's session.
    #[test]
    fn devices_do_not_share_a_phase() {
        let (mut m, _) = machine(1_000);
        assert_eq!(
            m.handle(
                "dev-a",
                Event::WantToTearDown {
                    cause: TearDownCause::Blind
                }
            ),
            Effect::TearDown
        );
        assert_eq!(
            m.handle(
                "dev-b",
                Event::WantToTearDown {
                    cause: TearDownCause::Blind
                }
            ),
            Effect::TearDown
        );
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

    // ── Evidence the teardown did not land ────────────────────────────────────

    /// A message on a ratchet we already destroyed is proof the peer never applied the teardown.
    /// Reading that proof as a reason to stay quiet for the whole window is what left the two
    /// sides disagreeing for half a minute at a time (device 2026-08-11, messageNumber 3 and 4).
    ///
    /// Mutation: ignore `evidence` and always hold the long window — this reddens.
    #[test]
    fn evidence_buys_a_faster_retry_than_the_window() {
        let (mut m, clock) = machine(1_000);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::TearDown
        );
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::TearDown
        );
    }

    /// Without evidence the same elapsed time is not enough. The fast lane is bought by the
    /// proof, not by asking twice.
    #[test]
    fn the_fast_retry_is_not_available_without_evidence() {
        let (mut m, clock) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Unacknowledged,
            },
        );
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        match m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        ) {
            Effect::DeferTearDown { .. } => {}
            other => panic!("expected a deferral, got {other:?}"),
        }
    }

    /// Evidence buys a few fast retries, not an open channel. After the budget the ordinary
    /// window returns — if three re-notifications did not land, the fourth is not the fix.
    ///
    /// Mutation: drop the `unacked < MAX` guard — this reddens.
    #[test]
    fn the_budget_runs_out_and_the_window_returns() {
        let (mut m, clock) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Unacknowledged,
            },
        );
        for _ in 0..(END_SESSION_MAX_UNACKED_RETRIES - 1) {
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
            assert_eq!(
                m.handle(
                    "dev",
                    Event::WantToTearDown {
                        cause: TearDownCause::Unacknowledged
                    }
                ),
                Effect::TearDown
            );
        }
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        match m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Unacknowledged,
            },
        ) {
            Effect::DeferTearDown { retry_after_ms } => {
                assert!(retry_after_ms > END_SESSION_EVIDENCE_RETRY_MS)
            }
            other => panic!("expected the ordinary window, got {other:?}"),
        }
    }

    /// The budget outlives the window it was spent in. Resetting it at the window boundary would
    /// hand out a fresh allowance every window — a bound per window rather than per storm, which
    /// is four sends per half-minute instead of one.
    ///
    /// Mutation: read `unacked` through `phase()` instead of `teardown_record` — this reddens.
    #[test]
    fn a_spent_budget_survives_the_window_that_spent_it() {
        let (mut m, clock) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Unacknowledged,
            },
        );
        for _ in 0..(END_SESSION_MAX_UNACKED_RETRIES - 1) {
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged,
                },
            );
        }
        // The long window passes and one ordinary teardown goes out.
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::TearDown
        );
        // It must not have come with a new allowance.
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        match m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Unacknowledged,
            },
        ) {
            Effect::DeferTearDown { .. } => {}
            other => panic!("expected the budget to still be spent, got {other:?}"),
        }
    }

    /// A device quiet for two windows is not in a storm, and its next divergence is a new one.
    #[test]
    fn a_long_quiet_returns_the_budget() {
        let (mut m, clock) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Unacknowledged,
            },
        );
        for _ in 0..(END_SESSION_MAX_UNACKED_RETRIES - 1) {
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged,
                },
            );
        }
        clock.advance_ms(UNACKED_BUDGET_TTL_MS + 1);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::TearDown
        );
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::TearDown
        );
    }

    /// A session that came back returns the budget whole: the teardown clearly landed, so the
    /// next divergence starts from nothing owed and nothing spent.
    #[test]
    fn a_rebuilt_session_returns_the_budget() {
        let (mut m, clock) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Unacknowledged,
            },
        );
        for _ in 0..(END_SESSION_MAX_UNACKED_RETRIES - 1) {
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged,
                },
            );
        }
        m.handle("dev", Event::OpenFinished);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::TearDown
        );
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::TearDown
        );
    }

    // ── The peer's own teardown ────────────────────────────────────────────────

    /// The case the iOS 20 s grace existed for: the peer tears down, our first post-reset msg0
    /// fails AEAD, and the blind teardown that used to go back at them is answered instead.
    ///
    /// Answered, not deferred: nothing is owed and no timer is armed. A `DeferTearDown` here
    /// would be the grace's opposite — a guaranteed teardown at a peer that already reset.
    #[test]
    fn the_peers_teardown_answers_a_blind_ask_of_ours() {
        let (mut m, _clock) = machine(1_000);
        assert_eq!(m.handle("dev", Event::PeerToreDown), Effect::Nothing);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Blind
                }
            ),
            Effect::TearDownNotNeeded
        );
        assert!(
            !m.owes_teardown("dev"),
            "nothing is owed — the peer already knows"
        );
    }

    /// Evidence is not silenced by it — only delayed by the short window, and owed.
    ///
    /// The delay is right rather than incidental: a message arriving microseconds after the
    /// peer's teardown was in flight before it, so it is ordering and not proof they ignored us.
    /// Three seconds later it is proof, and the debt is paid. The difference from a blind ask is
    /// the whole point — that one is answered and this one is owed.
    #[test]
    fn the_peers_teardown_delays_evidence_but_still_owes_it() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::PeerToreDown);
        assert!(matches!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::DeferTearDown { .. }
        ));
        assert!(m.owes_teardown("dev"));
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::TearDown,
            "the short window applies inside the peer's quiet; only the blind ask is silenced"
        );
    }

    /// Nor an explained one. Silence here is the 4-DH retry loop continuing: the peer cannot
    /// work out by itself that the one-time pre-key it chose is the problem.
    ///
    /// Held to the ordinary window rather than sent at once — it is not evidence of anything
    /// lost — so inside the quiet it is deferred and owed, and the timer pays it.
    #[test]
    fn the_peers_teardown_does_not_silence_an_explained_one() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::PeerToreDown);
        assert!(matches!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Explained
                }
            ),
            Effect::DeferTearDown { .. }
        ));
        assert!(m.owes_teardown("dev"));
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::TearDown);
    }

    /// The quiet ends, and then a blind teardown is ordinary again.
    #[test]
    fn a_blind_teardown_returns_once_the_quiet_passes() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::PeerToreDown);
        clock.advance_ms(PEER_TEARDOWN_QUIET_MS + 1);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Blind
                }
            ),
            Effect::TearDown
        );
    }

    /// A suppressed ask does not restart the quiet. The window is about the peer's teardown, so
    /// N failing decrypts inside it must not push its end further away each time — which is how
    /// a cooldown becomes a mute.
    #[test]
    fn suppressed_asks_do_not_extend_the_peers_quiet() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::PeerToreDown);
        for _ in 0..5 {
            clock.advance_ms(PEER_TEARDOWN_QUIET_MS / 6);
            assert_eq!(
                m.handle(
                    "dev",
                    Event::WantToTearDown {
                        cause: TearDownCause::Blind
                    }
                ),
                Effect::TearDownNotNeeded
            );
        }
        clock.advance_ms(PEER_TEARDOWN_QUIET_MS);
        assert_eq!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Blind
                }
            ),
            Effect::TearDown
        );
    }

    /// A debt we owed is discharged by the peer's teardown: they have now said the thing our
    /// deferred teardown was going to say. Paying it afterwards would be a teardown sent into a
    /// reset already under way — the crossing-teardown defect arriving by its own timer.
    #[test]
    fn the_peers_teardown_discharges_our_debt() {
        let (mut m, clock) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        assert!(
            m.owes_teardown("dev"),
            "pre-condition: the second ask is owed"
        );
        m.handle("dev", Event::PeerToreDown);
        assert!(!m.owes_teardown("dev"));
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }

    /// The retry budget survives it. A storm does not stop being a storm because the other side
    /// took a turn, and the budget is what bounds it.
    #[test]
    fn the_peers_teardown_keeps_the_retry_budget() {
        let (mut m, clock) = machine(1_000);
        for _ in 0..END_SESSION_MAX_UNACKED_RETRIES {
            assert_eq!(
                m.handle(
                    "dev",
                    Event::WantToTearDown {
                        cause: TearDownCause::Unacknowledged
                    }
                ),
                Effect::TearDown
            );
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        }
        m.handle("dev", Event::PeerToreDown);
        // Budget spent: evidence no longer buys the short window, so this is held to the full one.
        assert!(matches!(
            m.handle(
                "dev",
                Event::WantToTearDown {
                    cause: TearDownCause::Unacknowledged
                }
            ),
            Effect::DeferTearDown { .. }
        ));
    }

    /// Forgetting a contact forgets its phase — including a debt, which would otherwise be paid
    /// to a device the user has deleted.
    #[test]
    fn forgetting_a_device_forgets_its_debt() {
        let (mut m, clock) = machine(1_000);
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        m.handle(
            "dev",
            Event::WantToTearDown {
                cause: TearDownCause::Blind,
            },
        );
        m.handle("dev", Event::Forget);
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }
}
