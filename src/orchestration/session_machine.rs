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
/// One number where there were two: the core's `cooldowns` map said 5 s and the iOS
/// coordinator's `endSessionSentAt` said 30 s, for the same envelope to the same device. Both
/// gates were live, so what a peer actually experienced was whichever path noticed first — and
/// neither side could be reasoned about alone. 30 s is the one that was chosen against observed
/// storms; the 5 s cadence survives where it was earned, as the evidence retry below.
pub const END_SESSION_COOLDOWN_MS: u64 = 30_000;

/// Minimum time between successive *heals* of the same device (ms).
///
/// A heal and a teardown share the phase — both ask for the ratchet to be rebuilt — but they do
/// not cost the same. A teardown is an envelope to the peer, and its price is why the window
/// above is long. A heal is a local re-init off a leftover carrier the peer will re-deliver
/// anyway; holding it for half a minute delays a recovery that costs nobody anything.
pub const HEAL_COOLDOWN_MS: u64 = 5_000;

/// How soon a teardown may be repeated when there is **evidence** the last one did not land (ms).
///
/// There is no acknowledgement for END_SESSION; nothing says the peer applied it. The opposite is
/// observable — a message arriving on a ratchet we already destroyed is proof they did not. The
/// plain cooldown read that proof as a reason to stay quiet, and a single lost teardown left the
/// two sides disagreeing for the whole window (device 2026-08-11 07:19:03: messageNumber 3 and 4
/// both skipped, and the peer's own log has no END_SESSION in that window at all).
pub const END_SESSION_EVIDENCE_RETRY_MS: u64 = 3_000;

/// How many evidence-driven repeats a device gets before the ordinary window returns.
///
/// Bounded on purpose. This is the storm-prone path the cooldown exists for, so evidence buys a
/// few fast retries and not an open channel: if three re-notifications did not land, the fourth
/// is not what fixes it.
pub const END_SESSION_MAX_UNACKED_RETRIES: u32 = 3;

/// How long a spent retry budget is remembered (ms).
///
/// The budget is what stops evidence from becoming an open channel, so it must outlive the window
/// it was spent in — otherwise every window hands out a fresh allowance and the bound is per
/// window rather than per storm. It is not remembered forever either: a device quiet for two
/// windows is not in a storm, and its next divergence is a new one. This is the policy half of
/// the `purgeStaleCooldowns` timer it replaces, stated as a rule instead of a sweep.
pub const UNACKED_BUDGET_TTL_MS: u64 = END_SESSION_COOLDOWN_MS * 2;

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
    ///
    /// `unacked` counts the teardowns sent on evidence that the previous one never arrived. It is
    /// spent, not measured: only an evidence-driven send consumes it, and a session that comes
    /// back returns it whole.
    TearingDown {
        since_ms: u64,
        owed: bool,
        unacked: u32,
    },
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
    ///
    /// `evidence` is the caller saying it has proof the previous teardown did not land — today
    /// that means a message arrived on a session we no longer hold. It is a fact only the caller
    /// has; what it buys is the machine's to decide.
    WantToTearDown { evidence: bool },
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
    ///
    /// `TearingDown` is reported for the length of the *teardown* window, the longer of the two:
    /// it is the phase's own lifetime. A heal asks against its own, shorter window inside it —
    /// see `HEAL_COOLDOWN_MS`.
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
            }) if now.saturating_sub(*since_ms) < END_SESSION_COOLDOWN_MS => Phase::TearingDown {
                since_ms: *since_ms,
                owed: *owed,
                unacked: *unacked,
            },
            // An expired `Opening` or a `TearingDown` whose window has passed is `Absent` as far
            // as any decision is concerned. The entry is left in place so `Timeout` can still
            // find an owed teardown and so the retry budget outlives its window; `handle` is what
            // removes it.
            _ => Phase::Absent,
        }
    }

    /// The stored teardown record, whatever its window says: `(since_ms, owed, unacked)`.
    ///
    /// The budget is read through here rather than through `phase()` on purpose. A budget that
    /// expired with its window would be a fresh allowance every window, which is a bound per
    /// window and not per storm — see `UNACKED_BUDGET_TTL_MS`.
    fn teardown_record(&self, device_id: &str, now: u64) -> Option<(u64, bool, u32)> {
        match self.phases.get(device_id) {
            Some(Phase::TearingDown {
                since_ms,
                owed,
                unacked,
            }) => {
                let forgotten = now.saturating_sub(*since_ms) >= UNACKED_BUDGET_TTL_MS;
                Some((*since_ms, *owed, if forgotten { 0 } else { *unacked }))
            }
            _ => None,
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
                // The whole record goes, not just the `Opening`: a session that exists again
                // settles the debt against the one it replaced *and* returns the retry budget.
                // Paying the debt afterwards would tear down the session that fixed the problem
                // — the crossing-teardown defect, arriving by its own timer.
                self.phases.remove(device_id);
                Effect::Nothing
            }

            Event::WantToTearDown { evidence } => {
                let (since_ms, unacked) = match self.teardown_record(device_id, now) {
                    Some((since_ms, _, unacked)) => (since_ms, unacked),
                    None => {
                        // Nothing in flight: send, and charge the budget only if this send is
                        // itself a re-notification.
                        self.phases.insert(
                            device_id.to_string(),
                            Phase::TearingDown {
                                since_ms: now,
                                owed: false,
                                unacked: u32::from(evidence),
                            },
                        );
                        return Effect::TearDown;
                    }
                };
                let elapsed = now.saturating_sub(since_ms);
                // Which window this ask is held to. Evidence shortens it, and only while the
                // budget lasts; after that the ordinary window returns, budget and all.
                let on_evidence = evidence && unacked < END_SESSION_MAX_UNACKED_RETRIES;
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
                            unacked: unacked + u32::from(evidence),
                        },
                    );
                    return Effect::TearDown;
                }
                self.phases.insert(
                    device_id.to_string(),
                    Phase::TearingDown {
                        since_ms,
                        owed: true,
                        unacked,
                    },
                );
                Effect::DeferTearDown {
                    retry_after_ms: Self::remaining(now, since_ms, window),
                }
            }

            Event::WantToHeal => match self.teardown_record(device_id, now) {
                Some((since_ms, _, _)) if now.saturating_sub(since_ms) < HEAL_COOLDOWN_MS => {
                    Effect::DeferHeal {
                        retry_after_ms: Self::remaining(now, since_ms, HEAL_COOLDOWN_MS),
                    }
                }
                record => {
                    // A heal shares the phase with a teardown deliberately: both ask the peer to
                    // rebuild, and two of them inside one window is the storm this cools. It does
                    // not spend the teardown budget — nothing was sent to the peer.
                    let (owed, unacked) = record.map_or((false, 0), |(_, owed, u)| (owed, u));
                    self.phases.insert(
                        device_id.to_string(),
                        Phase::TearingDown {
                            since_ms: now,
                            owed,
                            unacked,
                        },
                    );
                    Effect::Heal
                }
            },

            Event::Timeout => {
                let Some((_, owed, unacked)) = self.teardown_record(device_id, now) else {
                    return Effect::Nothing;
                };
                // The window has passed either way, so the phase goes whatever the debt was.
                if owed {
                    // Paid exactly once, and as a fresh teardown — which re-enters the cooldown,
                    // so N suppressions inside one window still produce one send. The budget
                    // carries: the debt was incurred by asks that had their own evidence.
                    self.phases.insert(
                        device_id.to_string(),
                        Phase::TearingDown {
                            since_ms: now,
                            owed: false,
                            unacked,
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

    /// Drop teardown records nothing will ask about again.
    ///
    /// Memory hygiene, not policy: an entry past `UNACKED_BUDGET_TTL_MS` with no debt already
    /// answers every question the same way it would if it were absent. The iOS side swept these
    /// on a five-minute timer; the rule that made the sweep safe now lives in
    /// `teardown_record`, and this only reclaims the bytes.
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
        assert_eq!(
            m.handle("dev", Event::WantToTearDown { evidence: false }),
            Effect::TearDown
        );
        match m.handle("dev", Event::WantToTearDown { evidence: false }) {
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
        m.handle("dev", Event::WantToTearDown { evidence: false });
        for _ in 0..5 {
            m.handle("dev", Event::WantToTearDown { evidence: false });
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
        m.handle("dev", Event::WantToTearDown { evidence: false });
        m.handle("dev", Event::WantToTearDown { evidence: false });
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
        m.handle("dev", Event::WantToTearDown { evidence: false });
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
        m.handle("dev", Event::WantToTearDown { evidence: false });
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
        assert_eq!(
            m.handle("dev-a", Event::WantToTearDown { evidence: false }),
            Effect::TearDown
        );
        assert_eq!(
            m.handle("dev-b", Event::WantToTearDown { evidence: false }),
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
            m.handle("dev", Event::WantToTearDown { evidence: true }),
            Effect::TearDown
        );
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        assert_eq!(
            m.handle("dev", Event::WantToTearDown { evidence: true }),
            Effect::TearDown
        );
    }

    /// Without evidence the same elapsed time is not enough. The fast lane is bought by the
    /// proof, not by asking twice.
    #[test]
    fn the_fast_retry_is_not_available_without_evidence() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown { evidence: true });
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        match m.handle("dev", Event::WantToTearDown { evidence: false }) {
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
        m.handle("dev", Event::WantToTearDown { evidence: true });
        for _ in 0..(END_SESSION_MAX_UNACKED_RETRIES - 1) {
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
            assert_eq!(
                m.handle("dev", Event::WantToTearDown { evidence: true }),
                Effect::TearDown
            );
        }
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        match m.handle("dev", Event::WantToTearDown { evidence: true }) {
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
        m.handle("dev", Event::WantToTearDown { evidence: true });
        for _ in 0..(END_SESSION_MAX_UNACKED_RETRIES - 1) {
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
            m.handle("dev", Event::WantToTearDown { evidence: true });
        }
        // The long window passes and one ordinary teardown goes out.
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(
            m.handle("dev", Event::WantToTearDown { evidence: true }),
            Effect::TearDown
        );
        // It must not have come with a new allowance.
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        match m.handle("dev", Event::WantToTearDown { evidence: true }) {
            Effect::DeferTearDown { .. } => {}
            other => panic!("expected the budget to still be spent, got {other:?}"),
        }
    }

    /// A device quiet for two windows is not in a storm, and its next divergence is a new one.
    #[test]
    fn a_long_quiet_returns_the_budget() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown { evidence: true });
        for _ in 0..(END_SESSION_MAX_UNACKED_RETRIES - 1) {
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
            m.handle("dev", Event::WantToTearDown { evidence: true });
        }
        clock.advance_ms(UNACKED_BUDGET_TTL_MS + 1);
        assert_eq!(
            m.handle("dev", Event::WantToTearDown { evidence: true }),
            Effect::TearDown
        );
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        assert_eq!(
            m.handle("dev", Event::WantToTearDown { evidence: true }),
            Effect::TearDown
        );
    }

    /// A session that came back returns the budget whole: the teardown clearly landed, so the
    /// next divergence starts from nothing owed and nothing spent.
    #[test]
    fn a_rebuilt_session_returns_the_budget() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown { evidence: true });
        for _ in 0..(END_SESSION_MAX_UNACKED_RETRIES - 1) {
            clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
            m.handle("dev", Event::WantToTearDown { evidence: true });
        }
        m.handle("dev", Event::OpenFinished);
        assert_eq!(
            m.handle("dev", Event::WantToTearDown { evidence: true }),
            Effect::TearDown
        );
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        assert_eq!(
            m.handle("dev", Event::WantToTearDown { evidence: true }),
            Effect::TearDown
        );
    }

    /// The heal window is the shorter one. A heal is a local re-init off a carrier the peer
    /// re-delivers anyway; holding it for the teardown's half-minute delays a recovery that costs
    /// nobody anything.
    ///
    /// Mutation: measure the heal against `END_SESSION_COOLDOWN_MS` — this reddens.
    #[test]
    fn a_heal_waits_its_own_window_not_the_teardowns() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown { evidence: false });
        clock.advance_ms(HEAL_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::WantToHeal), Effect::Heal);
        // …and the teardown it shares the phase with is still held.
        match m.handle("dev", Event::WantToTearDown { evidence: false }) {
            Effect::DeferTearDown { .. } => {}
            other => panic!("expected the teardown to still be held, got {other:?}"),
        }
    }

    /// Healing does not spend the teardown budget: nothing went to the peer, so there is no
    /// re-notification to count.
    #[test]
    fn healing_does_not_spend_the_teardown_budget() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown { evidence: true });
        for _ in 0..3 {
            clock.advance_ms(HEAL_COOLDOWN_MS + 1);
            assert_eq!(m.handle("dev", Event::WantToHeal), Effect::Heal);
        }
        clock.advance_ms(END_SESSION_EVIDENCE_RETRY_MS + 1);
        assert_eq!(
            m.handle("dev", Event::WantToTearDown { evidence: true }),
            Effect::TearDown
        );
    }

    /// Forgetting a contact forgets its phase — including a debt, which would otherwise be paid
    /// to a device the user has deleted.
    #[test]
    fn forgetting_a_device_forgets_its_debt() {
        let (mut m, clock) = machine(1_000);
        m.handle("dev", Event::WantToTearDown { evidence: false });
        m.handle("dev", Event::WantToTearDown { evidence: false });
        m.handle("dev", Event::Forget);
        clock.advance_ms(END_SESSION_COOLDOWN_MS + 1);
        assert_eq!(m.handle("dev", Event::Timeout), Effect::Nothing);
    }
}
