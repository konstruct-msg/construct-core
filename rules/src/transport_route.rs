//! Which path the next call takes: the server directly, or a VEIL front. A pure machine —
//! `(state, event, mode, config, now) -> (state, effects)` — no I/O, no clock.
//!
//! Three copies of this lived apart until now — iOS `TransportReducer` with the two rules its
//! router applied around it, Android `TransportRoute`, construct-client `veil::transport_route` —
//! held together by shared vectors, which are this module's tests (`transport_route/vectors.json`).
//! The decision that kept them apart, `transport-route-per-platform-shared-vectors.md`, is
//! replaced by `a-front-that-does-not-answer-is-left.md`.
//!
//! Events carry what the machine reads and nothing else: a latency or a stream's carrier is the
//! platform's to log. Times are Unix milliseconds.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Auto,
    On,
}

/// Which path a call or a stream went on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Direct,
    Veil,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFailure {
    OpenTimeout,
    MidSessionTimeout,
    WriteFailed,
    Closed,
    TransportUnknown,
    MidSessionClosed,
    MidSessionUnknown,
}

impl StreamFailure {
    fn mid_session(self) -> bool {
        matches!(
            self,
            Self::MidSessionTimeout
                | Self::WriteFailed
                | Self::MidSessionClosed
                | Self::MidSessionUnknown
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcFailure {
    TransientCancellation,
    AuthRejected,
    ApplicationError,
    /// The server's edge answered with an HTTP status and no gRPC status — a 502/503/504 while a
    /// service behind it restarts. The path works; neither it nor the front is to blame
    /// (2026-11-21: three of these demoted a healthy front on iOS).
    ServerNotReady,
    TlsFingerprintBlocked,
    TlsCertExpired,
    WebTunnelBlocked,
    /// Ours, not the front's: the next start may take the same front.
    StaleLocalProxy,
    StreamTimeout,
    TransportUnknown,
}

impl RpcFailure {
    fn is_transport(self) -> bool {
        !matches!(
            self,
            Self::TransientCancellation
                | Self::AuthRejected
                | Self::ApplicationError
                | Self::ServerNotReady
        )
    }

    fn is_hard_relay(self) -> bool {
        matches!(
            self,
            Self::TlsFingerprintBlocked
                | Self::TlsCertExpired
                | Self::WebTunnelBlocked
                | Self::StaleLocalProxy
        )
    }

    /// When this failure rotates the proxy, the fault is the front's, and the rotation demotes it.
    fn blames_front(self) -> bool {
        self.is_transport() && self != Self::StaleLocalProxy
    }
}

/// Which channel a call went on: `Auth` (signed in, also the stream's connection) or `Sealed`
/// (no identity, a connection of its own). One can be dead while the other carries on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Auth,
    Sealed,
}

/// Soft transport failures in a row through VEIL, per lane; a success on a lane clears it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SoftFails {
    pub auth: u32,
    pub sealed: u32,
}

impl SoftFails {
    fn get(self, lane: Lane) -> u32 {
        match lane {
            Lane::Auth => self.auth,
            Lane::Sealed => self.sealed,
        }
    }

    fn with(self, lane: Lane, n: u32) -> Self {
        match lane {
            Lane::Auth => Self { auth: n, ..self },
            Lane::Sealed => Self { sealed: n, ..self },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Offline,
    Direct {
        fails: u32,
    },
    VeilProbing,
    VeilActive {
        relay: String,
        port: u16,
        since_ms: i64,
        soft_fails: SoftFails,
        /// Dials to this front that failed in a row, with none that succeeded between.
        front_fails: u32,
    },
    VeilCooldown {
        until_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    RpcSucceeded {
        via: Via,
        lane: Lane,
    },
    /// `foreground`: a call the person waits on; background maintenance does not move the path.
    RpcFailed {
        failure: RpcFailure,
        via: Via,
        foreground: bool,
        lane: Lane,
    },
    StreamOpened {
        via: Via,
    },
    StreamFailed {
        failure: StreamFailure,
        via: Via,
    },
    NetworkPathChanged {
        reachable: bool,
    },
    /// The mode changed; the new one is the `mode` argument.
    VeilModeChanged,
    VeilConfigChanged,
    BackgroundWake,
    ProxyStarted {
        relay: String,
        port: u16,
        restarted: bool,
    },
    ProxyStartFailed,
    /// A new connection to this front came up: handshake and pin.
    FrontDialed {
        relay: String,
    },
    /// A new connection to this front did not come up. One per dial, whatever it tried inside;
    /// a dial we stopped ourselves is not one. Of any front but the current one it says nothing.
    FrontDialFailed {
        relay: String,
    },
    CooldownElapsed,
    ManualReset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    InvalidateGrpcClient,
    /// Point gRPC at this local port, or away from the tunnel (`None`).
    SetVeilPort {
        port: Option<u16>,
    },
    /// Start the proxy and answer with `ProxyStarted` or `ProxyStartFailed`.
    RequestProxyStart,
    RequestProxyStop,
    /// The rotation that follows is this front's fault: count it before the next start.
    DemoteRelay {
        relay: String,
    },
    /// Post `CooldownElapsed` at this time.
    ScheduleCooldownEnd {
        at_ms: i64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub direct_fail_threshold: u32,
    /// A stream that established and then died counts in full (iOS 2026-08-11).
    pub mid_session_death_weight: u32,
    pub allow_direct_to_veil_escalation: bool,
    /// The only backoff after a failed start.
    pub veil_cooldown_ms: i64,
    /// Soft failures in a row on one lane through VEIL that replace the proxy (a relay can take a
    /// connection and carry nothing over it — Russia, 2026-10-16).
    pub veil_soft_fail_threshold: u32,
    /// Dials to the current front that fail in a row before it is left. Three, not one as Tor has
    /// it: a single silent handshake is ordinary on a mobile network (iOS, 10–11.2026: 32 of 224,
    /// and the next to the same front mostly came up).
    pub front_dial_fail_threshold: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            direct_fail_threshold: 2,
            mid_session_death_weight: 2,
            allow_direct_to_veil_escalation: true,
            veil_cooldown_ms: 30_000,
            veil_soft_fail_threshold: 3,
            front_dial_fail_threshold: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub state: State,
    pub effects: Vec<Effect>,
}

fn outcome(state: State, effects: Vec<Effect>) -> Outcome {
    Outcome { state, effects }
}

/// Where a fresh process starts. Auto never pre-activates VEIL from geography.
pub fn initial(mode: Mode, reachable: bool) -> State {
    if !reachable {
        State::Offline
    } else if mode == Mode::On {
        State::VeilProbing
    } else {
        State::Direct { fails: 0 }
    }
}

pub fn reduce(state: &State, event: &Event, mode: Mode, config: Config, now_ms: i64) -> Outcome {
    let effective = Config {
        allow_direct_to_veil_escalation: config.allow_direct_to_veil_escalation
            && mode != Mode::Off,
        ..config
    };
    let out = reduce_inner(state, event, mode, effective, now_ms);
    // Auto: a direct call that succeeds while VEIL is up means VEIL was a false positive.
    if mode == Mode::Auto
        && matches!(state, State::VeilActive { .. })
        && matches!(
            event,
            Event::RpcSucceeded {
                via: Via::Direct,
                ..
            }
        )
    {
        let mut effects = out.effects;
        for e in [Effect::RequestProxyStop, Effect::SetVeilPort { port: None }] {
            if !effects.contains(&e) {
                effects.push(e);
            }
        }
        return outcome(State::Direct { fails: 0 }, effects);
    }
    // On never goes direct (decisions/veil-on-never-goes-direct.md).
    if mode == Mode::On && matches!(out.state, State::Direct { .. }) {
        let mut effects = out.effects;
        if !effects.contains(&Effect::RequestProxyStart) {
            effects.push(Effect::RequestProxyStart);
        }
        return outcome(State::VeilProbing, effects);
    }
    out
}

fn teardown() -> Vec<Effect> {
    vec![
        Effect::RequestProxyStop,
        Effect::SetVeilPort { port: None },
        Effect::InvalidateGrpcClient,
    ]
}

fn rotate() -> Vec<Effect> {
    vec![
        Effect::RequestProxyStop,
        Effect::SetVeilPort { port: None },
        Effect::RequestProxyStart,
        Effect::InvalidateGrpcClient,
    ]
}

fn reduce_inner(state: &State, event: &Event, mode: Mode, config: Config, now_ms: i64) -> Outcome {
    // Events that apply whatever the state.
    match event {
        Event::NetworkPathChanged { reachable } => {
            if !reachable {
                return outcome(State::Offline, teardown());
            }
            let next = initial(mode, true);
            let mut effects = teardown();
            if next == State::VeilProbing {
                effects.push(Effect::RequestProxyStart);
            }
            return outcome(next, effects);
        }
        Event::ManualReset => {
            return if *state == (State::Direct { fails: 0 }) {
                outcome(state.clone(), vec![Effect::InvalidateGrpcClient])
            } else {
                outcome(State::Direct { fails: 0 }, teardown())
            };
        }
        Event::VeilModeChanged => return mode_changed(state, mode),
        // Active: replace the proxy. Anything else: a push must not move a working direct path
        // onto a relay, and a probe in flight finishes on its own.
        Event::VeilConfigChanged | Event::BackgroundWake => {
            return if matches!(state, State::VeilActive { .. }) {
                outcome(State::VeilProbing, rotate())
            } else {
                outcome(state.clone(), vec![])
            };
        }
        _ => {}
    }
    match state {
        State::Offline => outcome(state.clone(), vec![]),
        State::Direct { fails } => direct(*fails, event, config),
        State::VeilProbing => probing(event, config, now_ms),
        State::VeilActive { .. } => active(state, event, config),
        State::VeilCooldown { .. } => {
            if *event == Event::CooldownElapsed {
                outcome(
                    State::Direct { fails: 0 },
                    vec![Effect::InvalidateGrpcClient],
                )
            } else {
                outcome(state.clone(), vec![])
            }
        }
    }
}

fn mode_changed(state: &State, mode: Mode) -> Outcome {
    // Offline: an attempt would fail on DNS into a cooldown; the mode is reapplied on return.
    if *state == State::Offline {
        return outcome(state.clone(), vec![]);
    }
    match mode {
        Mode::Off => outcome(State::Direct { fails: 0 }, teardown()),
        Mode::On => {
            if matches!(state, State::VeilActive { .. } | State::VeilProbing) {
                outcome(state.clone(), vec![])
            } else {
                // What is open on the direct path goes before the tunnel exists.
                outcome(
                    State::VeilProbing,
                    vec![Effect::InvalidateGrpcClient, Effect::RequestProxyStart],
                )
            }
        }
        // Auto stops forcing and lets outcomes decide; it never starts VEIL by itself.
        Mode::Auto => outcome(state.clone(), vec![]),
    }
}

fn direct(fails: u32, event: &Event, config: Config) -> Outcome {
    let stay = |f| outcome(State::Direct { fails: f }, vec![]);
    match event {
        Event::RpcSucceeded { .. } => stay(0),
        Event::RpcFailed {
            failure,
            via,
            foreground,
            ..
        } => {
            if !foreground || *via == Via::Veil || !failure.is_transport() {
                stay(fails)
            } else {
                count_failure(fails, config, 1)
            }
        }
        Event::StreamOpened { via } => stay(if *via == Via::Veil { fails } else { 0 }),
        Event::StreamFailed { failure, via } => {
            if *via == Via::Veil {
                stay(fails)
            } else {
                let weight = if failure.mid_session() {
                    config.mid_session_death_weight
                } else {
                    1
                };
                count_failure(fails, config, weight)
            }
        }
        // Every way into Direct stops the proxy, so a start landing here raced past that stop.
        Event::ProxyStarted { .. } => outcome(
            State::Direct { fails },
            vec![Effect::RequestProxyStop, Effect::SetVeilPort { port: None }],
        ),
        _ => stay(fails),
    }
}

fn count_failure(fails: u32, config: Config, weight: u32) -> Outcome {
    let next = fails + weight.max(1);
    if config.allow_direct_to_veil_escalation && next >= config.direct_fail_threshold {
        return outcome(
            State::VeilProbing,
            vec![Effect::RequestProxyStart, Effect::InvalidateGrpcClient],
        );
    }
    outcome(State::Direct { fails: next }, vec![])
}

fn probing(event: &Event, config: Config, now_ms: i64) -> Outcome {
    match event {
        Event::ProxyStarted {
            relay,
            port,
            restarted,
        } => {
            let mut effects = vec![Effect::SetVeilPort { port: Some(*port) }];
            if *restarted {
                effects.push(Effect::InvalidateGrpcClient);
            }
            outcome(
                State::VeilActive {
                    relay: relay.clone(),
                    port: *port,
                    since_ms: now_ms,
                    soft_fails: SoftFails::default(),
                    front_fails: 0,
                },
                effects,
            )
        }
        Event::ProxyStartFailed => {
            let until = now_ms + config.veil_cooldown_ms;
            outcome(
                State::VeilCooldown { until_ms: until },
                vec![
                    Effect::SetVeilPort { port: None },
                    Effect::ScheduleCooldownEnd { at_ms: until },
                ],
            )
        }
        // The proxy is not up; call outcomes say nothing about it.
        _ => outcome(State::VeilProbing, vec![]),
    }
}

fn active(state: &State, event: &Event, config: Config) -> Outcome {
    let State::VeilActive {
        relay,
        port,
        since_ms,
        soft_fails,
        front_fails,
    } = state
    else {
        unreachable!("only called for VeilActive");
    };
    let with = |soft_fails, front_fails| State::VeilActive {
        relay: relay.clone(),
        port: *port,
        since_ms: *since_ms,
        soft_fails,
        front_fails,
    };
    let leave = |blamed: bool| {
        let mut effects = Vec::new();
        if blamed {
            effects.push(Effect::DemoteRelay {
                relay: relay.clone(),
            });
        }
        effects.extend(rotate());
        outcome(State::VeilProbing, effects)
    };
    match event {
        Event::RpcFailed {
            failure,
            via: Via::Veil,
            foreground: true,
            lane,
        } if failure.is_transport() => {
            // Hard: the relay is observably broken, rotate. Soft: the tunnel may live; reconnect —
            // until the same lane has failed softly `veil_soft_fail_threshold` times in a row.
            let fails = soft_fails.get(*lane) + 1;
            if failure.is_hard_relay() || fails >= config.veil_soft_fail_threshold {
                leave(failure.blames_front())
            } else {
                outcome(
                    with(soft_fails.with(*lane, fails), *front_fails),
                    vec![Effect::InvalidateGrpcClient],
                )
            }
        }
        // A call through the tunnel answered: that lane works.
        Event::RpcSucceeded {
            via: Via::Veil,
            lane,
        } => outcome(with(soft_fails.with(*lane, 0), *front_fails), vec![]),
        // A stream death alone does not prove the relay is burned.
        Event::StreamFailed { via: Via::Veil, .. } => {
            outcome(state.clone(), vec![Effect::InvalidateGrpcClient])
        }
        // A call over a connection that already stands does not clear this: it says nothing about
        // the front taking a new one.
        Event::FrontDialFailed { relay: dialed } if dialed == relay => {
            let fails = front_fails + 1;
            if fails >= config.front_dial_fail_threshold {
                leave(true)
            } else {
                outcome(with(*soft_fails, fails), vec![])
            }
        }
        Event::FrontDialed { relay: dialed } if dialed == relay => {
            outcome(with(*soft_fails, 0), vec![])
        }
        _ => outcome(state.clone(), vec![]),
    }
}

#[cfg(test)]
mod tests;
