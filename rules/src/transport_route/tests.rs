use super::*;
use serde_json::Value;

/// The cases iOS, Android and construct-client passed while each had its own machine.
fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors.json")).expect("json")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} in {v}"))
}

fn via(v: &Value) -> Via {
    match s(v, "via") {
        "direct" => Via::Direct,
        "veil" => Via::Veil,
        other => panic!("via {other}"),
    }
}

fn mode(v: &str) -> Mode {
    match v {
        "off" => Mode::Off,
        "auto" => Mode::Auto,
        "on" => Mode::On,
        other => panic!("mode {other}"),
    }
}

fn lane(v: &Value) -> Lane {
    match v.as_str().unwrap_or("auth") {
        "auth" => Lane::Auth,
        "sealed" => Lane::Sealed,
        other => panic!("lane {other}"),
    }
}

fn rpc_failure(v: &str) -> RpcFailure {
    match v {
        "transient_cancellation" => RpcFailure::TransientCancellation,
        "auth_rejected" => RpcFailure::AuthRejected,
        "application_error" => RpcFailure::ApplicationError,
        "tls_fingerprint_blocked" => RpcFailure::TlsFingerprintBlocked,
        "tls_cert_expired" => RpcFailure::TlsCertExpired,
        "web_tunnel_blocked" => RpcFailure::WebTunnelBlocked,
        "stale_local_proxy" => RpcFailure::StaleLocalProxy,
        "stream_timeout" => RpcFailure::StreamTimeout,
        "transport_unknown" => RpcFailure::TransportUnknown,
        other => panic!("rpc failure {other}"),
    }
}

fn stream_failure(v: &str) -> StreamFailure {
    match v {
        "open_timeout" => StreamFailure::OpenTimeout,
        "mid_session_timeout" => StreamFailure::MidSessionTimeout,
        "write_failed" => StreamFailure::WriteFailed,
        "closed" => StreamFailure::Closed,
        "transport_unknown" => StreamFailure::TransportUnknown,
        "mid_session_closed" => StreamFailure::MidSessionClosed,
        "mid_session_unknown" => StreamFailure::MidSessionUnknown,
        other => panic!("stream failure {other}"),
    }
}

fn state(v: &Value) -> State {
    match s(v, "kind") {
        "offline" => State::Offline,
        "direct" => State::Direct {
            fails: v["fails"].as_u64().unwrap() as u32,
        },
        "veil_probing" => State::VeilProbing,
        "veil_active" => State::VeilActive {
            relay: s(v, "relay").to_owned(),
            port: v["port"].as_u64().unwrap() as u16,
            since_ms: v["since_ms"].as_i64().unwrap(),
            soft_fails: SoftFails {
                auth: v["soft_fails"]["auth"].as_u64().unwrap() as u32,
                sealed: v["soft_fails"]["sealed"].as_u64().unwrap() as u32,
            },
            front_fails: 0,
        },
        "veil_cooldown" => State::VeilCooldown {
            until_ms: v["until_ms"].as_i64().unwrap(),
        },
        other => panic!("state {other}"),
    }
}

fn event(v: &Value) -> Event {
    match s(v, "kind") {
        "rpc_succeeded" => Event::RpcSucceeded {
            via: via(v),
            lane: lane(&v["lane"]),
        },
        "rpc_failed" => Event::RpcFailed {
            failure: rpc_failure(s(v, "failure")),
            via: via(v),
            foreground: v["foreground"].as_bool().unwrap(),
            lane: lane(&v["lane"]),
        },
        "stream_opened" => Event::StreamOpened { via: via(v) },
        "stream_failed" => Event::StreamFailed {
            failure: stream_failure(s(v, "failure")),
            via: via(v),
        },
        "network_path_changed" => Event::NetworkPathChanged {
            reachable: v["reachable"].as_bool().unwrap(),
        },
        "veil_mode_changed" => Event::VeilModeChanged,
        "veil_config_changed" => Event::VeilConfigChanged,
        "background_wake" => Event::BackgroundWake,
        "proxy_started" => Event::ProxyStarted {
            relay: s(v, "relay").to_owned(),
            port: v["port"].as_u64().unwrap() as u16,
            restarted: v["restarted"].as_bool().unwrap(),
        },
        "proxy_start_failed" => Event::ProxyStartFailed,
        "cooldown_elapsed" => Event::CooldownElapsed,
        "manual_reset" => Event::ManualReset,
        other => panic!("event {other}"),
    }
}

fn effect(v: &Value) -> Effect {
    match s(v, "kind") {
        "invalidate_grpc_client" => Effect::InvalidateGrpcClient,
        "set_veil_port" => Effect::SetVeilPort {
            port: v["port"].as_u64().map(|p| p as u16),
        },
        "request_proxy_start" => Effect::RequestProxyStart,
        "request_proxy_stop" => Effect::RequestProxyStop,
        "demote_relay" => Effect::DemoteRelay {
            relay: s(v, "relay").to_owned(),
        },
        "schedule_cooldown_end" => Effect::ScheduleCooldownEnd {
            at_ms: v["at_ms"].as_i64().unwrap(),
        },
        other => panic!("effect {other}"),
    }
}

fn config(defaults: &Value, over: &Value) -> Config {
    let get = |k: &str| over.get(k).unwrap_or(&defaults[k]).clone();
    Config {
        direct_fail_threshold: get("direct_fail_threshold").as_u64().unwrap() as u32,
        mid_session_death_weight: get("mid_session_death_weight").as_u64().unwrap() as u32,
        allow_direct_to_veil_escalation: get("allow_direct_to_veil_escalation").as_bool().unwrap(),
        veil_cooldown_ms: get("veil_cooldown_ms").as_i64().unwrap(),
        veil_soft_fail_threshold: get("veil_soft_fail_threshold").as_u64().unwrap() as u32,
        ..Config::default()
    }
}

/// Every shared case, as the three clients ran them: the starting state, or the final state and
/// the effects of the last event, in order.
#[test]
fn the_route_follows_the_shared_vectors() {
    let v = vectors();
    let now = v["now_ms"].as_i64().unwrap();
    let defaults = &v["default_config"];
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 50, "the vector file has its cases");
    let mut failed = Vec::new();
    for case in cases {
        let name = s(case, "name");
        if let Some(init) = case.get("initial") {
            let got = initial(mode(s(init, "mode")), init["reachable"].as_bool().unwrap());
            if got != state(&case["expect_state"]) {
                failed.push(format!("{name}: {got:?}"));
            }
            continue;
        }
        let cfg = config(defaults, case.get("config").unwrap_or(&Value::Null));
        let m = mode(s(case, "mode"));
        let mut current = state(&case["state"]);
        let mut effects = Vec::new();
        for e in case["events"].as_array().unwrap() {
            let out = reduce(&current, &event(e), m, cfg, now);
            current = out.state;
            effects = out.effects;
        }
        if current != state(&case["expect_state"]) {
            failed.push(format!("{name}: state {current:?}"));
        }
        if let Some(expected) = case.get("expect_effects") {
            let expected: Vec<Effect> = expected.as_array().unwrap().iter().map(effect).collect();
            if effects != expected {
                failed.push(format!("{name}: effects {effects:?}, want {expected:?}"));
            }
        }
    }
    assert!(
        failed.is_empty(),
        "{} cases:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

const RELAY: &str = "relay.example:443";

fn active(soft_fails: SoftFails, front_fails: u32) -> State {
    State::VeilActive {
        relay: RELAY.into(),
        port: 49262,
        since_ms: 1,
        soft_fails,
        front_fails,
    }
}

fn dial_failed(relay: &str) -> Event {
    Event::FrontDialFailed {
        relay: relay.into(),
    }
}

fn dialed(relay: &str) -> Event {
    Event::FrontDialed {
        relay: relay.into(),
    }
}

fn run(mut state: State, events: &[Event], mode: Mode) -> Outcome {
    let mut effects = Vec::new();
    for event in events {
        let out = reduce(&state, event, mode, Config::default(), 1_000_000);
        state = out.state;
        effects = out.effects;
    }
    Outcome { state, effects }
}

fn up(front_fails: u32) -> State {
    active(SoftFails::default(), front_fails)
}

/// The third dial in a row that fails leaves the front, for its fault, in either mode that has
/// one; the two before it only count (2026-11-24: 34 in a row moved nothing for 12.8 minutes).
#[test]
fn the_third_failed_dial_in_a_row_leaves_the_front() {
    for mode in [Mode::Auto, Mode::On] {
        let two = run(up(0), &[dial_failed(RELAY), dial_failed(RELAY)], mode);
        assert_eq!(two.state, up(2));
        assert_eq!(two.effects, vec![]);
        let three = run(up(0), &vec![dial_failed(RELAY); 3], mode);
        assert_eq!(three.state, State::VeilProbing);
        assert_eq!(
            three.effects,
            vec![
                Effect::DemoteRelay {
                    relay: RELAY.into()
                },
                Effect::RequestProxyStop,
                Effect::SetVeilPort { port: None },
                Effect::RequestProxyStart,
                Effect::InvalidateGrpcClient,
            ]
        );
    }
}

#[test]
fn a_dial_that_comes_up_starts_the_count_over() {
    let out = run(
        up(2),
        &[dialed(RELAY), dial_failed(RELAY), dial_failed(RELAY)],
        Mode::On,
    );
    assert_eq!(out.state, up(2));
}

/// A call answered over the connection that already stands is not a dial.
#[test]
fn a_call_that_answers_does_not_clear_failed_dials() {
    for lane in [Lane::Auth, Lane::Sealed] {
        let ok = Event::RpcSucceeded {
            via: Via::Veil,
            lane,
        };
        assert_eq!(run(up(2), &[ok], Mode::On).state, up(2));
    }
}

/// The other way too: a dial says nothing about calls, and soft failures keep the dials' count.
#[test]
fn dials_and_calls_are_counted_apart() {
    let soft = SoftFails { auth: 2, sealed: 1 };
    let out = run(
        active(soft, 1),
        &[dialed(RELAY), dial_failed(RELAY)],
        Mode::On,
    );
    assert_eq!(out.state, active(soft, 1));
    let failed = Event::RpcFailed {
        failure: RpcFailure::StreamTimeout,
        via: Via::Veil,
        foreground: true,
        lane: Lane::Sealed,
    };
    assert_eq!(
        run(up(2), &[failed], Mode::On).state,
        active(SoftFails { auth: 0, sealed: 1 }, 2)
    );
}

/// The address is the front, not the time: a late dial to the front before says nothing.
#[test]
fn another_fronts_dials_do_not_count() {
    let other = "other.example:443";
    let out = run(up(2), &[dial_failed(other), dialed(other)], Mode::On);
    assert_eq!(out.state, up(2));
    assert_eq!(out.effects, vec![]);
}

/// With no front up there is nothing to leave.
#[test]
fn dials_move_nothing_outside_an_active_front() {
    for state in [
        State::Offline,
        State::Direct { fails: 1 },
        State::VeilProbing,
        State::VeilCooldown {
            until_ms: 2_000_000,
        },
    ] {
        let out = run(state.clone(), &vec![dial_failed(RELAY); 4], Mode::Auto);
        assert_eq!(out.state, state);
        assert_eq!(out.effects, vec![]);
    }
}

#[test]
fn a_new_front_starts_at_zero() {
    let started = Event::ProxyStarted {
        relay: RELAY.into(),
        port: 1,
        restarted: true,
    };
    let out = run(State::VeilProbing, &[started], Mode::On);
    assert!(matches!(
        out.state,
        State::VeilActive {
            front_fails: 0,
            since_ms: 1_000_000,
            ..
        }
    ));
}

/// The server's edge with a service restarting behind it: the path works.
#[test]
fn a_server_that_is_not_ready_moves_nothing() {
    let failed = |via| Event::RpcFailed {
        failure: RpcFailure::ServerNotReady,
        via,
        foreground: true,
        lane: Lane::Auth,
    };
    let veil = run(up(0), &vec![failed(Via::Veil); 4], Mode::On);
    assert_eq!((veil.state, veil.effects), (up(0), vec![]));
    let direct = run(
        State::Direct { fails: 1 },
        &[failed(Via::Direct)],
        Mode::Auto,
    );
    assert_eq!(direct.state, State::Direct { fails: 1 });
}
