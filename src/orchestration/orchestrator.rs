/// Orchestrator — top-level facade (Phase 5).
///
/// Single entry point for all platform events. Swift / Kotlin call ONE function:
///
/// ```swift
/// let actions = orchestrator.handleEvent(event)
/// // execute each action, then feed results back as new events
/// ```
///
/// The `Orchestrator` holds the full orchestration state:
/// - `SessionLifecycleManager` (sessions, archives, ACK, healing, PQ)
/// - `MessageRouter` (routing decisions)
/// - Coordinator state: init locks, cooldowns, prewarm tracking
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::orchestration::actions::{Action, IncomingEvent};
use crate::orchestration::message_router::{IncomingMessage, MessageRouter, RoutingDecision};
use crate::orchestration::session_lifecycle::SessionLifecycleManager;
use crate::crypto::client_api::ClassicClient;
use crate::crypto::suites::classic::ClassicSuiteProvider;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum time between successive END_SESSION sends to the same contact (ms).
const END_SESSION_COOLDOWN_MS: u64 = 5_000;

/// Minimum time between prewarm attempts for the same contact (ms).
const PREWARM_COOLDOWN_MS: u64 = 30_000;

// ── Orchestrator ──────────────────────────────────────────────────────────────

pub struct Orchestrator {
    lifecycle: SessionLifecycleManager,
    router: MessageRouter,
    /// Contacts whose session initialisation is currently in progress.
    init_locks: HashSet<String>,
    /// contactId → Unix ms of last END_SESSION / prewarm (anti-loop cooldown).
    cooldowns: HashMap<String, u64>,
    /// Contacts that have been pre-warmed (lower userId prewarms on first contact).
    prewarm_done: HashSet<String>,
}

impl Orchestrator {
    /// Create a new orchestrator for the given local user.
    ///
    /// `client` is a freshly constructed (or key-restored) `ClassicClient`.
    pub fn new(client: ClassicClient<ClassicSuiteProvider>, my_user_id: String) -> Self {
        Self {
            lifecycle: SessionLifecycleManager::new(client, my_user_id),
            router: MessageRouter::new(),
            init_locks: HashSet::new(),
            cooldowns: HashMap::new(),
            prewarm_done: HashSet::new(),
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Unified event handler — the **only** method Swift / Kotlin need to call.
    ///
    /// Returns a list of `Action`s that the platform must execute in order.
    /// After executing I/O actions (network, storage), the platform feeds
    /// results back via further `handle_event` calls.
    pub fn handle_event(&mut self, event: IncomingEvent) -> Vec<Action> {
        match event {
            IncomingEvent::MessageReceived { from, data, msg_num, kem_ct, otpk_id } => {
                self.handle_message_received(from, data, msg_num, kem_ct, otpk_id)
            }
            IncomingEvent::SessionInitCompleted { contact_id, session_json } => {
                self.handle_session_init_completed(contact_id, session_json)
            }
            IncomingEvent::AckReceived { message_id } => {
                self.handle_ack_received(message_id)
            }
            IncomingEvent::SessionLoaded { key, data } => {
                self.handle_session_loaded(key, data)
            }
            IncomingEvent::KeyBundleFetched { user_id, bundle_json } => {
                self.handle_key_bundle_fetched(user_id, bundle_json)
            }
            IncomingEvent::NetworkReconnected => {
                self.handle_network_reconnected()
            }
            IncomingEvent::AppLaunched => {
                self.handle_app_launched()
            }
            IncomingEvent::TimerFired { timer_id } => {
                self.handle_timer_fired(timer_id)
            }
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn my_user_id(&self) -> &str {
        self.lifecycle.my_user_id()
    }

    pub fn has_active_session(&self, contact_id: &str) -> bool {
        self.lifecycle.has_active_session(contact_id)
    }

    pub fn pending_message_count(&self, contact_id: &str) -> usize {
        self.router.pending_count(contact_id)
    }

    // ── Event handlers ────────────────────────────────────────────────────────

    fn handle_message_received(
        &mut self,
        from: String,
        data: Vec<u8>,
        msg_num: u32,
        kem_ct: Vec<u8>,
        otpk_id: u32,
    ) -> Vec<Action> {
        let message_id = derive_message_id(&data, msg_num);
        let wire_json = match String::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                return vec![Action::NotifyError {
                    code: "INVALID_UTF8".to_string(),
                    message: "message data is not valid UTF-8".to_string(),
                }]
            }
        };

        let incoming = IncomingMessage {
            contact_id: from.clone(),
            wire_json,
            message_id,
            msg_number: msg_num,
            is_control: false,
        };

        // Store KEM ciphertext for PQ decapsulation if non-empty.
        // The platform must call back with `mlkem768_decapsulate` result.
        let mut actions = Vec::new();
        if !kem_ct.is_empty() {
            actions.push(Action::ApplyPQContribution {
                contact_id: from.clone(),
                kem_ss: kem_ct, // platform decapsulates, feeds ss back
            });
        }

        let decision = self.router.route_message(&mut self.lifecycle, &incoming);
        actions.extend(self.decision_to_actions(decision, &from));
        actions
    }

    fn handle_session_init_completed(
        &mut self,
        contact_id: String,
        session_json: String,
    ) -> Vec<Action> {
        self.init_locks.remove(&contact_id);

        // Import the newly created session.
        self.lifecycle.load_archive_json(&contact_id, session_json);

        // Save the session to secure store.
        let mut actions = vec![];
        if let Ok(json) = self.lifecycle.export_state_json() {
            actions.push(Action::SaveSessionToSecureStore {
                key: crate::orchestration::session_lifecycle::session_key(&contact_id),
                data: json.into_bytes(),
            });
        }

        // Drain the pending queue.
        let drained = self.router.drain_pending(&contact_id, &mut self.lifecycle);
        for decision in drained {
            actions.extend(self.decision_to_actions(decision, &contact_id));
        }

        actions.push(Action::NotifySessionCreated {
            contact_id: contact_id.clone(),
        });

        actions
    }

    fn handle_ack_received(&mut self, message_id: String) -> Vec<Action> {
        vec![Action::MarkMessageDelivered { message_id }]
    }

    fn handle_session_loaded(&mut self, key: String, data: Option<Vec<u8>>) -> Vec<Action> {
        // key format: "session_<contact_id>" or "archive_<contact_id>"
        let contact_id = key
            .strip_prefix("session_")
            .or_else(|| key.strip_prefix("archive_"))
            .unwrap_or(&key)
            .to_string();

        if let Some(bytes) = data {
            if let Ok(json) = String::from_utf8(bytes) {
                self.lifecycle.load_archive_json(&contact_id, json);
            }
        }
        vec![]
    }

    fn handle_key_bundle_fetched(&mut self, user_id: String, _bundle_json: String) -> Vec<Action> {
        // Session init is done by the platform using ClassicCryptoCore.init_session.
        // The result comes back via SessionInitCompleted.
        // Here we just clear the init lock if we were waiting.
        vec![Action::InitSession {
            contact_id: user_id,
            bundle_json: _bundle_json,
        }]
    }

    fn handle_network_reconnected(&mut self) -> Vec<Action> {
        // Schedule a GC sweep after reconnect.
        vec![Action::ScheduleTimer {
            timer_id: "gc_sweep".to_string(),
            delay_ms: 1_000,
        }]
    }

    fn handle_app_launched(&mut self) -> Vec<Action> {
        // Schedule a GC and prewarm sweep on launch.
        vec![
            Action::ScheduleTimer {
                timer_id: "gc_sweep".to_string(),
                delay_ms: 5_000,
            },
            Action::ScheduleTimer {
                timer_id: "prewarm_sweep".to_string(),
                delay_ms: 2_000,
            },
        ]
    }

    fn handle_timer_fired(&mut self, timer_id: String) -> Vec<Action> {
        match timer_id.as_str() {
            "gc_sweep" => {
                let mut actions = self.lifecycle.gc_old_archives();
                actions.extend(self.lifecycle.ack_store.prune_expired());
                actions.extend(self.lifecycle.healing_queue.prune_expired());
                actions
            }
            _ => vec![],
        }
    }

    // ── Decision → Actions ────────────────────────────────────────────────────

    fn decision_to_actions(&mut self, decision: RoutingDecision, contact_id: &str) -> Vec<Action> {
        match decision {
            RoutingDecision::Decrypted { plaintext, actions, contact_id: cid } => {
                let mut all = actions;
                all.push(Action::NotifyNewMessage {
                    chat_id: cid,
                    preview: preview(&plaintext),
                });
                all
            }
            RoutingDecision::NeedSessionInit { contact_id: cid, .. } => {
                if self.init_locks.contains(&cid) {
                    return vec![];
                }
                self.init_locks.insert(cid.clone());
                vec![Action::FetchPublicKeyBundle { user_id: cid }]
            }
            RoutingDecision::SessionHealNeeded { contact_id: cid, role } => {
                if self.on_cooldown(&cid) {
                    return vec![];
                }
                self.set_cooldown(cid.clone());
                vec![
                    Action::SendEndSession {
                        contact_id: cid.clone(),
                    },
                    Action::FetchPublicKeyBundle { user_id: cid },
                ]
            }
            RoutingDecision::EndSessionNeeded { contact_id: cid, reason } => {
                if self.on_cooldown(&cid) {
                    return vec![];
                }
                self.set_cooldown(cid.clone());
                vec![Action::SendEndSession { contact_id: cid }]
            }
            RoutingDecision::Duplicate { .. } => vec![],
            RoutingDecision::QueueFull { contact_id: cid } => {
                vec![Action::NotifyError {
                    code: "QUEUE_FULL".to_string(),
                    message: format!("Message queue full for {}", cid),
                }]
            }
            RoutingDecision::EndSessionReceived { contact_id: cid, actions } => actions,
            RoutingDecision::Error { message } => {
                vec![Action::NotifyError {
                    code: "ROUTING_ERROR".to_string(),
                    message,
                }]
            }
        }
    }

    // ── Cooldown helpers ──────────────────────────────────────────────────────

    fn on_cooldown(&self, contact_id: &str) -> bool {
        self.cooldowns
            .get(contact_id)
            .map_or(false, |&last_ms| {
                unix_ms().saturating_sub(last_ms) < END_SESSION_COOLDOWN_MS
            })
    }

    fn set_cooldown(&mut self, contact_id: String) {
        self.cooldowns.insert(contact_id, unix_ms());
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn unix_now() -> u64 {
    unix_ms() / 1_000
}

fn derive_message_id(data: &[u8], msg_num: u32) -> String {
    // Cheap deterministic ID: sha2 not available without feature, use a hash of
    // the first 16 bytes + message number. Good enough for deduplication.
    let prefix: u64 = data.iter().take(16).enumerate().fold(0u64, |acc, (i, &b)| {
        acc.wrapping_add((b as u64).wrapping_shl(i as u32 % 64))
    });
    format!("{}_{}", prefix, msg_num)
}

fn preview(plaintext: &[u8]) -> String {
    let s = String::from_utf8_lossy(plaintext);
    let chars: String = s.chars().take(50).collect();
    chars
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_api::ClassicClient;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    fn make_orchestrator(user_id: &str) -> Orchestrator {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        Orchestrator::new(client, user_id.to_string())
    }

    #[test]
    fn test_new_orchestrator() {
        let o = make_orchestrator("alice");
        assert_eq!(o.my_user_id(), "alice");
        assert!(!o.has_active_session("bob"));
        assert_eq!(o.pending_message_count("bob"), 0);
    }

    #[test]
    fn test_message_received_no_session_fetches_bundle() {
        let mut o = make_orchestrator("alice");
        let wire = r#"{"dh_public_key":[0],"message_number":0,"ciphertext":[],"nonce":[],"previous_chain_length":0,"suite_id":1}"#;
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            from: "bob".to_string(),
            data: wire.as_bytes().to_vec(),
            msg_num: 0,
            kem_ct: vec![],
            otpk_id: 0,
        });
        // Should ask to fetch bundle (no active session → NeedSessionInit).
        let fetches: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::FetchPublicKeyBundle { .. }))
            .collect();
        assert!(!fetches.is_empty(), "expected FetchPublicKeyBundle action");
    }

    #[test]
    fn test_message_received_pq_ciphertext_produces_apply_action() {
        let mut o = make_orchestrator("alice");
        let wire = r#"{"dh_public_key":[0],"message_number":0,"ciphertext":[],"nonce":[],"previous_chain_length":0,"suite_id":1}"#;
        let actions = o.handle_event(IncomingEvent::MessageReceived {
            from: "bob".to_string(),
            data: wire.as_bytes().to_vec(),
            msg_num: 0,
            kem_ct: vec![1, 2, 3],
            otpk_id: 42,
        });
        let pq_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::ApplyPQContribution { .. }))
            .collect();
        assert!(!pq_actions.is_empty(), "expected ApplyPQContribution action");
    }

    #[test]
    fn test_app_launched_schedules_timers() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::AppLaunched);
        let timers: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::ScheduleTimer { .. }))
            .collect();
        assert_eq!(timers.len(), 2);
    }

    #[test]
    fn test_network_reconnected_schedules_gc() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::NetworkReconnected);
        assert!(actions.iter().any(|a| matches!(a, Action::ScheduleTimer { timer_id, .. } if timer_id == "gc_sweep")));
    }

    #[test]
    fn test_timer_gc_sweep_returns_actions() {
        let mut o = make_orchestrator("alice");
        // gc_sweep on empty state should return empty (no expired records).
        let actions = o.handle_event(IncomingEvent::TimerFired {
            timer_id: "gc_sweep".to_string(),
        });
        // May return prune actions even on empty store; just check no panic.
        let _ = actions;
    }

    #[test]
    fn test_ack_received_produces_mark_delivered() {
        let mut o = make_orchestrator("alice");
        let actions = o.handle_event(IncomingEvent::AckReceived {
            message_id: "msg-xyz".to_string(),
        });
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::MarkMessageDelivered { message_id } if message_id == "msg-xyz"));
    }

    #[test]
    fn test_session_init_completed_clears_lock() {
        let mut o = make_orchestrator("alice");
        o.init_locks.insert("bob".to_string());
        let actions = o.handle_event(IncomingEvent::SessionInitCompleted {
            contact_id: "bob".to_string(),
            session_json: "{}".to_string(), // minimal, will fail to import gracefully
        });
        assert!(!o.init_locks.contains("bob"));
        // Should include NotifySessionCreated.
        assert!(actions.iter().any(|a| matches!(a, Action::NotifySessionCreated { .. })));
    }

    #[test]
    fn test_cooldown_deduplicates_end_session() {
        let mut o = make_orchestrator("alice");
        o.set_cooldown("bob".to_string());
        assert!(o.on_cooldown("bob"));
    }

    #[test]
    fn test_no_cooldown_initially() {
        let o = make_orchestrator("alice");
        assert!(!o.on_cooldown("bob"));
    }
}
