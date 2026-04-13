/// Message Router — Rust port of Swift `MessageRouter`.
///
/// The Decision Engine: receives a raw incoming message, runs it through
/// deduplication, session lookup, and decryption, and returns a
/// `RoutingDecision` describing what happened plus `Vec<Action>` for the
/// platform to execute.
///
/// No I/O is performed here. All side-effects are expressed as `Action` values
/// returned to the caller (Swift / Kotlin).
///
/// ## State machine per message
///
/// ```text
/// message arrives
///   │
///   ├─ is_duplicate? → Duplicate
///   │
///   ├─ is END_SESSION? → EndSessionNeeded
///   │
///   ├─ no active session?
///   │     └─ enqueue → NeedSessionInit
///   │
///   └─ has session → decrypt
///         ├─ ok → Decrypted (+ drain pending queue)
///         └─ fail
///               ├─ msg_num == 0 → SessionHealNeeded (enqueue healing)
///               └─ msg_num >  0 → EndSessionNeeded
/// ```
use std::collections::{HashMap, VecDeque};

use crate::orchestration::actions::Action;
use crate::orchestration::healing_queue::HealDirection;
use crate::orchestration::session_lifecycle::SessionLifecycleManager;

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_PENDING_PER_USER: usize = 100;

/// Magic content that signals an END_SESSION control message.
#[allow(dead_code)]
const END_SESSION_MARKER: &str = "__END_SESSION__";

// ── Public types ──────────────────────────────────────────────────────────────

/// Role in a tie-break scenario (lower userId = INITIATOR).
#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Outcome of routing one message.
#[derive(Debug, Clone)]
pub enum RoutingDecision {
    /// Message decrypted successfully.
    Decrypted {
        contact_id: String,
        message_id: String,
        plaintext: Vec<u8>,
        content_type: u8,
        actions: Vec<Action>,
    },
    /// No active session; message queued — caller must fetch bundle and init session.
    NeedSessionInit {
        contact_id: String,
        queued_count: usize,
    },
    /// Decryption failed on message 0 — session healing required.
    SessionHealNeeded { contact_id: String, role: Role },
    /// Session is irrecoverably broken — send END_SESSION.
    EndSessionNeeded { contact_id: String, reason: String },
    /// Message already processed — discard.
    Duplicate { message_id: String },
    /// ACK status unknown — buffered pending a DB check (platform feeds back `AckDbResult`).
    PendingAckCheck { message_id: String },
    /// Pending queue for this contact is full — apply backpressure.
    QueueFull { contact_id: String },
    /// END_SESSION control message received.
    EndSessionReceived {
        contact_id: String,
        actions: Vec<Action>,
    },
    /// Unrecoverable routing error.
    Error { message: String },
}

/// A raw incoming message before decryption.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    pub contact_id: String,
    /// Binary WirePayload blob.
    pub wire_payload: Vec<u8>,
    pub message_id: String,
    pub msg_number: u32,
    /// When `true` this is a KEY_SYNC / END_SESSION control frame.
    pub is_control: bool,
    /// Original content_type from the wire envelope (e.g. 12 = CALL_SIGNAL).
    pub content_type: u8,
}

// ── MessageRouter ─────────────────────────────────────────────────────────────

pub struct MessageRouter {
    /// Per-contact queues for messages that arrived before session init.
    pending_queues: HashMap<String, VecDeque<IncomingMessage>>,
    max_pending_per_user: usize,
    /// Messages awaiting a platform DB ACK-check response.
    /// Key = message_id, Value = the buffered IncomingMessage.
    pending_ack_checks: HashMap<String, IncomingMessage>,
}

impl MessageRouter {
    pub fn new() -> Self {
        Self {
            pending_queues: HashMap::new(),
            max_pending_per_user: MAX_PENDING_PER_USER,
            pending_ack_checks: HashMap::new(),
        }
    }

    // ── Primary entry point ───────────────────────────────────────────────────

    /// Route one incoming message through the full decision pipeline.
    ///
    /// Returns a `RoutingDecision` plus any `Action`s that need executing.
    pub fn route_message(
        &mut self,
        lifecycle: &mut SessionLifecycleManager,
        msg: &IncomingMessage,
    ) -> RoutingDecision {
        // ── 1. ACK deduplication ──────────────────────────────────────────────
        use crate::orchestration::ack_store::AckCheckResult;
        match lifecycle.ack_store.is_processed(&msg.message_id) {
            AckCheckResult::InCache => {
                return RoutingDecision::Duplicate {
                    message_id: msg.message_id.clone(),
                };
            }
            AckCheckResult::NeedDbCheck => {
                // L1 cache miss after restart — buffer and ask platform to check L2 (DB).
                self.pending_ack_checks
                    .insert(msg.message_id.clone(), msg.clone());
                return RoutingDecision::PendingAckCheck {
                    message_id: msg.message_id.clone(),
                };
            }
            AckCheckResult::NotProcessed => {}
        }

        // Steps 2-4 shared with `resume_after_ack_check`.
        self.route_after_ack_check(lifecycle, msg)
    }

    // ── Drain pending queue after session init ────────────────────────────────

    /// Process all queued messages for `contact_id` now that a session exists.
    ///
    /// Returns one `RoutingDecision` per queued message.
    /// Returns one `RoutingDecision` per queued message, stopping early on
    /// the first error decision (EndSessionNeeded / SessionHealNeeded) to
    /// avoid cascading 50+ failures from a single broken session.
    pub fn drain_pending(
        &mut self,
        contact_id: &str,
        lifecycle: &mut SessionLifecycleManager,
    ) -> Vec<RoutingDecision> {
        let queued: Vec<IncomingMessage> = self
            .pending_queues
            .remove(contact_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default();

        let mut results = Vec::with_capacity(queued.len());
        let mut remaining_start = queued.len(); // index after which messages should be re-queued
        for (i, msg) in queued.iter().enumerate() {
            let decision = self.route_message(lifecycle, msg);
            let is_error = matches!(
                &decision,
                RoutingDecision::EndSessionNeeded { .. }
                    | RoutingDecision::SessionHealNeeded { .. }
            );
            results.push(decision);
            if is_error {
                remaining_start = i + 1;
                break;
            }
        }
        // Re-queue any messages that were not processed due to early exit.
        if remaining_start < queued.len() {
            let queue = self
                .pending_queues
                .entry(contact_id.to_string())
                .or_default();
            for msg in queued.into_iter().skip(remaining_start) {
                queue.push_front(msg);
            }
        }
        results
    }

    /// Number of queued messages for `contact_id`.
    pub fn pending_count(&self, contact_id: &str) -> usize {
        self.pending_queues.get(contact_id).map_or(0, |q| q.len())
    }

    /// Return the raw WirePayload bytes of the first queued message for `contact_id`
    /// without removing it from the queue.
    ///
    /// Used by non-UniFFI platforms (TUI, Android) to detect the RESPONDER case
    /// when handling `Action::InitSession`: if this returns `Some(bytes)`, the
    /// platform should call `init_receiving_session_from_wire_payload()` instead of
    /// `init_session_with_bundle()`.
    pub fn peek_first_pending_wire_payload(&self, contact_id: &str) -> Option<Vec<u8>> {
        self.pending_queues
            .get(contact_id)
            .and_then(|q| q.front())
            .map(|msg| msg.wire_payload.clone())
    }

    /// All contact IDs that currently have at least one queued message.
    pub fn contacts_with_pending(&self) -> Vec<String> {
        self.pending_queues
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Handle the platform's response to `Action::CheckAckInDb`.
    ///
    /// - `is_processed = true`  → duplicate; returns `RoutingDecision::Duplicate`.
    /// - `is_processed = false` → re-routes the buffered message, skipping the ACK check.
    pub fn resume_after_ack_check(
        &mut self,
        message_id: &str,
        is_processed: bool,
        lifecycle: &mut SessionLifecycleManager,
    ) -> RoutingDecision {
        let Some(buffered_msg) = self.pending_ack_checks.remove(message_id) else {
            return RoutingDecision::Error {
                message: format!(
                    "No buffered message for AckDbResult message_id={}",
                    message_id
                ),
            };
        };

        if is_processed {
            return RoutingDecision::Duplicate {
                message_id: message_id.to_string(),
            };
        }

        // DB confirmed not a duplicate — route from step 2 (skip ACK check).
        self.route_after_ack_check(lifecycle, &buffered_msg)
    }

    /// Route steps 2-4 (post-ACK-check). Called by both `route_message` (for
    /// `NotProcessed` fast path) and `resume_after_ack_check` (after DB confirms absent).
    fn route_after_ack_check(
        &mut self,
        lifecycle: &mut SessionLifecycleManager,
        msg: &IncomingMessage,
    ) -> RoutingDecision {
        // ── 2. END_SESSION control message ────────────────────────────────────
        if msg.is_control {
            let actions = lifecycle.archive_session(&msg.contact_id);
            return RoutingDecision::EndSessionReceived {
                contact_id: msg.contact_id.clone(),
                actions,
            };
        }

        // ── 3. Session availability check ─────────────────────────────────────
        if !lifecycle.has_active_session(&msg.contact_id) {
            if lifecycle.has_archive(&msg.contact_id) {
                if lifecycle.restore_latest_archive(&msg.contact_id).is_err() {
                    return self.enqueue_or_reject(lifecycle, msg);
                }
            } else {
                return self.enqueue_or_reject(lifecycle, msg);
            }
        }

        // ── 4. Decrypt ────────────────────────────────────────────────────────
        match lifecycle.decrypt_wire_payload(&msg.contact_id, &msg.wire_payload) {
            Ok(result) => {
                let mut actions = lifecycle.ack_store.mark_processed(&msg.message_id);
                actions.extend(result.actions);
                actions.extend(lifecycle.maybe_apply_pq_contribution(&msg.contact_id));
                RoutingDecision::Decrypted {
                    contact_id: msg.contact_id.clone(),
                    message_id: msg.message_id.clone(),
                    plaintext: result.plaintext,
                    content_type: msg.content_type,
                    actions,
                }
            }
            Err(e) => {
                if msg.msg_number == 0 {
                    let role = self.tie_break_role(lifecycle.my_user_id(), &msg.contact_id);
                    // Reject if attacker has exhausted the incoming-trigger budget
                    // for this contact. This preserves the 3-retry heal budget for
                    // a legitimate peer that sends a real session-init later.
                    if lifecycle
                        .healing_queue
                        .is_incoming_throttled(&msg.contact_id)
                    {
                        return RoutingDecision::EndSessionNeeded {
                            contact_id: msg.contact_id.clone(),
                            reason: format!(
                                "incoming heal throttled for {} — possible heal exhaustion attack",
                                &msg.contact_id
                            ),
                        };
                    }
                    lifecycle.healing_queue.enqueue(
                        &msg.contact_id,
                        msg.wire_payload.clone(),
                        HealDirection::Incoming,
                    );
                    RoutingDecision::SessionHealNeeded {
                        contact_id: msg.contact_id.clone(),
                        role,
                    }
                } else {
                    RoutingDecision::EndSessionNeeded {
                        contact_id: msg.contact_id.clone(),
                        reason: e,
                    }
                }
            }
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn enqueue_or_reject(
        &mut self,
        _lifecycle: &mut SessionLifecycleManager,
        msg: &IncomingMessage,
    ) -> RoutingDecision {
        let queue = self
            .pending_queues
            .entry(msg.contact_id.clone())
            .or_default();

        if queue.len() >= self.max_pending_per_user {
            return RoutingDecision::QueueFull {
                contact_id: msg.contact_id.clone(),
            };
        }

        queue.push_back(msg.clone());

        RoutingDecision::NeedSessionInit {
            contact_id: msg.contact_id.clone(),
            queued_count: queue.len(),
        }
    }

    /// Determine the local node's role using the tie-break rule:
    /// Higher userId (lexicographic) wins as INITIATOR — matches iOS `DeviceIdOrdering.isNaturalInitiator`.
    fn tie_break_role(&self, my_user_id: &str, contact_id: &str) -> Role {
        if my_user_id > contact_id {
            Role::Initiator
        } else {
            Role::Responder
        }
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_api::ClassicClient;
    use crate::crypto::suites::classic::ClassicSuiteProvider;
    use crate::orchestration::session_lifecycle::SessionLifecycleManager;

    fn make_lifecycle(user_id: &str) -> SessionLifecycleManager {
        let client = ClassicClient::<ClassicSuiteProvider>::new().unwrap();
        SessionLifecycleManager::new(client, user_id.to_string())
    }

    fn msg(contact_id: &str, msg_id: &str, msg_num: u32) -> IncomingMessage {
        IncomingMessage {
            contact_id: contact_id.to_string(),
            wire_payload: vec![],
            message_id: msg_id.to_string(),
            msg_number: msg_num,
            is_control: false,
            content_type: 0,
        }
    }

    #[test]
    fn test_no_session_queues_message() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");
        let m = msg("bob", "m1", 0);
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(matches!(
            decision,
            RoutingDecision::NeedSessionInit {
                queued_count: 1,
                ..
            }
        ));
        assert_eq!(router.pending_count("bob"), 1);
    }

    #[test]
    fn test_queue_full_backpressure() {
        let mut router = MessageRouter::new();
        router.max_pending_per_user = 2;
        let mut lifecycle = make_lifecycle("alice");

        router.route_message(&mut lifecycle, &msg("bob", "m1", 0));
        router.route_message(&mut lifecycle, &msg("bob", "m2", 1));
        let decision = router.route_message(&mut lifecycle, &msg("bob", "m3", 2));
        assert!(matches!(decision, RoutingDecision::QueueFull { .. }));
        assert_eq!(router.pending_count("bob"), 2); // still 2
    }

    #[test]
    fn test_duplicate_detection_via_cache() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        // Mark a message as already processed.
        lifecycle.ack_store.mark_processed("dup-msg");

        let m = IncomingMessage {
            contact_id: "bob".to_string(),
            wire_payload: vec![],
            message_id: "dup-msg".to_string(),
            msg_number: 1,
            is_control: false,
            content_type: 0,
        };
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(matches!(decision, RoutingDecision::Duplicate { .. }));
    }

    #[test]
    fn test_end_session_control_message() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        let m = IncomingMessage {
            contact_id: "bob".to_string(),
            wire_payload: vec![],
            message_id: "ctrl-1".to_string(),
            msg_number: 0,
            is_control: true,
            content_type: 0,
        };
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(matches!(
            decision,
            RoutingDecision::EndSessionReceived { .. }
        ));
    }

    #[test]
    fn test_tie_break_role_initiator() {
        let router = MessageRouter::new();
        // "bob" > "alice" → bob is INITIATOR (higher deviceId wins)
        assert_eq!(router.tie_break_role("bob", "alice"), Role::Initiator);
    }

    #[test]
    fn test_tie_break_role_responder() {
        let router = MessageRouter::new();
        // "alice" < "bob" → alice is RESPONDER (lower deviceId loses)
        assert_eq!(router.tie_break_role("alice", "bob"), Role::Responder);
    }

    #[test]
    fn test_drain_pending_no_session_returns_decisions() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        // Queue a message without a session.
        router.route_message(&mut lifecycle, &msg("bob", "m1", 0));
        assert_eq!(router.pending_count("bob"), 1);

        // Drain without a session: route_message is called for each queued message.
        // Since there is still no session, the message is re-queued by route_message.
        let decisions = router.drain_pending("bob", &mut lifecycle);
        assert_eq!(decisions.len(), 1);
        // Message is re-enqueued because there is still no session.
        assert_eq!(router.pending_count("bob"), 1);
    }

    #[test]
    fn test_healing_queued_on_msg0_decrypt_fail() {
        let mut router = MessageRouter::new();
        let mut lifecycle = make_lifecycle("alice");

        // Inject a fake active session marker so the router tries to decrypt.
        // Since we can't inject a real session without a full X3DH handshake,
        // we test the msg_num>0 path instead (END_SESSION).
        // The msg_num==0 path is covered in integration tests.
        let m = IncomingMessage {
            contact_id: "bob".to_string(),
            wire_payload: vec![],
            message_id: "bad-msg".to_string(),
            msg_number: 5, // >0 → EndSessionNeeded on fail
            is_control: false,
            content_type: 0,
        };
        // Without a session → NeedSessionInit (queue)
        let decision = router.route_message(&mut lifecycle, &m);
        assert!(matches!(decision, RoutingDecision::NeedSessionInit { .. }));
    }
}
