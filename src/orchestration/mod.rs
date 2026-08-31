/// Orchestration layer — business logic that sits above the cryptographic primitives.
///
/// # Module structure
///
/// ```text
/// orchestration/
///   platform_bridge  — PlatformBridge callback trait (Phase 0)
///   actions          — Action + IncomingEvent enums (Phase 0, used by all phases)
///   clock            — Clock trait + SystemClock + MockClock (time injection)
///   ack_store        — ACK deduplication (Phase 1a)
///   healing_queue    — Session healing queue (Phase 1b)
///   pq_contribution  — PQ contribution manager (Phase 2)
///   session_lifecycle— Session lifecycle (Phase 3)       [TODO]
///   message_router   — Decision engine (Phase 4)         [TODO]
///   teardown_plan    — Which of a peer's devices a teardown touches
///   receiving_init_plan — Which queued message opens a session, against which device
///   send_plan        — Who gets a copy of an outgoing message
///   orchestrator     — Top-level facade (Phase 5)        [TODO]
/// ```
pub mod ack_store;
pub mod actions;
pub mod clock;
pub mod healing_queue;
pub mod message_router;
pub mod orchestrator;
pub mod platform_bridge;
pub mod pq_contribution;
pub mod receiving_init_plan;
pub mod send_plan;
pub mod session_lifecycle;
pub mod teardown_plan;

pub use ack_store::{AckCheckResult, AckStore};
pub use actions::{Action, IncomingEvent, ReceiptStatus, SecureStoreSlot};
pub use clock::{Clock, SystemClock, system_clock};
pub use healing_queue::{HealDirection, HealingDecision, HealingQueue, HealingRecord};
pub use message_router::{IncomingMessage, MessageRouter, Role, RoutingDecision, tie_break_role};
pub use orchestrator::Orchestrator;
pub use platform_bridge::PlatformBridge;
pub use pq_contribution::{
    DeferredContribution, EncapsulationResult, PQContributionManager, SPKRotationPending,
};
pub use receiving_init_plan::{
    ReceivingInitAttempt, ReceivingInitCarrier, ReceivingInitKind, plan_receiving_init,
    receiving_init_kind,
};
pub use send_plan::{DeliveryAudience, DeliveryTarget, plan_send};
pub use session_lifecycle::{DecryptResult, EncryptResult, SessionLifecycleManager};
pub use teardown_plan::{TeardownAction, TeardownDecision, plan_teardown};
