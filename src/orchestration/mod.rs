/// Orchestration layer — business logic that sits above the cryptographic primitives.
///
/// # Module structure
///
/// ```text
/// orchestration/
///   platform_bridge  — PlatformBridge callback trait (Phase 0)
///   actions          — Action + IncomingEvent enums (Phase 0, used by all phases)
///   ack_store        — ACK deduplication (Phase 1a)
///   healing_queue    — Session healing queue (Phase 1b)
///   pq_contribution  — PQ contribution manager (Phase 2)
///   session_lifecycle— Session lifecycle (Phase 3)       [TODO]
///   message_router   — Decision engine (Phase 4)         [TODO]
///   orchestrator     — Top-level facade (Phase 5)        [TODO]
/// ```
pub mod ack_store;
pub mod actions;
pub mod healing_queue;
pub mod message_router;
pub mod orchestrator;
pub mod platform_bridge;
pub mod pq_contribution;
pub mod session_lifecycle;

pub use ack_store::{AckCheckResult, AckStore};
pub use actions::{Action, IncomingEvent, ReceiptStatus};
pub use healing_queue::{HealingDecision, HealingQueue, HealingRecord};
pub use message_router::{IncomingMessage, MessageRouter, Role, RoutingDecision};
pub use orchestrator::Orchestrator;
pub use platform_bridge::PlatformBridge;
pub use pq_contribution::{
    DeferredContribution, EncapsulationResult, PQContributionManager, SPKRotationPending,
};
pub use session_lifecycle::{DecryptResult, EncryptResult, SessionLifecycleManager};
