/// Orchestration layer — business logic that sits above the cryptographic primitives.
///
/// # Module structure
///
/// ```text
/// orchestration/
///   platform_bridge  — PlatformBridge callback trait (Phase 0)
///   actions          — Action + IncomingEvent enums (Phase 0, used by all phases)
///   ack_store        — ACK deduplication (Phase 1a)      [TODO]
///   healing_queue    — Session healing queue (Phase 1b)  [TODO]
///   pq_contribution  — PQ contribution manager (Phase 2) [TODO]
///   session_lifecycle— Session lifecycle (Phase 3)       [TODO]
///   message_router   — Decision engine (Phase 4)         [TODO]
///   orchestrator     — Top-level facade (Phase 5)        [TODO]
/// ```
pub mod actions;
pub mod platform_bridge;

pub use actions::{Action, IncomingEvent, ReceiptStatus};
pub use platform_bridge::PlatformBridge;
