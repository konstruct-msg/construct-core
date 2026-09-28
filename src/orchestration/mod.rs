/// Orchestration layer — business logic that sits above the cryptographic primitives.
///
/// # Module structure
///
/// ```text
/// orchestration/
///   platform_bridge  — PlatformBridge callback trait
///   actions          — Action + IncomingEvent enums
///   clock            — Clock trait + SystemClock + MockClock (time injection)
///   ack_store        — ACK deduplication
///   session_lifecycle— The sessions held, current and previous states: encrypt/decrypt, retire
///   session_machine  — What phase a ratchet is in, and what may happen to it next
///   message_router   — Incoming message → dedup, session lookup, decrypt → RoutingDecision
///   decryption_error — "I could not read your message": the sealed error that replaced END_SESSION
///   initiation_plan  — Whether to open a session with a device now
///   receiving_init_plan — Which message can open a session
///   send_plan        — Who gets a copy of an outgoing message
///   receiving_decrypt_plan — Which device session an incoming message is tried against
///   pq_prekey_plan   — Which Kyber prekey an initiator encapsulates to, or why no session opens
///   orchestrator     — handle_event: every event in, every Action out
/// ```
pub mod ack_store;
pub mod actions;
pub mod clock;
pub mod decryption_error;
pub mod initiation_plan;
pub mod message_router;
pub mod orchestrator;
pub mod platform_bridge;
#[cfg(feature = "post-quantum")]
pub mod pq_prekey_plan;
pub mod receiving_decrypt_plan;
pub mod receiving_init_plan;
pub mod send_plan;
pub mod session_lifecycle;
pub mod session_machine;

pub use ack_store::{AckCheckResult, AckStore};
pub use actions::{Action, IncomingEvent, ReceiptStatus, SecureStoreSlot};
pub use clock::{Clock, SystemClock, system_clock};
pub use initiation_plan::{InitiationContext, InitiationDecision, plan_initiation};
pub use message_router::{IncomingMessage, MessageRouter, RoutingDecision};
pub use orchestrator::Orchestrator;
pub use platform_bridge::PlatformBridge;
#[cfg(feature = "post-quantum")]
pub use pq_prekey_plan::{
    KyberPrekeyOffer, PqxdhChoice, PqxdhContext, PqxdhOffer, PqxdhRefusal, plan_pqxdh,
};
pub use receiving_decrypt_plan::plan_receiving_decrypt;
pub use receiving_init_plan::{ReceivingInitCarrier, ReceivingInitKind, receiving_init_kind};
pub use send_plan::{DeliveryAudience, DeliveryTarget, plan_send};
pub use session_lifecycle::{DecryptResult, SessionLifecycleManager};
pub use session_machine::{
    Effect as SessionEffect, Event as SessionEvent, OPENING_TTL_MS, Phase, SessionMachine,
};
