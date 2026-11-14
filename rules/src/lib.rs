//! Client rules, written once.
//!
//! A decision over protocol data or a client's own state that two clients or more make, and that
//! must behave the same on each, lives here — not in Swift, Kotlin and Rust three times
//! (construct-docs `decisions/client-rules-shared-in-rust.md`; rule 2 of
//! `decisions/rules-from-the-first-year.md`). The rule that made the case: a closed "messages may
//! not have arrived" notice came back on every connection on iOS and Android while the Linux and
//! Windows client had fixed it a week earlier (construct-docs todo 290).
//!
//! What lives here is pure and sans-IO, with no cryptography: state, the transitions over it, and
//! the tests that pin them. No storage format either: each rule's state is `serde`, and the core
//! writes it as a CFE envelope with a message type of its own. iOS and Android reach a rule through
//! the core's one UniFFI component; a Rust client through `construct_core::rule_state`, which
//! re-exports the rule and writes its state, so no client depends on two versions of it.

pub mod calls;
pub mod device_refusal;
pub mod fanout_retry;
pub mod intake;
pub mod mailbox_gap;
pub mod names;
pub mod read_sync;
pub mod send_failure;
pub mod stream_cursor;
