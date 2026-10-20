//! Traffic protection: what is left of it.
//!
//! - `padding`: every ratchet plaintext is padded to 255-byte blocks before encryption, so the
//!   ciphertext length hides the message length within a block.
//! - `timing`: a small random delay before a send, so composing and sending do not correlate
//!   to the millisecond.
//!
//! Cover traffic (`cover_traffic`, `TrafficProtectionManager` over UniFFI) was retired in
//! 0.55.0: dummies cost network and battery, and no client ever sent one — iOS generated and
//! discarded them for want of a transport. `construct-docs/decisions/cover-traffic-retired.md`.

pub mod padding;
pub mod timing;

pub use padding::{
    DEFAULT_BLOCK_SIZE, PaddingError, pad_message, pad_message_default, unpad_message,
};
pub use timing::{random_send_delay, recommended_send_delay};
