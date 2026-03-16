//! # construct-ice
//!
//! ICE (Intrusion Countermeasures Electronics) — obfs4 pluggable transport for Construct Messenger.
//!
//! obfs4 makes traffic indistinguishable from random noise, providing
//! resistance against Deep Packet Inspection (DPI) systems.
//!
//! ## Status
//!
//! Library is complete and tested. Server integration is pending.
//!
//! **TODO(server-integration):** See `gateway/src/main.rs` in construct-server for the full
//! integration plan. Key points:
//! - Use `Obfs4Listener::bind(addr, ServerConfig::generate())` for the server side.
//! - `ServerConfig::bridge_line()` produces the string to distribute to censored clients.
//! - `ClientConfig::from_bridge_line("cert=... iat-mode=0")` is the client-side parser.
//! - Feature flag `tonic-transport` must be enabled for use with hyper/tonic servers.
//! - IAT modes: `IatMode::None` (default), `IatMode::Enabled` (10ms jitter), `IatMode::Paranoid`
//!   (random chunk sizing + 10ms jitter). Paranoid is recommended for China/Iran threat model.
//!
//! ## DPI Resistance
//!
//! Estimated resistance (private server, no public bridge IP leaks):
//! - Russia (TSPU/ТСПУ): **Low risk** — probabilistic blocking unlikely to fire on private IPs
//! - Iran (DPI): **Low-medium** — obfs4 entropy defeats most deployed filters
//! - China (GFW): **Medium** — ML classifiers are the main threat; IAT Paranoid mode helps
//!
//! Full analysis: CONSTRUCT_ICE_DPI_ANALYSIS.md in session files.
//!
//! ## Architecture
//!
//! ```text
//! [App] ↔ [Obfs4Stream (AsyncRead+AsyncWrite)] ~~~ obfuscated TCP ~~~ [Obfs4Listener] ↔ [App]
//! ```
//!
//! ## Usage
//!
//! ### Client
//! ```rust,no_run
//! use construct_ice::{ClientConfig, Obfs4Stream};
//!
//! # async fn example() -> Result<(), construct_ice::Error> {
//! let config = ClientConfig::from_bridge_cert("base64_bridge_cert_here")?;
//! let mut stream = Obfs4Stream::connect("relay.example.com:443", config).await?;
//! // stream implements AsyncRead + AsyncWrite — pass to tonic/hyper
//! # Ok(())
//! # }
//! ```
//!
//! ### Server
//! ```rust,no_run
//! use construct_ice::{ServerConfig, Obfs4Listener};
//!
//! # async fn example() -> Result<(), construct_ice::Error> {
//! let config = ServerConfig::generate();
//! let listener = Obfs4Listener::bind("0.0.0.0:443", config).await?;
//! while let Ok((stream, addr)) = listener.accept().await {
//!     // stream implements AsyncRead + AsyncWrite
//!     tokio::spawn(async move { /* handle(stream) */ });
//! }
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod crypto;
pub mod framing;
pub mod handshake;
pub mod iat;
pub mod replay_filter;
pub mod transport;

#[cfg(feature = "ffi")]
#[allow(unsafe_code)]
pub mod ffi;

mod error;

pub use error::Error;
pub use framing::PaddingStrategy;
pub use iat::IatMode;
pub use transport::{ClientConfig, Obfs4Listener, Obfs4Stream, ServerConfig};

/// Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
