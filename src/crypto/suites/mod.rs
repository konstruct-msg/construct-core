//! Криптографические наборы (Crypto Suites)
//!
//! Этот модуль содержит различные реализации CryptoProvider trait.
//!
//! ## Доступные наборы
//!
//! ### Classic Suite (Suite ID = 1)
//! - **KEM**: X25519 (ECDH на Curve25519)
//! - **Signatures**: Ed25519
//! - **AEAD**: ChaCha20-Poly1305
//! - **KDF**: HKDF-SHA256
//!
//! ### Hybrid Suite (Suite ID = 2) — постквантовый
//! - **KEM**: X25519 (PQ KEM handled separately via `pq_contribution`)
//! - **Signatures**: Ed25519 + ML-DSA-65 (гибрид — обе подписи должны верифицироваться)
//! - **AEAD**: ChaCha20-Poly1305
//! - **KDF**: HKDF-SHA256
//!
//! ## Выбор suite
//!
//! ```rust
//! use construct_core::crypto::suites::classic::ClassicSuiteProvider;
//! use construct_core::crypto::provider::CryptoProvider;
//!
//! type MySuite = ClassicSuiteProvider;
//!
//! let (private_key, public_key) = MySuite::generate_kem_keys()?;
//! ```

pub mod classic;

/// Post-quantum hybrid suite (Ed25519 + ML-DSA-65 signatures).
/// Available only when the `post-quantum` feature is enabled.
#[cfg(feature = "post-quantum")]
pub mod hybrid;
