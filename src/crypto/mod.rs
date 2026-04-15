//! Криптографический модуль
//!
//! # Архитектура
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        Application                          │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Client (High-Level API)                  │
//! │  - Управляет множественными сессиями                         │
//! │  - Хранит долгосрочные ключи пользователя                   │
//! │  - Предоставляет удобный API для приложения                 │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Session (Mid-Level)                      │
//! │  - Объединяет Handshake + Messaging                         │
//! │  - Одна сессия = один контакт                               │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                ┌─────────────┴─────────────┐
//!                ▼                           ▼
//! ┌───────────────────────────┐  ┌──────────────────────────┐
//! │   KeyAgreement (X3DH)     │  │  SecureMessaging (DR)    │
//! │  - X3DH handshake         │  │  - Double Ratchet        │
//! │  - Ephemeral keys         │  │  - Forward secrecy       │
//! │  - Root key derivation    │  │  - Break-in recovery     │
//! └───────────────────────────┘  └──────────────────────────┘
//!                │                           │
//!                └─────────────┬─────────────┘
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │              CryptoProvider (Crypto-Agility)                │
//! │  - KEM (X25519, ML-KEM)                                     │
//! │  - Signatures (Ed25519, ML-DSA)                             │
//! │  - AEAD (ChaCha20-Poly1305)                                 │
//! │  - KDF (HKDF-SHA256)                                        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Модули
//!
//! ### Core Traits
//! - [`provider`]: CryptoProvider trait для crypto-agility
//! - [`handshake`]: KeyAgreement trait для протоколов установки ключей
//! - [`messaging`]: SecureMessaging trait для протоколов обмена сообщениями
//!
//! ### Implementations
//! - [`suites`]: Реализации CryptoProvider (Classic, Hybrid)
//! - [`handshake::x3dh`]: X3DH протокол
//! - [`messaging::double_ratchet`]: Double Ratchet протокол
//!
//! ### High-Level APIs
//! - [`session_api`]: Session API (объединяет handshake + messaging)
//! - [`client_api`]: Client API (управляет ключами + множественными сессиями)
//!
//! ### Utilities
//! - [`keys`]: KeyManager для управления долгосрочными ключами
//! - `master_key`: Backup/restore ключей

// ============================================================================
// Core Traits
// ============================================================================

/// CryptoProvider trait для crypto-agility
pub mod provider;

/// Key Agreement protocols (X3DH, PQ-X3DH)
pub mod handshake;

/// Secure Messaging protocols (Double Ratchet)
pub mod messaging;

// ============================================================================
// Implementations
// ============================================================================

/// Криптографические наборы (Classic, Hybrid)
pub mod suites;

// ============================================================================
// High-Level APIs
// ============================================================================

/// Session API - объединяет handshake + messaging
pub mod session_api;

/// Client API - управляет ключами + множественными сессиями
pub mod client_api;

// ============================================================================
// Utilities
// ============================================================================

pub mod keys;

pub mod master_key;

/// Invite crypto - dynamic contact invites with ephemeral keys
pub mod invite_crypto;

/// Account recovery via BIP39 mnemonic + SLIP-0010 Ed25519 HD derivation
pub mod recovery;

/// Key Transparency — RFC 6962-style append-only Merkle log for identity key auditing
pub mod key_transparency;

/// ConstructPrivacyPass — OPRF blind token primitives (Ristretto255)
pub mod privacy_pass;

/// SLIP-39 social recovery — vault key Shamir Secret Sharing + bundle encryption
pub mod social_recovery;

// ============================================================================
// Post-Quantum (conditionally compiled)
// ============================================================================

#[cfg(feature = "post-quantum")]
pub mod pq_x3dh;

// ============================================================================
// Re-exports для удобства
// ============================================================================

pub use provider::CryptoProvider;

// Suite ID with validation
pub mod suite_id;
pub use suite_id::{InvalidSuiteId, SuiteID};

// Backward compatibility constants
/// Suite ID for the classic suite
pub const CLASSIC_SUITE_ID: u16 = 1;
/// Suite ID for Post-Quantum hybrid suite (reserved)
pub const PQ_HYBRID_SUITE_ID: u16 = 2;
