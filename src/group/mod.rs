//! MLS (Messaging Layer Security) group chat protocol — RFC 9420.
//!
//! This module wraps the `openmls` crate and exposes a simplified API
//! for creating, joining, and managing MLS groups.
//!
//! Architecture:
//!   MlsGroup (this module) wraps openmls::group::MlsGroup
//!   KeyPackage = identity credential + ciphersuite
//!   State persistence: CFE binary format (CfeMlsGroupV1)
//!
//! Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
//! Credential:  BasicCredential with Ed25519 device identity key

pub mod mls_group;
pub mod mls_error;

pub use mls_group::{MlsGroup, GroupConfig, MemberAddition};
pub use mls_error::MlsError;
