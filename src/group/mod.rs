//! MLS (Messaging Layer Security) group chat protocol — RFC 9420.
//!
//! This module wraps the `openmls` crate and exposes a simplified API
//! for creating, joining, and managing MLS groups.
//!
//! Architecture:
//!   `MlsStore` — ONE long-lived OpenMLS storage per device, holding all
//!   group states plus key-package private material (a Welcome can only be
//!   decrypted by the storage that generated the KeyPackage it addresses).
//!   State persistence: CFE binary format (`CfeMlsStoreV1`, msg_type 0x44),
//!   exported/imported as a whole; the Ed25519 signer stays outside the blob.
//!
//! Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
//! Credential:  BasicCredential with Ed25519 device identity key

pub mod mls_error;
pub mod mls_store;

pub use mls_error::MlsError;
pub use mls_store::{MemberAddition, MlsStore};
