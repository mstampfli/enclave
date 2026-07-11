//! Cryptographic core: identity, MLS group key agreement, and (Phase 3) the
//! media-key schedule.
//!
//! Design rule (non-negotiable): **assemble vetted primitives, hand-roll none.**
//! MLS comes from `openmls`, Ed25519 identity from `openmls_basic_credential`,
//! hashing from `sha2`. This crate wires them together and exposes safe,
//! narrow types; it does not invent crypto. See `../../docs/PRIMITIVES.md`.
//!
//! ## Surface
//! - [`Identity`] -- a device's long-term Ed25519 key + private-key storage.
//! - [`Group`] -- one MLS group (a call or DM): create / add / join / export /
//!   [`SafetyNumber`].
//!
//! Wire crossings are always bytes (serialized key packages and Welcomes); the
//! untrusted server only ever forwards these opaque blobs.

use openmls::prelude::Ciphersuite;

pub mod error;
pub mod group;
pub mod identity;
pub mod media;

pub use error::CryptoError;
pub use group::{Group, MemberAdd, SafetyNumber, TextMessage};
pub use identity::Identity;
pub use media::{MediaOpener, MediaSealer};

/// The single ciphersuite Enclave uses: X25519 KEM, AES-128-GCM, SHA-256, and
/// Ed25519 signatures. One fixed ciphersuite (not a negotiated set) keeps the
/// security surface small; Ed25519 identity matches `docs/PRIMITIVES.md`.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
