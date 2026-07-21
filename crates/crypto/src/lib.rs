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

use openmls::prelude::{Capabilities, Ciphersuite, CredentialType, ExtensionType};

pub mod blob;
pub mod error;
pub mod group;
pub mod identity;
pub mod media;
pub mod ring;
pub mod sign;
pub mod workspace;

pub use blob::{
    blob_addr, open_ballot, open_blob, open_chunk, seal_ballot, seal_blob, seal_chunk, SealedBlob,
    CHUNK_OVERHEAD,
};
pub use error::CryptoError;
pub use group::{Group, MemberAdd, SafetyNumber, TextMessage};
pub use identity::Identity;
pub use media::{MediaOpener, MediaSealer, MediaSigner, MEDIA_SIG_CONTEXT};
pub use ring::{ring_verify, RingKeypair, RingSig};
pub use sign::{verify_op, OP_SIG_CONTEXT};

/// The single ciphersuite Enclave uses: X25519 KEM, AES-128-GCM, SHA-256, and
/// Ed25519 signatures. One fixed ciphersuite (not a negotiated set) keeps the
/// security surface small; Ed25519 identity matches `docs/PRIMITIVES.md`.
/// Every encrypted text message is padded up to a multiple of this many bytes
/// before it is sealed, so an observer of the wire (the relay included) learns
/// only which bucket a message fell into, not its length. 256 bytes covers the
/// overwhelming majority of chat lines in a single bucket; a longer message
/// costs at most 255 wasted bytes.
///
/// This does not hide the length of *media*: audio and video frames are sized
/// by their codecs, and padding them to a constant rate is a different and much
/// more expensive tradeoff (see THREAT_MODEL.md).
pub const PADDING: usize = 256;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// The MLS capabilities we advertise: our single ciphersuite, the LastResort
/// extension (so our one reusable key package is valid), and Basic credentials
/// only. Advertising just AES-128-GCM means a peer can never add us to a
/// ChaCha20-Poly1305 group, so libcrux's ChaCha path is structurally unreachable
/// -- defense in depth around RUSTSEC-2026-0124.
pub(crate) fn enclave_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        Some(&[ExtensionType::LastResort]),
        None,
        Some(&[CredentialType::Basic]),
    )
}
