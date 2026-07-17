//! Domain errors for the crypto core.
//!
//! openmls exposes a large zoo of error types. Rather than leak them, we map
//! each failure to a small set of named domain variants and carry the source's
//! message as detail. Callers can match on the variant (e.g. distinguish "this
//! key package is forged" from "we could not build a group") without depending
//! on openmls's internal error enums.

/// Errors from identity, group, and media-key operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("identity generation failed: {0}")]
    Identity(String),

    #[error("key package build/serialize failed: {0}")]
    KeyPackage(String),

    /// A received key package failed validation (bad signature, wrong
    /// ciphersuite, expired). A forged or tampered identity lands here.
    #[error("key package rejected as invalid: {0}")]
    KeyPackageInvalid(String),

    #[error("group creation failed: {0}")]
    GroupCreate(String),

    #[error("adding member failed: {0}")]
    AddMember(String),

    #[error("applying commit failed: {0}")]
    Commit(String),

    #[error("removing member failed: {0}")]
    RemoveMember(String),

    #[error("joining group from welcome failed: {0}")]
    Join(String),

    #[error("exporting group secret failed: {0}")]
    Export(String),

    #[error("text message encrypt/decrypt failed: {0}")]
    Text(String),

    #[error("media frame seal/open failed: {0}")]
    Media(String),

    #[error("content-addressed blob seal/open failed: {0}")]
    Blob(String),

    #[error("serialization failed: {0}")]
    Serialize(String),
}
