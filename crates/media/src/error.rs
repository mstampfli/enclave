//! Media pipeline errors.

/// Errors from audio (and later video) encode/decode and capture.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("audio codec error: {0}")]
    Codec(String),
}
