//! Media pipeline: capture -> encode -> (hand off encoded frame to crypto) and
//! the reverse on receive. This crate never touches keys; it produces and
//! consumes *encoded* frames, which `enclave-crypto` seals/opens.
//!
//! ## Hot-path rules (performance-first)
//! - Reuse buffers; avoid per-frame heap churn in the steady state.
//! - A jitter buffer absorbs reorder/loss before decode; Opus has built-in
//!   packet-loss concealment.
//! - Capture/playback run on their own threads; the app thread never blocks on
//!   the audio device.
//!
//! Phase 3 ships the Opus codec ([`audio`]). Device capture/playback (`cpal`)
//! and video (Phase 5) build on top.

pub mod audio;
pub mod device;
pub mod error;
pub mod frame;
pub mod jitter;

pub use audio::{AudioDecoder, AudioEncoder};
pub use device::{AudioCapture, AudioPlayback, PlaybackSink};
pub use error::MediaError;
pub use jitter::{JitterBuffer, Popped};
