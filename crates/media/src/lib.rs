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
pub mod video;
/// Windows screen capture (Windows Graphics Capture / DXGI duplication).
#[cfg(windows)]
pub mod screen;

pub use audio::{AudioDecoder, AudioEncoder};
pub use device::{
    input_device_names, output_device_names, AudioCapture, AudioPlayback, PlaybackSink,
};
pub use error::MediaError;
pub use jitter::{JitterBuffer, Popped};
pub use video::H264Encoder;
#[cfg(windows)]
pub use screen::{CapturedFrame, ScreenCapture};
