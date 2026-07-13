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
pub mod camera;
pub mod device;
pub mod error;
pub mod frame;
pub mod jitter;
/// Screen/window capture (WGC/DXGI on Windows; XDG portal + PipeWire on
/// Wayland and raw MIT-SHM/XComposite grabs on X11 for Linux; a clean-failing
/// stub elsewhere).
pub mod screen;
/// System-audio loopback capture (WASAPI on Windows, PipeWire on Linux, a
/// clean-failing stub elsewhere).
pub mod system_audio;
pub mod video;

pub use audio::{AudioDecoder, AudioEncoder};
pub use camera::{camera_sources, CameraCapture, CameraSource};
pub use device::{
    input_device_names, output_device_names, AudioCapture, AudioPlayback, PlaybackSink,
};
pub use error::MediaError;
pub use jitter::{JitterBuffer, Popped};
pub use screen::{
    monitor_sources, per_window_audio_supported, window_sources, CaptureStatus, CapturedFrame,
    EndedReason, ScreenCapture, ScreenSource, SharedStatus, WindowSource,
};
pub use system_audio::{window_pid, AudioMix, LoopbackMode, SystemAudioCapture};
pub use video::H264Encoder;
