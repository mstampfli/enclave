//! System-audio loopback stub for platforms without a backend: starting fails
//! cleanly, so the client crate stays portable without platform gates.

use super::{AudioMix, LoopbackMode};
use crate::MediaError;

/// Unconstructible on this platform: [`Self::start`] always fails.
pub struct SystemAudioCapture {
    _private: (),
}

impl SystemAudioCapture {
    pub fn start(_mode: LoopbackMode, _mix: AudioMix) -> Result<Self, MediaError> {
        Err(MediaError::Codec(
            "system audio share is not supported on this platform".into(),
        ))
    }
}
