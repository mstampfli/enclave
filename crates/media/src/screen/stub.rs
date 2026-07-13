//! Screen capture stub for platforms without a backend (e.g. macOS today):
//! nothing to enumerate, and starting fails cleanly, so the client crate
//! stays portable without platform gates.

use super::{CaptureStatus, CapturedFrame, ScreenSource, SharedStatus, WindowSource};
use crate::MediaError;

pub fn monitor_sources() -> Vec<ScreenSource> {
    Vec::new()
}

pub fn window_sources() -> Vec<WindowSource> {
    Vec::new()
}

/// Unconstructible on this platform: every `start_*` fails.
pub struct ScreenCapture {
    status: SharedStatus,
}

impl ScreenCapture {
    pub fn start_index(_index: usize) -> Result<Self, MediaError> {
        Err(unsupported())
    }

    pub fn start_window(_hwnd: isize) -> Result<Self, MediaError> {
        Err(unsupported())
    }

    pub fn latest(&self) -> Option<CapturedFrame> {
        None
    }

    pub fn status(&self) -> CaptureStatus {
        self.status.get()
    }

    pub fn status_handle(&self) -> SharedStatus {
        self.status.clone()
    }
}

fn unsupported() -> MediaError {
    MediaError::Codec("screen share is not supported on this platform".into())
}
