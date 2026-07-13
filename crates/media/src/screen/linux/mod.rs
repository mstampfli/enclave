//! Linux screen and window capture: two backends, picked by session type.
//!
//! - **Wayland** ([`portal`]): the XDG ScreenCast portal's system dialog picks
//!   the source (apps cannot enumerate other windows on Wayland by design)
//!   and the compositor streams frames over PipeWire. Asynchronous start.
//! - **X11** ([`x11`]): raw grabs, like every X11 screen sharer. The app
//!   enumerates monitors (RandR) and windows (EWMH) itself -- the same picker
//!   experience as Windows -- and captures via MIT-SHM `GetImage` (monitors)
//!   or XComposite window pixmaps (single windows, works while obscured).
//!   Synchronous start. `_NET_WM_PID` also gives the shared window's process
//!   id, so per-app audio share works here too.
//!
//! Detection: a set `WAYLAND_DISPLAY` means Wayland (X11 grabs there could
//! only see XWayland clients, not the real desktop); otherwise a set
//! `DISPLAY` means X11; neither fails cleanly.

mod portal;
mod x11;

use super::{CaptureStatus, CapturedFrame, ScreenSource, SharedStatus, WindowSource};
use crate::MediaError;

/// What kind of graphical session this process lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionKind {
    Wayland,
    X11,
    Headless,
}

fn session_kind() -> SessionKind {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        SessionKind::Wayland
    } else if std::env::var_os("DISPLAY").is_some() {
        SessionKind::X11
    } else {
        SessionKind::Headless
    }
}

/// The monitors a picker can offer. On Wayland this is the single portal
/// pseudo-entry (the system dialog does the real picking); on X11 it is the
/// actual RandR monitor list.
pub fn monitor_sources() -> Vec<ScreenSource> {
    match session_kind() {
        SessionKind::Wayland => vec![ScreenSource {
            index: 0,
            name: "Screen or window (choose in the system dialog)".into(),
        }],
        SessionKind::X11 => x11::monitor_sources(),
        SessionKind::Headless => Vec::new(),
    }
}

/// The windows a picker can offer: real titles on X11 (EWMH), empty on
/// Wayland where only the portal dialog may list other apps' windows.
pub fn window_sources() -> Vec<WindowSource> {
    match session_kind() {
        SessionKind::X11 => x11::window_sources(),
        _ => Vec::new(),
    }
}

/// The process id owning an X11 window (`_NET_WM_PID`), for per-app audio.
/// `None` on Wayland: the portal never reveals which window was picked.
pub(crate) fn window_pid(hwnd: isize) -> Option<u32> {
    match session_kind() {
        SessionKind::X11 => x11::window_pid(hwnd),
        _ => None,
    }
}

/// Whether sharing a window can carry that window's own audio here: yes on
/// X11 (`_NET_WM_PID` + PipeWire per-app capture), no on Wayland.
pub(crate) fn per_window_audio_supported() -> bool {
    session_kind() == SessionKind::X11
}

/// Captures a monitor or window with the session's backend, exposing the
/// latest frame. Dropping it stops the capture.
pub struct ScreenCapture {
    inner: Inner,
}

enum Inner {
    Portal(portal::PortalCapture),
    X11(x11::X11Capture),
}

impl ScreenCapture {
    /// Start capturing a monitor: by RandR index on X11; on Wayland the index
    /// is nominal and the system dialog picks the actual source.
    pub fn start_index(index: usize) -> Result<Self, MediaError> {
        let inner = match session_kind() {
            SessionKind::Wayland => Inner::Portal(portal::PortalCapture::start_portal()?),
            SessionKind::X11 => Inner::X11(x11::X11Capture::start_monitor(index)?),
            SessionKind::Headless => return Err(no_session()),
        };
        Ok(Self { inner })
    }

    /// Start capturing a single window (an X window id from
    /// [`window_sources`]; on Wayland the system dialog picks instead).
    pub fn start_window(hwnd: isize) -> Result<Self, MediaError> {
        let inner = match session_kind() {
            SessionKind::Wayland => Inner::Portal(portal::PortalCapture::start_portal()?),
            SessionKind::X11 => Inner::X11(x11::X11Capture::start_window(hwnd)?),
            SessionKind::Headless => return Err(no_session()),
        };
        Ok(Self { inner })
    }

    /// Capture a specific PipeWire video node, skipping the portal. Hardware
    /// validation hook (`examples/screen_probe.rs`).
    #[doc(hidden)]
    pub fn start_node(node_id: u32) -> Result<Self, MediaError> {
        Ok(Self {
            inner: Inner::Portal(portal::PortalCapture::start_node(node_id)?),
        })
    }

    /// Capture an X11 monitor with the raw backend regardless of session
    /// detection. Hardware validation hook (`examples/screen_probe.rs`).
    #[doc(hidden)]
    pub fn start_x11_index(index: usize) -> Result<Self, MediaError> {
        Ok(Self {
            inner: Inner::X11(x11::X11Capture::start_monitor(index)?),
        })
    }

    /// Capture an X11 window with the raw backend regardless of session
    /// detection. Hardware validation hook (`examples/screen_probe.rs`).
    #[doc(hidden)]
    pub fn start_x11_window(hwnd: isize) -> Result<Self, MediaError> {
        Ok(Self {
            inner: Inner::X11(x11::X11Capture::start_window(hwnd)?),
        })
    }

    /// The most recently captured frame, if any has arrived yet.
    pub fn latest(&self) -> Option<CapturedFrame> {
        match &self.inner {
            Inner::Portal(c) => c.latest(),
            Inner::X11(c) => c.latest(),
        }
    }

    /// This capture's life-cycle status.
    pub fn status(&self) -> CaptureStatus {
        match &self.inner {
            Inner::Portal(c) => c.status(),
            Inner::X11(c) => c.status(),
        }
    }

    /// The shared status cell, for supervising the share after the capture has
    /// been moved into its encode thread.
    pub fn status_handle(&self) -> SharedStatus {
        match &self.inner {
            Inner::Portal(c) => c.status_handle(),
            Inner::X11(c) => c.status_handle(),
        }
    }
}

fn no_session() -> MediaError {
    MediaError::Codec("no graphical session (neither WAYLAND_DISPLAY nor DISPLAY is set)".into())
}
