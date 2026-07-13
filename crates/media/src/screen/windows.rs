//! Screen and window capture (Windows).
//!
//! - Monitors use DXGI Desktop Duplication (`DxgiDuplicationApi`): a background
//!   thread owns the (`!Send`) device and pushes each frame into the slot. Low
//!   latency, no capture border.
//! - Specific windows use Windows Graphics Capture (`GraphicsCaptureApiHandler`):
//!   a callback delivers frames on its own thread; WGC is the only API that can
//!   target a single window (DXGI is monitor-only).
//!
//! The shared frame slot, source types, and status cell live in [`super`]. A
//! Windows capture either starts `Live` or fails synchronously, so its
//! [`SharedStatus`] never leaves `Live`.
//!
//! HARDWARE PATH: capture cannot be exercised headlessly (no display / DXGI in
//! CI); it is compile-verified and validated on a real machine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use super::{store, CaptureStatus, CapturedFrame, ScreenSource, SharedStatus, Slot, WindowSource};

use windows_capture::capture::{CaptureControl, Context, GraphicsCaptureApiHandler};
use windows_capture::dxgi_duplication_api::DxgiDuplicationApi;
use windows_capture::frame::Frame;
use windows_capture::graphics_capture_api::InternalCaptureControl;
use windows_capture::monitor::Monitor;
use windows_capture::settings::{
    ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
    MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
};
use windows_capture::window::Window;

use crate::MediaError;

/// Enumerate the monitors attached to this machine. Best-effort: returns an
/// empty list if enumeration fails.
pub fn monitor_sources() -> Vec<ScreenSource> {
    let Ok(monitors) = Monitor::enumerate() else {
        return Vec::new();
    };
    monitors
        .into_iter()
        .filter_map(|m| {
            let index = m.index().ok()?;
            // Prefer the friendly device name; fall back to a generic label.
            let name = m
                .device_name()
                .or_else(|_| m.name())
                .unwrap_or_else(|_| format!("Display {index}"));
            Some(ScreenSource { index, name })
        })
        .collect()
}

/// Enumerate the shareable top-level windows (visible, titled, not our own).
/// Best-effort: returns an empty list if enumeration fails.
pub fn window_sources() -> Vec<WindowSource> {
    let Ok(windows) = Window::enumerate() else {
        return Vec::new();
    };
    windows
        .into_iter()
        .filter_map(|w| {
            let name = w.title().ok()?;
            if name.trim().is_empty() {
                return None; // untitled helper windows are not useful to share
            }
            Some(WindowSource {
                hwnd: w.as_raw_hwnd() as isize,
                name,
            })
        })
        .collect()
}

/// The WGC handler's associated error. We never actually fail a frame (bad ones
/// are skipped), but the trait needs an error type that is `Display` so the
/// crate's `GraphicsCaptureApiError<E>` can format it.
#[derive(Debug)]
struct HandlerError;

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "window capture handler error")
    }
}

impl std::error::Error for HandlerError {}

/// Delivers WGC window frames into the shared slot. `Flags` carries the slot in.
struct WindowCapture {
    slot: Slot,
    scratch: Vec<u8>,
}

impl GraphicsCaptureApiHandler for WindowCapture {
    type Flags = Slot;
    type Error = HandlerError;

    fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: ctx.flags,
            scratch: Vec::new(),
        })
    }

    fn on_frame_arrived(
        &mut self,
        frame: &mut Frame,
        _ctl: InternalCaptureControl,
    ) -> Result<(), Self::Error> {
        if let Ok(buf) = frame.buffer() {
            let (w, h) = (buf.width() as usize, buf.height() as usize);
            let tight = buf.as_nopadding_buffer(&mut self.scratch);
            store(&self.slot, w, h, tight);
        }
        Ok(())
    }
}

/// Which capture backend a [`ScreenCapture`] is running.
enum Backend {
    /// DXGI duplication of a monitor: a polling thread we stop via `stop`.
    Dxgi {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    },
    /// WGC capture of a window: a control handle we stop by consuming it.
    Window(Option<CaptureControl<WindowCapture, HandlerError>>),
}

/// Captures a monitor or a window on a background thread, exposing the latest
/// frame. Dropping it stops the capture.
pub struct ScreenCapture {
    latest: Slot,
    status: SharedStatus,
    backend: Backend,
}

impl ScreenCapture {
    /// Start capturing the primary monitor.
    pub fn start_primary() -> Result<Self, MediaError> {
        let monitor = Monitor::primary()
            .map_err(|e| MediaError::Codec(format!("no primary monitor: {e}")))?;
        Self::start_monitor(monitor)
    }

    /// Start capturing a specific monitor by its zero-based index (see
    /// [`monitor_sources`]).
    pub fn start_index(index: usize) -> Result<Self, MediaError> {
        let monitor = Monitor::from_index(index)
            .map_err(|e| MediaError::Codec(format!("no monitor {index}: {e}")))?;
        Self::start_monitor(monitor)
    }

    fn start_monitor(monitor: Monitor) -> Result<Self, MediaError> {
        let latest: Slot = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let l = latest.clone();
        let s = stop.clone();
        // The duplication device is !Send: create and use it on this thread.
        let (init_tx, init_rx) = mpsc::channel::<Result<(), String>>();
        let thread = std::thread::spawn(move || {
            let mut dup = match DxgiDuplicationApi::new(monitor) {
                Ok(d) => {
                    let _ = init_tx.send(Ok(()));
                    d
                }
                Err(e) => {
                    let _ = init_tx.send(Err(e.to_string()));
                    return;
                }
            };
            let mut scratch: Vec<u8> = Vec::new();
            while !s.load(Ordering::Relaxed) {
                // 100 ms timeout: if the desktop is static there is no new frame,
                // which is fine -- we just re-poll and keep the last one.
                let mut frame = match dup.acquire_next_frame(100) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let buf = match frame.buffer() {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let (w, h) = (buf.width() as usize, buf.height() as usize);
                let tight = buf.as_nopadding_buffer(&mut scratch);
                store(&l, w, h, tight);
            }
        });
        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                latest,
                status: SharedStatus::live(),
                backend: Backend::Dxgi {
                    stop,
                    thread: Some(thread),
                },
            }),
            Ok(Err(e)) => Err(MediaError::Codec(format!("screen capture: {e}"))),
            Err(_) => Err(MediaError::Codec("screen capture thread died".into())),
        }
    }

    /// Start capturing a specific window by its handle (see [`window_sources`]).
    pub fn start_window(hwnd: isize) -> Result<Self, MediaError> {
        let window = Window::from_raw_hwnd(hwnd as *mut std::ffi::c_void);
        if !window.is_valid() {
            return Err(MediaError::Codec(
                "that window is no longer available".into(),
            ));
        }
        let latest: Slot = Arc::new(Mutex::new(None));
        let settings = Settings::new(
            window,
            CursorCaptureSettings::WithoutCursor,
            DrawBorderSettings::Default,
            SecondaryWindowSettings::Default,
            MinimumUpdateIntervalSettings::Default,
            DirtyRegionSettings::Default,
            ColorFormat::Bgra8,
            latest.clone(),
        );
        let control = WindowCapture::start_free_threaded(settings)
            .map_err(|e| MediaError::Codec(format!("window capture: {e}")))?;
        Ok(Self {
            latest,
            status: SharedStatus::live(),
            backend: Backend::Window(Some(control)),
        })
    }

    /// The most recently captured frame, if any has arrived yet.
    pub fn latest(&self) -> Option<CapturedFrame> {
        self.latest.lock().unwrap().clone()
    }

    /// This capture's life-cycle status (always `Live` on Windows).
    pub fn status(&self) -> CaptureStatus {
        self.status.get()
    }

    /// The shared status cell, for supervising the share after the capture has
    /// been moved into its encode thread.
    pub fn status_handle(&self) -> SharedStatus {
        self.status.clone()
    }
}

impl Drop for ScreenCapture {
    fn drop(&mut self) {
        match &mut self.backend {
            Backend::Dxgi { stop, thread } => {
                stop.store(true, Ordering::Relaxed);
                if let Some(t) = thread.take() {
                    let _ = t.join();
                }
            }
            Backend::Window(control) => {
                if let Some(c) = control.take() {
                    let _ = c.stop();
                }
            }
        }
    }
}
