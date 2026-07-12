//! Primary-monitor screen capture via DXGI Desktop Duplication (Windows).
//!
//! A background thread owns the (`!Send`) D3D duplication device and keeps the
//! most recent frame in a slot; the encoder loop pulls the latest frame at its
//! own cadence and drops anything it could not keep up with, which is the right
//! behavior for real-time screen share. Frames are de-padded to a tight BGRA
//! buffer ready for [`crate::H264Encoder`].
//!
//! HARDWARE PATH: capture cannot be exercised headlessly (no display / DXGI in
//! CI); it is compile-verified and validated on a real machine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows_capture::dxgi_duplication_api::DxgiDuplicationApi;
use windows_capture::monitor::Monitor;

use crate::MediaError;

/// One captured frame: tightly packed BGRA (`width*height*4`, no row padding).
#[derive(Clone)]
pub struct CapturedFrame {
    pub bgra: Vec<u8>,
    pub width: usize,
    pub height: usize,
}

/// Captures the primary monitor on a background thread, exposing the latest
/// frame. Dropping it stops the capture.
pub struct ScreenCapture {
    latest: Arc<Mutex<Option<CapturedFrame>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ScreenCapture {
    /// Start capturing the primary monitor. Returns once capture has started (or
    /// with an error if the duplication device could not be created).
    pub fn start_primary() -> Result<Self, MediaError> {
        let monitor =
            Monitor::primary().map_err(|e| MediaError::Codec(format!("no primary monitor: {e}")))?;
        let latest: Arc<Mutex<Option<CapturedFrame>>> = Arc::new(Mutex::new(None));
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
                if tight.len() == w * h * 4 {
                    *l.lock().unwrap() = Some(CapturedFrame {
                        bgra: tight.to_vec(),
                        width: w,
                        height: h,
                    });
                }
            }
        });
        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                latest,
                stop,
                thread: Some(thread),
            }),
            Ok(Err(e)) => Err(MediaError::Codec(format!("screen capture: {e}"))),
            Err(_) => Err(MediaError::Codec("screen capture thread died".into())),
        }
    }

    /// The most recently captured frame, if any has arrived yet.
    pub fn latest(&self) -> Option<CapturedFrame> {
        self.latest.lock().unwrap().clone()
    }
}

impl Drop for ScreenCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
