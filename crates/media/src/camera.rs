//! Webcam capture (nokhwa). Opens a camera and yields tightly-packed BGRA frames
//! ready for [`crate::H264Encoder`], mirroring [`crate::screen`]'s output so the
//! two video sources share one encode/seal path.
//!
//! Like the audio and screen backends, the camera device is `!Send` (Media
//! Foundation / COM on Windows), so a [`CameraCapture`] is created and pumped on
//! one dedicated thread and never crosses threads.
//!
//! HARDWARE PATH: a real camera cannot be exercised headlessly; this is
//! compile-verified and validated on a real device.

use nokhwa::pixel_format::RgbFormat;
use nokhwa::utils::{ApiBackend, CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::Camera;

use crate::MediaError;

/// A camera the user can pick to share: its `index` (pass to
/// [`CameraCapture::open`]) and a human-readable `name`.
#[derive(Debug, Clone)]
pub struct CameraSource {
    pub index: u32,
    pub name: String,
}

/// Enumerate the cameras attached to this machine. Best-effort: returns an empty
/// list if the platform query fails (e.g. no backend / permissions).
pub fn camera_sources() -> Vec<CameraSource> {
    match nokhwa::query(ApiBackend::Auto) {
        Ok(infos) => infos
            .into_iter()
            .filter_map(|info| {
                let index = info.index().as_index().ok()?;
                Some(CameraSource {
                    index,
                    name: info.human_name(),
                })
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// A live webcam stream. [`Self::next_bgra`] blocks for the next frame and
/// returns it as tight BGRA plus its dimensions.
pub struct CameraCapture {
    cam: Camera,
    rgb: Vec<u8>,
    bgra: Vec<u8>,
}

impl CameraCapture {
    /// Open the camera at a zero-based `index` (0 = default) and start streaming
    /// at the highest frame rate the device offers.
    pub fn open(index: u32) -> Result<Self, MediaError> {
        let requested =
            RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
        let mut cam = Camera::new(CameraIndex::Index(index), requested)
            .map_err(|e| MediaError::Camera(e.to_string()))?;
        cam.open_stream()
            .map_err(|e| MediaError::Camera(e.to_string()))?;
        Ok(Self {
            cam,
            rgb: Vec::new(),
            bgra: Vec::new(),
        })
    }

    /// Block for the next frame and decode it to tightly-packed BGRA. Returns
    /// `(bgra, width, height)`. Buffers are reused across calls.
    pub fn next_bgra(&mut self) -> Result<(&[u8], usize, usize), MediaError> {
        let buf = self
            .cam
            .frame()
            .map_err(|e| MediaError::Camera(e.to_string()))?;
        let res = buf.resolution();
        let w = res.width() as usize;
        let h = res.height() as usize;
        let px = w * h;
        self.rgb.resize(px * 3, 0);
        buf.decode_image_to_buffer::<RgbFormat>(&mut self.rgb)
            .map_err(|e| MediaError::Camera(e.to_string()))?;
        // RGB888 -> BGRA8888 (what the H.264 encoder consumes).
        self.bgra.resize(px * 4, 0);
        for i in 0..px {
            let s = i * 3;
            let d = i * 4;
            self.bgra[d] = self.rgb[s + 2]; // B
            self.bgra[d + 1] = self.rgb[s + 1]; // G
            self.bgra[d + 2] = self.rgb[s]; // R
            self.bgra[d + 3] = 255; // A (opaque)
        }
        Ok((&self.bgra, w, h))
    }
}
