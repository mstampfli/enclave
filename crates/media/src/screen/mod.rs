//! Screen and window capture: one API, a backend per platform.
//!
//! Every backend feeds one shared "latest frame" slot that the encoder loop
//! pulls at its own cadence, dropping anything it cannot keep up with -- the
//! right behavior for real-time sharing.
//!
//! - **Windows** ([`windows`]): DXGI Desktop Duplication for monitors, Windows
//!   Graphics Capture for single windows. The app enumerates sources itself and
//!   starting a capture either works or fails immediately.
//! - **Linux** ([`linux`]): the XDG desktop portal's ScreenCast interface. The
//!   *system* picker dialog chooses the monitor or window (apps cannot
//!   enumerate other windows on Wayland by design), then the compositor
//!   delivers frames over a PipeWire video stream. Because a human sits
//!   between "start" and "frames" (and may cancel), starting is asynchronous:
//!   the capture is created immediately and reports its life cycle through
//!   [`CaptureStatus`].
//! - Anything else ([`stub`]): enumerations are empty and starting fails
//!   cleanly, so the client stays portable.
//!
//! All backends de-pad to a tight BGRA buffer ready for [`crate::H264Encoder`].

use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(windows, target_os = "linux")))]
mod stub;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{monitor_sources, window_sources, ScreenCapture};
#[cfg(not(any(windows, target_os = "linux")))]
pub use stub::{monitor_sources, window_sources, ScreenCapture};
#[cfg(windows)]
pub use windows::{monitor_sources, window_sources, ScreenCapture};

/// One captured frame: tightly packed BGRA (`width*height*4`, no row padding).
#[derive(Clone)]
pub struct CapturedFrame {
    pub bgra: Vec<u8>,
    pub width: usize,
    pub height: usize,
}

/// The shared latest-frame slot a backend fills and the encoder drains.
pub(crate) type Slot = Arc<Mutex<Option<CapturedFrame>>>;

/// Store a de-padded BGRA frame into the shared slot, dropping malformed ones.
pub(crate) fn store(slot: &Slot, w: usize, h: usize, tight: &[u8]) {
    if tight.len() == w * h * 4 {
        *slot.lock().unwrap() = Some(CapturedFrame {
            bgra: tight.to_vec(),
            width: w,
            height: h,
        });
    }
}

/// A monitor the user can pick to share: its zero-based `index` (pass to
/// [`ScreenCapture::start_index`]) and a human-readable `name`. On Linux the
/// list is a single "choose in the system dialog" entry (see [`linux`]).
#[derive(Debug, Clone)]
pub struct ScreenSource {
    pub index: usize,
    pub name: String,
}

/// A window the user can pick to share: an opaque platform handle `hwnd` (pass
/// to [`ScreenCapture::start_window`]) and its title. Empty on Linux, where
/// only the system picker may list other apps' windows.
#[derive(Debug, Clone)]
pub struct WindowSource {
    pub hwnd: isize,
    pub name: String,
}

/// Where a running capture is in its life cycle.
///
/// Windows captures are `Live` from the start (creation fails synchronously
/// instead). A Linux capture is `Starting` while the portal dialog is up and
/// becomes `Live` at the first delivered frame or `Ended` if the user cancels
/// the dialog, the session is revoked, or the stream dies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureStatus {
    Starting,
    Live,
    Ended(EndedReason),
}

/// Why a capture ended on its own, so the UI can tell "the user changed their
/// mind" (calm) from "something broke" (an error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndedReason {
    /// The user dismissed the system picker without sharing.
    Cancelled,
    /// The capture could not start or died mid-share.
    Failed(String),
}

impl std::fmt::Display for EndedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "share cancelled"),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

/// A capture's status cell, shared between the backend threads that update it
/// and whoever supervises the share (cheap to clone, lock held only to copy).
#[derive(Clone)]
pub struct SharedStatus(Arc<Mutex<CaptureStatus>>);

impl SharedStatus {
    // The constructors and transitions are backend-specific (Windows starts
    // `Live` and never moves; Linux walks the full life cycle), so each is
    // dead code on the platforms whose backend does not call it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn starting() -> Self {
        Self(Arc::new(Mutex::new(CaptureStatus::Starting)))
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn live() -> Self {
        Self(Arc::new(Mutex::new(CaptureStatus::Live)))
    }

    pub fn get(&self) -> CaptureStatus {
        self.0.lock().unwrap().clone()
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn set_live(&self) {
        let mut s = self.0.lock().unwrap();
        // Never resurrect an ended capture (a late frame racing a cancel).
        if *s == CaptureStatus::Starting {
            *s = CaptureStatus::Live;
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn set_ended(&self, reason: EndedReason) {
        let mut s = self.0.lock().unwrap();
        // First cause wins; later teardown noise must not overwrite it.
        if !matches!(*s, CaptureStatus::Ended(_)) {
            *s = CaptureStatus::Ended(reason);
        }
    }
}

/// Copy one video buffer into `out` as tight BGRA. Source rows are `stride`
/// bytes apart with `w*4` bytes of pixel data each; `swap_rb` converts
/// RGBx/RGBA sources by swizzling R and B. Returns `false` (leaving `out`
/// unspecified) if `src` cannot hold `h` such rows -- a malformed buffer is
/// dropped, never over-read.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn tighten_to_bgra(
    src: &[u8],
    stride: usize,
    w: usize,
    h: usize,
    swap_rb: bool,
    out: &mut Vec<u8>,
) -> bool {
    let row_bytes = match w.checked_mul(4) {
        Some(rb) => rb,
        None => return false,
    };
    if stride < row_bytes || w == 0 || h == 0 {
        return false;
    }
    // The last row only needs its pixel data, not the full stride of padding.
    let needed = match stride
        .checked_mul(h - 1)
        .and_then(|n| n.checked_add(row_bytes))
    {
        Some(n) => n,
        None => return false,
    };
    if src.len() < needed {
        return false;
    }
    out.clear();
    out.reserve(row_bytes * h);
    for row in 0..h {
        let line = &src[row * stride..row * stride + row_bytes];
        if swap_rb {
            for px in line.chunks_exact(4) {
                out.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
            }
        } else {
            out.extend_from_slice(line);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tightens_strided_rows() {
        // 2x2 BGRA with 4 bytes of row padding (stride 12).
        let mut src = Vec::new();
        for row in 0..2u8 {
            for px in 0..2u8 {
                src.extend_from_slice(&[row * 10 + px, 1, 2, 3]);
            }
            src.extend_from_slice(&[0xEE; 4]); // padding, must not leak through
        }
        let mut out = Vec::new();
        assert!(tighten_to_bgra(&src, 12, 2, 2, false, &mut out));
        assert_eq!(
            out,
            vec![0, 1, 2, 3, 1, 1, 2, 3, 10, 1, 2, 3, 11, 1, 2, 3],
            "rows de-padded in order"
        );
    }

    #[test]
    fn last_row_may_omit_padding() {
        // stride 12 but the buffer ends right after the last row's pixels,
        // as PipeWire buffers legally do.
        let src = [
            1, 2, 3, 4, 5, 6, 7, 8, 0xEE, 0xEE, 0xEE, 0xEE, // row 0 + pad
            9, 10, 11, 12, 13, 14, 15, 16, // row 1, no pad
        ];
        let mut out = Vec::new();
        assert!(tighten_to_bgra(&src, 12, 2, 2, false, &mut out));
        assert_eq!(out[8..], [9, 10, 11, 12, 13, 14, 15, 16]);
    }

    #[test]
    fn swizzles_rgbx_to_bgrx() {
        let src = [10, 20, 30, 40]; // R G B x
        let mut out = Vec::new();
        assert!(tighten_to_bgra(&src, 4, 1, 1, true, &mut out));
        assert_eq!(out, vec![30, 20, 10, 40], "R and B swapped, G/x kept");
    }

    #[test]
    fn rejects_short_and_degenerate_buffers() {
        let mut out = Vec::new();
        assert!(!tighten_to_bgra(&[0; 8], 8, 2, 2, false, &mut out), "short");
        assert!(
            !tighten_to_bgra(&[0; 64], 4, 2, 2, false, &mut out),
            "stride < row"
        );
        assert!(
            !tighten_to_bgra(&[], 4, 0, 1, false, &mut out),
            "zero width"
        );
        assert!(
            !tighten_to_bgra(&[], 4, 1, 0, false, &mut out),
            "zero height"
        );
    }

    #[test]
    fn status_transitions_are_one_way() {
        let died = || EndedReason::Failed("stream died".into());
        let s = SharedStatus::starting();
        assert_eq!(s.get(), CaptureStatus::Starting);
        s.set_live();
        assert_eq!(s.get(), CaptureStatus::Live);
        s.set_ended(died());
        assert_eq!(s.get(), CaptureStatus::Ended(died()));
        s.set_live(); // a straggler frame must not resurrect it
        assert_eq!(s.get(), CaptureStatus::Ended(died()));
        s.set_ended(EndedReason::Cancelled); // first cause wins
        assert_eq!(s.get(), CaptureStatus::Ended(died()));
    }

    #[test]
    fn store_accepts_only_exact_frames() {
        let slot: Slot = Arc::new(Mutex::new(None));
        store(&slot, 2, 1, &[0; 8]);
        assert!(slot.lock().unwrap().is_some());
        *slot.lock().unwrap() = None;
        store(&slot, 2, 1, &[0; 7]);
        assert!(slot.lock().unwrap().is_none(), "wrong-size frame dropped");
    }
}
