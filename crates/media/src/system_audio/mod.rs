//! System-audio loopback capture for "share audio" in a call: one API, a
//! backend per platform (WASAPI on Windows, PipeWire on Linux, a clean-failing
//! stub elsewhere).
//!
//! Two modes, both echo-aware:
//! - [`LoopbackMode::Process`]: capture only a target application's audio.
//!   Echo-free during a call because the call's own playback is not part of
//!   that app's stream. (On Windows the pid comes from the shared window; on
//!   Linux the portal hides which window was picked, so the client shares the
//!   system mix instead -- the mode itself works when a pid is known.)
//! - [`LoopbackMode::System`]: capture the whole output mix. Works with any
//!   share, but during a call it also captures the voices you are hearing
//!   (echo) unless the call plays to a different device -- the UI warns.
//!
//! Captured audio is normalized to 48 kHz stereo 16-bit by the platform's
//! audio engine, down-mixed to mono here, and pushed into a shared ring the
//! mic encoder drains and sums into each outgoing frame (so shared audio rides
//! the sender's existing single Opus stream -- the receiver needs no change
//! and there is no second decoder to keep in sync).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(windows, target_os = "linux")))]
mod stub;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::SystemAudioCapture;
#[cfg(not(any(windows, target_os = "linux")))]
pub use stub::SystemAudioCapture;
#[cfg(windows)]
pub use windows::SystemAudioCapture;

/// Shared 48 kHz mono i16 ring the mic encoder drains and mixes in.
pub type AudioMix = Arc<Mutex<VecDeque<i16>>>;

/// Cap the ring so shared audio cannot build unbounded latency (100 ms @ 48 k).
pub(crate) const MIX_CAP: usize = 4800;

/// What to capture.
#[derive(Debug, Clone, Copy)]
pub enum LoopbackMode {
    /// Only this process (and, on Windows, its children) -- echo-free.
    Process(u32),
    /// The whole output mix.
    System,
}

/// Resolve the process id that owns a window, for [`LoopbackMode::Process`]:
/// `GetWindowThreadProcessId` on Windows, EWMH `_NET_WM_PID` on Linux X11.
/// `None` where the platform cannot know (Wayland: the portal hides the
/// picked window's identity; the stub platforms have no windows to resolve).
pub fn window_pid(hwnd: isize) -> Option<u32> {
    #[cfg(windows)]
    {
        windows::window_pid(hwnd)
    }
    #[cfg(target_os = "linux")]
    {
        crate::screen::linux_window_pid(hwnd)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = hwnd;
        None
    }
}

/// Down-mix interleaved stereo i16 into the mono ring, dropping the oldest
/// samples past [`MIX_CAP`] so a stalled drain bounds latency, never memory.
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
pub(crate) fn mix_in_stereo_i16(mix: &AudioMix, stereo: &[i16]) {
    let mut ring = mix.lock().unwrap();
    for pair in stereo.chunks_exact(2) {
        let mono = ((pair[0] as i32 + pair[1] as i32) / 2) as i16;
        ring.push_back(mono);
    }
    while ring.len() > MIX_CAP {
        ring.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> AudioMix {
        Arc::new(Mutex::new(VecDeque::new()))
    }

    #[test]
    fn downmixes_stereo_to_mono() {
        let mix = ring();
        mix_in_stereo_i16(&mix, &[100, 200, -50, 50, 7, 8]);
        let got: Vec<i16> = mix.lock().unwrap().iter().copied().collect();
        assert_eq!(got, vec![150, 0, 7]);
    }

    #[test]
    fn averaging_cannot_overflow_i16() {
        let mix = ring();
        mix_in_stereo_i16(&mix, &[i16::MAX, i16::MAX, i16::MIN, i16::MIN]);
        let got: Vec<i16> = mix.lock().unwrap().iter().copied().collect();
        assert_eq!(got, vec![i16::MAX, i16::MIN]);
    }

    #[test]
    fn ring_is_bounded_dropping_oldest() {
        let mix = ring();
        // 2*MIX_CAP mono samples in: only the newest MIX_CAP survive.
        let stereo: Vec<i16> = (0..(2 * MIX_CAP as i32 * 2))
            .map(|i| (i % 1000) as i16)
            .collect();
        mix_in_stereo_i16(&mix, &stereo);
        let ring = mix.lock().unwrap();
        assert_eq!(ring.len(), MIX_CAP, "capped at MIX_CAP");
    }

    #[test]
    fn odd_trailing_sample_is_ignored() {
        let mix = ring();
        mix_in_stereo_i16(&mix, &[10, 20, 99]);
        assert_eq!(mix.lock().unwrap().len(), 1, "incomplete pair dropped");
    }
}
