//! Optional microphone noise suppression via RNNoise (Xiph), through the pure-Rust
//! `nnnoiseless` port with the model weights embedded. Sits on the mic path before
//! Opus encode: `mic PCM -> [suppress] -> encode`. Stateful per stream (the model
//! carries recurrent state), so each capture keeps its own instance.

use nnnoiseless::DenoiseState;

/// A single-channel 48 kHz noise suppressor. Feed it the mic's i16 PCM frames and
/// it removes steady-state background noise in place while preserving speech.
pub struct NoiseSuppressor {
    state: Box<DenoiseState<'static>>,
    frame_in: [f32; DenoiseState::FRAME_SIZE],
    frame_out: [f32; DenoiseState::FRAME_SIZE],
}

impl NoiseSuppressor {
    pub fn new() -> Self {
        Self {
            state: DenoiseState::new(),
            frame_in: [0.0; DenoiseState::FRAME_SIZE],
            frame_out: [0.0; DenoiseState::FRAME_SIZE],
        }
    }

    /// Denoise `pcm` (48 kHz mono i16) in place. RNNoise works on its native
    /// 480-sample (10 ms) frames, so call with a length that is a multiple of 480;
    /// our 960-sample capture frames are exactly two. RNNoise takes/returns f32 in
    /// the i16 value range (not normalised), so the conversion is a plain cast plus
    /// a rounded, clamped cast back. A trailing partial frame is left untouched.
    pub fn process(&mut self, pcm: &mut [i16]) {
        for chunk in pcm.chunks_mut(DenoiseState::FRAME_SIZE) {
            if chunk.len() < DenoiseState::FRAME_SIZE {
                break;
            }
            for (dst, &s) in self.frame_in.iter_mut().zip(chunk.iter()) {
                *dst = s as f32;
            }
            self.state
                .process_frame(&mut self.frame_out, &self.frame_in);
            for (dst, &v) in chunk.iter_mut().zip(self.frame_out.iter()) {
                *dst = v.round().clamp(i16::MIN as f32, i16::MAX as f32) as i16;
            }
        }
    }
}

impl Default for NoiseSuppressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_stays_silent_and_length_is_preserved() {
        let mut ns = NoiseSuppressor::new();
        let mut frame = [0i16; 960];
        ns.process(&mut frame);
        assert_eq!(frame.len(), 960);
        // Denoising pure silence must not synthesise energy.
        assert!(frame.iter().all(|&s| s.abs() <= 1));
    }

    #[test]
    fn a_trailing_partial_frame_is_left_untouched() {
        let mut ns = NoiseSuppressor::new();
        // Fewer than 480 samples: no whole RNNoise frame, so nothing changes.
        let mut frame = [1234i16; 200];
        ns.process(&mut frame);
        assert!(frame.iter().all(|&s| s == 1234));
    }
}
