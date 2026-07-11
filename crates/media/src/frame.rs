//! Pure framing and format helpers between the device (interleaved f32/i16 at
//! the device's channel count) and the codec (mono i16 in fixed 20 ms frames).
//! These are the testable core the hardware device layer builds on.

use crate::audio::FRAME_SAMPLES;

/// Convert a float sample in [-1.0, 1.0] to signed 16-bit PCM (clamped).
pub fn f32_to_i16(sample: f32) -> i16 {
    (sample.clamp(-1.0, 1.0) * i16::MAX as f32) as i16
}

/// Convert a signed 16-bit PCM sample to a float in [-1.0, 1.0].
pub fn i16_to_f32(sample: i16) -> f32 {
    sample as f32 / i16::MAX as f32
}

/// Downmix interleaved `channels`-channel audio to mono by averaging channels.
pub fn downmix_to_mono(interleaved: &[f32], channels: usize) -> Vec<f32> {
    if channels <= 1 {
        return interleaved.to_vec();
    }
    interleaved
        .chunks(channels)
        .map(|frame| frame.iter().sum::<f32>() / frame.len() as f32)
        .collect()
}

/// Buffers a stream of mono samples and emits fixed-size [`FRAME_SAMPLES`]
/// frames, holding any remainder for the next push.
pub struct FrameAccumulator {
    buf: Vec<i16>,
}

impl Default for FrameAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAccumulator {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(FRAME_SAMPLES * 2),
        }
    }

    /// Append `samples`, invoking `emit` once per complete frame; keep the rest.
    pub fn push(&mut self, samples: &[i16], mut emit: impl FnMut(&[i16])) {
        self.buf.extend_from_slice(samples);
        let mut start = 0;
        while start + FRAME_SAMPLES <= self.buf.len() {
            emit(&self.buf[start..start + FRAME_SAMPLES]);
            start += FRAME_SAMPLES;
        }
        if start > 0 {
            self.buf.drain(..start);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f32_i16_conversion_clamps_and_round_trips() {
        assert_eq!(f32_to_i16(0.0), 0);
        assert_eq!(f32_to_i16(1.0), i16::MAX);
        assert_eq!(f32_to_i16(2.0), i16::MAX, "clamped");
        assert_eq!(f32_to_i16(-2.0), -i16::MAX, "clamped");
        // Round trip stays close.
        for x in [-0.9_f32, -0.5, 0.0, 0.25, 0.75] {
            let back = i16_to_f32(f32_to_i16(x));
            assert!((back - x).abs() < 1e-3, "{x} -> {back}");
        }
    }

    #[test]
    fn downmix_averages_channels() {
        // Stereo interleaved L,R,L,R -> mono averages each pair.
        let stereo = [1.0, 3.0, 2.0, 4.0];
        assert_eq!(downmix_to_mono(&stereo, 2), vec![2.0, 3.0]);
        // Mono passes through unchanged.
        assert_eq!(downmix_to_mono(&[1.0, 2.0, 3.0], 1), vec![1.0, 2.0, 3.0]);
    }

    #[test]
    fn accumulator_emits_full_frames_and_keeps_remainder() {
        let mut acc = FrameAccumulator::new();
        let mut frames = 0usize;

        // One full frame plus 100 leftover samples.
        let input = vec![7i16; FRAME_SAMPLES + 100];
        acc.push(&input, |frame| {
            assert_eq!(frame.len(), FRAME_SAMPLES);
            frames += 1;
        });
        assert_eq!(frames, 1, "one complete frame emitted");

        // Adding FRAME_SAMPLES - 100 completes the buffered remainder.
        let rest = vec![7i16; FRAME_SAMPLES - 100];
        acc.push(&rest, |frame| {
            assert_eq!(frame.len(), FRAME_SAMPLES);
            frames += 1;
        });
        assert_eq!(
            frames, 2,
            "buffered remainder completes into a second frame"
        );
    }
}
