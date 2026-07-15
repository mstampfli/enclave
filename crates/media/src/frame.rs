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
    let mut out = Vec::new();
    downmix_to_mono_into(interleaved, channels, &mut out);
    out
}

/// Downmix into a caller-owned buffer, allocation-free when the buffer already
/// has capacity. Used by the real-time capture callback, which must not allocate
/// (a heap allocation in an audio callback risks a buffer under/overrun).
pub fn downmix_to_mono_into(interleaved: &[f32], channels: usize, out: &mut Vec<f32>) {
    out.clear();
    if channels <= 1 {
        out.extend_from_slice(interleaved);
        return;
    }
    out.extend(
        interleaved
            .chunks(channels)
            .map(|frame| frame.iter().sum::<f32>() / frame.len() as f32),
    );
}

/// Downmix interleaved i16 audio to mono directly (averaging in i32 to avoid
/// overflow), into a caller-owned buffer. Avoids the f32 round-trip for i16
/// devices and, like [`downmix_to_mono_into`], does not allocate.
pub fn downmix_i16_to_mono_into(interleaved: &[i16], channels: usize, out: &mut Vec<i16>) {
    out.clear();
    if channels <= 1 {
        out.extend_from_slice(interleaved);
        return;
    }
    out.extend(
        interleaved.chunks(channels).map(|frame| {
            (frame.iter().map(|&s| s as i32).sum::<i32>() / frame.len() as i32) as i16
        }),
    );
}

/// Streaming linear resampler between two sample rates, mono. It is fed
/// arbitrary-length chunks (as a device callback delivers them) and appends the
/// resampled stream, carrying the fractional read position and the last input
/// sample across calls so there are no seams at chunk boundaries. Linear
/// interpolation is adequate for band-limited voice; equal rates are a zero-cost
/// passthrough.
///
/// The whole codec/frame pipeline is fixed at 48 kHz, but audio devices open at
/// their own native rate (a 96 kHz speaker cannot be forced to 48 kHz in WASAPI
/// shared mode), so this bridges device rate <-> 48 kHz on both capture and
/// playback.
pub struct Resampler {
    /// Input samples consumed per output sample (in_rate / out_rate).
    in_per_out: f64,
    /// Output position within the current [`prev`, next-input] segment, in [0,1).
    opos: f64,
    prev: f32,
    primed: bool,
    passthrough: bool,
}

impl Resampler {
    pub fn new(in_rate: u32, out_rate: u32) -> Self {
        Self {
            in_per_out: in_rate as f64 / out_rate.max(1) as f64,
            opos: 0.0,
            prev: 0.0,
            primed: false,
            passthrough: in_rate == out_rate,
        }
    }

    /// Resample `input` (at the input rate) and append the result to `out` (at
    /// the output rate).
    pub fn process(&mut self, input: &[i16], out: &mut Vec<i16>) {
        if self.passthrough {
            out.extend_from_slice(input);
            return;
        }
        for &s in input {
            let cur = i16_to_f32(s);
            if !self.primed {
                self.prev = cur;
                self.primed = true;
                continue;
            }
            // Emit every output sample whose position falls in this input
            // segment [prev, cur], interpolating linearly between the two.
            while self.opos < 1.0 {
                let v = self.prev + (cur - self.prev) * self.opos as f32;
                out.push(f32_to_i16(v));
                self.opos += self.in_per_out;
            }
            self.opos -= 1.0;
            self.prev = cur;
        }
    }
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

    /// Feed `total` input samples in small chunks and return how many output
    /// samples the resampler produced -- exercising cross-chunk state carry.
    fn resample_count(in_rate: u32, out_rate: u32, total: usize) -> usize {
        let mut r = Resampler::new(in_rate, out_rate);
        let mut out = Vec::new();
        let input = vec![1000i16; total];
        for chunk in input.chunks(480) {
            r.process(chunk, &mut out);
        }
        out.len()
    }

    #[test]
    fn resampler_passthrough_is_identity() {
        let mut r = Resampler::new(48_000, 48_000);
        let mut out = Vec::new();
        r.process(&[1, 2, 3, 4, 5], &mut out);
        assert_eq!(out, vec![1, 2, 3, 4, 5], "equal rates copy through exactly");
    }

    #[test]
    fn resampler_matches_target_rate_ratio() {
        // 1 second of audio at each input rate should yield ~out_rate samples,
        // within a couple of samples for the priming/rounding edge.
        for &(inr, outr) in &[
            (48_000u32, 96_000u32), // 2x upsample (the 96 kHz-speaker case)
            (96_000, 48_000),       // 2x downsample
            (44_100, 48_000),       // non-integer up
            (48_000, 44_100),       // non-integer down
        ] {
            let got = resample_count(inr, outr, inr as usize);
            let want = outr as isize;
            let diff = (got as isize - want).abs();
            assert!(
                diff <= 2,
                "{inr}->{outr}: produced {got}, expected ~{want} (diff {diff})"
            );
        }
    }

    #[test]
    fn resampler_upsample_interpolates_midpoints() {
        // 2x upsample inserts the linear midpoint between input samples.
        let mut r = Resampler::new(24_000, 48_000);
        let mut out = Vec::new();
        r.process(&[0, 1000, 2000], &mut out);
        // First input primes; then each segment yields two samples (start, mid).
        assert_eq!(out, vec![0, 500, 1000, 1500]);
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
