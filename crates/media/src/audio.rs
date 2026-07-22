//! Opus audio codec: encode captured PCM to compressed frames and back.
//!
//! Enclave encrypts the *encoded* frame (see `enclave-crypto`'s media sealing),
//! never raw PCM, so this codec sits entirely on the plaintext side of the
//! trust boundary: `PCM -> [encode] -> frame -> [seal] -> wire`, reversed on
//! receive. 48 kHz mono, 20 ms frames -- the standard low-latency voice config.

use audiopus::coder::{Decoder, Encoder};
use audiopus::{Application, Channels, SampleRate};

use crate::MediaError;

/// Sample rate the pipeline runs at.
pub const SAMPLE_RATE_HZ: usize = 48_000;
/// Samples per frame per channel: 20 ms at 48 kHz.
pub const FRAME_SAMPLES: usize = 960;
/// Opus never emits more than ~4 kB for one frame.
const MAX_PACKET_BYTES: usize = 4000;

/// Apply an input-gain percentage (100 = unity) to a mono frame in place,
/// rounding and clamping so a boost saturates instead of wrapping.
pub fn apply_gain(pcm: &mut [i16], gain_pct: u32) {
    if gain_pct == 100 {
        return;
    }
    let g = gain_pct as f32 / 100.0;
    for s in pcm.iter_mut() {
        *s = (*s as f32 * g)
            .round()
            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;
    }
}

/// The loudness of a mono 48 kHz frame on a 0..=100 perceptual scale: RMS mapped
/// through dBFS, so it tracks how loud the frame *sounds* rather than raw
/// amplitude. Near silence (<= -80 dBFS) is 0; full scale (0 dBFS) is 100. One
/// comparable number drives both the input meter and the voice-activation gate.
pub fn frame_level_pct(pcm: &[i16]) -> u8 {
    if pcm.is_empty() {
        return 0;
    }
    let sum_sq: i64 = pcm.iter().map(|&s| (s as i64) * (s as i64)).sum();
    let rms = (sum_sq as f64 / pcm.len() as f64).sqrt();
    if rms < 1.0 {
        return 0;
    }
    // dBFS relative to i16 full scale, floored at -80 dB, mapped onto 0..=100.
    let dbfs = 20.0 * (rms / 32768.0).log10();
    let pct = (dbfs + 80.0) / 80.0 * 100.0;
    pct.clamp(0.0, 100.0) as u8
}

/// Encodes mono PCM frames to Opus packets.
pub struct AudioEncoder {
    inner: Encoder,
}

impl AudioEncoder {
    pub fn new() -> Result<Self, MediaError> {
        let inner = Encoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip)
            .map_err(|e| MediaError::Codec(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Encode exactly [`FRAME_SAMPLES`] mono samples into one Opus packet.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        let mut out = vec![0u8; MAX_PACKET_BYTES];
        let n = self
            .inner
            .encode(pcm, &mut out)
            .map_err(|e| MediaError::Codec(e.to_string()))?;
        out.truncate(n);
        Ok(out)
    }
}

/// Decodes Opus packets back to mono PCM frames.
pub struct AudioDecoder {
    inner: Decoder,
}

impl AudioDecoder {
    pub fn new() -> Result<Self, MediaError> {
        let inner = Decoder::new(SampleRate::Hz48000, Channels::Mono)
            .map_err(|e| MediaError::Codec(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Decode one Opus packet into up to [`FRAME_SAMPLES`] mono samples.
    pub fn decode(&mut self, packet: &[u8]) -> Result<Vec<i16>, MediaError> {
        let mut out = vec![0i16; FRAME_SAMPLES];
        let n = self
            .inner
            .decode(Some(packet), &mut out[..], false)
            .map_err(|e| MediaError::Codec(e.to_string()))?;
        out.truncate(n);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gain_boosts_and_saturates_without_wrapping() {
        let mut pcm = [100i16, -100, 0, 50];
        apply_gain(&mut pcm, 200);
        assert_eq!(pcm, [200, -200, 0, 100]);
        // A boost that would overflow i16 saturates instead of wrapping.
        let mut hot = [30_000i16, -30_000];
        apply_gain(&mut hot, 200);
        assert_eq!(hot, [i16::MAX, i16::MIN]);
        // Unity gain is an exact no-op.
        let mut same = [123i16, -456];
        apply_gain(&mut same, 100);
        assert_eq!(same, [123, -456]);
    }

    #[test]
    fn level_is_zero_for_silence_and_high_for_loud() {
        assert_eq!(frame_level_pct(&[]), 0);
        assert_eq!(frame_level_pct(&[0i16; 960]), 0);
        // Full-scale tone reads at the very top of the 0..=100 scale.
        assert!(frame_level_pct(&[i16::MAX; 960]) >= 99);
        // Louder input reads higher: a normal-speech level sits well above a
        // faint-noise level, and both are strictly between silence and full scale.
        let noise = frame_level_pct(&[80i16; 960]);
        let speech = frame_level_pct(&[3000i16; 960]);
        assert!(noise < speech);
        assert!((1..100).contains(&speech));
    }
}
