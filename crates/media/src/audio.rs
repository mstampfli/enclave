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
