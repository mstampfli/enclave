//! H.264 video encoding (openh264) for screen share. Turns BGRA frames into
//! Annex-B encoded frames; the caller seals each encoded frame with the same
//! SFrame media crypto as audio ([`crate` uses `MediaKind::Screen`]), so video
//! is end-to-end encrypted and per-frame source-authenticated too.
//!
//! Decoding happens in the *viewer's* WebView via WebCodecs (GPU-accelerated),
//! so this crate only encodes: encoded H.264 frames are small (a few KB), which
//! is what makes streaming them to the UI cheap and high-fps.

use openh264::encoder::{BitRate, Encoder, EncoderConfig, FrameRate, FrameType};
use openh264::formats::{BgraSliceU8, YUVBuffer};
use openh264::OpenH264API;

use crate::MediaError;

/// A real-time H.264 encoder. Resolution is taken from each frame, so a change
/// in the shared surface size is handled without recreating the encoder.
pub struct H264Encoder {
    inner: Encoder,
}

impl H264Encoder {
    /// New encoder targeting `bitrate_bps` at `fps`.
    pub fn new(bitrate_bps: u32, fps: f32) -> Result<Self, MediaError> {
        let config = EncoderConfig::new()
            .bitrate(BitRate::from_bps(bitrate_bps))
            .max_frame_rate(FrameRate::from_hz(fps));
        let api = OpenH264API::from_source();
        let inner = Encoder::with_api_config(api, config)
            .map_err(|e| MediaError::Codec(format!("h264 encoder init: {e}")))?;
        Ok(Self { inner })
    }

    /// Encode one tightly packed BGRA frame (`width*height*4` bytes, no row
    /// padding). Returns the Annex-B bytes and whether the frame is a keyframe
    /// (IDR). `force_key` requests an IDR -- e.g. for a viewer who just joined
    /// and needs a fresh reference. Empty output means the encoder skipped it.
    pub fn encode(
        &mut self,
        bgra: &[u8],
        width: usize,
        height: usize,
        force_key: bool,
    ) -> Result<(Vec<u8>, bool), MediaError> {
        if !width.is_multiple_of(2) || !height.is_multiple_of(2) {
            return Err(MediaError::Codec("h264 dimensions must be even".into()));
        }
        if bgra.len() != width * height * 4 {
            return Err(MediaError::Codec("h264 frame size mismatch".into()));
        }
        if force_key {
            self.inner.force_intra_frame();
        }
        let src = BgraSliceU8::new(bgra, (width, height));
        let yuv = YUVBuffer::from_rgb_source(src);
        let bitstream = self
            .inner
            .encode(&yuv)
            .map_err(|e| MediaError::Codec(format!("h264 encode: {e}")))?;
        let is_key = matches!(bitstream.frame_type(), FrameType::IDR | FrameType::I);
        Ok((bitstream.to_vec(), is_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_bgra_and_forces_a_keyframe_in_annexb() {
        let mut enc = H264Encoder::new(2_000_000, 30.0).unwrap();
        let (w, h) = (320usize, 240usize);
        // A non-uniform frame so the encoder has something to compress.
        let mut frame = vec![0u8; w * h * 4];
        for (i, px) in frame.chunks_mut(4).enumerate() {
            px[0] = (i % 256) as u8; // B
            px[1] = ((i / 7) % 256) as u8; // G
            px[2] = ((i / 13) % 256) as u8; // R
            px[3] = 255; // A
        }
        let (bytes, key) = enc.encode(&frame, w, h, true).unwrap();
        assert!(!bytes.is_empty(), "encoder produced a frame");
        assert!(key, "a forced first frame is a keyframe");
        // Annex-B streams start with a 4-byte start code.
        assert_eq!(&bytes[0..4], &[0, 0, 0, 1], "Annex-B start code");
    }

    #[test]
    fn rejects_odd_dimensions_and_wrong_size() {
        let mut enc = H264Encoder::new(1_000_000, 30.0).unwrap();
        assert!(enc.encode(&[0u8; 4], 1, 1, false).is_err(), "odd dims");
        assert!(enc.encode(&[0u8; 8], 320, 240, false).is_err(), "short buf");
    }
}
