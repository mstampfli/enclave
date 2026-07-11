//! Phase 3 (codec): Opus encode/decode round-trips real audio and compresses.

use enclave_media::audio::FRAME_SAMPLES;
use enclave_media::{AudioDecoder, AudioEncoder};

/// A 440 Hz sine tone, `frames` frames long, as mono i16 at 48 kHz.
fn tone(frames: usize) -> Vec<i16> {
    let n = frames * FRAME_SAMPLES;
    (0..n)
        .map(|i| {
            let t = i as f64 / 48_000.0;
            ((2.0 * std::f64::consts::PI * 440.0 * t).sin() * 12_000.0) as i16
        })
        .collect()
}

fn rms(pcm: &[i16]) -> f64 {
    if pcm.is_empty() {
        return 0.0;
    }
    let sum: f64 = pcm.iter().map(|&s| (s as f64).powi(2)).sum();
    (sum / pcm.len() as f64).sqrt()
}

#[test]
fn opus_round_trips_a_tone_and_compresses() {
    let mut encoder = AudioEncoder::new().unwrap();
    let mut decoder = AudioDecoder::new().unwrap();

    let pcm = tone(10);
    let mut decoded = Vec::new();
    let mut packet_bytes = 0usize;

    for frame in pcm.chunks(FRAME_SAMPLES) {
        let packet = encoder.encode(frame).unwrap();
        assert!(!packet.is_empty(), "encoder produced an empty packet");
        packet_bytes += packet.len();

        let out = decoder.decode(&packet).unwrap();
        assert_eq!(out.len(), FRAME_SAMPLES);
        decoded.extend_from_slice(&out);
    }

    // Real compression: Opus is far smaller than raw 16-bit PCM.
    let raw_bytes = pcm.len() * 2;
    assert!(
        packet_bytes < raw_bytes / 2,
        "expected compression: {packet_bytes} encoded vs {raw_bytes} raw"
    );

    // Recovered audio is a real tone, not silence. Skip the first frame for
    // Opus priming/lookahead.
    let recovered = rms(&decoded[FRAME_SAMPLES..]);
    assert!(
        recovered > 1_000.0,
        "recovered audio too quiet: rms={recovered}"
    );
}
