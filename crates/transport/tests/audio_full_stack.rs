//! Phase 3 capstone: the whole premise, end to end, over the real server.
//!
//! Alice speaks -> Opus encode -> seal -> relay -> Bob opens -> Opus decode ->
//! Bob hears clear voice. A wiretap on the relay sees only ciphertext that is
//! not the audio. This is the entire reason the project exists, in one test.

mod common;

use common::{establish, recv_media, GROUP};
use enclave_crypto::{MediaOpener, MediaSealer};
use enclave_media::audio::FRAME_SAMPLES;
use enclave_media::{AudioDecoder, AudioEncoder};
use enclave_protocol::{ClientMsg, DeviceId, MediaKind};

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

#[tokio::test]
async fn clear_voice_in_garbage_on_wire_clear_voice_out() {
    let mut e = establish().await;

    let root_alice = e.alice_group.media_root_secret(&e.alice).unwrap();
    let root_bob = e.bob_group.media_root_secret(&e.bob).unwrap();

    let mut sealer = MediaSealer::new(
        &root_alice,
        GROUP,
        DeviceId("alice".into()),
        &e.alice.identity_key(),
        1,
    )
    .unwrap();
    let mut opener = MediaOpener::new(&root_bob, &GROUP, &e.alice.identity_key(), 1).unwrap();
    let mut encoder = AudioEncoder::new().unwrap();
    let mut decoder = AudioDecoder::new().unwrap();

    // Alice: capture (synthetic tone) -> encode -> seal -> send.
    let pcm = tone(10);
    let mut opus_packets: Vec<Vec<u8>> = Vec::new();
    for frame in pcm.chunks(FRAME_SAMPLES) {
        let packet = encoder.encode(frame).unwrap();
        let sealed = sealer.seal(MediaKind::Audio, &packet).unwrap();
        e.alice_conn.send(ClientMsg::Media(sealed));
        opus_packets.push(packet);
    }

    // Bob: receive -> confirm the wire is garbage -> open -> decode.
    let mut decoded: Vec<i16> = Vec::new();
    for opus in &opus_packets {
        let relayed = recv_media(&mut e.bob_conn).await;

        // What a wiretap on the relay sees is NOT the Opus audio.
        assert_ne!(&relayed.payload.0, opus, "wire bytes must not be the audio");
        assert!(
            !relayed
                .payload
                .0
                .windows(opus.len())
                .any(|w| w == opus.as_slice()),
            "sealed frame must not contain the Opus packet"
        );

        let opened = opener.open(&relayed).unwrap();
        assert_eq!(&opened, opus, "far end recovers the exact Opus frame");
        decoded.extend_from_slice(&decoder.decode(&opened).unwrap());
    }

    // Through the addon, Bob hears clear voice -- a real tone, not silence.
    let recovered = rms(&decoded[FRAME_SAMPLES..]);
    assert!(
        recovered > 1_000.0,
        "recovered voice too quiet: rms={recovered}"
    );
}
