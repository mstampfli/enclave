//! Local hardware check for the audio pipeline: capture from the default mic,
//! Opus-encode, decode, and play back to the default speaker. You should hear
//! yourself with a short delay. In the real app the encoded frame is sealed and
//! sent over the network between encode and decode; here we short-circuit it so
//! you can verify the capture/codec/playback path on your own hardware.
//!
//! Run: `cargo run -p enclave-media --example mic_loopback`
//! (Use headphones to avoid feedback.)

use enclave_media::{AudioCapture, AudioDecoder, AudioEncoder, AudioPlayback};

fn main() {
    let (_capture, frames) = match AudioCapture::start() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not open microphone: {e}");
            std::process::exit(1);
        }
    };
    let playback = match AudioPlayback::start() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("could not open speaker: {e}");
            std::process::exit(1);
        }
    };
    let mut encoder = AudioEncoder::new().expect("opus encoder");
    let mut decoder = AudioDecoder::new().expect("opus decoder");

    println!("Loopback running. Speak into your mic (use headphones). Ctrl-C to stop.");
    for frame in frames {
        match encoder
            .encode(&frame)
            .and_then(|packet| decoder.decode(&packet))
        {
            Ok(pcm) => playback.push(&pcm),
            Err(e) => eprintln!("codec error: {e}"),
        }
    }
}
