//! Hardware check for microphone capture: list input devices, open the
//! default mic, and verify 48 kHz frames actually flow for 2 seconds. RMS is
//! reported for information only -- a silent room is a valid mic.
//!
//! Run: `cargo run -p enclave-media --example mic_probe`

use enclave_media::{input_device_names, AudioCapture};
use std::time::{Duration, Instant};

fn main() {
    for name in input_device_names() {
        println!("input device: {name}");
    }

    let (_capture, frames) = match AudioCapture::start() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[FAIL] could not open microphone: {e}");
            std::process::exit(1);
        }
    };

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut samples = 0usize;
    let mut energy = 0f64;
    while Instant::now() < deadline {
        match frames.recv_timeout(Duration::from_millis(500)) {
            Ok(pcm) => {
                samples += pcm.len();
                energy += pcm.iter().map(|&s| (s as f64) * (s as f64)).sum::<f64>();
            }
            Err(_) => break,
        }
    }

    let rms = if samples > 0 {
        (energy / samples as f64).sqrt()
    } else {
        0.0
    };
    // 2 s at 48 kHz mono is 96k samples; allow generous startup slack.
    let ok = samples > 48_000;
    println!(
        "[{}] mic capture: {} samples in 2s, rms {:.0}",
        if ok { "PASS" } else { "FAIL" },
        samples,
        rms
    );
    std::process::exit(if ok { 0 } else { 1 });
}
