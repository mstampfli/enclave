//! Hardware check for Linux system-audio loopback: plays a tone through the
//! normal playback path (cpal -> PipeWire), captures it back through the
//! monitor/loopback backend, and verifies real samples with real energy came
//! through -- for all three cases:
//!
//!   1. `LoopbackMode::System` (default sink monitor) hears the tone.
//!   2. `LoopbackMode::Process(our pid)` (per-app capture) hears the tone.
//!   3. `LoopbackMode::Process(pid 1)` fails cleanly (init is not playing audio).
//!
//! Run: `cargo run -p enclave-media --example system_audio_probe`
//! (Audible: the tone plays on the default output for ~2s per case.)

#[cfg(target_os = "linux")]
fn main() {
    use enclave_media::{AudioPlayback, LoopbackMode, SystemAudioCapture};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    // A 440 Hz tone at a modest level, pushed continuously to the speaker.
    let playback = match AudioPlayback::start() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("could not open speaker: {e}");
            std::process::exit(1);
        }
    };
    let sink = playback.sink();
    let tone_alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let tone_flag = tone_alive.clone();
    let tone = std::thread::spawn(move || {
        let mut t = 0usize;
        while tone_flag.load(std::sync::atomic::Ordering::Relaxed) {
            let frame: Vec<i16> = (0..960)
                .map(|i| {
                    let phase = (t + i) as f32 * 440.0 / 48_000.0;
                    ((phase * std::f32::consts::TAU).sin() * 8000.0) as i16
                })
                .collect();
            t += 960;
            sink.push(&frame);
            std::thread::sleep(Duration::from_millis(18)); // ~real-time pacing
        }
    });
    // Let the playback stream actually start making noise.
    std::thread::sleep(Duration::from_millis(500));

    /// Capture for `secs` and report (samples, rms).
    fn measure(mode: LoopbackMode, secs: u64) -> Result<(usize, f64), String> {
        let mix: enclave_media::AudioMix = Arc::new(Mutex::new(VecDeque::new()));
        let cap = SystemAudioCapture::start(mode, mix.clone()).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut n = 0usize;
        let mut energy = 0f64;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            let mut ring = mix.lock().unwrap();
            for s in ring.drain(..) {
                n += 1;
                energy += (s as f64) * (s as f64);
            }
        }
        drop(cap);
        let rms = if n > 0 {
            (energy / n as f64).sqrt()
        } else {
            0.0
        };
        Ok((n, rms))
    }

    let mut failed = false;

    match measure(LoopbackMode::System, 2) {
        Ok((n, rms)) => {
            // 2s at 48 kHz mono is 96k samples; allow generous slack for startup.
            let ok = n > 48_000 && rms > 100.0;
            println!(
                "[{}] System mix: {} samples, rms {:.0}",
                if ok { "PASS" } else { "FAIL" },
                n,
                rms
            );
            failed |= !ok;
        }
        Err(e) => {
            println!("[FAIL] System mix: {e}");
            failed = true;
        }
    }

    match measure(LoopbackMode::Process(std::process::id()), 2) {
        Ok((n, rms)) => {
            let ok = n > 48_000 && rms > 100.0;
            println!(
                "[{}] Per-app (our tone, pid {}): {} samples, rms {:.0}",
                if ok { "PASS" } else { "FAIL" },
                std::process::id(),
                n,
                rms
            );
            failed |= !ok;
        }
        Err(e) => {
            println!("[FAIL] Per-app (our tone): {e}");
            failed = true;
        }
    }

    match measure(LoopbackMode::Process(1), 1) {
        Ok((n, _)) => {
            println!("[FAIL] Per-app (pid 1) unexpectedly captured {n} samples");
            failed = true;
        }
        Err(e) => println!("[PASS] Per-app (pid 1) failed cleanly: {e}"),
    }

    tone_alive.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = tone.join();
    std::process::exit(if failed { 1 } else { 0 });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this probe exercises the Linux PipeWire loopback backend only");
}
