//! Hardware check for webcam capture: enumerate cameras, open the first one,
//! grab a few frames, and verify they are plausible BGRA (right size, not all
//! one value). Exercises the same nokhwa path the call's camera share uses.
//!
//! Run: `cargo run -p enclave-media --example camera_probe`

use enclave_media::{camera_sources, CameraCapture};

fn main() {
    let sources = camera_sources();
    if sources.is_empty() {
        eprintln!("[FAIL] no cameras found");
        std::process::exit(1);
    }
    for s in &sources {
        println!("camera {}: {}", s.index, s.name);
    }

    let mut cap = match CameraCapture::open(sources[0].index) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[FAIL] open camera {}: {e}", sources[0].index);
            std::process::exit(1);
        }
    };

    let mut ok = true;
    for i in 0..5 {
        match cap.next_bgra() {
            Ok((bgra, w, h)) => {
                let plausible = w > 0 && h > 0 && bgra.len() == w * h * 4;
                // A live sensor never yields a perfectly uniform frame.
                let uniform = bgra.chunks_exact(4).all(|px| px == &bgra[..4]);
                println!(
                    "frame {i}: {w}x{h}, {} bytes{}",
                    bgra.len(),
                    if uniform { " (uniform!)" } else { "" }
                );
                ok &= plausible && !uniform;
            }
            Err(e) => {
                println!("[FAIL] frame {i}: {e}");
                ok = false;
                break;
            }
        }
    }
    println!("[{}] camera capture", if ok { "PASS" } else { "FAIL" });
    std::process::exit(if ok { 0 } else { 1 });
}
