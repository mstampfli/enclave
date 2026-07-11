//! Enclave client.
//!
//! Wires the four libraries together: identity + MLS groups (`enclave-crypto`),
//! capture/encode (`enclave-media`), signaling + media transport
//! (`enclave-transport`), over the shared wire types (`enclave-protocol`), and
//! presents them through a self-contained WebView window (Phase 6, `wry`). No
//! browser is ever launched; the UI ships inside the app.

fn main() {
    println!(
        "enclave client: Phase 3. Ciphersuite {:?}, audio {} Hz / {}-sample frames.",
        enclave_crypto::CIPHERSUITE,
        enclave_media::audio::SAMPLE_RATE_HZ,
        enclave_media::audio::FRAME_SAMPLES,
    );
    println!("See ARCHITECTURE.md for the roadmap.");
}
