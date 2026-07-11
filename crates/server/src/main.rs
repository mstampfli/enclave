//! Enclave server: signaling + relay, self-hosted.
//!
//! Authenticates connections, relays MLS handshake messages, forwards
//! E2E-sealed Welcomes and text, and (Phase 3) fans out sealed media frames.
//! What it can NOT do, by construction: read call content -- it holds no keys
//! and every content payload is an opaque `enclave_protocol::Sealed`.
//!
//! Usage: `enclave-server [BIND_ADDR]` (default `127.0.0.1:8443`).

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8443".to_string());

    match enclave_transport::serve(&addr).await {
        Ok(handle) => {
            println!(
                "enclave-server listening on {} (relays ciphertext; holds no keys)",
                handle.addr
            );
            // Serve until the process is killed.
            std::future::pending::<()>().await;
        }
        Err(e) => {
            eprintln!("enclave-server failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    }
}
