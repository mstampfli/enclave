//! Enclave server: signaling + relay, self-hosted.
//!
//! Authenticates connections, relays MLS handshake messages, forwards
//! E2E-sealed Welcomes, text, and media, and tracks presence. It cannot read
//! call content -- it holds no keys and does not even depend on `enclave-crypto`.
//!
//! Usage: `enclave-server [SIGNALING_ADDR] [MEDIA_ADDR]`
//! (defaults `127.0.0.1:8443` and `127.0.0.1:8444`). Set `ENCLAVE_TLS_CERT` and
//! `ENCLAVE_TLS_KEY` (PEM file paths) to serve signaling over TLS (wss).

use std::fs::File;
use std::io::BufReader;

use enclave_transport::Server;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key in file")
    })
}

fn die(context: &str, e: impl std::fmt::Display) -> ! {
    eprintln!("enclave-server: {context}: {e}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let signaling_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8443".to_string());
    let media_addr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8444".to_string());

    let server = Server::new();

    // Signaling: TLS when a cert + key are provided, plaintext otherwise.
    let tls = std::env::var("ENCLAVE_TLS_CERT")
        .ok()
        .zip(std::env::var("ENCLAVE_TLS_KEY").ok());
    let bound = match tls {
        Some((cert_path, key_path)) => {
            let certs = load_certs(&cert_path).unwrap_or_else(|e| die("loading cert", e));
            let key = load_key(&key_path).unwrap_or_else(|e| die("loading key", e));
            server
                .serve_signaling_tls(&signaling_addr, certs, key)
                .await
                .map(|addr| (addr, "wss/TLS"))
        }
        None => server
            .serve_signaling(&signaling_addr)
            .await
            .map(|addr| (addr, "ws")),
    };
    match bound {
        Ok((addr, scheme)) => println!("signaling on {addr} ({scheme})"),
        Err(e) => die("binding signaling", e),
    }

    match server.serve_media(&media_addr).await {
        Ok(addr) => println!("media (UDP) on {addr}"),
        Err(e) => die("binding media", e),
    }

    println!("relaying ciphertext; holds no keys. Stop with Ctrl-C.");
    std::future::pending::<()>().await;
}
