//! Phase 7 hardening (ASVS V9): signaling works over TLS. A self-signed server
//! and a client that trusts it exchange the protocol over `wss://`.

use std::sync::Arc;
use std::time::Duration;

use enclave_protocol::{ClientMsg, ServerMsg, UserId};
use enclave_transport::{Connection, Server};

#[tokio::test]
async fn signaling_works_over_tls() {
    // A self-signed certificate for "localhost".
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();

    let server = Server::new();
    let addr = server
        .serve_signaling_tls("127.0.0.1:0", vec![cert_der.clone()], key_der)
        .await
        .unwrap();

    // The client trusts exactly that self-signed certificate.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();

    let url = format!("wss://localhost:{}", addr.port());
    let mut conn = Connection::connect_tls(&url, config).await.unwrap();

    // A create-account + fetch round-trip proves the protocol rides the hop.
    conn.send(ClientMsg::CreateAccount {
        username: "a".into(),
        password: "a-long-enough-password".into(),
        identity_pub: vec![],
        key_package: vec![9, 9],
    });
    conn.send(ClientMsg::FetchKeyPackages {
        user: UserId("a".into()),
    });

    loop {
        match tokio::time::timeout(Duration::from_secs(5), conn.recv()).await {
            Ok(Some(ServerMsg::KeyPackages { packages, .. })) => {
                assert_eq!(packages, vec![vec![9, 9]]);
                return;
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("connection closed"),
            Err(_) => panic!("timed out over TLS"),
        }
    }
}
