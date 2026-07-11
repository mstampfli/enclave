//! Phase 2 end-to-end: two clients exchange E2E text through a real WebSocket
//! relay, which forwards the ciphertext unchanged and never sees the plaintext.

mod common;

use common::{establish, recv_text, GROUP};
use enclave_protocol::{ClientMsg, Sealed};

#[tokio::test]
async fn two_clients_exchange_e2e_text_through_the_server() {
    let mut e = establish().await;

    let plaintext = b"the relay never sees this";
    let sealed = e.alice_group.encrypt_text(&e.alice, plaintext).expect("encrypt");
    e.alice_conn.send(ClientMsg::Text {
        group: GROUP,
        message: Sealed(sealed.clone()),
    });

    let relayed = recv_text(&mut e.bob_conn).await;

    // Forwarded byte-for-byte, and does not contain the plaintext.
    assert_eq!(relayed, sealed, "relay must forward ciphertext unchanged");
    assert!(
        !relayed.windows(plaintext.len()).any(|w| w == plaintext),
        "relayed bytes must not contain the plaintext"
    );

    let received = e.bob_group.decrypt_text(&e.bob, &relayed).expect("decrypt");
    assert_eq!(received.plaintext, plaintext);
    assert_eq!(received.sender, b"alice");
}
