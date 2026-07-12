//! The high-level client controller drives the whole flow -- create an account,
//! start a group, invite a peer, exchange E2E text, agree on the safety number,
//! and see presence -- without the UI (or this test) touching wire types or MLS.

use std::time::Duration;

use enclave_client::{Client, Event};
use enclave_transport::serve;

async fn next_event(client: &mut Client) -> Event {
    tokio::time::timeout(Duration::from_secs(5), client.next_event())
        .await
        .expect("timed out waiting for event")
        .expect("client disconnected")
}

/// Connect and create an account (identity files go to a temp dir).
async fn account(url: &str, name: &str) -> Client {
    let mut client = Client::connect(url).await.expect("connect");
    client.set_keystore_dir(std::env::temp_dir());
    client
        .create_account(name, "test-password-1234")
        .await
        .expect("create account");
    client
}

#[tokio::test]
async fn presence_events_reach_a_watcher() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    let mut alice = account(&url, "alice").await;
    let bob = account(&url, "bob").await;
    let bob_handle = bob.name().to_string();

    // Alice watches Bob (already online) -> she is told he is online.
    alice.add_friend(&bob_handle);
    loop {
        if let Event::Presence { user, status } = next_event(&mut alice).await {
            if user == bob_handle && status == "online" {
                break;
            }
        }
    }

    // Bob drops -> Alice is told he went offline.
    drop(bob);
    loop {
        if let Event::Presence { user, status } = next_event(&mut alice).await {
            if user == bob_handle && status == "offline" {
                break;
            }
        }
    }
}

#[tokio::test]
async fn two_clients_chat_through_the_controller() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let alice_handle = alice.name().to_string();
    let bob_handle = bob.name().to_string();

    // Alice starts a group and invites Bob by his handle.
    alice.start_group().unwrap();
    alice.invite(&bob_handle).await.unwrap();

    // Bob learns he joined.
    assert!(matches!(
        next_event(&mut bob).await,
        Event::MembershipChanged
    ));

    // Both sides show the same safety number.
    assert!(alice.safety_number().is_some());
    assert_eq!(alice.safety_number(), bob.safety_number());

    // Alice sends text; Bob receives it decrypted, authenticated as Alice's handle.
    alice.send_text("hello bob").await.unwrap();
    match next_event(&mut bob).await {
        Event::Text { from, text } => {
            assert_eq!(from, alice_handle);
            assert_eq!(text, "hello bob");
        }
        other => panic!("expected text, got {other:?}"),
    }

    // And the reverse direction works too.
    bob.send_text("hi alice").await.unwrap();
    match next_event(&mut alice).await {
        Event::Text { from, text } => {
            assert_eq!(from, bob_handle);
            assert_eq!(text, "hi alice");
        }
        other => panic!("expected text, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    // Create the account and learn the assigned handle.
    let mut zara = Client::connect(&url).await.unwrap();
    zara.set_keystore_dir(std::env::temp_dir());
    zara.create_account("zara", "the-right-password")
        .await
        .unwrap();
    let zara_handle = zara.name().to_string();

    // A second connection with the correct handle but wrong password is rejected
    // (this exercises the OPAQUE password check, not handle enumeration).
    let mut imposter = Client::connect(&url).await.unwrap();
    imposter.set_keystore_dir(std::env::temp_dir());
    assert!(imposter
        .login(&zara_handle, "the-wrong-password")
        .await
        .is_err());
    assert!(!imposter.is_logged_in());
}
