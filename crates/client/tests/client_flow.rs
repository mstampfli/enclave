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
        .create_account(name, "", "test-password-1234")
        .await
        .expect("create account");
    client
}

#[tokio::test]
async fn friend_request_accept_and_presence() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let alice_handle = alice.name().to_string();
    let bob_handle = bob.name().to_string();

    // Alice requests Bob; Bob receives the request and accepts it.
    alice.send_friend_request(&bob_handle);
    loop {
        if let Event::FriendRequest { from } = next_event(&mut bob).await {
            assert_eq!(from, alice_handle);
            break;
        }
    }
    bob.accept_friend(&alice_handle);

    // Now friends, Alice is told Bob is online (friends watch each other).
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
    // Having drained the stream, Alice lists Bob as a friend.
    assert!(alice.friends().iter().any(|f| f.username == bob_handle));
}

#[tokio::test]
async fn two_clients_chat_through_the_controller() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let alice_handle = alice.name().to_string();
    let bob_handle = bob.name().to_string();

    // Alice creates a named group with Bob.
    alice
        .create_group("hangout", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();

    // Bob learns he joined (skipping login friend-list chatter), then focuses it.
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let gid = bob
        .conversations()
        .first()
        .map(|c| c.id.clone())
        .expect("bob has the group");
    bob.switch(&gid);

    // Both sides show the same safety number for the active conversation.
    assert!(alice.safety_number().is_some());
    assert_eq!(alice.safety_number(), bob.safety_number());

    // Alice sends text; Bob receives it decrypted, authenticated as Alice's handle.
    alice.send_text("hello bob").await.unwrap();
    loop {
        if let Event::Message { from, text, .. } = next_event(&mut bob).await {
            assert_eq!(from, alice_handle);
            assert_eq!(text, "hello bob");
            break;
        }
    }

    // And the reverse direction works too.
    bob.send_text("hi alice").await.unwrap();
    loop {
        if let Event::Message { from, text, .. } = next_event(&mut alice).await {
            assert_eq!(from, bob_handle);
            assert_eq!(text, "hi alice");
            break;
        }
    }
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    // Create the account and learn the assigned handle.
    let mut zara = Client::connect(&url).await.unwrap();
    zara.set_keystore_dir(std::env::temp_dir());
    zara.create_account("zara", "", "the-right-password")
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
