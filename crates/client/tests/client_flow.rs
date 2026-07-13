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
async fn conversations_and_history_survive_restart() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    let dir = std::env::temp_dir().join(format!("enclave-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    async fn account_in(url: &str, dir: &std::path::Path, name: &str) -> Client {
        let mut c = Client::connect(url).await.expect("connect");
        c.set_keystore_dir(dir);
        c.create_account(name, "", "test-password-1234")
            .await
            .expect("create");
        c
    }

    let mut alice = account_in(&url, &dir, "alice").await;
    let mut bob = account_in(&url, &dir, "bob").await;
    let alice_user = alice.name().to_string();
    let bob_user = bob.name().to_string();

    // Alice makes a group with Bob and sends a message.
    alice
        .create_group("plans", std::slice::from_ref(&bob_user))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let gid = alice.active_id().unwrap();
    // Confirm the safety number out of band before the restart. create_group
    // establishes the roster in one step, so the number will not change again.
    alice.switch(&gid);
    assert!(!alice.is_verified(), "a fresh group starts unverified");
    let verified_number = alice.safety_number().expect("group has a safety number");
    alice.mark_verified();
    assert!(alice.is_verified(), "verified after confirming");
    let bob_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_gid);
    alice.send_text("before restart").await.unwrap();
    loop {
        if let Event::Message { text, .. } = next_event(&mut bob).await {
            if text == "before restart" {
                break;
            }
        }
    }

    // Restart Alice: drop the client, then log back in on the same device.
    drop(alice);
    let mut alice2 = Client::connect(&url).await.unwrap();
    alice2.set_keystore_dir(&dir);
    alice2
        .login(&alice_user, "test-password-1234")
        .await
        .unwrap();

    // The conversation and its history are restored from the encrypted session.
    assert!(
        alice2.conversations().iter().any(|c| c.id == gid),
        "group restored after restart"
    );
    assert!(
        alice2
            .conversation_history(&gid)
            .iter()
            .any(|(_, t, mine)| t == "before restart" && *mine),
        "history restored after restart"
    );

    // The verification mark survives the restart, checked against the same
    // (unchanged) safety number.
    alice2.switch(&gid);
    assert_eq!(
        alice2.safety_number().as_deref(),
        Some(verified_number.as_str()),
        "same safety number after restart"
    );
    assert!(
        alice2.is_verified(),
        "the verification mark survived the restart"
    );

    // The MLS group is genuinely live: Alice can still send and Bob receives.
    alice2.switch(&gid);
    alice2.send_text("after restart").await.unwrap();
    loop {
        if let Event::Message { text, .. } = next_event(&mut bob).await {
            if text == "after restart" {
                break;
            }
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
