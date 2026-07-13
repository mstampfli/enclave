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
            .any(|(_, t, mine, _)| t == "before restart" && *mine),
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

/// A message larger than one sealed frame is split, sent as multiple sealed
/// parts, and reassembled by the peer byte-for-byte. And a file sent by one
/// client is written to the other's downloads directory with identical bytes.
#[tokio::test]
async fn large_message_and_file_transfer_between_two_clients() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let dir = std::env::temp_dir().join(format!("enclave-xfer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut alice = Client::connect(&url).await.unwrap();
    alice.set_keystore_dir(&dir);
    alice
        .create_account("xferalice", "", "test-password-1234")
        .await
        .unwrap();
    let mut bob = account(&url, "xferbob").await;
    let (an, bn) = (alice.name().to_string(), bob.name().to_string());

    alice.send_friend_request(&bn);
    loop {
        if let Event::FriendRequest { from } = next_event(&mut bob).await {
            assert_eq!(from, an);
            break;
        }
    }
    bob.accept_friend(&an);

    // Establish the DM (drive both sides until the group is live).
    let conv = alice.open_dm(&bn).await.unwrap();
    alice.switch(&conv);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while alice.safety_number().is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "DM never established"
        );
        tokio::select! {
            _ = tokio::time::timeout(Duration::from_millis(150), alice.next_event()) => {}
            _ = tokio::time::timeout(Duration::from_millis(150), bob.next_event()) => {}
        }
        alice.switch(&conv);
    }
    // Bob opens his side of the DM so incoming text routes to a live group.
    // Pump him until his join has landed and the conversation exists.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while bob.conversations().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Bob never joined the DM"
        );
        let _ = tokio::time::timeout(Duration::from_millis(150), bob.next_event()).await;
    }
    let bob_conv = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_conv);

    // 1) A ~1.3 MiB message: larger than one frame, so it is chunked.
    let big: String = "The quick brown fox. ".repeat(65_536); // ~1.35 MiB
    assert!(big.len() > 1024 * 1024, "message must exceed one frame");
    alice.send_text(&big).await.unwrap();
    let got = recv_message(&mut bob).await;
    assert_eq!(got, big, "the large message reassembled byte-for-byte");

    // 2) A file with binary content, including bytes that are not valid UTF-8.
    // It must be OFFERED, not auto-downloaded: Bob sees an offer, accepts, and
    // only then does the file stream to his disk.
    let file_bytes: Vec<u8> = (0..(1024 * 1024 + 777))
        .map(|i| (i * 7 % 256) as u8)
        .collect();
    let src = dir.join("payload.bin");
    std::fs::write(&src, &file_bytes).unwrap();
    alice
        .send_file(&src.to_string_lossy())
        .await
        .expect("offer file");

    // Pump both sides until Bob is OFFERED the file (never auto-downloaded).
    let offer_id = pump_until_offer(&mut alice, &mut bob).await;
    // Nothing should have been written to disk yet: consent gates the download.
    bob.accept_file(&offer_id).expect("accept");
    let saved_path = pump_until_file(&mut alice, &mut bob).await;
    let received = std::fs::read(&saved_path).expect("read received file");
    assert_eq!(received, file_bytes, "the file arrived byte-for-byte");
    assert!(
        saved_path.contains("enclave-downloads"),
        "received file lands in the downloads directory, got {saved_path}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Drive both clients until Bob receives a file offer; return its id. Driving
/// Alice lets her process `FileUploadReady`; pumping her lets the paced upload
/// stream (the event loop does this in the real app).
async fn pump_until_offer(alice: &mut Client, bob: &mut Client) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "no file offer arrived");
        alice.pump_uploads();
        tokio::select! {
            _ = tokio::time::timeout(Duration::from_millis(50), alice.next_event()) => {}
            e = tokio::time::timeout(Duration::from_millis(50), bob.next_event()) => {
                if let Ok(Some(Event::FileOffered { offer_id, .. })) = e {
                    return offer_id;
                }
            }
        }
    }
}

/// Drive both clients until Bob's accepted download completes; return the path.
async fn pump_until_file(alice: &mut Client, bob: &mut Client) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "no file arrived");
        alice.pump_uploads();
        tokio::select! {
            _ = tokio::time::timeout(Duration::from_millis(50), alice.next_event()) => {}
            e = tokio::time::timeout(Duration::from_millis(50), bob.next_event()) => {
                if let Ok(Some(Event::File { file, .. })) = e {
                    return file.path;
                }
            }
        }
    }
}

/// Pump events until a text message arrives; return its text.
async fn recv_message(c: &mut Client) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "no message arrived");
        if let Ok(Some(Event::Message { text, .. })) =
            tokio::time::timeout(Duration::from_millis(200), c.next_event()).await
        {
            return text;
        }
    }
}


#[tokio::test]
async fn a_reliable_message_survives_a_reconnect_exactly_once() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let dir = std::env::temp_dir().join(format!("enclave-reliable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut alice = Client::connect(&url).await.unwrap();
    alice.set_keystore_dir(&dir);
    alice
        .create_account("relalice", "", "test-password-1234")
        .await
        .unwrap();
    let mut bob = account(&url, "relbob").await;
    let (an, bn) = (alice.name().to_string(), bob.name().to_string());

    alice.send_friend_request(&bn);
    loop {
        if let Event::FriendRequest { from } = next_event(&mut bob).await {
            assert_eq!(from, an);
            break;
        }
    }
    bob.accept_friend(&an);

    let conv = alice.open_dm(&bn).await.unwrap();
    alice.switch(&conv);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while alice.safety_number().is_none() {
        assert!(tokio::time::Instant::now() < deadline, "DM never established");
        tokio::select! {
            _ = tokio::time::timeout(Duration::from_millis(150), alice.next_event()) => {}
            _ = tokio::time::timeout(Duration::from_millis(150), bob.next_event()) => {}
        }
        alice.switch(&conv);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while bob.conversations().is_empty() {
        assert!(tokio::time::Instant::now() < deadline, "Bob never joined the DM");
        let _ = tokio::time::timeout(Duration::from_millis(150), bob.next_event()).await;
    }
    let bc = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bc);

    // Alice sends a message, then immediately reconnects (as if the socket
    // dropped before she knew it was acked). The unacked message is replayed on
    // reconnect; Bob must see it exactly once -- dedup absorbs any duplicate.
    alice.send_text("survive the reconnect").await.unwrap();
    alice.reconnect().await.unwrap();

    let mut count = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            _ = tokio::time::timeout(Duration::from_millis(60), alice.next_event()) => {}
            e = tokio::time::timeout(Duration::from_millis(60), bob.next_event()) => {
                if let Ok(Some(Event::Message { text, .. })) = e {
                    if text == "survive the reconnect" {
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 1, "delivered exactly once despite the reconnect");
    let _ = std::fs::remove_dir_all(&dir);
}
