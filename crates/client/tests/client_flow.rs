//! Phase 6: the high-level client controller drives the whole flow -- connect,
//! start a group, invite a peer, exchange E2E text, and agree on the safety
//! number -- without the UI (or this test) touching wire types or MLS.

use std::time::Duration;

use enclave_client::{Client, Event};
use enclave_transport::serve;

async fn next_event(client: &mut Client) -> Event {
    tokio::time::timeout(Duration::from_secs(5), client.next_event())
        .await
        .expect("timed out waiting for event")
        .expect("client disconnected")
}

#[tokio::test]
async fn two_clients_chat_through_the_controller() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    let mut alice = Client::connect(&url, "alice").await.unwrap();
    let mut bob = Client::connect(&url, "bob").await.unwrap();

    // Alice starts a group and invites Bob.
    alice.start_group().unwrap();
    alice.invite("bob").await.unwrap();

    // Bob learns he joined.
    assert!(matches!(
        next_event(&mut bob).await,
        Event::MembershipChanged
    ));

    // Both sides show the same safety number.
    assert!(alice.safety_number().is_some());
    assert_eq!(alice.safety_number(), bob.safety_number());

    // Alice sends text; Bob receives it decrypted, authenticated as Alice.
    alice.send_text("hello bob").await.unwrap();
    match next_event(&mut bob).await {
        Event::Text { from, text } => {
            assert_eq!(from, "alice");
            assert_eq!(text, "hello bob");
        }
        other => panic!("expected text, got {other:?}"),
    }

    // And the reverse direction works too.
    bob.send_text("hi alice").await.unwrap();
    match next_event(&mut alice).await {
        Event::Text { from, text } => {
            assert_eq!(from, "bob");
            assert_eq!(text, "hi alice");
        }
        other => panic!("expected text, got {other:?}"),
    }
}
