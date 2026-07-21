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

/// Drain a client's events until `pred` holds (or give up after a few seconds).
async fn pump_until<F: Fn(&Client) -> bool>(client: &mut Client, pred: F) {
    for _ in 0..200 {
        if pred(client) {
            return;
        }
        let _ = tokio::time::timeout(Duration::from_millis(50), client.next_event()).await;
    }
    assert!(pred(client), "condition never became true");
}

/// Pump two clients together until `pred` holds (or give up), so neither side's
/// op-queue or delivery stalls waiting on the other.
async fn pump2<F: Fn(&Client, &Client) -> bool>(a: &mut Client, b: &mut Client, pred: F) {
    for _ in 0..300 {
        if pred(a, b) {
            return;
        }
        let _ = tokio::time::timeout(Duration::from_millis(20), a.next_event()).await;
        let _ = tokio::time::timeout(Duration::from_millis(20), b.next_event()).await;
    }
    assert!(pred(a, b), "pump2 condition never became true");
}

/// Make `a` and `b` mutual friends (request + accept), pumping both to settle.
async fn become_friends(a: &mut Client, b: &mut Client) {
    let a_h = a.name().to_string();
    let b_h = b.name().to_string();
    a.send_friend_request(&b_h);
    pump_until(b, |c| {
        c.incoming_requests().iter().any(|f| f.username == a_h)
    })
    .await;
    b.accept_friend(&a_h);
    pump_until(a, |c| c.friends().iter().any(|f| f.username == b_h)).await;
    pump_until(b, |c| c.friends().iter().any(|f| f.username == a_h)).await;
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
    alice.send_text("hello bob", None).await.unwrap();
    loop {
        if let Event::Message { from, text, .. } = next_event(&mut bob).await {
            assert_eq!(from, alice_handle);
            assert_eq!(text, "hello bob");
            break;
        }
    }

    // And the reverse direction works too.
    bob.send_text("hi alice", None).await.unwrap();
    loop {
        if let Event::Message { from, text, .. } = next_event(&mut alice).await {
            assert_eq!(from, bob_handle);
            assert_eq!(text, "hi alice");
            break;
        }
    }
}

#[tokio::test]
async fn reply_and_delete_for_everyone_propagate() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_handle = bob.name().to_string();

    alice
        .create_group("hangout", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    bob.switch(&bob.conversations().first().unwrap().id.clone());

    // Alice sends a message; Bob receives it and learns its id.
    alice.send_text("the original", None).await.unwrap();
    let orig_id = loop {
        if let Event::Message { id, text, .. } = next_event(&mut bob).await {
            if text == "the original" {
                break id;
            }
        }
    };

    // Alice replies to it; Bob sees the reply carry the parent's id.
    alice.send_text("a reply", Some(&orig_id)).await.unwrap();
    loop {
        if let Event::Message { text, reply_to, .. } = next_event(&mut bob).await {
            if text == "a reply" {
                assert_eq!(reply_to, orig_id, "the reply references the original");
                break;
            }
        }
    }

    // Alice deletes the original for everyone; Bob's copy is tombstoned.
    alice.delete_message(&alice.active_id().unwrap(), &orig_id, true);
    loop {
        if let Event::MessageDeleted { id, .. } = next_event(&mut bob).await {
            assert_eq!(id, orig_id);
            break;
        }
    }
    // Bob's history keeps the line but marks it deleted (never removed).
    let gid = bob.conversations().first().unwrap().id.clone();
    let line = bob
        .conversation_history(&gid)
        .into_iter()
        .find(|l| l.id == orig_id)
        .expect("the line is still in history");
    assert!(line.deleted, "the original is marked deleted, not removed");
    assert!(line.text.is_empty(), "deleted content is cleared");
}

#[tokio::test]
async fn reactions_propagate_and_toggle_between_two_clients() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_handle = bob.name().to_string();
    let alice_user = alice.name().to_string();
    let bob_user = bob.name().to_string();

    alice
        .create_group("hangout", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let bob_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_gid);
    let alice_gid = alice.active_id().unwrap();

    // Alice sends a message; Bob receives it and learns its id.
    alice.send_text("react to me", None).await.unwrap();
    let mid = loop {
        if let Event::Message { id, text, .. } = next_event(&mut bob).await {
            if text == "react to me" {
                break id;
            }
        }
    };

    // Bob reacts with a thumbs-up; Alice is notified and her history shows it,
    // attributed to Bob (the authenticated sender), never a payload field.
    bob.react(&bob_gid, &mid, "\u{1F44D}");
    loop {
        if let Event::ReactionsChanged { id, reactions, .. } = next_event(&mut alice).await {
            if id == mid {
                assert_eq!(reactions.len(), 1);
                assert_eq!(reactions[0].emoji, "\u{1F44D}");
                assert_eq!(reactions[0].users, vec![bob_user.clone()]);
                break;
            }
        }
    }

    // Alice adds the SAME emoji: it now has two reactors.
    alice.react(&alice_gid, &mid, "\u{1F44D}");
    let line = alice
        .conversation_history(&alice_gid)
        .into_iter()
        .find(|l| l.id == mid)
        .unwrap();
    assert_eq!(line.reactions.len(), 1, "still one emoji");
    assert_eq!(line.reactions[0].users.len(), 2, "two reactors on it");
    // Bob learns of Alice's reaction too.
    loop {
        if let Event::ReactionsChanged { id, reactions, .. } = next_event(&mut bob).await {
            if id == mid && reactions.iter().any(|r| r.users.len() == 2) {
                break;
            }
        }
    }

    // Bob toggles his reaction OFF (reacting again removes it): only Alice remains.
    bob.react(&bob_gid, &mid, "\u{1F44D}");
    loop {
        if let Event::ReactionsChanged { id, reactions, .. } = next_event(&mut alice).await {
            if id == mid {
                assert_eq!(reactions.len(), 1);
                assert_eq!(
                    reactions[0].users,
                    vec![alice_user.clone()],
                    "only Alice's remains"
                );
                break;
            }
        }
    }
}

#[tokio::test]
async fn editing_a_message_propagates_and_only_the_author_can_edit() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_handle = bob.name().to_string();

    alice
        .create_group("hangout", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let bob_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_gid);
    let alice_gid = alice.active_id().unwrap();

    // Alice sends a message; Bob receives it and learns its id.
    alice.send_text("original", None).await.unwrap();
    let mid = loop {
        if let Event::Message { id, text, .. } = next_event(&mut bob).await {
            if text == "original" {
                break id;
            }
        }
    };

    // Bob cannot edit Alice's message (it is not his): refused locally, nothing sent.
    assert!(
        bob.edit_message(&bob_gid, &mid, "hacked").is_none(),
        "a member cannot edit another member's message"
    );

    // Alice edits her own message; Bob receives the edit and his copy updates.
    assert_eq!(
        alice
            .edit_message(&alice_gid, &mid, "edited text")
            .as_deref(),
        Some("edited text")
    );
    loop {
        if let Event::MessageEdited { id, text, .. } = next_event(&mut bob).await {
            if id == mid {
                assert_eq!(text, "edited text");
                break;
            }
        }
    }
    // Bob's history shows the new text, flagged edited; the line is not duplicated.
    let line = bob
        .conversation_history(&bob_gid)
        .into_iter()
        .find(|l| l.id == mid)
        .expect("the edited line is still there");
    assert_eq!(line.text, "edited text", "text was replaced in place");
    assert!(line.edited, "marked as edited");
    // Alice's own copy is edited and flagged too.
    let aline = alice
        .conversation_history(&alice_gid)
        .into_iter()
        .find(|l| l.id == mid)
        .unwrap();
    assert_eq!(aline.text, "edited text");
    assert!(aline.edited);
}

#[tokio::test]
async fn local_search_scopes_to_a_conversation_or_spans_all() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let _bob = account(&url, "bob").await; // the invitee (its key package is on the server)
    let bob_handle = _bob.name().to_string();

    // Two conversations, each with distinct messages, all recorded in Alice's
    // local history the moment she sends them.
    alice
        .create_group("recipes", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    let g1 = alice.active_id().unwrap();
    alice
        .send_text("apple pie is the best", None)
        .await
        .unwrap();
    alice.send_text("also cherry pie", None).await.unwrap();

    alice
        .create_group("plans", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    let g2 = alice.active_id().unwrap();
    alice.send_text("meet on tuesday", None).await.unwrap();

    // Global search: "pie" hits both recipe messages and nothing from the other.
    let hits = alice.search_messages("pie", None);
    assert_eq!(
        hits.len(),
        2,
        "both pie messages found across all conversations"
    );
    assert!(
        hits.iter().all(|h| h.conv == g1),
        "both are in the recipes group"
    );

    // Case-insensitive: "TUESDAY" finds the plans message.
    let hits = alice.search_messages("TUESDAY", None);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].conv, g2);

    // Scoped to g1: a g2 term finds nothing; a g1 term still finds both.
    assert!(alice.search_messages("tuesday", Some(&g1)).is_empty());
    assert_eq!(alice.search_messages("pie", Some(&g1)).len(), 2);

    // An empty query yields nothing.
    assert!(alice.search_messages("   ", None).is_empty());
}

#[tokio::test]
async fn polls_propagate_votes_tally_and_close() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_handle = bob.name().to_string();

    alice
        .create_group("team", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let bob_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_gid);
    let alice_gid = alice.active_id().unwrap();

    // Alice posts a single-choice poll (results always visible).
    let opts = vec!["Red".to_string(), "Green".to_string(), "Blue".to_string()];
    let (pid, _ts, view) = alice
        .create_poll("Favourite colour?", &opts, false, 0, 0, false)
        .unwrap();
    assert_eq!(view.options.len(), 3);
    assert!(view.is_author, "the creator may close it");
    assert_eq!(view.closes_at, 0, "no time limit");

    // Bob receives the poll.
    loop {
        if let Event::PollPosted { id, poll, .. } = next_event(&mut bob).await {
            if id == pid {
                assert_eq!(poll.question, "Favourite colour?");
                assert_eq!(poll.total, 0);
                break;
            }
        }
    }

    // Bob votes Green (index 1); Alice sees the tally update.
    bob.vote_poll(&bob_gid, &pid, vec![1]);
    loop {
        if let Event::PollUpdated { id, poll, .. } = next_event(&mut alice).await {
            if id == pid {
                assert_eq!(poll.counts, vec![0, 1, 0]);
                assert_eq!(poll.total, 1);
                break;
            }
        }
    }

    // Alice votes Green too; both see two votes on Green, and the voter
    // breakdown lists both of them under Green.
    let v = alice.vote_poll(&alice_gid, &pid, vec![1]).unwrap();
    assert_eq!(v.counts, vec![0, 2, 0]);
    assert_eq!(v.mine, vec![1]);
    assert_eq!(v.voters[1].len(), 2, "Green lists two voters");
    assert!(v.voters[0].is_empty() && v.voters[2].is_empty());
    loop {
        if let Event::PollUpdated { id, poll, .. } = next_event(&mut bob).await {
            if id == pid && poll.total == 2 {
                assert_eq!(poll.counts, vec![0, 2, 0]);
                break;
            }
        }
    }

    // Single-choice: Alice moves her vote to Blue; Green drops to 1, Blue is 1.
    let v = alice.vote_poll(&alice_gid, &pid, vec![2]).unwrap();
    assert_eq!(v.counts, vec![0, 1, 1], "the vote moved, it did not add");
    assert_eq!(v.mine, vec![2]);

    // Alice closes the poll; Bob is told, and can no longer vote.
    alice.close_poll(&alice_gid, &pid).unwrap();
    loop {
        if let Event::PollUpdated { id, poll, .. } = next_event(&mut bob).await {
            if id == pid && poll.closed {
                break;
            }
        }
    }
    assert!(
        bob.vote_poll(&bob_gid, &pid, vec![0]).is_none(),
        "a closed poll rejects votes"
    );
}

#[tokio::test]
async fn a_timed_poll_auto_closes_after_its_deadline() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let _bob = account(&url, "bob").await; // the invitee
    let bob_handle = _bob.name().to_string();
    alice
        .create_group("q", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    let gid = alice.active_id().unwrap();

    // A poll with a 60 ms limit. Before the deadline, voting works.
    let opts = vec!["A".to_string(), "B".to_string()];
    let (pid, _ts, view) = alice
        .create_poll("quick?", &opts, false, 0, 60, false)
        .unwrap();
    assert!(view.closes_at > 0, "the poll carries a deadline");
    assert!(
        alice.vote_poll(&gid, &pid, vec![0]).is_some(),
        "votes count before the deadline"
    );

    // After the deadline it auto-closes: votes are rejected and the view is closed.
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        alice.vote_poll(&gid, &pid, vec![1]).is_none(),
        "no votes after the deadline"
    );
    let line = alice
        .conversation_history(&gid)
        .into_iter()
        .find(|l| l.id == pid)
        .unwrap();
    assert!(
        line.poll.unwrap().closed,
        "the poll auto-closed once the deadline passed"
    );
}

#[tokio::test]
async fn a_buffered_poll_hides_votes_until_the_server_releases_them() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_handle = bob.name().to_string();

    alice
        .create_group("team", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let bob_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_gid);
    let alice_gid = alice.active_id().unwrap();

    // A server-buffered poll (reveal 2 = everyone, on close) that closes in 300 ms.
    // Creating it registers the poll with the server (BallotOpen).
    let opts = vec!["A".to_string(), "B".to_string()];
    let (pid, _ts, _v) = alice
        .create_poll("buffered?", &opts, false, 2, 300, false)
        .unwrap();
    loop {
        if let Event::PollPosted { id, .. } = next_event(&mut bob).await {
            if id == pid {
                break;
            }
        }
    }

    // Both vote; each ballot is a sealed BallotSubmit the server BUFFERS (not
    // relayed), so before release neither sees the other's vote.
    bob.vote_poll(&bob_gid, &pid, vec![1]);
    alice.vote_poll(&alice_gid, &pid, vec![0]);
    for _ in 0..8 {
        let _ = tokio::time::timeout(Duration::from_millis(20), alice.next_event()).await;
    }
    let before = alice
        .conversation_history(&alice_gid)
        .into_iter()
        .find(|l| l.id == pid)
        .unwrap()
        .poll
        .unwrap();
    assert_eq!(
        before.total, 1,
        "before release, only our own vote is visible"
    );
    assert!(!before.closed, "not closed before the deadline");

    // After the deadline the server sweep releases the ballots to the whole group,
    // with no one required to be online at close.
    let released = loop {
        if let Event::PollUpdated { id, poll, .. } = next_event(&mut alice).await {
            if id == pid && poll.closed {
                break poll;
            }
        }
    };
    assert_eq!(released.total, 2, "both votes appear at release");
    assert_eq!(released.counts, vec![1, 1], "one each");
}

#[tokio::test]
async fn an_anonymous_poll_tallies_without_attributing_votes() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let alice_user = alice.name().to_string();
    let bob_user = bob.name().to_string();

    alice
        .create_group("secret ballot", std::slice::from_ref(&bob_user))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let bob_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_gid);
    let alice_gid = alice.active_id().unwrap();

    // NOTE: no profile exchange and no waiting. The ring is built from the members'
    // Ed25519 identity keys in local MLS group state, so it exists the moment the
    // group does.

    // An anonymous, everyone-on-close poll (reveal 2 + anonymous) closing in 300ms.
    let opts = vec!["Yes".to_string(), "No".to_string()];
    let (pid, _ts, view) = alice
        .create_poll("Approve?", &opts, false, 2, 300, true)
        .unwrap();
    assert!(
        view.anonymous,
        "the ring assembled from both members' voting keys"
    );
    loop {
        if let Event::PollPosted { id, poll, .. } = next_event(&mut bob).await {
            if id == pid {
                assert!(poll.anonymous, "the peer sees it is anonymous");
                break;
            }
        }
    }

    // Both cast ring-signed ballots; the server buffers them and strips attribution.
    bob.vote_poll(&bob_gid, &pid, vec![0]);
    alice.vote_poll(&alice_gid, &pid, vec![1]);

    // At release the tally appears -- and no vote is attributable to a real member.
    let released = loop {
        if let Event::PollUpdated { id, poll, .. } = next_event(&mut alice).await {
            if id == pid && poll.closed {
                break poll;
            }
        }
    };
    assert_eq!(released.total, 2, "both anonymous ballots counted");
    assert_eq!(released.counts, vec![1, 1], "one Yes, one No");
    // No per-option voter breakdown is produced at all: not real names, and not
    // pseudonyms either, since listing which pseudonym picked what would still
    // show a voting pattern the poll promised not to reveal.
    let voters: Vec<String> = released.voters.iter().flatten().cloned().collect();
    assert!(
        voters.is_empty(),
        "an anonymous poll yields no voter breakdown, got {voters:?}"
    );
    assert!(
        !voters.iter().any(|v| v == &alice_user || v == &bob_user),
        "and certainly never a real username"
    );
}

/// Anonymity and audience are independent: an "only me, sealed until it closes"
/// poll can also be anonymous, so the creator learns the tally but still cannot
/// tell who cast which ballot, and non-owners learn nothing at all.
#[tokio::test]
async fn an_owner_only_poll_can_also_be_anonymous() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let alice_user = alice.name().to_string();
    let bob_user = bob.name().to_string();

    alice
        .create_group("sealed ballot", std::slice::from_ref(&bob_user))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let bob_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_gid);
    let alice_gid = alice.active_id().unwrap();

    // NOTE: no profile exchange and no waiting. The ring is built from the members'
    // Ed25519 identity keys in local MLS group state, so it exists the moment the
    // group does.

    // reveal 4 = only the creator, once it closes -- AND anonymous.
    let opts = vec!["Yes".to_string(), "No".to_string()];
    let (pid, _ts, view) = alice
        .create_poll("Approve?", &opts, false, 4, 300, true)
        .unwrap();
    assert!(view.anonymous, "owner-only polls can be anonymous too");

    loop {
        if let Event::PollPosted { id, poll, .. } = next_event(&mut bob).await {
            if id == pid {
                assert!(poll.anonymous, "the peer is told it is anonymous");
                break;
            }
        }
    }

    bob.vote_poll(&bob_gid, &pid, vec![0]);
    alice.vote_poll(&alice_gid, &pid, vec![1]);

    // The creator gets the tally when it closes, with no attribution.
    let released = loop {
        if let Event::PollUpdated { id, poll, .. } = next_event(&mut alice).await {
            if id == pid && poll.closed {
                break poll;
            }
        }
    };
    assert!(released.revealed, "the creator sees results once it closes");
    assert_eq!(released.total, 2, "both ballots reached the creator");
    assert_eq!(released.counts, vec![1, 1], "one Yes, one No");
    let voters: Vec<String> = released.voters.iter().flatten().cloned().collect();
    assert!(
        voters.is_empty(),
        "not even the creator gets a voter breakdown, got {voters:?}"
    );
    assert!(
        !voters.iter().any(|v| v == &alice_user || v == &bob_user),
        "and never a real username"
    );

    // Bob is not the owner: he learns it closed, but never the tally.
    for _ in 0..40 {
        let _ = tokio::time::timeout(Duration::from_millis(25), bob.next_event()).await;
    }
    let bobs = bob
        .conversation_history(&bob_gid)
        .into_iter()
        .find_map(|l| l.poll.filter(|_| l.id == pid))
        .expect("bob still sees the poll");
    assert!(
        !bobs.revealed,
        "a non-owner never has the results revealed to them"
    );
}

#[tokio::test]
async fn pinning_a_message_is_shared_across_members() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_handle = bob.name().to_string();

    alice
        .create_group("team", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let bob_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_gid);
    let alice_gid = alice.active_id().unwrap();

    alice.send_text("important", None).await.unwrap();
    let mid = loop {
        if let Event::Message { id, text, .. } = next_event(&mut bob).await {
            if text == "important" {
                break id;
            }
        }
    };

    // Alice pins it; Bob is told and his copy shows it pinned.
    assert_eq!(alice.pin_message(&alice_gid, &mid, true), Some(true));
    loop {
        if let Event::PinsChanged { id, pinned, .. } = next_event(&mut bob).await {
            if id == mid {
                assert!(pinned);
                break;
            }
        }
    }
    assert!(
        bob.conversation_history(&bob_gid)
            .into_iter()
            .find(|l| l.id == mid)
            .unwrap()
            .pinned,
        "pin is shared to the other member"
    );

    // Bob unpins it (pins are shared, so any member may); Alice sees it un-pin.
    assert_eq!(bob.pin_message(&bob_gid, &mid, false), Some(false));
    loop {
        if let Event::PinsChanged { id, pinned, .. } = next_event(&mut alice).await {
            if id == mid {
                assert!(!pinned);
                break;
            }
        }
    }
    assert!(
        !alice
            .conversation_history(&alice_gid)
            .into_iter()
            .find(|l| l.id == mid)
            .unwrap()
            .pinned,
        "the un-pin propagated back"
    );
}

#[tokio::test]
async fn disappearing_setting_propagates_and_expires() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_handle = bob.name().to_string();

    alice
        .create_group("hangout", std::slice::from_ref(&bob_handle))
        .await
        .unwrap();
    loop {
        if matches!(next_event(&mut bob).await, Event::ConversationsChanged) {
            break;
        }
    }
    let a_gid = alice.active_id().unwrap();
    let b_gid = bob.conversations().first().unwrap().id.clone();
    bob.switch(&b_gid);

    // Alice enables disappearing messages; Bob is told and adopts the same setting.
    alice.set_disappearing(&a_gid, 1); // 1 ms, so it expires immediately for the test
    loop {
        if let Event::DisappearingChanged { ms, .. } = next_event(&mut bob).await {
            assert_eq!(ms, 1, "the setting propagated to the peer");
            break;
        }
    }
    assert_eq!(bob.disappearing_of(&b_gid), 1, "bob adopted the setting");

    // Alice sends a message; both sides receive it, then the sweep removes it
    // (its ts is already older than the 1 ms window).
    alice.send_text("here then gone", None).await.unwrap();
    loop {
        if let Event::Message { text, .. } = next_event(&mut bob).await {
            if text == "here then gone" {
                break;
            }
        }
    }
    // A moment later the message is past its 1 ms lifetime on both devices.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let expired_a = alice.expire_messages();
    let expired_b = bob.expire_messages();
    assert!(
        expired_a.iter().any(|(_, ids)| !ids.is_empty()),
        "alice swept the message"
    );
    assert!(
        expired_b.iter().any(|(_, ids)| !ids.is_empty()),
        "bob swept the message"
    );
    assert!(
        !alice
            .conversation_history(&a_gid)
            .iter()
            .any(|l| l.text == "here then gone"),
        "the message is fully gone from alice's history (no placeholder)"
    );
    assert!(
        bob.conversation_history(&b_gid).is_empty()
            || !bob
                .conversation_history(&b_gid)
                .iter()
                .any(|l| l.text == "here then gone"),
        "the message is fully gone from bob's history"
    );
}

#[tokio::test]
async fn a_dm_does_not_wait_for_the_peer_to_be_online() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let alice = account(&url, "alice").await;
    let bob = account(&url, "bob").await;
    let alice_h = alice.name().to_string();
    let bob_h = bob.name().to_string();

    // The LARGER handle is the side that used to be stuck "waiting for the peer".
    // Have it open the DM while the peer has done nothing, and prove it works.
    let (mut opener, mut peer, peer_h) = if alice_h > bob_h {
        (alice, bob, bob_h)
    } else {
        (bob, alice, alice_h)
    };

    let conv = opener
        .open_dm(&peer_h)
        .await
        .expect("open_dm succeeds immediately");
    // It is established right away, not a pending placeholder.
    assert!(
        opener
            .conversations()
            .iter()
            .any(|c| c.id == conv && !c.pending),
        "the DM is established without waiting for the peer"
    );
    opener.switch(&conv);
    opener
        .send_text("hi, no waiting", None)
        .await
        .expect("can send at once");

    // The peer, coming online now, receives the queued Welcome, joins, and reads it.
    loop {
        if let Event::Message { text, .. } = next_event(&mut peer).await {
            if text == "hi, no waiting" {
                break;
            }
        }
    }
}

#[tokio::test]
async fn both_opening_a_dm_converge_on_one_group() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let alice_h = alice.name().to_string();
    let bob_h = bob.name().to_string();

    // Both open the DM at once, so both create a group for the same DM id.
    let ca = alice.open_dm(&bob_h).await.unwrap();
    let cb = bob.open_dm(&alice_h).await.unwrap();
    assert_eq!(ca, cb, "the DM id is deterministic for the pair");
    alice.switch(&ca);
    bob.switch(&cb);

    // Drain both until quiet so the two Welcomes cross and the tie-break (smaller
    // handle's group wins) resolves on both sides.
    async fn drain(c: &mut Client) {
        while tokio::time::timeout(Duration::from_millis(300), c.next_event())
            .await
            .is_ok()
        {}
    }
    drain(&mut alice).await;
    drain(&mut bob).await;

    // Converged: messages flow both ways (they would not if the two sides kept
    // different MLS groups).
    alice.send_text("from alice", None).await.unwrap();
    loop {
        if let Event::Message { text, .. } = next_event(&mut bob).await {
            if text == "from alice" {
                break;
            }
        }
    }
    bob.send_text("from bob", None).await.unwrap();
    loop {
        if let Event::Message { text, .. } = next_event(&mut alice).await {
            if text == "from bob" {
                break;
            }
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
    alice.send_text("before restart", None).await.unwrap();
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
            .any(|l| l.text == "before restart" && l.mine),
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
    alice2.send_text("after restart", None).await.unwrap();
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
    alice.send_text(&big, None).await.unwrap();
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
        assert!(
            tokio::time::Instant::now() < deadline,
            "no file offer arrived"
        );
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while bob.conversations().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Bob never joined the DM"
        );
        let _ = tokio::time::timeout(Duration::from_millis(150), bob.next_event()).await;
    }
    let bc = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bc);

    // Alice sends a message, then immediately reconnects (as if the socket
    // dropped before she knew it was acked). The unacked message is replayed on
    // reconnect; Bob must see it exactly once -- dedup absorbs any duplicate.
    alice
        .send_text("survive the reconnect", None)
        .await
        .unwrap();
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

/// Deleting a DM makes it disappear entirely (not to an Inactive list), but we
/// stay a member and keep the history + group, so reopening the same peer reuses
/// the group (no fork) and the scrollback is intact.
#[tokio::test]
async fn deleting_a_dm_retains_history_and_reopening_restores_it() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_h = bob.name().to_string();
    become_friends(&mut alice, &mut bob).await;

    let conv = alice.open_dm(&bob_h).await.expect("open dm");
    alice.switch(&conv);
    alice.send_text("keep me", None).await.unwrap();
    assert_eq!(alice.conversation_history(&conv).len(), 1);

    // Delete: disappears from the list entirely, history retained.
    alice.delete_conversation(&conv);
    assert!(
        !alice.conversations().iter().any(|c| c.id == conv),
        "a deleted conversation disappears from the list"
    );
    assert!(
        alice
            .conversation_history(&conv)
            .iter()
            .any(|l| l.text == "keep me"),
        "the sealed history is retained after delete"
    );

    // Re-open the same peer: same deterministic id, back to live, scrollback back.
    let conv2 = alice.open_dm(&bob_h).await.expect("reopen dm");
    assert_eq!(conv2, conv, "the DM id is deterministic for the pair");
    assert!(
        alice
            .conversations()
            .iter()
            .find(|c| c.id == conv2)
            .is_some_and(|c| !c.archived && !c.left),
        "the reopened conversation is back in the live Chats list"
    );
    assert!(
        alice
            .conversation_history(&conv2)
            .iter()
            .any(|l| l.text == "keep me"),
        "reopening restores the retained history"
    );
}

/// When a member leaves a group, the remaining members' roster (and member
/// count) drops the leaver: a designated remaining member commits the MLS
/// removal, since openmls forbids self-removal.
#[tokio::test]
async fn leaving_a_group_updates_the_member_count_for_others() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let mut carol = account(&url, "carol").await;
    let bob_h = bob.name().to_string();
    let carol_h = carol.name().to_string();

    alice
        .create_group("trio", &[bob_h.clone(), carol_h.clone()])
        .await
        .unwrap();
    let gid = alice.active_id().unwrap();
    // Everyone settles at 3 members.
    pump_until(&mut bob, |c| {
        c.conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| cc.members.len() == 3)
    })
    .await;
    pump_until(&mut carol, |c| {
        c.conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| cc.members.len() == 3)
    })
    .await;
    pump_until(&mut alice, |c| {
        c.conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| cc.members.len() == 3)
    })
    .await;

    // Carol leaves.
    carol.leave_group(&gid);

    // Alice and Bob converge to 2 members (the designated remover kicks Carol's leaf).
    async fn count_becomes_two(c: &mut Client, gid: &str) {
        pump_until(c, |cl| {
            cl.conversations()
                .iter()
                .find(|cc| cc.id == gid)
                .is_some_and(|cc| cc.members.len() == 2)
        })
        .await;
    }
    // Pump both concurrently-ish so whoever is the remover commits and both apply.
    for _ in 0..40 {
        let a_ok = alice
            .conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| cc.members.len() == 2);
        let b_ok = bob
            .conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| cc.members.len() == 2);
        if a_ok && b_ok {
            break;
        }
        let _ = tokio::time::timeout(Duration::from_millis(50), alice.next_event()).await;
        let _ = tokio::time::timeout(Duration::from_millis(50), bob.next_event()).await;
    }
    count_becomes_two(&mut alice, &gid).await;
    count_becomes_two(&mut bob, &gid).await;
}

/// Deleting a DM then reopening it must NOT fork the MLS group: because delete
/// keeps membership, reopening reuses the same group, so messages still flow both
/// ways. (Regression guard for the "can't message after remove/re-add" bug.)
#[tokio::test]
async fn deleting_and_reopening_a_dm_does_not_break_messaging() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_h = bob.name().to_string();
    become_friends(&mut alice, &mut bob).await;

    let conv = alice.open_dm(&bob_h).await.unwrap();
    alice.switch(&conv);
    alice.send_text("first", None).await.unwrap();
    pump_until(&mut bob, |c| {
        !c.conversations().is_empty() && c.conversations().iter().any(|cc| !cc.pending)
    })
    .await;
    let bob_conv = bob.conversations().first().unwrap().id.clone();
    bob.switch(&bob_conv);
    pump_until(&mut bob, |c| {
        c.conversation_history(&bob_conv)
            .iter()
            .any(|l| l.text == "first")
    })
    .await;

    // Alice deletes and reopens the DM.
    alice.delete_conversation(&conv);
    let conv2 = alice.open_dm(&bob_h).await.unwrap();
    assert_eq!(conv2, conv);
    alice.switch(&conv2);

    // Messaging still works both ways (no fork).
    alice.send_text("after reopen", None).await.unwrap();
    pump_until(&mut bob, |c| {
        c.conversation_history(&bob_conv)
            .iter()
            .any(|l| l.text == "after reopen")
    })
    .await;
    bob.send_text("got it", None).await.unwrap();
    pump_until(&mut alice, |c| {
        c.conversation_history(&conv2)
            .iter()
            .any(|l| l.text == "got it")
    })
    .await;
}

/// Archiving hides a conversation to the Archived page without any data change;
/// opening it again returns it to the live list with history intact.
#[tokio::test]
async fn archiving_hides_a_conversation_and_reopening_returns_it() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_h = bob.name().to_string();
    become_friends(&mut alice, &mut bob).await;

    let conv = alice.open_dm(&bob_h).await.expect("open dm");
    alice.switch(&conv);
    alice.send_text("still here", None).await.unwrap();

    alice.archive_conversation(&conv);
    assert!(
        alice
            .conversations()
            .iter()
            .find(|c| c.id == conv)
            .is_some_and(|c| c.archived),
        "an archived conversation moves to the Archived page"
    );
    assert!(
        alice
            .conversation_history(&conv)
            .iter()
            .any(|l| l.text == "still here"),
        "history is untouched while archived"
    );

    // Opening it again un-archives it.
    let conv2 = alice.open_dm(&bob_h).await.expect("reopen dm");
    assert_eq!(conv2, conv);
    assert!(
        alice
            .conversations()
            .iter()
            .find(|c| c.id == conv2)
            .is_some_and(|c| !c.archived && !c.left),
        "reopening returns the conversation to the live Chats list"
    );
    assert!(
        alice
            .conversation_history(&conv2)
            .iter()
            .any(|l| l.text == "still here"),
        "history is preserved across an archive round-trip"
    );
}

/// Deleting an ARCHIVED conversation removes it (it disappears), not a no-op.
#[tokio::test]
async fn deleting_an_archived_conversation_removes_it() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_h = bob.name().to_string();
    become_friends(&mut alice, &mut bob).await;

    let conv = alice.open_dm(&bob_h).await.unwrap();
    alice.switch(&conv);
    alice.send_text("hi", None).await.unwrap();
    alice.archive_conversation(&conv);
    assert!(
        alice
            .conversations()
            .iter()
            .find(|c| c.id == conv)
            .is_some_and(|c| c.archived),
        "archived first"
    );
    // Delete while archived.
    alice.delete_conversation(&conv);
    assert!(
        !alice.conversations().iter().any(|c| c.id == conv),
        "deleting an archived conversation makes it disappear"
    );
}

/// Clearing wipes a conversation's messages but keeps the conversation and its
/// channel, so it stays in the list and can still be used.
#[tokio::test]
async fn clearing_wipes_history_but_keeps_the_conversation() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_h = bob.name().to_string();
    become_friends(&mut alice, &mut bob).await;

    let conv = alice.open_dm(&bob_h).await.expect("open dm");
    alice.switch(&conv);
    alice.send_text("one", None).await.unwrap();
    alice.send_text("two", None).await.unwrap();
    assert_eq!(alice.conversation_history(&conv).len(), 2);

    alice.clear_history(&conv);
    assert!(
        alice
            .conversations()
            .iter()
            .find(|c| c.id == conv)
            .is_some_and(|c| !c.archived && !c.left),
        "the conversation itself survives a clear and stays live"
    );
    assert!(
        alice.conversation_history(&conv).is_empty(),
        "clearing removes every message"
    );

    // Still usable afterward.
    alice.switch(&conv);
    alice.send_text("after clear", None).await.unwrap();
    assert_eq!(alice.conversation_history(&conv).len(), 1);
}

/// A deleted DM (group left, history retained) must survive an app restart: the
/// retained record persists with no MLS group, stays hidden from the list, and
/// reopening the same peer restores its scrollback.
#[tokio::test]
async fn a_deleted_dm_survives_restart_and_restores_on_reopen() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let dir = std::env::temp_dir().join(format!("enclave-deldm-{}", std::process::id()));
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
    let bob_h = bob.name().to_string();
    become_friends(&mut alice, &mut bob).await;

    let conv = alice.open_dm(&bob_h).await.unwrap();
    alice.switch(&conv);
    alice.send_text("remember this", None).await.unwrap();
    alice.delete_conversation(&conv); // disappears, keeps membership + history
    assert!(
        !alice.conversations().iter().any(|c| c.id == conv),
        "a deleted conversation disappears"
    );

    // Restart Alice on the same device.
    drop(alice);
    let mut alice2 = Client::connect(&url).await.unwrap();
    alice2.set_keystore_dir(&dir);
    alice2
        .login(&alice_user, "test-password-1234")
        .await
        .unwrap();

    assert!(
        !alice2.conversations().iter().any(|c| c.id == conv),
        "a deleted conversation stays hidden across a restart"
    );
    assert!(
        alice2
            .conversation_history(&conv)
            .iter()
            .any(|l| l.text == "remember this"),
        "the deleted conversation's history survived the restart"
    );

    // The friendship is restored from the server, so the reopened DM is live.
    pump_until(&mut alice2, |c| {
        c.friends().iter().any(|f| f.username == bob_h)
    })
    .await;

    // Reopening the same peer brings it back live with the scrollback.
    let conv2 = alice2.open_dm(&bob_h).await.unwrap();
    assert_eq!(conv2, conv);
    assert!(
        alice2
            .conversations()
            .iter()
            .find(|c| c.id == conv2)
            .is_some_and(|c| !c.archived && !c.left),
        "reopening after a restart returns it to the live list"
    );
    assert!(
        alice2
            .conversation_history(&conv2)
            .iter()
            .any(|l| l.text == "remember this"),
        "history restored after restart + reopen"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// When a friend removes us, the DM stays (readable) and they become a "past
/// contact". If they later re-add us, we reconnect automatically (the counter-add
/// case) without a prompt, and the conversation is sendable again.
#[tokio::test]
async fn a_removed_friend_becomes_a_past_contact_and_readd_auto_reconnects() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let alice_h = alice.name().to_string();
    let bob_h = bob.name().to_string();

    // Become friends.
    alice.send_friend_request(&bob_h);
    pump_until(&mut bob, |c| {
        c.incoming_requests().iter().any(|f| f.username == alice_h)
    })
    .await;
    bob.accept_friend(&alice_h);
    pump_until(&mut alice, |c| {
        c.friends().iter().any(|f| f.username == bob_h)
    })
    .await;

    // Open the DM and leave some history.
    let conv = alice.open_dm(&bob_h).await.unwrap();
    alice.switch(&conv);
    alice.send_text("hey bob", None).await.unwrap();

    // Bob removes Alice.
    bob.remove_friend(&alice_h);
    pump_until(&mut alice, |c| {
        !c.friends().iter().any(|f| f.username == bob_h)
    })
    .await;

    // The DM persists, Bob is a past contact, and the DM is now read-only.
    assert!(
        alice.conversations().iter().any(|cc| cc.id == conv),
        "the DM stays in the list after being removed"
    );
    assert!(
        alice.past_contacts().iter().any(|f| f.username == bob_h),
        "the ex-friend becomes a past contact"
    );
    assert!(
        alice
            .conversations()
            .iter()
            .find(|cc| cc.id == conv)
            .is_some_and(|cc| cc.reconnect && cc.can_send && !cc.archived && !cc.left),
        "the DM stays live and sendable (texting re-adds) but flags reconnect"
    );
    // The history is still readable.
    assert!(
        alice
            .conversation_history(&conv)
            .iter()
            .any(|l| l.text == "hey bob"),
        "history is still readable after being removed"
    );

    // Bob re-adds Alice: she auto-accepts (counter-add) and they are friends again.
    bob.send_friend_request(&alice_h);
    pump_until(&mut alice, |c| {
        c.friends().iter().any(|f| f.username == bob_h)
    })
    .await;
    assert!(
        alice.past_contacts().is_empty(),
        "reconnecting clears the past-contact status"
    );
    assert!(
        alice
            .conversations()
            .iter()
            .find(|cc| cc.id == conv)
            .is_some_and(|cc| cc.can_send && !cc.reconnect),
        "the DM is sendable and connected again after reconnect"
    );
}

/// Being removed from a group makes it read-only (moves to Inactive) but keeps
/// its history readable, rather than leaving a broken "live" conversation.
#[tokio::test]
async fn being_removed_from_a_group_makes_it_read_only_but_readable() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_h = bob.name().to_string();

    alice
        .create_group("crew", std::slice::from_ref(&bob_h))
        .await
        .unwrap();
    let gid = alice.active_id().unwrap();

    // Bob joins the group and receives a message, so he has history.
    pump_until(&mut bob, |c| {
        c.conversations().iter().any(|cc| cc.id == gid)
    })
    .await;
    alice.switch(&gid);
    alice.send_text("welcome to the crew", None).await.unwrap();
    pump_until(&mut bob, |c| {
        c.conversation_history(&gid)
            .iter()
            .any(|l| l.text == "welcome to the crew")
    })
    .await;

    // Alice removes Bob.
    alice.remove_member(&gid, &bob_h).unwrap();

    // Bob applies the remove commit, detects he is out, and the group becomes
    // Left (read-only) while its history stays readable.
    pump_until(&mut bob, |c| {
        c.conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| cc.left)
    })
    .await;
    assert!(
        bob.conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| !cc.can_send),
        "the removed group is read-only for bob"
    );
    assert!(
        bob.conversation_history(&gid)
            .iter()
            .any(|l| l.text == "welcome to the crew"),
        "bob can still read the group's history after being removed"
    );
}

/// Rejoining a group you were removed from (a fresh Welcome for the same group)
/// restores it: it goes live again and its retained history reappears.
#[tokio::test]
async fn rejoining_a_group_after_removal_restores_its_history() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let bob_h = bob.name().to_string();

    alice
        .create_group("crew", std::slice::from_ref(&bob_h))
        .await
        .unwrap();
    let gid = alice.active_id().unwrap();
    pump_until(&mut bob, |c| {
        c.conversations().iter().any(|cc| cc.id == gid)
    })
    .await;
    alice.switch(&gid);
    alice.send_text("original crew chat", None).await.unwrap();
    pump_until(&mut bob, |c| {
        c.conversation_history(&gid)
            .iter()
            .any(|l| l.text == "original crew chat")
    })
    .await;

    // Alice removes Bob; Bob's group goes read-only.
    alice.remove_member(&gid, &bob_h).unwrap();
    pump_until(&mut bob, |c| {
        c.conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| cc.left)
    })
    .await;

    // Alice re-invites Bob. His fresh Welcome restores the group to live, with the
    // old history intact.
    alice.switch(&gid);
    alice.add_to_active_group(&bob_h).await.unwrap();
    pump_until(&mut bob, |c| {
        c.conversations()
            .iter()
            .find(|cc| cc.id == gid)
            .is_some_and(|cc| !cc.left && !cc.archived)
    })
    .await;
    assert!(
        bob.conversation_history(&gid)
            .iter()
            .any(|l| l.text == "original crew chat"),
        "the group's history is restored after rejoining"
    );
}

/// The mirror of the above: when WE remove someone, they are NOT a past contact,
/// so a re-add from them arrives as an ordinary request to accept, not a silent
/// auto-reconnect. (Their DM still stays readable in the Inactive section.)
#[tokio::test]
async fn removing_someone_ourselves_does_not_auto_reconnect_on_their_readd() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    let alice_h = alice.name().to_string();
    let bob_h = bob.name().to_string();

    alice.send_friend_request(&bob_h);
    pump_until(&mut bob, |c| {
        c.incoming_requests().iter().any(|f| f.username == alice_h)
    })
    .await;
    bob.accept_friend(&alice_h);
    pump_until(&mut alice, |c| {
        c.friends().iter().any(|f| f.username == bob_h)
    })
    .await;

    let conv = alice.open_dm(&bob_h).await.unwrap();
    alice.switch(&conv);
    alice.send_text("hi", None).await.unwrap();

    // ALICE removes Bob (she initiated).
    alice.remove_friend(&bob_h);
    pump_until(&mut alice, |c| {
        !c.friends().iter().any(|f| f.username == bob_h)
    })
    .await;
    assert!(
        alice.past_contacts().is_empty(),
        "someone we removed is not a past contact"
    );

    // Bob re-adds Alice: it must surface as a normal request, not auto-accept.
    bob.send_friend_request(&alice_h);
    let mut saw_request = false;
    for _ in 0..40 {
        match tokio::time::timeout(Duration::from_millis(50), alice.next_event()).await {
            Ok(Some(Event::FriendRequest { from })) if from == bob_h => {
                saw_request = true;
                break;
            }
            _ => {}
        }
    }
    assert!(
        saw_request,
        "bob's re-add surfaced as a request to decide on"
    );
    assert!(
        !alice.friends().iter().any(|f| f.username == bob_h),
        "we are NOT auto-reconnected to someone we removed"
    );
}

/// "Notes to self" is a private, on-device scratchpad: everything typed into it
/// stays local (an online friend never hears a whisper of it) and survives a
/// restart via the encrypted session, with no MLS group or routing reconstructed.
#[tokio::test]
async fn notes_to_self_stay_local_and_survive_restart() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);

    let dir = std::env::temp_dir().join(format!("enclave-notes-it-{}", std::process::id()));
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
    // Bob is an online friend: the strongest observable check is that he still
    // never receives anything from Alice's private notes.
    become_friends(&mut alice, &mut bob).await;

    // Alice writes two notes to herself.
    let notes = alice.open_self_notes().unwrap();
    assert!(
        alice
            .conversations()
            .iter()
            .any(|c| c.id == notes && c.self_notes),
        "the notes conversation exists and is flagged local-only"
    );
    alice.send_text("remember the milk", None).await.unwrap();
    alice.send_text("and the eggs", None).await.unwrap();
    assert_eq!(
        alice.conversation_history(&notes).len(),
        2,
        "both notes recorded in local history"
    );

    // Nothing was relayed: pump Bob's stream; he gains no conversation and hears
    // no message. A local-only note never reaches the server, let alone a peer.
    for _ in 0..40 {
        let _ = tokio::time::timeout(Duration::from_millis(25), bob.next_event()).await;
    }
    assert!(
        bob.conversations().is_empty(),
        "the peer received nothing -- the notes never left the device"
    );

    // Restart Alice: the notes are restored from the encrypted local session.
    drop(alice);
    let mut alice2 = Client::connect(&url).await.unwrap();
    alice2.set_keystore_dir(&dir);
    alice2
        .login(&alice_user, "test-password-1234")
        .await
        .unwrap();

    let restored = alice2
        .conversations()
        .into_iter()
        .find(|c| c.id == notes)
        .expect("notes restored after restart");
    assert!(restored.self_notes, "still local-only after reload");
    let hist = alice2.conversation_history(&notes);
    assert_eq!(hist.len(), 2, "both notes survived the restart");
    assert_eq!(hist[0].text, "remember the milk");
    assert_eq!(hist[1].text, "and the eggs");

    // And it is still local after the restart: a further note reaches no peer.
    alice2.switch(&notes);
    alice2.send_text("third note", None).await.unwrap();
    for _ in 0..40 {
        let _ = tokio::time::timeout(Duration::from_millis(25), bob.next_event()).await;
    }
    assert!(
        bob.conversations().is_empty(),
        "still nothing relayed after the restart"
    );
    assert_eq!(alice2.conversation_history(&notes).len(), 3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The requirement that matters most here: an anonymous poll must work the
/// instant a conversation exists. No profile exchange, no key publication, no
/// waiting, and nobody on the other end ever having to be reachable. The ring is
/// every member's Ed25519 identity key, which arrives with membership itself and
/// is already what the safety number verifies.
#[tokio::test]
async fn an_anonymous_poll_works_immediately_with_nobody_reachable() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let bob = account(&url, "bob").await;
    let bob_user = bob.name().to_string();

    alice
        .create_group("instant", std::slice::from_ref(&bob_user))
        .await
        .unwrap();

    // Straight to an anonymous poll: nothing pumped, nothing exchanged, and Bob
    // has done nothing at all. Under the previous design the ring came from
    // broadcast profiles, so this could not be created until Bob had connected.
    let opts = vec!["Yes".to_string(), "No".to_string()];
    let (_pid, _ts, view) = alice
        .create_poll("Approve?", &opts, false, 2, 0, true)
        .expect("an anonymous poll is creatable the moment the group exists");
    assert!(
        view.anonymous,
        "and it is genuinely anonymous, not silently downgraded"
    );
}

/// Closing the open chat must stay closed. Becoming friends -- accepting a
/// request, or having one auto-accepted -- refreshes the conversation list,
/// which used to re-broadcast a stale active conversation and pull the UI back
/// into the chat you had just left. Deselecting in the core keeps it closed.
#[tokio::test]
async fn a_closed_chat_is_not_reopened_by_a_friend_change() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut alice = account(&url, "alice").await;
    let mut bob = account(&url, "bob").await;
    become_friends(&mut alice, &mut bob).await;
    let bob_h = bob.name().to_string();

    // Alice opens the DM: the core now has an active conversation.
    alice.open_dm(&bob_h).await.unwrap();
    assert!(alice.active_id().is_some(), "the DM is active while open");

    // Alice presses the home button; the core deselects.
    alice.deselect();
    assert!(
        alice.active_id().is_none(),
        "closing the chat clears the active conversation"
    );

    // A third person becomes Alice's friend. The acceptance fires the same
    // conversation-list refresh that used to re-open the closed chat.
    let mut carol = account(&url, "carol").await;
    become_friends(&mut alice, &mut carol).await;

    assert!(
        alice.active_id().is_none(),
        "accepting a friend must not re-open the chat Alice closed"
    );
}

/// M0 end to end: an owner creates a workspace and adds a member; both clients
/// converge on the same op-log state -- owner as Owner, the added member as
/// Member -- driven entirely by the signed, server-relayed op-log. Proves the
/// crypto op-log, the protocol messages, the relay store, and the client
/// plumbing all agree.
#[tokio::test]
async fn a_workspace_is_created_and_a_member_is_added_end_to_end() {
    use enclave_protocol::{Role, WorkspaceOp};

    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut bob = account(&url, "bob").await;
    let owner_h = owner.name().to_string();
    let bob_h = bob.name().to_string();
    let bob_key = bob.identity_key().unwrap();

    // Owner creates the workspace; state arrives on the server echo.
    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;
    assert_eq!(
        owner.workspace(&ws).unwrap().role_of(&owner_h),
        Some(Role::Owner)
    );

    // Owner adds Bob (needs Bob's identity key, as a real invite flow would carry).
    owner
        .workspace_submit(
            &ws,
            WorkspaceOp::AddMember {
                member: bob_h.clone(),
                member_key: bob_key,
            },
        )
        .unwrap();

    // Both converge: owner sees two members; Bob learns the workspace (via the
    // broadcast -> gap -> full-log fetch) and sees himself as a Member.
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    pump_until(&mut bob, |c| {
        c.workspace(&ws)
            .is_some_and(|s| s.role_of(&bob_h) == Some(Role::Member))
    })
    .await;

    let owner_view = owner.workspace(&ws).unwrap();
    let bob_view = bob.workspace(&ws).unwrap();
    assert_eq!(owner_view.name, "Team");
    assert_eq!(bob_view.name, "Team");
    assert_eq!(owner_view.role_of(&owner_h), Some(Role::Owner));
    assert_eq!(bob_view.role_of(&owner_h), Some(Role::Owner));
    assert_eq!(bob_view.role_of(&bob_h), Some(Role::Member));
    // Same chain head -> identical, verified history on both sides.
    assert_eq!(owner_view.head_hash(), bob_view.head_hash());
}

/// End to end: an owner mints an invite code, a stranger redeems it, and the
/// owner's client (as the online admin) admits them via the normal signed add,
/// so the redeemer ends up a real member without the owner ever typing their
/// username. Proves the create -> redeem -> route-to-admin -> admit path.
#[tokio::test]
async fn an_invite_code_admits_a_redeemer() {
    use enclave_protocol::Role;

    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut carol = account(&url, "carol").await;
    let carol_h = carol.name().to_string();

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;

    // Owner mints an invite; capture the code off the event.
    owner.create_invite(&ws, 0, 0);
    let mut code = String::new();
    for _ in 0..100 {
        if let Ok(Some(Event::InviteCreated { code: c, .. })) =
            tokio::time::timeout(Duration::from_millis(50), owner.next_event()).await
        {
            code = c;
            break;
        }
    }
    assert!(!code.is_empty(), "no invite code arrived");

    // Carol redeems it; the relay routes a JoinRequest to the owner. Interleave
    // pumping both: the owner admits on JoinRequested (as main.rs does), and Carol
    // converges to a member once the Welcome lands.
    carol.redeem_invite(&code);
    let mut admitted = false;
    for _ in 0..200 {
        if let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(50), owner.next_event()).await
        {
            if let Event::JoinRequested {
                workspace,
                requester,
            } = ev
            {
                owner.workspace_add_member(&workspace, &requester).await.unwrap();
                admitted = true;
            }
        }
        let _ = tokio::time::timeout(Duration::from_millis(50), carol.next_event()).await;
        if carol
            .workspace(&ws)
            .is_some_and(|s| s.role_of(&carol_h) == Some(Role::Member))
        {
            break;
        }
    }
    assert!(admitted, "owner never received the join request");
    assert_eq!(
        carol.workspace(&ws).and_then(|s| s.role_of(&carol_h)),
        Some(Role::Member),
        "redeemer did not become a member"
    );
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
}

/// An admin can drag a member from one voice channel to another: the relay
/// (checking the admin role) directs the member's client, which joins the target
/// -- so presence moves. A non-admin's move is refused. Proves the voice-move
/// authorization and directive path end to end.
#[tokio::test]
async fn an_admin_moves_a_member_between_voice_channels() {
    use enclave_protocol::Role;

    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut bob = account(&url, "bob").await;
    let bob_h = bob.name().to_string();

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;
    owner.workspace_add_member(&ws, &bob_h).await.unwrap();
    pump2(&mut owner, &mut bob, |_, b| {
        b.workspace(&ws).is_some_and(|s| s.role_of(&bob_h) == Some(Role::Member))
    })
    .await;

    let vc1 = owner.create_voice_channel(&ws, "Room A", None).unwrap();
    let vc2 = owner.create_voice_channel(&ws, "Room B", None).unwrap();
    pump2(&mut owner, &mut bob, |o, b| {
        o.workspace(&ws).is_some_and(|s| s.channels.len() == 2)
            && b.workspace(&ws).is_some_and(|s| s.channels.len() == 2)
    })
    .await;

    // Bob joins Room A; the owner sees him there.
    bob.join_voice_channel(&ws, &vc1).unwrap();
    pump2(&mut owner, &mut bob, |o, _| o.voice_members(&ws, &vc1).contains(&bob_h)).await;

    // A non-admin (bob) cannot move anyone: no presence change results.
    bob.voice_move_member(&ws, &vc2, &bob_h).unwrap();
    for _ in 0..10 {
        let _ = tokio::time::timeout(Duration::from_millis(30), owner.next_event()).await;
        let _ = tokio::time::timeout(Duration::from_millis(30), bob.next_event()).await;
    }
    assert!(owner.voice_members(&ws, &vc1).contains(&bob_h), "non-admin move had no effect");

    // The owner (admin) moves bob to Room B. Bob's client acts on the directive
    // exactly as the app loop does (join the target on Event::VoiceMoveTo).
    owner.voice_move_member(&ws, &vc2, &bob_h).unwrap();
    let mut moved = false;
    for _ in 0..200 {
        if let Ok(Some(Event::VoiceMoveTo { workspace, channel })) =
            tokio::time::timeout(Duration::from_millis(30), bob.next_event()).await
        {
            bob.join_voice_channel(&workspace, &channel).unwrap();
            moved = true;
        }
        let _ = tokio::time::timeout(Duration::from_millis(10), owner.next_event()).await;
        if owner.voice_members(&ws, &vc2).contains(&bob_h) {
            break;
        }
    }
    assert!(moved, "bob never received the move directive");
    pump_until(&mut owner, |c| {
        c.voice_members(&ws, &vc2).contains(&bob_h) && !c.voice_members(&ws, &vc1).contains(&bob_h)
    })
    .await;
}

/// A channel can be created inside a category, so the sidebar hierarchy (the
/// expandable category groups) has real membership behind it, not just a flat
/// list. Proves the category id threads from create_channel through the op-log.
#[tokio::test]
async fn a_channel_can_be_created_inside_a_category() {
    use enclave_protocol::WorkspaceOp;

    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;

    // Create a category, then a channel inside it.
    let cat = [9u8; 16];
    owner
        .workspace_submit(
            &ws,
            WorkspaceOp::CreateCategory {
                category: cat,
                name: "Rooms".into(),
            },
        )
        .unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws)
            .is_some_and(|s| s.categories.contains_key(&cat))
    })
    .await;
    let cat_hex: String = cat.iter().map(|b| format!("{b:02x}")).collect();
    owner.create_channel(&ws, "lounge", Some(&cat_hex)).unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws)
            .is_some_and(|s| s.channels.values().any(|ch| ch.name == "lounge"))
    })
    .await;

    let s = owner.workspace(&ws).unwrap();
    let ch = s.channels.values().find(|c| c.name == "lounge").unwrap();
    assert_eq!(ch.category, Some(cat), "channel landed in the category");
}

/// A shared invite link redeemed by several people at once must admit ALL of
/// them: the adds queue and drain one per freed op-log slot rather than racing
/// the MLS commit and dropping all but the first (the old busy-check behavior).
#[tokio::test]
async fn a_burst_of_invite_redemptions_all_get_admitted() {
    use enclave_protocol::Role;

    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut r1 = account(&url, "ann").await;
    let mut r2 = account(&url, "ben").await;
    let mut r3 = account(&url, "cal").await;
    let names = [
        r1.name().to_string(),
        r2.name().to_string(),
        r3.name().to_string(),
    ];

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;

    owner.create_invite(&ws, 0, 0);
    let mut code = String::new();
    for _ in 0..100 {
        if let Ok(Some(Event::InviteCreated { code: c, .. })) =
            tokio::time::timeout(Duration::from_millis(50), owner.next_event()).await
        {
            code = c;
            break;
        }
    }
    assert!(!code.is_empty());

    // Three people redeem the same link at once.
    r1.redeem_invite(&code);
    r2.redeem_invite(&code);
    r3.redeem_invite(&code);

    // Drive the owner exactly as the app loop does: admit on each JoinRequested
    // (which queues), then drain the queue as the op-log frees up. Pump the
    // redeemers so their Welcomes land.
    for _ in 0..600 {
        if let Ok(Some(Event::JoinRequested {
            workspace,
            requester,
        })) = tokio::time::timeout(Duration::from_millis(20), owner.next_event()).await
        {
            owner
                .workspace_add_member(&workspace, &requester)
                .await
                .unwrap();
        }
        let _ = owner.pump_workspace_adds().await;
        let _ = tokio::time::timeout(Duration::from_millis(5), r1.next_event()).await;
        let _ = tokio::time::timeout(Duration::from_millis(5), r2.next_event()).await;
        let _ = tokio::time::timeout(Duration::from_millis(5), r3.next_event()).await;
        if names
            .iter()
            .all(|n| owner.workspace(&ws).is_some_and(|s| s.members.contains_key(n)))
        {
            break;
        }
    }

    // No drops: owner + all three redeemers, and each redeemer sees itself joined.
    let s = owner.workspace(&ws).unwrap();
    assert_eq!(s.members.len(), 4, "all three admitted without a drop");
    for n in &names {
        assert!(s.members.contains_key(n), "{n} was dropped");
    }
    pump_until(&mut r1, |c| {
        c.workspace(&ws)
            .is_some_and(|st| st.role_of(&names[0]) == Some(Role::Member))
    })
    .await;
    pump_until(&mut r2, |c| {
        c.workspace(&ws)
            .is_some_and(|st| st.role_of(&names[1]) == Some(Role::Member))
    })
    .await;
    pump_until(&mut r3, |c| {
        c.workspace(&ws)
            .is_some_and(|st| st.role_of(&names[2]) == Some(Role::Member))
    })
    .await;
}

/// M1 end to end: an owner creates a workspace, adds a member, creates a public
/// text channel, and the two exchange messages sealed under the workspace MLS
/// group -- proving the WG lifecycle (create / Welcome-join / commit) and
/// channel messaging work across two real clients through the relay.
#[tokio::test]
async fn members_exchange_messages_in_a_workspace_channel() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut bob = account(&url, "bob").await;
    let owner_h = owner.name().to_string();
    let bob_h = bob.name().to_string();

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;

    // Add Bob: fetches his key package, adds him to the WG, records the op, sends
    // the Welcome + commit. Both converge on a two-member workspace.
    owner.workspace_add_member(&ws, &bob_h).await.unwrap();
    pump_until(&mut bob, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;

    // Owner creates a public text channel; both see it in the op-log.
    let chan = owner.create_channel(&ws, "general", None).unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;
    pump_until(&mut bob, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;

    // Owner posts; Bob receives and decrypts via the WG, attributed to the owner.
    owner
        .send_channel_post(&ws, &chan, "hello channel")
        .unwrap();
    pump_until(&mut bob, |c| !c.channel_history(&ws, &chan).is_empty()).await;
    let bobs = bob.channel_history(&ws, &chan);
    assert_eq!(bobs[0].text, "hello channel");
    assert_eq!(bobs[0].user, owner_h, "sender is MLS-authenticated");
    assert!(!bobs[0].mine);

    // Bob replies; the owner receives it.
    bob.send_channel_post(&ws, &chan, "hi back").unwrap();
    pump_until(&mut owner, |c| {
        c.channel_history(&ws, &chan).iter().any(|m| !m.mine)
    })
    .await;
    let owners = owner.channel_history(&ws, &chan);
    assert!(owners
        .iter()
        .any(|m| m.text == "hi back" && m.user == bob_h && !m.mine));
    // The owner's own post is also in history.
    assert!(owners.iter().any(|m| m.text == "hello channel" && m.mine));
}

/// A non-member online during a workspace's channel traffic receives none of it:
/// the relay fans channel posts only to members (deny-by-default), and a
/// non-member holds no WG key to decrypt even if they did. Membership access
/// control for workspace content.
#[tokio::test]
async fn a_non_member_never_sees_a_workspaces_channel_traffic() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut bob = account(&url, "bob").await;
    let mut mallory = account(&url, "mallory").await; // online, but never added
    let bob_h = bob.name().to_string();

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;
    owner.workspace_add_member(&ws, &bob_h).await.unwrap();
    // Wait for the owner's own AddMember echo (state advanced) before the next
    // structural op, so create_channel signs against the current head.
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    pump_until(&mut bob, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    let chan = owner.create_channel(&ws, "general", None).unwrap();
    pump_until(&mut bob, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;

    owner.send_channel_post(&ws, &chan, "members only").unwrap();
    pump_until(&mut bob, |c| !c.channel_history(&ws, &chan).is_empty()).await;

    // Give Mallory ample opportunity to have received anything, then confirm she
    // got nothing: not the workspace, not the channel traffic.
    for _ in 0..30 {
        let _ = tokio::time::timeout(Duration::from_millis(20), mallory.next_event()).await;
    }
    assert!(
        mallory.workspace(&ws).is_none(),
        "a non-member does not learn the workspace"
    );
    assert!(
        mallory.channel_history(&ws, &chan).is_empty(),
        "a non-member receives no channel messages"
    );
}
// appended diagnostic

/// M2 scrollback: a member added *after* messages were posted can read that
/// history. On join they receive the channel history keys (sealed under the WG)
/// and backfill from the relay's stored, sealed history -- the Discord-style
/// scrollback that pure MLS forbids.
#[tokio::test]
async fn a_late_joiner_reads_channel_history_from_before_they_joined() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut bob = account(&url, "bob").await;
    let mut carol = account(&url, "carol").await;
    let bob_h = bob.name().to_string();
    let carol_h = carol.name().to_string();

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;
    owner.workspace_add_member(&ws, &bob_h).await.unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    let chan = owner.create_channel(&ws, "general", None).unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;
    pump_until(&mut bob, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;

    // Post history BEFORE Carol exists in the workspace.
    owner.send_channel_post(&ws, &chan, "first").unwrap();
    owner.send_channel_post(&ws, &chan, "second").unwrap();
    pump_until(&mut bob, |c| c.channel_history(&ws, &chan).len() == 2).await;

    // Now add Carol; she must be able to read the two earlier messages.
    owner.workspace_add_member(&ws, &carol_h).await.unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 3)
    })
    .await;
    pump_until(&mut carol, |c| c.channel_history(&ws, &chan).len() == 2).await;

    let texts: Vec<String> = carol
        .channel_history(&ws, &chan)
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert!(
        texts.contains(&"first".to_string()) && texts.contains(&"second".to_string()),
        "late joiner backfilled pre-join history: {texts:?}"
    );
}

/// M2 rotation: removing a member rotates every channel's history key, so the
/// removed member cannot read anything posted after their removal, while
/// remaining members can. History-key forward secrecy across a removal.
#[tokio::test]
async fn a_removed_member_cannot_read_messages_posted_after_removal() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut bob = account(&url, "bob").await;
    let mut carol = account(&url, "carol").await;
    let bob_h = bob.name().to_string();
    let carol_h = carol.name().to_string();

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;
    owner.workspace_add_member(&ws, &bob_h).await.unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    owner.workspace_add_member(&ws, &carol_h).await.unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 3)
    })
    .await;
    let chan = owner.create_channel(&ws, "general", None).unwrap();
    // Sequence past the owner's own CreateChannel echo before the next structural
    // op, and let Bob apply every WG commit in order (add-carol before remove).
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;
    pump_until(&mut bob, |c| {
        c.workspace(&ws)
            .is_some_and(|s| s.members.len() == 3 && !s.channels.is_empty())
    })
    .await;
    pump_until(&mut carol, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;

    // Carol reads a pre-removal message.
    owner.send_channel_post(&ws, &chan, "before").unwrap();
    pump_until(&mut carol, |c| !c.channel_history(&ws, &chan).is_empty()).await;

    // Remove Carol; the key rotates to a new epoch shared only with Bob.
    owner.workspace_remove_member(&ws, &carol_h).unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    // Let Bob apply the removal commit + receive the rotated key.
    for _ in 0..40 {
        let _ = tokio::time::timeout(Duration::from_millis(20), bob.next_event()).await;
    }

    // Post AFTER removal (under the new epoch key).
    owner
        .send_channel_post(&ws, &chan, "after removal")
        .unwrap();
    // Bob (remaining) reads it.
    pump_until(&mut bob, |c| {
        c.channel_history(&ws, &chan)
            .iter()
            .any(|m| m.text == "after removal")
    })
    .await;

    // Carol gets no chance to read the post-removal message.
    for _ in 0..40 {
        let _ = tokio::time::timeout(Duration::from_millis(20), carol.next_event()).await;
    }
    let carol_texts: Vec<String> = carol
        .channel_history(&ws, &chan)
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert!(
        carol_texts.contains(&"before".to_string()),
        "removed member keeps pre-removal history"
    );
    assert!(
        !carol_texts.contains(&"after removal".to_string()),
        "removed member cannot read post-removal messages: {carol_texts:?}"
    );
}

/// The op-submission queue: a burst of structural ops submitted back-to-back
/// (three channels at once, no waiting between) all land, because each is signed
/// against the head as it advances instead of colliding on a seq.
#[tokio::test]
async fn a_burst_of_structural_ops_all_land_via_the_queue() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;

    // Fire three creates with no pumping between them.
    owner.create_channel(&ws, "general", None).unwrap();
    owner.create_channel(&ws, "random", None).unwrap();
    owner.create_channel(&ws, "dev", None).unwrap();

    // All three land, in order, on the single linear log.
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.channels.len() == 3)
    })
    .await;
    let names: std::collections::BTreeSet<String> = owner
        .workspace(&ws)
        .unwrap()
        .channels
        .values()
        .map(|ch| ch.name.clone())
        .collect();
    assert_eq!(
        names,
        ["dev", "general", "random"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    );
}

/// M3: a private channel is readable only by its members. A workspace member who
/// is not in the private channel receives none of its traffic (the relay routes
/// to the channel's subset) and holds no key for it (it has its own MLS group).
#[tokio::test]
async fn a_private_channel_is_readable_only_by_its_members() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut bob = account(&url, "bob").await;
    let mut carol = account(&url, "carol").await;
    let bob_h = bob.name().to_string();
    let carol_h = carol.name().to_string();

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;
    owner.workspace_add_member(&ws, &bob_h).await.unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    owner.workspace_add_member(&ws, &carol_h).await.unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 3)
    })
    .await;
    // Both catch up so their WG is current.
    pump_until(&mut bob, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 3)
    })
    .await;
    pump_until(&mut carol, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 3)
    })
    .await;

    // Owner creates a PRIVATE channel and adds only Bob to it.
    let chan = owner.create_private_channel(&ws, "staff", None).unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;
    owner.add_channel_member(&ws, &chan, &bob_h).await.unwrap();
    // Owner sees Bob as a channel member (op applied).
    let chan_id = {
        let mut b = [0u8; 16];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&chan[i * 2..i * 2 + 2], 16).unwrap();
        }
        b
    };
    pump_until(&mut owner, |c| {
        c.workspace(&ws)
            .is_some_and(|s| s.is_channel_member(&chan_id, &bob_h))
    })
    .await;
    // Let Bob process the channel Welcome + key share.
    for _ in 0..60 {
        let _ = tokio::time::timeout(Duration::from_millis(20), bob.next_event()).await;
    }

    owner.send_channel_post(&ws, &chan, "top secret").unwrap();
    pump_until(&mut bob, |c| !c.channel_history(&ws, &chan).is_empty()).await;
    assert_eq!(bob.channel_history(&ws, &chan)[0].text, "top secret");

    // Carol -- a workspace member, but NOT in this private channel -- gets nothing.
    for _ in 0..40 {
        let _ = tokio::time::timeout(Duration::from_millis(20), carol.next_event()).await;
    }
    assert!(
        carol.channel_history(&ws, &chan).is_empty(),
        "a non-channel-member of the workspace sees no private-channel traffic"
    );
}

/// M4: voice channel presence. When members join/leave a voice channel, the
/// relay broadcasts the roster to the channel's members, so everyone sees who is
/// in voice (the audio itself rides the existing SFU/call path, started
/// separately). Presence is what makes a voice channel visible.
#[tokio::test]
async fn voice_channel_presence_tracks_who_is_connected() {
    let handle = serve("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", handle.addr);
    let mut owner = account(&url, "owner").await;
    let mut bob = account(&url, "bob").await;
    let owner_h = owner.name().to_string();
    let bob_h = bob.name().to_string();

    let ws = owner.create_workspace("Team").unwrap();
    pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await;
    owner.workspace_add_member(&ws, &bob_h).await.unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| s.members.len() == 2)
    })
    .await;
    let chan = owner.create_voice_channel(&ws, "Lounge", None).unwrap();
    pump_until(&mut owner, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;
    pump_until(&mut bob, |c| {
        c.workspace(&ws).is_some_and(|s| !s.channels.is_empty())
    })
    .await;

    // Owner joins voice; Bob (a channel member) sees the roster update.
    owner.join_voice_channel(&ws, &chan).unwrap();
    pump_until(&mut bob, |c| c.voice_members(&ws, &chan).contains(&owner_h)).await;
    assert_eq!(bob.voice_members(&ws, &chan), vec![owner_h.clone()]);

    // Bob joins too; both are now in voice, visible to both.
    bob.join_voice_channel(&ws, &chan).unwrap();
    pump_until(&mut owner, |c| c.voice_members(&ws, &chan).len() == 2).await;
    pump_until(&mut bob, |c| c.voice_members(&ws, &chan).len() == 2).await;
    assert!(bob.voice_members(&ws, &chan).contains(&bob_h));
    assert!(owner.voice_members(&ws, &chan).contains(&bob_h));

    // Owner leaves; Bob sees them drop out.
    owner.leave_voice_channel();
    pump_until(&mut bob, |c| {
        !c.voice_members(&ws, &chan).contains(&owner_h)
    })
    .await;
    assert_eq!(bob.voice_members(&ws, &chan), vec![bob_h]);
}
