//! Unit tests for the pure relay routing core (no network).

use enclave_protocol::{ClientMsg, DeviceId, GroupId, Presence, Sealed, ServerMsg, UserId};
use enclave_transport::{Outgoing, Relay};

// Drive a full OPAQUE registration against the relay on `conn`. Returns the
// server-assigned handle (name#1234) and the finish outgoings (Auth + presence).
// Uses the real handshake -- no test backdoor into the auth path.
fn authenticate(r: &mut Relay, conn: u64, name: &str, kp: Vec<u8>) -> (String, Vec<Outgoing>) {
    let password = "a-sufficiently-long-password";
    let (request, state) =
        enclave_transport::opaque::client_register_start(password).expect("register start");
    let out = r.handle(
        conn,
        ClientMsg::RegisterStart {
            name: name.into(),
            request,
        },
    );
    let (handle, response) = match &out[0].msg {
        ServerMsg::RegisterResponse { handle, response } => (handle.clone(), response.clone()),
        other => panic!("expected RegisterResponse, got {other:?}"),
    };
    let (upload, _export) = state.finish(password, &response).expect("register finish");
    let finish = r.handle(
        conn,
        ClientMsg::RegisterFinish {
            upload,
            identity_pub: vec![],
            key_package: kp,
            display: String::new(),
        },
    );
    (handle, finish)
}

// Create an account on a fresh connection. Returns (conn, handle); the handle is
// the routing device id in the account model.
fn register(r: &mut Relay, name: &str, kp: Vec<u8>) -> (u64, String) {
    let conn = r.connect();
    let (handle, _) = authenticate(r, conn, name, kp);
    (conn, handle)
}

// Log an existing account back in on a fresh connection (real OPAQUE handshake).
// Returns the new conn and the finish outgoings (Auth + snapshot + any queued).
fn login(r: &mut Relay, handle: &str, kp: Vec<u8>) -> (u64, Vec<Outgoing>) {
    let conn = r.connect();
    let password = "a-sufficiently-long-password";
    let (request, state) =
        enclave_transport::opaque::client_login_start(password).expect("login start");
    let out = r.handle(
        conn,
        ClientMsg::LoginStart {
            handle: handle.into(),
            request,
        },
    );
    let response = match &out[0].msg {
        ServerMsg::LoginResponse { response } => response.clone(),
        other => panic!("expected LoginResponse, got {other:?}"),
    };
    let (finalization, _export) = state.finish(password, &response).expect("login finish");
    let finish = r.handle(
        conn,
        ClientMsg::LoginFinish {
            finalization,
            key_package: kp,
        },
    );
    (conn, finish)
}

#[test]
fn fetch_returns_the_reusable_key_package() {
    let mut r = Relay::new();
    let (conn, h) = register(&mut r, "u", vec![9, 9, 9]);

    let out = r.handle(
        conn,
        ClientMsg::FetchKeyPackages {
            user: UserId(h.clone()),
        },
    );
    assert_eq!(out.len(), 1);
    match &out[0].msg {
        ServerMsg::KeyPackages { packages, .. } => assert_eq!(packages, &vec![vec![9, 9, 9]]),
        other => panic!("expected KeyPackages, got {other:?}"),
    }

    // Last-resort key packages are reusable: a second fetch returns it again.
    let out2 = r.handle(conn, ClientMsg::FetchKeyPackages { user: UserId(h) });
    match &out2[0].msg {
        ServerMsg::KeyPackages { packages, .. } => assert_eq!(packages, &vec![vec![9, 9, 9]]),
        other => panic!("expected KeyPackages, got {other:?}"),
    }
}

#[test]
fn text_fans_out_to_other_members_only_and_relays_bytes_unchanged() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = GroupId([5u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    ); // Alice bootstraps
    r.handle(
        a,
        ClientMsg::Welcome {
            to: DeviceId(bh),
            name: String::new(),
            group: group.clone(),
            message: Sealed(vec![]),
        },
    ); // Alice invites Bob into routing

    let out = r.handle(
        a,
        ClientMsg::Text {
            group: group.clone(),
            message: Sealed(vec![7, 7, 7]),
        },
    );

    // Delivered to Bob only, never echoed to the sender.
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, b);
    match &out[0].msg {
        // The relay forwards the ciphertext verbatim; it cannot alter or read it.
        ServerMsg::Text { message, .. } => assert_eq!(message.0, vec![7, 7, 7]),
        other => panic!("expected Text, got {other:?}"),
    }
}

#[test]
fn a_member_can_vouch_a_peer_back_into_a_forgotten_group() {
    // Recovery path: after a server state loss, only the first re-affirmer
    // bootstraps the group and the peer's self-join is rejected. A vouch from the
    // (now sole) member re-adds the peer, so their shared conversation routes
    // again -- without either recreating it.
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = GroupId([7u8; 32]);

    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    ); // a bootstraps
    r.handle(
        b,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    ); // b rejected (non-empty, not a member)

    // Before the vouch, a's message reaches no one (b is not a routing member).
    let out = r.handle(
        a,
        ClientMsg::Text {
            group: group.clone(),
            message: Sealed(vec![1]),
        },
    );
    assert!(out.is_empty(), "b is not a routing member yet");

    // a (a member) vouches b in; now a's message fans out to b.
    r.handle(
        a,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(bh),
        },
    );
    let out = r.handle(
        a,
        ClientMsg::Text {
            group: group.clone(),
            message: Sealed(vec![2]),
        },
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, b);
}

#[test]
fn a_non_member_cannot_vouch_or_self_join_to_eavesdrop() {
    // A vouch is only honored from an existing member, and a stranger cannot
    // self-join a non-empty group -- so a guessable (DM) group id cannot be used
    // to subscribe to a conversation you are not in.
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let (m, mh) = register(&mut r, "m", vec![3]); // mallory
    let group = GroupId([8u8; 32]);

    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(bh),
        },
    ); // group is now {a, b}

    // Mallory (not a member) cannot vouch herself in, nor self-join.
    r.handle(
        m,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(mh),
        },
    );
    r.handle(
        m,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );

    // a's message reaches b, never mallory.
    let out = r.handle(
        a,
        ClientMsg::Text {
            group: group.clone(),
            message: Sealed(vec![9]),
        },
    );
    let recipients: Vec<u64> = out.iter().map(|o| o.to).collect();
    assert_eq!(recipients, vec![b], "only b, never mallory");
    assert_ne!(out.first().map(|o| o.to), Some(m));
}

#[test]
fn calling_rings_other_members_then_tracks_participants() {
    let mut r = Relay::new();
    let (a, ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = GroupId([12u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(bh.clone()),
        },
    );

    // a starts the call -> b is rung, and members get the participant list [a].
    let out = r.handle(
        a,
        ClientMsg::JoinCall {
            group: group.clone(),
        },
    );
    assert!(
        out.iter().any(
            |o| o.to == b && matches!(&o.msg, ServerMsg::CallOffer { from, .. } if from == &ah)
        ),
        "b must be rung when a starts the call"
    );
    let parts_to_b = out.iter().find_map(|o| match &o.msg {
        ServerMsg::CallParticipants { participants, .. } if o.to == b => Some(participants.clone()),
        _ => None,
    });
    assert_eq!(parts_to_b, Some(vec![ah.clone()]));

    // b joins -> no new ring; participants become {a, b}.
    let out = r.handle(
        b,
        ClientMsg::JoinCall {
            group: group.clone(),
        },
    );
    assert!(
        !out.iter()
            .any(|o| matches!(o.msg, ServerMsg::CallOffer { .. })),
        "joining an active call does not ring"
    );
    let mut parts = out
        .iter()
        .find_map(|o| match &o.msg {
            ServerMsg::CallParticipants { participants, .. } if o.to == a => {
                Some(participants.clone())
            }
            _ => None,
        })
        .unwrap();
    parts.sort();
    assert_eq!(parts, vec![ah.clone(), bh.clone()]);

    // a leaves -> [b]; b leaves -> call ended (empty).
    let out = r.handle(
        a,
        ClientMsg::LeaveCall {
            group: group.clone(),
        },
    );
    assert_eq!(
        out.iter().find_map(|o| match &o.msg {
            ServerMsg::CallParticipants { participants, .. } if o.to == b =>
                Some(participants.clone()),
            _ => None,
        }),
        Some(vec![bh.clone()])
    );
    let out = r.handle(b, ClientMsg::LeaveCall { group });
    assert!(out.iter().any(
        |o| matches!(&o.msg, ServerMsg::CallParticipants { participants, .. } if participants.is_empty())
    ));
}

#[test]
fn disconnect_drops_the_device_from_its_call() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = GroupId([13u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(bh.clone()),
        },
    );
    r.handle(
        a,
        ClientMsg::JoinCall {
            group: group.clone(),
        },
    );
    r.handle(b, ClientMsg::JoinCall { group });

    // a drops -> b is told the call is now just {b}.
    let out = r.disconnect(a);
    assert_eq!(
        out.iter().find_map(|o| match &o.msg {
            ServerMsg::CallParticipants { participants, .. } if o.to == b =>
                Some(participants.clone()),
            _ => None,
        }),
        Some(vec![bh])
    );
}

#[test]
fn messages_to_an_offline_member_are_queued_and_delivered_on_login() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = GroupId([21u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(bh.clone()),
        },
    );

    // b goes offline; a's text is queued, not delivered live.
    r.disconnect(b);
    let out = r.handle(
        a,
        ClientMsg::Text {
            group,
            message: Sealed(vec![42]),
        },
    );
    assert!(out.is_empty(), "b is offline: the text is queued, not sent");

    // b logs back in -> the queued text is delivered, exactly once.
    let has_text = |outs: &[Outgoing]| {
        outs.iter()
            .any(|o| matches!(&o.msg, ServerMsg::Text { message, .. } if message.0 == vec![42]))
    };
    let (_c1, finish1) = login(&mut r, &bh, vec![2]);
    assert!(has_text(&finish1), "queued text delivered on next login");
    let (_c2, finish2) = login(&mut r, &bh, vec![2]);
    assert!(!has_text(&finish2), "the queue is drained after delivery");
}

#[test]
fn leaving_and_removing_drop_routing_membership() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let (c, ch) = register(&mut r, "c", vec![3]);
    let group = GroupId([31u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(bh),
        },
    );
    r.handle(
        a,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(ch.clone()),
        },
    ); // {a, b, c}

    // c leaves -> a's message no longer reaches c.
    r.handle(
        c,
        ClientMsg::LeaveGroup {
            group: group.clone(),
        },
    );
    let recips: Vec<u64> = r
        .handle(
            a,
            ClientMsg::Text {
                group: group.clone(),
                message: Sealed(vec![1]),
            },
        )
        .iter()
        .map(|o| o.to)
        .collect();
    assert_eq!(recips, vec![b], "c left: only b remains");

    // a removes b -> now a's message reaches no one.
    r.handle(
        a,
        ClientMsg::RemoveMember {
            group: group.clone(),
            member: DeviceId("b".into()),
        },
    );
    assert!(r
        .handle(
            a,
            ClientMsg::Text {
                group,
                message: Sealed(vec![2]),
            },
        )
        .is_empty());
}

#[test]
fn a_non_member_cannot_remove_anyone() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let (m, _mh) = register(&mut r, "m", vec![3]); // outsider
    let group = GroupId([32u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::AffirmMember {
            group: group.clone(),
            member: DeviceId(bh),
        },
    );

    // Mallory (not a member) tries to remove b -> ignored.
    r.handle(
        m,
        ClientMsg::RemoveMember {
            group: group.clone(),
            member: DeviceId("b".into()),
        },
    );
    let recips: Vec<u64> = r
        .handle(
            a,
            ClientMsg::Text {
                group,
                message: Sealed(vec![1]),
            },
        )
        .iter()
        .map(|o| o.to)
        .collect();
    assert_eq!(
        recips,
        vec![b],
        "b is still a member; mallory's removal ignored"
    );
}

#[test]
fn text_fans_out_to_all_other_members_in_a_larger_group() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let (c, ch) = register(&mut r, "c", vec![3]);
    let group = GroupId([6u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    ); // Alice bootstraps
    for peer in [bh, ch] {
        r.handle(
            a,
            ClientMsg::Welcome {
                to: DeviceId(peer),
                name: String::new(),
                group: group.clone(),
                message: Sealed(vec![]),
            },
        );
    }

    let out = r.handle(
        a,
        ClientMsg::Text {
            group,
            message: Sealed(vec![1, 2, 3]),
        },
    );

    // Delivered to both other members, never to the sender.
    assert_eq!(out.len(), 2);
    assert!(out.iter().any(|o| o.to == b));
    assert!(out.iter().any(|o| o.to == c));
    assert!(!out.iter().any(|o| o.to == a));
}

#[test]
fn welcome_is_directed_and_adds_the_recipient_to_routing() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = GroupId([3u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );

    // Alice welcomes Bob's device directly.
    let out = r.handle(
        a,
        ClientMsg::Welcome {
            to: DeviceId(bh),
            name: String::new(),
            group: group.clone(),
            message: Sealed(vec![4, 2]),
        },
    );
    // The Welcome is directed to Bob only. (The handler also broadcasts the
    // updated GroupMembers to the group, so the output is not only the Welcome.)
    assert!(
        out.iter()
            .any(|o| o.to == b && matches!(o.msg, ServerMsg::Welcome { .. })),
        "the Welcome is delivered to Bob"
    );
    assert!(
        !out.iter()
            .any(|o| matches!(o.msg, ServerMsg::Welcome { .. }) && o.to == a),
        "the Welcome is not sent to Alice"
    );

    // Bob is now in the routing set, so a subsequent Text reaches him without
    // an explicit JoinGroup from Bob.
    let out2 = r.handle(
        a,
        ClientMsg::Text {
            group,
            message: Sealed(vec![1]),
        },
    );
    assert_eq!(out2.len(), 1);
    assert_eq!(out2[0].to, b);
}

#[test]
fn disconnect_removes_the_device_from_routing() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = GroupId([8u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    ); // Alice bootstraps
    r.handle(
        a,
        ClientMsg::Welcome {
            to: DeviceId(bh),
            name: String::new(),
            group: group.clone(),
            message: Sealed(vec![]),
        },
    );

    r.disconnect(b);

    let out = r.handle(
        a,
        ClientMsg::Text {
            group,
            message: Sealed(vec![0]),
        },
    );
    assert!(
        out.is_empty(),
        "a disconnected device must not be routed to"
    );
}

#[test]
fn non_member_cannot_join_or_inject() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let (mallory, mallory_h) = register(&mut r, "mallory", vec![3]);
    let group = GroupId([9u8; 32]);

    // Alice creates the group and invites Bob (the legitimate path).
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::Welcome {
            to: DeviceId(bh),
            name: String::new(),
            group: group.clone(),
            message: Sealed(vec![]),
        },
    );

    // Mallory tries to self-join the existing group: rejected.
    r.handle(
        mallory,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );

    // She cannot inject a message (not a member).
    let injected = r.handle(
        mallory,
        ClientMsg::Text {
            group: group.clone(),
            message: Sealed(vec![6, 6, 6]),
        },
    );
    assert!(
        injected.is_empty(),
        "a non-member must not inject into a group"
    );

    // She cannot invite herself via a Welcome (not a member).
    let sneaked = r.handle(
        mallory,
        ClientMsg::Welcome {
            to: DeviceId(mallory_h),
            name: String::new(),
            group: group.clone(),
            message: Sealed(vec![]),
        },
    );
    assert!(sneaked.is_empty(), "a non-member cannot invite");

    // Alice's legitimate message still reaches only Bob.
    let out = r.handle(
        a,
        ClientMsg::Text {
            group,
            message: Sealed(vec![1]),
        },
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, b);
}

#[test]
fn presence_reaches_watchers_on_connect_and_disconnect() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "alice", vec![1]);
    let (b, bob_h) = register(&mut r, "bob", vec![2]);

    // Alice watches Bob (already online) -> she is told immediately he is online.
    let out = r.handle(
        a,
        ClientMsg::WatchPresence {
            users: vec![UserId(bob_h.clone())],
        },
    );
    assert!(out.iter().any(|o| o.to == a
        && matches!(
            &o.msg,
            ServerMsg::Presence { user, status: Presence::Online } if user.0 == bob_h
        )));

    // Bob disconnects -> Alice (watching Bob) is told he is offline.
    let out = r.disconnect(b);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, a);
    assert!(matches!(
        &out[0].msg,
        ServerMsg::Presence { user, status: Presence::Offline } if user.0 == bob_h
    ));
}

// ---- File transfer: consent-gated offers (stored + live) ----------------

// Register Alice and Bob and put them in a shared routing group. Returns their
// connections + handles and the group id. Both are online.
fn two_member_group(r: &mut Relay) -> (u64, String, u64, String, GroupId) {
    let (a, ah) = register(r, "a", vec![1]);
    let (b, bh) = register(r, "b", vec![2]);
    let group = GroupId([42u8; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::Welcome {
            to: DeviceId(bh.clone()),
            name: String::new(),
            group: group.clone(),
            message: Sealed(vec![]),
        },
    );
    (a, ah, b, bh, group)
}

fn offered(out: &[Outgoing]) -> Option<&ServerMsg> {
    out.iter()
        .map(|o| &o.msg)
        .find(|m| matches!(m, ServerMsg::FileOffered { .. }))
}

#[test]
fn a_stored_file_is_offered_not_pushed_and_delivered_only_on_accept() {
    let mut r = Relay::new();
    let (a, ah, b, bh, group) = two_member_group(&mut r);
    let offer_id = [7u8; 16];

    // Alice offers a stored file: the server admits it and asks her to upload.
    let out = r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id,
            group: group.clone(),
            size: 100,
            manifest: Sealed(vec![0xAA]),
            live: false,
        },
    );
    assert!(
        matches!(&out[0].msg, ServerMsg::FileUploadReady { offer_id: o } if *o == offer_id),
        "sender told to upload, got {:?}",
        out
    );

    // Alice uploads a chunk and finishes. Bob is NOT sent the bytes.
    let up = r.handle(
        a,
        ClientMsg::FileChunk {
            offer_id,
            index: 0,
            data: Sealed(vec![1, 2, 3]),
        },
    );
    assert!(
        up.is_empty(),
        "an uploaded chunk is buffered, never fanned out"
    );
    let done = r.handle(a, ClientMsg::FileComplete { offer_id });

    // Bob (online) is *offered* the file, and only that -- no chunk.
    assert_eq!(done.len(), 1, "exactly one notification");
    assert_eq!(done[0].to, b);
    match &done[0].msg {
        ServerMsg::FileOffered {
            manifest,
            live,
            from,
            ..
        } => {
            assert_eq!(manifest.0, vec![0xAA], "the sealed manifest reaches Bob");
            assert!(!live);
            assert_eq!(from.0, ah);
        }
        other => panic!("expected FileOffered, got {other:?}"),
    }
    assert!(
        !done
            .iter()
            .any(|o| matches!(o.msg, ServerMsg::FileChunk { .. })),
        "no file bytes are auto-downloaded"
    );

    // Bob accepts: Alice is told, and a blob delivery to Bob is scheduled.
    let acc = r.handle(b, ClientMsg::FileAccept { offer_id });
    assert!(
        acc.iter().any(
            |o| o.to == a && matches!(&o.msg, ServerMsg::FileAccepted { by, .. } if by.0 == bh)
        ),
        "sender notified of the accept"
    );
    let deliveries = r.take_blob_deliveries();
    assert_eq!(deliveries.len(), 1, "one off-lock blob delivery queued");
    assert_eq!(deliveries[0].to, b);
    assert_eq!(deliveries[0].recipient.0, bh);
    assert_eq!(deliveries[0].from.0, ah);
}

#[test]
fn declining_a_stored_offer_notifies_the_sender() {
    let mut r = Relay::new();
    let (a, _ah, b, bh, group) = two_member_group(&mut r);
    let offer_id = [8u8; 16];
    r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id,
            group,
            size: 10,
            manifest: Sealed(vec![1]),
            live: false,
        },
    );
    r.handle(
        a,
        ClientMsg::FileChunk {
            offer_id,
            index: 0,
            data: Sealed(vec![9]),
        },
    );
    r.handle(a, ClientMsg::FileComplete { offer_id });

    let out = r.handle(b, ClientMsg::FileDecline { offer_id });
    assert!(
        out.iter().any(
            |o| o.to == a && matches!(&o.msg, ServerMsg::FileDeclined { by, .. } if by.0 == bh)
        ),
        "sender told who declined"
    );
    // The offer is gone: a late accept delivers nothing.
    assert!(r.handle(b, ClientMsg::FileAccept { offer_id }).is_empty());
    assert!(r.take_blob_deliveries().is_empty());
}

#[test]
fn a_stored_offer_to_an_offline_recipient_is_queued_until_login() {
    let mut r = Relay::new();
    let (a, ah, b, bh, group) = two_member_group(&mut r);
    // Bob goes offline before the upload completes.
    r.disconnect(b);
    let offer_id = [9u8; 16];
    r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id,
            group,
            size: 10,
            manifest: Sealed(vec![0xCD]),
            live: false,
        },
    );
    r.handle(
        a,
        ClientMsg::FileChunk {
            offer_id,
            index: 0,
            data: Sealed(vec![1]),
        },
    );
    let done = r.handle(a, ClientMsg::FileComplete { offer_id });
    assert!(done.is_empty(), "nothing delivered while Bob is offline");

    // Bob logs back in and finds the offer waiting.
    let (_b2, finish) = login(&mut r, &bh, vec![2]);
    let off = offered(&finish).expect("offer delivered on login");
    match off {
        ServerMsg::FileOffered { manifest, from, .. } => {
            assert_eq!(manifest.0, vec![0xCD]);
            assert_eq!(from.0, ah);
        }
        other => panic!("expected FileOffered, got {other:?}"),
    }
}

#[test]
fn a_live_offer_streams_through_the_server_to_accepting_recipients() {
    let mut r = Relay::new();
    let (a, ah, b, bh, group) = two_member_group(&mut r);
    let offer_id = [10u8; 16];

    // Live offer to an online recipient: Bob is offered it, nothing is stored.
    let out = r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id,
            group,
            size: 0,
            manifest: Sealed(vec![0xEE]),
            live: true,
        },
    );
    assert_eq!(out[0].to, b);
    assert!(matches!(
        &out[0].msg,
        ServerMsg::FileOffered { live: true, .. }
    ));

    // Bob accepts -> Alice is cued.
    let acc = r.handle(b, ClientMsg::FileAccept { offer_id });
    assert!(acc
        .iter()
        .any(|o| o.to == a && matches!(&o.msg, ServerMsg::FileAccepted { by, .. } if by.0 == bh)));

    // Alice streams a chunk -> relayed to Bob (never buffered).
    let chunk = r.handle(
        a,
        ClientMsg::FileChunk {
            offer_id,
            index: 0,
            data: Sealed(vec![5, 6]),
        },
    );
    assert_eq!(chunk.len(), 1);
    assert_eq!(chunk[0].to, b);
    match &chunk[0].msg {
        ServerMsg::FileChunk { data, from, .. } => {
            assert_eq!(data.0, vec![5, 6]);
            assert_eq!(from.0, ah);
        }
        other => panic!("expected FileChunk, got {other:?}"),
    }
    assert!(
        r.take_blob_deliveries().is_empty(),
        "live never touches the store"
    );

    // Completion is relayed too.
    let comp = r.handle(a, ClientMsg::FileComplete { offer_id });
    assert_eq!(comp[0].to, b);
    assert!(matches!(&comp[0].msg, ServerMsg::FileComplete { .. }));
}

#[test]
fn a_live_offer_to_an_offline_recipient_is_rejected() {
    let mut r = Relay::new();
    let (a, _ah, b, _bh, group) = two_member_group(&mut r);
    r.disconnect(b);
    let out = r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id: [11u8; 16],
            group,
            size: 0,
            manifest: Sealed(vec![1]),
            live: true,
        },
    );
    assert!(
        matches!(&out[0].msg, ServerMsg::FileOfferRejected { .. }),
        "live needs the recipient online, got {:?}",
        out
    );
}

#[test]
fn an_over_cap_stored_file_is_rejected_before_upload() {
    let mut r = Relay::new();
    let (a, _ah, _b, _bh, group) = two_member_group(&mut r);
    let too_big = enclave_transport::filestore::PER_FILE_MAX + 1;
    let out = r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id: [12u8; 16],
            group,
            size: too_big,
            manifest: Sealed(vec![1]),
            live: false,
        },
    );
    assert!(matches!(&out[0].msg, ServerMsg::FileOfferRejected { .. }));
}

#[test]
fn a_low_disk_server_refuses_to_store_a_file() {
    let mut r = Relay::new();
    // Swap in a store whose free-disk probe sits right at the floor.
    let dir = std::env::temp_dir().join(format!("enclave-lowdisk-{}", std::process::id()));
    r.set_file_store(enclave_transport::FileStore::with_disk_probe(dir, || {
        enclave_transport::filestore::DISK_FREE_FLOOR
    }));
    let (a, _ah, _b, _bh, group) = two_member_group(&mut r);
    let out = r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id: [13u8; 16],
            group,
            size: 1024,
            manifest: Sealed(vec![1]),
            live: false,
        },
    );
    assert!(matches!(&out[0].msg, ServerMsg::FileOfferRejected { .. }));
}

#[test]
fn cancelling_an_offer_withdraws_it_from_recipients() {
    let mut r = Relay::new();
    let (a, _ah, b, _bh, group) = two_member_group(&mut r);
    let offer_id = [14u8; 16];
    r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id,
            group,
            size: 10,
            manifest: Sealed(vec![1]),
            live: false,
        },
    );
    r.handle(
        a,
        ClientMsg::FileChunk {
            offer_id,
            index: 0,
            data: Sealed(vec![1]),
        },
    );
    r.handle(a, ClientMsg::FileComplete { offer_id });

    let out = r.handle(a, ClientMsg::FileCancel { offer_id });
    assert!(
        out.iter()
            .any(|o| o.to == b && matches!(o.msg, ServerMsg::FileDeclined { .. })),
        "recipient told the offer is withdrawn"
    );
    assert!(
        r.handle(b, ClientMsg::FileAccept { offer_id }).is_empty(),
        "offer is gone"
    );
}

#[test]
fn a_non_member_cannot_offer_a_file_to_a_group() {
    let mut r = Relay::new();
    let (_a, _ah, _b, _bh, group) = two_member_group(&mut r);
    let (c, _ch) = register(&mut r, "c", vec![3]); // never joined the group
    let out = r.handle(
        c,
        ClientMsg::FileOffer {
            offer_id: [15u8; 16],
            group,
            size: 10,
            manifest: Sealed(vec![1]),
            live: false,
        },
    );
    assert!(out.is_empty(), "deny-by-default: a stranger cannot offer");
}

#[test]
fn a_chunk_from_someone_who_is_not_the_sender_is_ignored() {
    let mut r = Relay::new();
    let (a, _ah, b, _bh, group) = two_member_group(&mut r);
    let offer_id = [16u8; 16];
    r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id,
            group,
            size: 100,
            manifest: Sealed(vec![1]),
            live: false,
        },
    );
    // Bob is not the sender: his chunk must not be appended or relayed.
    let out = r.handle(
        b,
        ClientMsg::FileChunk {
            offer_id,
            index: 0,
            data: Sealed(vec![9, 9]),
        },
    );
    assert!(out.is_empty());
}

#[test]
fn a_spilled_message_reaches_the_recipient_on_reconnect() {
    // When an online recipient's live outbound is full, the server spills the
    // reliable message into their offline queue instead of dropping it; they
    // receive it on their next reconnect. Nothing is lost.
    let mut r = Relay::new();
    let (_a, ah, b, bh, group) = two_member_group(&mut r);
    let queued = r.spill_offline(
        b,
        ServerMsg::Text {
            group: group.clone(),
            from: DeviceId(ah.clone()),
            message: Sealed(vec![1, 2, 3]),
        },
    );
    assert!(queued, "spilled into the offline queue");
    // Bob's stuck connection drops; on reconnect he drains the spilled message.
    r.disconnect(b);
    let (_b2, finish) = login(&mut r, &bh, vec![2]);
    assert!(
        finish.iter().any(|o| matches!(
            &o.msg,
            ServerMsg::Text { message, .. } if message.0 == vec![1, 2, 3]
        )),
        "the spilled message is delivered on reconnect, not lost"
    );
}

#[test]
fn only_reliable_messages_spill() {
    use enclave_transport::relay::spillable;
    let group = GroupId([0u8; 32]);
    assert!(spillable(&ServerMsg::Text {
        group: group.clone(),
        from: DeviceId("a".into()),
        message: Sealed(vec![]),
    }));
    assert!(spillable(&ServerMsg::Mls {
        group: group.clone(),
        from: DeviceId("a".into()),
        message: Sealed(vec![]),
    }));
    // Latest-wins / real-time state is not spilled (dropping a stale one is fine).
    assert!(!spillable(&ServerMsg::Presence {
        user: UserId("a".into()),
        status: Presence::Online,
    }));
    assert!(!spillable(&ServerMsg::CallParticipants {
        group,
        participants: vec![],
    }));
}

#[test]
fn a_timed_out_live_recipient_is_dropped_and_the_sender_is_told() {
    // When the server gives up relaying a live chunk to a too-slow recipient, it
    // drops them from the stream (later chunks skip them) and tells the sender
    // precisely which offer did not reach them.
    let mut r = Relay::new();
    let (a, _ah, b, bh, group) = two_member_group(&mut r);
    let offer_id = [20u8; 16];
    r.handle(
        a,
        ClientMsg::FileOffer {
            offer_id,
            group,
            size: 0,
            manifest: Sealed(vec![1]),
            live: true,
        },
    );
    r.handle(b, ClientMsg::FileAccept { offer_id });

    let notify = r.drop_live_recipient(offer_id, b);
    assert!(
        notify.iter().any(
            |o| o.to == a && matches!(&o.msg, ServerMsg::FileDeclined { by, .. } if by.0 == bh)
        ),
        "the sender is told the recipient did not receive it"
    );
    // A later chunk no longer routes to the dropped recipient.
    let out = r.handle(
        a,
        ClientMsg::FileChunk {
            offer_id,
            index: 0,
            data: Sealed(vec![9]),
        },
    );
    assert!(
        out.is_empty(),
        "the dropped recipient no longer receives chunks"
    );
}

// --- Poll (ballot buffer) quotas: a member must not be able to spam the relay
// out of memory, nor stamp on another member's poll. ---

// Open a group containing `a` and `b`, returning it.
fn poll_group(r: &mut Relay, a: u64, bh: &str, tag: u8) -> GroupId {
    let group = GroupId([tag; 32]);
    r.handle(
        a,
        ClientMsg::JoinGroup {
            group: group.clone(),
        },
    );
    r.handle(
        a,
        ClientMsg::Welcome {
            to: DeviceId(bh.to_string()),
            name: String::new(),
            group: group.clone(),
            message: Sealed(vec![]),
        },
    );
    group
}

fn error_detail(out: &[Outgoing]) -> Option<String> {
    out.iter().find_map(|o| match &o.msg {
        ServerMsg::Error { detail } => Some(detail.clone()),
        _ => None,
    })
}

#[test]
fn reopening_a_poll_id_is_refused_and_cannot_discard_cast_ballots() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = poll_group(&mut r, a, &bh, 21);
    let poll = [1u8; 16];

    r.handle(
        a,
        ClientMsg::BallotOpen {
            poll,
            group: group.clone(),
            mode: 2,
            release_at: None,
        },
    );
    r.handle(
        b,
        ClientMsg::BallotSubmit {
            poll,
            ballot: Sealed(vec![9; 76]),
        },
    );

    // Bob re-opens Alice's poll id: refused, and Bob's cast ballot survives.
    let out = r.handle(
        b,
        ClientMsg::BallotOpen {
            poll,
            group: group.clone(),
            mode: 2,
            release_at: None,
        },
    );
    assert_eq!(
        error_detail(&out).as_deref(),
        Some("that poll is already open"),
        "a re-used poll id is refused with a clear reason"
    );

    // The owner closes: the ballot cast before the re-open attempt is still there.
    let out = r.handle(a, ClientMsg::BallotClose { poll });
    let released: usize = out
        .iter()
        .filter_map(|o| match &o.msg {
            ServerMsg::Ballots { ballots, .. } => Some(ballots.len()),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    assert_eq!(
        released, 1,
        "the ballot was not wiped by the re-open attempt"
    );
}

#[test]
fn one_device_cannot_open_unbounded_polls() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (_b, bh) = register(&mut r, "b", vec![2]);
    let group = poll_group(&mut r, a, &bh, 22);

    // Fill the per-device quota; every one of these is accepted.
    let mut opened = 0;
    for n in 0..64u16 {
        let mut poll = [0u8; 16];
        poll[..2].copy_from_slice(&n.to_le_bytes());
        let out = r.handle(
            a,
            ClientMsg::BallotOpen {
                poll,
                group: group.clone(),
                mode: 2,
                release_at: None,
            },
        );
        match error_detail(&out) {
            None => opened += 1,
            Some(detail) => {
                assert!(
                    detail.contains("too many open polls"),
                    "refusal explains the quota, got: {detail}"
                );
                assert!(opened > 0, "some polls were accepted before the cap");
                return; // the cap bit, with a clean error
            }
        }
    }
    panic!("the per-device poll quota never applied: opened {opened} polls unchecked");
}

#[test]
fn an_oversized_ballot_is_refused() {
    let mut r = Relay::new();
    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (b, bh) = register(&mut r, "b", vec![2]);
    let group = poll_group(&mut r, a, &bh, 23);
    let poll = [3u8; 16];
    r.handle(
        a,
        ClientMsg::BallotOpen {
            poll,
            group: group.clone(),
            mode: 2,
            release_at: None,
        },
    );

    // A real ballot is ~76 bytes; this is a memory-parking attempt.
    let out = r.handle(
        b,
        ClientMsg::BallotSubmit {
            poll,
            ballot: Sealed(vec![0; 64 * 1024]),
        },
    );
    assert_eq!(
        error_detail(&out).as_deref(),
        Some("that ballot is too large to accept"),
        "an oversized ballot is refused with a clear reason"
    );

    // A normal-sized ballot on the same poll is still accepted.
    let out = r.handle(
        b,
        ClientMsg::BallotSubmit {
            poll,
            ballot: Sealed(vec![1; 76]),
        },
    );
    assert!(error_detail(&out).is_none(), "a real ballot still works");
}

#[test]
fn an_abandoned_poll_is_reclaimed_and_frees_its_quota() {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    let mut r = Relay::new();
    let clock = Arc::new(Mutex::new(SystemTime::now()));
    let c = Arc::clone(&clock);
    r.set_clock(move || *c.lock().unwrap());

    let (a, _ah) = register(&mut r, "a", vec![1]);
    let (_b, bh) = register(&mut r, "b", vec![2]);
    let group = poll_group(&mut r, a, &bh, 24);
    let poll = [4u8; 16];

    // A poll with no deadline: only its owner could ever close it.
    r.handle(
        a,
        ClientMsg::BallotOpen {
            poll,
            group: group.clone(),
            mode: 2,
            release_at: None,
        },
    );
    // Nothing is due yet, so the sweep leaves it alone.
    r.sweep_ballots();
    let out = r.handle(
        a,
        ClientMsg::BallotOpen {
            poll,
            group: group.clone(),
            mode: 2,
            release_at: None,
        },
    );
    assert!(
        error_detail(&out).is_some(),
        "the poll is still open before the TTL"
    );

    // Long after it was abandoned, the relay reclaims it.
    *clock.lock().unwrap() += Duration::from_secs(31 * 24 * 60 * 60);
    r.sweep_ballots();
    let out = r.handle(
        a,
        ClientMsg::BallotOpen {
            poll,
            group,
            mode: 2,
            release_at: None,
        },
    );
    assert!(
        error_detail(&out).is_none(),
        "the abandoned poll was reclaimed, so its id and quota are free again"
    );
}
