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
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, b);
    assert!(matches!(out[0].msg, ServerMsg::Welcome { .. }));

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
