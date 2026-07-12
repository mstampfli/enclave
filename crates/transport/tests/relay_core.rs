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
    let upload = state.finish(password, &response).expect("register finish");
    let finish = r.handle(
        conn,
        ClientMsg::RegisterFinish {
            upload,
            identity_pub: vec![],
            key_package: kp,
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

#[test]
fn fetch_returns_a_published_key_package_once() {
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

    // Single-use: a second fetch returns nothing.
    let out2 = r.handle(conn, ClientMsg::FetchKeyPackages { user: UserId(h) });
    match &out2[0].msg {
        ServerMsg::KeyPackages { packages, .. } => assert!(packages.is_empty()),
        other => panic!("expected empty KeyPackages, got {other:?}"),
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
