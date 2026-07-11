//! Unit tests for the pure relay routing core (no network).

use enclave_protocol::{ClientMsg, DeviceId, GroupId, Sealed, ServerMsg, UserId};
use enclave_transport::Relay;

fn register(r: &mut Relay, user: &str, device: &str, kp: Vec<u8>) -> u64 {
    let conn = r.connect();
    r.handle(
        conn,
        ClientMsg::Register {
            user: UserId(user.into()),
            device: DeviceId(device.into()),
            identity_pub: vec![],
            key_package: kp,
        },
    );
    conn
}

#[test]
fn fetch_returns_a_published_key_package_once() {
    let mut r = Relay::new();
    let conn = register(&mut r, "u", "u1", vec![9, 9, 9]);

    let out = r.handle(conn, ClientMsg::FetchKeyPackages { user: UserId("u".into()) });
    assert_eq!(out.len(), 1);
    match &out[0].msg {
        ServerMsg::KeyPackages { packages, .. } => assert_eq!(packages, &vec![vec![9, 9, 9]]),
        other => panic!("expected KeyPackages, got {other:?}"),
    }

    // Single-use: a second fetch returns nothing.
    let out2 = r.handle(conn, ClientMsg::FetchKeyPackages { user: UserId("u".into()) });
    match &out2[0].msg {
        ServerMsg::KeyPackages { packages, .. } => assert!(packages.is_empty()),
        other => panic!("expected empty KeyPackages, got {other:?}"),
    }
}

#[test]
fn text_fans_out_to_other_members_only_and_relays_bytes_unchanged() {
    let mut r = Relay::new();
    let a = register(&mut r, "a", "a1", vec![1]);
    let b = register(&mut r, "b", "b1", vec![2]);
    let group = GroupId([5u8; 32]);
    r.handle(a, ClientMsg::JoinGroup { group: group.clone() });
    r.handle(b, ClientMsg::JoinGroup { group: group.clone() });

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
    let a = register(&mut r, "a", "a1", vec![1]);
    let b = register(&mut r, "b", "b1", vec![2]);
    let c = register(&mut r, "c", "c1", vec![3]);
    let group = GroupId([6u8; 32]);
    for conn in [a, b, c] {
        r.handle(conn, ClientMsg::JoinGroup { group: group.clone() });
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
    let a = register(&mut r, "a", "a1", vec![1]);
    let b = register(&mut r, "b", "b1", vec![2]);
    let group = GroupId([3u8; 32]);
    r.handle(a, ClientMsg::JoinGroup { group: group.clone() });

    // Alice welcomes Bob's device directly.
    let out = r.handle(
        a,
        ClientMsg::Welcome {
            to: DeviceId("b1".into()),
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
    let a = register(&mut r, "a", "a1", vec![1]);
    let b = register(&mut r, "b", "b1", vec![2]);
    let group = GroupId([8u8; 32]);
    r.handle(a, ClientMsg::JoinGroup { group: group.clone() });
    r.handle(b, ClientMsg::JoinGroup { group: group.clone() });

    r.disconnect(b);

    let out = r.handle(
        a,
        ClientMsg::Text {
            group,
            message: Sealed(vec![0]),
        },
    );
    assert!(out.is_empty(), "a disconnected device must not be routed to");
}
