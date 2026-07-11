//! Shared harness for transport integration tests: start a relay server and
//! bring two clients (Alice, Bob) into the same MLS group through it.
#![allow(dead_code)] // each test binary uses a subset of these helpers.

use std::time::Duration;

use enclave_crypto::{Group, Identity};
use enclave_protocol::{ClientMsg, DeviceId, GroupId, MediaFrame, Sealed, ServerMsg, UserId};
use enclave_transport::{serve, Connection};

/// App-level routing group id (independent of MLS's internal group id).
pub const GROUP: GroupId = GroupId([7u8; 32]);
pub const RECV_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn fetch_key_package(conn: &mut Connection, user: &str) -> Vec<u8> {
    for _ in 0..100 {
        conn.send(ClientMsg::FetchKeyPackages {
            user: UserId(user.into()),
        });
        match tokio::time::timeout(RECV_TIMEOUT, conn.recv()).await {
            Ok(Some(ServerMsg::KeyPackages { packages, .. })) => {
                if let Some(kp) = packages.into_iter().next() {
                    return kp;
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("connection closed while fetching key package"),
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no key package published for {user}");
}

pub async fn recv_welcome(conn: &mut Connection) -> Vec<u8> {
    loop {
        match tokio::time::timeout(RECV_TIMEOUT, conn.recv()).await {
            Ok(Some(ServerMsg::Welcome { message, .. })) => return message.0,
            Ok(Some(_)) => continue,
            Ok(None) => panic!("connection closed before Welcome"),
            Err(_) => panic!("timed out waiting for Welcome"),
        }
    }
}

pub async fn recv_text(conn: &mut Connection) -> Vec<u8> {
    loop {
        match tokio::time::timeout(RECV_TIMEOUT, conn.recv()).await {
            Ok(Some(ServerMsg::Text { message, .. })) => return message.0,
            Ok(Some(_)) => continue,
            Ok(None) => panic!("connection closed before Text"),
            Err(_) => panic!("timed out waiting for Text"),
        }
    }
}

pub async fn recv_media(conn: &mut Connection) -> MediaFrame {
    loop {
        match tokio::time::timeout(RECV_TIMEOUT, conn.recv()).await {
            Ok(Some(ServerMsg::Media(frame))) => return frame,
            Ok(Some(_)) => continue,
            Ok(None) => panic!("connection closed before Media"),
            Err(_) => panic!("timed out waiting for Media"),
        }
    }
}

/// Two clients in one MLS group, formed through a live relay server.
pub struct Established {
    pub alice: Identity,
    pub bob: Identity,
    pub alice_group: Group,
    pub bob_group: Group,
    pub alice_conn: Connection,
    pub bob_conn: Connection,
}

/// Start a server, connect Alice and Bob, register both, and add Bob to a group
/// via a Welcome relayed through the server. Returns everything the caller needs
/// to exchange messages.
pub async fn establish() -> Established {
    let handle = serve("127.0.0.1:0").await.expect("bind server");
    let url = format!("ws://{}", handle.addr);

    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");

    let mut alice_conn = Connection::connect(&url).await.expect("alice connects");
    let mut bob_conn = Connection::connect(&url).await.expect("bob connects");

    alice_conn.send(ClientMsg::Register {
        user: UserId("alice".into()),
        device: DeviceId("alice-1".into()),
        identity_pub: alice.identity_key(),
        key_package: alice.new_key_package().expect("alice kp"),
    });
    bob_conn.send(ClientMsg::Register {
        user: UserId("bob".into()),
        device: DeviceId("bob-1".into()),
        identity_pub: bob.identity_key(),
        key_package: bob.new_key_package().expect("bob kp"),
    });

    let bob_kp = fetch_key_package(&mut alice_conn, "bob").await;

    let mut alice_group = Group::create(&alice).expect("create group");
    alice_conn.send(ClientMsg::JoinGroup { group: GROUP });
    let welcome = alice_group.add_member(&alice, &bob_kp).expect("add bob");
    alice_conn.send(ClientMsg::Welcome {
        to: DeviceId("bob-1".into()),
        group: GROUP,
        message: Sealed(welcome),
    });

    let welcome_bytes = recv_welcome(&mut bob_conn).await;
    let bob_group = Group::join(&bob, &welcome_bytes).expect("bob joins");
    bob_conn.send(ClientMsg::JoinGroup { group: GROUP });

    Established {
        alice,
        bob,
        alice_group,
        bob_group,
        alice_conn,
        bob_conn,
    }
}
