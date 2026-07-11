//! The Enclave client controller: the high-level app-logic API the UI drives.
//!
//! It composes identity + crypto + transport into a small surface -- connect,
//! start or join a group, invite a friend, send text, read the safety number,
//! and pump events -- so the window (or a test) never touches the wire types or
//! the MLS machinery directly.
//!
//! The design is single-task and caller-driven: the owner calls async methods
//! and pumps [`Client::next_event`]; there is no background task, so the
//! non-`Send` MLS group never has to cross a thread boundary.

use std::collections::VecDeque;
use std::time::Duration;

use enclave_crypto::{Group, Identity};
use enclave_protocol::{ClientMsg, DeviceId, GroupId, Sealed, ServerMsg, UserId};
use enclave_transport::Connection;

/// Errors surfaced to the UI.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("crypto: {0}")]
    Crypto(#[from] enclave_crypto::CryptoError),
    #[error("transport: {0}")]
    Transport(#[from] enclave_transport::TransportError),
    #[error("not in a group yet")]
    NoGroup,
    #[error("no key package available for that peer")]
    NoKeyPackage,
    #[error("disconnected from server")]
    Disconnected,
}

/// Something the UI should react to.
#[derive(Debug, Clone)]
pub enum Event {
    /// A text message arrived from `from`.
    Text { from: String, text: String },
    /// Group membership changed (someone joined, or we joined).
    MembershipChanged,
    /// A non-fatal error worth showing.
    Error(String),
}

/// One connected user session. One device, one group (for now).
pub struct Client {
    identity: Identity,
    conn: Connection,
    name: String,
    group: Option<Group>,
    group_id: Option<GroupId>,
    pending: VecDeque<Event>,
}

impl Client {
    /// Connect to a server and register under `name` (one device per user for
    /// now; the device id is the name).
    pub async fn connect(server_url: &str, name: &str) -> Result<Self, ClientError> {
        let identity = Identity::generate(name)?;
        let conn = Connection::connect(server_url).await?;
        conn.send(ClientMsg::Register {
            user: UserId(name.into()),
            device: DeviceId(name.into()),
            identity_pub: identity.identity_key(),
            key_package: identity.new_key_package()?,
        });
        Ok(Self {
            identity,
            conn,
            name: name.into(),
            group: None,
            group_id: None,
            pending: VecDeque::new(),
        })
    }

    /// Our display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Start a fresh group that we own. The routing id is derived from our
    /// identity key (unique per user).
    pub fn start_group(&mut self) -> Result<(), ClientError> {
        let group = Group::create(&self.identity)?;
        let group_id = self.derive_group_id();
        self.conn.send(ClientMsg::JoinGroup {
            group: group_id.clone(),
        });
        self.group = Some(group);
        self.group_id = Some(group_id);
        Ok(())
    }

    /// Invite a peer by name: fetch their key package, add them, and deliver the
    /// Welcome (plus the commit for any existing members) through the server.
    pub async fn invite(&mut self, peer: &str) -> Result<(), ClientError> {
        let group_id = self.group_id.clone().ok_or(ClientError::NoGroup)?;
        let key_package = self.fetch_key_package(peer).await?;

        let group = self.group.as_mut().ok_or(ClientError::NoGroup)?;
        let add = group.add_member(&self.identity, &key_package)?;

        self.conn.send(ClientMsg::Welcome {
            to: DeviceId(peer.into()),
            group: group_id.clone(),
            message: Sealed(add.welcome),
        });
        // Fan the commit out to any pre-existing members. A just-added member
        // also receives it but cannot apply it (already at that epoch), which is
        // benign and ignored on their side.
        self.conn.send(ClientMsg::Mls {
            group: group_id,
            message: Sealed(add.commit),
        });
        Ok(())
    }

    /// Encrypt and send a text message to the group.
    pub async fn send_text(&mut self, text: &str) -> Result<(), ClientError> {
        let group_id = self.group_id.clone().ok_or(ClientError::NoGroup)?;
        let group = self.group.as_mut().ok_or(ClientError::NoGroup)?;
        let sealed = group.encrypt_text(&self.identity, text.as_bytes())?;
        self.conn.send(ClientMsg::Text {
            group: group_id,
            message: Sealed(sealed),
        });
        Ok(())
    }

    /// The group's safety number, if we are in a group. Compare it out-of-band
    /// with peers to confirm no ghost member was inserted.
    pub fn safety_number(&self) -> Option<String> {
        self.group.as_ref().map(|g| g.safety_number().to_string())
    }

    /// Await the next event, processing incoming server messages until one
    /// produces something the UI cares about. Returns `None` if disconnected.
    pub async fn next_event(&mut self) -> Option<Event> {
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        loop {
            let msg = self.conn.recv().await?;
            if let Some(event) = self.handle(msg) {
                return Some(event);
            }
        }
    }

    /// Routing group id derived from our 32-byte Ed25519 identity key.
    fn derive_group_id(&self) -> GroupId {
        let key = self.identity.identity_key();
        let mut id = [0u8; 32];
        let n = key.len().min(32);
        id[..n].copy_from_slice(&key[..n]);
        GroupId(id)
    }

    /// Fetch a peer's key package, retrying until their registration lands and
    /// queueing any events that arrive meanwhile.
    async fn fetch_key_package(&mut self, peer: &str) -> Result<Vec<u8>, ClientError> {
        for _ in 0..100 {
            self.conn.send(ClientMsg::FetchKeyPackages {
                user: UserId(peer.into()),
            });
            loop {
                match tokio::time::timeout(Duration::from_millis(200), self.conn.recv()).await {
                    Ok(Some(ServerMsg::KeyPackages { packages, .. })) => {
                        if let Some(kp) = packages.into_iter().next() {
                            return Ok(kp);
                        }
                        break; // empty; retry after a short wait
                    }
                    Ok(Some(other)) => {
                        if let Some(event) = self.handle(other) {
                            self.pending.push_back(event);
                        }
                    }
                    Ok(None) => return Err(ClientError::Disconnected),
                    Err(_) => break, // timed out; retry
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Err(ClientError::NoKeyPackage)
    }

    /// Turn one server message into an optional UI event, updating group state.
    fn handle(&mut self, msg: ServerMsg) -> Option<Event> {
        match msg {
            ServerMsg::Welcome { group, message, .. } => {
                match Group::join(&self.identity, &message.0) {
                    Ok(joined) => {
                        self.group = Some(joined);
                        self.group_id = Some(group.clone());
                        self.conn.send(ClientMsg::JoinGroup { group });
                        Some(Event::MembershipChanged)
                    }
                    Err(e) => Some(Event::Error(format!("join failed: {e}"))),
                }
            }
            ServerMsg::Text { message, .. } => {
                let group = self.group.as_mut()?;
                match group.decrypt_text(&self.identity, &message.0) {
                    Ok(tm) => Some(Event::Text {
                        from: String::from_utf8_lossy(&tm.sender).into_owned(),
                        text: String::from_utf8_lossy(&tm.plaintext).into_owned(),
                    }),
                    Err(e) => Some(Event::Error(format!("decrypt failed: {e}"))),
                }
            }
            ServerMsg::Mls { message, .. } => {
                let group = self.group.as_mut()?;
                // Pre-existing members advance; a member who just joined via a
                // Welcome gets its own add-commit echoed and cannot apply it,
                // which is benign and ignored.
                match group.apply_commit(&self.identity, &message.0) {
                    Ok(()) => Some(Event::MembershipChanged),
                    Err(_) => None,
                }
            }
            ServerMsg::Error { detail } => Some(Event::Error(detail)),
            _ => None,
        }
    }
}
