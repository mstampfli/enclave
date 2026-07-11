//! The Enclave client controller: the high-level app-logic API the UI drives.
//!
//! Flow: `connect` opens the socket, then `create_account` or `login`
//! authenticates (username + password, no email). Once logged in, the caller
//! can start/join groups, invite friends, send text, watch presence, and pump
//! events. The identity key is persisted per account on this device, so logging
//! back in restores the same identity (and safety number).
//!
//! Single-task and caller-driven: there is no background task, so the non-`Send`
//! MLS group never crosses a thread boundary.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use enclave_crypto::{Group, Identity};
use enclave_protocol::{ClientMsg, DeviceId, GroupId, Presence, Sealed, ServerMsg, UserId};
use enclave_transport::Connection;

/// Errors surfaced to the UI.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("crypto: {0}")]
    Crypto(#[from] enclave_crypto::CryptoError),
    #[error("transport: {0}")]
    Transport(#[from] enclave_transport::TransportError),
    #[error("{0}")]
    Auth(String),
    #[error("not logged in")]
    NotLoggedIn,
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
    /// A watched friend's presence changed ("online" / "away" / "offline").
    Presence { user: String, status: String },
    /// A non-fatal error worth showing.
    Error(String),
}

fn presence_label(status: Presence) -> String {
    match status {
        Presence::Online => "online",
        Presence::Away => "away",
        Presence::Offline => "offline",
    }
    .to_string()
}

/// One connected session. Unauthenticated until `create_account`/`login`.
pub struct Client {
    conn: Connection,
    identity: Option<Identity>,
    username: Option<String>,
    keystore_dir: PathBuf,
    group: Option<Group>,
    group_id: Option<GroupId>,
    pending: VecDeque<Event>,
    friends: Vec<UserId>,
    roster_path: Option<PathBuf>,
}

impl Client {
    /// Open a connection to a server. Not authenticated yet.
    pub async fn connect(server_url: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(server_url).await?;
        Ok(Self {
            conn,
            identity: None,
            username: None,
            keystore_dir: PathBuf::from("."),
            group: None,
            group_id: None,
            pending: VecDeque::new(),
            friends: Vec::new(),
            roster_path: None,
        })
    }

    /// Where identity key files and rosters are stored (default: current dir).
    pub fn set_keystore_dir(&mut self, dir: impl Into<PathBuf>) {
        self.keystore_dir = dir.into();
    }

    /// Create a new account (username + password, no email) and log in. The new
    /// identity is generated and saved to this device.
    pub async fn create_account(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<(), ClientError> {
        let identity = Identity::generate(username)?;
        let _ = identity.save(&self.identity_path(username));
        let key_package = identity.new_key_package()?;
        self.conn.send(ClientMsg::CreateAccount {
            username: username.to_string(),
            password: password.to_string(),
            identity_pub: identity.identity_key(),
            key_package,
        });
        self.await_auth().await?;
        self.finish_login(identity, username);
        Ok(())
    }

    /// Log in to an existing account, restoring the saved identity on this
    /// device (a fresh one is generated if none is saved here).
    pub async fn login(&mut self, username: &str, password: &str) -> Result<(), ClientError> {
        let identity = Identity::load(username, &self.identity_path(username))
            .or_else(|_| Identity::generate(username))?;
        let key_package = identity.new_key_package()?;
        self.conn.send(ClientMsg::Login {
            username: username.to_string(),
            password: password.to_string(),
            key_package,
        });
        self.await_auth().await?;
        let _ = identity.save(&self.identity_path(username));
        self.finish_login(identity, username);
        Ok(())
    }

    /// End the session: go offline and forget the group.
    pub fn logout(&mut self) {
        self.conn.send(ClientMsg::Logout);
        self.identity = None;
        self.username = None;
        self.group = None;
        self.group_id = None;
        self.friends.clear();
        self.roster_path = None;
    }

    fn finish_login(&mut self, identity: Identity, username: &str) {
        self.identity = Some(identity);
        self.username = Some(username.to_string());
    }

    /// Pump messages until the auth result arrives; queue any other events.
    async fn await_auth(&mut self) -> Result<(), ClientError> {
        loop {
            match tokio::time::timeout(Duration::from_secs(10), self.conn.recv()).await {
                Ok(Some(ServerMsg::Auth { ok: true, .. })) => return Ok(()),
                Ok(Some(ServerMsg::Auth {
                    ok: false, detail, ..
                })) => return Err(ClientError::Auth(detail)),
                Ok(Some(other)) => {
                    if let Some(event) = self.handle(other) {
                        self.pending.push_back(event);
                    }
                }
                Ok(None) => return Err(ClientError::Disconnected),
                Err(_) => return Err(ClientError::Auth("server did not respond".into())),
            }
        }
    }

    fn identity_path(&self, username: &str) -> PathBuf {
        self.keystore_dir.join(format!("enclave-{username}.id"))
    }

    fn identity(&self) -> Result<&Identity, ClientError> {
        self.identity.as_ref().ok_or(ClientError::NotLoggedIn)
    }

    /// The logged-in username, or "" if not logged in.
    pub fn name(&self) -> &str {
        self.username.as_deref().unwrap_or("")
    }

    /// Whether we are logged in.
    pub fn is_logged_in(&self) -> bool {
        self.identity.is_some()
    }

    /// Manually set our presence (e.g. Away, or back to Online).
    pub fn set_status(&self, status: Presence) {
        self.conn.send(ClientMsg::Presence { status });
    }

    /// The current friends roster.
    pub fn friends(&self) -> &[UserId] {
        &self.friends
    }

    /// Point the client at a JSON roster file: load any existing friends, watch
    /// their presence, and auto-save on future changes.
    pub fn use_roster_file(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(names) = serde_json::from_str::<Vec<String>>(&text) {
                self.friends = names.into_iter().map(UserId).collect();
            }
        }
        if !self.friends.is_empty() {
            self.conn.send(ClientMsg::WatchPresence {
                users: self.friends.clone(),
            });
        }
        self.roster_path = Some(path);
    }

    /// Add a friend, watch their presence, and persist the roster.
    pub fn add_friend(&mut self, user: &str) {
        let user = UserId(user.to_string());
        if self.friends.contains(&user) {
            return;
        }
        self.friends.push(user.clone());
        self.conn
            .send(ClientMsg::WatchPresence { users: vec![user] });
        self.save_roster();
    }

    fn save_roster(&self) {
        let Some(path) = &self.roster_path else {
            return;
        };
        let names: Vec<&str> = self.friends.iter().map(|u| u.0.as_str()).collect();
        if let Ok(text) = serde_json::to_string_pretty(&names) {
            let _ = std::fs::write(path, text);
        }
    }

    /// Start a fresh group that we own. The routing id is derived from our
    /// identity key (unique per user).
    pub fn start_group(&mut self) -> Result<(), ClientError> {
        let identity = self.identity()?;
        let group = Group::create(identity)?;
        let group_id = derive_group_id(identity);
        self.conn.send(ClientMsg::JoinGroup {
            group: group_id.clone(),
        });
        self.group = Some(group);
        self.group_id = Some(group_id);
        Ok(())
    }

    /// Invite a peer by name: fetch their key package, add them, and deliver the
    /// Welcome (plus the commit for existing members) through the server.
    pub async fn invite(&mut self, peer: &str) -> Result<(), ClientError> {
        let group_id = self.group_id.clone().ok_or(ClientError::NoGroup)?;
        let key_package = self.fetch_key_package(peer).await?;

        let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let group = self.group.as_mut().ok_or(ClientError::NoGroup)?;
        let add = group.add_member(identity, &key_package)?;

        self.conn.send(ClientMsg::Welcome {
            to: DeviceId(peer.into()),
            group: group_id.clone(),
            message: Sealed(add.welcome),
        });
        self.conn.send(ClientMsg::Mls {
            group: group_id,
            message: Sealed(add.commit),
        });
        Ok(())
    }

    /// Encrypt and send a text message to the group.
    pub async fn send_text(&mut self, text: &str) -> Result<(), ClientError> {
        let group_id = self.group_id.clone().ok_or(ClientError::NoGroup)?;
        let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let group = self.group.as_mut().ok_or(ClientError::NoGroup)?;
        let sealed = group.encrypt_text(identity, text.as_bytes())?;
        self.conn.send(ClientMsg::Text {
            group: group_id,
            message: Sealed(sealed),
        });
        Ok(())
    }

    /// The group's safety number, if we are in a group.
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

    /// Fetch a peer's key package, retrying until their registration lands.
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
                        break;
                    }
                    Ok(Some(other)) => {
                        if let Some(event) = self.handle(other) {
                            self.pending.push_back(event);
                        }
                    }
                    Ok(None) => return Err(ClientError::Disconnected),
                    Err(_) => break,
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
                let identity = self.identity.as_ref()?;
                match Group::join(identity, &message.0) {
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
                let identity = self.identity.as_ref()?;
                let group = self.group.as_mut()?;
                match group.decrypt_text(identity, &message.0) {
                    Ok(tm) => Some(Event::Text {
                        from: String::from_utf8_lossy(&tm.sender).into_owned(),
                        text: String::from_utf8_lossy(&tm.plaintext).into_owned(),
                    }),
                    Err(e) => Some(Event::Error(format!("decrypt failed: {e}"))),
                }
            }
            ServerMsg::Mls { message, .. } => {
                let identity = self.identity.as_ref()?;
                let group = self.group.as_mut()?;
                match group.apply_commit(identity, &message.0) {
                    Ok(()) => Some(Event::MembershipChanged),
                    Err(_) => None,
                }
            }
            ServerMsg::Presence { user, status } => Some(Event::Presence {
                user: user.0,
                status: presence_label(status),
            }),
            ServerMsg::Auth { .. } => None,
            ServerMsg::Error { detail } => Some(Event::Error(detail)),
            _ => None,
        }
    }
}

/// Routing group id derived from a 32-byte Ed25519 identity key.
fn derive_group_id(identity: &Identity) -> GroupId {
    let key = identity.identity_key();
    let mut id = [0u8; 32];
    let n = key.len().min(32);
    id[..n].copy_from_slice(&key[..n]);
    GroupId(id)
}
