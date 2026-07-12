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

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::Duration;

use enclave_crypto::{Group, Identity};
use enclave_protocol::{ClientMsg, DeviceId, Friend, GroupId, Presence, Sealed, ServerMsg, UserId};
use enclave_transport::accounts::MIN_PASSWORD_LEN;
use enclave_transport::{opaque, Connection};
use sha2::{Digest, Sha256};

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
    /// A text message arrived in conversation `conv` (hex group id).
    Message {
        conv: String,
        from: String,
        text: String,
        mine: bool,
    },
    /// The set of conversations changed (a DM or group was created or joined);
    /// the UI re-reads them via `conversations()`.
    ConversationsChanged,
    /// A watched friend's presence changed ("online" / "away" / "offline").
    Presence { user: String, status: String },
    /// Someone sent us a friend request (their full handle).
    FriendRequest { from: String },
    /// The friends list or pending requests changed; read them via the getters.
    FriendsChanged,
    /// A non-fatal error worth showing.
    Error(String),
}

/// Whether a conversation is a 1:1 DM or a named group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConvKind {
    Dm,
    Group,
}

/// A conversation summary handed to the UI.
#[derive(Clone)]
pub struct ConversationInfo {
    /// Hex group id (stable conversation key).
    pub id: String,
    pub title: String,
    pub is_dm: bool,
    pub members: Vec<String>,
    /// A DM whose MLS group is not established yet (waiting on the peer).
    pub pending: bool,
}

/// One live conversation and its scoped history.
struct Conversation {
    /// `None` while a DM we initiated waits for the peer (smaller handle) to
    /// create the MLS group and send us the Welcome.
    group: Option<Group>,
    kind: ConvKind,
    title: String,
    members: Vec<String>,
    history: Vec<ChatLine>,
}

#[derive(Clone)]
struct ChatLine {
    from: String,
    text: String,
    mine: bool,
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
    /// All live conversations, keyed by routing group id.
    conversations: HashMap<GroupId, Conversation>,
    /// The conversation currently shown / targeted by send_text.
    active: Option<GroupId>,
    pending: VecDeque<Event>,
    /// Our own display name (cosmetic; the username is the unique id).
    display: String,
    /// Accepted friends and pending requests, mirrored from the server.
    friends: Vec<Friend>,
    incoming: Vec<Friend>,
    outgoing: Vec<Friend>,
    /// username -> current display name, learned from friend snapshots.
    display_names: HashMap<String, String>,
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
            conversations: HashMap::new(),
            active: None,
            pending: VecDeque::new(),
            display: String::new(),
            friends: Vec::new(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            display_names: HashMap::new(),
        })
    }

    /// Where identity key files and rosters are stored (default: current dir).
    pub fn set_keystore_dir(&mut self, dir: impl Into<PathBuf>) {
        self.keystore_dir = dir.into();
    }

    /// Create a new account from a display `name` and log in via OPAQUE: the
    /// password is used only locally and never sent to the server. The server
    /// assigns a full `name#1234` handle; the new identity is bound to it and
    /// saved (encrypted) to this device.
    pub async fn create_account(
        &mut self,
        username: &str,
        display: &str,
        password: &str,
    ) -> Result<(), ClientError> {
        // The zero-knowledge server cannot measure the password, so the policy
        // is enforced here.
        if password.len() < MIN_PASSWORD_LEN {
            return Err(ClientError::Auth(format!(
                "password must be at least {MIN_PASSWORD_LEN} characters"
            )));
        }
        // OPAQUE registration (2 round-trips). The password stays in this method.
        let (request, reg_state) = opaque::client_register_start(password)
            .map_err(|e| ClientError::Auth(e.to_string()))?;
        self.conn.send(ClientMsg::RegisterStart {
            name: username.to_string(),
            request,
        });
        // The server confirms our unique username; bind the identity to it.
        let (handle, response) = self.await_register_response().await?;

        let identity = Identity::generate(&handle)?;
        let _ = identity.save(&self.identity_path(&handle), password);
        let key_package = identity.new_key_package()?;
        let upload = reg_state
            .finish(password, &response)
            .map_err(|e| ClientError::Auth(e.to_string()))?;
        self.conn.send(ClientMsg::RegisterFinish {
            upload,
            identity_pub: identity.identity_key(),
            key_package,
            display: display.to_string(),
        });
        let server_display = self.await_auth().await?;
        self.finish_login(identity, &handle, server_display);
        Ok(())
    }

    /// Log in to an existing account by full `handle` (`name#1234`) via OPAQUE,
    /// restoring the saved identity on this device (a fresh one is generated if
    /// none is saved here). The password never leaves this device.
    pub async fn login(&mut self, handle: &str, password: &str) -> Result<(), ClientError> {
        let identity = Identity::load(handle, &self.identity_path(handle), password)
            .or_else(|_| Identity::generate(handle))?;
        let key_package = identity.new_key_package()?;

        // OPAQUE login (2 round-trips): prove knowledge of the password without
        // sending it. A wrong password fails the client-side finish below.
        let (request, login_state) =
            opaque::client_login_start(password).map_err(|e| ClientError::Auth(e.to_string()))?;
        self.conn.send(ClientMsg::LoginStart {
            handle: handle.to_string(),
            request,
        });
        let response = self.await_login_response().await?;
        let finalization = login_state
            .finish(password, &response)
            .map_err(|_| ClientError::Auth("wrong handle or password".into()))?;
        self.conn.send(ClientMsg::LoginFinish {
            finalization,
            key_package,
        });
        let server_display = self.await_auth().await?;
        let _ = identity.save(&self.identity_path(handle), password);
        self.finish_login(identity, handle, server_display);
        Ok(())
    }

    /// End the session: go offline and forget the group.
    pub fn logout(&mut self) {
        self.conn.send(ClientMsg::Logout);
        self.identity = None;
        self.username = None;
        self.conversations.clear();
        self.active = None;
        self.display.clear();
        self.friends.clear();
        self.incoming.clear();
        self.outgoing.clear();
        self.display_names.clear();
    }

    fn finish_login(&mut self, identity: Identity, username: &str, display: String) {
        self.identity = Some(identity);
        self.username = Some(username.to_string());
        let display = if display.trim().is_empty() {
            username.to_string()
        } else {
            display
        };
        self.display_names
            .insert(username.to_string(), display.clone());
        self.display = display;
    }

    /// Pump messages until the auth result arrives; queue any other events.
    /// Returns the server's stored display name for us on success.
    async fn await_auth(&mut self) -> Result<String, ClientError> {
        loop {
            match tokio::time::timeout(Duration::from_secs(10), self.conn.recv()).await {
                Ok(Some(ServerMsg::Auth {
                    ok: true, display, ..
                })) => return Ok(display),
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

    /// Pump messages until the OPAQUE registration response arrives. A failure
    /// (e.g. username taken) comes back as an `Auth { ok: false }` instead.
    async fn await_register_response(&mut self) -> Result<(String, Vec<u8>), ClientError> {
        loop {
            match tokio::time::timeout(Duration::from_secs(10), self.conn.recv()).await {
                Ok(Some(ServerMsg::RegisterResponse { handle, response })) => {
                    return Ok((handle, response))
                }
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

    /// Pump messages until the OPAQUE login (credential) response arrives. A
    /// rejection (e.g. lockout) comes back as an `Auth { ok: false }` instead.
    async fn await_login_response(&mut self) -> Result<Vec<u8>, ClientError> {
        loop {
            match tokio::time::timeout(Duration::from_secs(10), self.conn.recv()).await {
                Ok(Some(ServerMsg::LoginResponse { response })) => return Ok(response),
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

    fn identity_path(&self, handle: &str) -> PathBuf {
        // '#' is filename-legal on Windows but noisy; keep the keystore tidy.
        let safe = handle.replace('#', "-");
        self.keystore_dir.join(format!("enclave-{safe}.id"))
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

    /// Our own display name.
    pub fn display_name(&self) -> &str {
        &self.display
    }

    /// The display name for a username (falls back to the username).
    pub fn display_of(&self, username: &str) -> String {
        self.display_names
            .get(username)
            .cloned()
            .unwrap_or_else(|| username.to_string())
    }

    /// Accepted friends (username + display), mirrored from the server.
    pub fn friends(&self) -> &[Friend] {
        &self.friends
    }

    /// Incoming friend requests awaiting our accept/decline.
    pub fn incoming_requests(&self) -> &[Friend] {
        &self.incoming
    }

    /// Friend requests we have sent that are not yet accepted.
    pub fn outgoing_requests(&self) -> &[Friend] {
        &self.outgoing
    }

    /// Change our display name (cosmetic); friends are notified by the server.
    pub fn set_display_name(&mut self, display: &str) {
        self.display = display.to_string();
        if let Some(u) = self.username.clone() {
            self.display_names.insert(u, display.to_string());
        }
        self.conn.send(ClientMsg::SetDisplayName {
            display: display.to_string(),
        });
    }

    /// Send a friend request to a unique username. If they had already requested
    /// us, the server makes us friends immediately.
    pub fn send_friend_request(&self, handle: &str) {
        self.conn.send(ClientMsg::FriendRequest {
            to: handle.to_string(),
        });
    }

    /// Accept a pending incoming request from `handle`.
    pub fn accept_friend(&self, handle: &str) {
        self.conn.send(ClientMsg::FriendAccept {
            from: handle.to_string(),
        });
    }

    /// Decline an incoming request from, or cancel an outgoing request to, `handle`.
    pub fn decline_friend(&self, handle: &str) {
        self.conn.send(ClientMsg::FriendDecline {
            who: handle.to_string(),
        });
    }

    /// Remove an existing friend.
    pub fn remove_friend(&self, handle: &str) {
        self.conn.send(ClientMsg::FriendRemove {
            handle: handle.to_string(),
        });
    }

    /// Ask the server for the current friends + pending-requests snapshot.
    pub fn refresh_friends(&self) {
        self.conn.send(ClientMsg::ListFriends);
    }

    /// Open (or focus) a 1:1 DM with a friend. The lexicographically-smaller
    /// handle is the canonical creator of the shared MLS group; if we are the
    /// larger handle we nudge them to create it and show a pending conversation
    /// until their Welcome arrives. Returns the conversation id (hex).
    pub async fn open_dm(&mut self, friend: &str) -> Result<String, ClientError> {
        let me = self.me()?;
        let dm_id = derive_dm_id(&me, friend);
        if self.conversations.contains_key(&dm_id) {
            self.active = Some(dm_id.clone());
            return Ok(hex_id(&dm_id));
        }
        if me.as_str() < friend {
            // We create the group and invite them.
            let identity = self.identity()?;
            let group = Group::create(identity)?;
            self.conn.send(ClientMsg::JoinGroup {
                group: dm_id.clone(),
            });
            self.conversations.insert(
                dm_id.clone(),
                Conversation {
                    group: Some(group),
                    kind: ConvKind::Dm,
                    title: friend.to_string(),
                    members: vec![me, friend.to_string()],
                    history: Vec::new(),
                },
            );
            self.invite_peer(&dm_id, friend, "").await?;
        } else {
            // They are the creator; ask them to open it, and show it as pending.
            self.conn.send(ClientMsg::RequestDm {
                to: friend.to_string(),
            });
            self.conversations.insert(
                dm_id.clone(),
                Conversation {
                    group: None,
                    kind: ConvKind::Dm,
                    title: friend.to_string(),
                    members: vec![me, friend.to_string()],
                    history: Vec::new(),
                },
            );
        }
        self.active = Some(dm_id.clone());
        Ok(hex_id(&dm_id))
    }

    /// Create a named group with `members` (full handles) and focus it. We own
    /// the MLS group; a fresh random routing id keeps it distinct from any DM.
    pub async fn create_group(
        &mut self,
        name: &str,
        members: &[String],
    ) -> Result<String, ClientError> {
        let me = self.me()?;
        let identity = self.identity()?;
        let group = Group::create(identity)?;
        let group_id = random_group_id();
        self.conn.send(ClientMsg::JoinGroup {
            group: group_id.clone(),
        });
        self.conversations.insert(
            group_id.clone(),
            Conversation {
                group: Some(group),
                kind: ConvKind::Group,
                title: name.to_string(),
                members: vec![me],
                history: Vec::new(),
            },
        );
        for member in members {
            self.invite_peer(&group_id, member, name).await?;
        }
        self.active = Some(group_id.clone());
        Ok(hex_id(&group_id))
    }

    /// Add a friend to the active named group (no effect on a DM -- to grow a
    /// DM, create a new group instead).
    pub async fn add_to_active_group(&mut self, friend: &str) -> Result<(), ClientError> {
        let group_id = self.active.clone().ok_or(ClientError::NoGroup)?;
        let name = {
            let conv = self
                .conversations
                .get(&group_id)
                .ok_or(ClientError::NoGroup)?;
            if conv.kind != ConvKind::Group {
                return Err(ClientError::NoGroup);
            }
            conv.title.clone()
        };
        self.invite_peer(&group_id, friend, &name).await
    }

    /// Fetch `friend`'s key package, add them to the conversation's MLS group,
    /// and deliver the Welcome (with the conversation `name`) plus the commit.
    async fn invite_peer(
        &mut self,
        group_id: &GroupId,
        friend: &str,
        name: &str,
    ) -> Result<(), ClientError> {
        let key_package = self.fetch_key_package(friend).await?;
        let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let conv = self
            .conversations
            .get_mut(group_id)
            .ok_or(ClientError::NoGroup)?;
        let group = conv.group.as_mut().ok_or(ClientError::NoGroup)?;
        let add = group.add_member(identity, &key_package)?;
        if !conv.members.iter().any(|m| m == friend) {
            conv.members.push(friend.to_string());
        }
        self.conn.send(ClientMsg::Welcome {
            to: DeviceId(friend.into()),
            group: group_id.clone(),
            name: name.to_string(),
            message: Sealed(add.welcome),
        });
        self.conn.send(ClientMsg::Mls {
            group: group_id.clone(),
            message: Sealed(add.commit),
        });
        Ok(())
    }

    /// Focus a conversation by its hex id.
    pub fn switch(&mut self, conv: &str) {
        if let Some(id) = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()
        {
            self.active = Some(id);
        }
    }

    /// Encrypt and send a text message to the active conversation. Also records
    /// it in that conversation's local history.
    pub async fn send_text(&mut self, text: &str) -> Result<(), ClientError> {
        let group_id = self.active.clone().ok_or(ClientError::NoGroup)?;
        let me = self.me()?;
        let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let conv = self
            .conversations
            .get_mut(&group_id)
            .ok_or(ClientError::NoGroup)?;
        let group = conv.group.as_mut().ok_or(ClientError::NoGroup)?;
        let sealed = group.encrypt_text(identity, text.as_bytes())?;
        conv.history.push(ChatLine {
            from: me,
            text: text.to_string(),
            mine: true,
        });
        self.conn.send(ClientMsg::Text {
            group: group_id,
            message: Sealed(sealed),
        });
        Ok(())
    }

    /// A summary of every conversation, for the sidebar. DM titles resolve to the
    /// peer's current display name.
    pub fn conversations(&self) -> Vec<ConversationInfo> {
        let me = self.username.clone().unwrap_or_default();
        self.conversations
            .iter()
            .map(|(id, c)| {
                let title = match c.kind {
                    ConvKind::Dm => {
                        let peer = c
                            .members
                            .iter()
                            .find(|m| **m != me)
                            .cloned()
                            .unwrap_or_else(|| c.title.clone());
                        self.display_of(&peer)
                    }
                    ConvKind::Group => c.title.clone(),
                };
                ConversationInfo {
                    id: hex_id(id),
                    title,
                    is_dm: c.kind == ConvKind::Dm,
                    members: c.members.clone(),
                    pending: c.group.is_none(),
                }
            })
            .collect()
    }

    /// The active conversation's id (hex), if any.
    pub fn active_id(&self) -> Option<String> {
        self.active.as_ref().map(hex_id)
    }

    /// The scoped history (from, text, mine) of a conversation by hex id.
    pub fn conversation_history(&self, conv: &str) -> Vec<(String, String, bool)> {
        self.conversations
            .iter()
            .find(|(id, _)| hex_id(id) == conv)
            .map(|(_, c)| {
                c.history
                    .iter()
                    .map(|l| (self.display_of(&l.from), l.text.clone(), l.mine))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The active conversation's safety number, if it has an established group.
    pub fn safety_number(&self) -> Option<String> {
        let id = self.active.as_ref()?;
        let conv = self.conversations.get(id)?;
        conv.group.as_ref().map(|g| g.safety_number().to_string())
    }

    /// The logged-in handle, or an error if not logged in.
    fn me(&self) -> Result<String, ClientError> {
        self.username.clone().ok_or(ClientError::NotLoggedIn)
    }

    /// Await the next event, processing incoming server messages until one
    /// produces something the UI cares about. Returns `None` if disconnected.
    pub async fn next_event(&mut self) -> Option<Event> {
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        loop {
            let msg = self.conn.recv().await?;
            // A DM nudge needs an async follow-up (create the group + invite),
            // which the sync `handle` cannot do -- so service it here. It must
            // not steal focus, so the active conversation is preserved.
            if let ServerMsg::DmRequested { from } = &msg {
                let from = from.clone();
                let prev = self.active.clone();
                let _ = self.open_dm(&from).await;
                self.active = prev;
                return Some(Event::ConversationsChanged);
            }
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
            ServerMsg::Welcome {
                group,
                from,
                name,
                message,
            } => {
                let identity = self.identity.as_ref()?;
                let joined = match Group::join(identity, &message.0) {
                    Ok(j) => j,
                    Err(e) => return Some(Event::Error(format!("join failed: {e}"))),
                };
                self.conn.send(ClientMsg::JoinGroup {
                    group: group.clone(),
                });
                let is_dm = name.is_empty();
                match self.conversations.get_mut(&group) {
                    // Populate a pending DM (or re-affirm) by adopting the group.
                    Some(conv) => conv.group = Some(joined),
                    None => {
                        let me = self.username.clone().unwrap_or_default();
                        let title = if is_dm { from.0.clone() } else { name };
                        self.conversations.insert(
                            group,
                            Conversation {
                                group: Some(joined),
                                kind: if is_dm { ConvKind::Dm } else { ConvKind::Group },
                                title,
                                members: vec![me, from.0],
                                history: Vec::new(),
                            },
                        );
                    }
                }
                Some(Event::ConversationsChanged)
            }
            ServerMsg::Text { group, message, .. } => {
                let identity = self.identity.as_ref()?;
                let conv = self.conversations.get_mut(&group)?;
                let g = conv.group.as_mut()?;
                match g.decrypt_text(identity, &message.0) {
                    Ok(tm) => {
                        let username = String::from_utf8_lossy(&tm.sender).into_owned();
                        let text = String::from_utf8_lossy(&tm.plaintext).into_owned();
                        conv.history.push(ChatLine {
                            from: username.clone(),
                            text: text.clone(),
                            mine: false,
                        });
                        let from = self
                            .display_names
                            .get(&username)
                            .cloned()
                            .unwrap_or(username);
                        Some(Event::Message {
                            conv: hex_id(&group),
                            from,
                            text,
                            mine: false,
                        })
                    }
                    Err(e) => Some(Event::Error(format!("decrypt failed: {e}"))),
                }
            }
            ServerMsg::Mls { group, message, .. } => {
                let identity = self.identity.as_ref()?;
                let conv = self.conversations.get_mut(&group)?;
                let g = conv.group.as_mut()?;
                match g.apply_commit(identity, &message.0) {
                    Ok(()) => Some(Event::ConversationsChanged),
                    Err(_) => None,
                }
            }
            ServerMsg::Presence { user, status } => Some(Event::Presence {
                user: user.0,
                status: presence_label(status),
            }),
            ServerMsg::Friends {
                friends,
                incoming,
                outgoing,
            } => {
                for f in friends.iter().chain(&incoming).chain(&outgoing) {
                    self.display_names
                        .insert(f.username.clone(), f.display.clone());
                }
                self.friends = friends;
                self.incoming = incoming;
                self.outgoing = outgoing;
                Some(Event::FriendsChanged)
            }
            ServerMsg::FriendRequestReceived { from } => Some(Event::FriendRequest { from }),
            // The authoritative list follows in a Friends snapshot; surface the
            // change so the UI refreshes.
            ServerMsg::FriendAccepted { .. } | ServerMsg::FriendRemoved { .. } => {
                Some(Event::FriendsChanged)
            }
            ServerMsg::Auth { .. } => None,
            ServerMsg::Error { detail } => Some(Event::Error(detail)),
            _ => None,
        }
    }
}

/// Deterministic routing id for the 1:1 DM between two handles: the same for
/// both sides regardless of who opens it first.
fn derive_dm_id(a: &str, b: &str) -> GroupId {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(b"enclave-dm\0");
    h.update(lo.as_bytes());
    h.update([0u8]);
    h.update(hi.as_bytes());
    let digest = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&digest);
    GroupId(id)
}

/// A fresh random routing id for a named group.
fn random_group_id() -> GroupId {
    let mut id = [0u8; 32];
    let _ = getrandom::getrandom(&mut id);
    GroupId(id)
}

/// Hex encoding of a routing group id -- the stable conversation key the UI uses.
fn hex_id(id: &GroupId) -> String {
    let mut s = String::with_capacity(64);
    for b in id.0 {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
