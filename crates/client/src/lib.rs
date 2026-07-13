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
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use crate::transfer::{FileManifest, FileSink, Part, Reassembler, TransferMeta};
use enclave_crypto::{Group, Identity};
use enclave_protocol::{ClientMsg, DeviceId, Friend, GroupId, Presence, Sealed, ServerMsg, UserId};
use enclave_transport::accounts::MIN_PASSWORD_LEN;
use enclave_transport::{opaque, Connection};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod call;
mod session;
mod transfer;

/// Largest file the sender will try to *store* on the server for offline
/// delivery (mirrors the server's `PER_FILE_MAX`). A bigger file is sent live
/// (both parties online, nothing stored). Kept in sync with the server by hand;
/// the server is the authority and rejects an over-size stored offer anyway.
pub const STORE_FILE_MAX: u64 = 250 * 1024 * 1024;

/// Why a screen share ended on its own (see [`Client::reap_ended_share`]):
/// `Cancelled` is the user changing their mind at the system picker, `Failed`
/// is a real error worth showing loudly.
pub use enclave_media::EndedReason as ShareEnded;

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
    #[error("audio: {0}")]
    Audio(String),
}

/// A file that arrived (or was sent) in a conversation. The bytes live on
/// disk at `path`; only this descriptor crosses the IPC bridge.
#[derive(Debug, Clone)]
pub struct FileRef {
    pub name: String,
    pub size: u64,
    /// Local path: where a received file was written, or the source of a sent
    /// one.
    pub path: String,
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
    /// A file finished arriving in conversation `conv`, from display name
    /// `from`, and was written to `file.path`.
    File {
        conv: String,
        from: String,
        file: FileRef,
    },
    /// Someone offered a file in conversation `conv`. It is NOT downloaded: the
    /// UI shows a consent prompt, and the user calls `accept_file`/`decline_file`
    /// with `offer_id`. `live` means the sender is streaming now (accept
    /// promptly). This is the whole point of the consent flow: nothing touches
    /// the recipient's disk until they say yes.
    FileOffered {
        conv: String,
        offer_id: String,
        from: String,
        name: String,
        size: u64,
        live: bool,
    },
    /// An offer we were shown is gone (the sender withdrew it, it expired, or a
    /// transfer resolved): the UI removes its prompt/row for `offer_id`.
    FileOfferClosed { conv: String, offer_id: String },
    /// Progress of an in-flight transfer we are sending or receiving, 0..=1.
    /// `label` names it (a filename, or "message"); `done` marks completion.
    TransferProgress {
        conv: String,
        id: String,
        label: String,
        sent: u64,
        total: u64,
        incoming: bool,
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
    /// An incoming call started in conversation `conv`, initiated by `from`
    /// (display name). The UI rings.
    CallOffer { conv: String, from: String },
    /// The participant list of conversation `conv`'s call changed (display
    /// names). Empty means the call ended.
    CallParticipants {
        conv: String,
        participants: Vec<String>,
    },
    /// `from` (display name) declined our call in conversation `conv`.
    CallDeclined { conv: String, from: String },
    /// An H.264 video frame from `from` (display name) to show in the UI.
    /// `data` is the Annex-B bytes; the UI decodes it with WebCodecs. `camera`
    /// routes it: a per-user webcam tile (`true`) or the full-screen share
    /// viewer (`false`).
    ScreenFrame {
        from: String,
        data: Vec<u8>,
        keyframe: bool,
        camera: bool,
    },
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
    /// The MLS-internal group id, for persisting/reloading (empty until live).
    mls_group_id: Vec<u8>,
    kind: ConvKind,
    title: String,
    members: Vec<String>,
    history: Vec<ChatLine>,
    /// The safety number the user confirmed out of band. Compared against the
    /// live number, so a rekey (which changes it) drops back to unverified.
    verified: Option<String>,
    /// Reassembles incoming chunked messages/files. In-flight transfers do not
    /// survive a restart (they complete within a session over reliable TCP).
    #[allow(dead_code)]
    reassembler: Reassembler,
}

#[derive(Clone)]
struct ChatLine {
    from: String,
    /// For a text message, the text. For a file, a human label (the filename).
    text: String,
    mine: bool,
    /// Present when this line is a file rather than plain text.
    file: Option<FileRef>,
}

/// A file we are offering, kept until it is uploaded/streamed or resolved. The
/// bytes stay on disk at `path`; they are read and sealed only when the server
/// says to (stored: on `FileUploadReady`; live: on the first `FileAccepted`).
struct OutgoingFile {
    group: GroupId,
    path: String,
    name: String,
    mime: String,
    size: u64,
    live: bool,
    /// Set once we have begun sending chunks, so a second trigger (e.g. a second
    /// recipient accepting a live offer) does not restart the stream.
    started: bool,
}

/// An upload in progress: the open file and our position in it. The pump seals
/// and sends one chunk at a time only while the connection's bounded file queue
/// has room, so a large (or live, arbitrary-size) file is streamed from disk and
/// paced by the socket -- never sealed or buffered whole in memory.
struct Upload {
    group: GroupId,
    file: std::fs::File,
    /// Display name, for progress.
    name: String,
    meta: TransferMeta,
    /// Total chunks and the next one to send.
    total: u32,
    index: u32,
    size: u64,
    sent: u64,
}

/// A file offered to us, awaiting our consent. Nothing is written to disk until
/// we accept; on accept a [`FileSink`] streams the chunks straight to disk.
struct IncomingFile {
    group: GroupId,
    from: String,
    name: String,
    size: u64,
    /// Set only once the user explicitly accepts. Chunks are written to disk
    /// only for an accepted offer, so a malicious server cannot bypass the
    /// consent gate by streaming an un-accepted file's bytes at us.
    accepted: bool,
    /// The streaming disk sink, created when we accept and the first chunk lands.
    sink: Option<FileSink>,
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
    /// OPAQUE export key (password-derived): the at-rest key for the session file.
    export_key: Vec<u8>,
    /// Our own display name (cosmetic; the username is the unique id).
    display: String,
    /// Accepted friends and pending requests, mirrored from the server.
    friends: Vec<Friend>,
    incoming: Vec<Friend>,
    outgoing: Vec<Friend>,
    /// username -> current display name, learned from friend snapshots.
    display_names: HashMap<String, String>,
    /// The server's UDP media address (derived from the signaling URL).
    media_addr: Option<SocketAddr>,
    /// The in-progress voice call, if any.
    call: Option<call::Call>,
    /// Incoming screen frames from the current call, drained by `next_event`.
    screen_rx: Option<tokio::sync::mpsc::UnboundedReceiver<call::ScreenFrameOut>>,
    /// The conversation the current call belongs to (for the LeaveCall signal,
    /// since the user may switch conversations while in a call).
    call_group: Option<GroupId>,
    /// Selected microphone (input) device name; `None` = host default.
    input_device: Option<String>,
    /// Selected speaker (output) device name; `None` = host default.
    output_device: Option<String>,
    /// The server URL, retained so a dropped socket can be reconnected.
    server_url: String,
    /// The login password, kept in memory (zeroized) only for the session so a
    /// reconnect can re-authenticate. Never persisted. (A session-resumption
    /// token would avoid retaining it; see the reconnect note.)
    password: Zeroizing<String>,
    /// Files we are offering, keyed by offer id (see [`OutgoingFile`]).
    outgoing_files: HashMap<[u8; 16], OutgoingFile>,
    /// Uploads in progress, keyed by offer id, streamed by [`pump_uploads`].
    uploads: HashMap<[u8; 16], Upload>,
    /// Files offered to us, awaiting/undergoing consented download (see
    /// [`IncomingFile`]). An entry exists from the offer until it resolves.
    incoming_files: HashMap<[u8; 16], IncomingFile>,
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
            export_key: Vec::new(),
            display: String::new(),
            friends: Vec::new(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            display_names: HashMap::new(),
            media_addr: media_addr_from(server_url),
            call: None,
            screen_rx: None,
            call_group: None,
            input_device: None,
            output_device: None,
            server_url: server_url.to_string(),
            password: Zeroizing::new(String::new()),
            outgoing_files: HashMap::new(),
            uploads: HashMap::new(),
            incoming_files: HashMap::new(),
        })
    }

    /// Reconnect to the server after the socket dropped (restart, network blip)
    /// and re-authenticate with the retained credentials, restoring routing. The
    /// full login path is reused, which is idempotent: the same identity and
    /// session are re-loaded from disk and re-affirmed. Fails if not logged in.
    pub async fn reconnect(&mut self) -> Result<(), ClientError> {
        let handle = self.username.clone().ok_or(ClientError::NotLoggedIn)?;
        if self.password.is_empty() {
            return Err(ClientError::NotLoggedIn);
        }
        let password = self.password.clone();
        // The old socket is gone, so any in-progress uploads cannot be resumed
        // cleanly against a fresh session; abandon them (the user re-sends).
        self.uploads.clear();
        self.conn = Connection::connect(&self.server_url).await?;
        self.login(&handle, &password).await
    }

    /// Where identity key files and rosters are stored (default: current dir).
    /// Also the home of the machine-local audio device preferences, loaded here.
    pub fn set_keystore_dir(&mut self, dir: impl Into<PathBuf>) {
        self.keystore_dir = dir.into();
        let prefs = AudioPrefs::load(&self.audio_prefs_path());
        self.input_device = prefs.input;
        self.output_device = prefs.output;
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
        let (upload, export_key) = reg_state
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
        self.export_key = export_key;
        self.password = Zeroizing::new(password.to_string());
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
        let (finalization, export_key) = login_state
            .finish(password, &response)
            .map_err(|_| ClientError::Auth("wrong handle or password".into()))?;
        self.conn.send(ClientMsg::LoginFinish {
            finalization,
            key_package,
        });
        let server_display = self.await_auth().await?;
        let _ = identity.save(&self.identity_path(handle), password);
        self.finish_login(identity, handle, server_display);
        self.export_key = export_key;
        self.password = Zeroizing::new(password.to_string());
        self.load_session();
        Ok(())
    }

    /// End the session: go offline and forget the group.
    pub fn logout(&mut self) {
        self.conn.send(ClientMsg::Logout);
        self.identity = None;
        self.username = None;
        self.call = None;
        self.conversations.clear();
        self.active = None;
        self.export_key.clear();
        self.password = Zeroizing::new(String::new());
        self.call_group = None;
        self.display.clear();
        self.friends.clear();
        self.incoming.clear();
        self.outgoing.clear();
        self.display_names.clear();
        self.outgoing_files.clear();
        self.uploads.clear();
        self.incoming_files.clear();
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
            let mls_group_id = group.mls_group_id();
            self.conn.send(ClientMsg::JoinGroup {
                group: dm_id.clone(),
            });
            self.conversations.insert(
                dm_id.clone(),
                Conversation {
                    group: Some(group),
                    mls_group_id,
                    kind: ConvKind::Dm,
                    title: friend.to_string(),
                    members: vec![me, friend.to_string()],
                    history: Vec::new(),
                    verified: None,
                    reassembler: Reassembler::new(),
                },
            );
            self.invite_peer(&dm_id, friend, "").await?;
            self.save_session();
        } else {
            // They are the creator; ask them to open it, and show it as pending.
            self.conn.send(ClientMsg::RequestDm {
                to: friend.to_string(),
            });
            self.conversations.insert(
                dm_id.clone(),
                Conversation {
                    group: None,
                    mls_group_id: Vec::new(),
                    kind: ConvKind::Dm,
                    title: friend.to_string(),
                    members: vec![me, friend.to_string()],
                    history: Vec::new(),
                    verified: None,
                    reassembler: Reassembler::new(),
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
        let mls_group_id = group.mls_group_id();
        let group_id = random_group_id();
        self.conn.send(ClientMsg::JoinGroup {
            group: group_id.clone(),
        });
        self.conversations.insert(
            group_id.clone(),
            Conversation {
                group: Some(group),
                mls_group_id,
                kind: ConvKind::Group,
                title: name.to_string(),
                members: vec![me],
                history: Vec::new(),
                verified: None,
                reassembler: Reassembler::new(),
            },
        );
        for member in members {
            self.invite_peer(&group_id, member, name).await?;
        }
        self.save_session();
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
        self.invite_peer(&group_id, friend, &name).await?;
        self.save_session();
        Ok(())
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

    /// Leave / delete a conversation: stop receiving its traffic and drop it
    /// locally. If a call is active in it, leave that first.
    pub fn leave_conversation(&mut self, conv_hex: &str) {
        let Some(group_id) = self.group_by_hex(conv_hex) else {
            return;
        };
        if self.call_group.as_ref() == Some(&group_id) {
            self.leave_call();
        }
        self.conn.send(ClientMsg::LeaveGroup {
            group: group_id.clone(),
        });
        self.conversations.remove(&group_id);
        if self.active.as_ref() == Some(&group_id) {
            self.active = None;
        }
        self.save_session();
    }

    /// Remove a member from a group: MLS-rekey so they cannot read the new epoch,
    /// drop them from the server's routing set, and fan the commit to the rest.
    pub fn remove_member(&mut self, conv_hex: &str, member: &str) -> Result<(), ClientError> {
        let group_id = self.group_by_hex(conv_hex).ok_or(ClientError::NoGroup)?;
        let commit = {
            let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
            let conv = self
                .conversations
                .get_mut(&group_id)
                .ok_or(ClientError::NoGroup)?;
            let group = conv.group.as_mut().ok_or(ClientError::NoGroup)?;
            // The roster maps a member's username (credential label) to their key.
            let target_key = group
                .member_keys()
                .into_iter()
                .find(|(label, _)| label == member)
                .map(|(_, key)| key)
                .ok_or(ClientError::NoGroup)?;
            let commit = group.remove_member(identity, &target_key)?;
            conv.members.retain(|m| m != member);
            commit
        };
        self.conn.send(ClientMsg::RemoveMember {
            group: group_id.clone(),
            member: DeviceId(member.into()),
        });
        self.conn.send(ClientMsg::Mls {
            group: group_id,
            message: Sealed(commit),
        });
        self.save_session();
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

    /// Encrypt and send a text message to the active conversation. A message
    /// that fits in one sealed frame is a single part; a larger one is split
    /// into chunks (see [`crate::transfer`]) that the peer reassembles. Records
    /// the message in local history.
    pub async fn send_text(&mut self, text: &str) -> Result<(), ClientError> {
        let group_id = self.active.clone().ok_or(ClientError::NoGroup)?;
        let me = self.me()?;
        self.send_transfer(&group_id, TransferMeta::Text, text.as_bytes())?;
        if let Some(conv) = self.conversations.get_mut(&group_id) {
            conv.history.push(ChatLine {
                from: me,
                text: text.to_string(),
                mine: true,
                file: None,
            });
        }
        self.save_session();
        Ok(())
    }

    /// Offer a file to the active conversation. The file is NOT sent yet: a
    /// sealed manifest (name, size) is offered so each recipient can accept or
    /// decline. A file up to [`STORE_FILE_MAX`] is offered for offline delivery
    /// (the server buffers it on disk once the recipient accepts); a larger one
    /// is offered live (streamed in real time to whoever accepts, requiring them
    /// online). The bytes are read and sealed only when the server says to
    /// upload/stream, never up front, so the whole file is never held in memory.
    /// Returns the [`FileRef`] for the sender's own history.
    pub async fn send_file(&mut self, path: &str) -> Result<FileRef, ClientError> {
        let group_id = self.active.clone().ok_or(ClientError::NoGroup)?;
        let me = self.me()?;
        let p = std::path::Path::new(path);
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_owned)
            .ok_or_else(|| ClientError::Audio("that path has no file name".into()))?;
        let meta_fs = std::fs::metadata(p)
            .map_err(|e| ClientError::Audio(format!("cannot read {name}: {e}")))?;
        let size = meta_fs.len();
        let mime = mime_from_name(&name);
        let live = size > STORE_FILE_MAX;

        // Seal the manifest so recipients learn the name/size without the bytes.
        let manifest = FileManifest {
            name: name.clone(),
            mime: mime.clone(),
            size,
        };
        let sealed_manifest = self.seal(&group_id, &manifest.encode())?;

        let offer_id = new_transfer_id();
        self.conn.send(ClientMsg::FileOffer {
            offer_id,
            group: group_id.clone(),
            // The server only needs the size to enforce its store quota; a live
            // transfer stores nothing, so it is not told the size.
            size: if live { 0 } else { size },
            manifest: Sealed(sealed_manifest),
            live,
        });
        self.outgoing_files.insert(
            offer_id,
            OutgoingFile {
                group: group_id.clone(),
                path: path.to_string(),
                name: name.clone(),
                mime,
                size,
                live,
                started: false,
            },
        );

        let file_ref = FileRef {
            name: name.clone(),
            size,
            path: path.to_string(),
        };
        if let Some(conv) = self.conversations.get_mut(&group_id) {
            conv.history.push(ChatLine {
                from: me,
                text: name,
                mine: true,
                file: Some(file_ref.clone()),
            });
        }
        self.save_session();
        Ok(file_ref)
    }

    /// Consent to receive an offered file: tell the server, which then delivers
    /// its chunks. `offer_id` is the hex id from an [`Event::FileOffered`].
    pub fn accept_file(&mut self, offer_id: &str) -> Result<(), ClientError> {
        let id = decode_offer_id(offer_id).ok_or(ClientError::NoGroup)?;
        match self.incoming_files.get_mut(&id) {
            Some(inc) => inc.accepted = true,
            None => return Ok(()), // already gone; nothing to do
        }
        self.conn.send(ClientMsg::FileAccept { offer_id: id });
        Ok(())
    }

    /// Refuse an offered file: tell the server (which drops it) and forget it.
    pub fn decline_file(&mut self, offer_id: &str) -> Result<(), ClientError> {
        let id = decode_offer_id(offer_id).ok_or(ClientError::NoGroup)?;
        if let Some(inc) = self.incoming_files.remove(&id) {
            if let Some(sink) = inc.sink {
                sink.abort();
            }
            self.conn.send(ClientMsg::FileDecline { offer_id: id });
        }
        Ok(())
    }

    /// Withdraw a file we offered (e.g. sent by mistake): tell the server, which
    /// deletes it and notifies any recipients.
    pub fn cancel_file(&mut self, offer_id: &str) -> Result<(), ClientError> {
        let id = decode_offer_id(offer_id).ok_or(ClientError::NoGroup)?;
        if self.outgoing_files.remove(&id).is_some() {
            self.uploads.remove(&id); // stop streaming it if in progress
            self.conn.send(ClientMsg::FileCancel { offer_id: id });
        }
        Ok(())
    }

    /// Begin uploading an offered file: open it and register an [`Upload`]; the
    /// bytes are streamed later by [`pump_uploads`], paced by the connection.
    /// Marks the offer started so a repeated trigger does not re-stream it.
    fn start_upload(&mut self, offer_id: [u8; 16]) {
        let (group, path, name, mime, size) = match self.outgoing_files.get_mut(&offer_id) {
            Some(o) if !o.started => {
                o.started = true;
                (o.group.clone(), o.path.clone(), o.name.clone(), o.mime.clone(), o.size)
            }
            _ => return, // unknown or already streaming
        };
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                self.pending
                    .push_back(Event::Error(format!("cannot open {name}: {e}")));
                return;
            }
        };
        let total = (size as usize).div_ceil(transfer::CHUNK_BYTES).max(1) as u32;
        self.uploads.insert(
            offer_id,
            Upload {
                group,
                file,
                meta: TransferMeta::File {
                    name: name.clone(),
                    mime,
                },
                name,
                total,
                index: 0,
                size,
                sent: 0,
            },
        );
    }

    /// Push in-progress uploads forward: for each, seal and send chunks while the
    /// connection's bounded file queue has room, then `FileComplete` when done.
    /// Non-blocking -- when the queue is full it stops and resumes on the next
    /// call, so the socket (and any slow relayed recipient) paces the upload and
    /// the whole file is never buffered in memory. Driven by the event loop.
    pub fn pump_uploads(&mut self) {
        let ids: Vec<[u8; 16]> = self.uploads.keys().copied().collect();
        for id in ids {
            // Send while there is room in the bounded file queue (backpressure).
            while self.conn.file_capacity() > 0 {
                // Read the next chunk (or detect completion) under a short borrow.
                let chunk = {
                    let Some(up) = self.uploads.get_mut(&id) else {
                        break;
                    };
                    if up.index >= up.total {
                        None // done
                    } else {
                        let mut buf = vec![0u8; transfer::CHUNK_BYTES];
                        match read_full(&mut up.file, &mut buf) {
                            Ok(n) => Some((
                                up.index,
                                up.total,
                                up.group.clone(),
                                up.meta.clone(),
                                buf[..n].to_vec(),
                                n,
                            )),
                            Err(e) => {
                                let name = up.name.clone();
                                self.pending
                                    .push_back(Event::Error(format!("reading {name}: {e}")));
                                self.uploads.remove(&id);
                                break;
                            }
                        }
                    }
                };
                match chunk {
                    None => {
                        // Every chunk sent: signal completion and finish.
                        self.conn.try_send_file(ClientMsg::FileComplete { offer_id: id });
                        self.uploads.remove(&id);
                        break;
                    }
                    Some((index, total, group, meta, data, n)) => {
                        let part = Part {
                            id,
                            index,
                            total,
                            meta,
                            data,
                        };
                        let sealed = match self.seal(&group, &part.encode()) {
                            Ok(s) => s,
                            Err(e) => {
                                self.pending
                                    .push_back(Event::Error(format!("sealing a file chunk: {e}")));
                                self.uploads.remove(&id);
                                break;
                            }
                        };
                        // Capacity was checked at the loop head and we are the
                        // only file producer, so a send fails only if the
                        // connection dropped -- abandon the doomed upload then.
                        if !self.conn.try_send_file(ClientMsg::FileChunk {
                            offer_id: id,
                            data: Sealed(sealed),
                        }) {
                            self.uploads.remove(&id);
                            break;
                        }
                        let (label, size, sent) = match self.uploads.get_mut(&id) {
                            Some(up) => {
                                up.index += 1;
                                up.sent += n as u64;
                                (up.name.clone(), up.size, up.sent)
                            }
                            None => break,
                        };
                        self.pending.push_back(Event::TransferProgress {
                            conv: hex_id(&group),
                            id: hex::encode(id),
                            label,
                            sent,
                            total: size,
                            incoming: false,
                        });
                    }
                }
            }
        }
    }

    /// Split `data` into parts and send each one sealed to `group_id`.
    fn send_transfer(
        &mut self,
        group_id: &GroupId,
        meta: TransferMeta,
        data: &[u8],
    ) -> Result<(), ClientError> {
        let id = new_transfer_id();
        for part in transfer::split(id, meta, data) {
            self.seal_and_send(group_id, &part)?;
        }
        Ok(())
    }

    /// Seal one serialized part with the group key and hand it to the relay as a
    /// Text message (used for text and large-text transfers).
    fn seal_and_send(&mut self, group_id: &GroupId, part: &[u8]) -> Result<(), ClientError> {
        let sealed = self.seal(group_id, part)?;
        self.conn.send(ClientMsg::Text {
            group: group_id.clone(),
            message: Sealed(sealed),
        });
        Ok(())
    }

    /// Seal `plaintext` with a group's MLS key, returning the ciphertext without
    /// sending it (used for file manifests and file chunks).
    fn seal(&mut self, group_id: &GroupId, plaintext: &[u8]) -> Result<Vec<u8>, ClientError> {
        let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let conv = self
            .conversations
            .get_mut(group_id)
            .ok_or(ClientError::NoGroup)?;
        let group = conv.group.as_mut().ok_or(ClientError::NoGroup)?;
        Ok(group.encrypt_text(identity, plaintext)?)
    }

    /// A file was offered to us. Decrypt its manifest (no download needed),
    /// record the pending offer, and surface a consent prompt. Nothing touches
    /// disk here: the bytes arrive only if the user accepts.
    fn handle_file_offered(
        &mut self,
        offer_id: [u8; 16],
        group: GroupId,
        from: DeviceId,
        manifest: Sealed,
        live: bool,
    ) -> Option<Event> {
        // Decrypt the manifest with the group key.
        let plaintext = {
            let identity = self.identity.as_ref()?;
            let conv = self.conversations.get_mut(&group)?;
            let g = conv.group.as_mut()?;
            g.decrypt_text(identity, &manifest.0).ok()?.plaintext
        };
        let m = FileManifest::decode(&plaintext)?;
        let safe = safe_file_name(&m.name);
        let from_display = self.display_of(&from.0);
        self.incoming_files.insert(
            offer_id,
            IncomingFile {
                group: group.clone(),
                from: from.0.clone(),
                name: safe.clone(),
                size: m.size,
                accepted: false,
                sink: None,
            },
        );
        Some(Event::FileOffered {
            conv: hex_id(&group),
            offer_id: hex::encode(offer_id),
            from: from_display,
            name: safe,
            size: m.size,
            live,
        })
    }

    /// The server refused our stored offer. If the store simply could not take
    /// it (full, low disk, too big), retry the same file live -- the recipient
    /// may be online. If the live attempt (or any other) is refused, give up.
    fn handle_offer_rejected(&mut self, offer_id: [u8; 16], reason: String) -> Option<Event> {
        let can_retry_live = self
            .outgoing_files
            .get(&offer_id)
            .is_some_and(|o| !o.live);
        if can_retry_live {
            let (group, manifest) = {
                let o = self.outgoing_files.get(&offer_id)?;
                (
                    o.group.clone(),
                    FileManifest {
                        name: o.name.clone(),
                        mime: o.mime.clone(),
                        size: o.size,
                    },
                )
            };
            let sealed = self.seal(&group, &manifest.encode()).ok()?;
            if let Some(o) = self.outgoing_files.get_mut(&offer_id) {
                o.live = true;
                o.started = false;
            }
            self.conn.send(ClientMsg::FileOffer {
                offer_id,
                group,
                size: 0,
                manifest: Sealed(sealed),
                live: true,
            });
            return None; // silent fallback; a real failure is reported below
        }
        let name = self
            .outgoing_files
            .remove(&offer_id)
            .map(|o| o.name)
            .unwrap_or_else(|| "file".into());
        Some(Event::Error(format!("Could not send {name}: {reason}")))
    }

    /// A recipient declined our offer, or an offer shown to us was withdrawn /
    /// expired (server sends an empty `by` for a lapse or a sender cancel).
    fn handle_file_declined(&mut self, offer_id: [u8; 16], by: DeviceId) -> Option<Event> {
        // An offer we made: a recipient declined, or it lapsed. Leave the record
        // (a group peer may still accept a live one); just report the outcome.
        if let Some(o) = self.outgoing_files.get(&offer_id) {
            let name = o.name.clone();
            let who = if by.0.is_empty() {
                "no reply".to_string()
            } else {
                format!("declined by {}", self.display_of(&by.0))
            };
            return Some(Event::Error(format!("{name} was not delivered ({who})")));
        }
        // An offer shown to us: the sender withdrew it or it expired. Remove the
        // prompt and drop any partial download.
        if let Some(inc) = self.incoming_files.remove(&offer_id) {
            if let Some(sink) = inc.sink {
                sink.abort();
            }
            return Some(Event::FileOfferClosed {
                conv: hex_id(&inc.group),
                offer_id: hex::encode(offer_id),
            });
        }
        None
    }

    /// A chunk of a file we accepted: decrypt it, create the streaming disk sink
    /// on the first chunk (sized from the offered manifest), write the part, and
    /// finalize when the last one lands. The whole file is never held in memory.
    fn handle_file_chunk(&mut self, offer_id: [u8; 16], data: Sealed) -> Option<Event> {
        // Consent gate (defense in depth): write chunks only for an offer the
        // user explicitly accepted. A malicious server that streams an
        // un-accepted file's bytes at us gets them dropped, never written.
        let group = match self.incoming_files.get(&offer_id) {
            Some(inc) if inc.accepted => inc.group.clone(),
            _ => return None,
        };
        // Decrypt the sealed part.
        let part = {
            let identity = self.identity.as_ref()?;
            let conv = self.conversations.get_mut(&group)?;
            let g = conv.group.as_mut()?;
            let tm = g.decrypt_text(identity, &data.0).ok()?;
            Part::decode(&tm.plaintext)?
        };
        // A file chunk must carry file metadata; ignore anything else.
        if !matches!(part.meta, TransferMeta::File { .. }) {
            return None;
        }
        let dir = self.downloads_dir();

        // Create the sink lazily on the first chunk, reserving a safe unique
        // path under the downloads directory (path-traversal safe).
        let need_sink = self
            .incoming_files
            .get(&offer_id)
            .map(|i| i.sink.is_none())
            .unwrap_or(false);
        if need_sink {
            let (name, size) = {
                let inc = self.incoming_files.get(&offer_id)?;
                (inc.name.clone(), inc.size)
            };
            let total = (size as usize).div_ceil(transfer::CHUNK_BYTES).max(1) as u32;
            match reserve_download(&dir, &name) {
                Ok((file, path)) => {
                    let sink = FileSink::new(file, path, name, total, size);
                    if let Some(inc) = self.incoming_files.get_mut(&offer_id) {
                        inc.sink = Some(sink);
                    }
                }
                Err(e) => {
                    self.incoming_files.remove(&offer_id);
                    return Some(Event::Error(format!("could not start download: {e}")));
                }
            }
        }

        // Write the part.
        let (size, write) = {
            let inc = self.incoming_files.get_mut(&offer_id)?;
            let sink = inc.sink.as_mut()?;
            (inc.size, sink.write_part(&part).map(|done| (done, sink.bytes())))
        };
        let (done, sent) = match write {
            Ok(v) => v,
            Err(e) => {
                if let Some(inc) = self.incoming_files.remove(&offer_id) {
                    if let Some(sink) = inc.sink {
                        sink.abort();
                    }
                }
                return Some(Event::Error(format!("download failed: {e}")));
            }
        };

        // Surface progress.
        let label = self
            .incoming_files
            .get(&offer_id)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        self.pending.push_back(Event::TransferProgress {
            conv: hex_id(&group),
            id: hex::encode(offer_id),
            label,
            sent,
            total: size,
            incoming: true,
        });
        if !done {
            return None;
        }

        // Complete: flush, record in history, and hand the UI the file.
        let mut inc = self.incoming_files.remove(&offer_id)?;
        let mut sink = inc.sink.take()?;
        if let Err(e) = sink.finish() {
            sink.abort();
            return Some(Event::Error(format!("could not finish download: {e}")));
        }
        let file = FileRef {
            name: sink.name().to_string(),
            size: sink.bytes(),
            path: sink.path().to_string_lossy().into_owned(),
        };
        let from_display = self.display_of(&inc.from);
        if let Some(conv) = self.conversations.get_mut(&group) {
            conv.history.push(ChatLine {
                from: inc.from.clone(),
                text: file.name.clone(),
                mine: false,
                file: Some(file.clone()),
            });
        }
        self.save_session();
        // Also close the offer prompt in the UI (it becomes a delivered file).
        self.pending.push_back(Event::FileOfferClosed {
            conv: hex_id(&group),
            offer_id: hex::encode(offer_id),
        });
        Some(Event::File {
            conv: hex_id(&group),
            from: from_display,
            file,
        })
    }

    /// The sender says every chunk of `offer_id` has been delivered. Normally
    /// the last chunk already completed the file, so this finds nothing. If the
    /// download is still pending here, chunks were lost: abort it as incomplete.
    fn handle_file_complete(&mut self, offer_id: [u8; 16]) -> Option<Event> {
        let inc = self.incoming_files.remove(&offer_id)?;
        let conv = hex_id(&inc.group);
        let name = inc.name.clone();
        if let Some(sink) = inc.sink {
            sink.abort();
        }
        self.pending.push_back(Event::FileOfferClosed {
            conv,
            offer_id: hex::encode(offer_id),
        });
        Some(Event::Error(format!("{name} did not arrive completely")))
    }

    /// The directory received files are written to (`downloads/` under the
    /// keystore). Created on demand.
    fn downloads_dir(&self) -> PathBuf {
        self.keystore_dir.join("enclave-downloads")
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
    pub fn conversation_history(&self, conv: &str) -> Vec<(String, String, bool, Option<FileRef>)> {
        self.conversations
            .iter()
            .find(|(id, _)| hex_id(id) == conv)
            .map(|(_, c)| {
                c.history
                    .iter()
                    .map(|l| {
                        (
                            self.display_of(&l.from),
                            l.text.clone(),
                            l.mine,
                            l.file.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether the user has confirmed the active conversation's *current* safety
    /// number out of band. A rekey changes the number, so this goes back to
    /// false on any membership change: trust is never carried across one.
    pub fn is_verified(&self) -> bool {
        let Some(id) = self.active.as_ref() else {
            return false;
        };
        let Some(conv) = self.conversations.get(id) else {
            return false;
        };
        match (&conv.verified, conv.group.as_ref()) {
            (Some(confirmed), Some(group)) => *confirmed == group.safety_number().to_string(),
            _ => false,
        }
    }

    /// Record that the user compared the active conversation's safety number
    /// out of band and it matched. Persisted with the session, so it survives a
    /// restart (the whole point: a mark that resets every run teaches people to
    /// ignore it).
    pub fn mark_verified(&mut self) {
        let Some(id) = self.active.clone() else {
            return;
        };
        let Some(number) = self
            .conversations
            .get(&id)
            .and_then(|c| c.group.as_ref())
            .map(|g| g.safety_number().to_string())
        else {
            return;
        };
        if let Some(conv) = self.conversations.get_mut(&id) {
            conv.verified = Some(number);
        }
        self.save_session();
    }

    /// The active conversation's safety number, if it has an established group.
    pub fn safety_number(&self) -> Option<String> {
        let id = self.active.as_ref()?;
        let conv = self.conversations.get(id)?;
        conv.group.as_ref().map(|g| g.safety_number().to_string())
    }

    /// Whether a voice call is currently active.
    pub fn in_call(&self) -> bool {
        self.call.is_some()
    }

    /// Join a voice call in the active conversation: derive the group media key,
    /// open the UDP media channel, and start mic capture + speaker playback. All
    /// members who join the same conversation's call hear each other.
    pub async fn start_call(&mut self) -> Result<(), ClientError> {
        if self.call.is_some() {
            return Ok(());
        }
        let media_addr = self
            .media_addr
            .ok_or_else(|| ClientError::Audio("no media address for this server".into()))?;
        let group_id = self.active.clone().ok_or(ClientError::NoGroup)?;
        let me = self.me()?;
        let params = {
            let identity = self.identity()?;
            let conv = self
                .conversations
                .get(&group_id)
                .ok_or(ClientError::NoGroup)?;
            let group = conv.group.as_ref().ok_or(ClientError::NoGroup)?;
            call::CallParams {
                media_addr,
                group: group_id.clone(),
                me,
                root_secret: group.media_root_secret(identity)?,
                my_identity_key: identity.identity_key(),
                signer: identity.media_signer()?,
                member_keys: group.member_keys().into_iter().collect(),
                input_device: self.input_device.clone(),
                output_device: self.output_device.clone(),
            }
        };
        let (call, screen_rx) = call::Call::start(params).await?;
        self.call = Some(call);
        self.screen_rx = Some(screen_rx);
        self.call_group = Some(group_id.clone());
        // Signal the call so the server rings other members and tracks who is in.
        self.conn.send(ClientMsg::JoinCall { group: group_id });
        Ok(())
    }

    /// Leave the current voice call (tears down the media pipeline and tells the
    /// server, so the other participants see us leave).
    pub fn leave_call(&mut self) {
        self.call = None;
        self.screen_rx = None;
        if let Some(group) = self.call_group.take() {
            self.conn.send(ClientMsg::LeaveCall { group });
        }
    }

    /// The monitors available to share (index + name), for a source picker.
    /// On Linux this is a single "choose in the system dialog" entry: the XDG
    /// portal picks the actual monitor or window.
    pub fn screen_sources(&self) -> Vec<(usize, String)> {
        enclave_media::monitor_sources()
            .into_iter()
            .map(|s| (s.index, s.name))
            .collect()
    }

    /// The windows available to share (hwnd + title), for a source picker.
    /// Empty on Linux, where only the system dialog may list other windows.
    pub fn window_sources(&self) -> Vec<(isize, String)> {
        enclave_media::window_sources()
            .into_iter()
            .map(|s| (s.hwnd, s.name))
            .collect()
    }

    /// The cameras available to share (index + name), for a source picker.
    pub fn camera_sources(&self) -> Vec<(u32, String)> {
        enclave_media::camera_sources()
            .into_iter()
            .map(|s| (s.index, s.name))
            .collect()
    }

    /// Start sharing a monitor into the current call. Requires being in the call
    /// (the media session carries audio, screen, and camera together).
    pub fn start_screen_share(&mut self, monitor_index: usize) -> Result<(), ClientError> {
        let call = self
            .call
            .as_mut()
            .ok_or_else(|| ClientError::Audio("join the call before sharing".into()))?;
        call.start_screen(monitor_index)
    }

    /// Start sharing a single window into the current call.
    pub fn start_window_share(&mut self, hwnd: isize) -> Result<(), ClientError> {
        let call = self
            .call
            .as_mut()
            .ok_or_else(|| ClientError::Audio("join the call before sharing".into()))?;
        call.start_window(hwnd)
    }

    /// Stop sharing the screen or window, including any shared system audio (they
    /// are one logical share); the call keeps running.
    pub fn stop_screen_share(&mut self) {
        if let Some(call) = self.call.as_mut() {
            call.stop_screen();
            call.stop_system_audio();
        }
    }

    /// If the screen share ended on its own (the user cancelled the system
    /// picker, the compositor revoked the share, the capture died), tear it
    /// down -- shared system audio included -- and say why. Poll this from the
    /// event loop; `None` means the share is fine (or there is none).
    pub fn reap_ended_share(&mut self) -> Option<ShareEnded> {
        self.call.as_mut()?.reap_ended_screen()
    }

    /// The process id owning a window, for per-app audio (`None` where the
    /// platform cannot know, e.g. Wayland portal shares).
    pub fn window_pid(&self, hwnd: isize) -> Option<u32> {
        enclave_media::window_pid(hwnd)
    }

    /// Whether sharing a window here can carry just that app's audio
    /// (Windows, Linux X11) or shared audio is always the whole mix (Wayland).
    pub fn per_window_audio(&self) -> bool {
        enclave_media::per_window_audio_supported()
    }

    /// Start sharing system audio into the call. `pid` = one app (echo-free);
    /// `None` = the whole endpoint mix.
    pub fn start_system_audio(&mut self, pid: Option<u32>) -> Result<(), ClientError> {
        let call = self
            .call
            .as_mut()
            .ok_or_else(|| ClientError::Audio("join the call before sharing audio".into()))?;
        call.start_system_audio(pid)
    }

    /// Stop sharing system audio (the call keeps running).
    pub fn stop_system_audio(&mut self) {
        if let Some(call) = self.call.as_mut() {
            call.stop_system_audio();
        }
    }

    /// Whether we are currently sharing system audio.
    pub fn is_sharing_audio(&self) -> bool {
        self.call.as_ref().is_some_and(|c| c.is_sharing_audio())
    }

    /// Whether we are currently sharing our screen.
    pub fn is_sharing(&self) -> bool {
        self.call.as_ref().is_some_and(|c| c.is_sharing())
    }

    /// Start sharing a camera into the current call.
    pub fn start_camera(&mut self, camera_index: u32) -> Result<(), ClientError> {
        let call = self
            .call
            .as_mut()
            .ok_or_else(|| ClientError::Audio("join the call before sharing camera".into()))?;
        call.start_camera(camera_index)
    }

    /// Stop sharing the camera (the call keeps running).
    pub fn stop_camera(&mut self) {
        if let Some(call) = self.call.as_mut() {
            call.stop_camera();
        }
    }

    /// Whether our camera is currently being shared.
    pub fn is_camera_on(&self) -> bool {
        self.call.as_ref().is_some_and(|c| c.is_camera_on())
    }

    /// Mute or unmute our microphone for the current call.
    pub fn set_muted(&self, muted: bool) {
        if let Some(call) = self.call.as_ref() {
            call.set_muted(muted);
        }
    }

    /// Whether our microphone is currently muted.
    pub fn is_muted(&self) -> bool {
        self.call.as_ref().is_some_and(|c| c.is_muted())
    }

    /// Deafen or undeafen (mute/unmute incoming audio) for the current call.
    pub fn set_deafened(&self, deafened: bool) {
        if let Some(call) = self.call.as_ref() {
            call.set_deafened(deafened);
        }
    }

    /// Decline an incoming call in conversation `conv_hex` (we were rung but will
    /// not join). The caller is notified; the UI falls back to a "call active"
    /// banner so we can still join later.
    pub fn decline_call(&mut self, conv_hex: &str) {
        if let Some(group) = self.group_by_hex(conv_hex) {
            self.conn.send(ClientMsg::DeclineCall { group });
        }
    }

    /// Resolve the routing group id behind a hex conversation id from the UI.
    fn group_by_hex(&self, hex: &str) -> Option<GroupId> {
        self.conversations
            .keys()
            .find(|g| hex_id(g) == hex)
            .cloned()
    }

    /// The available audio devices and the current selection, for the settings
    /// picker. An empty selection means the host default is in use.
    pub fn audio_devices(&self) -> AudioDeviceInfo {
        AudioDeviceInfo {
            inputs: enclave_media::input_device_names(),
            outputs: enclave_media::output_device_names(),
            input: self.input_device.clone(),
            output: self.output_device.clone(),
        }
    }

    /// Choose the microphone. `None` restores the host default. Persisted to the
    /// machine-local prefs and, if a call is in progress, applied to it live.
    pub fn set_input_device(&mut self, name: Option<String>) -> Result<(), ClientError> {
        self.input_device = name.filter(|s| !s.is_empty());
        self.save_audio_prefs();
        if let Some(call) = self.call.as_mut() {
            call.set_input_device(self.input_device.as_deref())?;
        }
        Ok(())
    }

    /// Choose the speaker. `None` restores the host default. Persisted to the
    /// machine-local prefs and, if a call is in progress, applied to it live.
    pub fn set_output_device(&mut self, name: Option<String>) -> Result<(), ClientError> {
        self.output_device = name.filter(|s| !s.is_empty());
        self.save_audio_prefs();
        if let Some(call) = self.call.as_mut() {
            call.set_output_device(self.output_device.as_deref())?;
        }
        Ok(())
    }

    fn audio_prefs_path(&self) -> PathBuf {
        self.keystore_dir.join("enclave-audio.json")
    }

    fn save_audio_prefs(&self) {
        AudioPrefs {
            input: self.input_device.clone(),
            output: self.output_device.clone(),
        }
        .save(&self.audio_prefs_path());
    }

    /// The logged-in handle, or an error if not logged in.
    fn me(&self) -> Result<String, ClientError> {
        self.username.clone().ok_or(ClientError::NotLoggedIn)
    }

    /// The per-account session file (encrypted MLS state + conversations).
    fn session_path(&self) -> PathBuf {
        let user = self.username.as_deref().unwrap_or("unknown");
        let safe: String = user
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        self.keystore_dir.join(format!("enclave-{safe}.session"))
    }

    /// Persist the live conversations (MLS group state + scoped history)
    /// encrypted at rest under the OPAQUE export key.
    fn save_session(&self) {
        if self.export_key.is_empty() {
            return;
        }
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        let conversations = self
            .conversations
            .iter()
            .filter(|(_, c)| c.group.is_some())
            .map(|(routing, c)| session::PersistConv {
                routing_id: routing.0,
                mls_group_id: c.mls_group_id.clone(),
                is_dm: c.kind == ConvKind::Dm,
                title: c.title.clone(),
                members: c.members.clone(),
                verified: c.verified.clone(),
                history: c
                    .history
                    .iter()
                    .map(|l| session::PersistLine {
                        from: l.from.clone(),
                        text: l.text.clone(),
                        mine: l.mine,
                        file: l.file.as_ref().map(|f| session::PersistFile {
                            name: f.name.clone(),
                            size: f.size,
                            path: f.path.clone(),
                        }),
                    })
                    .collect(),
            })
            .collect();
        let data = session::SessionData {
            mls: identity.storage_snapshot(),
            conversations,
        };
        session::save(&self.session_path(), &self.export_key, &data);
    }

    /// Restore conversations (MLS state + history) from the encrypted session
    /// file, reloading each group so past chats are back after a restart.
    fn load_session(&mut self) {
        if self.export_key.is_empty() {
            return;
        }
        let data = session::load(&self.session_path(), &self.export_key);
        if data.conversations.is_empty() {
            return;
        }
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        identity.restore_storage(data.mls);
        let mut loaded: Vec<(GroupId, Conversation)> = Vec::new();
        for pc in data.conversations {
            let Ok(group) = Group::load(identity, &pc.mls_group_id) else {
                continue; // group state missing/corrupt; skip it
            };
            let history = pc
                .history
                .into_iter()
                .map(|l| ChatLine {
                    from: l.from,
                    text: l.text,
                    mine: l.mine,
                    file: l.file.map(|f| FileRef {
                        name: f.name,
                        size: f.size,
                        path: f.path,
                    }),
                })
                .collect();
            loaded.push((
                GroupId(pc.routing_id),
                Conversation {
                    group: Some(group),
                    mls_group_id: pc.mls_group_id,
                    kind: if pc.is_dm {
                        ConvKind::Dm
                    } else {
                        ConvKind::Group
                    },
                    title: pc.title,
                    members: pc.members,
                    verified: pc.verified,
                    reassembler: Reassembler::new(),
                    history,
                },
            ));
        }
        for (gid, conv) in loaded {
            // Re-announce our own routing membership so the server fans traffic
            // to us (bootstraps or re-affirms).
            self.conn.send(ClientMsg::JoinGroup { group: gid.clone() });
            // Then vouch for the peers we know share this conversation, so the
            // server can rebuild routing it lost (e.g. across a restart) instead
            // of locking them out of their own group. The server only honors this
            // because we just (re)affirmed membership; a non-member cannot use it.
            for member in &conv.members {
                if Some(member.as_str()) != self.username.as_deref() {
                    self.conn.send(ClientMsg::AffirmMember {
                        group: gid.clone(),
                        member: DeviceId(member.clone()),
                    });
                }
            }
            self.conversations.insert(gid, conv);
        }
    }

    /// Copy the encrypted session file to `dst` for backup or transfer. It opens
    /// only with the same account + password (export key) elsewhere.
    pub fn export_session(&self, dst: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::copy(self.session_path(), dst).map(|_| ())
    }

    /// Import a session file exported elsewhere, replacing the local one, and
    /// reload it into live conversations.
    pub fn import_session(&mut self, src: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::copy(src, self.session_path())?;
        self.conversations.clear();
        self.active = None;
        self.load_session();
        Ok(())
    }

    /// Await the next event, processing incoming server messages until one
    /// produces something the UI cares about. Returns `None` if disconnected.
    pub async fn next_event(&mut self) -> Option<Event> {
        enum Src {
            Msg(ServerMsg),
            Screen(call::ScreenFrameOut),
        }
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Some(event);
            }
            // Wait for a server message, or an incoming screen frame from the
            // active call. Disjoint field borrows so both can be selected on.
            let src = {
                let Self {
                    conn, screen_rx, ..
                } = &mut *self;
                match screen_rx.as_mut() {
                    Some(rx) => tokio::select! {
                        m = conn.recv() => Src::Msg(m?),
                        sf = rx.recv() => match sf {
                            Some(sf) => Src::Screen(sf),
                            None => continue, // screen channel closed with the call
                        },
                    },
                    None => Src::Msg(conn.recv().await?),
                }
            };
            match src {
                Src::Screen(sf) => {
                    return Some(Event::ScreenFrame {
                        from: self.display_of(&sf.from),
                        data: sf.h264,
                        keyframe: sf.keyframe,
                        camera: sf.camera,
                    });
                }
                Src::Msg(msg) => {
                    // A DM nudge needs an async follow-up (create the group +
                    // invite), which the sync `handle` cannot do -- service it
                    // here without stealing focus from the active conversation.
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
                let mls_group_id = joined.mls_group_id();
                self.conn.send(ClientMsg::JoinGroup {
                    group: group.clone(),
                });
                let is_dm = name.is_empty();
                match self.conversations.get_mut(&group) {
                    // Populate a pending DM (or re-affirm) by adopting the group.
                    Some(conv) => {
                        conv.group = Some(joined);
                        conv.mls_group_id = mls_group_id;
                    }
                    None => {
                        let me = self.username.clone().unwrap_or_default();
                        let title = if is_dm { from.0.clone() } else { name };
                        self.conversations.insert(
                            group,
                            Conversation {
                                group: Some(joined),
                                mls_group_id,
                                kind: if is_dm { ConvKind::Dm } else { ConvKind::Group },
                                title,
                                members: vec![me, from.0],
                                history: Vec::new(),
                                verified: None,
                                reassembler: Reassembler::new(),
                            },
                        );
                    }
                }
                self.save_session();
                Some(Event::ConversationsChanged)
            }
            ServerMsg::Text { group, message, .. } => {
                // Decrypt one sealed part and hand it to this conversation's
                // reassembler, all inside a tight borrow of `conv` so the rest
                // of the handler can touch `self` freely. A message/file becomes
                // visible only once its last part arrives.
                let (username, part_summary, complete) = {
                    let identity = self.identity.as_ref()?;
                    let conv = self.conversations.get_mut(&group)?;
                    let g = conv.group.as_mut()?;
                    let tm = match g.decrypt_text(identity, &message.0) {
                        Ok(tm) => tm,
                        Err(e) => return Some(Event::Error(format!("decrypt failed: {e}"))),
                    };
                    let username = String::from_utf8_lossy(&tm.sender).into_owned();
                    // A member sent a sealed blob that is not a valid part:
                    // authenticated but malformed, drop it quietly.
                    let part = transfer::Part::decode(&tm.plaintext)?;
                    // SECURITY: files must go through the consent flow (offer ->
                    // accept -> FileChunk), never the Text channel. Drop a
                    // File-meta part smuggled over Text so it can never
                    // auto-download, even from a malicious or outdated peer.
                    if matches!(part.meta, TransferMeta::File { .. }) {
                        return None;
                    }
                    let summary = (part.total > 1)
                        .then(|| (hex::encode(part.id), "message".to_string(), part.index, part.total));
                    let complete = conv.reassembler.accept(part);
                    (username, summary, complete)
                };

                let from_display = self
                    .display_names
                    .get(&username)
                    .cloned()
                    .unwrap_or_else(|| username.clone());

                let Some(done) = complete else {
                    // Still assembling: surface progress if this was multi-part.
                    if let Some((id, label, index, total)) = part_summary {
                        self.pending.push_back(Event::TransferProgress {
                            conv: hex_id(&group),
                            id,
                            label,
                            sent: (index as u64 + 1) * transfer::CHUNK_BYTES as u64,
                            total: total as u64 * transfer::CHUNK_BYTES as u64,
                            incoming: true,
                        });
                    }
                    return None;
                };

                // Only Text transfers reach here (File-meta parts were dropped
                // above); reject anything else defensively rather than treat it
                // as text.
                if !matches!(done.meta, TransferMeta::Text) {
                    return None;
                }
                let text = String::from_utf8_lossy(&done.data).into_owned();
                if let Some(conv) = self.conversations.get_mut(&group) {
                    conv.history.push(ChatLine {
                        from: username,
                        text: text.clone(),
                        mine: false,
                        file: None,
                    });
                }
                self.save_session();
                Some(Event::Message {
                    conv: hex_id(&group),
                    from: from_display,
                    text,
                    mine: false,
                })
            }
            ServerMsg::FileOffered {
                offer_id,
                group,
                from,
                manifest,
                live,
                ..
            } => self.handle_file_offered(offer_id, group, from, manifest, live),
            ServerMsg::FileUploadReady { offer_id } => {
                // The server admitted our stored offer: begin uploading (the
                // pump streams the bytes, paced by the connection).
                self.start_upload(offer_id);
                None
            }
            ServerMsg::FileAccepted { offer_id, .. } => {
                // For a live offer this is the cue to start streaming; for a
                // stored one the server delivers, so it is informational.
                if self
                    .outgoing_files
                    .get(&offer_id)
                    .is_some_and(|o| o.live && !o.started)
                {
                    self.start_upload(offer_id);
                }
                None
            }
            ServerMsg::FileOfferRejected { offer_id, reason } => {
                self.handle_offer_rejected(offer_id, reason)
            }
            ServerMsg::FileDeclined { offer_id, by } => self.handle_file_declined(offer_id, by),
            ServerMsg::FileChunk { offer_id, from: _, data } => {
                self.handle_file_chunk(offer_id, data)
            }
            ServerMsg::FileComplete { offer_id, .. } => self.handle_file_complete(offer_id),
            ServerMsg::Mls { group, message, .. } => {
                let identity = self.identity.as_ref()?;
                let conv = self.conversations.get_mut(&group)?;
                let g = conv.group.as_mut()?;
                match g.apply_commit(identity, &message.0) {
                    Ok(()) => {
                        self.save_session();
                        Some(Event::ConversationsChanged)
                    }
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
            ServerMsg::CallOffer { group, from } => Some(Event::CallOffer {
                conv: hex_id(&group),
                from: self.display_of(&from),
            }),
            ServerMsg::CallParticipants {
                group,
                participants,
            } => Some(Event::CallParticipants {
                conv: hex_id(&group),
                participants: participants.iter().map(|p| self.display_of(p)).collect(),
            }),
            ServerMsg::CallDeclined { group, from } => Some(Event::CallDeclined {
                conv: hex_id(&group),
                from: self.display_of(&from),
            }),
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

/// A fresh random 128-bit transfer id.
fn new_transfer_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let _ = getrandom::getrandom(&mut id);
    id
}

/// Read up to `buf.len()` bytes, retrying short reads so a full chunk is
/// returned even if the OS hands back the file in pieces. Returns the count
/// (less than `buf.len()` only at end of file).
fn read_full(reader: &mut impl std::io::Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Reduce an attacker-controlled filename to a safe base name: the final path
/// component only, with separators and control characters stripped, never
/// empty, never `.`/`..`. This is the primary defense against path traversal
/// (a peer naming a file `../../.ssh/authorized_keys`) -- see THREAT_MODEL.md.
fn safe_file_name(raw: &str) -> String {
    // Take only the last component under either separator, so any directory
    // prefix (`../`, `/etc/`, `C:\`) is discarded before we look at the name.
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\' && *c != '\0')
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').trim();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        // Cap the length so a pathological name cannot blow past filesystem
        // limits; keep the tail (extension) rather than the head.
        let max = 200;
        if trimmed.len() <= max {
            trimmed.to_string()
        } else {
            trimmed[trimmed.len() - max..].to_string()
        }
    }
}

/// Reserve a fresh file under `dir` for an incoming download: sanitize `name`,
/// never escape `dir`, and never overwrite (if the name is taken, ` (1)`,
/// ` (2)`, ... is appended). Returns the opened file handle and its path; the
/// caller streams the bytes into it. `create_new` reserves the name atomically,
/// so two arrivals cannot race onto one path. Verifies the path is genuinely
/// inside `dir` (defense in depth against any sanitization gap). See
/// THREAT_MODEL.md: the filename is attacker-controlled.
fn reserve_download(dir: &std::path::Path, name: &str) -> std::io::Result<(std::fs::File, PathBuf)> {
    std::fs::create_dir_all(dir)?;
    // Canonicalize the target directory so the containment check compares real
    // paths, not ones with symlinks or `.` segments.
    let base = dir.canonicalize()?;
    let safe = safe_file_name(name);
    let (stem, ext) = match safe.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (safe.clone(), String::new()),
    };

    for n in 0..10_000 {
        let candidate = if n == 0 {
            format!("{stem}{ext}")
        } else {
            format!("{stem} ({n}){ext}")
        };
        let path = base.join(&candidate);
        // Containment: the parent of the target must still be `base`. A crafted
        // name that somehow reintroduced a separator would fail this.
        if path.parent() != Some(base.as_path()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to write outside the downloads directory",
            ));
        }
        // create_new is atomic: it fails if the file exists, so two arrivals
        // cannot race onto the same name.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(f) => return Ok((f, path)),
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "too many files with that name",
    ))
}

/// Parse a hex offer id from the UI back into raw bytes. `None` if malformed.
fn decode_offer_id(hex_id: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_id).ok()?;
    bytes.try_into().ok()
}

/// Best-effort MIME type from a filename extension. Used only as a hint in the
/// UI; a received file is never opened or executed based on it.
fn mime_from_name(name: &str) -> String {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("txt" | "md" | "log") => "text/plain",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// The available audio devices plus the current selection, for the settings
/// picker. An empty `input`/`output` means the host default is in use.
#[derive(Debug, Clone)]
pub struct AudioDeviceInfo {
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub input: Option<String>,
    pub output: Option<String>,
}

/// Machine-local audio device preferences: which mic and speaker to use for
/// calls on this device. This is not account data; it holds no secrets, is the
/// same regardless of which account logs in here, and never leaves the machine,
/// so it is stored as plain JSON next to the keystore rather than in the
/// encrypted session.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct AudioPrefs {
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    output: Option<String>,
}

impl AudioPrefs {
    fn load(path: &std::path::Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &std::path::Path) {
        if let Ok(json) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }
}

/// Derive the UDP media address from the `ws(s)://host:port` signaling URL: the
/// same host, on the server's media port (8444 by default).
fn media_addr_from(server_url: &str) -> Option<SocketAddr> {
    let rest = server_url
        .strip_prefix("ws://")
        .or_else(|| server_url.strip_prefix("wss://"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
    format!("{host}:8444").to_socket_addrs().ok()?.next()
}

#[cfg(test)]
mod file_security_tests {
    use super::{reserve_download, safe_file_name};
    use std::io::Write;
    use std::path::PathBuf;

    // Reserve a download path and write `data` into it, mirroring how the
    // streaming sink lands a file. Returns the final path.
    fn write_received(dir: &std::path::Path, name: &str, data: &[u8]) -> std::io::Result<PathBuf> {
        let (mut file, path) = reserve_download(dir, name)?;
        file.write_all(data)?;
        Ok(path)
    }

    #[test]
    fn path_traversal_names_are_neutralized() {
        // Every one of these must reduce to a harmless base name, never a path.
        for evil in [
            "../../../../etc/passwd",
            "/etc/shadow",
            "..\\..\\Windows\\System32\\cmd.exe",
            "....//....//secret",
            "foo/bar/baz.txt",
            "a/../../b",
        ] {
            let safe = safe_file_name(evil);
            assert!(!safe.contains('/'), "{evil} -> {safe} still has /");
            assert!(!safe.contains('\\'), "{evil} -> {safe} still has \\");
            assert_ne!(safe, "..", "{evil} -> {safe}");
            assert_ne!(safe, ".", "{evil} -> {safe}");
            assert!(!safe.is_empty());
        }
    }

    #[test]
    fn degenerate_names_get_a_fallback() {
        for empty in ["", "   ", "..", ".", "/", "\\", "///", "..."] {
            assert_eq!(safe_file_name(empty), "file", "{empty:?}");
        }
    }

    #[test]
    fn control_chars_and_nulls_are_stripped() {
        assert_eq!(safe_file_name("re\0port\n.pdf"), "report.pdf");
    }

    #[test]
    fn a_written_file_never_escapes_the_downloads_dir() {
        let dir = std::env::temp_dir().join(format!("enclave-sec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // A traversal name must land INSIDE dir, not at its parent.
        let path = write_received(&dir, "../escaped.txt", b"x").expect("write");
        let canon_dir = dir.canonicalize().unwrap();
        assert!(
            path.starts_with(&canon_dir),
            "{path:?} escaped {canon_dir:?}"
        );
        assert!(
            !std::fs::metadata(dir.join("../escaped.txt")).is_ok_and(|_| true)
                || !dir.parent().unwrap().join("escaped.txt").exists()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_existing_file_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("enclave-sec2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let p1 = write_received(&dir, "doc.txt", b"first").unwrap();
        let p2 = write_received(&dir, "doc.txt", b"second").unwrap();
        assert_ne!(p1, p2, "second file must get a distinct name");
        assert_eq!(
            std::fs::read(&p1).unwrap(),
            b"first",
            "first file untouched"
        );
        assert_eq!(std::fs::read(&p2).unwrap(), b"second");
        assert!(p2.to_string_lossy().contains("(1)"), "got {p2:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
