//! The relay routing core: a pure state machine, no async, no sockets.
//!
//! This is the delivery service's brain. It tracks who is online, holds
//! published key packages, and knows which devices route into which group --
//! all *metadata*. It never inspects message content: every payload it moves is
//! an opaque [`Sealed`] blob. Keeping it pure makes the routing exhaustively
//! unit-testable without spinning up a network.
//!
//! The async WebSocket shell in [`crate::server`] owns one `Relay` and simply
//! feeds it decoded [`ClientMsg`]s, then ships the [`Outgoing`] results to the
//! addressed connections.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use enclave_protocol::{
    ClientMsg, DeviceId, Friend, GroupId, Permission, Presence, Sealed, ServerMsg, UserId,
};

use crate::accounts::{AccountStore, AuthOutcome};
use crate::avatarstore::AvatarStore;
use crate::filestore::FileStore;
use crate::friends::{FriendStore, RequestOutcome};
use crate::groups::GroupStore;
use crate::msgqueue::MessageQueue;
use crate::opaque::{OpaqueServer, ServerLoginState};
use crate::workspaces::WorkspaceStore;

/// Opaque handle for one client connection. Assigned by the relay on connect.
pub type ConnId = u64;

/// Failed logins allowed per connection before it is locked out (ASVS V2).
const MAX_LOGIN_ATTEMPTS: u32 = 5;

/// How long a live (streamed) file offer waits for the recipient to accept
/// before it lapses. Live transfer is "like a call": the sender is online and
/// streaming, so the window is short.
const LIVE_OFFER_TTL: Duration = Duration::from_secs(90);

/// Concurrent file offers one sender may have open at once (stored + live),
/// so a member cannot spam offers to exhaust store metadata/inodes (ASVS V11).
const MAX_OFFERS_PER_SENDER: usize = 32;

/// The empty device id the server uses as the `by` of a `FileDeclined` that is
/// really a lapse (TTL) or a sender cancel, not a specific recipient's refusal.
const NO_DEVICE: &str = "";

/// A message the relay wants delivered to a specific connection.
#[derive(Debug, Clone)]
pub struct Outgoing {
    pub to: ConnId,
    pub msg: ServerMsg,
}

/// A stored blob the async server should stream to a recipient off the relay
/// lock (so a large read never blocks all other connections). Produced by a
/// `FileAccept` on a stored offer; the server streams the blob via
/// [`crate::filestore::BlobReader`], then calls
/// [`Relay::finish_stored_delivery`] or [`Relay::abort_stored_delivery`].
#[derive(Debug, Clone)]
pub struct BlobDelivery {
    /// The accepting recipient's connection.
    pub to: ConnId,
    /// The accepting recipient's device (to resolve the offer afterwards).
    pub recipient: DeviceId,
    pub offer_id: [u8; 16],
    /// The original sender device, for the chunk envelope.
    pub from: DeviceId,
    pub blob: PathBuf,
    /// Set true to ask the off-lock streamer to stop early (the recipient aborted
    /// the download). The streamer checks it between chunks and, when set, stops
    /// and leaves the offer pending so the recipient can download it again.
    pub cancel: Arc<AtomicBool>,
}

/// One stored-upload chunk to flush to disk off the global lock. The size cap
/// and byte accounting were already reserved under the lock; only the write
/// itself is deferred, so a slow disk never stalls the relay.
#[derive(Debug, Clone)]
pub struct FileAppend {
    /// The offer whose write this is (to drop the offer on a write error).
    pub offer_id: [u8; 16],
    /// The blob file to append to.
    pub blob: PathBuf,
    /// The chunk bytes to write (length-prefixed by `write_reserved`).
    pub data: Vec<u8>,
}

/// A live (streamed, never stored) file offer in flight.
struct LiveOffer {
    sender: DeviceId,
    /// Recipients the offer was sent to and who are still candidates.
    recipients: HashSet<DeviceId>,
    /// Recipients who accepted; the sender's chunks are relayed to them.
    accepted: HashSet<DeviceId>,
    expires_at: SystemTime,
}

/// Routing state for the signaling + delivery service. Holds no keys and no
/// message content.
pub struct Relay {
    next_conn: ConnId,
    /// Online devices and their current connection (both directions).
    device_conn: HashMap<DeviceId, ConnId>,
    conn_device: HashMap<ConnId, DeviceId>,
    /// The one reusable (last-resort) key package published per user, handed out
    /// on every fetch without being consumed.
    key_packages: HashMap<UserId, Vec<u8>>,
    /// Last-seen identity public key per user (reference only).
    identities: HashMap<UserId, Vec<u8>>,
    /// Group routing fan-out sets: which devices should receive group traffic.
    /// Persisted, so conversations survive a server restart.
    groups: GroupStore,
    /// Buffered/routed poll ballots, keyed by poll id. In-memory: a server restart
    /// mid-poll loses buffered ballots (a documented limitation; the content is
    /// opaque either way). The server never reads a ballot -- it only withholds and
    /// routes them per the poll's mode.
    ballots: HashMap<[u8; 16], BufferedPoll>,
    /// Who is currently in the voice call of each group. Ephemeral (a call is a
    /// live session): not persisted, and cleared as participants leave/disconnect.
    active_calls: HashMap<GroupId, HashSet<DeviceId>>,
    /// Store-and-forward queue for members who are offline; delivered on their
    /// next login. Persisted, so offline messages survive a restart.
    queue: MessageQueue,
    /// Learned UDP endpoint per device, for the real-time media channel.
    udp_addrs: HashMap<DeviceId, SocketAddr>,
    /// The user on each connection (from Register), for presence.
    conn_user: HashMap<ConnId, UserId>,
    /// Last-known presence per user.
    presence: HashMap<UserId, Presence>,
    /// Connections that want presence updates about a given user (friends).
    presence_watchers: HashMap<UserId, HashSet<ConnId>>,
    /// Accounts (OPAQUE envelope + identity key). Server never sees passwords.
    accounts: AccountStore,
    /// The friend graph (accepted friends + pending requests). Metadata.
    friends: FriendStore,
    /// Workspace op-logs + membership index (metadata; content stays E2E).
    workspaces: WorkspaceStore,
    /// Who is currently connected to each voice channel, `(workspace, channel) ->
    /// handles`. In memory; cleared for a handle on disconnect.
    voice_presence: HashMap<([u8; 16], [u8; 16]), HashSet<String>>,
    /// The server's long-term OPAQUE state (OPRF seed + static keypair).
    opaque: OpaqueServer,
    /// In-flight OPAQUE logins, keyed by connection, between the two round-trips.
    pending_login: HashMap<ConnId, PendingLogin>,
    /// Handles reserved by an in-flight registration, so two concurrent sign-ups
    /// of the same name cannot be assigned the same `name#1234`.
    reserved: HashSet<String>,
    /// The handle reserved for the registration in progress on each connection.
    pending_register: HashMap<ConnId, String>,
    /// Failed login attempts per connection, for lockout.
    login_attempts: HashMap<ConnId, u32>,
    /// On-disk store for offered files awaiting the recipient's consent (stored
    /// path). Holds opaque sealed blobs; enforces the size/disk quota + TTL.
    files: FileStore,
    /// Persistent, content-addressed store for encrypted profile avatars. Holds
    /// opaque ciphertext; the address-equals-hash check bounds it against
    /// poisoning and the per-user ring bounds its size.
    avatars: AvatarStore,
    /// Live (streamed, never stored) file offers, keyed by offer id.
    live_offers: HashMap<[u8; 16], LiveOffer>,
    /// Stored-blob deliveries the async shell should stream off-lock. Drained
    /// after each `handle` via [`take_blob_deliveries`](Self::take_blob_deliveries).
    blob_deliveries: Vec<BlobDelivery>,
    /// Cancel flags for in-flight stored deliveries, keyed by (offer, recipient).
    /// A recipient's `FileAbort` sets its flag so the off-lock streamer stops
    /// early; the flag is removed when the delivery finishes or aborts.
    delivery_tokens: HashMap<([u8; 16], DeviceId), Arc<AtomicBool>>,
    /// Stored-upload chunk writes the async shell should flush to disk OFF the
    /// global lock (a slow disk write under the lock would stall every client).
    /// Drained after each `handle` via [`take_file_appends`](Self::take_file_appends).
    file_appends: Vec<FileAppend>,
    /// Injected wall clock, so file TTLs are testable. Defaults to the system
    /// clock; the async shell may leave it as is.
    now: Box<dyn Fn() -> SystemTime + Send>,
}

/// A poll whose ballots the server buffers/routes on the group's behalf, WITHOUT
/// ever seeing their content (each ballot is opaque `Sealed` bytes). `mode`: 0 =
/// release the whole set to the GROUP at close; 1 = route each ballot to the OWNER
/// live (a private survey the owner watches); 2 = buffer and release to the OWNER
/// at close. The owner is the device that opened the poll -- the only one that may
/// close it early.
/// Quotas on buffered polls. An open poll costs the relay memory until it is
/// released, so their number is bounded per owner AND globally, and a ballot is
/// bounded in size. These are far above real use: a poll is a handful of bytes
/// of bookkeeping, and a real ballot is a fixed-width sealed body (plus a ring
/// signature on an anonymous poll, which grows only with the group's size), so
/// the caps bite only on abuse.
const MAX_OPEN_POLLS_PER_DEVICE: usize = 16;
const MAX_OPEN_POLLS_TOTAL: usize = 1024;
/// Generous ceiling for one sealed ballot: a plain ballot is ~76 bytes, and an
/// anonymous one adds ~32 bytes per ring member, so this still admits a ring of
/// several hundred while refusing a blob sent to exhaust memory.
const MAX_BALLOT_BYTES: usize = 16 * 1024;
/// How long an un-closed poll may sit before the relay reclaims it. Without
/// this, a poll opened with no deadline and never closed would hold its owner's
/// quota (and the relay's memory) forever.
const POLL_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

struct BufferedPoll {
    owner: DeviceId,
    group: GroupId,
    mode: u8,
    /// Auto-release time; `None` = owner-triggered close only.
    release_at: Option<SystemTime>,
    /// Strip submitter attribution on release (an anonymous poll). Independent of
    /// `mode`, which decides only who receives the ballots and when.
    anonymous: bool,
    /// When the poll was opened, so an abandoned one can be reclaimed (POLL_TTL).
    opened_at: SystemTime,
    /// Sealed ballots, deduped by submitter device (last write wins).
    ballots: HashMap<DeviceId, Sealed>,
}

impl Default for Relay {
    fn default() -> Self {
        Relay::new()
    }
}

/// Server-side state for an OPAQUE login in progress on one connection.
struct PendingLogin {
    handle: String,
    state: ServerLoginState,
}

impl Relay {
    pub fn new() -> Self {
        Self {
            next_conn: 0,
            device_conn: HashMap::new(),
            conn_device: HashMap::new(),
            key_packages: HashMap::new(),
            identities: HashMap::new(),
            groups: GroupStore::default(),
            ballots: HashMap::new(),
            active_calls: HashMap::new(),
            queue: MessageQueue::new(),
            udp_addrs: HashMap::new(),
            conn_user: HashMap::new(),
            presence: HashMap::new(),
            presence_watchers: HashMap::new(),
            accounts: AccountStore::default(),
            friends: FriendStore::default(),
            workspaces: WorkspaceStore::new(),
            voice_presence: HashMap::new(),
            opaque: OpaqueServer::default(),
            pending_login: HashMap::new(),
            reserved: HashSet::new(),
            pending_register: HashMap::new(),
            login_attempts: HashMap::new(),
            files: fresh_file_store(),
            avatars: fresh_avatar_store(),
            live_offers: HashMap::new(),
            blob_deliveries: Vec::new(),
            delivery_tokens: HashMap::new(),
            file_appends: Vec::new(),
            now: Box::new(SystemTime::now),
        }
    }

    /// Create a relay backed by a specific (e.g. persistent) account store, with
    /// a fresh ephemeral OPAQUE setup. Use [`Relay::with_auth`] to also supply a
    /// persistent OPAQUE setup (required so accounts survive a restart).
    pub fn with_accounts(accounts: AccountStore) -> Self {
        Self {
            accounts,
            ..Self::new()
        }
    }

    /// Create a relay backed by a persistent account store, OPAQUE setup,
    /// friend graph, group routing, offline queue, and an on-disk file store
    /// rooted at `files_dir`. The account envelopes are only usable under the
    /// OPAQUE setup they were registered against, so those two must persist
    /// together.
    pub fn with_auth(
        accounts: AccountStore,
        opaque: OpaqueServer,
        friends: FriendStore,
        workspaces: WorkspaceStore,
        groups: GroupStore,
        queue: MessageQueue,
        files_dir: PathBuf,
    ) -> Self {
        Self {
            accounts,
            opaque,
            friends,
            workspaces,
            groups,
            queue,
            avatars: AvatarStore::load(files_dir.join("avatars")),
            files: FileStore::new(files_dir),
            ..Self::new()
        }
    }

    /// Replace the wall clock (tests inject a fixed/advanceable time so file
    /// TTLs are deterministic).
    pub fn set_clock(&mut self, clock: impl Fn() -> SystemTime + Send + 'static) {
        self.now = Box::new(clock);
    }

    /// Point the file store at a specific directory with an injected free-disk
    /// probe (tests, to exercise the disk-floor without a real full disk).
    pub fn set_file_store(&mut self, store: FileStore) {
        self.files = store;
    }

    /// Register a new connection and get its id.
    pub fn connect(&mut self) -> ConnId {
        let id = self.next_conn;
        self.next_conn += 1;
        id
    }

    /// Drop a connection: forget its device, remove it from all routing sets,
    /// and (if this was the user's last connection) broadcast that they went
    /// offline. Returns any presence updates to deliver.
    pub fn disconnect(&mut self, conn: ConnId) -> Vec<Outgoing> {
        let mut out = Vec::new();
        if let Some(device) = self.conn_device.remove(&conn) {
            self.device_conn.remove(&device);
            self.udp_addrs.remove(&device);
            // Keep the device in `groups`: membership is account-level and
            // persisted, so a member who reconnects (or comes back after a server
            // restart) stays a routing member. Offline devices are already
            // skipped by fan-out (they are not in device_conn).
            // But do drop them from any live call and tell the other participants.
            out.extend(self.drop_from_calls(&device));
            // Drop them from any voice channel presence too.
            out.extend(self.clear_voice_for(&device.0));
            // Tear down live file offers the device was streaming, and drop it
            // from live offers it was receiving (a stored offer survives: its
            // blob is on disk and can be delivered/accepted after reconnect).
            out.extend(self.drop_from_live_offers(&device));
        }
        self.login_attempts.remove(&conn);
        self.pending_login.remove(&conn);
        if let Some(handle) = self.pending_register.remove(&conn) {
            self.reserved.remove(&handle);
        }
        for watchers in self.presence_watchers.values_mut() {
            watchers.remove(&conn);
        }
        if let Some(user) = self.conn_user.remove(&conn) {
            if !self.conn_user.values().any(|u| *u == user) {
                out.extend(self.set_presence(&user, Presence::Offline));
            }
        }
        out
    }

    /// Establish an authenticated session for `conn`: map user/device, publish
    /// the key package, and mark online.
    fn setup_session(
        &mut self,
        conn: ConnId,
        handle: String,
        identity_pub: Vec<u8>,
        key_package: Vec<u8>,
    ) -> Vec<Outgoing> {
        let user = UserId(handle.clone());
        let device = DeviceId(handle.clone());
        self.identities.insert(user.clone(), identity_pub);
        self.device_conn.insert(device.clone(), conn);
        self.conn_device.insert(conn, device);
        self.conn_user.insert(conn, user.clone());
        self.key_packages.insert(user.clone(), key_package);

        let mut out = vec![Outgoing {
            to: conn,
            msg: self.friends_snapshot(&handle),
        }];
        // Deliver anything queued while this device was offline (text, MLS
        // handshakes, Welcomes), in order, before live traffic resumes.
        for msg in self.queue.take(&handle) {
            out.push(Outgoing { to: conn, msg });
        }
        // Wire mutual friend presence BEFORE announcing, so online friends are
        // already watching us when the Online broadcast goes out.
        out.extend(self.wire_friend_presence(conn, &handle));
        out.extend(self.set_presence(&user, Presence::Online));
        out
    }

    /// Set up mutual presence watching between `handle` (on `conn`) and each of
    /// its friends, returning each friend's current presence for `conn`.
    fn wire_friend_presence(&mut self, conn: ConnId, handle: &str) -> Vec<Outgoing> {
        let mut out = Vec::new();
        for f in self.friends.friends_of(handle) {
            let fu = UserId(f.clone());
            // We watch the friend.
            self.presence_watchers
                .entry(fu.clone())
                .or_default()
                .insert(conn);
            if let Some(&status) = self.presence.get(&fu) {
                out.push(Outgoing {
                    to: conn,
                    msg: ServerMsg::Presence { user: fu, status },
                });
            }
            // If the friend is online, they watch us.
            if let Some(&f_conn) = self.device_conn.get(&DeviceId(f)) {
                self.presence_watchers
                    .entry(UserId(handle.to_string()))
                    .or_default()
                    .insert(f_conn);
            }
        }
        out
    }

    /// Two handles just became friends: wire presence both ways and notify the
    /// other side (if online). `me` is on `my_conn`.
    fn on_new_friendship(&mut self, my_conn: ConnId, me: &str, other: &str) -> Vec<Outgoing> {
        let mut out = self.wire_friend_presence(my_conn, me);
        out.push(Outgoing {
            to: my_conn,
            msg: self.friends_snapshot(me),
        });
        if let Some(&other_conn) = self.device_conn.get(&DeviceId(other.to_string())) {
            out.push(Outgoing {
                to: other_conn,
                msg: ServerMsg::FriendAccepted {
                    handle: me.to_string(),
                },
            });
            out.extend(self.wire_friend_presence(other_conn, other));
            out.push(Outgoing {
                to: other_conn,
                msg: self.friends_snapshot(other),
            });
        }
        out
    }

    /// Record a user's presence and return updates for everyone watching them.
    fn set_presence(&mut self, user: &UserId, status: Presence) -> Vec<Outgoing> {
        self.presence.insert(user.clone(), status);
        match self.presence_watchers.get(user) {
            Some(watchers) => watchers
                .iter()
                .map(|&conn| Outgoing {
                    to: conn,
                    msg: ServerMsg::Presence {
                        user: user.clone(),
                        status,
                    },
                })
                .collect(),
            None => vec![],
        }
    }

    // --- Real-time UDP media channel ---

    /// A device announces its UDP endpoint and the group it will stream to.
    pub fn udp_hello(&mut self, src: SocketAddr, device: DeviceId, group: GroupId) {
        self.udp_addrs.insert(device.clone(), src);
        // Same deny-by-default rule as JoinGroup: only bootstrap or re-affirm.
        self.groups.join(group, device);
    }

    /// Learn `sender`'s current UDP endpoint from an incoming frame, and return
    /// the UDP endpoints of the other group members to forward it to. A
    /// non-member is dropped (ASVS V4).
    pub fn udp_media_targets(
        &mut self,
        src: SocketAddr,
        group: &GroupId,
        sender: &DeviceId,
    ) -> Vec<SocketAddr> {
        self.udp_addrs.insert(sender.clone(), src);
        if !self.is_member(group, sender) {
            return vec![];
        }
        let Some(members) = self.groups.members(group) else {
            return vec![];
        };
        members
            .iter()
            .filter(|device| *device != sender)
            .filter_map(|device| self.udp_addrs.get(device).copied())
            .collect()
    }

    /// Handle one client message, returning messages to deliver. Pure: the only
    /// effect is on `self`'s routing state.
    pub fn handle(&mut self, from: ConnId, msg: ClientMsg) -> Vec<Outgoing> {
        // Auth gate (ASVS V4): only the OPAQUE handshake messages are allowed
        // before a session is established.
        match &msg {
            ClientMsg::RegisterStart { .. }
            | ClientMsg::RegisterFinish { .. }
            | ClientMsg::LoginStart { .. }
            | ClientMsg::LoginFinish { .. }
            | ClientMsg::Logout => {}
            _ if self.conn_user.contains_key(&from) => {}
            _ => return vec![],
        }
        match msg {
            // A reliability wrapper: route the inner message exactly as if it
            // were sent bare. The ack that confirms durable acceptance is added
            // by the async shell (it knows whether delivery/persistence
            // succeeded); the pure relay only routes.
            ClientMsg::Reliable { msg, .. } => self.handle(from, *msg),

            ClientMsg::RegisterStart { name, request } => {
                // Release any prior in-flight reservation on this connection.
                if let Some(prev) = self.pending_register.remove(&from) {
                    self.reserved.remove(&prev);
                }
                let name = name.trim().to_string();
                let valid = !name.is_empty()
                    && name.chars().count() <= 24
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
                if !valid {
                    return auth_fail(
                        from,
                        String::new(),
                        "usernames are 1-24 chars: letters, digits, . _ -",
                    );
                }
                let Some(handle) = self.claim_username(&name) else {
                    return auth_fail(from, name, "that username is taken");
                };
                match self.opaque.register_start(&handle, &request) {
                    Ok(response) => {
                        self.reserved.insert(handle.clone());
                        self.pending_register.insert(from, handle.clone());
                        vec![Outgoing {
                            to: from,
                            msg: ServerMsg::RegisterResponse { handle, response },
                        }]
                    }
                    Err(_) => auth_fail(from, name, "registration failed"),
                }
            }

            ClientMsg::RegisterFinish {
                upload,
                identity_pub,
                key_package,
                display,
            } => {
                // The username was claimed and reserved at RegisterStart.
                let Some(handle) = self.pending_register.remove(&from) else {
                    return auth_fail(from, String::new(), "registration expired; start over");
                };
                self.reserved.remove(&handle);
                let envelope = match self.opaque.register_finish(&upload) {
                    Ok(env) => env,
                    Err(_) => return auth_fail(from, handle, "registration failed"),
                };
                match self.accounts.create_account(
                    &handle,
                    envelope,
                    identity_pub.clone(),
                    display,
                    self.now_secs(),
                ) {
                    AuthOutcome::Created => {
                        let display = self.accounts.display(&handle);
                        let mut out = vec![Outgoing {
                            to: from,
                            msg: ServerMsg::Auth {
                                ok: true,
                                handle: handle.clone(),
                                display,
                                detail: "account created".into(),
                            },
                        }];
                        out.extend(self.setup_session(from, handle, identity_pub, key_package));
                        out
                    }
                    // The handle was reserved unique, so these should not occur.
                    AuthOutcome::UsernameTaken => auth_fail(from, handle, "that handle is taken"),
                    AuthOutcome::InvalidUsername => auth_fail(from, handle, "invalid handle"),
                }
            }

            ClientMsg::LoginStart { handle, request } => {
                if *self.login_attempts.get(&from).unwrap_or(&0) >= MAX_LOGIN_ATTEMPTS {
                    return auth_fail(from, handle, "too many attempts; reconnect to retry");
                }
                // Unknown handles take the same path via OPAQUE dummy mode (a
                // `None` envelope), so a login attempt cannot enumerate handles.
                let envelope = self.accounts.envelope(&handle).map(|e| e.to_vec());
                match self
                    .opaque
                    .login_start(&handle, envelope.as_deref(), &request)
                {
                    Ok((response, state)) => {
                        self.pending_login
                            .insert(from, PendingLogin { handle, state });
                        vec![Outgoing {
                            to: from,
                            msg: ServerMsg::LoginResponse { response },
                        }]
                    }
                    Err(_) => auth_fail(from, handle, "wrong handle or password"),
                }
            }

            ClientMsg::LoginFinish {
                finalization,
                key_package,
            } => {
                let Some(PendingLogin { handle, state }) = self.pending_login.remove(&from) else {
                    return vec![];
                };
                match state.finish(&finalization) {
                    // Dummy mode never yields Ok, so a success implies the account
                    // exists and the password was correct.
                    Ok(()) => {
                        self.login_attempts.remove(&from);
                        let identity_pub = self
                            .accounts
                            .identity_pub(&handle)
                            .map(|s| s.to_vec())
                            .unwrap_or_default();
                        let display = self.accounts.display(&handle);
                        let mut out = vec![Outgoing {
                            to: from,
                            msg: ServerMsg::Auth {
                                ok: true,
                                handle: handle.clone(),
                                display,
                                detail: "logged in".into(),
                            },
                        }];
                        out.extend(self.setup_session(from, handle, identity_pub, key_package));
                        out
                    }
                    Err(_) => {
                        *self.login_attempts.entry(from).or_insert(0) += 1;
                        auth_fail(from, handle, "wrong username or password")
                    }
                }
            }

            ClientMsg::Logout => self.disconnect(from),

            ClientMsg::FetchKeyPackages { user } => {
                // Last-resort key packages are reusable: hand it out without
                // consuming it, so a peer can be added to unlimited groups.
                let packages = self.key_packages.get(&user).cloned().into_iter().collect();
                vec![Outgoing {
                    to: from,
                    msg: ServerMsg::KeyPackages { user, packages },
                }]
            }

            ClientMsg::JoinGroup { group } => {
                if let Some(device) = self.conn_device.get(&from).cloned() {
                    // Deny-by-default (ASVS V4): a self-join may only bootstrap a
                    // new (empty) group or re-affirm existing membership. Joining
                    // an existing group is done via a Welcome from a member.
                    self.groups.join(group.clone(), device);
                }
                // Hand the (re)joining member the current membership so a returning
                // client's count is correct even after changes it missed offline.
                self.members_broadcast(&group)
            }

            ClientMsg::AffirmMember { group, member } => {
                // Only an existing routing member may vouch another device into a
                // group (deny-by-default, ASVS V4). This lets a reconnecting
                // member rebuild routing the server lost, re-adding peers the
                // bootstrap-or-reaffirm rule would reject; a non-member's vouch is
                // ignored, so a guessable (DM) group id cannot be used to
                // subscribe to a conversation you are not in.
                let voucher = self.device_for(from);
                if self.is_member(&group, &voucher) {
                    self.groups.add(&group, member);
                }
                vec![]
            }

            ClientMsg::LeaveGroup { group } => {
                let device = self.device_for(from);
                self.groups.remove(&group, &device);
                // Remaining members get the new authoritative membership (count
                // updates for everyone online now, and on their next join if not).
                let mut out = self.members_broadcast(&group);
                // Also drop the leaver from the group's live call, if any.
                out.extend(self.drop_from_calls(&device));
                out
            }

            ClientMsg::RemoveMember { group, member } => {
                // Only a current member may remove another from routing (ASVS V4).
                let remover = self.device_for(from);
                if !self.is_member(&group, &remover) {
                    return vec![];
                }
                self.groups.remove(&group, &member);
                // Tell the removed member (if online) so they can mark the group
                // read-only; the relayed removal commit may not reach them once
                // de-routed, so this is the reliable signal. The rest get the new
                // authoritative membership.
                let mut out = self.members_broadcast(&group);
                if let Some(&conn) = self.device_conn.get(&member) {
                    out.push(Outgoing {
                        to: conn,
                        msg: ServerMsg::RemovedFromGroup { group },
                    });
                }
                out
            }

            ClientMsg::Welcome {
                to,
                group,
                name,
                message,
            } => {
                let from_device = self.device_for(from);
                // Only a current member may invite (ASVS V4, deny-by-default).
                if !self.is_member(&group, &from_device) {
                    return vec![];
                }
                self.groups.add(&group, to.clone());
                let welcome = ServerMsg::Welcome {
                    group: group.clone(),
                    from: from_device,
                    name,
                    message,
                };
                // The whole group (including the new member) gets the updated
                // membership so the count reflects the add immediately.
                let mut out = self.members_broadcast(&group);
                match self.device_conn.get(&to) {
                    Some(&conn) => out.push(Outgoing {
                        to: conn,
                        msg: welcome,
                    }),
                    // Target offline: queue the Welcome for their next login, so a
                    // member added while away still joins the group.
                    None => out.extend(self.queue_for_offline(from, &to.0, welcome)),
                }
                out
            }

            ClientMsg::Mls { group, message } => {
                let from_device = self.device_for(from);
                self.fanout(from, &group, |g| ServerMsg::Mls {
                    group: g,
                    from: from_device.clone(),
                    message: message.clone(),
                })
            }

            ClientMsg::Text { group, message } => {
                let from_device = self.device_for(from);
                self.fanout(from, &group, |g| ServerMsg::Text {
                    group: g,
                    from: from_device.clone(),
                    message: message.clone(),
                })
            }

            // Register a buffered/routed poll. The sender becomes its owner; only a
            // group member may open a poll for the group.
            ClientMsg::BallotOpen {
                poll,
                group,
                mode,
                release_at,
                anonymous,
            } => {
                let Some(owner) = self.conn_device.get(&from).cloned() else {
                    return vec![];
                };
                if !self.is_member(&group, &owner) {
                    return vec![];
                }
                // Deny-by-default on a re-used poll id (ASVS V4, object level):
                // re-opening an id would otherwise let ANY member reset another
                // member's poll and discard the ballots already cast in it.
                if self.ballots.contains_key(&poll) {
                    return poll_refused(from, "that poll is already open");
                }
                if self.ballots.len() >= MAX_OPEN_POLLS_TOTAL {
                    return poll_refused(
                        from,
                        "the server has too many open polls right now; try again later",
                    );
                }
                // Counted from the one authoritative map rather than a side
                // counter that could drift out of step with releases, expiries
                // and reclaims. Bounded by MAX_OPEN_POLLS_TOTAL and only run
                // when a poll is opened, which is rare.
                let mine = self.ballots.values().filter(|bp| bp.owner == owner).count();
                if mine >= MAX_OPEN_POLLS_PER_DEVICE {
                    return poll_refused(
                        from,
                        "you already have too many open polls; close one before starting another",
                    );
                }
                self.ballots.insert(
                    poll,
                    BufferedPoll {
                        owner,
                        group,
                        mode,
                        release_at: release_at.map(|ms| UNIX_EPOCH + Duration::from_millis(ms)),
                        anonymous,
                        opened_at: (self.now)(),
                        ballots: HashMap::new(),
                    },
                );
                vec![]
            }

            // A sealed ballot. Buffer it (deduped by submitter), or in owner-live
            // mode forward it straight to the owner. Only group members may submit.
            ClientMsg::BallotSubmit { poll, ballot } => {
                let Some(dev) = self.conn_device.get(&from).cloned() else {
                    return vec![];
                };
                let Some((group, owner, mode)) = self
                    .ballots
                    .get(&poll)
                    .map(|bp| (bp.group.clone(), bp.owner.clone(), bp.mode))
                else {
                    return vec![]; // unknown or already-closed poll
                };
                if !self.is_member(&group, &dev) {
                    return vec![];
                }
                // A real ballot is tiny and fixed-width; anything far larger is
                // an attempt to park memory on the relay, not a vote.
                if ballot.0.len() > MAX_BALLOT_BYTES {
                    return poll_refused(from, "that ballot is too large to accept");
                }
                if mode == 1 {
                    let msg = ServerMsg::Ballots {
                        group,
                        poll,
                        ballots: vec![(dev, ballot)],
                    };
                    return match self.device_conn.get(&owner).copied() {
                        Some(conn) => vec![Outgoing { to: conn, msg }],
                        None => {
                            self.queue.enqueue(&owner.0, msg);
                            vec![]
                        }
                    };
                }
                if let Some(bp) = self.ballots.get_mut(&poll) {
                    bp.ballots.insert(dev, ballot);
                }
                vec![]
            }

            // The owner ends a buffered poll now: release its ballots per mode.
            ClientMsg::BallotClose { poll } => {
                let Some(dev) = self.conn_device.get(&from).cloned() else {
                    return vec![];
                };
                match self.ballots.get(&poll) {
                    Some(bp) if bp.owner == dev => {}
                    _ => return vec![],
                }
                self.release_ballots(&poll)
            }

            ClientMsg::Media(frame) => {
                let group = frame.group.clone();
                self.fanout(from, &group, |_| ServerMsg::Media(frame.clone()))
            }

            ClientMsg::Presence { status } => match self.conn_user.get(&from).cloned() {
                Some(user) => self.set_presence(&user, status),
                None => vec![],
            },

            ClientMsg::WatchPresence { users } => {
                let mut out = Vec::new();
                for user in users {
                    self.presence_watchers
                        .entry(user.clone())
                        .or_default()
                        .insert(from);
                    // Send the current status right away, if known.
                    if let Some(&status) = self.presence.get(&user) {
                        out.push(Outgoing {
                            to: from,
                            msg: ServerMsg::Presence { user, status },
                        });
                    }
                }
                out
            }

            ClientMsg::FriendRequest { to } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                if !self.accounts.contains(&to) {
                    return vec![Outgoing {
                        to: from,
                        msg: ServerMsg::Error {
                            detail: "no such handle".into(),
                        },
                    }];
                }
                match self.friends.request(&me, &to, self.now_secs()) {
                    RequestOutcome::Sent => {
                        let mut out = vec![Outgoing {
                            to: from,
                            msg: self.friends_snapshot(&me),
                        }];
                        // Notify the target if they are online.
                        if let Some(&to_conn) = self.device_conn.get(&DeviceId(to.clone())) {
                            out.push(Outgoing {
                                to: to_conn,
                                msg: ServerMsg::FriendRequestReceived { from: me.clone() },
                            });
                            out.push(Outgoing {
                                to: to_conn,
                                msg: self.friends_snapshot(&to),
                            });
                        }
                        out
                    }
                    RequestOutcome::NowFriends => self.on_new_friendship(from, &me, &to),
                    _ => vec![Outgoing {
                        to: from,
                        msg: self.friends_snapshot(&me),
                    }],
                }
            }

            ClientMsg::FriendAccept { from: requester } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                if self.friends.accept(&me, &requester, self.now_secs()) {
                    self.on_new_friendship(from, &me, &requester)
                } else {
                    vec![Outgoing {
                        to: from,
                        msg: self.friends_snapshot(&me),
                    }]
                }
            }

            ClientMsg::FriendDecline { who } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                self.friends.decline(&me, &who);
                let mut out = vec![Outgoing {
                    to: from,
                    msg: self.friends_snapshot(&me),
                }];
                if let Some(&other_conn) = self.device_conn.get(&DeviceId(who.clone())) {
                    out.push(Outgoing {
                        to: other_conn,
                        msg: self.friends_snapshot(&who),
                    });
                }
                out
            }

            ClientMsg::FriendRemove { handle } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                self.friends.remove(&me, &handle);
                // Stop watching each other's presence.
                if let Some(w) = self.presence_watchers.get_mut(&UserId(handle.clone())) {
                    w.remove(&from);
                }
                let mut out = vec![Outgoing {
                    to: from,
                    msg: self.friends_snapshot(&me),
                }];
                if let Some(&other_conn) = self.device_conn.get(&DeviceId(handle.clone())) {
                    if let Some(w) = self.presence_watchers.get_mut(&UserId(me.clone())) {
                        w.remove(&other_conn);
                    }
                    out.push(Outgoing {
                        to: other_conn,
                        msg: ServerMsg::FriendRemoved { handle: me.clone() },
                    });
                    out.push(Outgoing {
                        to: other_conn,
                        msg: self.friends_snapshot(&handle),
                    });
                }
                out
            }

            ClientMsg::ListFriends => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                let mut out = vec![Outgoing {
                    to: from,
                    msg: self.friends_snapshot(&me),
                }];
                out.extend(self.wire_friend_presence(from, &me));
                out
            }

            // ---- Workspaces ----
            ClientMsg::WorkspaceSubmitOp { workspace, op } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                // A submitter may only append ops they signed themselves; the
                // store then verifies chain, signature, and authorization.
                if op.author != me {
                    return workspace_error(from, "you can only submit your own ops");
                }
                match self.workspaces.submit(workspace, op.clone()) {
                    Ok(members) => {
                        let msg = ServerMsg::WorkspaceOps {
                            workspace,
                            ops: vec![op],
                        };
                        // Broadcast to every online member (the sender included --
                        // clients apply ops idempotently by seq). Offline members
                        // catch up via WorkspaceFetch on reconnect, so nothing is
                        // queued here.
                        self.deliver_to_members(&members, msg)
                    }
                    Err(e) => workspace_error(from, e.reason()),
                }
            }

            ClientMsg::WorkspaceFetch { workspace } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                // Deny-by-default: only a current member may read the log.
                if !self.workspaces.is_member(&workspace, &me) {
                    return vec![];
                }
                let ops = self.workspaces.log(&workspace).to_vec();
                vec![Outgoing {
                    to: from,
                    msg: ServerMsg::WorkspaceOps { workspace, ops },
                }]
            }

            ClientMsg::WorkspaceListMine => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                vec![Outgoing {
                    to: from,
                    msg: ServerMsg::Workspaces {
                        workspaces: self.workspaces.workspaces_of(&me),
                    },
                }]
            }

            ClientMsg::WorkspaceWelcome {
                workspace,
                channel,
                to,
                welcome,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                // Sender must be in the relevant set; recipient must be too (their
                // Add op is submitted first). For a private channel that is the
                // channel's member set; for the WG, the whole workspace.
                let ok = match channel {
                    Some(ch) => {
                        self.workspaces.is_channel_member(&workspace, &ch, &me)
                            && self.workspaces.is_channel_member(&workspace, &ch, &to)
                    }
                    None => {
                        self.workspaces.is_member(&workspace, &me)
                            && self.workspaces.is_member(&workspace, &to)
                    }
                };
                if !ok {
                    return vec![];
                }
                let msg = ServerMsg::WorkspaceWelcome {
                    workspace,
                    channel,
                    from: me,
                    welcome,
                };
                match self.device_conn.get(&DeviceId(to)) {
                    Some(&conn) => vec![Outgoing { to: conn, msg }],
                    None => vec![], // offline: resync on next login
                }
            }

            ClientMsg::WorkspaceCommit {
                workspace,
                channel,
                commit,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                if !self.workspaces.is_member(&workspace, &me) {
                    return vec![];
                }
                // Deliver to the relevant group's members (channel subset or WG).
                let members = match channel {
                    Some(ch) => self.workspaces.channel_members(&workspace, &ch),
                    None => self.workspaces.members(&workspace),
                };
                self.deliver_to_members_except(
                    &members,
                    &me,
                    ServerMsg::WorkspaceCommit {
                        workspace,
                        channel,
                        from: me.clone(),
                        commit,
                    },
                )
            }

            ClientMsg::ChannelPost {
                workspace,
                channel,
                epoch,
                message,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                if !self.workspaces.is_member(&workspace, &me) {
                    return vec![];
                }
                // Only a member of THIS channel may post (private channels have a
                // subset). Store for scrollback, then fan out to the channel's
                // members (the whole workspace for a public channel).
                if !self.workspaces.is_channel_member(&workspace, &channel, &me) {
                    return vec![];
                }
                self.workspaces
                    .store_message(workspace, channel, epoch, message.clone());
                let members = self.workspaces.channel_members(&workspace, &channel);
                self.deliver_to_members_except(
                    &members,
                    &me,
                    ServerMsg::ChannelPost {
                        workspace,
                        channel,
                        epoch,
                        from: me.clone(),
                        message,
                    },
                )
            }

            ClientMsg::ChannelKeyShare {
                workspace,
                group_channel,
                to,
                message,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                if !self.workspaces.is_member(&workspace, &me) {
                    return vec![];
                }
                let out = ServerMsg::ChannelKeyShare {
                    workspace,
                    group_channel,
                    from: me.clone(),
                    message,
                };
                match to {
                    // A directed bundle to one (member) recipient.
                    Some(handle) if self.workspaces.is_member(&workspace, &handle) => {
                        match self.device_conn.get(&DeviceId(handle)) {
                            Some(&conn) => vec![Outgoing { to: conn, msg: out }],
                            None => vec![],
                        }
                    }
                    Some(_) => vec![], // not a member
                    // A broadcast (new channel key) to all members but the sender.
                    None => {
                        let members = self.workspaces.members(&workspace);
                        self.deliver_to_members_except(&members, &me, out)
                    }
                }
            }

            ClientMsg::ChannelHistoryFetch {
                workspace,
                channel,
                before,
                limit,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                // Only a channel member may fetch its history (private subset).
                if !self.workspaces.is_channel_member(&workspace, &channel, &me) {
                    return vec![];
                }
                let (messages, has_more) =
                    self.workspaces
                        .channel_history_page(&workspace, &channel, before, limit);
                vec![Outgoing {
                    to: from,
                    msg: ServerMsg::ChannelHistory {
                        workspace,
                        channel,
                        messages,
                        has_more,
                    },
                }]
            }

            ClientMsg::GroupHistoryConfig { group, to, message } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                let Some(members) = self.groups.members(&group) else {
                    return vec![];
                };
                if !members.contains(&DeviceId(me.clone())) {
                    return vec![];
                }
                let out = ServerMsg::GroupHistoryConfig {
                    group: group.clone(),
                    from: me.clone(),
                    message,
                };
                match to {
                    // Hand the current key to one member (a new joiner).
                    Some(handle) if members.contains(&DeviceId(handle.clone())) => {
                        match self.device_conn.get(&DeviceId(handle)) {
                            Some(&conn) => vec![Outgoing { to: conn, msg: out }],
                            None => vec![],
                        }
                    }
                    Some(_) => vec![],
                    // Broadcast the setting to every other member.
                    None => {
                        let me_dev = DeviceId(me);
                        members
                            .iter()
                            .filter(|d| **d != me_dev)
                            .filter_map(|d| self.device_conn.get(d).copied())
                            .map(|conn| Outgoing {
                                to: conn,
                                msg: out.clone(),
                            })
                            .collect()
                    }
                }
            }

            ClientMsg::GroupHistoryPost {
                group,
                epoch,
                message,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                let is_member = self
                    .groups
                    .members(&group)
                    .is_some_and(|m| m.contains(&DeviceId(me)));
                if !is_member {
                    return vec![];
                }
                self.workspaces
                    .store_message(group_store_id(&group), [0u8; 16], epoch, message);
                vec![]
            }

            ClientMsg::GroupHistoryFetch {
                group,
                before,
                limit,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                let is_member = self
                    .groups
                    .members(&group)
                    .is_some_and(|m| m.contains(&DeviceId(me)));
                if !is_member {
                    return vec![];
                }
                let (messages, has_more) = self.workspaces.channel_history_page(
                    &group_store_id(&group),
                    &[0u8; 16],
                    before,
                    limit,
                );
                vec![Outgoing {
                    to: from,
                    msg: ServerMsg::GroupHistory {
                        group,
                        messages,
                        has_more,
                    },
                }]
            }

            ClientMsg::VoiceJoin { workspace, channel } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                if !self.workspaces.is_channel_member(&workspace, &channel, &me) {
                    return vec![];
                }
                self.voice_presence
                    .entry((workspace, channel))
                    .or_default()
                    .insert(me);
                self.voice_broadcast(workspace, channel)
            }

            ClientMsg::VoiceLeave { workspace, channel } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                if let Some(set) = self.voice_presence.get_mut(&(workspace, channel)) {
                    set.remove(&me);
                    if set.is_empty() {
                        self.voice_presence.remove(&(workspace, channel));
                    }
                }
                self.voice_broadcast(workspace, channel)
            }

            ClientMsg::CreateInvite {
                workspace,
                ttl_secs,
                max_uses,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                // Only someone who can manage members may mint an invite (the
                // redeemer is admitted by such a member's signed op, but minting is
                // gated too so a plain member cannot hand out join links).
                if !self
                    .workspaces
                    .has_permission(&workspace, &me, Permission::ManageMembers)
                {
                    return workspace_error(from, "you do not have permission to create an invite");
                }
                let code = {
                    use rand::RngCore as _;
                    let mut bytes = [0u8; 12];
                    rand::rngs::OsRng.fill_bytes(&mut bytes);
                    hex::encode(bytes)
                };
                let expires_at = if ttl_secs == 0 {
                    0
                } else {
                    self.now_secs() + ttl_secs
                };
                self.workspaces
                    .create_invite(workspace, code.clone(), expires_at, max_uses);
                vec![Outgoing {
                    to: from,
                    msg: ServerMsg::InviteCreated { workspace, code },
                }]
            }

            ClientMsg::RedeemInvite { code } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                let now = self.now_secs();
                let ws = match self.workspaces.peek_invite(&code, now) {
                    Ok(ws) => ws,
                    Err(e) => return workspace_error(from, e.reason()),
                };
                if self.workspaces.is_member(&ws, &me) {
                    return workspace_error(from, "you are already in that workspace");
                }
                // Route to one online member who can admit (holds ManageMembers),
                // whose client performs the signed add. Spend a use only once we
                // know a request will actually be routed.
                let admin_conn = self
                    .workspaces
                    .members_with(&ws, Permission::ManageMembers)
                    .into_iter()
                    .find_map(|h| self.device_conn.get(&DeviceId(h)).copied());
                let Some(admin_conn) = admin_conn else {
                    return workspace_error(
                        from,
                        "no one who can admit you is online; try again later",
                    );
                };
                self.workspaces.consume_invite(&code, now);
                vec![Outgoing {
                    to: admin_conn,
                    msg: ServerMsg::JoinRequest {
                        workspace: ws,
                        requester: me,
                    },
                }]
            }

            ClientMsg::VoiceMoveMember {
                workspace,
                channel,
                member,
            } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                // Only someone with the move-voice permission may move others.
                if !self
                    .workspaces
                    .has_permission(&workspace, &me, Permission::MoveVoiceMembers)
                {
                    return workspace_error(
                        from,
                        "you do not have permission to move members between voice channels",
                    );
                }
                // The target must be a voice channel the member is allowed into.
                if !self.workspaces.is_voice_channel(&workspace, &channel)
                    || !self.workspaces.is_channel_member(&workspace, &channel, &member)
                {
                    return vec![];
                }
                // The member must currently be in some OTHER voice channel here.
                let in_other_voice = self.voice_presence.iter().any(|((ws, ch), set)| {
                    *ws == workspace && *ch != channel && set.contains(&member)
                });
                if !in_other_voice {
                    return workspace_error(from, "that member is not in another voice channel here");
                }
                // Direct the member's client to switch; its VoiceJoin/Leave carry
                // the presence change, so nothing is double counted here.
                match self.device_conn.get(&DeviceId(member)) {
                    Some(&conn) => vec![Outgoing {
                        to: conn,
                        msg: ServerMsg::VoiceMoved { workspace, channel },
                    }],
                    None => vec![],
                }
            }

            ClientMsg::RequestDm { to } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                match self.device_conn.get(&DeviceId(to)) {
                    Some(&to_conn) => vec![Outgoing {
                        to: to_conn,
                        msg: ServerMsg::DmRequested { from: me },
                    }],
                    None => vec![],
                }
            }

            ClientMsg::SetDisplayName { display } => {
                let Some(me) = self.conn_user.get(&from).map(|u| u.0.clone()) else {
                    return vec![];
                };
                self.accounts.set_display(&me, &display);
                // Push each online friend a refreshed snapshot so they see the
                // new display name for us.
                self.friends
                    .friends_of(&me)
                    .into_iter()
                    .filter_map(|f| self.device_conn.get(&DeviceId(f.clone())).map(|&c| (c, f)))
                    .map(|(conn, f)| Outgoing {
                        to: conn,
                        msg: self.friends_snapshot(&f),
                    })
                    .collect()
            }

            ClientMsg::JoinCall { group } => {
                let device = self.device_for(from);
                // Only a routing member of the group may join its call.
                if !self.is_member(&group, &device) {
                    return vec![];
                }
                let call = self.active_calls.entry(group.clone()).or_default();
                let first = call.is_empty();
                call.insert(device.clone());
                let mut out = Vec::new();
                // The first participant starts the call: ring the other members.
                if first {
                    let caller = device.0.clone();
                    out.extend(self.ring_other_members(&group, &device, &caller));
                }
                out.extend(self.call_participants_broadcast(&group));
                out
            }

            ClientMsg::LeaveCall { group } => {
                let device = self.device_for(from);
                if let Some(call) = self.active_calls.get_mut(&group) {
                    call.remove(&device);
                    if call.is_empty() {
                        self.active_calls.remove(&group);
                    }
                }
                self.call_participants_broadcast(&group)
            }

            ClientMsg::DeclineCall { group } => {
                let device = self.device_for(from);
                if !self.is_member(&group, &device) {
                    return vec![];
                }
                self.call_participants(&group)
                    .into_iter()
                    .filter(|p| p != &device)
                    .filter_map(|p| self.device_conn.get(&p).copied())
                    .map(|conn| Outgoing {
                        to: conn,
                        msg: ServerMsg::CallDeclined {
                            group: group.clone(),
                            from: device.0.clone(),
                        },
                    })
                    .collect()
            }

            ClientMsg::FileOffer {
                offer_id,
                group,
                size,
                manifest,
                live,
            } => self.handle_file_offer(from, offer_id, group, size, manifest, live),

            ClientMsg::FileChunk {
                offer_id,
                index,
                data,
            } => self.handle_file_chunk(from, offer_id, index, data),

            ClientMsg::FileAbort { offer_id } => self.handle_file_abort(from, offer_id),

            ClientMsg::FileComplete { offer_id } => self.handle_file_complete(from, offer_id),

            ClientMsg::FileAccept { offer_id } => self.handle_file_accept(from, offer_id),

            ClientMsg::FileDecline { offer_id } => self.handle_file_decline(from, offer_id),

            ClientMsg::FileCancel { offer_id } => self.handle_file_cancel(from, offer_id),

            // Store an encrypted avatar blob for the uploader. Auth-gated above;
            // the store verifies `addr == SHA-256(data)` so a client can only
            // write its own content-addressed bytes (no overwriting another
            // user's blob), caps the size, and rings the per-user history. The
            // bytes are opaque ciphertext -- the key lives only in the sealed
            // profile, so the server cannot read the image.
            ClientMsg::PutAvatar { addr, data } => {
                if let Some(owner) = self.conn_user.get(&from).map(|u| u.0.clone()) {
                    self.avatars.put(&addr, &data, &owner);
                }
                vec![]
            }

            // Serve an avatar blob by its content address. The 256-bit address is
            // a bearer capability learned only from a sealed profile, so any
            // authenticated requester that presents it is authorized; the reply
            // carries opaque ciphertext, useless without the key.
            ClientMsg::FetchAvatar { addr } => {
                let data = self.avatars.get(&addr);
                vec![Outgoing {
                    to: from,
                    msg: ServerMsg::Avatar { addr, data },
                }]
            }
        }
    }

    /// A member offers a file to a group. A stored (`!live`) offer is admitted to
    /// the on-disk store (subject to the size/disk quota) for offline delivery;
    /// a `live` offer is relayed to online recipients to stream in real time.
    /// Deny-by-default: only a routing member of the group may offer (ASVS V4).
    fn handle_file_offer(
        &mut self,
        from: ConnId,
        offer_id: [u8; 16],
        group: GroupId,
        size: u64,
        manifest: Sealed,
        live: bool,
    ) -> Vec<Outgoing> {
        let sender = self.device_for(from);
        if !self.is_member(&group, &sender) {
            return vec![];
        }
        // A fresh offer id only; never reuse one already in flight.
        if self.files.sender_of(&offer_id).is_some() || self.live_offers.contains_key(&offer_id) {
            return vec![];
        }
        // Cap concurrent offers per sender (anti-spam, ASVS V11).
        let open = self.files.offer_count_for(&sender.0)
            + self
                .live_offers
                .values()
                .filter(|o| o.sender == sender)
                .count();
        if open >= MAX_OFFERS_PER_SENDER {
            return vec![reject(from, offer_id, "you have too many file offers open")];
        }
        // Recipients are the group's routing members except the sender.
        let recipients: Vec<DeviceId> = match self.groups.members(&group) {
            Some(m) => m.iter().filter(|d| **d != sender).cloned().collect(),
            None => return vec![],
        };
        if recipients.is_empty() {
            return vec![reject(
                from,
                offer_id,
                "no one is in this conversation to receive it",
            )];
        }

        if live {
            // Live needs the recipient online now; offline recipients are skipped.
            let online: HashSet<DeviceId> = recipients
                .iter()
                .filter(|d| self.device_conn.contains_key(*d))
                .cloned()
                .collect();
            if online.is_empty() {
                return vec![reject(
                    from,
                    offer_id,
                    "the recipient is offline; a file this large needs them online",
                )];
            }
            let expires_at = (self.now)() + LIVE_OFFER_TTL;
            let mut out = Vec::new();
            for dev in &online {
                if let Some(&conn) = self.device_conn.get(dev) {
                    out.push(Outgoing {
                        to: conn,
                        msg: ServerMsg::FileOffered {
                            offer_id,
                            group: group.clone(),
                            from: sender.clone(),
                            size,
                            manifest: manifest.clone(),
                            live: true,
                        },
                    });
                }
            }
            self.live_offers.insert(
                offer_id,
                LiveOffer {
                    sender,
                    recipients: online.clone(),
                    accepted: HashSet::new(),
                    expires_at,
                },
            );
            out
        } else {
            // Stored: admit to the on-disk store, then let the sender upload.
            let recip_names: Vec<String> = recipients.iter().map(|d| d.0.clone()).collect();
            let now = (self.now)();
            match self.files.begin(
                offer_id,
                group,
                sender.0.clone(),
                recip_names,
                size,
                manifest,
                now,
            ) {
                Ok(()) => vec![Outgoing {
                    to: from,
                    msg: ServerMsg::FileUploadReady { offer_id },
                }],
                Err(reason) => vec![reject(from, offer_id, reason.as_str())],
            }
        }
    }

    /// One sealed chunk from the sender: appended to a stored upload, or relayed
    /// to the accepting recipients of a live offer. Only the offer's own sender
    /// may push chunks (ASVS V4).
    fn handle_file_chunk(
        &mut self,
        from: ConnId,
        offer_id: [u8; 16],
        index: u32,
        data: Sealed,
    ) -> Vec<Outgoing> {
        let sender = self.device_for(from);
        if self.files.sender_of(&offer_id) == Some(sender.0.as_str()) {
            // Stored upload: reserve the bytes under the lock (cap + accounting),
            // then defer the DISK WRITE to the async shell off the lock, so a slow
            // disk never stalls every other client.
            match self.files.reserve_append(&offer_id, data.0.len()) {
                Ok(blob) => {
                    self.file_appends.push(FileAppend {
                        offer_id,
                        blob,
                        data: data.0,
                    });
                    vec![]
                }
                // Overrun (declared less than uploaded): the offer was dropped.
                Err(_) => vec![reject(
                    from,
                    offer_id,
                    "the upload exceeded the size you declared",
                )],
            }
        } else if self
            .live_offers
            .get(&offer_id)
            .is_some_and(|o| o.sender == sender)
        {
            // Live stream: relay to everyone who accepted (and is still online).
            let targets: Vec<DeviceId> = self.live_offers[&offer_id]
                .accepted
                .iter()
                .cloned()
                .collect();
            targets
                .into_iter()
                .filter_map(|dev| self.device_conn.get(&dev).copied())
                .map(|conn| Outgoing {
                    to: conn,
                    msg: ServerMsg::FileChunk {
                        offer_id,
                        from: sender.clone(),
                        index,
                        data: data.clone(),
                    },
                })
                .collect()
        } else {
            vec![]
        }
    }

    /// The sender finished uploading/streaming. For a stored offer this makes it
    /// deliverable and offers it to the recipients (queuing for those offline);
    /// for a live offer it tells the accepting recipients the stream is done.
    fn handle_file_complete(&mut self, from: ConnId, offer_id: [u8; 16]) -> Vec<Outgoing> {
        let sender = self.device_for(from);
        if self.files.sender_of(&offer_id) == Some(sender.0.as_str()) {
            if self.files.finish(&offer_id).is_err() {
                return vec![];
            }
            let Some((group, _sender, size, manifest, recipients)) =
                self.files.offer_meta(&offer_id)
            else {
                return vec![];
            };
            let mut out = Vec::new();
            for name in recipients {
                let dev = DeviceId(name);
                let msg = ServerMsg::FileOffered {
                    offer_id,
                    group: group.clone(),
                    from: sender.clone(),
                    size,
                    manifest: manifest.clone(),
                    live: false,
                };
                match self.device_conn.get(&dev) {
                    Some(&conn) => out.push(Outgoing { to: conn, msg }),
                    // Offline: park the offer for their next login (notify the
                    // sender if the queue is at its global cap).
                    None => out.extend(self.queue_for_offline(from, &dev.0, msg)),
                }
            }
            out
        } else if self
            .live_offers
            .get(&offer_id)
            .is_some_and(|o| o.sender == sender)
        {
            let offer = self.live_offers.remove(&offer_id).expect("just checked");
            offer
                .accepted
                .into_iter()
                .filter_map(|dev| self.device_conn.get(&dev).copied())
                .map(|conn| Outgoing {
                    to: conn,
                    msg: ServerMsg::FileComplete {
                        offer_id,
                        from: sender.clone(),
                    },
                })
                .collect()
        } else {
            vec![]
        }
    }

    /// A recipient consents. For a stored offer this queues an off-lock blob
    /// delivery and tells the sender; for a live offer it enrolls the recipient
    /// in the stream and cues the sender to start.
    fn handle_file_accept(&mut self, from: ConnId, offer_id: [u8; 16]) -> Vec<Outgoing> {
        let recipient = self.device_for(from);
        // Stored: schedule the off-lock delivery if this recipient may have it.
        if let Some((blob, sender_name)) = self.files.begin_delivery(&offer_id, &recipient.0) {
            // A fresh cancel flag for this delivery attempt; a later `FileAbort`
            // from this recipient sets it to stop the stream early.
            let cancel = Arc::new(AtomicBool::new(false));
            self.delivery_tokens
                .insert((offer_id, recipient.clone()), cancel.clone());
            self.blob_deliveries.push(BlobDelivery {
                to: from,
                recipient: recipient.clone(),
                offer_id,
                from: DeviceId(sender_name.clone()),
                blob,
                cancel,
            });
            // Tell the sender it was accepted (if online).
            return self.notify_sender(
                &DeviceId(sender_name),
                ServerMsg::FileAccepted {
                    offer_id,
                    by: recipient,
                },
            );
        }
        // Live: enroll in the stream and cue the sender.
        if let Some(offer) = self.live_offers.get_mut(&offer_id) {
            if !offer.recipients.contains(&recipient) {
                return vec![];
            }
            offer.accepted.insert(recipient.clone());
            let sender = offer.sender.clone();
            return self.notify_sender(
                &sender,
                ServerMsg::FileAccepted {
                    offer_id,
                    by: recipient,
                },
            );
        }
        vec![]
    }

    /// A recipient refuses. The offer is resolved for them (and deleted once
    /// every recipient has resolved); the sender is told.
    fn handle_file_decline(&mut self, from: ConnId, offer_id: [u8; 16]) -> Vec<Outgoing> {
        let recipient = self.device_for(from);
        if let Some((_group, sender)) = self.files.offer_group(&offer_id) {
            self.files.resolve(&offer_id, &recipient.0);
            return self.notify_sender(
                &DeviceId(sender),
                ServerMsg::FileDeclined {
                    offer_id,
                    by: recipient,
                },
            );
        }
        if let Some(offer) = self.live_offers.get_mut(&offer_id) {
            offer.recipients.remove(&recipient);
            offer.accepted.remove(&recipient);
            let sender = offer.sender.clone();
            let empty = offer.recipients.is_empty();
            if empty {
                self.live_offers.remove(&offer_id);
            }
            return self.notify_sender(
                &sender,
                ServerMsg::FileDeclined {
                    offer_id,
                    by: recipient,
                },
            );
        }
        vec![]
    }

    /// A recipient aborts their in-progress download WITHOUT declining it. The
    /// offer stays available (stored: the recipient remains pending; live: still
    /// a candidate), so they can download it again while the sender keeps sharing.
    /// Nothing is announced to the sender -- an abort is the recipient's private
    /// pause, not a decline.
    fn handle_file_abort(&mut self, from: ConnId, offer_id: [u8; 16]) -> Vec<Outgoing> {
        let recipient = self.device_for(from);
        // Stored: signal the in-flight streamer to stop early. It then calls
        // `abort_stored_delivery`, which leaves the recipient pending (so a later
        // `FileAccept` re-delivers). If no delivery is in flight, this is a no-op.
        if let Some(token) = self.delivery_tokens.get(&(offer_id, recipient.clone())) {
            token.store(true, Ordering::Relaxed);
        }
        // Live: stop relaying chunks to this recipient but keep them a candidate,
        // so they can re-accept and rejoin the stream while it lasts.
        if let Some(offer) = self.live_offers.get_mut(&offer_id) {
            offer.accepted.remove(&recipient);
        }
        vec![]
    }

    /// The sender withdraws an offer: delete it and tell any pending recipients
    /// it is gone (so their consent prompt disappears).
    fn handle_file_cancel(&mut self, from: ConnId, offer_id: [u8; 16]) -> Vec<Outgoing> {
        let sender = self.device_for(from);
        if self.files.sender_of(&offer_id) == Some(sender.0.as_str()) {
            let pending = self
                .files
                .pending_recipients(&offer_id)
                .map(|(_, r)| r)
                .unwrap_or_default();
            self.files.remove(&offer_id);
            return pending
                .into_iter()
                .filter_map(|name| self.device_conn.get(&DeviceId(name)).copied())
                .map(|conn| Outgoing {
                    to: conn,
                    msg: ServerMsg::FileDeclined {
                        offer_id,
                        by: DeviceId(NO_DEVICE.into()),
                    },
                })
                .collect();
        }
        if let Some(offer) = self.live_offers.remove(&offer_id) {
            if offer.sender != sender {
                // Not the owner: put it back untouched.
                self.live_offers.insert(offer_id, offer);
                return vec![];
            }
            return offer
                .recipients
                .into_iter()
                .filter_map(|dev| self.device_conn.get(&dev).copied())
                .map(|conn| Outgoing {
                    to: conn,
                    msg: ServerMsg::FileDeclined {
                        offer_id,
                        by: DeviceId(NO_DEVICE.into()),
                    },
                })
                .collect();
        }
        vec![]
    }

    /// Handle a device going offline for live file offers: cancel the ones it
    /// was sending (tell the recipients the stream is gone) and drop it from the
    /// ones it was receiving (tell those senders it declined-by-departure).
    fn drop_from_live_offers(&mut self, device: &DeviceId) -> Vec<Outgoing> {
        let mut out = Vec::new();
        // Offers this device was sending: remove and notify their recipients.
        let sent: Vec<[u8; 16]> = self
            .live_offers
            .iter()
            .filter(|(_, o)| &o.sender == device)
            .map(|(id, _)| *id)
            .collect();
        for offer_id in sent {
            if let Some(offer) = self.live_offers.remove(&offer_id) {
                for dev in offer.recipients {
                    out.extend(self.notify_sender(
                        &dev,
                        ServerMsg::FileDeclined {
                            offer_id,
                            by: DeviceId(NO_DEVICE.into()),
                        },
                    ));
                }
            }
        }
        // Offers this device was receiving: drop it and tell those senders.
        let receiving: Vec<([u8; 16], DeviceId)> = self
            .live_offers
            .iter()
            .filter(|(_, o)| o.recipients.contains(device))
            .map(|(id, o)| (*id, o.sender.clone()))
            .collect();
        for (offer_id, sender) in receiving {
            let empty = if let Some(offer) = self.live_offers.get_mut(&offer_id) {
                offer.recipients.remove(device);
                offer.accepted.remove(device);
                offer.recipients.is_empty()
            } else {
                false
            };
            if empty {
                self.live_offers.remove(&offer_id);
            }
            out.extend(self.notify_sender(
                &sender,
                ServerMsg::FileDeclined {
                    offer_id,
                    by: device.clone(),
                },
            ));
        }
        out
    }

    /// Deliver `msg` to a device if it is online, else nothing (used to notify a
    /// sender of an accept/decline; senders can be offline for stored offers).
    fn notify_sender(&self, device: &DeviceId, msg: ServerMsg) -> Vec<Outgoing> {
        match self.device_conn.get(device) {
            Some(&conn) => vec![Outgoing { to: conn, msg }],
            None => vec![],
        }
    }

    /// Drain the stored-blob deliveries queued by the most recent `handle`, for
    /// the async shell to stream off-lock.
    pub fn take_blob_deliveries(&mut self) -> Vec<BlobDelivery> {
        std::mem::take(&mut self.blob_deliveries)
    }

    /// Drain the stored-upload chunk writes queued by the most recent `handle`,
    /// for the async shell to flush to disk off the global lock.
    pub fn take_file_appends(&mut self) -> Vec<FileAppend> {
        std::mem::take(&mut self.file_appends)
    }

    /// Drop an offer whose off-lock disk write failed (I/O error), notifying the
    /// uploading sender so its upload does not stall silently.
    pub fn fail_file_append(&mut self, offer_id: [u8; 16]) -> Vec<Outgoing> {
        let sender = self.files.sender_of(&offer_id).map(str::to_string);
        let conn = sender.and_then(|s| self.device_conn.get(&DeviceId(s)).copied());
        self.files.remove(&offer_id);
        match conn {
            Some(to) => vec![Outgoing {
                to,
                msg: ServerMsg::FileOfferRejected {
                    offer_id,
                    reason: "the server could not store the file".into(),
                },
            }],
            None => vec![],
        }
    }

    /// A stored delivery streamed successfully: resolve the recipient (deleting
    /// the blob once every recipient has resolved).
    pub fn finish_stored_delivery(&mut self, offer_id: &[u8; 16], recipient: &DeviceId) {
        self.delivery_tokens.remove(&(*offer_id, recipient.clone()));
        self.files.finish_delivery(offer_id, &recipient.0);
    }

    /// A stored delivery failed midway (recipient dropped) or was aborted by the
    /// recipient: free the in-flight slot but leave the offer pending so it can be
    /// retried.
    pub fn abort_stored_delivery(&mut self, offer_id: &[u8; 16], recipient: &DeviceId) {
        self.delivery_tokens.remove(&(*offer_id, recipient.clone()));
        self.files.abort_delivery(offer_id, &recipient.0);
    }

    /// Sweep expired file offers (stored TTL and live accept-window), telling
    /// each lapsed offer's sender. Called periodically by the async shell.
    pub fn sweep_files(&mut self) -> Vec<Outgoing> {
        let now = (self.now)();
        let mut out = Vec::new();
        for (offer_id, sender) in self.files.sweep(now) {
            out.extend(self.notify_sender(
                &DeviceId(sender),
                ServerMsg::FileDeclined {
                    offer_id,
                    by: DeviceId(NO_DEVICE.into()),
                },
            ));
        }
        let expired_live: Vec<[u8; 16]> = self
            .live_offers
            .iter()
            .filter(|(_, o)| o.expires_at <= now)
            .map(|(id, _)| *id)
            .collect();
        for offer_id in expired_live {
            if let Some(offer) = self.live_offers.remove(&offer_id) {
                out.extend(self.notify_sender(
                    &offer.sender,
                    ServerMsg::FileDeclined {
                        offer_id,
                        by: DeviceId(NO_DEVICE.into()),
                    },
                ));
            }
        }
        out
    }

    /// Release a buffered poll: hand its ballots to the right recipients and clear
    /// it (one-shot). For mode 0 every group member receives the whole set; for
    /// modes 1/2 only the owner does, and the other members receive an empty
    /// `Ballots` so their client learns the poll closed. Online members get it
    /// live, offline members via the persistent queue.
    fn release_ballots(&mut self, poll_id: &[u8; 16]) -> Vec<Outgoing> {
        let Some(bp) = self.ballots.remove(poll_id) else {
            return vec![];
        };
        let members: Vec<DeviceId> = self
            .groups
            .members(&bp.group)
            .map(|m| m.iter().cloned().collect())
            .unwrap_or_default();
        // An anonymous poll strips submitter attribution, so recipients get the
        // ballots with no idea who sent each (the ring signature inside each ballot
        // still proves a member cast it). This is independent of who receives
        // them, so it applies equally to a group release and an owner-only one.
        let strip = bp.anonymous;
        let all: Vec<(DeviceId, Sealed)> = bp
            .ballots
            .into_iter()
            .map(|(d, s)| (if strip { DeviceId(String::new()) } else { d }, s))
            .collect();
        let mut out = Vec::new();
        for dev in members {
            // Mode 0 releases the whole set to every member; the owner modes give
            // it only to the owner (others get an empty set = closure signal).
            let data = if bp.mode == 0 || dev == bp.owner {
                all.clone()
            } else {
                Vec::new()
            };
            let msg = ServerMsg::Ballots {
                group: bp.group.clone(),
                poll: *poll_id,
                ballots: data,
            };
            match self.device_conn.get(&dev).copied() {
                Some(conn) => out.push(Outgoing { to: conn, msg }),
                None => {
                    self.queue.enqueue(&dev.0, msg);
                }
            }
        }
        out
    }

    /// Release every buffered poll whose deadline has passed (no one need be
    /// online). Mirrors [`sweep_files`](Self::sweep_files); driven by the same tick.
    pub fn sweep_ballots(&mut self) -> Vec<Outgoing> {
        let now = (self.now)();
        let due: Vec<[u8; 16]> = self
            .ballots
            .iter()
            .filter(|(_, bp)| bp.release_at.is_some_and(|t| t <= now))
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::new();
        for id in due {
            out.extend(self.release_ballots(&id));
        }
        // Reclaim polls nobody ever closed. Dropped rather than released: the
        // owner chose "close when I say", and publishing a month-old tally they
        // never asked for would be a worse surprise than letting it lapse. The
        // poll still exists in each client's own history.
        self.ballots
            .retain(|_, bp| now.duration_since(bp.opened_at).unwrap_or_default() < POLL_TTL);
        out
    }

    /// Deliver a `CallOffer` to every online routing member of `group` except
    /// the caller, so their clients ring.
    fn ring_other_members(
        &self,
        group: &GroupId,
        caller_device: &DeviceId,
        caller: &str,
    ) -> Vec<Outgoing> {
        let Some(members) = self.groups.members(group) else {
            return vec![];
        };
        members
            .iter()
            .filter(|dev| *dev != caller_device)
            .filter_map(|dev| self.device_conn.get(dev).copied())
            .map(|conn| Outgoing {
                to: conn,
                msg: ServerMsg::CallOffer {
                    group: group.clone(),
                    from: caller.to_string(),
                },
            })
            .collect()
    }

    /// The devices currently in `group`'s call.
    fn call_participants(&self, group: &GroupId) -> Vec<DeviceId> {
        self.active_calls
            .get(group)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Push the current call participant list of `group` to every online routing
    /// member (an empty list means the call has ended).
    fn call_participants_broadcast(&self, group: &GroupId) -> Vec<Outgoing> {
        let participants: Vec<String> = self
            .call_participants(group)
            .into_iter()
            .map(|d| d.0)
            .collect();
        let Some(members) = self.groups.members(group) else {
            return vec![];
        };
        members
            .iter()
            .filter_map(|dev| self.device_conn.get(dev).copied())
            .map(|conn| Outgoing {
                to: conn,
                msg: ServerMsg::CallParticipants {
                    group: group.clone(),
                    participants: participants.clone(),
                },
            })
            .collect()
    }

    /// Remove `device` from every call it was in, returning participant-update
    /// broadcasts for the affected groups (used on disconnect).
    fn drop_from_calls(&mut self, device: &DeviceId) -> Vec<Outgoing> {
        let affected: Vec<GroupId> = self
            .active_calls
            .iter()
            .filter(|(_, members)| members.contains(device))
            .map(|(g, _)| g.clone())
            .collect();
        let mut out = Vec::new();
        for g in affected {
            if let Some(call) = self.active_calls.get_mut(&g) {
                call.remove(device);
                if call.is_empty() {
                    self.active_calls.remove(&g);
                }
            }
            out.extend(self.call_participants_broadcast(&g));
        }
        out
    }

    /// Claim `name` as a username if it is free (neither registered nor reserved
    /// by an in-flight sign-up). Usernames are globally unique -- no suffix.
    fn claim_username(&self, name: &str) -> Option<String> {
        if self.accounts.contains(name) || self.reserved.contains(name) {
            None
        } else {
            Some(name.to_string())
        }
    }

    /// The friends + pending-requests snapshot for `handle`, each entry carrying
    /// the person's current display name.
    fn friends_snapshot(&self, handle: &str) -> ServerMsg {
        let to_friends = |names: Vec<String>| -> Vec<Friend> {
            names
                .into_iter()
                .map(|u| Friend {
                    display: self.accounts.display(&u),
                    // The friend's account age, and (for accepted friends only)
                    // when this friendship formed. `since` is None for pending
                    // requests, since no friendship exists yet.
                    member_since: self.accounts.created_at(&u),
                    since: self.friends.friends_since(handle, &u),
                    username: u,
                })
                .collect()
        };
        ServerMsg::Friends {
            friends: to_friends(self.friends.friends_of(handle)),
            incoming: to_friends(self.friends.incoming(handle)),
            outgoing: to_friends(self.friends.outgoing(handle)),
        }
    }

    /// Deliver `msg` to every currently-online member handle. Offline members are
    /// skipped (they resync via `WorkspaceFetch` on reconnect), so this never
    /// grows the offline queue with workspace ops.
    fn deliver_to_members(&self, members: &[String], msg: ServerMsg) -> Vec<Outgoing> {
        self.deliver_to_members_except(members, "", msg)
    }

    /// As [`deliver_to_members`](Self::deliver_to_members), but skips `except`
    /// (the sender, who already has the content locally).
    fn deliver_to_members_except(
        &self,
        members: &[String],
        except: &str,
        msg: ServerMsg,
    ) -> Vec<Outgoing> {
        members
            .iter()
            .filter(|m| m.as_str() != except)
            .filter_map(|m| {
                self.device_conn
                    .get(&DeviceId(m.clone()))
                    .map(|&conn| Outgoing {
                        to: conn,
                        msg: msg.clone(),
                    })
            })
            .collect()
    }

    /// Broadcast a voice channel's current roster to the channel's members (so
    /// everyone sees who is in voice, joined or not).
    fn voice_broadcast(&self, ws: [u8; 16], channel: [u8; 16]) -> Vec<Outgoing> {
        let mut members: Vec<String> = self
            .voice_presence
            .get(&(ws, channel))
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        members.sort();
        let channel_members = self.workspaces.channel_members(&ws, &channel);
        self.deliver_to_members(
            &channel_members,
            ServerMsg::VoicePresence {
                workspace: ws,
                channel,
                members,
            },
        )
    }

    /// Drop a disconnected handle from every voice channel, returning the presence
    /// broadcasts for the channels they were in.
    fn clear_voice_for(&mut self, handle: &str) -> Vec<Outgoing> {
        let affected: Vec<([u8; 16], [u8; 16])> = self
            .voice_presence
            .iter()
            .filter(|(_, set)| set.contains(handle))
            .map(|(k, _)| *k)
            .collect();
        let mut out = Vec::new();
        for (ws, channel) in affected {
            if let Some(set) = self.voice_presence.get_mut(&(ws, channel)) {
                set.remove(handle);
                if set.is_empty() {
                    self.voice_presence.remove(&(ws, channel));
                }
            }
            out.extend(self.voice_broadcast(ws, channel));
        }
        out
    }

    /// The relay clock as unix seconds, for stamping account/friendship times.
    fn now_secs(&self) -> u64 {
        (self.now)()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// The device currently on `conn`, or an empty id if unregistered.
    fn device_for(&self, conn: ConnId) -> DeviceId {
        self.conn_device
            .get(&conn)
            .cloned()
            .unwrap_or_else(|| DeviceId(String::new()))
    }

    /// Whether `device` is a routing member of `group`.
    fn is_member(&self, group: &GroupId, device: &DeviceId) -> bool {
        self.groups.is_member(group, device)
    }

    /// Send the group's current authoritative membership to every online member,
    /// so their displayed member list/count reflects a join/leave/remove at once
    /// (independent of the MLS leaf tree, which cannot drop an offline leaver).
    fn members_broadcast(&self, group: &GroupId) -> Vec<Outgoing> {
        let Some(set) = self.groups.members(group) else {
            return vec![];
        };
        let members: Vec<String> = set.iter().map(|d| d.0.clone()).collect();
        set.iter()
            .filter_map(|dev| self.device_conn.get(dev).copied().map(|conn| (dev, conn)))
            .map(|(_, conn)| Outgoing {
                to: conn,
                msg: ServerMsg::GroupMembers {
                    group: group.clone(),
                    members: members.clone(),
                },
            })
            .collect()
    }

    /// Deliver `make(group)` to every online member of `group` except the
    /// sender's own device. Deny-by-default: a non-member cannot inject.
    fn fanout(
        &mut self,
        from: ConnId,
        group: &GroupId,
        make: impl Fn(GroupId) -> ServerMsg,
    ) -> Vec<Outgoing> {
        let sender_device = self.conn_device.get(&from).cloned();
        // Only a member of the group may fan traffic to it (ASVS V4).
        match &sender_device {
            Some(device) if self.is_member(group, device) => {}
            _ => return vec![],
        }
        // Snapshot the recipient set so we can also mutate the offline queue.
        let recipients: Vec<DeviceId> = match self.groups.members(group) {
            Some(members) => members.iter().cloned().collect(),
            None => return vec![],
        };
        let mut out = Vec::new();
        for dev in recipients {
            if Some(&dev) == sender_device.as_ref() {
                continue;
            }
            let msg = make(group.clone());
            match self.device_conn.get(&dev) {
                // Online: deliver now.
                Some(&conn) => out.push(Outgoing { to: conn, msg }),
                // Offline: park it for delivery on their next login; tell the
                // sender if the queue is at its global cap (never a silent drop).
                None => out.extend(self.queue_for_offline(from, &dev.0, msg)),
            }
        }
        out
    }

    /// Park `msg` in the persistent offline queue for `device`. Returns a
    /// sender-facing `Error` to append only when the queue is at its global cap
    /// -- i.e. real resource exhaustion. Below that the queue evicts the device's
    /// own oldest to make room, so an incoming message is never silently lost;
    /// at true exhaustion the sender is told rather than the message vanishing.
    fn queue_for_offline(
        &mut self,
        sender: ConnId,
        device: &str,
        msg: ServerMsg,
    ) -> Option<Outgoing> {
        if self.queue.enqueue(device, msg) {
            None
        } else {
            Some(Outgoing {
                to: sender,
                msg: server_full_error(),
            })
        }
    }

    /// Spill a message meant for an *online* recipient whose live outbound is
    /// full into their persistent offline queue instead of dropping it (it is
    /// delivered on their next reconnect). Returns whether it was queued
    /// (`false` = the offline queue is at its global cap, or the target has no
    /// device). Used by the async shell as the no-drop path for a stuck reader.
    pub fn spill_offline(&mut self, to: ConnId, msg: ServerMsg) -> bool {
        match self.conn_device.get(&to).cloned() {
            Some(device) => self.queue.enqueue(&device.0, msg),
            None => false,
        }
    }

    /// A relayed live chunk could not be delivered to `recipient` within the
    /// backpressure window (they are too slow or gone): drop them from the
    /// offer's live stream so later chunks skip them (no per-chunk stall), and
    /// tell the offer's sender they did not receive it (identified precisely by
    /// the cleartext `offer_id`). Returns the sender notification to deliver.
    pub fn drop_live_recipient(&mut self, offer_id: [u8; 16], recipient: ConnId) -> Vec<Outgoing> {
        let Some(dev) = self.conn_device.get(&recipient).cloned() else {
            return vec![];
        };
        let Some(offer) = self.live_offers.get_mut(&offer_id) else {
            return vec![];
        };
        let dropped = offer.recipients.remove(&dev) | offer.accepted.remove(&dev);
        let sender = offer.sender.clone();
        if offer.recipients.is_empty() {
            self.live_offers.remove(&offer_id);
        }
        if dropped {
            self.notify_sender(&sender, ServerMsg::FileDeclined { offer_id, by: dev })
        } else {
            vec![]
        }
    }
}

/// The message the server sends a sender when a reliable message could not be
/// delivered *and* could not be stored -- the offline queue is at its global
/// byte cap (real resource exhaustion). Surfaced so nothing is ever lost
/// silently: at true exhaustion the sender is told, not left guessing.
fn server_full_error() -> ServerMsg {
    ServerMsg::Error {
        detail: "the server is out of queue space; a message could not be delivered".into(),
    }
}

/// Whether a server->client message should be preserved in the offline queue
/// rather than dropped when a live outbound is full. Reliable-delivery messages
/// (text, MLS handshake, group Welcome, a file offer) spill; real-time or
/// latest-wins ones (media, presence, call/friend state) do not -- dropping a
/// stale one is correct, and the next update supersedes it.
pub fn spillable(msg: &ServerMsg) -> bool {
    matches!(
        msg,
        ServerMsg::Text { .. }
            | ServerMsg::Mls { .. }
            | ServerMsg::Welcome { .. }
            | ServerMsg::FileOffered { .. }
    )
}

/// Refuse a workspace op, telling the submitter why. The client applies ops
/// idempotently and resyncs on gaps, so a refusal is reported once, not retried.
/// The 16-byte id a group's stored history is keyed by (reusing the durable,
/// paged channel-history store). Derived from the 32-byte group id.
fn group_store_id(group: &GroupId) -> [u8; 16] {
    let mut id = [0u8; 16];
    id.copy_from_slice(&group.0[..16]);
    id
}

fn workspace_error(to: ConnId, detail: &str) -> Vec<Outgoing> {
    vec![Outgoing {
        to,
        msg: ServerMsg::Error {
            detail: detail.to_string(),
        },
    }]
}

/// Refuse a poll operation, telling the sender why in words their client can
/// show. Poll controls are not on the reliable-delivery path, so a refusal is
/// reported once rather than retried silently.
fn poll_refused(to: ConnId, detail: &str) -> Vec<Outgoing> {
    vec![Outgoing {
        to,
        msg: ServerMsg::Error {
            detail: detail.to_string(),
        },
    }]
}

/// Build a `FileOfferRejected` reply to the sender.
fn reject(to: ConnId, offer_id: [u8; 16], reason: &str) -> Outgoing {
    Outgoing {
        to,
        msg: ServerMsg::FileOfferRejected {
            offer_id,
            reason: reason.to_string(),
        },
    }
}

/// A file store in a unique temp directory, for a relay created without an
/// explicit store (tests, `Relay::new`). Real deployments call `with_auth`.
fn fresh_file_store() -> FileStore {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "enclave-relay-files-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    FileStore::new(dir)
}

fn fresh_avatar_store() -> AvatarStore {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "enclave-relay-avatars-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    AvatarStore::load(dir)
}

/// Build an auth-failure reply. Login failures use a single coarse message so
/// they do not leak whether a handle exists (ASVS V2); OPAQUE dummy mode makes
/// the crypto path indistinguishable too.
fn auth_fail(conn: ConnId, handle: String, detail: &str) -> Vec<Outgoing> {
    vec![Outgoing {
        to: conn,
        msg: ServerMsg::Auth {
            ok: false,
            handle,
            display: String::new(),
            detail: detail.into(),
        },
    }]
}
