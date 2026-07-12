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

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

use enclave_protocol::{ClientMsg, DeviceId, Friend, GroupId, Presence, ServerMsg, UserId};

use crate::accounts::{AccountStore, AuthOutcome};
use crate::friends::{FriendStore, RequestOutcome};
use crate::opaque::{OpaqueServer, ServerLoginState};

/// Opaque handle for one client connection. Assigned by the relay on connect.
pub type ConnId = u64;

/// Failed logins allowed per connection before it is locked out (ASVS V2).
const MAX_LOGIN_ATTEMPTS: u32 = 5;

/// A message the relay wants delivered to a specific connection.
#[derive(Debug, Clone)]
pub struct Outgoing {
    pub to: ConnId,
    pub msg: ServerMsg,
}

/// Routing state for the signaling + delivery service. Holds no keys and no
/// message content.
#[derive(Default)]
pub struct Relay {
    next_conn: ConnId,
    /// Online devices and their current connection (both directions).
    device_conn: HashMap<DeviceId, ConnId>,
    conn_device: HashMap<ConnId, DeviceId>,
    /// Published single-use key packages per user (consumed on fetch).
    key_packages: HashMap<UserId, VecDeque<Vec<u8>>>,
    /// Last-seen identity public key per user (reference only).
    identities: HashMap<UserId, Vec<u8>>,
    /// Group routing fan-out sets: which devices should receive group traffic.
    group_members: HashMap<GroupId, HashSet<DeviceId>>,
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
}

/// Server-side state for an OPAQUE login in progress on one connection.
struct PendingLogin {
    handle: String,
    state: ServerLoginState,
}

impl Relay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a relay backed by a specific (e.g. persistent) account store, with
    /// a fresh ephemeral OPAQUE setup. Use [`Relay::with_auth`] to also supply a
    /// persistent OPAQUE setup (required so accounts survive a restart).
    pub fn with_accounts(accounts: AccountStore) -> Self {
        Self {
            accounts,
            ..Self::default()
        }
    }

    /// Create a relay backed by a persistent account store, OPAQUE setup, and
    /// friend graph. The account envelopes are only usable under the OPAQUE
    /// setup they were registered against, so those two must persist together.
    pub fn with_auth(accounts: AccountStore, opaque: OpaqueServer, friends: FriendStore) -> Self {
        Self {
            accounts,
            opaque,
            friends,
            ..Self::default()
        }
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
        if let Some(device) = self.conn_device.remove(&conn) {
            self.device_conn.remove(&device);
            self.udp_addrs.remove(&device);
            for members in self.group_members.values_mut() {
                members.remove(&device);
            }
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
                return self.set_presence(&user, Presence::Offline);
            }
        }
        vec![]
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
        self.key_packages
            .entry(user.clone())
            .or_default()
            .push_back(key_package);

        let mut out = vec![Outgoing {
            to: conn,
            msg: self.friends_snapshot(&handle),
        }];
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
        let members = self.group_members.entry(group).or_default();
        if members.is_empty() || members.contains(&device) {
            members.insert(device);
        }
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
        let Some(members) = self.group_members.get(group) else {
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
                match self
                    .accounts
                    .create_account(&handle, envelope, identity_pub.clone(), display)
                {
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
                // Key packages are single-use; hand out one per fetch.
                let package = self.key_packages.get_mut(&user).and_then(|q| q.pop_front());
                let packages = package.into_iter().collect();
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
                    let members = self.group_members.entry(group).or_default();
                    if members.is_empty() || members.contains(&device) {
                        members.insert(device);
                    }
                }
                vec![]
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
                self.group_members
                    .entry(group.clone())
                    .or_default()
                    .insert(to.clone());
                match self.device_conn.get(&to) {
                    Some(&conn) => vec![Outgoing {
                        to: conn,
                        msg: ServerMsg::Welcome {
                            group,
                            from: from_device,
                            name,
                            message,
                        },
                    }],
                    None => vec![], // target offline; a real DS would queue it
                }
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
                match self.friends.request(&me, &to) {
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
                if self.friends.accept(&me, &requester) {
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

            ClientMsg::PublishKeyPackages { packages } => {
                if let Some(user) = self.conn_user.get(&from).cloned() {
                    let q = self.key_packages.entry(user).or_default();
                    for kp in packages {
                        q.push_back(kp);
                    }
                }
                vec![]
            }
        }
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
        let with_display = |names: Vec<String>| -> Vec<Friend> {
            names
                .into_iter()
                .map(|u| Friend {
                    display: self.accounts.display(&u),
                    username: u,
                })
                .collect()
        };
        ServerMsg::Friends {
            friends: with_display(self.friends.friends_of(handle)),
            incoming: with_display(self.friends.incoming(handle)),
            outgoing: with_display(self.friends.outgoing(handle)),
        }
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
        self.group_members
            .get(group)
            .is_some_and(|members| members.contains(device))
    }

    /// Deliver `make(group)` to every online member of `group` except the
    /// sender's own device. Deny-by-default: a non-member cannot inject.
    fn fanout(
        &self,
        from: ConnId,
        group: &GroupId,
        make: impl Fn(GroupId) -> ServerMsg,
    ) -> Vec<Outgoing> {
        let sender_device = self.conn_device.get(&from);
        // Only a member of the group may fan traffic to it (ASVS V4).
        match sender_device {
            Some(device) if self.is_member(group, device) => {}
            _ => return vec![],
        }
        let Some(members) = self.group_members.get(group) else {
            return vec![];
        };
        members
            .iter()
            .filter(|dev| Some(*dev) != sender_device)
            .filter_map(|dev| self.device_conn.get(dev))
            .map(|&conn| Outgoing {
                to: conn,
                msg: make(group.clone()),
            })
            .collect()
    }
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
