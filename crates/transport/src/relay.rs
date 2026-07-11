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

use enclave_protocol::{ClientMsg, DeviceId, GroupId, ServerMsg, UserId};

/// Opaque handle for one client connection. Assigned by the relay on connect.
pub type ConnId = u64;

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
}

impl Relay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new connection and get its id.
    pub fn connect(&mut self) -> ConnId {
        let id = self.next_conn;
        self.next_conn += 1;
        id
    }

    /// Drop a connection: forget its device and remove it from all routing sets.
    pub fn disconnect(&mut self, conn: ConnId) {
        if let Some(device) = self.conn_device.remove(&conn) {
            self.device_conn.remove(&device);
            self.udp_addrs.remove(&device);
            for members in self.group_members.values_mut() {
                members.remove(&device);
            }
        }
    }

    // --- Real-time UDP media channel ---

    /// A device announces its UDP endpoint and the group it will stream to.
    pub fn udp_hello(&mut self, src: SocketAddr, device: DeviceId, group: GroupId) {
        self.udp_addrs.insert(device.clone(), src);
        self.group_members.entry(group).or_default().insert(device);
    }

    /// Learn `sender`'s current UDP endpoint from an incoming frame, and return
    /// the UDP endpoints of the other group members to forward it to.
    pub fn udp_media_targets(
        &mut self,
        src: SocketAddr,
        group: &GroupId,
        sender: &DeviceId,
    ) -> Vec<SocketAddr> {
        self.udp_addrs.insert(sender.clone(), src);
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
        match msg {
            ClientMsg::Register {
                user,
                device,
                identity_pub,
                key_package,
            } => {
                self.identities.insert(user.clone(), identity_pub);
                // A device may reconnect; overwrite its mapping.
                self.device_conn.insert(device.clone(), from);
                self.conn_device.insert(from, device);
                self.key_packages.entry(user).or_default().push_back(key_package);
                vec![]
            }

            ClientMsg::FetchKeyPackages { user } => {
                // Key packages are single-use; hand out one per fetch.
                let package = self
                    .key_packages
                    .get_mut(&user)
                    .and_then(|q| q.pop_front());
                let packages = package.into_iter().collect();
                vec![Outgoing {
                    to: from,
                    msg: ServerMsg::KeyPackages { user, packages },
                }]
            }

            ClientMsg::JoinGroup { group } => {
                if let Some(device) = self.conn_device.get(&from).cloned() {
                    self.group_members.entry(group).or_default().insert(device);
                }
                vec![]
            }

            ClientMsg::Welcome { to, group, message } => {
                // The new member is now a routing member of the group.
                self.group_members
                    .entry(group.clone())
                    .or_default()
                    .insert(to.clone());
                let from_device = self.device_for(from);
                match self.device_conn.get(&to) {
                    Some(&conn) => vec![Outgoing {
                        to: conn,
                        msg: ServerMsg::Welcome {
                            group,
                            from: from_device,
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

            ClientMsg::Presence { .. } => vec![], // Phase 6
        }
    }

    /// The device currently on `conn`, or an empty id if unregistered.
    fn device_for(&self, conn: ConnId) -> DeviceId {
        self.conn_device
            .get(&conn)
            .cloned()
            .unwrap_or_else(|| DeviceId(String::new()))
    }

    /// Deliver `make(group)` to every online member of `group` except the
    /// sender's own device.
    fn fanout(
        &self,
        from: ConnId,
        group: &GroupId,
        make: impl Fn(GroupId) -> ServerMsg,
    ) -> Vec<Outgoing> {
        let sender_device = self.conn_device.get(&from);
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
