//! Enclave wire protocol: the types that cross the network.
//!
//! # The load-bearing invariant
//!
//! The signaling/SFU server is *semi-trusted*: it routes and stays up, but it
//! must never be able to read call content. This crate encodes that invariant
//! in the type system -- every field the server inspects or forwards is either
//! routing metadata (ids, presence) or an opaque [`Sealed`] blob it cannot open.
//! There is deliberately no variant that hands the server plaintext media, text,
//! or key material. If a future change needs the server to read content, it has
//! to break this type on purpose, in review.
//!
//! Metadata (who is in a call, when, packet timing/sizes) IS visible to the
//! server. That is an accepted tradeoff of the self-hosted-SFU topology; see
//! THREAT_MODEL.md ("Information disclosure").

use serde::{Deserialize, Serialize};

/// Stable identity of a person. Bound to their long-term identity public key.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct UserId(pub String);

/// A single device/client belonging to a user. MLS membership is per-device.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct DeviceId(pub String);

/// Identifies one MLS group == one call or one DM thread.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

/// Opaque, end-to-end-encrypted bytes. The server can store and forward these
/// but cannot open them: it holds no key. Newtype (not a bare `Vec<u8>`) so the
/// "server never sees plaintext" boundary is visible at every call site.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Sealed(pub Vec<u8>);

/// Kind of real-time media a frame carries. Drives jitter-buffer/codec routing
/// only; the payload is always [`Sealed`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MediaKind {
    Audio,
    Video,
    Screen,
}

/// One end-to-end-encrypted media frame as it appears on the wire.
///
/// The header is plaintext (the SFU needs it to route + order); the `payload`
/// is SFrame-style AEAD ciphertext of an already-encoded Opus/video frame. The
/// `(sender, epoch, counter)` triple is the AEAD nonce source and must be unique
/// per media key -- see `enclave-crypto` for the enforced counter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MediaFrame {
    pub group: GroupId,
    pub sender: DeviceId,
    pub kind: MediaKind,
    /// MLS epoch the sending key was derived from; receivers reject stale epochs.
    pub epoch: u64,
    /// Per-sender, per-epoch monotonic counter. Never reused. Nonce input.
    pub counter: u64,
    pub payload: Sealed,
    /// The sender's Ed25519 signature over the header + ciphertext, proving the
    /// frame was produced by the holder of the claimed sender's identity key.
    /// Without this, any group member could seal a frame under another member's
    /// (group-derivable) media key and impersonate them; the receiver verifies
    /// this against the sender's roster public key and rejects a mismatch.
    pub sig: Vec<u8>,
}

/// Client -> server messages over the (TLS) signaling channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientMsg {
    /// OPAQUE registration, step 1: a desired unique `name` (username) plus a
    /// blinded registration request. The server accepts it if the username is
    /// free. The password is never sent -- not here, not anywhere.
    RegisterStart { name: String, request: Vec<u8> },
    /// OPAQUE registration, step 2: the client's upload (the future stored
    /// envelope), this device's identity public key and signed KeyPackage, and
    /// the chosen `display` name (cosmetic; empty defaults to the username).
    RegisterFinish {
        upload: Vec<u8>,
        identity_pub: Vec<u8>,
        key_package: Vec<u8>,
        display: String,
    },
    /// OPAQUE login, step 1: a blinded credential request for the full `handle`
    /// (`name#1234`).
    LoginStart { handle: String, request: Vec<u8> },
    /// OPAQUE login, step 2: the client's credential finalization proving
    /// knowledge of the password, plus a fresh KeyPackage to publish. The server
    /// verifies the proof and authenticates (or rejects) the session.
    LoginFinish {
        finalization: Vec<u8>,
        key_package: Vec<u8>,
    },
    /// End the authenticated session (go offline).
    Logout,
    /// Ask for a peer's published KeyPackages in order to add them to a group.
    FetchKeyPackages { user: UserId },
    /// Announce that this device is now a routing member of `group` (sent after
    /// creating or joining it). Lets the server fan group traffic out to it.
    /// Membership is routing metadata, visible to the server by design.
    JoinGroup { group: GroupId },
    /// Deliver a Welcome directly to a new member's device. The server also
    /// records `to` as a routing member of `group`. The payload is opaque. The
    /// `name` labels the conversation (empty for a 1:1 DM, where the recipient
    /// labels it by the sender); group names are low-sensitivity metadata.
    Welcome {
        to: DeviceId,
        group: GroupId,
        name: String,
        message: Sealed,
    },
    /// An MLS handshake message (Proposal/Commit) the server blindly relays to
    /// group members. Opaque to the server.
    Mls { group: GroupId, message: Sealed },
    /// An end-to-end-encrypted application message (text DM). Opaque.
    Text { group: GroupId, message: Sealed },
    /// A real-time encrypted media frame destined for the SFU to fan out.
    Media(MediaFrame),
    /// Coarse presence the user chooses to expose. Metadata, visible to server.
    Presence { status: Presence },
    /// Subscribe to presence updates for these users (a friends roster). The
    /// server replies with their current presence and pushes future changes.
    WatchPresence { users: Vec<UserId> },
    /// Send a friend request to the full handle `to`. If they had already
    /// requested you, you become friends immediately.
    FriendRequest { to: String },
    /// Accept a pending incoming friend request from `from`.
    FriendAccept { from: String },
    /// Decline an incoming request from, or cancel an outgoing request to, `who`.
    FriendDecline { who: String },
    /// Remove an existing friend.
    FriendRemove { handle: String },
    /// Ask for the current friends + pending-requests snapshot.
    ListFriends,
    /// Ask `to` to open a DM with us (used when we are the lexicographically
    /// larger username, so the smaller one creates the shared MLS group).
    RequestDm { to: String },
    /// Change our display name (cosmetic); friends are notified.
    SetDisplayName { display: String },
}

/// A person in the friend graph: the unique `username` (login/add id) plus the
/// current cosmetic `display` name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Friend {
    pub username: String,
    pub display: String,
}

/// Server -> client messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServerMsg {
    /// OPAQUE registration, step 1 reply: the server-assigned `handle`
    /// (`name#1234`) plus the server's registration response.
    RegisterResponse {
        handle: String,
        response: Vec<u8>,
    },
    /// OPAQUE login, step 1 reply: the server's credential response (a challenge
    /// the client can only answer with the right password).
    LoginResponse {
        response: Vec<u8>,
    },
    /// Final result of a registration or login exchange. `handle` is the unique
    /// username the session is authenticated as; `display` is its current
    /// display name (empty on failure).
    Auth {
        ok: bool,
        handle: String,
        display: String,
        detail: String,
    },
    KeyPackages {
        user: UserId,
        packages: Vec<Vec<u8>>,
    },
    Welcome {
        group: GroupId,
        from: DeviceId,
        name: String,
        message: Sealed,
    },
    Mls {
        group: GroupId,
        from: DeviceId,
        message: Sealed,
    },
    Text {
        group: GroupId,
        from: DeviceId,
        message: Sealed,
    },
    Media(MediaFrame),
    Presence {
        user: UserId,
        status: Presence,
    },
    /// Someone sent you a friend request.
    FriendRequestReceived {
        from: String,
    },
    /// A handle you requested has accepted; you are now friends.
    FriendAccepted {
        handle: String,
    },
    /// A handle removed you as a friend (or you removed them).
    FriendRemoved {
        handle: String,
    },
    /// The current friends + pending-requests snapshot for this session, each
    /// carrying the person's current display name.
    Friends {
        friends: Vec<Friend>,
        incoming: Vec<Friend>,
        outgoing: Vec<Friend>,
    },
    /// `from` asks us to open the DM (we are the canonical creator).
    DmRequested {
        from: String,
    },
    Error {
        detail: String,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Presence {
    Online,
    Away,
    Offline,
}

/// Messages on the real-time UDP media channel. The frame payload is the same
/// opaque `Sealed` bytes as everywhere else; UDP just carries it with lower
/// latency (and loss tolerance) than the reliable signaling channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UdpMsg {
    /// Announce this device's UDP endpoint and the group it streams to, so the
    /// relay learns where to forward frames addressed to that group.
    Hello { device: DeviceId, group: GroupId },
    /// One sealed media frame to fan out to the rest of the group.
    Frame(MediaFrame),
}

/// Protocol-level errors shared across crates.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("malformed frame: {0}")]
    MalformedFrame(&'static str),
    #[error("unknown group")]
    UnknownGroup,
    #[error("stale epoch: frame {frame} < current {current}")]
    StaleEpoch { frame: u64, current: u64 },
}
