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
///
/// Serialization is format-aware: in a human-readable format (the JSON
/// signaling channel) the bytes are base64, not a numeric array. A JSON array
/// of `u8` costs ~3.4 bytes per byte, which would push a sealed message chunk
/// past the 1 MiB frame limit; base64 costs ~1.33 and keeps a 512 KiB chunk
/// comfortably under it. A binary format (the UDP media path) still gets raw
/// bytes, with no overhead.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Sealed(pub Vec<u8>);

impl Serialize for Sealed {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            use base64::Engine;
            s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Sealed {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            use base64::Engine;
            let s = String::deserialize(d)?;
            base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .map(Sealed)
                .map_err(serde::de::Error::custom)
        } else {
            Ok(Sealed(Vec::<u8>::deserialize(d)?))
        }
    }
}

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
    /// Vouch that `member` is a routing member of `group`. The server honors it
    /// only when the *sender* is already a routing member, so a reconnecting
    /// member can rebuild the routing set the server lost (e.g. after a restart)
    /// by re-adding peers that the bootstrap-or-reaffirm rule would otherwise
    /// lock out. A member only grants routing it already holds; a non-member's
    /// vouch is ignored, so this cannot be used to subscribe to a stranger's
    /// group (even one with a guessable DM id).
    AffirmMember { group: GroupId, member: DeviceId },
    /// Leave `group`: drop this device from the group's routing set (used when
    /// deleting/leaving a conversation, so the server stops fanning it to us).
    LeaveGroup { group: GroupId },
    /// Remove `member` from `group`'s routing set. Honored only from a current
    /// member. The MLS rekey that actually locks the removed member out of future
    /// epochs travels separately as an Mls commit to the remaining members.
    RemoveMember { group: GroupId, member: DeviceId },
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
    /// Register a buffered/routed poll with the server. The sender is recorded as
    /// the poll's OWNER (the only device that may `BallotClose` it early). `mode`:
    /// 0 = buffer for the GROUP, release to it at close; 1 = route each ballot to
    /// the OWNER live (a private survey the owner watches); 2 = buffer for the
    /// OWNER, release to the owner at close. `release_at` = auto-release time (unix
    /// ms) or None for owner-triggered close only. Ballot contents are never seen.
    BallotOpen {
        poll: [u8; 16],
        group: GroupId,
        /// Who gets the ballots and when: 0 = the whole group once the poll
        /// closes, 1 = the owner as each ballot arrives, 2 = the owner once the
        /// poll closes.
        mode: u8,
        release_at: Option<u64>,
        /// Strip the submitter's identity when releasing, so recipients get an
        /// unattributed batch. Orthogonal to `mode` on purpose: anonymity is a
        /// property of *how* ballots are released, not of *who* receives them,
        /// and folding it into the mode number would multiply the modes.
        anonymous: bool,
    },
    /// Submit one sealed ballot for a poll opened with `BallotOpen`. The server
    /// buffers it (deduped by submitter, last write wins) or, in owner-live mode,
    /// forwards it to the owner immediately. The `ballot` is opaque ciphertext.
    BallotSubmit { poll: [u8; 16], ballot: Sealed },
    /// The owner ends a buffered poll now: the server releases the buffered ballots
    /// (to the group or the owner, per the poll's mode). Honored only from the
    /// device that opened the poll.
    BallotClose { poll: [u8; 16] },
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
    /// Join (or start) the voice call in `group`. If we are the first participant
    /// the server rings the other members; otherwise it just adds us. Call
    /// signaling is metadata (who is calling whom, when), not content.
    JoinCall { group: GroupId },
    /// Leave the voice call in `group`.
    LeaveCall { group: GroupId },
    /// Decline the incoming call in `group` (we were rung but will not join). The
    /// caller is told; our client falls back to showing a "call active" banner.
    DeclineCall { group: GroupId },

    /// Offer a file to `group`. A file is never pushed to a recipient: it is
    /// offered, and each recipient explicitly accepts or declines. `manifest` is
    /// the sealed name+mime+size the recipients decrypt to decide, without
    /// downloading. `size` is the plaintext size, which the server needs to
    /// enforce its store quota; it is 0 for a `live` offer (the server stores
    /// nothing, so needs no size). When `live` is false the server buffers the
    /// upload on disk for offline delivery if it fits the quota; when true the
    /// bytes are streamed in real time to whoever accepts and never stored.
    FileOffer {
        offer_id: [u8; 16],
        group: GroupId,
        size: u64,
        manifest: Sealed,
        live: bool,
    },
    /// One sealed chunk of an offered file: appended to the server's store while
    /// uploading, or relayed live to accepting recipients. `data` is the chunk
    /// sealed under the offer's per-file content key (see `crypto::seal_chunk`) --
    /// NOT an MLS message, so streaming or dropping chunks never disturbs the
    /// group's message ratchet. `index` is the chunk's 0-based position, needed
    /// (and authenticated) to derive its nonce; it is not secret.
    FileChunk {
        offer_id: [u8; 16],
        index: u32,
        data: Sealed,
    },
    /// The sender has sent every chunk of `offer_id`.
    FileComplete { offer_id: [u8; 16] },
    /// Consent to receive an offered file. The server then delivers its chunks
    /// (from the store, or by relaying the sender's live stream).
    FileAccept { offer_id: [u8; 16] },
    /// Refuse an offered file. The server drops it once every recipient resolves.
    FileDecline { offer_id: [u8; 16] },
    /// Abort our in-progress download of an offer WITHOUT declining it: the
    /// server stops the in-flight stream but leaves the offer available, so we
    /// can download it again later (until the sender withdraws it or goes
    /// offline). Distinct from `FileDecline`, which gives the offer up entirely.
    FileAbort { offer_id: [u8; 16] },
    /// Withdraw an offer we made (before or during upload/streaming).
    FileCancel { offer_id: [u8; 16] },

    /// Upload an encrypted, content-addressed avatar blob. `addr` MUST equal the
    /// SHA-256 of `data`; the server verifies this and rejects a mismatch, so an
    /// address can only ever name its own content and one user can never
    /// overwrite another's blob. The bytes are opaque ciphertext -- the server
    /// cannot read the image. Sent inside [`Reliable`] so the upload survives a
    /// drop before the profile that references it is broadcast.
    PutAvatar { addr: [u8; 32], data: Vec<u8> },
    /// Fetch an avatar blob by its content address (learned from a sealed
    /// profile). The 256-bit address is an unguessable bearer capability, so
    /// possession of it is the authorization. Replied to with [`ServerMsg::Avatar`].
    FetchAvatar { addr: [u8; 32] },

    /// A message wrapped for at-least-once delivery. The server processes `msg`
    /// exactly as if it were sent bare, then replies [`ServerMsg::Ack`] with the
    /// same `seq` once it has *durably accepted* it (delivered to online members
    /// and persisted for offline ones). The sender keeps it in a retransmit
    /// buffer until the ack arrives and resends it on reconnect (or on a retry
    /// timer), so a connection drop, a server restart, or a transient queue-full
    /// never silently loses a chat message. Duplicates from a resend are deduped
    /// by the receiver (chunked messages by their transfer id; MLS by epoch).
    /// `seq` is a per-session monotonic counter, meaningful only between this
    /// sender and the server.
    Reliable { seq: u64, msg: Box<ClientMsg> },

    // ---- Workspaces ----
    /// Append a signed op to a workspace's log. `workspace` is the id; for the
    /// genesis `Create` op the server registers the new workspace. The server
    /// validates the entry (signature, chain, monotonic seq) before appending,
    /// then broadcasts it to the workspace's members as [`ServerMsg::WorkspaceOps`].
    WorkspaceSubmitOp {
        workspace: WorkspaceId,
        op: SignedOp,
    },
    /// Fetch a workspace's full op-log (on join or reconnect), replied to with
    /// [`ServerMsg::WorkspaceOps`].
    WorkspaceFetch { workspace: WorkspaceId },
    /// List the workspaces this account is a member of, replied to with
    /// [`ServerMsg::Workspaces`].
    WorkspaceListMine,
    /// Deliver an MLS Welcome for a workspace group to a member just added.
    /// `channel = None` targets the workspace group (WG, keys public channels);
    /// `channel = Some(id)` targets that **private channel's** own group. `to`
    /// must already be a member of the relevant set (its Add op is submitted
    /// first). Opaque.
    WorkspaceWelcome {
        workspace: WorkspaceId,
        channel: Option<ChannelId>,
        to: String,
        welcome: Sealed,
    },
    /// Broadcast an MLS commit (add/remove) to the members of a workspace group
    /// so they advance to the new epoch. `channel` scopes it to the WG (`None`)
    /// or a private channel's group. Opaque.
    WorkspaceCommit {
        workspace: WorkspaceId,
        channel: Option<ChannelId>,
        commit: Sealed,
    },
    /// Post a message to a channel. The payload is sealed under the channel's
    /// epoch **history key** (`crypto::seal_channel`); the relay both fans it to
    /// members and stores it for scrollback. `channel`/`epoch` are metadata the
    /// relay already knows (the op-log carries channels), needed to store and to
    /// pick the opening key; the text stays sealed.
    ChannelPost {
        workspace: WorkspaceId,
        channel: ChannelId,
        epoch: u64,
        message: Sealed,
    },
    /// Distribute channel history key(s). `group_channel = None` means the bundle
    /// is sealed under the WG (public-channel keys); `Some(id)` means it is sealed
    /// under that private channel's own group (so only its members can open it,
    /// even if the relay misroutes). `to = None` broadcasts to members; `to =
    /// Some(handle)` is directed to one.
    ChannelKeyShare {
        workspace: WorkspaceId,
        group_channel: Option<ChannelId>,
        to: Option<String>,
        message: Sealed,
    },
    /// Fetch one page of a channel's stored history for backfill, replied to with
    /// [`ServerMsg::ChannelHistory`]. Members only. `before = None` fetches the
    /// newest page; `Some(seq)` fetches the page just older than `seq` (the cursor
    /// a client carries from a prior page) so scrollback loads incrementally
    /// rather than dumping the whole backlog. `limit` is clamped server-side.
    ChannelHistoryFetch {
        workspace: WorkspaceId,
        channel: ChannelId,
        before: Option<u64>,
        limit: u32,
    },
    /// Share a group's history-sharing configuration (MLS-sealed: the epoch and its
    /// history key, or an "off" marker). `to = None` broadcasts to the group; `to
    /// = Some(handle)` hands the current epoch's key to one new member on join.
    /// Opt-in per group; while on, messages are also stored for scrollback, which
    /// costs forward secrecy on that stored copy.
    GroupHistoryConfig {
        group: GroupId,
        to: Option<String>,
        message: Sealed,
    },
    /// Store one group message for scrollback, off-ratchet-sealed under the group's
    /// current epoch history key. The relay stores it (holding no key) so a future
    /// member can backfill it. Members only.
    GroupHistoryPost {
        group: GroupId,
        epoch: u64,
        message: Sealed,
    },
    /// Fetch a page of a group's stored history (reply: [`ServerMsg::GroupHistory`]).
    /// Members only; paged by seq like a channel's.
    GroupHistoryFetch {
        group: GroupId,
        before: Option<u64>,
        limit: u32,
    },
    /// Join a voice channel's presence (we are now connected). The relay tracks
    /// it and broadcasts the updated roster to the channel's members, so everyone
    /// sees who is in voice without joining. The actual media rides the existing
    /// call/SFU path on the voice channel's group.
    VoiceJoin {
        workspace: WorkspaceId,
        channel: ChannelId,
    },
    /// Leave a voice channel's presence.
    VoiceLeave {
        workspace: WorkspaceId,
        channel: ChannelId,
    },
    /// Create a shareable invite code for a workspace (admins/owner only). The
    /// relay verifies the requester's role, mints a code, and replies with
    /// [`ServerMsg::InviteCreated`]. `ttl_secs = 0` never expires; `max_uses = 0`
    /// is unlimited.
    CreateInvite {
        workspace: WorkspaceId,
        ttl_secs: u64,
        max_uses: u32,
    },
    /// Redeem an invite code to request admission to its workspace. The relay
    /// validates the code and routes a [`ServerMsg::JoinRequest`] to an online
    /// admin, whose client performs the (signed, op-logged) add. A dead code or
    /// no online admin comes back as [`ServerMsg::Error`].
    RedeemInvite { code: String },
    /// Move another member from their current voice channel to `channel`. Admin
    /// only; the relay verifies the role and directs the member's client with
    /// [`ServerMsg::VoiceMoved`] (presence then flows via the member's normal
    /// join/leave, so it is never double counted).
    VoiceMoveMember {
        workspace: WorkspaceId,
        channel: ChannelId,
        member: String,
    },
}

/// A person in the friend graph: the unique `username` (login/add id) plus the
/// current cosmetic `display` name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Friend {
    pub username: String,
    pub display: String,
    /// When this friendship was formed (unix seconds), if the server recorded it.
    /// `None` for pending requests and for friendships that predate the server
    /// tracking it. Server-authoritative, so both sides agree.
    #[serde(default)]
    pub since: Option<u64>,
    /// When this person's account was created (unix seconds), if known. `None`
    /// for accounts that predate the server tracking it.
    #[serde(default)]
    pub member_since: Option<u64>,
}

// ---------------------------------------------------------------------------
// Workspaces: Discord/Slack-style containers of text/voice channels. Structure
// and membership are server-visible metadata (the accepted tier); channel
// *content* stays end-to-end encrypted and never appears here. The authoritative
// record of a workspace's structure is its **op-log**: an append-only,
// hash-chained sequence of identity-signed [`SignedOp`]s. Roles and membership
// are decided by replaying that log (see `enclave_crypto::workspace`), so the
// relay cannot forge who is a member or an admin -- only route and store.
// ---------------------------------------------------------------------------

/// 16-byte opaque ids (random at creation), so ids leak no ordering or count.
pub type WorkspaceId = [u8; 16];
pub type ChannelId = [u8; 16];
pub type CategoryId = [u8; 16];

/// What a channel carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelKind {
    Text,
    Voice,
}

/// A workspace capability. Roles are named bundles of these; a member's effective
/// permissions are the union of their assigned roles' permissions, and the owner
/// (the genesis creator, exactly one) implicitly holds every permission. A member
/// with no roles can participate (read/post) but not manage anything -- authority
/// is deny-by-default. Adding a capability later is just a new variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Permission {
    /// Create/rename/delete channels and categories, and move/nest them.
    ManageChannels,
    /// Add or remove workspace members, and mint invite codes.
    ManageMembers,
    /// Add or remove members of private channels.
    ManageChannelMembers,
    /// Create, edit, delete roles and assign them to members.
    ManageRoles,
    /// Move members between voice channels.
    MoveVoiceMembers,
}

impl Permission {
    /// Every capability, for the owner and for a role editor's checklist.
    pub const ALL: [Permission; 5] = [
        Permission::ManageChannels,
        Permission::ManageMembers,
        Permission::ManageChannelMembers,
        Permission::ManageRoles,
        Permission::MoveVoiceMembers,
    ];

    /// A stable snake_case token for the wire to the UI and back.
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::ManageChannels => "manage_channels",
            Permission::ManageMembers => "manage_members",
            Permission::ManageChannelMembers => "manage_channel_members",
            Permission::ManageRoles => "manage_roles",
            Permission::MoveVoiceMembers => "move_voice_members",
        }
    }

    /// Parse the token produced by [`Permission::as_str`].
    pub fn from_token(s: &str) -> Option<Permission> {
        Permission::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

/// Identifier for a workspace role definition.
pub type RoleId = [u8; 16];

/// One structural change to a workspace. The op-log is a sequence of these, each
/// wrapped in a signed, chained [`SignedOp`]. Content (messages) is NOT here --
/// only structure, membership, and roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkspaceOp {
    /// Genesis (seq 0 only): names the workspace and fixes its owner. `owner_key`
    /// is the owner's identity public key, the root of all later authorization.
    Create {
        name: String,
        owner: String,
        owner_key: Vec<u8>,
    },
    /// Add a member, recording the identity key their future ops are verified
    /// against. Needs `ManageMembers`.
    AddMember { member: String, member_key: Vec<u8> },
    /// Remove a member (they lose access; channels they were in rekey). Needs
    /// `ManageMembers`; the owner cannot be removed.
    RemoveMember { member: String },
    /// Define a new role. Needs `ManageRoles`, and a non-owner may only put
    /// permissions they themselves hold into it (no privilege escalation).
    CreateRole {
        role: RoleId,
        name: String,
        permissions: Vec<Permission>,
    },
    /// Change a role's name and permission set (same escalation rule as create).
    EditRole {
        role: RoleId,
        name: String,
        permissions: Vec<Permission>,
    },
    /// Delete a role (it is removed from every member who had it). Needs `ManageRoles`.
    DeleteRole { role: RoleId },
    /// Assign a role to a member. Needs `ManageRoles`, and a non-owner may only
    /// assign a role whose permissions they themselves hold. The owner is not a
    /// role target.
    AssignRole { member: String, role: RoleId },
    /// Remove a role from a member. Needs `ManageRoles`.
    UnassignRole { member: String, role: RoleId },
    /// Create a category (a channel group in the sidebar).
    CreateCategory { category: CategoryId, name: String },
    /// Create a channel. `private` channels have their own subset membership
    /// (managed by later Add/RemoveChannelMember ops in M3); a public channel is
    /// keyed off the workspace group.
    CreateChannel {
        channel: ChannelId,
        name: String,
        kind: ChannelKind,
        private: bool,
        category: Option<CategoryId>,
    },
    /// Rename a channel.
    RenameChannel { channel: ChannelId, name: String },
    /// Delete a channel.
    DeleteChannel { channel: ChannelId },
    /// Add a workspace member to a **private** channel's member set (they can then
    /// receive its key and traffic). Admin only; the member must be in the
    /// workspace. No effect on a public channel (all members are in it).
    AddChannelMember { channel: ChannelId, member: String },
    /// Remove a member from a private channel (its key rotates for the rest).
    RemoveChannelMember { channel: ChannelId, member: String },
    /// Move a channel under a category (or to the top level with `None`), e.g. by
    /// dragging it onto a category in the sidebar. Admin only.
    SetChannelCategory {
        channel: ChannelId,
        category: Option<CategoryId>,
    },
    /// Nest a category under another (or move it to the top level with `None`),
    /// e.g. by dragging a category onto a category. Admin only; the op-log rejects
    /// a move that would form a cycle or exceed the nesting depth.
    SetCategoryParent {
        category: CategoryId,
        parent: Option<CategoryId>,
    },
}

/// An op-log entry: one [`WorkspaceOp`] made attributable and tamper-evident.
/// `sig` is `author`'s identity-key signature over the entry's body (everything
/// but `sig`, via [`SignedOp::body_bytes`]); `prev_hash` chains it to the prior
/// entry so a reordered or forked log is detectable. Verified by replay in
/// `enclave_crypto::workspace`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOp {
    /// Per-workspace position, starting at 0 (the genesis `Create`).
    pub seq: u64,
    /// SHA-256 of the previous entry's `body_bytes` (all-zero for seq 0).
    pub prev_hash: [u8; 32],
    /// The acting member's handle.
    pub author: String,
    /// The author's identity public key, so the signature is self-contained.
    pub author_key: Vec<u8>,
    /// Unix seconds (server-independent; set by the author, sanity-checked).
    pub ts: u64,
    pub op: WorkspaceOp,
    /// Detached identity signature over `body_bytes()` under context
    /// [`WS_OP_CONTEXT`].
    pub sig: Vec<u8>,
}

/// Signing/hashing domain tag for workspace op-log entries. The canonical bytes
/// that are signed and hashed (every field but `sig`) are produced by
/// `enclave_crypto::workspace`, which owns all op-log verification.
pub const WS_OP_CONTEXT: &[u8] = b"enclave/ws-op/v1";

/// A workspace as summarized for the sidebar list (metadata only).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    pub id: WorkspaceId,
    pub name: String,
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
    /// Buffered ballots released to this recipient (the whole group, or the poll's
    /// owner, per its mode). Each entry is (submitter, sealed ballot), delivered at
    /// the release moment. The submitter is the server's authenticated view of who
    /// sent each ballot (attribution, not vote content -- the ballot is opaque).
    Ballots {
        group: GroupId,
        poll: [u8; 16],
        ballots: Vec<(DeviceId, Sealed)>,
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
    /// You were removed from a group (a member removed you). Its history stays
    /// readable on your device, but the conversation becomes read-only.
    RemovedFromGroup {
        group: GroupId,
    },
    /// The server's authoritative routing membership for `group` (usernames),
    /// sent when it changes (join/leave/remove) and on (re)join. Clients use it
    /// for the displayed member list/count -- which does not depend on the MLS
    /// leaf tree, so it stays correct even when no member is online to commit a
    /// crypto removal. The safety number (from the crypto tree) remains the
    /// security anchor; this list is convenience.
    GroupMembers {
        group: GroupId,
        members: Vec<String>,
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
    /// A call just started in `group`, initiated by `from`: ring the user.
    CallOffer {
        group: GroupId,
        from: String,
    },
    /// The current participants of the call in `group` (empty = the call ended).
    /// Drives the "call active" banner and the who-is-in-the-call display.
    CallParticipants {
        group: GroupId,
        participants: Vec<String>,
    },
    /// `from` declined the call in `group`.
    CallDeclined {
        group: GroupId,
        from: String,
    },
    /// The server admitted a stored offer; the sender may begin uploading its
    /// chunks. (Sent only for non-live offers.)
    FileUploadReady {
        offer_id: [u8; 16],
    },
    /// The server refused to store the offer (too large, store full, or low on
    /// disk). `reason` is a short human-readable explanation. The sender may
    /// retry the transfer live if the recipients are online.
    FileOfferRejected {
        offer_id: [u8; 16],
        reason: String,
    },
    /// A file has been offered to you. Do NOT download it automatically: show
    /// the user (from the decrypted `manifest`) who sent what, and accept or
    /// decline. `live` means the sender is streaming now, so accept promptly.
    FileOffered {
        offer_id: [u8; 16],
        group: GroupId,
        from: DeviceId,
        size: u64,
        manifest: Sealed,
        live: bool,
    },
    /// A recipient accepted `offer_id`. For a live offer this is the sender's cue
    /// to start streaming chunks; for a stored offer it is informational.
    FileAccepted {
        offer_id: [u8; 16],
        by: DeviceId,
    },
    /// A recipient declined `offer_id` (or it expired for them).
    FileDeclined {
        offer_id: [u8; 16],
        by: DeviceId,
    },
    /// One sealed chunk of a file you accepted, from device `from`. `data` is
    /// sealed under the offer's content key (from the manifest), not the group
    /// ratchet; `index` is its authenticated 0-based position.
    FileChunk {
        offer_id: [u8; 16],
        from: DeviceId,
        index: u32,
        data: Sealed,
    },
    /// Every chunk of `offer_id` from `from` has been delivered.
    FileComplete {
        offer_id: [u8; 16],
        from: DeviceId,
    },
    /// Reply to [`ClientMsg::FetchAvatar`]: the ciphertext stored under `addr`,
    /// or `None` if the server has no such blob (never uploaded, or evicted).
    /// The bytes are opaque; only a group member holds the key to decrypt them.
    Avatar {
        addr: [u8; 32],
        data: Option<Vec<u8>>,
    },
    /// Confirms the server durably accepted the [`ClientMsg::Reliable`] with this
    /// `seq`. The sender then drops it from its retransmit buffer. Until it
    /// arrives the sender keeps retransmitting, so a message that momentarily
    /// could not be accepted (e.g. the offline queue was at its global cap) is
    /// simply retried rather than reported failed.
    Ack {
        seq: u64,
    },
    Error {
        detail: String,
    },

    // ---- Workspaces ----
    /// One or more op-log entries for a workspace: the full log (reply to
    /// [`ClientMsg::WorkspaceFetch`] or on membership) or a single newly-appended
    /// op broadcast to members. `ops` are contiguous by `seq`; the client applies
    /// them in order via `enclave_crypto::workspace`.
    WorkspaceOps {
        workspace: WorkspaceId,
        ops: Vec<SignedOp>,
    },
    /// The workspaces this account belongs to (reply to
    /// [`ClientMsg::WorkspaceListMine`]).
    Workspaces {
        workspaces: Vec<WorkspaceSummary>,
    },
    /// An MLS Welcome for a workspace group we were just added to (`channel =
    /// None` = the WG; `Some(id)` = that private channel's group). `from` is the
    /// adder.
    WorkspaceWelcome {
        workspace: WorkspaceId,
        channel: Option<ChannelId>,
        from: String,
        welcome: Sealed,
    },
    /// An MLS commit to apply to a workspace group (`channel` scopes it). `from`
    /// is its author.
    WorkspaceCommit {
        workspace: WorkspaceId,
        channel: Option<ChannelId>,
        from: String,
        commit: Sealed,
    },
    /// A channel message sealed under the channel's epoch history key. `from` is
    /// the sender; the payload is opened with `crypto::open_channel`.
    ChannelPost {
        workspace: WorkspaceId,
        channel: ChannelId,
        epoch: u64,
        from: String,
        message: Sealed,
    },
    /// Channel history key(s) shared with us. `group_channel` says which group
    /// sealed them (WG if `None`, else that private channel's group). `from` is
    /// the sharer.
    ChannelKeyShare {
        workspace: WorkspaceId,
        group_channel: Option<ChannelId>,
        from: String,
        message: Sealed,
    },
    /// One page of a channel's stored history for backfill: `(seq, epoch, sealed)`
    /// oldest first within the page (reply to
    /// [`ClientMsg::ChannelHistoryFetch`]). `seq` is the paging cursor: the
    /// client remembers the smallest it holds to fetch the next older page.
    /// `has_more` says whether still-older retained messages exist before this
    /// page, so the UI knows whether to offer "load older".
    ChannelHistory {
        workspace: WorkspaceId,
        channel: ChannelId,
        messages: Vec<(u64, u64, Sealed)>,
        has_more: bool,
    },
    /// A group's history-sharing configuration, MLS-sealed (reply to
    /// [`ClientMsg::GroupHistoryConfig`]). `from` is the member who set it.
    GroupHistoryConfig {
        group: GroupId,
        from: String,
        message: Sealed,
    },
    /// A page of a group's stored history: `(seq, epoch, sealed)` oldest first
    /// (reply to [`ClientMsg::GroupHistoryFetch`]).
    GroupHistory {
        group: GroupId,
        messages: Vec<(u64, u64, Sealed)>,
        has_more: bool,
    },
    /// The current occupants of a voice channel (handles), broadcast to the
    /// channel's members whenever someone joins or leaves.
    VoicePresence {
        workspace: WorkspaceId,
        channel: ChannelId,
        members: Vec<String>,
    },
    /// A freshly minted invite code (reply to [`ClientMsg::CreateInvite`]), for
    /// the creator to copy and share.
    InviteCreated {
        workspace: WorkspaceId,
        code: String,
    },
    /// Someone redeemed an invite and is asking to join. Delivered to one online
    /// admin, whose client admits them via the normal signed add flow. `requester`
    /// is the redeemer's handle.
    JoinRequest {
        workspace: WorkspaceId,
        requester: String,
    },
    /// An admin moved us to `channel`: our client joins that voice channel (which
    /// leaves the one we were in), so presence updates through the normal path.
    VoiceMoved {
        workspace: WorkspaceId,
        channel: ChannelId,
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
    /// One fragment of a sealed frame too large for a single datagram (video
    /// keyframes). `group`/`sender` let the relay route it like a `Frame`; the
    /// receiver reassembles `count` fragments (by `id`) back into the frame.
    Fragment {
        group: GroupId,
        sender: DeviceId,
        id: u32,
        index: u16,
        count: u16,
        data: Vec<u8>,
    },
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
