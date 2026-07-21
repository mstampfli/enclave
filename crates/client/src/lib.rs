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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::transfer::{FileManifest, FileSink, Reassembler, TransferMeta};
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

/// How long an un-acked reliable message waits before it is retransmitted. On a
/// healthy connection the server acks in well under this, so a retransmit only
/// fires when an ack (or the message) was actually lost -- or when a transient
/// server-queue-full is clearing. Reconnect resends immediately, independent of
/// this timer.
const RETRANSMIT_AFTER: Duration = Duration::from_secs(5);

/// Transfer ids remembered for receiver-side dedup, so a fully-resent message
/// (whose earlier delivery's ack was lost) is not shown twice. A window rather
/// than forever: retransmits happen within seconds, so a few thousand recent
/// ids covers it without unbounded growth.
const MAX_SEEN_IDS: usize = 4096;

/// How long a message may go un-acked (retransmitting) before the client warns
/// the user it is not getting through. Well past a normal reconnect, so a brief
/// blip is silent, but a genuinely stuck connection surfaces rather than
/// retransmitting invisibly forever.
const UNDELIVERED_WARN_AFTER: Duration = Duration::from_secs(30);

/// Un-acked reliable messages tolerated before the client warns that delivery is
/// backing up (a stuck or absent server). They are still kept and retried, never
/// dropped; this just bounds how far the backlog grows silently.
const MAX_UNACKED_BEFORE_WARN: usize = 256;

/// Minimum spacing between self-update rekeys used to heal a desynced
/// conversation (see [`Client::heal_group`]). A burst of undecryptable messages
/// triggers at most one rekey per window, which is ample for the peer to apply
/// the commit and the epoch to advance before we would consider another.
const HEAL_COOLDOWN: Duration = Duration::from_secs(15);

/// Whether an MLS decrypt error is the sender-ratchet "too far in the future"
/// desync -- the one healing a conversation can fix (as opposed to tampering, a
/// stray frame, or a mid-join skew, which a rekey would not help). Matched on the
/// openmls message text, the only signal the wrapped error exposes.
fn is_ratchet_desync(err: &enclave_crypto::CryptoError) -> bool {
    err.to_string().contains("too far in the future")
}

/// Whether an MLS decrypt error is a group-id MISMATCH -- the two peers of a DM
/// ended up on different MLS groups for the same conversation (a fork). Healed by
/// the smaller handle re-establishing the peer into its canonical group.
fn is_group_fork(err: &enclave_crypto::CryptoError) -> bool {
    err.to_string().contains("group ID differs")
}

/// Minimum spacing between DM re-establishments used to heal a forked DM, so a
/// burst of undecryptable messages triggers at most one re-invite per window.
const REINVITE_COOLDOWN: Duration = Duration::from_secs(15);

/// Why a screen share ended on its own (see [`Client::reap_ended_share`]):
/// `Cancelled` is the user changing their mind at the system picker, `Failed`
/// is a real error worth showing loudly.
pub use enclave_media::EndedReason as ShareEnded;
pub use transfer::{AvatarRef, Profile, Reaction};

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
    #[error("profile: {0}")]
    Profile(String),
    #[error("workspace: {0}")]
    Workspace(String),
}

/// One channel message in local history (the decrypted, authenticated form).
#[derive(Clone)]
struct ChannelMsg {
    id: [u8; 16],
    /// Sender handle (MLS-authenticated by the WG).
    user: String,
    text: String,
    ts: u64,
    mine: bool,
}

/// A channel message as the UI reads it (hex ids, resolved fields).
#[derive(Clone, Debug)]
pub struct ChannelLine {
    pub id: String,
    pub user: String,
    pub text: String,
    pub ts: u64,
    pub mine: bool,
}

/// The sealed plaintext of a channel post, carried *inside* the WG ciphertext so
/// the relay never sees which channel or what was said. The sender is
/// MLS-authenticated by the WG, so it is not repeated here.
#[derive(serde::Serialize, serde::Deserialize)]
struct ChannelWire {
    channel: [u8; 16],
    id: [u8; 16],
    text: String,
    ts: u64,
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
    /// A text message arrived in conversation `conv` (hex group id). `from` is
    /// the sender's current display name (for notifications); `user` is their
    /// stable username, so the UI resolves the name/avatar from it at render.
    Message {
        conv: String,
        /// Hex message id shared with the peer (reply/forward/delete/details).
        id: String,
        /// Creation time, unix milliseconds.
        ts: u64,
        /// Hex id of the message this replies to, or empty.
        reply_to: String,
        from: String,
        user: String,
        text: String,
        mine: bool,
    },
    /// A file finished arriving in conversation `conv`, from `from` (display
    /// name) / `user` (username), and was written to `file.path`.
    File {
        conv: String,
        /// Hex offer id (the file's message id) and creation time.
        id: String,
        ts: u64,
        from: String,
        user: String,
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
    /// An offer we were shown resolved into a delivered file (or a transfer we
    /// completed): the UI removes the pending prompt, the file itself now shows
    /// in chat. Only for a clean resolution -- never for a withdrawal.
    FileOfferClosed {
        conv: String,
        offer_id: String,
    },
    /// An offer we were shown is no longer available: the sender withdrew it or
    /// went offline. The UI marks the offer's message "no longer available" but
    /// KEEPS it in chat (name, size, the whole file row) -- nothing is removed.
    FileOfferUnavailable {
        conv: String,
        offer_id: String,
    },
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
    Presence {
        user: String,
        status: String,
    },
    /// Someone sent us a friend request (their full handle).
    FriendRequest {
        from: String,
    },
    /// The friends list or pending requests changed; read them via the getters.
    FriendsChanged,
    /// An incoming call started in conversation `conv`, initiated by `from`
    /// (display name). The UI rings.
    CallOffer {
        conv: String,
        from: String,
    },
    /// The participant list of conversation `conv`'s call changed (usernames;
    /// the UI resolves display names). Empty means the call ended.
    CallParticipants {
        conv: String,
        participants: Vec<String>,
    },
    /// `from` (display name) declined our call in conversation `conv`.
    CallDeclined {
        conv: String,
        from: String,
    },
    /// An H.264 video frame from `from` (username; the UI resolves the name and
    /// keys the per-user canvas by it) to show in the UI. `data` is the Annex-B
    /// bytes; the UI decodes it with WebCodecs. `camera` routes it: a per-user
    /// webcam tile (`true`) or the full-screen share viewer (`false`).
    ScreenFrame {
        from: String,
        data: Vec<u8>,
        keyframe: bool,
        camera: bool,
    },
    /// A user's end-to-end profile (display name, status, accent, avatar)
    /// changed or first arrived; the UI re-reads it via `profile_of`. `user` is
    /// the username. Also fires when a requested avatar blob finishes decrypting,
    /// so the tile can swap initials for the picture.
    ProfileChanged {
        user: String,
    },
    /// A neutral status line shown INSIDE conversation `conv` (hex id) rather
    /// than as a popup: e.g. a file was declined or delivered. It is not stored
    /// in history; it is a transient in-chat note.
    Notice {
        conv: String,
        text: String,
    },
    /// A message was deleted (by us, or by its author for everyone): the UI marks
    /// the line as a "message deleted" placeholder, never removing it.
    MessageDeleted {
        conv: String,
        id: String,
    },
    /// A message's emoji reactions changed (someone reacted or un-reacted). The
    /// UI replaces that message's reaction chips with `reactions`.
    ReactionsChanged {
        conv: String,
        id: String,
        reactions: Vec<transfer::Reaction>,
    },
    /// A message was edited by its author: the UI replaces the line's text and
    /// shows an "edited" marker.
    MessageEdited {
        conv: String,
        id: String,
        text: String,
    },
    /// A poll was posted (by a peer, or by us): the UI adds a poll card line.
    PollPosted {
        conv: String,
        id: String,
        ts: u64,
        from: String,
        user: String,
        mine: bool,
        poll: PollView,
    },
    /// A poll's state changed (a vote landed, or it was closed): the UI refreshes
    /// that poll card in place.
    PollUpdated {
        conv: String,
        id: String,
        poll: PollView,
    },
    /// A message was pinned or unpinned (by anyone): the UI updates its indicator
    /// and the conversation's pinned bar.
    PinsChanged {
        conv: String,
        id: String,
        pinned: bool,
    },
    /// The peer changed the disappearing-messages setting for `conv` (ms, 0=off).
    /// The UI reflects it; the local sweep enforces it.
    DisappearingChanged {
        conv: String,
        ms: u32,
    },
    /// A voice message arrived (or we sent one): the UI shows a small player.
    /// `path` is the local clip (played via `play_voice`), `duration_ms` its length.
    VoiceMessage {
        conv: String,
        id: String,
        ts: u64,
        from: String,
        user: String,
        path: String,
        duration_ms: u32,
        waveform: Vec<u8>,
        mine: bool,
    },
    /// A non-fatal error worth showing.
    /// A workspace we belong to changed: created/joined, or its op-log advanced
    /// (membership, roles, categories, or channels). The UI re-reads workspace
    /// state from the client.
    WorkspacesChanged,
    /// A message arrived (or was sent by us) in a workspace channel.
    ChannelMessage {
        workspace: String,
        channel: String,
        /// Stable message id.
        id: String,
        /// Sender handle (MLS-authenticated); empty for our own echo.
        user: String,
        text: String,
        ts: u64,
        mine: bool,
    },
    Error(String),
}

/// Whether a conversation is a 1:1 DM or a named group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConvKind {
    Dm,
    Group,
}

/// Where a conversation sits in its lifecycle. History is retained in every
/// state (encrypted at rest); the difference is visibility and membership. The
/// MLS group (and thus routing/membership) is kept in every state EXCEPT `Left`.
///
/// - `Active`: shown in the Chats list, live in its MLS group.
/// - `Archived`: hidden from the Chats list, shown on the Archived page. Still a
///   member, still receiving; opening it (or a new message) returns it to Active.
/// - `Deleted`: hidden everywhere (it "disappears"), but still a member so it
///   reappears in Active the moment a message arrives, or when reopened (a DM by
///   clicking the person, a group from "groups you share" on a friend). Because
///   the group is kept, reopening reuses it (no fork) and the history is intact.
/// - `Left`: truly left the group (or was removed): the MLS group is torn down
///   and we are no longer a member. Read-only on the Archived page; rejoining is
///   only possible if a member re-invites us (a fresh Welcome restores it).
#[derive(Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Visibility {
    #[default]
    Active,
    Archived,
    Deleted,
    Left,
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
    /// Hidden to the Archived page (still a member). Not in the live Chats list.
    pub archived: bool,
    /// We left or were removed from this group: read-only, on the Archived page.
    pub left: bool,
    /// Whether we can send here. `false` only for `left` (read-only); a DM whose
    /// peer unfriended us is still sendable -- sending reconnects (see `reconnect`).
    pub can_send: bool,
    /// A DM whose peer is no longer a friend: still sendable, but sending it
    /// re-adds them (sends a reconnect request). The composer shows a hint.
    pub reconnect: bool,
    /// The local-only "Notes to self" scratchpad: just us, nothing leaves the
    /// device. The UI renders it distinctly and hides call/verify/members.
    pub self_notes: bool,
}

/// One line of a conversation's history, as handed to the UI.
pub struct HistoryLine {
    /// Hex message id, shared with the peer (for reply/forward/delete/details).
    pub id: String,
    /// Creation time, unix milliseconds.
    pub ts: u64,
    /// Sender username (stable identity) and its current display name.
    pub user: String,
    pub display: String,
    pub text: String,
    pub mine: bool,
    pub file: Option<FileRef>,
    pub system: bool,
    pub deleted: bool,
    /// Hex id of the message this replies to, or empty.
    pub reply_to: String,
    /// Voice-message duration in ms, or 0 if this line is not a voice message.
    pub voice_ms: u32,
    /// Amplitude envelope for a voice message's waveform (empty otherwise).
    pub waveform: Vec<u8>,
    /// Emoji reactions on this line (empty if none).
    pub reactions: Vec<transfer::Reaction>,
    /// Whether this message was edited after being sent (shows an "edited" mark).
    pub edited: bool,
    /// Present when this line is a poll: its question, options, tallies, and my
    /// vote. The UI renders a poll card instead of a text bubble.
    pub poll: Option<PollView>,
    /// Whether this message is pinned in the conversation.
    pub pinned: bool,
}

/// A stored poll: a conversation annotation keyed by the poll's message id. Votes
/// map each member's username to its chosen option indices (last write wins).
#[derive(Clone)]
struct Poll {
    question: String,
    options: Vec<String>,
    multi: bool,
    /// 0 = tallies always shown, 1 = after you vote, 2 = after the creator closes.
    reveal: u8,
    closed: bool,
    /// Absolute deadline (unix ms); once past, the poll counts as closed. `None`
    /// means no time limit. Shared, so every member auto-closes at the same moment.
    closes_at: Option<u64>,
    /// Creator username (only they may close the poll).
    author: String,
    votes: HashMap<String, Vec<u8>>,
    /// Content key for server-buffered ballots (reveal >= 2); `None` for immediate
    /// polls. All members hold it (it rides in the MLS-sealed poll); the server
    /// does not, so buffered ballots stay unreadable to it.
    ballot_key: Option<[u8; 32]>,
    /// Anonymous poll: ballots are ring-signed and tallied by key image, so no one
    /// (server, owner, peers) can attribute a vote.
    anonymous: bool,
    /// The ring (members' voting public keys) for an anonymous poll.
    ring: Vec<[u8; 32]>,
    /// For an anonymous poll, the pseudonym (key image) our OWN ballot is filed
    /// under. Votes are keyed by key image rather than username there, so without
    /// this we could not find our own vote to show back to us. It names only
    /// ourselves, to ourselves, and is unlinkable to an identity by anyone else.
    my_tag: Option<String>,
}

impl Poll {
    /// The server-side routing mode for a buffered poll, or `None` for an immediate
    /// (reveal 0/1) poll that votes over normal MLS. 0 = release to the group at
    /// close, 1 = route to the owner live, 2 = buffer and release to the owner,
    /// 3 = release to the group but with submitter attribution stripped (anonymous).
    /// Who the server releases this poll's ballots to, and when. Anonymity is NOT
    /// encoded here: it rides its own flag on `BallotOpen`, so "who sees the
    /// ballots" and "are they attributed" stay independent.
    fn server_mode(&self) -> Option<u8> {
        match self.reveal {
            2 => Some(0), // the whole group, once it closes
            3 => Some(1), // the owner, as ballots arrive
            4 => Some(2), // the owner, once it closes
            _ => None,
        }
    }
}

impl Poll {
    /// Whether the poll is closed right now -- explicitly, or because its deadline
    /// has passed.
    fn is_closed(&self) -> bool {
        self.closed || self.closes_at.is_some_and(|t| now_ms() >= t)
    }
}

impl From<session::PersistPoll> for Poll {
    fn from(p: session::PersistPoll) -> Poll {
        Poll {
            question: p.question,
            options: p.options,
            multi: p.multi,
            reveal: p.reveal,
            closed: p.closed,
            closes_at: p.closes_at,
            author: p.author,
            votes: p.votes.into_iter().collect(),
            ballot_key: p.ballot_key,
            anonymous: p.anonymous,
            ring: p.ring,
            my_tag: p.my_tag,
        }
    }
}

impl From<&Poll> for session::PersistPoll {
    fn from(p: &Poll) -> session::PersistPoll {
        session::PersistPoll {
            question: p.question.clone(),
            options: p.options.clone(),
            multi: p.multi,
            reveal: p.reveal,
            closed: p.closed,
            closes_at: p.closes_at,
            author: p.author.clone(),
            votes: p
                .votes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            ballot_key: p.ballot_key,
            anonymous: p.anonymous,
            ring: p.ring.clone(),
            my_tag: p.my_tag.clone(),
        }
    }
}

/// A poll as handed to the UI: its definition plus the current tallies, my own
/// selection, and whether the tallies should be revealed yet.
#[derive(Debug, Clone)]
pub struct PollView {
    pub question: String,
    pub options: Vec<String>,
    /// Votes per option (index-aligned with `options`).
    pub counts: Vec<u32>,
    pub multi: bool,
    pub reveal: u8,
    pub closed: bool,
    /// My selected option indices.
    pub mine: Vec<u8>,
    /// Number of distinct voters.
    pub total: u32,
    /// Whether the UI should reveal the tallies now, per the reveal mode.
    pub revealed: bool,
    /// Whether we created the poll (so we may close it).
    pub is_author: bool,
    /// Absolute deadline (unix ms), or 0 for no time limit. The UI shows a live
    /// countdown and treats the poll as closed once it passes.
    pub closes_at: u64,
    /// Voters for each option (index-aligned with `options`). For a normal poll
    /// these are usernames; for an anonymous poll they are opaque pseudonyms (key
    /// image hex) the UI renders as "Anonymous". Always present; shown only once
    /// results are revealed.
    pub voters: Vec<Vec<String>>,
    /// An anonymous poll (ring-signed ballots; voters unattributable).
    pub anonymous: bool,
}

/// One hit from a local message search, with enough context to render a result
/// row and jump to the message.
pub struct SearchHit {
    /// Hex id of the conversation the match is in, and its resolved title.
    pub conv: String,
    pub conv_title: String,
    /// Whether the containing conversation is the local-only "Notes to self".
    pub self_notes: bool,
    /// Hex id + timestamp of the matching message.
    pub id: String,
    pub ts: u64,
    /// Sender username (stable) and current display name.
    pub user: String,
    pub display: String,
    /// The matching line's text (for a file line, its name).
    pub text: String,
    pub mine: bool,
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
    /// If set, disappearing messages is on for this conversation: each line is
    /// removed locally once `now - ts` exceeds this many ms. The setting is shared
    /// with the peer; the per-message deletion is local (no read-state leaves).
    disappearing_ms: Option<u32>,
    /// Where this conversation sits in its lifecycle (list visibility + group
    /// membership). See [`Visibility`]. Defaults to `Active`.
    visibility: Visibility,
    /// A private on-device scratchpad ("Notes to self"): it has no MLS group and
    /// exactly one member (us), and NOTHING it holds ever reaches the network.
    /// Every send path checks this and records locally instead of sealing to the
    /// server, and the routing announces on login/reload skip it. History is still
    /// encrypted at rest with the rest of the session, so it is private but local.
    local_only: bool,
    /// Emoji reactions on this conversation's messages, keyed by message id. An
    /// annotation overlay (not part of a line's content) so a reaction can be
    /// added or removed after the message was sent. Persisted with the history.
    reactions: HashMap<[u8; 16], Vec<transfer::Reaction>>,
    /// Ids of messages that have been edited, so the UI can show an "edited"
    /// marker. The edited text itself lives in the line; this only flags it.
    edited: HashSet<[u8; 16]>,
    /// Polls in this conversation, keyed by the poll's message id. The line for a
    /// poll is a normal history entry; this holds its options, votes, and state.
    polls: HashMap<[u8; 16], Poll>,
    /// Ids of messages pinned in this conversation. Pins are shared: any member
    /// may pin or unpin, and every member sees the same set.
    pinned: HashSet<[u8; 16]>,
}

#[derive(Clone)]
struct ChatLine {
    /// Stable id both peers share: the message's transfer id (or a file's offer
    /// id). Lets the UI reply to / forward / delete / show details for the line.
    id: [u8; 16],
    /// When this line was created locally (unix milliseconds), for the timestamp.
    ts: u64,
    from: String,
    /// For a text message, the text. For a file, a human label (the filename).
    /// For a system line, the notice text ("X declined foo").
    text: String,
    mine: bool,
    /// Present when this line is a file rather than plain text.
    file: Option<FileRef>,
    /// A system notice (e.g. "X declined foo") rather than a person's message:
    /// rendered as a small centered line, and persisted so it stays in the chat
    /// for good rather than vanishing on the next reload.
    system: bool,
    /// Set once this message has been deleted: the row stays but shows a
    /// "message deleted" placeholder instead of its content. `deleted` for
    /// everyone (a peer withdrew it) reads the same as deleted just for me.
    deleted: bool,
    /// The id of the message this one replies to, if any. The quoted preview is
    /// resolved from the local copy of that message at render, never re-sent.
    reply_to: Option<[u8; 16]>,
    /// Set (to the duration in ms) when this line is a voice message; `file` then
    /// holds the local path to the decoded-on-demand clip. The UI shows a player.
    voice_ms: Option<u32>,
    /// Amplitude envelope for a voice message's waveform (empty otherwise).
    waveform: Vec<u8>,
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
    /// Per-file content key: every chunk is sealed under it (kept so a re-stream,
    /// e.g. a second recipient accepting a live offer, reuses the same key the
    /// manifest advertised).
    content_key: [u8; 32],
    /// Set once we have begun sending chunks, so a second trigger (e.g. a second
    /// recipient accepting a live offer) does not restart the stream.
    started: bool,
}

/// A reliable message awaiting the server's ack. `first` is when it was first
/// sent (the stall clock, for warning the user), `last` when it was last (re)sent
/// (the retry clock). Both survive a restart as "now" on reload.
struct Pending {
    msg: ClientMsg,
    first: Instant,
    last: Instant,
}

/// An upload in progress: the open file and our position in it. The pump seals
/// and sends one chunk at a time only while the connection's bounded file queue
/// has room, so a large (or live, arbitrary-size) file is streamed from disk and
/// paced by the socket -- never sealed or buffered whole in memory.
struct Upload {
    offer_id: [u8; 16],
    group: GroupId,
    file: std::fs::File,
    /// Display name, for progress.
    name: String,
    /// The per-file content key each chunk is sealed under.
    content_key: [u8; 32],
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
    /// The per-file content key from the sealed manifest: every chunk is opened
    /// with it (see `crypto::open_chunk`), so bulk bytes never touch the ratchet.
    content_key: [u8; 32],
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
    /// Workspaces we belong to, keyed by id, as the replayed op-log state -- the
    /// authoritative structure/membership we verify locally (never trusting the
    /// relay's copy). See `enclave_crypto::workspace`.
    workspaces: HashMap<[u8; 16], enclave_crypto::workspace::WorkspaceState>,
    /// Per-workspace WG MLS group -- the shared key schedule that seals public
    /// channel messages. Membership tracks the workspace's (public) membership.
    workspace_groups: HashMap<[u8; 16], Group>,
    /// Channel message history, keyed by `(workspace, channel)`.
    channel_history: HashMap<([u8; 16], [u8; 16]), Vec<ChannelMsg>>,
    /// Handles that removed US (they initiated the un-friend). Only these auto-
    /// reconnect when they re-add us; a person WE removed does not. Cleared once
    /// we are friends again. Persisted so the direction survives a restart.
    removed_me: std::collections::BTreeSet<String>,
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
    /// Reliable-delivery state. `next_seq` labels each reliable message;
    /// `unacked` holds the ones the server has not yet acknowledged (with the
    /// time they were last sent), retransmitted on reconnect and on a timer until
    /// acked, so a dropped connection or a transient server-full never loses a
    /// message. `seen` dedups a fully-resent message on the receive side.
    /// `delivery_warned` tracks whether we have already told the user delivery is
    /// stuck, so the warning fires on the transition, not every tick.
    next_seq: u64,
    unacked: BTreeMap<u64, Pending>,
    seen: transfer::SeenSet,
    delivery_warned: bool,
    /// Files offered to us, awaiting/undergoing consented download (see
    /// [`IncomingFile`]). An entry exists from the offer until it resolves.
    incoming_files: HashMap<[u8; 16], IncomingFile>,
    /// Our own end-to-end profile: display name, status, accent, bio, avatar
    /// reference. Sealed and broadcast to the groups we share; the server never
    /// sees it. Persisted in the session.
    my_profile: transfer::Profile,
    /// Seed for our ring-signature voting keypair (anonymous polls). Stable per
    /// account (persisted); our voting public key rides in `my_profile`.
    /// Cached profiles of people we share a group with, keyed by username.
    /// Persisted, so names and avatars render immediately on restart.
    profiles: HashMap<String, transfer::Profile>,
    /// Avatar decryption keys for blobs we have requested but not yet received
    /// (content address -> one-time key from the sealed profile), so a
    /// [`ServerMsg::Avatar`] reply can be authenticated and opened.
    pending_avatars: HashMap<[u8; 32], [u8; 32]>,
    /// When we last committed a self-update to heal a desynced conversation, per
    /// group. Debounces the heal so a burst of undecryptable messages triggers at
    /// most one rekey per cooldown (see [`Client::heal_group`]).
    last_heal: HashMap<GroupId, Instant>,
    /// An in-progress voice-message recording, if any (mic capture + the target
    /// conversation). Present only between `start_voice` and `stop_voice`/
    /// `cancel_voice`.
    voice_rec: Option<VoiceRec>,
    /// A stopped-but-not-yet-sent voice message, held so the user can preview it
    /// before sending (see `stop_voice` / `send_voice` / `cancel_voice`).
    voice_pending: Option<PendingVoice>,
    /// A persistent speaker stream for playing voice messages, created on first
    /// play and reused (a stable stream lifecycle, unlike a per-play detached one).
    voice_playback: Option<enclave_media::AudioPlayback>,
    /// DMs found to be forked (peer on a different MLS group), awaiting the
    /// smaller handle to re-establish the peer. Drained by `pump_reinvites`.
    pending_reinvites: HashSet<GroupId>,
    /// When we last re-established each forked DM, to debounce (see REINVITE_COOLDOWN).
    last_reinvite: HashMap<GroupId, Instant>,
}

/// A recorded-and-encoded voice message waiting for the user to send or discard.
struct PendingVoice {
    bytes: Vec<u8>,
    duration_ms: u32,
    waveform: Vec<u8>,
    group: GroupId,
}

/// A voice message being recorded: the live mic capture (kept alive so the stream
/// keeps running), the frame channel it feeds, when it began, and which
/// conversation it is for.
struct VoiceRec {
    _capture: enclave_media::AudioCapture,
    rx: std::sync::mpsc::Receiver<Vec<i16>>,
    group: GroupId,
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
            workspaces: HashMap::new(),
            workspace_groups: HashMap::new(),
            channel_history: HashMap::new(),
            active: None,
            pending: VecDeque::new(),
            export_key: Vec::new(),
            display: String::new(),
            friends: Vec::new(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            removed_me: std::collections::BTreeSet::new(),
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
            next_seq: 0,
            unacked: BTreeMap::new(),
            seen: transfer::SeenSet::new(MAX_SEEN_IDS),
            delivery_warned: false,
            my_profile: transfer::Profile::default(),
            profiles: HashMap::new(),
            last_heal: HashMap::new(),
            voice_rec: None,
            voice_pending: None,
            voice_playback: None,
            pending_reinvites: HashSet::new(),
            last_reinvite: HashMap::new(),
            pending_avatars: HashMap::new(),
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
        self.login(&handle, &password).await?;
        // Replay everything the server had not acked before the drop, so no
        // reliable message is lost across a reconnect (the receiver dedups any
        // that actually got through).
        self.resend_unacked();
        Ok(())
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
            // The display name is end-to-end now: the server gets an empty one
            // (it defaults to the username) and never learns the chosen name.
            display: String::new(),
        });
        let server_display = self.await_auth().await?;
        self.finish_login(identity, &handle, server_display);
        self.export_key = export_key;
        self.password = Zeroizing::new(password.to_string());
        // Record the chosen display name in the end-to-end profile; it will be
        // sealed and broadcast once the user shares a group.
        if !display.trim().is_empty() {
            self.display = display.to_string();
            self.my_profile.display_name = display.to_string();
        }
        self.save_session();
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
        self.workspaces.clear();
        self.workspace_groups.clear();
        self.channel_history.clear();
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
        self.unacked.clear();
        self.seen.clear();
        self.my_profile = transfer::Profile::default();
        self.profiles.clear();
        self.pending_avatars.clear();
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
        // Discover the workspaces we belong to; the reply drives a full-log fetch
        // for any we do not already hold (a fresh login or new device).
        self.conn.send(ClientMsg::WorkspaceListMine);
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

    /// This device's long-term identity public key -- what a workspace owner
    /// records when adding us so our future ops verify, and what a peer pins.
    pub fn identity_key(&self) -> Option<Vec<u8>> {
        self.identity.as_ref().map(|i| i.identity_key())
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

    /// The display name for a username, preferring the end-to-end profile the
    /// user set (server-blind), then the legacy server-distributed name, then the
    /// username itself. Our own name comes from our own profile.
    pub fn display_of(&self, username: &str) -> String {
        let from_profile = if Some(username) == self.username.as_deref() {
            (!self.my_profile.display_name.is_empty()).then(|| self.my_profile.display_name.clone())
        } else {
            self.profiles
                .get(username)
                .map(|p| p.display_name.clone())
                .filter(|d| !d.is_empty())
        };
        from_profile
            .or_else(|| self.display_names.get(username).cloned())
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

    /// People who removed us and have not been reconnected: they auto-reconnect
    /// if they re-add us, and their DM stays readable. Sourced from `removed_me`
    /// (the recorded removal direction), so a person we removed is not listed.
    pub fn past_contacts(&self) -> Vec<Friend> {
        self.removed_me
            .iter()
            .filter(|h| !self.is_friend(h))
            .map(|h| Friend {
                username: h.clone(),
                display: self.display_of(h),
                since: None,
                member_since: None,
            })
            .collect()
    }

    /// Whether `handle` is currently an accepted friend.
    fn is_friend(&self, handle: &str) -> bool {
        self.friends.iter().any(|f| f.username == handle)
    }

    /// If `group_id` is a DM whose peer is no longer a friend, send them a
    /// reconnect (friend) request. Called when messaging into such a DM so that
    /// texting a removed person re-adds them.
    fn reconnect_dm_peer_if_needed(&mut self, group_id: &GroupId) {
        let me = self.username.clone().unwrap_or_default();
        let peer = self.conversations.get(group_id).and_then(|c| {
            (c.kind == ConvKind::Dm)
                .then(|| c.members.iter().find(|m| **m != me).cloned())
                .flatten()
        });
        if let Some(peer) = peer {
            if !self.is_friend(&peer) {
                self.send_friend_request(&peer);
            }
        }
    }

    /// Groups we currently share with `friend` (both members), across every
    /// visibility EXCEPT Left (we can't restore a group we exited). Includes
    /// Deleted ones, so a friend's profile can list them and clicking restores.
    /// Returns (hex id, title) pairs.
    pub fn shared_groups(&self, friend: &str) -> Vec<(String, String)> {
        self.conversations
            .iter()
            .filter(|(_, c)| {
                c.kind == ConvKind::Group
                    && c.visibility != Visibility::Left
                    && c.members.iter().any(|m| m == friend)
            })
            .map(|(id, c)| (hex_id(id), c.title.clone()))
            .collect()
    }

    /// Change our display name. Unlike the legacy server-visible name, this now
    /// lives in the end-to-end profile: it is sealed and broadcast to the groups
    /// we share, so the server never learns it.
    pub fn set_display_name(&mut self, display: &str) {
        self.display = display.to_string();
        self.my_profile.display_name = display.to_string();
        self.commit_profile();
    }

    /// Our own current profile, for the editor and self-card.
    pub fn my_profile(&self) -> &transfer::Profile {
        &self.my_profile
    }

    /// A peer's cached profile, if we have received one (we share a group).
    pub fn profile_of(&self, username: &str) -> Option<&transfer::Profile> {
        self.profiles.get(username)
    }

    /// Every profile we know: our own plus each cached peer, for the UI to seed
    /// its render map on login.
    pub fn all_profiles(&self) -> Vec<(String, transfer::Profile)> {
        let mut out: Vec<(String, transfer::Profile)> = self
            .profiles
            .iter()
            .map(|(u, p)| (u.clone(), p.clone()))
            .collect();
        if let Some(me) = &self.username {
            out.push((me.clone(), self.my_profile.clone()));
        }
        out
    }

    /// Set the custom status (emoji + free text) at once; sealed + broadcast.
    /// Distinct from `set_status`, which sets the coarse server-visible presence.
    pub fn set_custom_status(&mut self, emoji: &str, text: &str) {
        self.my_profile.status_emoji = emoji.to_string();
        self.my_profile.status_text = text.to_string();
        self.commit_profile();
    }

    /// Set the personal accent color ("#rrggbb", or "" for the app default).
    pub fn set_accent(&mut self, accent: &str) {
        self.my_profile.accent = accent.to_string();
        self.commit_profile();
    }

    /// Set the short bio / about line.
    pub fn set_bio(&mut self, bio: &str) {
        self.my_profile.bio = bio.to_string();
        self.commit_profile();
    }

    /// Replace our avatar with `image` (already downscaled + re-encoded by the
    /// UI). The image is encrypted under a fresh key, uploaded to the server as
    /// an opaque content-addressed blob, cached locally so we can show it too,
    /// and referenced (address + key) in the sealed profile we then broadcast.
    /// Rejects an oversized image so a caller can surface a clear error.
    pub fn set_avatar(&mut self, image: &[u8], mime: &str) -> Result<(), ClientError> {
        let sealed = enclave_crypto::seal_blob(image)?;
        if sealed.ciphertext.len() > transfer::MAX_AVATAR_BYTES {
            return Err(ClientError::Profile(
                "avatar image is too large; pick a smaller one".into(),
            ));
        }
        // Cache the plaintext locally (content-addressed) so our own tile shows
        // it without a round-trip, and upload the ciphertext to the server.
        self.cache_avatar(&sealed.addr, image);
        self.send_reliable(ClientMsg::PutAvatar {
            addr: sealed.addr,
            data: sealed.ciphertext.clone(),
        });
        self.my_profile.avatar = Some(transfer::AvatarRef {
            addr: sealed.addr,
            key: sealed.key,
            mime: mime.to_string(),
            size: sealed.ciphertext.len() as u32,
        });
        self.commit_profile();
        Ok(())
    }

    /// Remove our avatar (back to initials); sealed + broadcast.
    pub fn clear_avatar(&mut self) {
        self.my_profile.avatar = None;
        self.commit_profile();
    }

    /// Bump the profile version, persist, and broadcast the new profile to every
    /// group we share. The monotonic version lets receivers apply last-writer-
    /// wins and ignore a reordered or duplicated update.
    fn commit_profile(&mut self) {
        self.my_profile.version = self.my_profile.version.saturating_add(1);
        self.save_session();
        self.broadcast_profile();
    }

    /// Seal our current profile and send it into every established group. Cheap
    /// (a few hundred bytes each): the avatar image is not inline, only its
    /// content address + key. A pending DM (no group yet) is skipped; it gets our
    /// profile when the group is established.
    fn broadcast_profile(&mut self) {
        if self.username.is_none() {
            return;
        }
        let payload = self.my_profile.encode();
        let groups: Vec<GroupId> = self
            .conversations
            .iter()
            .filter(|(_, c)| c.group.is_some())
            .map(|(id, _)| id.clone())
            .collect();
        for group in groups {
            let _ = self.send_transfer(&group, TransferMeta::Profile, &payload);
        }
    }

    /// Send our current profile into one specific group (used when a group is
    /// established or a member joins, so the new co-member gets it promptly).
    fn send_profile_to(&mut self, group: &GroupId) {
        if self.username.is_none() {
            return;
        }
        let payload = self.my_profile.encode();
        let _ = self.send_transfer(group, TransferMeta::Profile, &payload);
    }

    /// The local content-addressed cache of decrypted avatar images. A file is
    /// named by its hex address and is immutable (a new avatar gets a new
    /// address), so a cached entry is never stale and never needs invalidation.
    fn avatar_dir(&self) -> PathBuf {
        self.keystore_dir.join("avatars")
    }

    fn avatar_path(&self, addr: &[u8; 32]) -> PathBuf {
        self.avatar_dir().join(hex::encode(addr))
    }

    /// Whether the decrypted avatar for `addr` is already cached locally.
    pub fn have_avatar(&self, addr: &[u8; 32]) -> bool {
        self.avatar_path(addr).exists()
    }

    /// The local path of a cached avatar image, for the UI's `enclave://` handler.
    pub fn avatar_file(&self, addr: &[u8; 32]) -> Option<PathBuf> {
        let p = self.avatar_path(addr);
        p.exists().then_some(p)
    }

    /// Write a decrypted avatar image into the content-addressed cache.
    fn cache_avatar(&self, addr: &[u8; 32], image: &[u8]) {
        let _ = std::fs::create_dir_all(self.avatar_dir());
        let _ = std::fs::write(self.avatar_path(addr), image);
    }

    /// Apply a peer's sealed profile update. It is attributed to `username` --
    /// the authenticated MLS sender -- never to any field inside the payload, so
    /// a peer can only ever set its own profile. Applies last-writer-wins by
    /// version, caches + persists, and fetches the avatar blob if it is new.
    fn on_profile_update(&mut self, username: &str, data: &[u8]) -> Option<Event> {
        let mut profile = transfer::Profile::decode(data)?;
        // DoS guard: drop an avatar reference claiming to exceed the cap so its
        // blob is never fetched -- a peer cannot make us download a huge image.
        if profile
            .avatar
            .as_ref()
            .is_some_and(|a| a.size as usize > transfer::MAX_AVATAR_BYTES)
        {
            profile.avatar = None;
        }
        // Last-writer-wins: keep only a strictly newer version (or the first
        // one), so a reordered or duplicated broadcast never regresses state.
        if let Some(existing) = self.profiles.get(username) {
            if profile.version <= existing.version {
                return None;
            }
        }
        let avatar = profile.avatar.clone();
        self.profiles.insert(username.to_string(), profile);
        self.save_session();
        // Fetch the avatar blob only if we do not already hold its decrypted
        // image (content-addressed, so an unchanged avatar is a cache hit).
        if let Some(av) = avatar {
            if !self.have_avatar(&av.addr) {
                self.pending_avatars.insert(av.addr, av.key);
                self.conn.send(ClientMsg::FetchAvatar { addr: av.addr });
            }
        }
        Some(Event::ProfileChanged {
            user: username.to_string(),
        })
    }

    /// The username whose cached profile points at avatar `addr` (to re-render
    /// the right tile once the blob decrypts).
    fn user_with_avatar(&self, addr: &[u8; 32]) -> Option<String> {
        self.profiles
            .iter()
            .find(|(_, p)| p.avatar.as_ref().is_some_and(|a| &a.addr == addr))
            .map(|(u, _)| u.clone())
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

    /// Remove an existing friend. WE initiated it, so `handle` is not marked as
    /// "removed us": a later re-add from them is a normal request, not a silent
    /// auto-reconnect. Their DM stays readable in the Inactive section.
    pub fn remove_friend(&mut self, handle: &str) {
        self.removed_me.remove(handle);
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
        // Already established? Just focus it, and bring it back to the Chats list
        // if it was archived (opening it counts as activity).
        if self
            .conversations
            .get(&dm_id)
            .is_some_and(|c| c.group.is_some())
        {
            if self.touch_conversation(&dm_id) {
                self.save_session();
            }
            self.active = Some(dm_id.clone());
            return Ok(hex_id(&dm_id));
        }
        // Drop any stale pending placeholder from an older session before
        // creating, but CARRY FORWARD its history and disappearing setting: a
        // previously deleted DM (visibility Deleted, group None) keeps its sealed
        // scrollback, so re-opening the same peer restores the old conversation.
        let prior = self.conversations.remove(&dm_id);
        let restored_history = prior
            .as_ref()
            .map(|c| c.history.clone())
            .unwrap_or_default();
        let restored_disappearing = prior.as_ref().and_then(|c| c.disappearing_ms);
        // Create the MLS group NOW from the peer's published key package and queue
        // the Welcome (delivered when they next log in) -- a DM never waits for the
        // peer to be online. If BOTH sides open it at once, the two groups converge
        // deterministically on the smaller handle's (see the Welcome handler).
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
                history: restored_history,
                verified: None,
                reassembler: Reassembler::new(),
                disappearing_ms: restored_disappearing,
                visibility: Visibility::Active,
                local_only: false,
                reactions: HashMap::new(),
                edited: HashSet::new(),
                polls: HashMap::new(),
                pinned: HashSet::new(),
            },
        );
        self.invite_peer(&dm_id, friend, "").await?;
        // Hand the peer our profile as soon as the DM exists, so opening a
        // conversation reveals each other's name/avatar right away.
        self.send_profile_to(&dm_id);
        self.save_session();
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
                disappearing_ms: None,
                visibility: Visibility::Active,
                local_only: false,
                reactions: HashMap::new(),
                edited: HashSet::new(),
                polls: HashMap::new(),
                pinned: HashSet::new(),
            },
        );
        for member in members {
            self.invite_peer(&group_id, member, name).await?;
        }
        // Announce our profile to the new group's members.
        self.send_profile_to(&group_id);
        self.save_session();
        self.active = Some(group_id.clone());
        Ok(hex_id(&group_id))
    }

    /// Open (creating on first use) the local-only "Notes to self" scratchpad and
    /// focus it. It is a conversation with exactly one member (us) and NO MLS
    /// group: nothing it holds is ever sealed or sent -- every send path records
    /// locally instead (see the `local_only` guard in `send_text`/`offer_file`/
    /// `send_voice`). Idempotent: there is exactly one per account, keyed by a
    /// stable derived id, so calling this again just re-focuses the same notes.
    pub fn open_self_notes(&mut self) -> Result<String, ClientError> {
        let me = self.me()?;
        let id = derive_self_id(&me);
        // Restore visibility if it was archived/deleted; never touch the network.
        if self.conversations.contains_key(&id) {
            self.touch_conversation(&id);
            self.active = Some(id.clone());
            self.save_session();
            return Ok(hex_id(&id));
        }
        self.conversations.insert(
            id.clone(),
            Conversation {
                group: None,
                mls_group_id: Vec::new(),
                kind: ConvKind::Dm,
                title: "Notes to self".to_string(),
                members: vec![me],
                history: Vec::new(),
                verified: None,
                reassembler: Reassembler::new(),
                disappearing_ms: None,
                visibility: Visibility::Active,
                local_only: true,
                reactions: HashMap::new(),
                edited: HashSet::new(),
                polls: HashMap::new(),
                pinned: HashSet::new(),
            },
        );
        self.active = Some(id.clone());
        self.save_session();
        Ok(hex_id(&id))
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
        // The new member needs our profile too.
        self.send_profile_to(&group_id);
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
        // While fetching the key package we may have ADOPTED the peer's own group
        // (a both-opened-at-once DM the tie-break resolved in their favor). If the
        // peer is already a member, the DM is already established -- do not add
        // them again (which would fail as a duplicate).
        if group.member_keys().iter().any(|(name, _)| name == friend) {
            return Ok(());
        }
        let add = group.add_member(identity, &key_package, friend)?;
        if !conv.members.iter().any(|m| m == friend) {
            conv.members.push(friend.to_string());
        }
        self.send_reliable(ClientMsg::Welcome {
            to: DeviceId(friend.into()),
            group: group_id.clone(),
            name: name.to_string(),
            message: Sealed(add.welcome),
        });
        self.send_reliable(ClientMsg::Mls {
            group: group_id.clone(),
            message: Sealed(add.commit),
        });
        Ok(())
    }

    /// Delete a conversation: it disappears from the Chats list (no Inactive
    /// section) but we stay a member and keep the sealed history, so it reappears
    /// in Active the moment a message arrives, or when reopened -- a DM by
    /// clicking the person, a group from "groups you share" on a friend. The MLS
    /// group is KEPT, so reopening reuses it (no fork). Use `clear_history` to
    /// wipe the messages, or `leave_group` to truly exit a group.
    pub fn delete_conversation(&mut self, conv_hex: &str) {
        let Some(group_id) = self.group_by_hex(conv_hex) else {
            return;
        };
        let left = self
            .conversations
            .get(&group_id)
            .is_some_and(|c| c.visibility == Visibility::Left);
        if left {
            // Already out of the group (no membership to keep): deleting removes it
            // from view entirely.
            self.conversations.remove(&group_id);
        } else if let Some(c) = self.conversations.get_mut(&group_id) {
            // Keep the group + membership so it can reappear; only hide it.
            c.visibility = Visibility::Deleted;
        }
        if self.active.as_ref() == Some(&group_id) {
            self.active = None;
        }
        self.save_session();
    }

    /// Truly leave a group: leave the MLS group (stop receiving) and delete its
    /// provider state so a rejoin can recreate it, while keeping the history
    /// readable on the Archived page. Rejoining is only possible if a member
    /// re-invites us (a fresh Welcome restores it).
    pub fn leave_group(&mut self, conv_hex: &str) {
        let Some(group_id) = self.group_by_hex(conv_hex) else {
            return;
        };
        // "Notes to self" has no group to leave and must never touch the network:
        // there is nothing to leave. (The UI hides the option; this is a backstop.)
        if self.is_local_only(&group_id) {
            return;
        }
        if self.call_group.as_ref() == Some(&group_id) {
            self.leave_call();
        }
        self.conn.send(ClientMsg::LeaveGroup {
            group: group_id.clone(),
        });
        let me = self.username.clone().unwrap_or_default();
        let taken = self.conversations.get_mut(&group_id).and_then(|c| {
            c.visibility = Visibility::Left;
            // We are no longer in the group, so drop ourselves from our own copy of
            // the roster (the server won't send us further membership updates).
            c.members.retain(|m| m != &me);
            c.group.take()
        });
        if let (Some(g), Some(identity)) = (taken, self.identity.as_ref()) {
            let _ = g.delete(identity);
        }
        if self.active.as_ref() == Some(&group_id) {
            self.active = None;
        }
        self.save_session();
    }

    /// Hide a conversation to the Archived page with no data change: it stays a
    /// member and keeps receiving, and returns to Active when opened or on a new
    /// message. A reversible declutter, distinct from delete (which disappears).
    pub fn archive_conversation(&mut self, conv_hex: &str) {
        let Some(group_id) = self.group_by_hex(conv_hex) else {
            return;
        };
        if let Some(c) = self.conversations.get_mut(&group_id) {
            if c.visibility == Visibility::Active {
                c.visibility = Visibility::Archived;
            }
        }
        if self.active.as_ref() == Some(&group_id) {
            self.active = None;
        }
        self.save_session();
    }

    /// Return an Archived or Deleted conversation to the live Chats list without
    /// opening it. A Left group cannot be un-archived (we are no longer a member).
    pub fn unarchive_conversation(&mut self, conv_hex: &str) {
        let Some(group_id) = self.group_by_hex(conv_hex) else {
            return;
        };
        if let Some(c) = self.conversations.get_mut(&group_id) {
            if c.visibility == Visibility::Archived || c.visibility == Visibility::Deleted {
                c.visibility = Visibility::Active;
            }
        }
        self.save_session();
    }

    /// Wipe a conversation's message history, keeping the conversation and its
    /// MLS channel intact. The scrollback is gone locally; nothing is sent to
    /// the peer (their copy is theirs to clear).
    pub fn clear_history(&mut self, conv_hex: &str) {
        let Some(group_id) = self.group_by_hex(conv_hex) else {
            return;
        };
        if let Some(c) = self.conversations.get_mut(&group_id) {
            c.history.clear();
        }
        self.save_session();
    }

    /// Return an Archived or Deleted conversation to Active because it saw
    /// activity (a message sent or received, or it was opened). No-op for Active
    /// or Left conversations (Left has no group and receives nothing). Returns
    /// true if the visibility actually changed, so the caller can re-emit the
    /// conversation list.
    fn touch_conversation(&mut self, group_id: &GroupId) -> bool {
        if let Some(c) = self.conversations.get_mut(group_id) {
            if c.visibility == Visibility::Archived || c.visibility == Visibility::Deleted {
                c.visibility = Visibility::Active;
                return true;
            }
        }
        false
    }

    /// Note that `group` saw new activity (a message received in it). If it was
    /// Archived or Deleted, return it to Active and queue a conversation-list
    /// refresh so it reappears in the Chats list. Called from the incoming-message
    /// path; the send path un-hides via `open_dm`/`switch` when the conversation
    /// is opened to type into it.
    fn note_activity(&mut self, group_id: &GroupId) {
        if self.touch_conversation(group_id) {
            self.pending.push_back(Event::ConversationsChanged);
        }
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
        self.send_reliable(ClientMsg::Mls {
            group: group_id,
            message: Sealed(commit),
        });
        self.save_session();
        Ok(())
    }

    /// Where decoded-on-demand voice clips are cached (one file per message id).
    fn voice_dir(&self) -> PathBuf {
        self.keystore_dir.join("voice")
    }

    /// Begin recording a voice message for the active conversation. Refuses while
    /// in a call (the mic is in use) or with no conversation open. The mic runs
    /// until [`send_voice`](Self::send_voice) or [`cancel_voice`](Self::cancel_voice).
    pub fn start_voice(&mut self) -> Result<(), ClientError> {
        if self.call.is_some() {
            return Err(ClientError::Audio(
                "can't record a voice message during a call".into(),
            ));
        }
        let group = self.active.clone().ok_or(ClientError::NoGroup)?;
        let (capture, rx) =
            enclave_media::AudioCapture::start().map_err(|e| ClientError::Audio(e.to_string()))?;
        self.voice_rec = Some(VoiceRec {
            _capture: capture,
            rx,
            group,
        });
        Ok(())
    }

    /// Discard an in-progress voice recording or a stopped-but-unsent preview.
    pub fn cancel_voice(&mut self) {
        self.voice_rec = None; // dropping the capture stops the mic stream
        self.voice_pending = None;
    }

    /// Stop recording and encode the captured audio, holding it as a PENDING voice
    /// message (not sent). Returns a local path to preview it and the duration, so
    /// the user can listen before choosing to send (`send_voice`) or discard
    /// (`cancel_voice`). Errors if nothing was captured or encoding fails.
    pub fn stop_voice(&mut self) -> Result<(String, u32, Vec<u8>), ClientError> {
        let rec = self
            .voice_rec
            .take()
            .ok_or_else(|| ClientError::Audio("no voice recording in progress".into()))?;
        // Draining the channel after the capture is dropped collects every frame
        // the mic pushed (each is 20 ms of 48 kHz mono).
        let mut pcm: Vec<i16> = Vec::new();
        while let Ok(frame) = rec.rx.try_recv() {
            pcm.extend_from_slice(&frame);
        }
        if pcm.is_empty() {
            return Err(ClientError::Audio("the recording was empty".into()));
        }
        let frame_samples = enclave_media::audio::FRAME_SAMPLES;
        let duration_ms = (pcm.len() as u64 * 1000 / 48_000) as u32;
        let mut enc =
            enclave_media::AudioEncoder::new().map_err(|e| ClientError::Audio(e.to_string()))?;
        let mut packets = Vec::with_capacity(pcm.len() / frame_samples + 1);
        for chunk in pcm.chunks(frame_samples) {
            let mut frame = chunk.to_vec();
            frame.resize(frame_samples, 0); // pad the final short frame with silence
            packets.push(
                enc.encode(&frame)
                    .map_err(|e| ClientError::Audio(e.to_string()))?,
            );
        }
        let waveform = transfer::waveform_bars(&pcm, 64);
        let bytes = transfer::VoiceClip {
            duration_ms,
            packets,
            waveform: waveform.clone(),
        }
        .encode();
        // Write a preview file the user can play before sending.
        let preview = self
            .store_voice_at("__preview", &bytes)
            .ok_or_else(|| ClientError::Audio("could not cache the recording".into()))?;
        self.voice_pending = Some(PendingVoice {
            bytes,
            duration_ms,
            waveform: waveform.clone(),
            group: rec.group,
        });
        Ok((preview, duration_ms, waveform))
    }

    /// Send the pending (stopped) voice message and record it locally. Returns the
    /// message id, timestamp, and duration (ms).
    pub async fn send_voice(&mut self) -> Result<(String, u64, u32, Vec<u8>), ClientError> {
        let pending = self
            .voice_pending
            .take()
            .ok_or_else(|| ClientError::Audio("no voice message to send".into()))?;
        let PendingVoice {
            bytes,
            duration_ms,
            waveform,
            group,
        } = pending;
        // "Notes to self" is local-only: cache the clip and record it with a
        // fresh local id, but never seal or send it. Everything else is identical.
        let id = if self.is_local_only(&group) {
            new_transfer_id()
        } else {
            self.send_transfer(&group, TransferMeta::Voice, &bytes)?
        };
        let path = self.store_voice_at(&hex::encode(id), &bytes);
        let ts = now_ms();
        let me = self.me()?;
        if let Some(conv) = self.conversations.get_mut(&group) {
            conv.history.push(ChatLine {
                id,
                ts,
                from: me,
                text: String::new(),
                mine: true,
                file: path.clone().map(|p| FileRef {
                    name: "Voice message".into(),
                    size: bytes.len() as u64,
                    path: p,
                }),
                system: false,
                deleted: false,
                reply_to: None,
                voice_ms: Some(duration_ms),
                waveform: waveform.clone(),
            });
        }
        self.save_session();
        Ok((hex::encode(id), ts, duration_ms, waveform))
    }

    /// Write a voice clip to the local cache under `name`, returning its path (or
    /// `None` if the cache directory could not be written).
    fn store_voice_at(&self, name: &str, bytes: &[u8]) -> Option<String> {
        let dir = self.voice_dir();
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join(name);
        std::fs::write(&path, bytes).ok()?;
        Some(path.to_string_lossy().into_owned())
    }

    /// The local path of a cached voice clip by its hex message id (for the
    /// sender to replay its own voice message).
    pub fn voice_clip_path(&self, id_hex: &str) -> String {
        self.voice_dir().join(id_hex).to_string_lossy().into_owned()
    }

    /// Play a cached voice clip through the selected speaker. Decodes inline (a
    /// clip is small and fast) and feeds a PERSISTENT playback stream held by the
    /// client (created on first play, reused after) -- a stable stream lifecycle
    /// that plays reliably, unlike a per-play detached stream. Errors are logged.
    pub fn play_voice(&mut self, path: &str, offset_ms: u32) {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("enclave: voice play: cannot read {path}: {e}");
                return;
            }
        };
        let Some(clip) = transfer::VoiceClip::decode(&bytes) else {
            eprintln!("enclave: voice play: clip did not decode");
            return;
        };
        let mut dec = match enclave_media::AudioDecoder::new() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("enclave: voice play: decoder: {e}");
                return;
            }
        };
        let mut pcm: Vec<i16> = Vec::new();
        for pkt in &clip.packets {
            match dec.decode(pkt) {
                Ok(samples) => pcm.extend_from_slice(&samples),
                Err(e) => eprintln!("enclave: voice play: a packet failed to decode: {e}"),
            }
        }
        if pcm.is_empty() {
            eprintln!(
                "enclave: voice play: nothing decoded (0 of {} packets)",
                clip.packets.len()
            );
            return;
        }
        if self.voice_playback.is_none() {
            match enclave_media::AudioPlayback::start_on(self.output_device.as_deref()) {
                Ok(p) => self.voice_playback = Some(p),
                Err(e) => {
                    eprintln!("enclave: voice play: could not open speaker: {e}");
                    return;
                }
            }
        }
        eprintln!(
            "enclave: voice play: {} samples ({} ms) -> speaker {:?}",
            pcm.len(),
            clip.duration_ms,
            self.output_device.as_deref().unwrap_or("(default)")
        );
        // Resume from `offset_ms` into the clip (48 samples per ms at 48 kHz) so a
        // paused message continues where it stopped instead of restarting.
        let skip = (offset_ms as usize).saturating_mul(48).min(pcm.len());
        if let Some(p) = &self.voice_playback {
            // Replace anything still queued so a switch/resume never piles up.
            p.clear();
            p.push(&pcm[skip..]);
        }
    }

    /// Stop voice playback at once (pause): drop whatever is still queued.
    pub fn stop_voice_playback(&self) {
        if let Some(p) = &self.voice_playback {
            p.clear();
        }
    }

    /// Delete a message. `everyone` (only meaningful for our own message) also
    /// tells the other members to tombstone it. Locally the line is always kept
    /// but marked deleted (a placeholder), never removed. Returns the group so the
    /// caller can report the change.
    pub fn delete_message(&mut self, conv: &str, id_hex: &str, everyone: bool) {
        let Some(mid) = decode_offer_id(id_hex) else {
            return;
        };
        let Some(group) = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()
        else {
            return;
        };
        // Our own copy is FULLY removed (both for "just me" and "for everyone").
        let mut is_mine = false;
        if let Some(c) = self.conversations.get_mut(&group) {
            if let Some(pos) = c.history.iter().position(|l| l.id == mid) {
                is_mine = c.history[pos].mine;
                c.history.remove(pos);
            }
        }
        // Only the author may withdraw a message for everyone; the peer tombstones
        // it (shows "message deleted") while our own copy is gone entirely.
        if everyone && is_mine {
            let _ = self.send_transfer(&group, TransferMeta::Delete, &mid);
        }
        self.save_session();
    }

    /// Toggle `user`'s `emoji` reaction on message `mid` within a conversation's
    /// reaction map, and return the message's reactions after the change. Empty
    /// emoji lists (and empty message entries) are pruned so the map only ever
    /// holds live reactions. Shared by the send and receive paths so both mutate
    /// the state identically.
    fn apply_reaction(
        reactions: &mut HashMap<[u8; 16], Vec<transfer::Reaction>>,
        mid: [u8; 16],
        user: &str,
        emoji: &str,
        add: bool,
    ) -> Vec<transfer::Reaction> {
        let list = reactions.entry(mid).or_default();
        if let Some(r) = list.iter_mut().find(|r| r.emoji == emoji) {
            r.users.retain(|u| u != user);
            if add {
                r.users.push(user.to_string());
            }
        } else if add {
            list.push(transfer::Reaction {
                emoji: emoji.to_string(),
                users: vec![user.to_string()],
            });
        }
        list.retain(|r| !r.users.is_empty());
        let result = list.clone();
        if list.is_empty() {
            reactions.remove(&mid);
        }
        result
    }

    /// Toggle OUR emoji reaction on a message: if we already reacted with `emoji`
    /// we remove it, otherwise we add it. The change is applied locally and, for a
    /// networked conversation, sealed to the group as a [`TransferMeta::React`]
    /// control (never for local-only notes). Returns the message's reactions after
    /// the change so the caller can update the UI immediately.
    pub fn react(
        &mut self,
        conv: &str,
        id_hex: &str,
        emoji: &str,
    ) -> Option<Vec<transfer::Reaction>> {
        let mid = decode_offer_id(id_hex)?;
        let emoji = emoji.trim();
        if emoji.is_empty() || emoji.len() > transfer::MAX_REACTION_BYTES {
            return None;
        }
        let group = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()?;
        let me = self.me().ok()?;
        // Toggle: if I already hold this emoji on this message, remove it.
        let add = !self
            .conversations
            .get(&group)
            .and_then(|c| c.reactions.get(&mid))
            .is_some_and(|list| {
                list.iter()
                    .any(|r| r.emoji == emoji && r.users.iter().any(|u| u == &me))
            });
        let reactions = {
            let c = self.conversations.get_mut(&group)?;
            Self::apply_reaction(&mut c.reactions, mid, &me, emoji, add)
        };
        if !self.is_local_only(&group) {
            let body = transfer::ReactBody {
                target: mid,
                emoji: emoji.to_string(),
                add,
            };
            let _ = self.send_transfer(&group, TransferMeta::React, &body.encode());
        }
        self.save_session();
        Some(reactions)
    }

    /// Edit one of OUR OWN messages: replace its text locally, flag it edited, and
    /// (for a networked conversation) seal a [`TransferMeta::Edit`] control so the
    /// other members update their copy. Only a text line we authored can be edited
    /// -- a file/voice line, a deleted line, or someone else's message is refused.
    /// Returns the new text on success so the caller can refresh the UI.
    pub fn edit_message(&mut self, conv: &str, id_hex: &str, text: &str) -> Option<String> {
        let mid = decode_offer_id(id_hex)?;
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let group = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()?;
        {
            let c = self.conversations.get_mut(&group)?;
            let line = c.history.iter_mut().find(|l| l.id == mid)?;
            // Only our own, still-live, text messages are editable.
            if !line.mine || line.deleted || line.file.is_some() || line.voice_ms.is_some() {
                return None;
            }
            line.text = text.to_string();
            c.edited.insert(mid);
        }
        if !self.is_local_only(&group) {
            let body = transfer::EditBody {
                target: mid,
                text: text.to_string(),
            };
            let _ = self.send_transfer(&group, TransferMeta::Edit, &body.encode());
        }
        self.save_session();
        Some(text.to_string())
    }

    /// Post a poll to the active conversation: a message line the members can vote
    /// on. `reveal` is 0 (always show tallies), 1 (after you vote), or 2 (after the
    /// creator closes). Returns the poll's message id (hex) + timestamp, and the
    /// poll view for our own optimistic render. Refuses a malformed poll.
    pub fn create_poll(
        &mut self,
        question: &str,
        options: &[String],
        multi: bool,
        reveal: u8,
        duration_ms: u64,
        anonymous: bool,
    ) -> Option<(String, u64, PollView)> {
        let group = self.active.clone()?;
        let me = self.me().ok()?;
        let opts: Vec<String> = options
            .iter()
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty())
            .collect();
        let closes_at = if duration_ms > 0 {
            Some(now_ms() + duration_ms)
        } else {
            None
        };
        // reveal >= 2 is a server-buffered poll: mint a shared ballot key so votes
        // seal off the MLS ratchet (the server holds ciphertext it can't read).
        let buffered = reveal >= 2 && !self.is_local_only(&group);
        let ballot_key = if buffered {
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k).ok()?;
            Some(k)
        } else {
            None
        };
        // Anonymous polls (only meaningful for "everyone, on close"): assemble the
        // ring from the members' voting keys, including our own. A member with no
        // published voting key is left out of the ring (they can't vote anonymously).
        // Anonymity is offered only for the two modes that release ballots as a
        // single batch when the poll closes: to the group (2) or to the creator
        // alone (4). The live modes forward each ballot the moment it arrives, so
        // its arrival time would identify the voter in a small group no matter
        // how the ballot is signed -- batching does as much work here as the ring
        // signature does, so a "live anonymous" poll would not keep its promise.
        let anonymous = anonymous && (reveal == 2 || reveal == 4) && buffered;
        // The ring is every member's Ed25519 identity key, read straight out of
        // our own MLS group state. Those keys arrive with membership itself, are
        // already what the safety number verifies, and are never fetched from the
        // server -- so a ring exists for any group, offline, with nobody needing
        // to have been reachable and nothing extra to publish.
        let ring: Vec<[u8; 32]> = if anonymous {
            self.conversations
                .get(&group)
                .and_then(|c| c.group.as_ref())
                .map(|g| {
                    let mut keys: Vec<[u8; 32]> = g
                        .member_keys()
                        .into_iter()
                        .filter_map(|(_, k)| <[u8; 32]>::try_from(k.as_slice()).ok())
                        .collect();
                    // A fixed order every verifier agrees on, derived from the keys
                    // themselves rather than from roster order (which can differ
                    // between members) or names (which would order by identity).
                    keys.sort_unstable();
                    keys.dedup();
                    keys
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // Anonymity needs at least a 2-member ring: a ring of one hides nobody.
        // Refuse rather than quietly hand back an attributed poll -- silently
        // downgrading a privacy choice the user explicitly made is worse than
        // failing, because they would never learn the votes were attributable.
        if anonymous && ring.len() < 2 {
            self.pending.push_back(Event::Error(
                "This poll cannot be anonymous yet: a ring of one hides nobody, and no one \
                 else here has a voting key cached yet. It arrives with their profile and is \
                 stored permanently, so this is one-time per contact and never affects who \
                 needs to be around when a poll closes."
                    .into(),
            ));
            return None;
        }
        let body = transfer::PollBody {
            question: question.trim().to_string(),
            options: opts,
            multi,
            reveal,
            closes_at,
            ballot_key,
            anonymous,
            ring: if anonymous { ring.clone() } else { Vec::new() },
        };
        if !body.valid() {
            return None;
        }
        let id = if self.is_local_only(&group) {
            new_transfer_id()
        } else {
            self.send_transfer(&group, TransferMeta::Poll, &body.encode())
                .ok()?
        };
        let ts = now_ms();
        let poll = Poll {
            question: body.question.clone(),
            options: body.options.clone(),
            multi,
            reveal,
            closed: false,
            closes_at,
            author: me.clone(),
            votes: HashMap::new(),
            ballot_key,
            anonymous,
            ring: body.ring.clone(),
            my_tag: None,
        };
        // Register the buffered poll with the server so it withholds/routes ballots
        // and knows we (the sender) are the owner who may close it early.
        if let Some(mode) = poll.server_mode() {
            self.send_reliable(ClientMsg::BallotOpen {
                poll: id,
                group: group.clone(),
                mode,
                release_at: closes_at,
                anonymous,
            });
        }
        let view = Self::build_poll_view(&poll, &me);
        if let Some(c) = self.conversations.get_mut(&group) {
            c.polls.insert(id, poll);
            c.history.push(ChatLine {
                id,
                ts,
                from: me,
                text: body.question,
                mine: true,
                file: None,
                system: false,
                deleted: false,
                reply_to: None,
                voice_ms: None,
                waveform: Vec::new(),
            });
        }
        self.save_session();
        Some((hex::encode(id), ts, view))
    }

    /// Cast (or change, or with an empty selection retract) OUR vote on a poll.
    /// Single-choice polls keep at most one option; invalid indices are dropped.
    /// Seals a [`TransferMeta::Vote`] to the group (unless local-only). Returns the
    /// updated poll view.
    pub fn vote_poll(&mut self, conv: &str, poll_id: &str, options: Vec<u8>) -> Option<PollView> {
        let mid = decode_offer_id(poll_id)?;
        let group = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()?;
        let me = self.me().ok()?;
        let (sel, ballot_key, anonymous, ring) = {
            let c = self.conversations.get_mut(&group)?;
            let poll = c.polls.get_mut(&mid)?;
            if poll.is_closed() {
                return None; // a closed (or expired) poll accepts no more votes
            }
            let mut sel: Vec<u8> = options
                .into_iter()
                .filter(|&i| (i as usize) < poll.options.len())
                .collect();
            sel.sort_unstable();
            sel.dedup();
            if !poll.multi {
                sel.truncate(1);
            }
            // A non-anonymous poll applies our vote now, keyed by our username. An
            // anonymous poll keys by our key image instead (set below, after we
            // sign), so nothing here would attribute the vote to us.
            if !poll.anonymous {
                if sel.is_empty() {
                    poll.votes.remove(&me);
                } else {
                    poll.votes.insert(me.clone(), sel.clone());
                }
            }
            (sel, poll.ballot_key, poll.anonymous, poll.ring.clone())
        };
        if !self.is_local_only(&group) {
            let body = transfer::VoteBody {
                target: mid,
                options: sel.clone(),
            };
            match ballot_key {
                // Anonymous poll: seal the choice, ring-sign it (proving a member
                // cast it, without saying which), and submit. Our own vote is keyed
                // locally by our key image -- the same pseudonym others will see.
                Some(key) if anonymous => {
                    if let Ok(sealed) = enclave_crypto::seal_ballot(&key, &mid, &body.encode()) {
                        let kp = self.identity.as_ref().and_then(|i| i.ring_keypair().ok());
                        if let Some(sig) = kp.and_then(|k| k.sign(&sealed, &mid, &ring).ok()) {
                            let tag = hex::encode(sig.key_image);
                            if let Some(p) = self
                                .conversations
                                .get_mut(&group)
                                .and_then(|c| c.polls.get_mut(&mid))
                            {
                                // Remember the pseudonym we filed under, so we can
                                // still show the user their own choice back.
                                p.my_tag = Some(tag.clone());
                                if sel.is_empty() {
                                    p.votes.remove(&tag);
                                } else {
                                    p.votes.insert(tag, sel.clone());
                                }
                            }
                            let ballot = transfer::AnonBallot {
                                sealed_choice: sealed,
                                sig,
                            };
                            self.send_reliable(ClientMsg::BallotSubmit {
                                poll: mid,
                                ballot: Sealed(ballot.encode()),
                            });
                        }
                    }
                }
                // Server-buffered (non-anonymous) poll: seal off the ratchet and
                // submit a BallotSubmit the server withholds/routes (never Text).
                Some(key) => {
                    if let Ok(sealed) = enclave_crypto::seal_ballot(&key, &mid, &body.encode()) {
                        self.send_reliable(ClientMsg::BallotSubmit {
                            poll: mid,
                            ballot: Sealed(sealed),
                        });
                    }
                }
                // Immediate poll (reveal 0/1): vote over normal MLS as before.
                None => {
                    let _ = self.send_transfer(&group, TransferMeta::Vote, &body.encode());
                }
            }
        }
        self.save_session();
        let poll = self.conversations.get(&group)?.polls.get(&mid)?;
        Some(Self::build_poll_view(poll, &me))
    }

    /// Close a poll we created: no more votes, and (for reveal mode 2) the tallies
    /// become visible. Only the creator may close. Returns the updated view.
    pub fn close_poll(&mut self, conv: &str, poll_id: &str) -> Option<PollView> {
        let mid = decode_offer_id(poll_id)?;
        let group = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()?;
        let me = self.me().ok()?;
        let mode = {
            let c = self.conversations.get_mut(&group)?;
            let poll = c.polls.get_mut(&mid)?;
            if poll.author != me {
                return None; // only the creator closes their poll
            }
            poll.closed = true;
            poll.server_mode()
        };
        if !self.is_local_only(&group) {
            match mode {
                // Buffered poll: ask the server to release its ballots now. The
                // released Ballots delivery closes it (and delivers the tally) for
                // everyone -- no MLS close control needed.
                Some(_) => self.send_reliable(ClientMsg::BallotClose { poll: mid }),
                // Immediate poll: seal the close control to the group as before.
                None => {
                    let _ = self.send_transfer(&group, TransferMeta::PollClose, &mid);
                }
            }
        }
        self.save_session();
        let poll = self.conversations.get(&group)?.polls.get(&mid)?;
        Some(Self::build_poll_view(poll, &me))
    }

    /// Pin or unpin a message for the whole conversation (pins are shared). Applies
    /// locally and seals a [`TransferMeta::Pin`] so every member updates. Returns
    /// the new pinned state.
    pub fn pin_message(&mut self, conv: &str, id_hex: &str, pinned: bool) -> Option<bool> {
        let mid = decode_offer_id(id_hex)?;
        let group = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()?;
        {
            let c = self.conversations.get_mut(&group)?;
            // The message must exist in this conversation to be pinned.
            if !c.history.iter().any(|l| l.id == mid) {
                return None;
            }
            if pinned {
                c.pinned.insert(mid);
            } else {
                c.pinned.remove(&mid);
            }
        }
        if !self.is_local_only(&group) {
            let body = transfer::PinBody {
                target: mid,
                pinned,
            };
            let _ = self.send_transfer(&group, TransferMeta::Pin, &body.encode());
        }
        self.save_session();
        Some(pinned)
    }

    /// Turn disappearing messages on (a duration in ms) or off (0) for a
    /// conversation, and tell the peer so both sides run the same local timer.
    /// Only the on/off + duration is shared; deletion is local, so no read-state
    /// or per-message timing ever leaves either device.
    pub fn set_disappearing(&mut self, conv: &str, ms: u32) {
        let Some(group) = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()
        else {
            return;
        };
        if let Some(c) = self.conversations.get_mut(&group) {
            c.disappearing_ms = if ms == 0 { None } else { Some(ms) };
        }
        // "Notes to self" applies the timer purely locally; nothing is shared,
        // because there is no peer and nothing may cross the network.
        if !self.is_local_only(&group) {
            let _ = self.send_transfer(&group, TransferMeta::Disappear, &ms.to_le_bytes());
        }
        self.save_session();
    }

    /// The disappearing-messages duration (ms) for a conversation, 0 if off.
    pub fn disappearing_of(&self, conv: &str) -> u32 {
        self.conversations
            .iter()
            .find(|(k, _)| hex_id(k) == conv)
            .and_then(|(_, c)| c.disappearing_ms)
            .unwrap_or(0)
    }

    /// Remove messages whose disappearing timer has elapsed (fully, no
    /// placeholder). Returns the removed message ids per conversation (hex), so
    /// the UI can drop them. Called periodically by the app loop.
    pub fn expire_messages(&mut self) -> Vec<(String, Vec<String>)> {
        let now = now_ms();
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for (gid, c) in self.conversations.iter_mut() {
            let Some(ms) = c.disappearing_ms else {
                continue;
            };
            let mut removed = Vec::new();
            c.history.retain(|l| {
                if now.saturating_sub(l.ts) > ms as u64 {
                    removed.push(hex::encode(l.id));
                    false
                } else {
                    true
                }
            });
            if !removed.is_empty() {
                out.push((hex_id(gid), removed));
            }
        }
        if !out.is_empty() {
            self.save_session();
        }
        out
    }

    /// Focus a conversation by its hex id. Opening an archived conversation
    /// counts as activity and returns it to the Chats list.
    pub fn switch(&mut self, conv: &str) {
        if let Some(id) = self
            .conversations
            .keys()
            .find(|k| hex_id(k) == conv)
            .cloned()
        {
            if self.touch_conversation(&id) {
                self.save_session();
            }
            self.active = Some(id);
        }
    }

    /// Clear the active conversation (the UI closed the open chat and went to the
    /// home view). Keeps the core's notion of "what is open" in step with the UI,
    /// so a later conversation-list refresh -- e.g. after a friend is accepted --
    /// does not re-broadcast a stale active conversation and yank the UI back in.
    pub fn deselect(&mut self) {
        self.active = None;
    }

    /// Encrypt and send a text message to the active conversation. A message
    /// that fits in one sealed frame is a single part; a larger one is split
    /// into chunks (see [`crate::transfer`]) that the peer reassembles. Records
    /// the message in local history.
    pub async fn send_text(
        &mut self,
        text: &str,
        reply_to: Option<&str>,
    ) -> Result<(String, u64), ClientError> {
        let group_id = self.active.clone().ok_or(ClientError::NoGroup)?;
        let me = self.me()?;
        let reply_to = reply_to.and_then(decode_offer_id);
        // "Notes to self" is local-only: record the line and stop. Nothing is
        // sealed or sent -- no `send_transfer`, no reconnect, no network at all.
        if self.is_local_only(&group_id) {
            let id = new_transfer_id();
            let ts = now_ms();
            if let Some(conv) = self.conversations.get_mut(&group_id) {
                conv.history.push(ChatLine {
                    id,
                    ts,
                    from: me,
                    text: text.to_string(),
                    mine: true,
                    file: None,
                    system: false,
                    deleted: false,
                    reply_to,
                    voice_ms: None,
                    waveform: Vec::new(),
                });
            }
            self.save_session();
            return Ok((hex::encode(id), ts));
        }
        // Messaging a DM whose peer unfriended us re-adds them (a reconnect).
        self.reconnect_dm_peer_if_needed(&group_id);
        let body = transfer::TextBody {
            text: text.to_string(),
            reply_to,
        };
        let id = self.send_transfer(&group_id, TransferMeta::Text, &body.encode())?;
        let ts = now_ms();
        if let Some(conv) = self.conversations.get_mut(&group_id) {
            conv.history.push(ChatLine {
                id,
                ts,
                from: me,
                text: text.to_string(),
                mine: true,
                file: None,
                system: false,
                deleted: false,
                reply_to,
                voice_ms: None,
                waveform: Vec::new(),
            });
        }
        self.save_session();
        Ok((hex::encode(id), ts))
    }

    /// Whether `group_id` is the local-only "Notes to self" scratchpad -- the
    /// single check every send path consults before it would touch the network.
    fn is_local_only(&self, group_id: &GroupId) -> bool {
        self.conversations
            .get(group_id)
            .is_some_and(|c| c.local_only)
    }

    /// Offer a file to the active conversation. The file is NOT sent yet: a
    /// sealed manifest (name, size) is offered so each recipient can accept or
    /// decline. A file up to [`STORE_FILE_MAX`] is offered for offline delivery
    /// (the server buffers it on disk once the recipient accepts); a larger one
    /// is offered live (streamed in real time to whoever accepts, requiring them
    /// online). The bytes are read and sealed only when the server says to
    /// upload/stream, never up front, so the whole file is never held in memory.
    /// Returns the [`FileRef`] for the sender's own history.
    /// Offer a file the normal way: buffered on the server for offline delivery
    /// if small enough, otherwise streamed live. Capped at [`MAX_RECEIVE_BYTES`].
    /// Offer a file. Returns the file descriptor and the offer's hex id, so the
    /// UI can label the sender's own message with a "Stop sharing" control.
    pub async fn send_file(&mut self, path: &str) -> Result<(FileRef, String), ClientError> {
        self.offer_file(path, false).await
    }

    /// Explicitly LIVE-share a file: a real-time stream, never stored, with NO
    /// size limit. Both parties must be online; the bytes go straight to the
    /// recipient's disk (never buffered whole in RAM), and the recipient consents
    /// to the declared size, so there is no ceiling to enforce.
    pub async fn send_file_live(&mut self, path: &str) -> Result<(FileRef, String), ClientError> {
        self.offer_file(path, true).await
    }

    async fn offer_file(
        &mut self,
        path: &str,
        force_live: bool,
    ) -> Result<(FileRef, String), ClientError> {
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
        // "Notes to self" is local-only: attach the file as a local reference
        // (name/size/path) and stop. Nothing is sealed, offered, or uploaded --
        // the bytes stay where they are on disk and "Open" opens them in place.
        // No size ceiling applies since nothing crosses the network.
        if self.is_local_only(&group_id) {
            let file_ref = FileRef {
                name: name.clone(),
                size,
                path: path.to_string(),
            };
            let id = new_transfer_id();
            if let Some(conv) = self.conversations.get_mut(&group_id) {
                conv.history.push(ChatLine {
                    id,
                    ts: now_ms(),
                    from: me,
                    text: name,
                    mine: true,
                    file: Some(file_ref.clone()),
                    system: false,
                    deleted: false,
                    reply_to: None,
                    voice_ms: None,
                    waveform: Vec::new(),
                });
            }
            self.save_session();
            return Ok((file_ref, hex::encode(id)));
        }
        // The normal path enforces the hard ceiling (a stored recipient's sink
        // caps at it). Explicit live sharing has no cap: it streams to disk and
        // the recipient consents to the declared size.
        if !force_live && size > transfer::MAX_RECEIVE_BYTES {
            let gb = transfer::MAX_RECEIVE_BYTES / (1024 * 1024 * 1024);
            return Err(ClientError::Audio(format!(
                "{name} is too large to send normally ({size_gb:.1} GB, limit {gb} GB); use Live share instead",
                size_gb = size as f64 / (1024.0 * 1024.0 * 1024.0),
            )));
        }
        let mime = mime_from_name(&name);
        let live = force_live || size > STORE_FILE_MAX;

        // Fresh per-file content key: every chunk is sealed under it (off the MLS
        // ratchet), and it travels only inside the sealed manifest below.
        let mut content_key = [0u8; 32];
        getrandom::getrandom(&mut content_key)
            .map_err(|e| ClientError::Audio(format!("rng: {e}")))?;

        // Seal the manifest so recipients learn the name/size (and the content
        // key) without the bytes.
        let manifest = FileManifest {
            name: name.clone(),
            mime: mime.clone(),
            size,
            content_key,
        };
        let sealed_manifest = self.seal(&group_id, &manifest.encode())?;

        let offer_id = new_transfer_id();
        // Reliable so a dropped offer is retransmitted, not silently lost (the
        // server dedups by the unique offer id). Without this a connection blip
        // meant the file "just never arrived" with no error.
        self.send_reliable(ClientMsg::FileOffer {
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
                content_key,
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
                id: offer_id,
                ts: now_ms(),
                from: me,
                text: name,
                mine: true,
                file: Some(file_ref.clone()),
                system: false,
                deleted: false,
                reply_to: None,
                voice_ms: None,
                waveform: Vec::new(),
            });
        }
        self.save_session();
        Ok((file_ref, hex::encode(offer_id)))
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

    /// Refuse an offered file for good: tell the server (which gives the offer up
    /// for us) and forget it. The UI keeps the message, marked declined; declining
    /// is final, so there is no re-download afterwards (that is what abort is for).
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

    /// Abort an in-progress download WITHOUT giving the offer up: stop writing,
    /// discard the partial file, and tell the server to stop streaming -- but keep
    /// the offer so the user can download it again. The offer stays available
    /// until the sender withdraws it or goes offline. Idempotent: aborting an
    /// unknown or already-aborted offer is a no-op.
    pub fn abort_file(&mut self, offer_id: &str) -> Result<(), ClientError> {
        let id = decode_offer_id(offer_id).ok_or(ClientError::NoGroup)?;
        if let Some(inc) = self.incoming_files.get_mut(&id) {
            inc.accepted = false;
            if let Some(sink) = inc.sink.take() {
                sink.abort();
            }
            // Tell the server to stop the in-flight stream and leave the offer
            // pending; a later `accept_file` re-downloads it from the start.
            self.conn.send(ClientMsg::FileAbort { offer_id: id });
        }
        Ok(())
    }

    /// Heal a conversation whose application-message ratchet has desynced -- a
    /// receiver so far behind the sender's generation that openmls rejects new
    /// messages ("too far in the future"). We commit a self-update (rekey), which
    /// starts a fresh epoch and resets every member's message ratchet to 0, so
    /// both sides talk again. The rekey commit rides the SEPARATE handshake
    /// ratchet (undisturbed by the application-message desync), so the peer can
    /// apply it even while ordinary messages are undecryptable. Debounced per
    /// group so a burst of undecryptable messages triggers at most one rekey per
    /// cooldown -- ample time for the peer to apply it and the epoch to advance.
    ///
    /// For a one-directional desync (the common case: one side sent a large file
    /// under the old design) only the stuck receiver ever reaches this, so exactly
    /// one member commits and there is no competing commit. (A simultaneous
    /// both-directions desync could race two commits; that resolves to recreating
    /// the conversation, the same fallback as before, and cannot happen from new
    /// transfers now that file bytes are off the ratchet.)
    fn heal_group(&mut self, group: &GroupId) {
        let now = Instant::now();
        if let Some(&t) = self.last_heal.get(group) {
            if now.duration_since(t) < HEAL_COOLDOWN {
                return; // a rekey is already in flight for this group
            }
        }
        let commit = {
            let Some(identity) = self.identity.as_ref() else {
                return;
            };
            let Some(conv) = self.conversations.get_mut(group) else {
                return;
            };
            let Some(g) = conv.group.as_mut() else { return };
            match g.rekey(identity) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("enclave: could not heal a desynced conversation: {e}");
                    return;
                }
            }
        };
        self.last_heal.insert(group.clone(), now);
        // Reliable: the heal must reach the peer even across a reconnect, or the
        // conversation stays broken.
        self.send_reliable(ClientMsg::Mls {
            group: group.clone(),
            message: Sealed(commit),
        });
        self.save_session();
        eprintln!("enclave: healing a desynced conversation (rekey)");
    }

    /// Note a forked DM (the peer is on a different MLS group) so it gets healed.
    /// Only the SMALLER handle queues a re-establish, deterministically, so the
    /// two sides never both rebuild (which would fork again). The larger handle
    /// waits for the smaller's fresh Welcome.
    fn queue_dm_reinvite(&mut self, group: &GroupId) {
        let me = self.username.clone().unwrap_or_default();
        let Some(conv) = self.conversations.get(group) else {
            return;
        };
        if !matches!(conv.kind, ConvKind::Dm) {
            return;
        }
        // The peer is taken from the AUTHENTICATED MLS membership, never from
        // server-provided metadata, so a malicious server cannot steer who we act
        // on. Only the smaller handle acts (deterministic; no double-rebuild).
        let Some(g) = conv.group.as_ref() else { return };
        let members: Vec<String> = g.member_keys().into_iter().map(|(n, _)| n).collect();
        match members.iter().find(|n| **n != me) {
            Some(peer) => {
                // EITHER side re-establishes (so it works whichever client is
                // online / on the new build). Both re-establishing still converges:
                // each sends the other a fresh Welcome, and the Welcome tie-break
                // makes the smaller handle's group win. Debounced in pump_reinvites.
                eprintln!("enclave: DM fork detected; me={me} peer={peer} members={members:?}");
                self.pending_reinvites.insert(group.clone());
            }
            None => eprintln!("enclave: DM fork but no peer in my group members={members:?}"),
        }
    }

    /// Re-establish any forked DMs (drained + debounced). Driven by the app loop.
    pub async fn pump_reinvites(&mut self) {
        let groups: Vec<GroupId> = self.pending_reinvites.drain().collect();
        let now = Instant::now();
        for g in groups {
            if self
                .last_reinvite
                .get(&g)
                .is_some_and(|t| now.duration_since(*t) < REINVITE_COOLDOWN)
            {
                continue;
            }
            self.last_reinvite.insert(g.clone(), now);
            match self.reestablish_dm_peer(&g).await {
                Ok(Some(peer)) => eprintln!("enclave: re-establishing a forked DM with {peer}"),
                Ok(None) => {}
                Err(e) => eprintln!("enclave: could not re-establish a forked DM: {e}"),
            }
        }
    }

    /// Remove the peer (rekeying off any stale state) then re-add them, so they
    /// receive a fresh Welcome and converge onto our canonical DM group. The peer
    /// is read from the AUTHENTICATED MLS membership -- never from server metadata
    /// -- and re-added with an identity-bound `add_member`, so a malicious server
    /// can neither steer who we re-add nor substitute a ghost. Returns the peer
    /// re-established, or `None` if there was nothing to do.
    async fn reestablish_dm_peer(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Option<String>, ClientError> {
        let me = self.username.clone().unwrap_or_default();
        // The peer is the OTHER member of the AUTHENTICATED MLS group -- read from
        // `member_keys` (never server metadata). We do NOT remove it yet.
        let Some((peer, peer_key)) = self
            .conversations
            .get(group_id)
            .and_then(|c| c.group.as_ref())
            .and_then(|g| g.member_keys().into_iter().find(|(n, _)| *n != me))
        else {
            return Ok(None); // no peer to re-establish
        };
        // Fetch and IDENTITY-CHECK the key package BEFORE any change, so a
        // substituted (valid-but-wrong-identity) package fails closed without
        // corrupting the group (no orphaned "just me" state).
        let key_package = self.fetch_key_package(&peer).await?;
        let add = {
            let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
            let got = Group::key_package_identity(identity, &key_package)?;
            if got != peer {
                return Err(ClientError::Crypto(
                    enclave_crypto::CryptoError::KeyPackageInvalid(format!(
                        "re-establish: key package identity {got:?} is not the peer {peer:?}"
                    )),
                ));
            }
            let conv = self
                .conversations
                .get_mut(group_id)
                .ok_or(ClientError::NoGroup)?;
            let group = conv.group.as_mut().ok_or(ClientError::NoGroup)?;
            // Now safe: remove the stale member, then re-add the validated one.
            let _ = group.remove_member(identity, &peer_key)?;
            group.add_member(identity, &key_package, &peer)?
        };
        self.send_reliable(ClientMsg::Welcome {
            to: DeviceId(peer.clone()),
            group: group_id.clone(),
            name: String::new(),
            message: Sealed(add.welcome),
        });
        self.send_reliable(ClientMsg::Mls {
            group: group_id.clone(),
            message: Sealed(add.commit),
        });
        self.save_session();
        Ok(Some(peer))
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
        let (group, path, name, size, content_key) = match self.outgoing_files.get_mut(&offer_id) {
            Some(o) if !o.started => {
                o.started = true;
                (
                    o.group.clone(),
                    o.path.clone(),
                    o.name.clone(),
                    o.size,
                    o.content_key,
                )
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
                offer_id,
                group,
                file,
                content_key,
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
                                up.offer_id,
                                up.group.clone(),
                                up.content_key,
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
                        self.conn
                            .try_send_file(ClientMsg::FileComplete { offer_id: id });
                        self.uploads.remove(&id);
                        break;
                    }
                    Some((index, offer_id, group, content_key, data, n)) => {
                        // Seal the raw chunk under the per-file content key (not
                        // the MLS ratchet), binding its position, so streaming or
                        // dropping it never disturbs the group's message keys.
                        let sealed =
                            match enclave_crypto::seal_chunk(&content_key, &offer_id, index, &data)
                            {
                                Ok(s) => s,
                                Err(e) => {
                                    self.pending.push_back(Event::Error(format!(
                                        "sealing a file chunk: {e}"
                                    )));
                                    self.uploads.remove(&id);
                                    break;
                                }
                            };
                        // Capacity was checked at the loop head and we are the
                        // only file producer, so a send fails only if the
                        // connection dropped -- abandon the doomed upload then.
                        if !self.conn.try_send_file(ClientMsg::FileChunk {
                            offer_id: id,
                            index,
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
    /// Split, seal, and send a transfer; returns its id so the caller can label
    /// the message in local history with the same id both peers will see.
    fn send_transfer(
        &mut self,
        group_id: &GroupId,
        meta: TransferMeta,
        data: &[u8],
    ) -> Result<[u8; 16], ClientError> {
        let id = new_transfer_id();
        for part in transfer::split(id, meta, data) {
            self.seal_and_send(group_id, &part)?;
        }
        Ok(id)
    }

    /// Seal one serialized part with the group key and hand it to the relay as a
    /// Text message (used for text and large-text transfers). Each part is sent
    /// reliably: the server acks it and the sender retransmits until acked, so a
    /// message never silently vanishes on a connection drop or server restart.
    fn seal_and_send(&mut self, group_id: &GroupId, part: &[u8]) -> Result<(), ClientError> {
        let sealed = self.seal(group_id, part)?;
        self.send_reliable(ClientMsg::Text {
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

    /// Send `msg` with at-least-once delivery: label it with a sequence number,
    /// keep it in the retransmit buffer until the server acks, and wrap it in a
    /// [`ClientMsg::Reliable`]. Used for chat text, MLS handshakes, and Welcomes
    /// -- messages whose loss would be a bug, not a dropped video frame.
    fn send_reliable(&mut self, msg: ClientMsg) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let now = Instant::now();
        self.unacked.insert(
            seq,
            Pending {
                msg: msg.clone(),
                first: now,
                last: now,
            },
        );
        self.conn.send(ClientMsg::Reliable {
            seq,
            msg: Box::new(msg),
        });
    }

    /// Resend every un-acked reliable message (in sequence order). Called on
    /// reconnect: the new socket has none of the old in-flight state, so anything
    /// the server had not yet acked must be replayed. The receiver dedups any
    /// that actually did get through the first time.
    fn resend_unacked(&mut self) {
        let now = Instant::now();
        let pending: Vec<(u64, ClientMsg)> = self
            .unacked
            .iter_mut()
            .map(|(seq, p)| {
                p.last = now;
                (*seq, p.msg.clone())
            })
            .collect();
        for (seq, msg) in pending {
            self.conn.send(ClientMsg::Reliable {
                seq,
                msg: Box::new(msg),
            });
        }
    }

    /// Retransmit reliable messages the server has not acked within
    /// [`RETRANSMIT_AFTER`], and surface a warning if delivery is persistently
    /// stuck (a message retrying past [`UNDELIVERED_WARN_AFTER`], or a backlog
    /// past [`MAX_UNACKED_BEFORE_WARN`]). Driven by the event loop; on a healthy
    /// connection nothing is due and nothing is stuck. Returns a one-shot warning
    /// event on the transition into a stuck state (never every tick).
    pub fn pump_retransmits(&mut self) -> Option<Event> {
        let now = Instant::now();
        let due: Vec<u64> = self
            .unacked
            .iter()
            .filter(|(_, p)| now.duration_since(p.last) >= RETRANSMIT_AFTER)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in due {
            if let Some(p) = self.unacked.get_mut(&seq) {
                p.last = now;
                let msg = p.msg.clone();
                self.conn.send(ClientMsg::Reliable {
                    seq,
                    msg: Box::new(msg),
                });
            }
        }

        // Warn once when delivery becomes persistently stuck, and reset when it
        // recovers, so the user learns their messages are not getting through
        // instead of them retransmitting invisibly forever.
        let stuck = self.unacked.len() > MAX_UNACKED_BEFORE_WARN
            || self
                .unacked
                .values()
                .any(|p| now.duration_since(p.first) >= UNDELIVERED_WARN_AFTER);
        if stuck && !self.delivery_warned {
            self.delivery_warned = true;
            // We now know delivery is failing: flush the pending buffer to disk
            // so these messages survive even a hard kill and are retransmitted on
            // next launch. (Each send already persists; this makes it a hard
            // guarantee at the moment we detect we cannot send.)
            self.save_session();
            let n = self.unacked.len();
            return Some(Event::Error(format!(
                "{n} message{} not delivered yet -- still retrying; check your connection.",
                if n == 1 { "" } else { "s" }
            )));
        }
        if !stuck {
            self.delivery_warned = false;
        }
        None
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
        // Decrypt the manifest with the group key. A silently-dropped offer is
        // the "file never popped up, no idea why" symptom, so each failure is
        // logged rather than swallowed by `?`.
        let decrypted = {
            let identity = self.identity.as_ref()?;
            let Some(conv) = self.conversations.get_mut(&group) else {
                eprintln!("enclave: file offer for a conversation we don't have; dropped");
                return None;
            };
            let Some(g) = conv.group.as_mut() else {
                eprintln!("enclave: file offer for a not-yet-established group; dropped");
                return None;
            };
            g.decrypt_text(identity, &manifest.0)
        };
        let plaintext = match decrypted {
            Ok(tm) => tm.plaintext,
            Err(e) => {
                eprintln!("enclave: file offer manifest failed to decrypt: {e}; dropped");
                // A desynced ratchet (a legacy conversation from before file bytes
                // were moved off it) drops offers too; heal it so the retry lands.
                if is_ratchet_desync(&e) {
                    self.heal_group(&group);
                } else if is_group_fork(&e) {
                    self.queue_dm_reinvite(&group);
                }
                return None;
            }
        };
        let Some(m) = FileManifest::decode(&plaintext) else {
            eprintln!("enclave: file offer manifest was malformed; dropped");
            return None;
        };
        let safe = safe_file_name(&m.name);
        let from_display = self.display_of(&from.0);
        self.incoming_files.insert(
            offer_id,
            IncomingFile {
                group: group.clone(),
                from: from.0.clone(),
                name: safe.clone(),
                size: m.size,
                content_key: m.content_key,
                accepted: false,
                sink: None,
            },
        );
        // An incoming file is activity too: bring an archived conversation back.
        self.note_activity(&group);
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
        let can_retry_live = self.outgoing_files.get(&offer_id).is_some_and(|o| !o.live);
        if can_retry_live {
            let (group, manifest) = {
                let o = self.outgoing_files.get(&offer_id)?;
                (
                    o.group.clone(),
                    FileManifest {
                        name: o.name.clone(),
                        mime: o.mime.clone(),
                        size: o.size,
                        // Reuse the same key the chunks are sealed under.
                        content_key: o.content_key,
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
            let group = o.group.clone();
            let conv = hex_id(&group);
            let text = if by.0.is_empty() {
                format!("{name} was not delivered (no reply)")
            } else {
                format!("{} declined {name}", self.display_of(&by.0))
            };
            // Persist it as a system line so it stays in the chat for good (it is
            // rendered as the same small centered notice); the event just shows it
            // immediately if the conversation is already open.
            if let Some(conv_state) = self.conversations.get_mut(&group) {
                conv_state.history.push(ChatLine {
                    id: new_transfer_id(),
                    ts: now_ms(),
                    from: String::new(),
                    text: text.clone(),
                    mine: false,
                    file: None,
                    system: true,
                    deleted: false,
                    reply_to: None,
                    voice_ms: None,
                    waveform: Vec::new(),
                });
            }
            self.save_session();
            return Some(Event::Notice { conv, text });
        }
        // An offer shown to us: the sender withdrew it or went offline. Drop any
        // partial download and forget the offer (it cannot be re-downloaded), but
        // KEEP its message in chat -- mark it "no longer available", never remove.
        if let Some(inc) = self.incoming_files.remove(&offer_id) {
            if let Some(sink) = inc.sink {
                sink.abort();
            }
            return Some(Event::FileOfferUnavailable {
                conv: hex_id(&inc.group),
                offer_id: hex::encode(offer_id),
            });
        }
        None
    }

    /// A chunk of a file we accepted: decrypt it, create the streaming disk sink
    /// on the first chunk (sized from the offered manifest), write the part, and
    /// finalize when the last one lands. The whole file is never held in memory.
    fn handle_file_chunk(&mut self, offer_id: [u8; 16], index: u32, data: Sealed) -> Option<Event> {
        // Consent gate (defense in depth): write chunks only for an offer the
        // user explicitly accepted. A malicious server that streams an
        // un-accepted file's bytes at us gets them dropped, never written.
        let (group, content_key) = match self.incoming_files.get(&offer_id) {
            Some(inc) if inc.accepted => (inc.group.clone(), inc.content_key),
            _ => return None,
        };
        // Open the chunk under the offer's content key. This never touches the
        // MLS ratchet, so a chunk we drop (a cancelled or replayed download) can
        // never desync the conversation. A tampered/misindexed chunk fails the
        // AEAD and is dropped.
        let chunk = enclave_crypto::open_chunk(&content_key, &offer_id, index, &data.0).ok()?;
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

        // Write the chunk at its authenticated position.
        let (size, write) = {
            let inc = self.incoming_files.get_mut(&offer_id)?;
            let sink = inc.sink.as_mut()?;
            (
                inc.size,
                sink.write_chunk(index, &chunk)
                    .map(|done| (done, sink.bytes())),
            )
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
        let ts = now_ms();
        if let Some(conv) = self.conversations.get_mut(&group) {
            conv.history.push(ChatLine {
                id: offer_id,
                ts,
                from: inc.from.clone(),
                text: file.name.clone(),
                mine: false,
                file: Some(file.clone()),
                system: false,
                deleted: false,
                reply_to: None,
                voice_ms: None,
                waveform: Vec::new(),
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
            id: hex::encode(offer_id),
            ts,
            from: from_display,
            user: inc.from.clone(),
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
        // Deleted conversations disappear entirely (they reappear on a new message
        // or when reopened). Everything else is returned; the UI shows Active in
        // the live list and Archived/Left on the Archived page.
        self.conversations
            .iter()
            .filter(|(_, c)| c.visibility != Visibility::Deleted)
            .map(|(id, c)| {
                // "Notes to self" has no peer: it is just us. Report it as its own
                // kind, always sendable, never pending/reconnecting.
                if c.local_only {
                    return ConversationInfo {
                        id: hex_id(id),
                        title: c.title.clone(),
                        is_dm: true,
                        members: c.members.clone(),
                        pending: false,
                        archived: c.visibility == Visibility::Archived,
                        left: false,
                        can_send: true,
                        reconnect: false,
                        self_notes: true,
                    };
                }
                let (title, peer_is_friend) = match c.kind {
                    ConvKind::Dm => {
                        let peer = c
                            .members
                            .iter()
                            .find(|m| **m != me)
                            .cloned()
                            .unwrap_or_else(|| c.title.clone());
                        (self.display_of(&peer), self.is_friend(&peer))
                    }
                    ConvKind::Group => (c.title.clone(), true),
                };
                let is_dm = c.kind == ConvKind::Dm;
                let left = c.visibility == Visibility::Left;
                ConversationInfo {
                    id: hex_id(id),
                    title,
                    is_dm,
                    members: c.members.clone(),
                    pending: c.group.is_none() && !left,
                    archived: c.visibility == Visibility::Archived,
                    left,
                    // Left groups are read-only; everything else is sendable.
                    can_send: !left,
                    // A DM whose peer unfriended us: sending re-adds them.
                    reconnect: is_dm && !peer_is_friend && !left,
                    self_notes: false,
                }
            })
            .collect()
    }

    /// The active conversation's id (hex), if any.
    pub fn active_id(&self) -> Option<String> {
        self.active.as_ref().map(hex_id)
    }

    /// The scoped history (from, text, mine) of a conversation by hex id.
    /// History as `(username, display_name, text, mine, file)` per line. The
    /// username is the stable identity (for the avatar); the display name is
    /// resolved live so a rename shows on reload.
    /// Build the UI-facing view of a stored poll for viewer `me`: tallies, my
    /// selection, and whether results should be revealed yet per the reveal mode.
    fn build_poll_view(poll: &Poll, me: &str) -> PollView {
        let mut counts = vec![0u32; poll.options.len()];
        let mut voters = vec![Vec::new(); poll.options.len()];
        for (user, sel) in &poll.votes {
            for &i in sel {
                if let Some(c) = counts.get_mut(i as usize) {
                    *c += 1;
                }
                // Never build a per-option voter list for an anonymous poll: those
                // keys are key-image pseudonyms, and a breakdown of them is exactly
                // what the poll promises not to produce. Counts still tally.
                if poll.anonymous {
                    continue;
                }
                if let Some(v) = voters.get_mut(i as usize) {
                    v.push(user.clone());
                }
            }
        }
        // An anonymous poll files our vote under our key image, not our name, so
        // look it up by whichever key we actually stored it under.
        let my_key = poll.my_tag.as_deref().unwrap_or(me);
        let mine = poll.votes.get(my_key).cloned().unwrap_or_default();
        let eff_closed = poll.is_closed();
        let am_owner = poll.author == me;
        let revealed = match poll.reveal {
            1 => poll.votes.contains_key(me), // after you vote
            2 => eff_closed,                  // everyone, after it closes
            3 => am_owner,                    // owner-only, live
            4 => am_owner && eff_closed,      // owner-only, after it closes
            _ => true,                        // always
        };
        PollView {
            question: poll.question.clone(),
            options: poll.options.clone(),
            counts,
            multi: poll.multi,
            reveal: poll.reveal,
            closed: eff_closed,
            mine,
            total: poll.votes.len() as u32,
            revealed,
            is_author: poll.author == me,
            closes_at: poll.closes_at.unwrap_or(0),
            voters,
            anonymous: poll.anonymous,
        }
    }

    pub fn conversation_history(&self, conv: &str) -> Vec<HistoryLine> {
        let me = self.username.clone().unwrap_or_default();
        self.conversations
            .iter()
            .find(|(id, _)| hex_id(id) == conv)
            .map(|(_, c)| {
                c.history
                    .iter()
                    .map(|l| HistoryLine {
                        id: hex::encode(l.id),
                        ts: l.ts,
                        user: l.from.clone(),
                        display: self.display_of(&l.from),
                        text: l.text.clone(),
                        mine: l.mine,
                        file: l.file.clone(),
                        system: l.system,
                        deleted: l.deleted,
                        reply_to: l.reply_to.map(hex::encode).unwrap_or_default(),
                        voice_ms: l.voice_ms.unwrap_or(0),
                        waveform: l.waveform.clone(),
                        reactions: c.reactions.get(&l.id).cloned().unwrap_or_default(),
                        edited: c.edited.contains(&l.id),
                        poll: c.polls.get(&l.id).map(|p| Self::build_poll_view(p, &me)),
                        pinned: c.pinned.contains(&l.id),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Local full-text search over decrypted message history. `conv = Some(hex)`
    /// scopes it to one conversation; `None` searches all of them. Matching is a
    /// case-insensitive substring over each line's text (a file line's text is its
    /// name), skipping deleted and system lines. Results are newest-first and
    /// capped. The server never sees this: history is decrypted, in memory, here.
    pub fn search_messages(&self, query: &str, conv: Option<&str>) -> Vec<SearchHit> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let me = self.username.clone().unwrap_or_default();
        let mut hits = Vec::new();
        for (id, c) in &self.conversations {
            // Deleted (hidden) conversations are excluded; everything else is
            // searchable, including archived and left ones.
            if c.visibility == Visibility::Deleted {
                continue;
            }
            let hex = hex_id(id);
            if let Some(only) = conv {
                if hex != only {
                    continue;
                }
            }
            let title = if c.local_only {
                c.title.clone()
            } else if c.kind == ConvKind::Dm {
                let peer = c
                    .members
                    .iter()
                    .find(|m| **m != me)
                    .cloned()
                    .unwrap_or_else(|| c.title.clone());
                self.display_of(&peer)
            } else {
                c.title.clone()
            };
            for l in &c.history {
                if l.deleted || l.system || l.text.is_empty() {
                    continue;
                }
                if !l.text.to_lowercase().contains(&q) {
                    continue;
                }
                hits.push(SearchHit {
                    conv: hex.clone(),
                    conv_title: title.clone(),
                    self_notes: c.local_only,
                    id: hex::encode(l.id),
                    ts: l.ts,
                    user: l.from.clone(),
                    display: self.display_of(&l.from),
                    text: l.text.clone(),
                    mine: l.mine,
                });
            }
        }
        hits.sort_by(|a, b| b.ts.cmp(&a.ts));
        hits.truncate(300);
        hits
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

    // ---- Workspaces ----------------------------------------------------------
    //
    // The op-log is applied only from the server's authoritative broadcast (never
    // optimistically), so every member -- submitter included -- converges on the
    // same linear history and a concurrent, now-stale op is simply rejected and
    // resigned rather than diverging local state.

    /// A read-only view of a workspace's replayed state, by hex id.
    pub fn workspace(&self, ws_hex: &str) -> Option<&enclave_crypto::workspace::WorkspaceState> {
        decode_offer_id(ws_hex).and_then(|id| self.workspaces.get(&id))
    }

    /// The workspaces we currently hold: `(hex id, name)`, for the sidebar rail.
    pub fn workspace_list(&self) -> Vec<(String, String)> {
        let mut list: Vec<(String, String)> = self
            .workspaces
            .iter()
            .map(|(id, s)| (hex::encode(id), s.name.clone()))
            .collect();
        list.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
        list
    }

    /// Create a workspace owned by us. Mints a random id, signs the genesis op,
    /// and submits it. State is populated when the server echoes the op back
    /// (surfaced as [`Event::WorkspacesChanged`]); the hex id is returned now so
    /// the caller can navigate to it once it appears.
    pub fn create_workspace(&mut self, name: &str) -> Result<String, ClientError> {
        let me = self.me()?;
        let id = new_transfer_id();
        let (op, wg) = {
            let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
            let op = enclave_crypto::workspace::sign_genesis(identity, &me, name, now_secs())?;
            // The WG MLS group that keys this workspace's public channels. Created
            // now (locally); other members join it via a Welcome when added.
            let wg = Group::create(identity)?;
            (op, wg)
        };
        self.workspace_groups.insert(id, wg);
        self.conn
            .send(ClientMsg::WorkspaceSubmitOp { workspace: id, op });
        Ok(hex::encode(id))
    }

    /// Add `handle` to a workspace: fetch their key package, add them to the WG
    /// MLS group, record them in the op-log, and deliver the Welcome + commit.
    /// The op is submitted first so the relay will route the Welcome to them.
    pub async fn workspace_add_member(
        &mut self,
        ws_hex: &str,
        handle: &str,
    ) -> Result<(), ClientError> {
        let id = decode_offer_id(ws_hex)
            .ok_or_else(|| ClientError::Workspace("bad workspace id".into()))?;
        let kp = self.fetch_key_package(handle).await?;
        let (add, member_key) = {
            let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
            let member_key = Group::key_package_signature_key(identity, &kp)?;
            let wg = self
                .workspace_groups
                .get_mut(&id)
                .ok_or_else(|| ClientError::Workspace("workspace group missing".into()))?;
            (wg.add_member(identity, &kp, handle)?, member_key)
        };
        self.workspace_submit(
            ws_hex,
            enclave_protocol::WorkspaceOp::AddMember {
                member: handle.to_string(),
                member_key,
            },
        )?;
        self.conn.send(ClientMsg::WorkspaceWelcome {
            workspace: id,
            to: handle.to_string(),
            welcome: Sealed(add.welcome),
        });
        self.conn.send(ClientMsg::WorkspaceCommit {
            workspace: id,
            commit: Sealed(add.commit),
        });
        Ok(())
    }

    /// Create a public text channel in a workspace; returns its hex id.
    pub fn create_channel(&mut self, ws_hex: &str, name: &str) -> Result<String, ClientError> {
        let channel = new_transfer_id();
        self.workspace_submit(
            ws_hex,
            enclave_protocol::WorkspaceOp::CreateChannel {
                channel,
                name: name.to_string(),
                kind: enclave_protocol::ChannelKind::Text,
                private: false,
                category: None,
            },
        )?;
        Ok(hex::encode(channel))
    }

    /// Post a text message to a channel: seal `(channel, id, text, ts)` under the
    /// WG group (so the relay sees neither the channel nor the text) and fan it to
    /// members. Records it locally and emits our own [`Event::ChannelMessage`].
    pub fn send_channel_post(
        &mut self,
        ws_hex: &str,
        channel_hex: &str,
        text: &str,
    ) -> Result<(), ClientError> {
        let me = self.me()?;
        let ws = decode_offer_id(ws_hex)
            .ok_or_else(|| ClientError::Workspace("bad workspace id".into()))?;
        let channel = decode_offer_id(channel_hex)
            .ok_or_else(|| ClientError::Workspace("bad channel id".into()))?;
        let msg_id = new_transfer_id();
        let ts = now_ms();
        let wire = ChannelWire {
            channel,
            id: msg_id,
            text: text.to_string(),
            ts,
        };
        let plaintext = bincode::serialize(&wire).unwrap_or_default();
        let sealed = {
            let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
            let wg = self
                .workspace_groups
                .get_mut(&ws)
                .ok_or_else(|| ClientError::Workspace("workspace group missing".into()))?;
            wg.encrypt_text(identity, &plaintext)?
        };
        self.channel_history
            .entry((ws, channel))
            .or_default()
            .push(ChannelMsg {
                id: msg_id,
                user: me.clone(),
                text: text.to_string(),
                ts,
                mine: true,
            });
        self.conn.send(ClientMsg::ChannelPost {
            workspace: ws,
            message: Sealed(sealed),
        });
        self.pending.push_back(Event::ChannelMessage {
            workspace: ws_hex.to_string(),
            channel: channel_hex.to_string(),
            id: hex::encode(msg_id),
            user: me,
            text: text.to_string(),
            ts,
            mine: true,
        });
        Ok(())
    }

    /// A channel's local message history, oldest first (for the UI and tests).
    pub fn channel_history(&self, ws_hex: &str, channel_hex: &str) -> Vec<ChannelLine> {
        match (decode_offer_id(ws_hex), decode_offer_id(channel_hex)) {
            (Some(ws), Some(ch)) => self
                .channel_history
                .get(&(ws, ch))
                .map(|v| {
                    v.iter()
                        .map(|m| ChannelLine {
                            id: hex::encode(m.id),
                            user: m.user.clone(),
                            text: m.text.clone(),
                            ts: m.ts,
                            mine: m.mine,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Join a WG from a Welcome we were sent when added to a workspace.
    fn join_workspace_group(&mut self, ws: [u8; 16], welcome: &[u8]) {
        let joined = self
            .identity
            .as_ref()
            .and_then(|id| Group::join(id, welcome).ok());
        if let Some(wg) = joined {
            self.workspace_groups.insert(ws, wg);
        }
    }

    /// Apply a WG MLS commit (add/remove) to advance our epoch.
    fn apply_workspace_commit(&mut self, ws: [u8; 16], commit: &[u8]) {
        if let (Some(id), Some(wg)) = (self.identity.as_ref(), self.workspace_groups.get_mut(&ws)) {
            let _ = wg.apply_commit(id, commit);
        }
    }

    /// Decrypt an incoming channel post via the WG and record it.
    fn receive_channel_post(&mut self, ws: [u8; 16], message: &[u8]) -> Option<Event> {
        let decoded = match (self.identity.as_ref(), self.workspace_groups.get_mut(&ws)) {
            (Some(id), Some(wg)) => wg.decrypt_text(id, message).ok(),
            _ => None,
        }?;
        let wire: ChannelWire = bincode::deserialize(&decoded.plaintext).ok()?;
        // Attribute to the MLS-authenticated sender, not the relay's `from`.
        let user = String::from_utf8_lossy(&decoded.sender).into_owned();
        self.channel_history
            .entry((ws, wire.channel))
            .or_default()
            .push(ChannelMsg {
                id: wire.id,
                user: user.clone(),
                text: wire.text.clone(),
                ts: wire.ts,
                mine: false,
            });
        Some(Event::ChannelMessage {
            workspace: hex::encode(ws),
            channel: hex::encode(wire.channel),
            id: hex::encode(wire.id),
            user,
            text: wire.text,
            ts: wire.ts,
            mine: false,
        })
    }

    /// Sign and submit one structural op (add/remove member, role, channel, ...)
    /// against a workspace we hold. Signed against our current known head; if the
    /// log has advanced under us the server rejects it and the caller re-issues.
    /// Not applied locally -- the echo advances our state.
    pub fn workspace_submit(
        &mut self,
        ws_hex: &str,
        op: enclave_protocol::WorkspaceOp,
    ) -> Result<(), ClientError> {
        let me = self.me()?;
        let id = decode_offer_id(ws_hex)
            .ok_or_else(|| ClientError::Workspace("bad workspace id".into()))?;
        let identity = self.identity.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let state = self
            .workspaces
            .get(&id)
            .ok_or_else(|| ClientError::Workspace("unknown workspace".into()))?;
        let signed = enclave_crypto::workspace::sign_op(identity, &me, state, now_secs(), op)?;
        self.conn.send(ClientMsg::WorkspaceSubmitOp {
            workspace: id,
            op: signed,
        });
        Ok(())
    }

    /// Apply op-log entries from the server -- the single place workspace state
    /// advances. Idempotent by `seq` (a re-broadcast echo of an op we already
    /// hold is ignored); on a gap (we are behind) it refetches the full log.
    fn apply_workspace_ops(
        &mut self,
        ws: [u8; 16],
        ops: Vec<enclave_protocol::SignedOp>,
    ) -> Option<Event> {
        let state = self.workspaces.entry(ws).or_default();
        let mut changed = false;
        for op in ops {
            match op.seq.cmp(&state.next_seq()) {
                std::cmp::Ordering::Less => {} // already applied (echo / dup)
                std::cmp::Ordering::Equal => {
                    if state.apply(&op).is_ok() {
                        changed = true;
                    }
                    // A verification failure here means the relay accepted an op
                    // we reject; we simply do not advance, keeping our view sound.
                }
                std::cmp::Ordering::Greater => {
                    // We are behind: request the whole log and stop applying this
                    // batch (the refetch will deliver a contiguous run).
                    self.conn.send(ClientMsg::WorkspaceFetch { workspace: ws });
                    break;
                }
            }
        }
        // Drop a workspace that ended up empty (e.g. a stray fetch of nothing).
        if self.workspaces.get(&ws).is_some_and(|s| s.owner.is_empty()) {
            self.workspaces.remove(&ws);
            return None;
        }
        changed.then_some(Event::WorkspacesChanged)
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
            // Persist conversations with a live group, plus Left ones (group torn
            // down, but their history is retained and readable on the Archived
            // page) and the local-only "Notes to self" scratchpad (never had a
            // group, but its notes must survive a restart). A still-pending DM
            // placeholder (group None, Active) is transient and re-created on the
            // next open, so it is not persisted.
            .filter(|(_, c)| c.group.is_some() || c.visibility == Visibility::Left || c.local_only)
            .map(|(routing, c)| session::PersistConv {
                routing_id: routing.0,
                mls_group_id: c.mls_group_id.clone(),
                is_dm: c.kind == ConvKind::Dm,
                title: c.title.clone(),
                members: c.members.clone(),
                verified: c.verified.clone(),
                disappearing_ms: c.disappearing_ms,
                visibility: c.visibility,
                local_only: c.local_only,
                reactions: c.reactions.iter().map(|(k, v)| (*k, v.clone())).collect(),
                edited: c.edited.iter().copied().collect(),
                polls: c.polls.iter().map(|(k, v)| (*k, v.into())).collect(),
                pinned: c.pinned.iter().copied().collect(),
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
                        system: l.system,
                        id: l.id,
                        ts: l.ts,
                        deleted: l.deleted,
                        reply_to: l.reply_to,
                        voice_ms: l.voice_ms,
                        waveform: l.waveform.clone(),
                    })
                    .collect(),
            })
            .collect();
        let data = session::SessionData {
            mls: identity.storage_snapshot(),
            conversations,
            next_seq: self.next_seq,
            // Persist un-acked reliable messages so one sent just before the app
            // closes is retransmitted on next launch, not lost.
            unacked: self
                .unacked
                .iter()
                .map(|(seq, p)| (*seq, p.msg.clone()))
                .collect(),
            seen_ids: self.seen.snapshot(),
            my_profile: self.my_profile.clone(),
            peer_profiles: self
                .profiles
                .iter()
                .map(|(u, p)| (u.clone(), p.clone()))
                .collect(),
            removed_me: self.removed_me.iter().cloned().collect(),
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
        // Restore reliable-delivery state first, so a message that was un-acked
        // when the app last closed is retransmitted on this launch (not lost).
        // Backdate its last-sent so the retransmit pump replays it promptly.
        self.next_seq = self.next_seq.max(data.next_seq);
        let now = Instant::now();
        let due = now.checked_sub(RETRANSMIT_AFTER).unwrap_or(now);
        for (seq, msg) in data.unacked {
            // A fresh stall clock (`first: now`) so a restart does not instantly
            // warn; `last: due` so the retransmit pump replays it promptly.
            self.unacked.entry(seq).or_insert(Pending {
                msg,
                first: now,
                last: due,
            });
        }
        self.seen.restore(data.seen_ids);
        // Restore our own profile and the cached peer profiles so names/avatars
        // render immediately, before any fresh broadcast arrives.
        self.my_profile = data.my_profile;
        // Restore (or keep the freshly-minted) voting seed, and publish its public
        // key in our profile so peers can build anonymous-poll rings.
        if !self.display.is_empty() && self.my_profile.display_name.is_empty() {
            // Migrate a pre-profile session's server-side display name into the
            // profile once, so upgrading users keep their name.
            self.my_profile.display_name = self.display.clone();
        }
        self.profiles = data.peer_profiles.into_iter().collect();
        self.removed_me = data.removed_me.into_iter().collect();
        if data.conversations.is_empty() {
            return;
        }
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        identity.restore_storage(data.mls);
        let mut loaded: Vec<(GroupId, Conversation)> = Vec::new();
        for pc in data.conversations {
            // A Left conversation has no MLS group to reload, only the retained
            // history; the local-only "Notes to self" scratchpad never had one.
            // All others (incl. Deleted, which stays a member) must reload their
            // group or be skipped (missing/corrupt state).
            let group = if pc.visibility == Visibility::Left || pc.local_only {
                None
            } else {
                match Group::load(identity, &pc.mls_group_id) {
                    Ok(g) => Some(g),
                    Err(_) => continue,
                }
            };
            let history = pc
                .history
                .into_iter()
                .map(|l| ChatLine {
                    id: l.id,
                    ts: l.ts,
                    from: l.from,
                    text: l.text,
                    mine: l.mine,
                    file: l.file.map(|f| FileRef {
                        name: f.name,
                        size: f.size,
                        path: f.path,
                    }),
                    system: l.system,
                    deleted: l.deleted,
                    reply_to: l.reply_to,
                    voice_ms: l.voice_ms,
                    waveform: l.waveform,
                })
                .collect();
            loaded.push((
                GroupId(pc.routing_id),
                Conversation {
                    group,
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
                    disappearing_ms: pc.disappearing_ms,
                    visibility: pc.visibility,
                    local_only: pc.local_only,
                    reactions: pc.reactions.into_iter().collect(),
                    edited: pc.edited.into_iter().collect(),
                    polls: pc.polls.into_iter().map(|(id, p)| (id, p.into())).collect(),
                    pinned: pc.pinned.into_iter().collect(),
                },
            ));
        }
        for (gid, conv) in loaded {
            // A Left conversation is no longer in its group: do not re-announce
            // routing for it (that would rejoin). Just keep the retained history.
            // (Deleted stays a member, so it DOES re-announce and keeps receiving,
            // which is how it reappears on a new message.) The local-only "Notes
            // to self" scratchpad has no group and MUST never touch the network,
            // so it is inserted without any routing announce.
            if conv.visibility == Visibility::Left || conv.local_only {
                self.conversations.insert(gid, conv);
                continue;
            }
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
                        // The username (stable identity); the UI resolves the
                        // display name and avatar from it, and keys per-user
                        // canvases by it, so a rename never orphans a tile.
                        from: sf.from,
                        data: sf.h264,
                        keyframe: sf.keyframe,
                        camera: sf.camera,
                    });
                }
                Src::Msg(msg) => {
                    // `DmRequested` is obsolete: DMs are now created directly by
                    // whoever opens one (see `open_dm`). We deliberately do NOT
                    // auto-create a group on this server-delivered nudge -- doing so
                    // would let a malicious server drive unbounded group creation +
                    // key-package fetches on our client. Ignore it.
                    if matches!(msg, ServerMsg::DmRequested { .. }) {
                        return None;
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
                let group_key = group.clone();
                let is_dm = name.is_empty();
                // Both sides of a DM may have created a group (if both opened it).
                // Converge on the one created by the smaller handle: if I already
                // have an established group here and my handle is smaller than the
                // inviter's, keep mine and ignore their Welcome -- they will adopt
                // mine when my Welcome reaches them.
                let have_group = self
                    .conversations
                    .get(&group)
                    .is_some_and(|c| c.group.is_some());
                if is_dm {
                    let me = self.username.clone().unwrap_or_default();
                    eprintln!(
                        "enclave: DM Welcome from {}; i_have_a_group={have_group} i_am_smaller={}",
                        from.0,
                        me.as_str() < from.0.as_str()
                    );
                    if have_group && me.as_str() < from.0.as_str() {
                        eprintln!(
                            "enclave: keeping my group, ignoring their Welcome (mine is canonical)"
                        );
                        return None;
                    }
                }
                let identity = self.identity.as_ref()?;
                let joined = match Group::join(identity, &message.0) {
                    Ok(j) => j,
                    Err(e) => {
                        eprintln!("enclave: DM Welcome join failed: {e}");
                        return Some(Event::Error(format!("join failed: {e}")));
                    }
                };
                if is_dm {
                    eprintln!("enclave: adopted the peer's DM group (converged)");
                }
                let mls_group_id = joined.mls_group_id();
                self.conn.send(ClientMsg::JoinGroup {
                    group: group.clone(),
                });
                match self.conversations.get_mut(&group) {
                    // Adopt the group (replacing our own if we had made one, which
                    // only happens on a both-opened-at-once DM the tie-break above
                    // resolved in the inviter's favor). If this conversation had
                    // been deleted/left, re-attaching its group RESTORES it: the
                    // retained history is still here, so mark it Active again.
                    Some(conv) => {
                        conv.group = Some(joined);
                        conv.mls_group_id = mls_group_id;
                        conv.visibility = Visibility::Active;
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
                                disappearing_ms: None,
                                visibility: Visibility::Active,
                                local_only: false,
                                reactions: HashMap::new(),
                                edited: HashSet::new(),
                                polls: HashMap::new(),
                                pinned: HashSet::new(),
                            },
                        );
                    }
                }
                // We just adopted this group, so any queued re-establish for it is
                // moot (we have converged); drop it to avoid needless churn.
                self.pending_reinvites.remove(&group_key);
                self.last_reinvite.remove(&group_key);
                self.save_session();
                // Give the members who just added us our profile (and, for a DM,
                // complete the mutual exchange the creator started).
                self.send_profile_to(&group_key);
                Some(Event::ConversationsChanged)
            }
            ServerMsg::Ballots {
                group,
                poll,
                ballots,
            } => {
                // The server released a buffered poll (a deadline passed, or its
                // owner closed it). Open each ballot with the poll's shared key,
                // apply the votes -- attributed to the server's authenticated
                // submitter (device == username) -- and mark the poll closed here.
                let me = self.username.clone().unwrap_or_default();
                let view = {
                    let conv = self.conversations.get_mut(&group)?;
                    let p = conv.polls.get_mut(&poll)?;
                    let key = match p.ballot_key {
                        Some(k) => k,
                        None => return None, // not a buffered poll we know
                    };
                    p.closed = true;
                    for (dev, sealed) in ballots {
                        // For an anonymous poll the ballot is a ring-signed AnonBallot:
                        // verify the signature against the ring, then key the vote by
                        // the (unlinkable-to-identity) key image. Otherwise the ballot
                        // is the plain sealed choice, keyed by its submitter.
                        let (choice_bytes, voter_key) = if p.anonymous {
                            let Some(ab) = transfer::AnonBallot::decode(&sealed.0) else {
                                continue;
                            };
                            if !enclave_crypto::ring_verify(
                                &ab.sealed_choice,
                                &poll,
                                &p.ring,
                                &ab.sig,
                            ) {
                                continue; // a forged or non-member ballot: reject
                            }
                            (ab.sealed_choice, hex::encode(ab.sig.key_image))
                        } else {
                            (sealed.0.clone(), dev.0.clone())
                        };
                        let Ok(pt) = enclave_crypto::open_ballot(&key, &poll, &choice_bytes) else {
                            continue;
                        };
                        let Some(vb) = transfer::VoteBody::decode(&pt) else {
                            continue;
                        };
                        let mut sel: Vec<u8> = vb
                            .options
                            .into_iter()
                            .filter(|&i| (i as usize) < p.options.len())
                            .collect();
                        sel.sort_unstable();
                        sel.dedup();
                        if !p.multi {
                            sel.truncate(1);
                        }
                        if sel.is_empty() {
                            p.votes.remove(&voter_key);
                        } else {
                            p.votes.insert(voter_key, sel);
                        }
                    }
                    Self::build_poll_view(p, &me)
                };
                self.save_session();
                return Some(Event::PollUpdated {
                    conv: hex_id(&group),
                    id: hex::encode(poll),
                    poll: view,
                });
            }
            ServerMsg::Text { group, message, .. } => {
                // Decrypt one sealed part and hand it to this conversation's
                // reassembler, all inside a tight borrow of `conv` so the rest
                // of the handler can touch `self` freely. A message/file becomes
                // visible only once its last part arrives.
                // Decrypt under a short borrow, so a heal (which needs &mut self)
                // can run after it if the ratchet desynced.
                let decrypted = {
                    let identity = self.identity.as_ref()?;
                    let conv = self.conversations.get_mut(&group)?;
                    let g = conv.group.as_mut()?;
                    g.decrypt_text(identity, &message.0)
                };
                let tm = match decrypted {
                    Ok(tm) => tm,
                    // A message we cannot open (a transient MLS epoch skew
                    // during a rekey, an out-of-order handshake, a stray frame
                    // for a group we are mid-joining) is dropped, not shown:
                    // it is not user-actionable, and profile broadcasts made
                    // these common. Reliable delivery + last-writer-wins mean
                    // anything that matters is re-sent. Log once for triage.
                    Err(e) => {
                        eprintln!("enclave: dropped an undecryptable message: {e}");
                        // If the ratchet has desynced (a legacy conversation whose
                        // file chunks rode the ratchet), heal it with a rekey so
                        // the conversation comes back to life.
                        if is_ratchet_desync(&e) {
                            self.heal_group(&group);
                        } else if is_group_fork(&e) {
                            // The DM forked (peer on a different MLS group): the
                            // smaller handle re-establishes it.
                            self.queue_dm_reinvite(&group);
                        }
                        return None;
                    }
                };
                let (username, part_summary, complete) = {
                    let conv = self.conversations.get_mut(&group)?;
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
                    let summary = (part.total > 1).then(|| {
                        (
                            hex::encode(part.id),
                            "message".to_string(),
                            part.index,
                            part.total,
                        )
                    });
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

                // A profile update rides the same sealed channel: apply it,
                // attributed to the authenticated sender, and stop (it is not a
                // chat line). Its own version dedups it, so it skips the text
                // seen-set below.
                if matches!(done.meta, TransferMeta::Profile) {
                    return self.on_profile_update(&username, &done.data);
                }
                // A "delete for everyone" control: tombstone the referenced line,
                // but ONLY if its author is this sealed message's authenticated
                // sender -- a member can never delete another member's message.
                if matches!(done.meta, TransferMeta::Delete) {
                    let mut target = [0u8; 16];
                    if done.data.len() == 16 {
                        target.copy_from_slice(&done.data);
                        if let Some(conv) = self.conversations.get_mut(&group) {
                            if let Some(l) = conv
                                .history
                                .iter_mut()
                                .find(|l| l.id == target && l.from == username)
                            {
                                l.deleted = true;
                                l.text.clear();
                                l.file = None;
                                self.save_session();
                                return Some(Event::MessageDeleted {
                                    conv: hex_id(&group),
                                    id: hex::encode(target),
                                });
                            }
                        }
                    }
                    return None;
                }
                // An emoji-reaction toggle. The reactor is the authenticated
                // sender (never a payload field), so a member can only ever add or
                // remove ITS OWN reaction. Applies to any message in the group.
                if matches!(done.meta, TransferMeta::React) {
                    let body = transfer::ReactBody::decode(&done.data)?;
                    if body.emoji.is_empty() || body.emoji.len() > transfer::MAX_REACTION_BYTES {
                        return None;
                    }
                    let reactions = {
                        let conv = self.conversations.get_mut(&group)?;
                        Self::apply_reaction(
                            &mut conv.reactions,
                            body.target,
                            &username,
                            &body.emoji,
                            body.add,
                        )
                    };
                    self.save_session();
                    return Some(Event::ReactionsChanged {
                        conv: hex_id(&group),
                        id: hex::encode(body.target),
                        reactions,
                    });
                }
                // An "edit this message" control: replace the target's text, but
                // ONLY if its author is this sealed message's authenticated sender
                // -- a member can never edit another member's message.
                if matches!(done.meta, TransferMeta::Edit) {
                    let body = transfer::EditBody::decode(&done.data)?;
                    if let Some(conv) = self.conversations.get_mut(&group) {
                        if let Some(l) = conv
                            .history
                            .iter_mut()
                            .find(|l| l.id == body.target && l.from == username && !l.deleted)
                        {
                            l.text = body.text.clone();
                            conv.edited.insert(body.target);
                            self.save_session();
                            return Some(Event::MessageEdited {
                                conv: hex_id(&group),
                                id: hex::encode(body.target),
                                text: body.text,
                            });
                        }
                    }
                    return None;
                }
                // A poll was posted: add its line and hand the UI a poll card.
                if matches!(done.meta, TransferMeta::Poll) {
                    if !self.seen.insert(done.id) {
                        return None; // a resent duplicate; show it once
                    }
                    let body = transfer::PollBody::decode(&done.data)?;
                    if !body.valid() {
                        return None;
                    }
                    let me = self.username.clone().unwrap_or_default();
                    let ts = now_ms();
                    let poll = Poll {
                        question: body.question.clone(),
                        options: body.options.clone(),
                        multi: body.multi,
                        reveal: body.reveal,
                        closed: false,
                        closes_at: body.closes_at,
                        author: username.clone(),
                        votes: HashMap::new(),
                        ballot_key: body.ballot_key,
                        anonymous: body.anonymous,
                        ring: body.ring.clone(),
                        my_tag: None,
                    };
                    let view = Self::build_poll_view(&poll, &me);
                    if let Some(conv) = self.conversations.get_mut(&group) {
                        conv.polls.insert(done.id, poll);
                        conv.history.push(ChatLine {
                            id: done.id,
                            ts,
                            from: username.clone(),
                            text: body.question,
                            mine: false,
                            file: None,
                            system: false,
                            deleted: false,
                            reply_to: None,
                            voice_ms: None,
                            waveform: Vec::new(),
                        });
                    }
                    self.save_session();
                    self.note_activity(&group);
                    return Some(Event::PollPosted {
                        conv: hex_id(&group),
                        id: hex::encode(done.id),
                        ts,
                        from: from_display,
                        user: username,
                        mine: false,
                        poll: view,
                    });
                }
                // A vote on a poll: record the sender's choice (their own, always),
                // then hand the UI the refreshed tallies.
                if matches!(done.meta, TransferMeta::Vote) {
                    let body = transfer::VoteBody::decode(&done.data)?;
                    let me = self.username.clone().unwrap_or_default();
                    let view = {
                        let conv = self.conversations.get_mut(&group)?;
                        let poll = conv.polls.get_mut(&body.target)?;
                        if poll.is_closed() {
                            return None; // ignore votes after close/expiry
                        }
                        let mut sel: Vec<u8> = body
                            .options
                            .into_iter()
                            .filter(|&i| (i as usize) < poll.options.len())
                            .collect();
                        sel.sort_unstable();
                        sel.dedup();
                        if !poll.multi {
                            sel.truncate(1);
                        }
                        if sel.is_empty() {
                            poll.votes.remove(&username);
                        } else {
                            poll.votes.insert(username.clone(), sel);
                        }
                        Self::build_poll_view(poll, &me)
                    };
                    self.save_session();
                    return Some(Event::PollUpdated {
                        conv: hex_id(&group),
                        id: hex::encode(body.target),
                        poll: view,
                    });
                }
                // A "close poll" control: honored only if the poll's author is this
                // sealed message's authenticated sender.
                if matches!(done.meta, TransferMeta::PollClose) {
                    if done.data.len() != 16 {
                        return None;
                    }
                    let mut target = [0u8; 16];
                    target.copy_from_slice(&done.data);
                    let me = self.username.clone().unwrap_or_default();
                    let view = {
                        let conv = self.conversations.get_mut(&group)?;
                        let poll = conv.polls.get_mut(&target)?;
                        if poll.author != username {
                            return None;
                        }
                        poll.closed = true;
                        Self::build_poll_view(poll, &me)
                    };
                    self.save_session();
                    return Some(Event::PollUpdated {
                        conv: hex_id(&group),
                        id: hex::encode(target),
                        poll: view,
                    });
                }
                // A pin/unpin control: shared, so any member's toggle applies.
                if matches!(done.meta, TransferMeta::Pin) {
                    let body = transfer::PinBody::decode(&done.data)?;
                    if let Some(conv) = self.conversations.get_mut(&group) {
                        // Only pin a message we actually have.
                        if conv.history.iter().any(|l| l.id == body.target) {
                            if body.pinned {
                                conv.pinned.insert(body.target);
                            } else {
                                conv.pinned.remove(&body.target);
                            }
                            self.save_session();
                            return Some(Event::PinsChanged {
                                conv: hex_id(&group),
                                id: hex::encode(body.target),
                                pinned: body.pinned,
                            });
                        }
                    }
                    return None;
                }
                // The peer changed the disappearing-messages setting: adopt it.
                if matches!(done.meta, TransferMeta::Disappear) {
                    let ms = if done.data.len() == 4 {
                        u32::from_le_bytes([done.data[0], done.data[1], done.data[2], done.data[3]])
                    } else {
                        0
                    };
                    if let Some(conv) = self.conversations.get_mut(&group) {
                        conv.disappearing_ms = if ms == 0 { None } else { Some(ms) };
                    }
                    self.save_session();
                    return Some(Event::DisappearingChanged {
                        conv: hex_id(&group),
                        ms,
                    });
                }
                // A voice message: cache the clip and hand the UI a player.
                if matches!(done.meta, TransferMeta::Voice) {
                    if !self.seen.insert(done.id) {
                        return None; // a resent duplicate; show it once
                    }
                    let clip = transfer::VoiceClip::decode(&done.data)?;
                    let path = self.store_voice_at(&hex::encode(done.id), &done.data)?;
                    let ts = now_ms();
                    if let Some(conv) = self.conversations.get_mut(&group) {
                        conv.history.push(ChatLine {
                            id: done.id,
                            ts,
                            from: username.clone(),
                            text: String::new(),
                            mine: false,
                            file: Some(FileRef {
                                name: "Voice message".into(),
                                size: done.data.len() as u64,
                                path: path.clone(),
                            }),
                            system: false,
                            deleted: false,
                            reply_to: None,
                            voice_ms: Some(clip.duration_ms),
                            waveform: clip.waveform.clone(),
                        });
                    }
                    self.save_session();
                    self.note_activity(&group);
                    return Some(Event::VoiceMessage {
                        conv: hex_id(&group),
                        id: hex::encode(done.id),
                        ts,
                        from: from_display,
                        user: username,
                        path,
                        duration_ms: clip.duration_ms,
                        waveform: clip.waveform.clone(),
                        mine: false,
                    });
                }
                // Only Text transfers reach here (File-meta parts were dropped
                // above); reject anything else defensively rather than treat it
                // as text.
                if !matches!(done.meta, TransferMeta::Text) {
                    return None;
                }
                // Dedup a message that was fully resent (a retransmit whose
                // earlier delivery's ack was lost): show it exactly once.
                if !self.seen.insert(done.id) {
                    return None;
                }
                // Decode the structured body (text + optional reply target). Fall
                // back to treating the raw bytes as text for resilience.
                let (text, reply_to) = match transfer::TextBody::decode(&done.data) {
                    Some(b) => (b.text, b.reply_to),
                    None => (String::from_utf8_lossy(&done.data).into_owned(), None),
                };
                let ts = now_ms();
                if let Some(conv) = self.conversations.get_mut(&group) {
                    conv.history.push(ChatLine {
                        id: done.id,
                        ts,
                        from: username.clone(),
                        text: text.clone(),
                        mine: false,
                        file: None,
                        system: false,
                        deleted: false,
                        reply_to,
                        voice_ms: None,
                        waveform: Vec::new(),
                    });
                }
                self.save_session();
                self.note_activity(&group);
                Some(Event::Message {
                    conv: hex_id(&group),
                    id: hex::encode(done.id),
                    ts,
                    reply_to: reply_to.map(hex::encode).unwrap_or_default(),
                    from: from_display,
                    user: username,
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
            ServerMsg::FileChunk {
                offer_id,
                from: _,
                index,
                data,
            } => self.handle_file_chunk(offer_id, index, data),
            ServerMsg::FileComplete { offer_id, .. } => self.handle_file_complete(offer_id),
            ServerMsg::Ack { seq } => {
                // The server durably accepted this reliable message: stop tracking
                // it for retransmission.
                self.unacked.remove(&seq);
                None
            }
            ServerMsg::Avatar { addr, data } => {
                // The reply to one of our FetchAvatar requests. Use the key we
                // stashed when asking, verify the returned bytes hash to `addr`
                // (open_blob does this) and decrypt them, then cache the image and
                // re-render whoever it belongs to. Failures are logged (not
                // toasted) and the tile keeps its initials; a later profile
                // update re-triggers the fetch.
                let key = self.pending_avatars.remove(&addr)?;
                let Some(bytes) = data else {
                    eprintln!("enclave: avatar {} not found on server", hex::encode(addr));
                    return None;
                };
                match enclave_crypto::open_blob(&bytes, &addr, &key) {
                    Ok(image) => {
                        self.cache_avatar(&addr, &image);
                        self.user_with_avatar(&addr)
                            .map(|user| Event::ProfileChanged { user })
                    }
                    Err(e) => {
                        eprintln!("enclave: avatar {} failed to open: {e}", hex::encode(addr));
                        None
                    }
                }
            }
            ServerMsg::Mls { group, message, .. } => {
                let identity = self.identity.as_ref()?;
                let me = self.username.clone().unwrap_or_default();
                // Apply the commit; if it removed us, take the now-dead group out to
                // delete its state (so a rejoin can recreate it) and mark it Left.
                // The displayed roster is driven by the server's GroupMembers, not
                // this leaf tree, so we do not sync members here.
                let removed_group: Option<Group> = {
                    let conv = self.conversations.get_mut(&group)?;
                    let apply = {
                        let g = conv.group.as_mut()?;
                        g.apply_commit(identity, &message.0)
                            .map(|()| g.is_member(&me))
                    };
                    match apply {
                        Ok(true) => None,
                        Ok(false) => {
                            conv.visibility = Visibility::Left;
                            conv.group.take()
                        }
                        Err(_) => return None,
                    }
                };
                let removed = removed_group.is_some();
                if let Some(g) = removed_group {
                    let _ = g.delete(identity);
                }
                self.save_session();
                if !removed {
                    // Membership changed: re-announce our profile to the group so a
                    // member who just joined receives it (the version dedups it for
                    // members who already had it).
                    self.send_profile_to(&group);
                }
                Some(Event::ConversationsChanged)
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
                // Anyone we are friends with again is no longer "removed us".
                let friend_names: Vec<String> =
                    self.friends.iter().map(|f| f.username.clone()).collect();
                self.removed_me.retain(|h| !friend_names.contains(h));
                Some(Event::FriendsChanged)
            }
            ServerMsg::FriendRequestReceived { from } => {
                // Auto-reconnect ONLY when they removed us: a re-add from someone
                // who dropped us reconnects silently (the counter-add case) and
                // restores the DM. A re-add from someone WE removed is surfaced as
                // a normal request to accept or decline.
                if self.removed_me.contains(&from) {
                    self.accept_friend(&from);
                    return Some(Event::FriendsChanged);
                }
                Some(Event::FriendRequest { from })
            }
            ServerMsg::FriendRemoved { handle } => {
                // They removed us: remember the direction so a later re-add from
                // them auto-reconnects. The conversation and its history stay; only
                // sending pauses until reconnected.
                self.removed_me.insert(handle);
                Some(Event::FriendsChanged)
            }
            ServerMsg::WorkspaceOps { workspace, ops } => self.apply_workspace_ops(workspace, ops),
            ServerMsg::WorkspaceWelcome {
                workspace, welcome, ..
            } => {
                self.join_workspace_group(workspace, &welcome.0);
                None
            }
            ServerMsg::WorkspaceCommit {
                workspace, commit, ..
            } => {
                self.apply_workspace_commit(workspace, &commit.0);
                None
            }
            ServerMsg::ChannelPost {
                workspace, message, ..
            } => self.receive_channel_post(workspace, &message.0),
            ServerMsg::Workspaces { workspaces } => {
                // Fetch the full log for any workspace we do not yet hold, so a
                // fresh login / new device catches up. Known ones are already live.
                for w in &workspaces {
                    if !self.workspaces.contains_key(&w.id) {
                        self.conn
                            .send(ClientMsg::WorkspaceFetch { workspace: w.id });
                    }
                }
                None
            }
            ServerMsg::GroupMembers { group, members } => {
                // The server's authoritative routing membership for a GROUP. It is
                // the source of truth for the displayed member list/count (a leaver
                // can't be removed from the MLS leaf tree while offline, but the
                // server always knows). DMs keep their fixed [me, peer] roster.
                if let Some(conv) = self.conversations.get_mut(&group) {
                    if conv.kind == ConvKind::Group {
                        conv.members = members;
                        self.save_session();
                        return Some(Event::ConversationsChanged);
                    }
                }
                None
            }
            ServerMsg::RemovedFromGroup { group } => {
                // A member removed us from this group. Keep the history readable
                // but tear down the dead channel (deleting the MLS state so a
                // future rejoin can recreate it) and mark it Left (read-only).
                let taken = self.conversations.get_mut(&group).and_then(|c| {
                    c.visibility = Visibility::Left;
                    c.group.take()
                });
                if taken.is_some() {
                    if let (Some(g), Some(identity)) = (taken, self.identity.as_ref()) {
                        let _ = g.delete(identity);
                    }
                    self.save_session();
                    return Some(Event::ConversationsChanged);
                }
                None
            }
            // The authoritative list follows in a Friends snapshot; surface the
            // change so the UI refreshes.
            ServerMsg::FriendAccepted { .. } => Some(Event::FriendsChanged),
            ServerMsg::CallOffer { group, from } => Some(Event::CallOffer {
                conv: hex_id(&group),
                from: self.display_of(&from),
            }),
            ServerMsg::CallParticipants {
                group,
                participants,
            } => Some(Event::CallParticipants {
                conv: hex_id(&group),
                // Usernames (stable identity); the UI resolves display names for
                // the nameplates and matches our own entry by username, so a
                // rename can never drop us out of the participant tiles.
                participants,
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

/// The stable routing id of our own "Notes to self" scratchpad. Derived from our
/// username under a distinct domain so there is exactly one per account and it
/// can never collide with a DM id (`enclave-dm`) or a random group id. Nothing is
/// ever routed to it -- the id only keys the local conversation map.
fn derive_self_id(me: &str) -> GroupId {
    let mut h = Sha256::new();
    h.update(b"enclave-self\0");
    h.update(me.as_bytes());
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

/// Wall-clock now in unix milliseconds, for message timestamps. Zero if the
/// clock is before the epoch (unreachable in practice).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wall-clock now in unix seconds, for workspace op timestamps.
fn now_secs() -> u64 {
    now_ms() / 1000
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
/// PRIMITIVE (with `reserve_download`): safe naming of an attacker-controlled
/// received filename -- no path traversal, no overwrite.
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
fn reserve_download(
    dir: &std::path::Path,
    name: &str,
) -> std::io::Result<(std::fs::File, PathBuf)> {
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
