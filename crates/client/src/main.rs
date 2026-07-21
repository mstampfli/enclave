//! Enclave client: a self-contained native window (wry: WebView2 on Windows,
//! WebKitGTK on Linux). The UI is bundled into the binary and driven over an
//! IPC bridge; all crypto, keys, and transport live in Rust
//! ([`enclave_client::Client`]).
//!
//! The controller runs on its own thread with a Tokio runtime; the tao event
//! loop owns the WebView on the main thread and shuttles events between them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Shared index mapping a message id (hex) to the local path of the image file it
/// carries, so the `enclave://localhost/media/<id>` route can serve a thumbnail
/// for a file that is actually in our history -- never an arbitrary path.
type SharedMedia = Arc<Mutex<HashMap<String, PathBuf>>>;

/// Register the active conversation's file paths into the media index (accumulates
/// across conversations; ids are unique). The route decides at serve time whether
/// the bytes are an image, so registering every file is safe.
fn reindex_media(c: &Client, index: &SharedMedia) {
    let Some(id) = c.active_id() else { return };
    if let Ok(mut m) = index.lock() {
        for l in c.conversation_history(&id) {
            if let Some(f) = &l.file {
                m.insert(l.id.clone(), PathBuf::from(&f.path));
            }
        }
    }
}

/// Sniff a common image type from the leading bytes, or `None` if it is not one
/// we will serve. Keeps the media route to images only.
fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() > 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

use enclave_client::{Client, Event, Reaction};
use enclave_protocol::{Friend, Presence};
use std::borrow::Cow;

use tao::event::{Event as TaoEvent, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
#[cfg(target_os = "linux")]
use tao::platform::unix::WindowExtUnix;
use tao::window::WindowBuilder;
use tokio::sync::mpsc;
use wry::http::Request;
use wry::WebViewBuilder;
#[cfg(target_os = "linux")]
use wry::WebViewBuilderExtUnix;
#[cfg(windows)]
use wry::WebViewBuilderExtWindows;

const UI_HTML: &str = include_str!("ui/index.html");

/// Commands the UI sends to the core.
#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum UiCommand {
    /// The UI booted; `webcodecs` reports whether the WebView can decode
    /// H.264 (WebCodecs), i.e. whether watching shares/cameras will work.
    UiReady {
        webcodecs: bool,
    },
    CreateAccount {
        server: String,
        username: String,
        display: String,
        password: String,
    },
    Login {
        server: String,
        username: String,
        password: String,
    },
    Logout,
    /// Change our display name (now end-to-end: sealed, server-blind).
    SetDisplayName {
        display: String,
    },
    /// Set our custom status: a status emoji and free text (either may be empty).
    SetCustomStatus {
        emoji: String,
        text: String,
    },
    /// Set our personal accent color ("#rrggbb", or "" for the app default).
    SetAccent {
        accent: String,
    },
    /// Set our short bio / about line.
    SetBio {
        bio: String,
    },
    /// Replace our avatar with a base64 image (already downscaled + re-encoded by
    /// the UI). `mime` is the image type (e.g. "image/jpeg").
    SetAvatar {
        data: String,
        mime: String,
    },
    /// Remove our avatar (back to initials).
    ClearAvatar,
    /// Back up the encrypted session to a discoverable file.
    ExportSession,
    /// Import a session file (same account + password) from `path`.
    ImportSession {
        path: String,
    },
    /// The user compared the safety number out of band and it matched.
    MarkVerified,
    /// Join the active conversation's voice call.
    StartCall,
    /// Leave the current voice call.
    LeaveCall,
    /// Decline an incoming call in conversation `conv` (hex id).
    DeclineCall {
        conv: String,
    },
    /// Report the shareable screens, windows, and cameras for the source picker.
    ListShareSources,
    /// Start sharing a chosen source: "monitor:N", "window:HWND", or "camera:N".
    /// `audio` also shares that source's audio (per-app for a window, whole
    /// system for a monitor); ignored for cameras.
    StartShare {
        source: String,
        audio: bool,
    },
    /// Stop sharing the screen or window (and any shared audio).
    StopScreenShare,
    /// Stop sharing the camera.
    StopCamera,
    /// Mute or unmute the microphone.
    SetMuted {
        muted: bool,
    },
    /// Deafen or undeafen (mute incoming audio).
    SetDeafened {
        deafened: bool,
    },
    /// Report the available audio devices + current selection (settings modal).
    ListAudioDevices,
    /// Choose the microphone (empty string = host default).
    SetInputDevice {
        name: String,
    },
    /// Choose the speaker (empty string = host default).
    SetOutputDevice {
        name: String,
    },
    /// Open (or focus) a 1:1 DM with a friend handle.
    OpenDm {
        handle: String,
    },
    /// Open (creating on first use) the local-only "Notes to self" scratchpad.
    OpenSelfNotes,
    /// Ask for the groups we share with `handle` (to list on their profile).
    RequestSharedGroups {
        handle: String,
    },
    /// Create a named group with the given member handles.
    CreateGroup {
        name: String,
        members: Vec<String>,
    },
    /// Add a friend to the active named group.
    AddToGroup {
        handle: String,
    },
    /// Delete a conversation (hex id): it disappears but stays a member, so it
    /// reappears on a new message or when reopened. Keeps the group + history.
    DeleteConversation {
        conv: String,
    },
    /// Truly leave a group (hex id): stop receiving; history stays readable on
    /// the Archived page. Rejoin only if re-invited.
    LeaveGroup {
        conv: String,
    },
    /// Hide a conversation (hex id) to the Archived page without any data change;
    /// it returns on the next message or when reopened.
    ArchiveConversation {
        conv: String,
    },
    /// Return an archived conversation (hex id) to the live list.
    UnarchiveConversation {
        conv: String,
    },
    /// Wipe a conversation's (hex id) message history, keeping the channel.
    ClearHistory {
        conv: String,
    },
    /// Remove a member (username) from a group (hex id).
    RemoveMember {
        conv: String,
        member: String,
    },
    /// Focus a conversation by its id.
    SwitchConversation {
        conv: String,
    },
    /// The UI closed the open chat (back to the home view). Clears the core's
    /// active conversation so a later refresh does not re-open it.
    CloseConversation,
    SendText {
        text: String,
        /// Hex id of the message being replied to, or empty for a normal message.
        #[serde(default)]
        reply_to: String,
    },
    /// Delete a message. `everyone` (only for our own message) also withdraws it
    /// for the other members; otherwise it is deleted just for us.
    DeleteMessage {
        conv: String,
        id: String,
        everyone: bool,
    },
    /// Toggle our emoji reaction on a message (add if absent, remove if present).
    React {
        conv: String,
        id: String,
        emoji: String,
    },
    /// Edit one of our own text messages, replacing its text.
    EditMessage {
        conv: String,
        id: String,
        text: String,
    },
    /// Search message history locally. `conv` scopes it to one conversation;
    /// null/absent searches all of them. Replies with `SearchResults`.
    SearchMessages {
        query: String,
        #[serde(default)]
        conv: Option<String>,
    },
    /// Post a poll to the active conversation. `reveal` is 0 (always), 1 (after
    /// you vote), or 2 (after the creator closes).
    CreatePoll {
        question: String,
        options: Vec<String>,
        multi: bool,
        reveal: u8,
        #[serde(default)]
        duration_ms: u64,
        #[serde(default)]
        anonymous: bool,
    },
    /// Cast/change/retract our vote on a poll (`options` = chosen indices; empty
    /// retracts). Single-choice polls keep at most one.
    VotePoll {
        conv: String,
        id: String,
        options: Vec<u8>,
    },
    /// Close a poll we created (no more votes; reveals results for reveal mode 2).
    ClosePoll {
        conv: String,
        id: String,
    },
    /// Pin or unpin a message for the whole conversation (pins are shared).
    PinMessage {
        conv: String,
        id: String,
        pinned: bool,
    },
    /// Turn disappearing messages on (ms) or off (0) for a conversation.
    SetDisappearing {
        conv: String,
        ms: u32,
    },
    /// Turn group history sharing on or off (new members can read messages from
    /// when it was enabled). No forward secrecy on the stored copies while on.
    SetGroupHistory {
        conv: String,
        enable: bool,
    },
    /// Start recording a voice message for the active conversation.
    StartVoice,
    /// Stop recording and hold it for preview (does not send).
    StopVoice,
    /// Send the previewed (stopped) voice message.
    SendVoice,
    /// Discard the in-progress recording or the previewed voice message.
    CancelVoice,
    /// Play a received (or sent, or previewed) voice clip at `path`, starting
    /// `offset_ms` into it (for resuming a paused message).
    PlayVoice {
        path: String,
        #[serde(default)]
        offset_ms: u32,
    },
    /// Stop/pause voice playback at once.
    StopVoicePlayback,
    /// Open a native multi-file picker; the chosen files are ATTACHED to the
    /// composer (an `AttachFiles` event), not sent, so the user can add a message
    /// and more files before sending.
    PickFiles,
    /// Attach specific paths (from native drag-and-drop) to the composer: the core
    /// stats them and replies with `AttachFiles`. Bytes never cross this bridge.
    AttachPaths {
        paths: Vec<String>,
    },
    /// Offer one attached file (from the composer tray) to the active
    /// conversation. `live` streams it in real time; otherwise it is stored.
    SendFilePath {
        path: String,
        #[serde(default)]
        live: bool,
    },
    /// Open a received (or sent) file with the OS default application. `path`
    /// must be a path the core previously reported; the UI never invents one.
    OpenFile {
        path: String,
    },
    /// Open an http(s) link from a message in the default browser (explicit click).
    OpenLink {
        url: String,
    },
    /// Consent to download a file that was offered to us (`offer_id` from a
    /// FileOffered event). Nothing was downloaded until this.
    AcceptFile {
        offer_id: String,
    },
    /// Refuse a file that was offered to us for good; declining is final.
    DeclineFile {
        offer_id: String,
    },
    /// Abort our in-progress download but keep the offer, so it can be downloaded
    /// again (until the sender withdraws it or goes offline).
    AbortFile {
        offer_id: String,
    },
    /// Withdraw a file we offered: stop sharing it with the recipients.
    CancelFile {
        offer_id: String,
    },
    /// Send a friend request to a full handle.
    AddFriend {
        user: String,
    },
    AcceptFriend {
        handle: String,
    },
    DeclineFriend {
        handle: String,
    },
    RemoveFriend {
        handle: String,
    },
    SetPresence {
        status: String,
    },

    // ---- Workspaces ----
    CreateWorkspace {
        name: String,
    },
    CreateChannel {
        workspace: String,
        name: String,
        #[serde(default)]
        category: Option<String>,
    },
    CreateVoiceChannel {
        workspace: String,
        name: String,
        #[serde(default)]
        category: Option<String>,
    },
    CreatePrivateChannel {
        workspace: String,
        name: String,
        #[serde(default)]
        category: Option<String>,
        /// A private voice channel (its own MLS group keys the call) when true.
        #[serde(default)]
        voice: bool,
    },
    AddWorkspaceMember {
        workspace: String,
        handle: String,
    },
    RemoveWorkspaceMember {
        workspace: String,
        handle: String,
    },
    AddChannelMember {
        workspace: String,
        channel: String,
        handle: String,
    },
    /// Create a custom role with the given permission tokens.
    CreateRole {
        workspace: String,
        name: String,
        permissions: Vec<String>,
    },
    /// Change a role's name and permission set.
    EditRole {
        workspace: String,
        role: String,
        name: String,
        permissions: Vec<String>,
    },
    /// Delete a role (removed from everyone who had it).
    DeleteRole {
        workspace: String,
        role: String,
    },
    /// Assign a role to a member.
    AssignRole {
        workspace: String,
        handle: String,
        role: String,
    },
    /// Remove a role from a member.
    UnassignRole {
        workspace: String,
        handle: String,
        role: String,
    },
    CreateCategory {
        workspace: String,
        name: String,
    },
    /// Move a channel under a category (drag onto a category), or to the top
    /// level when `category` is absent.
    MoveChannel {
        workspace: String,
        channel: String,
        #[serde(default)]
        category: Option<String>,
    },
    /// Nest a category under another (drag onto a category), or to the top level
    /// when `parent` is absent.
    MoveCategory {
        workspace: String,
        category: String,
        #[serde(default)]
        parent: Option<String>,
    },
    SendChannelPost {
        workspace: String,
        channel: String,
        text: String,
    },
    /// Load a text channel's history (op-log gives structure; messages come via
    /// the channel keys + backfill). Emits the channel's messages.
    OpenChannel {
        workspace: String,
        channel: String,
    },
    /// Fetch the page of channel history just older than the oldest we hold, for
    /// scroll-up "load older".
    LoadOlderChannel {
        workspace: String,
        channel: String,
    },
    JoinVoice {
        workspace: String,
        channel: String,
    },
    LeaveVoice,
    /// Mint a shareable invite code for a workspace (admins only).
    CreateInvite {
        workspace: String,
        ttl_secs: u64,
        max_uses: u32,
    },
    /// Redeem an invite code to join its workspace.
    RedeemInvite {
        code: String,
    },
    /// As an admin, move a member to another voice channel (drag them onto it).
    VoiceMoveMember {
        workspace: String,
        channel: String,
        member: String,
    },
}

/// A message line for the UI.
#[derive(serde::Serialize, Clone)]
struct Line {
    from: String,
    /// The sender's username (stable), so the UI resolves the name + avatar.
    user: String,
    text: String,
    mine: bool,
    /// Present when this line is a file. The UI shows a file row instead of a
    /// text bubble and can ask the core to open it.
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<FileLine>,
    /// A persisted system notice ("X declined foo"): the UI renders it as the
    /// small centered line, not a message bubble.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    system: bool,
    /// Stable message id (hex), for reply / forward / delete / details.
    id: String,
    /// Creation time, unix milliseconds, for the timestamp.
    ts: u64,
    /// Whether the message was deleted (shows a placeholder).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    deleted: bool,
    /// Hex id of the message this replies to, or empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    reply_to: String,
    /// Voice-message duration in ms, or 0 if not a voice message.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    voice_ms: u32,
    /// Amplitude envelope for a voice message's waveform (empty otherwise).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    waveform: Vec<u8>,
    /// Emoji reactions on this line (omitted when there are none).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reactions: Vec<Reaction>,
    /// Whether this message was edited after sending (shows an "edited" marker).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    edited: bool,
    /// Present when this line is a poll (the UI renders a poll card).
    #[serde(skip_serializing_if = "Option::is_none")]
    poll: Option<PollViewOut>,
    /// Whether this message is pinned in the conversation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pinned: bool,
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// A file attached to a message line, for the UI.
#[derive(serde::Serialize, Clone)]
struct FileLine {
    name: String,
    size: u64,
    path: String,
}

/// A poll as sent to the UI: definition, tallies, my vote, and reveal state.
#[derive(serde::Serialize, Clone)]
struct PollViewOut {
    question: String,
    options: Vec<String>,
    counts: Vec<u32>,
    multi: bool,
    reveal: u8,
    closed: bool,
    mine: Vec<u8>,
    total: u32,
    revealed: bool,
    is_author: bool,
    closes_at: u64,
    voters: Vec<Vec<String>>,
    anonymous: bool,
}

impl From<enclave_client::PollView> for PollViewOut {
    fn from(p: enclave_client::PollView) -> PollViewOut {
        PollViewOut {
            question: p.question,
            options: p.options,
            counts: p.counts,
            multi: p.multi,
            reveal: p.reveal,
            closed: p.closed,
            mine: p.mine,
            total: p.total,
            revealed: p.revealed,
            is_author: p.is_author,
            closes_at: p.closes_at,
            voters: p.voters,
            anonymous: p.anonymous,
        }
    }
}

/// A workspace with the full detail the UI renders: the channel tree, members,
/// and our own role.
#[derive(serde::Serialize, Clone)]
struct WorkspaceOut {
    id: String,
    name: String,
    /// Whether we are the owner (holds every permission, untouchable).
    am_owner: bool,
    /// Our effective permission tokens (e.g. "manage_channels"), for gating UI.
    my_permissions: Vec<String>,
    /// The workspace's role definitions (the built-in Owner role included, flagged).
    roles: Vec<RoleOut>,
    categories: Vec<CategoryOut>,
    channels: Vec<ChannelOut>,
    members: Vec<MemberOut>,
}

/// A role definition for the UI's role editor.
#[derive(serde::Serialize, Clone)]
struct RoleOut {
    id: String,
    name: String,
    /// Permission tokens this role grants.
    permissions: Vec<String>,
    /// True for the built-in Owner role (shown but not editable/deletable).
    builtin: bool,
}

#[derive(serde::Serialize, Clone)]
struct CategoryOut {
    id: String,
    name: String,
    /// Parent category id (hex) for nesting, or `None` at the top level.
    parent: Option<String>,
}

#[derive(serde::Serialize, Clone)]
struct ChannelOut {
    id: String,
    name: String,
    /// "text" | "voice".
    kind: String,
    private: bool,
    category: Option<String>,
    /// Whether we are a member of this (possibly private) channel.
    member: bool,
}

#[derive(serde::Serialize, Clone)]
struct MemberOut {
    handle: String,
    /// Whether this member is the owner.
    is_owner: bool,
    /// The role ids (hex) assigned to this member (empty for a bare member).
    roles: Vec<String>,
}

/// One channel message for the UI's channel view.
#[derive(serde::Serialize, Clone)]
struct ChannelLineOut {
    id: String,
    user: String,
    text: String,
    ts: u64,
    mine: bool,
}

/// Build the ChannelHistory UI event from the client's current (timestamp-sorted)
/// history for a channel plus whether older pages remain to load.
fn channel_history_event(c: &enclave_client::Client, workspace: &str, channel: &str) -> UiEvent {
    UiEvent::ChannelHistory {
        workspace: workspace.to_string(),
        channel: channel.to_string(),
        messages: c
            .channel_history(workspace, channel)
            .into_iter()
            .map(|m| ChannelLineOut {
                id: m.id,
                user: m.user,
                text: m.text,
                ts: m.ts,
                mine: m.mine,
            })
            .collect(),
        has_more: c.channel_has_more(workspace, channel),
    }
}

/// Build the rich per-workspace views for the UI from replayed op-log state.
fn workspace_views(c: &enclave_client::Client) -> Vec<WorkspaceOut> {
    let me = c.name().to_string();
    let mut out = Vec::new();
    for (id_hex, _name) in c.workspace_list() {
        let Some(state) = c.workspace(&id_hex) else {
            continue;
        };
        let categories = state
            .categories
            .iter()
            .map(|(cid, info)| CategoryOut {
                id: hex::encode(cid),
                name: info.name.clone(),
                parent: info.parent.map(hex::encode),
            })
            .collect();
        let channels = state
            .channels
            .values()
            .map(|ch| ChannelOut {
                id: hex::encode(ch.id),
                name: ch.name.clone(),
                kind: match ch.kind {
                    enclave_protocol::ChannelKind::Text => "text",
                    enclave_protocol::ChannelKind::Voice => "voice",
                }
                .to_string(),
                private: ch.private,
                category: ch.category.map(hex::encode),
                member: state.is_channel_member(&ch.id, &me),
            })
            .collect();
        let members = state
            .members
            .keys()
            .map(|h| MemberOut {
                handle: h.clone(),
                is_owner: state.is_owner(h),
                roles: state
                    .member_roles
                    .get(h)
                    .map(|ids| {
                        ids.iter()
                            .filter(|rid| **rid != enclave_crypto::workspace::OWNER_ROLE_ID)
                            .map(hex::encode)
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect();
        let roles = state
            .roles
            .iter()
            .map(|(rid, def)| RoleOut {
                id: hex::encode(rid),
                name: def.name.clone(),
                permissions: def
                    .permissions
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect(),
                builtin: *rid == enclave_crypto::workspace::OWNER_ROLE_ID,
            })
            .collect();
        let my_permissions = state
            .permissions_of(&me)
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();
        out.push(WorkspaceOut {
            id: id_hex,
            name: state.name.clone(),
            am_owner: state.is_owner(&me),
            my_permissions,
            roles,
            categories,
            channels,
            members,
        });
    }
    out
}

/// One message-search result, for the UI's results list.
#[derive(serde::Serialize, Clone)]
struct SearchHitOut {
    conv: String,
    conv_title: String,
    self_notes: bool,
    id: String,
    ts: u64,
    user: String,
    display: String,
    text: String,
    mine: bool,
}

/// A shareable video source for the picker. `id` is an opaque token the UI
/// echoes back in `StartShare`: "monitor:N", "window:HWND", or "camera:N".
#[derive(serde::Serialize, Clone)]
struct ShareSource {
    id: String,
    name: String,
}

/// A conversation summary for the sidebar.
#[derive(serde::Serialize, Clone)]
struct ConvSummary {
    id: String,
    title: String,
    is_dm: bool,
    pending: bool,
    members: Vec<String>,
    /// Hidden to the Archived page (still a member).
    archived: bool,
    /// Left or removed from the group: read-only, on the Archived page.
    left: bool,
    /// Whether the composer is usable (false only for a left/removed group).
    can_send: bool,
    /// A DM whose peer unfriended us: sendable, but sending re-adds them.
    reconnect: bool,
    /// The local-only "Notes to self" scratchpad: rendered distinctly, and its
    /// call/verify/members controls are hidden.
    self_notes: bool,
    /// Whether group history sharing is on (new members can read messages from
    /// when it was enabled).
    history_on: bool,
}

/// A file the user attached to the composer (path + display name + size), before
/// sending. The bytes stay on disk; only this metadata reaches the UI.
#[derive(serde::Serialize, Clone)]
struct AttachedFile {
    path: String,
    name: String,
    size: u64,
}

/// Stat each path into an [`AttachedFile`] (skipping directories / unreadable
/// paths), for the composer's attachment tray.
fn stat_attachments(paths: &[String]) -> Vec<AttachedFile> {
    paths
        .iter()
        .filter_map(|p| {
            let meta = std::fs::metadata(p).ok()?;
            if !meta.is_file() {
                return None;
            }
            let name = std::path::Path::new(p)
                .file_name()?
                .to_string_lossy()
                .into_owned();
            Some(AttachedFile {
                path: p.clone(),
                name,
                size: meta.len(),
            })
        })
        .collect()
}

/// Events the core sends to the UI (serialized straight into `onEnclaveEvent`).
#[derive(serde::Serialize, Clone)]
#[serde(tag = "type")]
enum UiEvent {
    LoggedIn {
        username: String,
        display: String,
    },
    LoggedOut,
    /// The full conversation list for the sidebar.
    Conversations {
        conversations: Vec<ConvSummary>,
    },
    /// The active conversation changed: its id, title, safety number, and history.
    ActiveConversation {
        conv: Option<String>,
        title: String,
        safety: Option<String>,
        /// Whether this conversation's *current* safety number was confirmed
        /// out of band. Comes from the core, and survives a restart.
        verified: bool,
        history: Vec<Line>,
        /// Disappearing-messages duration (ms) for this conversation, 0 if off.
        #[serde(default)]
        disappearing_ms: u32,
    },
    /// A single message arrived (or was sent) in conversation `conv`.
    Message {
        conv: String,
        /// Hex message id + creation time (unix ms) for reply/forward/delete/details.
        #[serde(default)]
        id: String,
        #[serde(default)]
        ts: u64,
        /// Hex id of the message this replies to, or empty.
        #[serde(default)]
        reply_to: String,
        from: String,
        #[serde(default)]
        user: String,
        text: String,
        mine: bool,
    },
    /// A file arrived (or was sent) in `conv`: show a file row and offer Open.
    FileMessage {
        conv: String,
        #[serde(default)]
        id: String,
        #[serde(default)]
        ts: u64,
        from: String,
        #[serde(default)]
        user: String,
        name: String,
        size: u64,
        path: String,
        mine: bool,
        /// The offer's hex id for our OWN sent files, so the UI can offer a "Stop
        /// sharing" control; empty for received files (nothing to withdraw).
        #[serde(default)]
        offer_id: String,
    },
    /// Progress of an in-flight transfer, so the UI can show a bar for a large
    /// message or file. `sent`/`total` are byte counts; `incoming` marks a
    /// download vs an upload.
    TransferProgress {
        conv: String,
        id: String,
        label: String,
        sent: u64,
        total: u64,
        incoming: bool,
    },
    /// A file was offered to us; the UI shows a consent prompt (Accept /
    /// Decline). Nothing has been downloaded. `live` means accept promptly.
    FileOffered {
        conv: String,
        offer_id: String,
        from: String,
        name: String,
        size: u64,
        live: bool,
    },
    /// An offer we were shown resolved into a delivered file: the UI removes the
    /// pending prompt (the file itself now shows in chat).
    FileOfferClosed {
        conv: String,
        offer_id: String,
    },
    /// An offer we were shown is no longer available (sender withdrew it or went
    /// offline): the UI marks its message unavailable but keeps it in chat.
    FileOfferUnavailable {
        conv: String,
        offer_id: String,
    },
    /// A file drag is over the window (`active` true) or has left/dropped
    /// (`false`): the UI shows or hides a drop overlay.
    DropTarget {
        active: bool,
    },
    /// Files the user picked or dropped, to attach to the composer (not yet sent).
    AttachFiles {
        files: Vec<AttachedFile>,
    },
    Presence {
        user: String,
        status: String,
    },
    /// A neutral status line shown inside a conversation (e.g. "X declined foo").
    Notice {
        conv: String,
        text: String,
    },
    /// A message was deleted: the UI marks its line as a placeholder, kept in chat.
    MessageDeleted {
        conv: String,
        id: String,
    },
    /// A message's emoji reactions changed: the UI replaces that line's chips.
    ReactionsChanged {
        conv: String,
        id: String,
        reactions: Vec<Reaction>,
    },
    /// A message was edited by its author: the UI updates the text + "edited" mark.
    MessageEdited {
        conv: String,
        id: String,
        text: String,
    },
    /// A poll was posted: the UI adds a poll card line.
    PollPosted {
        conv: String,
        id: String,
        ts: u64,
        from: String,
        user: String,
        mine: bool,
        poll: PollViewOut,
    },
    /// A poll's tallies or state changed: the UI refreshes that card.
    PollUpdated {
        conv: String,
        id: String,
        poll: PollViewOut,
    },
    /// A message was pinned or unpinned: the UI updates its indicator + pin bar.
    PinsChanged {
        conv: String,
        id: String,
        pinned: bool,
    },
    /// Local message-search results (newest first). `scoped` is true when the
    /// search was limited to one conversation. `query` echoes the input.
    SearchResults {
        query: String,
        scoped: bool,
        hits: Vec<SearchHitOut>,
    },
    /// The disappearing-messages setting for `conv` changed (ms, 0=off).
    DisappearingChanged {
        conv: String,
        ms: u32,
    },
    /// Messages whose disappearing timer elapsed were removed: the UI drops them.
    MessagesExpired {
        conv: String,
        ids: Vec<String>,
    },
    /// A voice message arrived (or we sent one): the UI shows a small player.
    VoiceMessage {
        conv: String,
        #[serde(default)]
        id: String,
        #[serde(default)]
        ts: u64,
        from: String,
        #[serde(default)]
        user: String,
        path: String,
        duration_ms: u32,
        #[serde(default)]
        waveform: Vec<u8>,
        mine: bool,
    },
    /// A recording was stopped and is ready to preview before sending: the UI
    /// shows a preview player with Send / Discard.
    VoicePreview {
        path: String,
        duration_ms: u32,
        #[serde(default)]
        waveform: Vec<u8>,
    },
    /// A user's end-to-end profile (our own or a peer's) for the UI to render:
    /// name, custom status, accent, bio, and the avatar's content address (used
    /// to build an `enclave://localhost/avatar/<hex>` image URL). `avatar` is
    /// `None` for the initials fallback. Emitted for all known users on login and
    /// whenever one changes or an avatar finishes decrypting.
    Profile {
        user: String,
        display: String,
        status_emoji: String,
        status_text: String,
        accent: String,
        bio: String,
        avatar: Option<String>,
        me: bool,
    },
    /// Whether a voice call is currently active.
    CallState {
        in_call: bool,
    },
    /// The available audio devices and current selection for the settings modal.
    AudioDevices {
        inputs: Vec<String>,
        outputs: Vec<String>,
        input: Option<String>,
        output: Option<String>,
    },
    /// An incoming call started in `conv`, from display name `from`: ring.
    CallOffer {
        conv: String,
        from: String,
    },
    /// The participants of `conv`'s call (usernames); empty = call ended.
    CallParticipants {
        conv: String,
        participants: Vec<String>,
    },
    /// `from` declined our call in `conv`.
    CallDeclined {
        conv: String,
        from: String,
    },
    /// An H.264 video frame (base64 Annex-B) from `from` to render via
    /// WebCodecs. `camera` routes it: a per-user webcam tile or the share viewer.
    ScreenFrame {
        from: String,
        data: String,
        keyframe: bool,
        camera: bool,
    },
    /// Whether we are currently sharing our own screen.
    ScreenShareState {
        sharing: bool,
    },
    /// Whether our own camera is currently on.
    CameraState {
        on: bool,
    },
    /// The monitors, windows, and cameras this machine can share, for the picker.
    /// `per_app_audio` tells the UI whether a window share can carry only that
    /// app's audio (Windows) or shared audio is always the whole mix (Linux).
    ShareSources {
        screens: Vec<ShareSource>,
        windows: Vec<ShareSource>,
        cameras: Vec<ShareSource>,
        per_app_audio: bool,
    },
    /// Someone sent us a friend request.
    FriendRequest {
        from: String,
    },
    /// The current friends + pending-requests snapshot (username + display).
    /// People we no longer connect to but share history with live in the Chats
    /// sidebar's "Inactive" section, not here.
    Friends {
        friends: Vec<Friend>,
        incoming: Vec<Friend>,
        outgoing: Vec<Friend>,
    },
    /// The workspaces we belong to (hex id + name), for the sidebar rail. The
    /// full channel/role detail is read on demand per workspace (later phases).
    Workspaces {
        workspaces: Vec<WorkspaceOut>,
    },
    /// A message in a workspace channel (ours or a peer's).
    ChannelMessage {
        workspace: String,
        channel: String,
        id: String,
        user: String,
        text: String,
        ts: u64,
        mine: bool,
    },
    /// A voice channel's occupants changed.
    VoicePresence {
        workspace: String,
        channel: String,
        members: Vec<String>,
    },
    /// A channel's message history, loaded when the channel is opened or when a
    /// fetched page (newest catch-up or older backfill) lands. `has_more` says
    /// whether older pages remain, so the UI can offer "load older".
    ChannelHistory {
        workspace: String,
        channel: String,
        messages: Vec<ChannelLineOut>,
        has_more: bool,
    },
    /// Groups we share with `handle` (hex id, title), for their profile card.
    SharedGroups {
        handle: String,
        groups: Vec<(String, String)>,
    },
    /// A workspace invite code we just minted, for the UI to show and copy.
    InviteCreated {
        workspace: String,
        code: String,
    },
    Status {
        message: String,
        error: bool,
    },
    /// Connection state to the server: "online" | "reconnecting" | "offline".
    Connection {
        state: String,
    },
}

fn main() -> wry::Result<()> {
    let event_loop = EventLoopBuilder::<UiEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("Enclave")
        .with_inner_size(tao::dpi::LogicalSize::new(1000.0, 680.0))
        // Floor the window size so it can never be shrunk into an overlapping,
        // overflowing mess; below the sidebar's collapse width the layout still
        // stays clean via the drawer.
        .with_min_inner_size(tao::dpi::LogicalSize::new(360.0, 480.0))
        .build(&event_loop)
        .expect("build window");

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<UiCommand>();
    // Clones for the native drag-drop handler (files dropped on the window).
    let drag_cmd_tx = cmd_tx.clone();
    let drag_proxy = proxy.clone();

    // Whether the window is focused, so the core only raises OS toasts when the
    // user is not already looking at Enclave.
    let focused = Arc::new(AtomicBool::new(true));

    // Each process gets its own WebView user-data folder. Two instances sharing
    // the default folder collide with a WebView2 "invalid parameter" error, so
    // running multiple windows (e.g. two accounts on one machine) would fail.
    let wv_data = std::env::temp_dir().join(format!("enclave-webview-{}", std::process::id()));
    let mut web_context = wry::WebContext::new(Some(wv_data));
    // Serve the UI from a custom-protocol origin (https://enclave.localhost/ on
    // Windows, enclave://localhost/ on WebKitGTK) instead of NavigateToString.
    // That origin is a *secure context*, which the opaque about:blank origin of
    // with_html is not -- and WebCodecs (the H.264 screen-share decoder) is
    // only available in a secure context.
    let builder = WebViewBuilder::new_with_web_context(&mut web_context);
    // WebView2 can only register custom protocols under an http(s) mapping.
    #[cfg(windows)]
    let builder = builder.with_https_scheme(true);
    // Avatars are served from the local decrypted cache at
    // enclave://localhost/avatar/<hex>; everything else serves the app HTML.
    let avatar_dir = app_dir().join("avatars");
    let media_index: SharedMedia = Arc::new(Mutex::new(HashMap::new()));
    let media_for_handler = media_index.clone();
    let builder = builder
        .with_custom_protocol("enclave".to_string(), move |_id, req| {
            // Serve a thumbnail for an image file that is in our history: the path
            // is looked up from the vetted media index by message id (hex only, so
            // no path can be injected), and only image bytes are returned.
            if let Some(hexid) = req.uri().path().strip_prefix("/media/") {
                if hexid.len() <= 32 && hexid.bytes().all(|b| b.is_ascii_hexdigit()) {
                    let path = media_for_handler
                        .lock()
                        .ok()
                        .and_then(|m| m.get(hexid).cloned());
                    if let Some(path) = path {
                        if let Ok(bytes) = std::fs::read(&path) {
                            if let Some(mime) = image_mime(&bytes) {
                                return wry::http::Response::builder()
                                    .header("Content-Type", mime)
                                    .header("Cache-Control", "no-store")
                                    .body(Cow::Owned(bytes))
                                    .unwrap();
                            }
                        }
                    }
                }
                return wry::http::Response::builder()
                    .status(404)
                    .header("Cache-Control", "no-store")
                    .body(Cow::Owned(Vec::new()))
                    .unwrap();
            }
            if let Some(hexaddr) = req.uri().path().strip_prefix("/avatar/") {
                // The path is a 64-char hex content address -- hex only, so no
                // "..", slash, or absolute path can escape the cache directory.
                if hexaddr.len() == 64 && hexaddr.bytes().all(|b| b.is_ascii_hexdigit()) {
                    if let Ok(bytes) = std::fs::read(avatar_dir.join(hexaddr)) {
                        let mime = if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
                            "image/png"
                        } else {
                            "image/jpeg"
                        };
                        return wry::http::Response::builder()
                            .header("Content-Type", mime)
                            // Immutable: a content address never names other bytes.
                            .header("Cache-Control", "max-age=31536000, immutable")
                            .body(Cow::Owned(bytes))
                            .unwrap();
                    }
                }
                // Not cached yet (or bad address): 404, no caching, so a later
                // request succeeds once the avatar decrypts. The UI shows initials.
                return wry::http::Response::builder()
                    .status(404)
                    .header("Cache-Control", "no-store")
                    .body(Cow::Owned(Vec::new()))
                    .unwrap();
            }
            wry::http::Response::builder()
                .header("Content-Type", "text/html")
                .body(Cow::Borrowed(UI_HTML.as_bytes()))
                .unwrap()
        })
        .with_url("enclave://localhost/")
        // Enable the Web Inspector so the DOM/CSS can be examined live (right-click
        // -> Inspect Element on WebKitGTK).
        .with_devtools(true)
        .with_ipc_handler(move |req: Request<String>| {
            if let Ok(cmd) = serde_json::from_str::<UiCommand>(req.body()) {
                let _ = cmd_tx.send(cmd);
            }
        })
        // Handle dropped files ourselves so the WebView never navigates to them
        // (the default "open the file in a new view" browser behavior the user
        // never wants). Returning true blocks that default. wry hands us real
        // filesystem paths, so a dropped file is offered like any other.
        .with_drag_drop_handler(move |event: wry::DragDropEvent| {
            match event {
                wry::DragDropEvent::Enter { .. } | wry::DragDropEvent::Over { .. } => {
                    emit(&drag_proxy, UiEvent::DropTarget { active: true });
                }
                wry::DragDropEvent::Leave => {
                    emit(&drag_proxy, UiEvent::DropTarget { active: false });
                }
                wry::DragDropEvent::Drop { paths, .. } => {
                    emit(&drag_proxy, UiEvent::DropTarget { active: false });
                    // Attach the dropped files to the composer (the user adds a
                    // message / picks live before sending), never auto-send.
                    let strs: Vec<String> = paths
                        .iter()
                        .filter_map(|p| p.to_str().map(str::to_string))
                        .collect();
                    if !strs.is_empty() {
                        let _ = drag_cmd_tx.send(UiCommand::AttachPaths { paths: strs });
                    }
                }
                _ => {}
            }
            true // we handled it; block the OS/WebView default
        });
    // On Linux, tao windows are GTK windows and wry attaches to the GTK
    // widget tree (a raw Wayland/X11 handle is unsupported). The webview must
    // land in tao's default vbox: the window itself is a GtkBin that already
    // holds that box and can take no second child.
    #[cfg(target_os = "linux")]
    let webview = builder.build_gtk(
        window
            .default_vbox()
            .expect("tao always adds a default GtkBox"),
    )?;
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window)?;

    // Auto-open the Web Inspector when ENCLAVE_DEVTOOLS is set (WebKitGTK ignores
    // the right-click/F12 path), so the DOM/CSS can be examined live.
    if std::env::var_os("ENCLAVE_DEVTOOLS").is_some() {
        webview.open_devtools();
    }

    let core_focused = focused.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(run_client(cmd_rx, proxy, core_focused, media_index));
    });

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            TaoEvent::UserEvent(ui) => {
                if let Ok(json) = serde_json::to_string(&ui) {
                    let _ = webview.evaluate_script(&format!("window.onEnclaveEvent({json})"));
                }
            }
            TaoEvent::WindowEvent {
                event: WindowEvent::Focused(f),
                ..
            } => focused.store(f, Ordering::Relaxed),
            TaoEvent::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {}
        }
    });
}

/// Standard base64 (no line breaks) for shipping a binary H.264 frame to the
/// WebView as a JSON string. Small dependency-free encoder for the hot path.
fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64 (ignoring padding and any whitespace), for receiving
/// an avatar image the WebView encoded. Returns `None` on an invalid character.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Raise an OS desktop notification (toast) off the async loop.
fn notify_os(title: String, body: String) {
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .summary(&title)
            .body(&body)
            .appname("Enclave")
            .show();
    });
}

fn emit(proxy: &EventLoopProxy<UiEvent>, event: UiEvent) {
    let _ = proxy.send_event(event);
}

fn error_status(proxy: &EventLoopProxy<UiEvent>, message: String) {
    emit(
        proxy,
        UiEvent::Status {
            message,
            error: true,
        },
    );
}

/// The sidebar conversation list.
fn conv_summaries(c: &Client) -> Vec<ConvSummary> {
    c.conversations()
        .into_iter()
        .map(|i| {
            let history_on = c.group_history_on(&i.id);
            ConvSummary {
                id: i.id,
                title: i.title,
                is_dm: i.is_dm,
                pending: i.pending,
                members: i.members,
                archived: i.archived,
                left: i.left,
                can_send: i.can_send,
                reconnect: i.reconnect,
                self_notes: i.self_notes,
                history_on,
            }
        })
        .collect()
}

/// Offer a file at `path` to the active conversation (stored, or `live`), then
/// tell the UI to show it as our own sent message. Shared by the file picker
/// (`SendFile`/`SendFileLive`) and native drag-and-drop (`SendFilePath`).
async fn offer_file_from(
    c: &mut Client,
    proxy: &EventLoopProxy<UiEvent>,
    path: String,
    live: bool,
) {
    let conv = c.active_id();
    let from = c.display_name().to_string();
    let user = c.name().to_string();
    let result = if live {
        c.send_file_live(&path).await
    } else {
        c.send_file(&path).await
    };
    match result {
        Ok((file, offer_id)) => {
            if let Some(conv) = conv {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                emit(
                    proxy,
                    UiEvent::FileMessage {
                        conv,
                        id: offer_id.clone(),
                        ts,
                        from,
                        user,
                        name: file.name,
                        size: file.size,
                        path: file.path,
                        mine: true,
                        offer_id,
                    },
                );
            }
        }
        Err(e) => error_status(
            proxy,
            format!(
                "Could not {}: {e}",
                if live { "live share" } else { "send file" }
            ),
        ),
    }
}

/// The active-conversation snapshot (id, title, safety number, scoped history).
fn active_conversation_event(c: &Client) -> UiEvent {
    let conv = c.active_id();
    let (title, history) = match &conv {
        Some(id) => {
            let title = c
                .conversations()
                .into_iter()
                .find(|i| &i.id == id)
                .map(|i| i.title)
                .unwrap_or_default();
            let history = c
                .conversation_history(id)
                .into_iter()
                .map(|l| Line {
                    from: l.display,
                    user: l.user,
                    text: l.text,
                    mine: l.mine,
                    file: l.file.map(|f| FileLine {
                        name: f.name,
                        size: f.size,
                        path: f.path,
                    }),
                    system: l.system,
                    id: l.id,
                    ts: l.ts,
                    deleted: l.deleted,
                    reply_to: l.reply_to,
                    voice_ms: l.voice_ms,
                    waveform: l.waveform,
                    reactions: l.reactions,
                    edited: l.edited,
                    poll: l.poll.map(PollViewOut::from),
                    pinned: l.pinned,
                })
                .collect();
            (title, history)
        }
        None => (String::new(), Vec::new()),
    };
    let disappearing_ms = conv.as_deref().map(|id| c.disappearing_of(id)).unwrap_or(0);
    UiEvent::ActiveConversation {
        conv,
        title,
        safety: c.safety_number(),
        verified: c.is_verified(),
        history,
        disappearing_ms,
    }
}

/// Push both the sidebar list and the active-conversation snapshot.
fn emit_conversations(proxy: &EventLoopProxy<UiEvent>, c: &Client) {
    emit(
        proxy,
        UiEvent::Conversations {
            conversations: conv_summaries(c),
        },
    );
    emit(proxy, active_conversation_event(c));
}

/// Turn a stored profile into the UI event, resolving the avatar reference to
/// its hex content address only when the decrypted image is actually cached
/// locally (so the UI shows a picture only when it can load one).
fn profile_event(c: &Client, user: &str, profile: &enclave_client::Profile, me: bool) -> UiEvent {
    let avatar = profile
        .avatar
        .as_ref()
        .filter(|a| c.have_avatar(&a.addr))
        .map(|a| hex::encode(a.addr));
    UiEvent::Profile {
        user: user.to_string(),
        display: profile.display_name.clone(),
        status_emoji: profile.status_emoji.clone(),
        status_text: profile.status_text.clone(),
        accent: profile.accent.clone(),
        bio: profile.bio.clone(),
        avatar,
        me,
    }
}

/// Emit one user's profile to the UI (peer or self).
fn emit_profile(proxy: &EventLoopProxy<UiEvent>, c: &Client, user: &str) {
    let me = !user.is_empty() && c.name() == user;
    let profile = if me {
        Some(c.my_profile().clone())
    } else {
        c.profile_of(user).cloned()
    };
    if let Some(p) = profile {
        emit(proxy, profile_event(c, user, &p, me));
    }
}

/// Seed the UI with every profile we know (our own + cached peers), on login.
fn emit_all_profiles(proxy: &EventLoopProxy<UiEvent>, c: &Client) {
    let me = c.name().to_string();
    for (user, profile) in c.all_profiles() {
        emit(proxy, profile_event(c, &user, &profile, user == me));
    }
}

fn emit_audio_devices(proxy: &EventLoopProxy<UiEvent>, c: &Client) {
    let info = c.audio_devices();
    emit(
        proxy,
        UiEvent::AudioDevices {
            inputs: info.inputs,
            outputs: info.outputs,
            input: info.input,
            output: info.output,
        },
    );
}

/// Parse a share-source token ("monitor:N", "window:HWND", or "camera:N") and
/// start that share, optionally also sharing its audio, reporting the new state
/// or an error to the UI.
///
/// Picking a source while one is already live switches to it: the core replaces
/// the capture, and any shared audio is restarted, because the new source has a
/// different owning process (or none at all).
fn start_share(c: &mut Client, proxy: &EventLoopProxy<UiEvent>, source: &str, audio: bool) {
    let Some((kind, id)) = source.split_once(':') else {
        error_status(proxy, format!("Bad share source: {source}"));
        return;
    };
    match kind {
        "monitor" => match id.parse::<usize>() {
            Ok(m) => match c.start_screen_share(m) {
                Ok(()) => {
                    emit(proxy, UiEvent::ScreenShareState { sharing: true });
                    // A monitor has no single owning process: whole-endpoint
                    // loopback (the UI already warned about the echo).
                    c.stop_system_audio();
                    if audio {
                        share_audio(c, proxy, None);
                    }
                }
                Err(e) => error_status(proxy, format!("Could not share screen: {e}")),
            },
            Err(_) => error_status(proxy, format!("Bad monitor id: {id}")),
        },
        "window" => match id.parse::<isize>() {
            Ok(h) => match c.start_window_share(h) {
                Ok(()) => {
                    emit(proxy, UiEvent::ScreenShareState { sharing: true });
                    // Per-app audio: capture only this window's process (echo-free).
                    c.stop_system_audio();
                    if audio {
                        match c.window_pid(h) {
                            Some(pid) => share_audio(c, proxy, Some(pid)),
                            None => error_status(
                                proxy,
                                "Sharing the window, but could not find its audio".into(),
                            ),
                        }
                    }
                }
                Err(e) => error_status(proxy, format!("Could not share window: {e}")),
            },
            Err(_) => error_status(proxy, format!("Bad window id: {id}")),
        },
        "camera" => match id.parse::<u32>() {
            Ok(n) => match c.start_camera(n) {
                Ok(()) => emit(proxy, UiEvent::CameraState { on: true }),
                Err(e) => error_status(proxy, format!("Could not share camera: {e}")),
            },
            Err(_) => error_status(proxy, format!("Bad camera id: {id}")),
        },
        _ => error_status(proxy, format!("Unknown share kind: {kind}")),
    }
}

/// Start system-audio sharing (per-app if `pid` is set, else whole endpoint),
/// surfacing any failure without tearing down the already-running video share.
fn share_audio(c: &mut Client, proxy: &EventLoopProxy<UiEvent>, pid: Option<u32>) {
    if let Err(e) = c.start_system_audio(pid) {
        error_status(proxy, format!("Sharing screen, but audio failed: {e}"));
    }
}

fn app_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

async fn run_client(
    mut cmd_rx: mpsc::UnboundedReceiver<UiCommand>,
    proxy: EventLoopProxy<UiEvent>,
    focused: Arc<AtomicBool>,
    media_index: SharedMedia,
) {
    let mut client: Option<Client> = None;
    let mut last_expire = std::time::Instant::now();
    loop {
        let mut ran_command = false;
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_command(&mut client, &proxy, cmd).await;
            ran_command = true;
        }
        // A command may have switched conversations or sent a file: keep the media
        // index current so the Media tab can serve thumbnails for the open chat.
        if ran_command {
            if let Some(c) = client.as_ref() {
                reindex_media(c, &media_index);
            }
        }

        // Periodically sweep messages whose disappearing timer has elapsed
        // (fully removed on this device, no signal to anyone).
        if last_expire.elapsed() >= Duration::from_secs(5) {
            last_expire = std::time::Instant::now();
            if let Some(c) = client.as_mut() {
                for (conv, ids) in c.expire_messages() {
                    emit(&proxy, UiEvent::MessagesExpired { conv, ids });
                }
            }
        }

        // Push any in-progress file uploads forward, paced by the connection's
        // bounded file queue (backpressure), so a large upload streams from disk
        // instead of buffering in memory. Retransmit any reliable message the
        // server has not yet acked, so nothing is lost to a drop or a transient
        // server-full.
        if let Some(c) = client.as_mut() {
            c.pump_uploads();
            if let Some(Event::Error(message)) = c.pump_retransmits() {
                error_status(&proxy, message);
            }
            // Heal any DM found to be forked (peer on a different MLS group).
            c.pump_reinvites().await;
            // Admit any queued workspace members freed by the last op's echo (a
            // burst of invite redemptions drains one per freed slot).
            for (_workspace, handle) in c.pump_workspace_adds().await {
                emit(
                    &proxy,
                    UiEvent::Status {
                        message: format!("Admitted {handle}."),
                        error: false,
                    },
                );
            }
        }

        // A share can end without a command: the user cancels the system
        // picker (Linux portal), the compositor revokes the share, or the
        // capture dies. Reap it so the UI reflects reality.
        if let Some(c) = client.as_mut() {
            if let Some(reason) = c.reap_ended_share() {
                emit(&proxy, UiEvent::ScreenShareState { sharing: false });
                match reason {
                    enclave_client::ShareEnded::Cancelled => emit(
                        &proxy,
                        UiEvent::Status {
                            message: "Share cancelled.".into(),
                            error: false,
                        },
                    ),
                    enclave_client::ShareEnded::Failed(e) => {
                        error_status(&proxy, format!("Screen share ended: {e}"))
                    }
                }
            }
        }

        let next = async {
            match client.as_mut() {
                Some(c) => c.next_event().await,
                None => std::future::pending::<Option<Event>>().await,
            }
        };
        match tokio::time::timeout(Duration::from_millis(50), next).await {
            Ok(Some(event)) => match event {
                Event::Message {
                    conv,
                    id,
                    ts,
                    reply_to,
                    from,
                    user,
                    text,
                    mine,
                } => {
                    // Toast an incoming message only when the user is not looking
                    // at Enclave (unfocused); the in-app ding + unread badge cover
                    // the focused-but-other-conversation case.
                    if !mine && !focused.load(Ordering::Relaxed) {
                        notify_os(from.clone(), text.clone());
                    }
                    emit(
                        &proxy,
                        UiEvent::Message {
                            conv,
                            id,
                            ts,
                            reply_to,
                            from,
                            user,
                            text,
                            mine,
                        },
                    );
                }
                Event::ConversationsChanged => {
                    if let Some(c) = client.as_ref() {
                        emit_conversations(&proxy, c);
                    }
                }
                Event::Presence { user, status } => {
                    emit(&proxy, UiEvent::Presence { user, status })
                }
                Event::FriendRequest { from } => emit(&proxy, UiEvent::FriendRequest { from }),
                Event::CallOffer { conv, from } => {
                    if !focused.load(Ordering::Relaxed) {
                        notify_os("Incoming call".into(), format!("{from} is calling"));
                    }
                    emit(&proxy, UiEvent::CallOffer { conv, from })
                }
                Event::CallParticipants { conv, participants } => {
                    emit(&proxy, UiEvent::CallParticipants { conv, participants })
                }
                Event::CallDeclined { conv, from } => {
                    emit(&proxy, UiEvent::CallDeclined { conv, from })
                }
                Event::ScreenFrame {
                    from,
                    data,
                    keyframe,
                    camera,
                } => emit(
                    &proxy,
                    UiEvent::ScreenFrame {
                        from,
                        data: base64_encode(&data),
                        keyframe,
                        camera,
                    },
                ),
                Event::WorkspacesChanged => {
                    if let Some(c) = client.as_ref() {
                        emit(
                            &proxy,
                            UiEvent::Workspaces {
                                workspaces: workspace_views(c),
                            },
                        );
                    }
                }
                Event::ChannelMessage {
                    workspace,
                    channel,
                    id,
                    user,
                    text,
                    ts,
                    mine,
                } => emit(
                    &proxy,
                    UiEvent::ChannelMessage {
                        workspace,
                        channel,
                        id,
                        user,
                        text,
                        ts,
                        mine,
                    },
                ),
                Event::ChannelHistoryChanged {
                    workspace, channel, ..
                } => {
                    if let Some(c) = client.as_ref() {
                        emit(&proxy, channel_history_event(c, &workspace, &channel));
                    }
                }
                Event::InviteCreated { workspace, code } => {
                    emit(&proxy, UiEvent::InviteCreated { workspace, code });
                }
                Event::JoinRequested {
                    workspace,
                    requester,
                } => {
                    // An online admin admits an invite redeemer via the normal
                    // signed add flow (the op-log records us as the adder). The add
                    // is queued; the "Admitted X" toast fires from pump_workspace_adds
                    // once it actually lands, so a burst is admitted in turn.
                    if let Some(c) = client.as_mut() {
                        if let Err(e) = c.workspace_add_member(&workspace, &requester).await {
                            error_status(&proxy, format!("Could not admit {requester}: {e}"));
                        }
                    }
                }
                Event::VoiceMoveTo { workspace, channel } => {
                    // An admin moved us: join the target voice channel (which leaves
                    // the one we were in) and start audio best-effort.
                    if let Some(c) = client.as_mut() {
                        if c.join_voice_channel(&workspace, &channel).is_ok() {
                            let _ = c.start_voice_media().await;
                            emit(
                                &proxy,
                                UiEvent::Status {
                                    message: "You were moved to another voice channel.".into(),
                                    error: false,
                                },
                            );
                        }
                    }
                }
                Event::VoicePresence {
                    workspace,
                    channel,
                    members,
                } => emit(
                    &proxy,
                    UiEvent::VoicePresence {
                        workspace,
                        channel,
                        members,
                    },
                ),
                Event::FriendsChanged => {
                    if let Some(c) = client.as_ref() {
                        emit(
                            &proxy,
                            UiEvent::Friends {
                                friends: c.friends().to_vec(),
                                incoming: c.incoming_requests().to_vec(),
                                outgoing: c.outgoing_requests().to_vec(),
                            },
                        );
                        // A friendship change flips a DM's peer_friend (and thus
                        // the composer's Reconnect state) and can add/remove a past
                        // contact, so refresh the conversation summaries too.
                        emit_conversations(&proxy, c);
                    }
                }
                Event::ProfileChanged { user } => {
                    if let Some(c) = client.as_ref() {
                        emit_profile(&proxy, c, &user);
                        // DM titles, the chat header, and message history resolve
                        // names through `display_of` in the core, so re-emit them
                        // to reflect a peer's rename immediately (not only on
                        // re-entering the conversation).
                        emit_conversations(&proxy, c);
                    }
                }
                Event::File {
                    conv,
                    id,
                    ts,
                    from,
                    user,
                    file,
                } => {
                    if !focused.load(Ordering::Relaxed) {
                        notify_os(from.clone(), format!("sent a file: {}", file.name));
                    }
                    // A received image becomes servable as a thumbnail.
                    if let Ok(mut m) = media_index.lock() {
                        m.insert(id.clone(), PathBuf::from(&file.path));
                    }
                    emit(
                        &proxy,
                        UiEvent::FileMessage {
                            conv,
                            id,
                            ts,
                            from,
                            user,
                            name: file.name,
                            size: file.size,
                            path: file.path,
                            mine: false,
                            offer_id: String::new(),
                        },
                    );
                }
                Event::TransferProgress {
                    conv,
                    id,
                    label,
                    sent,
                    total,
                    incoming,
                } => emit(
                    &proxy,
                    UiEvent::TransferProgress {
                        conv,
                        id,
                        label,
                        sent,
                        total,
                        incoming,
                    },
                ),
                Event::FileOffered {
                    conv,
                    offer_id,
                    from,
                    name,
                    size,
                    live,
                } => {
                    if !focused.load(Ordering::Relaxed) {
                        notify_os(from.clone(), format!("wants to send a file: {name}"));
                    }
                    emit(
                        &proxy,
                        UiEvent::FileOffered {
                            conv,
                            offer_id,
                            from,
                            name,
                            size,
                            live,
                        },
                    );
                }
                Event::FileOfferClosed { conv, offer_id } => {
                    emit(&proxy, UiEvent::FileOfferClosed { conv, offer_id });
                }
                Event::FileOfferUnavailable { conv, offer_id } => {
                    emit(&proxy, UiEvent::FileOfferUnavailable { conv, offer_id });
                }
                Event::Notice { conv, text } => emit(&proxy, UiEvent::Notice { conv, text }),
                Event::MessageDeleted { conv, id } => {
                    emit(&proxy, UiEvent::MessageDeleted { conv, id })
                }
                Event::ReactionsChanged {
                    conv,
                    id,
                    reactions,
                } => emit(
                    &proxy,
                    UiEvent::ReactionsChanged {
                        conv,
                        id,
                        reactions,
                    },
                ),
                Event::MessageEdited { conv, id, text } => {
                    emit(&proxy, UiEvent::MessageEdited { conv, id, text })
                }
                Event::PollPosted {
                    conv,
                    id,
                    ts,
                    from,
                    user,
                    mine,
                    poll,
                } => emit(
                    &proxy,
                    UiEvent::PollPosted {
                        conv,
                        id,
                        ts,
                        from,
                        user,
                        mine,
                        poll: poll.into(),
                    },
                ),
                Event::PollUpdated { conv, id, poll } => emit(
                    &proxy,
                    UiEvent::PollUpdated {
                        conv,
                        id,
                        poll: poll.into(),
                    },
                ),
                Event::PinsChanged { conv, id, pinned } => {
                    emit(&proxy, UiEvent::PinsChanged { conv, id, pinned })
                }
                Event::DisappearingChanged { conv, ms } => {
                    emit(&proxy, UiEvent::DisappearingChanged { conv, ms })
                }
                Event::VoiceMessage {
                    conv,
                    id,
                    ts,
                    from,
                    user,
                    path,
                    duration_ms,
                    waveform,
                    mine,
                } => {
                    if !mine && !focused.load(Ordering::Relaxed) {
                        notify_os(from.clone(), "sent a voice message".into());
                    }
                    emit(
                        &proxy,
                        UiEvent::VoiceMessage {
                            conv,
                            id,
                            ts,
                            from,
                            user,
                            path,
                            duration_ms,
                            waveform,
                            mine,
                        },
                    );
                }
                Event::Error(message) => error_status(&proxy, message),
            },
            Ok(None) => {
                // The socket dropped (server restart, network blip). Try to
                // reconnect with backoff, re-authenticating with the retained
                // credentials, before giving up and logging out.
                let reconnected = if client.is_some() {
                    emit(
                        &proxy,
                        UiEvent::Connection {
                            state: "reconnecting".into(),
                        },
                    );
                    let mut ok = false;
                    let mut delay = 1u64;
                    for _ in 0..6 {
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                        if let Some(c) = client.as_mut() {
                            if c.reconnect().await.is_ok() {
                                ok = true;
                                break;
                            }
                        }
                        delay = (delay * 2).min(15);
                    }
                    ok
                } else {
                    false
                };
                if reconnected {
                    emit(
                        &proxy,
                        UiEvent::Connection {
                            state: "online".into(),
                        },
                    );
                    if let Some(c) = client.as_ref() {
                        emit_conversations(&proxy, c);
                    }
                } else {
                    client = None;
                    emit(&proxy, UiEvent::LoggedOut);
                    error_status(&proxy, "Lost connection to the server.".into());
                }
            }
            Err(_) => {}
        }
    }
}

/// Connect + authenticate (creating the account or logging in), then wire up the
/// roster and report the logged-in state.
async fn authenticate(
    client: &mut Option<Client>,
    proxy: &EventLoopProxy<UiEvent>,
    server: &str,
    username: &str,
    display: &str,
    password: &str,
    create: bool,
) {
    let mut c = match Client::connect(server).await {
        Ok(c) => c,
        Err(_) => {
            error_status(proxy, format!("Could not reach {server}."));
            return;
        }
    };
    c.set_keystore_dir(app_dir());
    let result = if create {
        c.create_account(username, display, password).await
    } else {
        c.login(username, password).await
    };
    match result {
        Ok(()) => {
            // The server pushes our friends + presence automatically on login.
            let username = c.name().to_string();
            let display = c.display_name().to_string();
            *client = Some(c);
            emit(proxy, UiEvent::LoggedIn { username, display });
            // Login restores the saved conversations, but nothing told the UI:
            // it started empty and stayed empty, so a restart looked like the
            // chats were gone. Push the restored list.
            if let Some(c) = client.as_ref() {
                emit_conversations(proxy, c);
                // Seed the UI with every profile we know (our own + cached
                // peers), so names and avatars render before any fresh broadcast.
                emit_all_profiles(proxy, c);
            }
        }
        Err(e) => error_status(proxy, e.to_string()),
    }
}

async fn handle_command(
    client: &mut Option<Client>,
    proxy: &EventLoopProxy<UiEvent>,
    cmd: UiCommand,
) {
    match cmd {
        UiCommand::UiReady { webcodecs } => {
            eprintln!("enclave: UI ready; WebCodecs H.264 decode: {webcodecs}");
            if !webcodecs {
                error_status(
                    proxy,
                    "This system's WebView cannot decode H.264 (WebCodecs missing); \
                     watching screen shares and cameras will not work. On Linux, \
                     install the GStreamer H.264 decoder (gstreamer1.0-libav)."
                        .into(),
                );
            }
        }
        UiCommand::CreateAccount {
            server,
            username,
            display,
            password,
        } => authenticate(client, proxy, &server, &username, &display, &password, true).await,
        UiCommand::Login {
            server,
            username,
            password,
        } => authenticate(client, proxy, &server, &username, "", &password, false).await,
        UiCommand::Logout => {
            if let Some(c) = client.as_mut() {
                c.logout();
            }
            *client = None;
            emit(proxy, UiEvent::LoggedOut);
        }
        UiCommand::SetDisplayName { display } => {
            if let Some(c) = client.as_mut() {
                c.set_display_name(&display);
                emit_conversations(proxy, c);
                emit_profile(proxy, c, c.name());
            }
        }
        UiCommand::SetCustomStatus { emoji, text } => {
            if let Some(c) = client.as_mut() {
                c.set_custom_status(&emoji, &text);
                emit_profile(proxy, c, c.name());
            }
        }
        UiCommand::SetAccent { accent } => {
            if let Some(c) = client.as_mut() {
                c.set_accent(&accent);
                emit_profile(proxy, c, c.name());
            }
        }
        UiCommand::SetBio { bio } => {
            if let Some(c) = client.as_mut() {
                c.set_bio(&bio);
                emit_profile(proxy, c, c.name());
            }
        }
        UiCommand::SetAvatar { data, mime } => {
            if let Some(c) = client.as_mut() {
                match base64_decode(&data) {
                    Some(bytes) => match c.set_avatar(&bytes, &mime) {
                        Ok(()) => emit_profile(proxy, c, c.name()),
                        Err(e) => error_status(proxy, e.to_string()),
                    },
                    None => error_status(proxy, "avatar image could not be read".into()),
                }
            }
        }
        UiCommand::ClearAvatar => {
            if let Some(c) = client.as_mut() {
                c.clear_avatar();
                emit_profile(proxy, c, c.name());
            }
        }
        UiCommand::ExportSession => {
            if let Some(c) = client.as_ref() {
                let dst = app_dir().join(format!("enclave-{}-backup.enc", c.name()));
                match c.export_session(&dst) {
                    Ok(()) => emit(
                        proxy,
                        UiEvent::Status {
                            message: format!("Exported your encrypted chats to {}", dst.display()),
                            error: false,
                        },
                    ),
                    Err(e) => error_status(proxy, format!("Export failed: {e}")),
                }
            }
        }
        UiCommand::ImportSession { path } => {
            if let Some(c) = client.as_mut() {
                match c.import_session(&path) {
                    Ok(()) => {
                        emit_conversations(proxy, c);
                        emit(
                            proxy,
                            UiEvent::Status {
                                message: "Imported chats from backup.".into(),
                                error: false,
                            },
                        );
                    }
                    Err(e) => error_status(proxy, format!("Import failed: {e}")),
                }
            }
        }
        UiCommand::MarkVerified => {
            if let Some(c) = client.as_mut() {
                c.mark_verified();
                emit(proxy, active_conversation_event(c));
            }
        }
        UiCommand::StartCall => {
            if let Some(c) = client.as_mut() {
                match c.start_call().await {
                    Ok(()) => emit(proxy, UiEvent::CallState { in_call: true }),
                    Err(e) => error_status(proxy, format!("Could not start call: {e}")),
                }
            }
        }
        UiCommand::LeaveCall => {
            if let Some(c) = client.as_mut() {
                c.leave_call();
                emit(proxy, UiEvent::CallState { in_call: false });
            }
        }
        UiCommand::DeclineCall { conv } => {
            if let Some(c) = client.as_mut() {
                c.decline_call(&conv);
            }
        }
        UiCommand::ListShareSources => {
            if let Some(c) = client.as_ref() {
                let screens = c
                    .screen_sources()
                    .into_iter()
                    .map(|(id, name)| ShareSource {
                        id: format!("monitor:{id}"),
                        name,
                    })
                    .collect();
                let windows = c
                    .window_sources()
                    .into_iter()
                    .map(|(id, name)| ShareSource {
                        id: format!("window:{id}"),
                        name,
                    })
                    .collect();
                let cameras = c
                    .camera_sources()
                    .into_iter()
                    .map(|(id, name)| ShareSource {
                        id: format!("camera:{id}"),
                        name,
                    })
                    .collect();
                emit(
                    proxy,
                    UiEvent::ShareSources {
                        screens,
                        windows,
                        cameras,
                        per_app_audio: c.per_window_audio(),
                    },
                );
            }
        }
        UiCommand::StartShare { source, audio } => {
            if let Some(c) = client.as_mut() {
                start_share(c, proxy, &source, audio);
            }
        }
        UiCommand::StopScreenShare => {
            if let Some(c) = client.as_mut() {
                c.stop_screen_share();
                emit(proxy, UiEvent::ScreenShareState { sharing: false });
            }
        }
        UiCommand::StopCamera => {
            if let Some(c) = client.as_mut() {
                c.stop_camera();
                emit(proxy, UiEvent::CameraState { on: false });
            }
        }
        UiCommand::SetMuted { muted } => {
            if let Some(c) = client.as_ref() {
                c.set_muted(muted);
            }
        }
        UiCommand::SetDeafened { deafened } => {
            if let Some(c) = client.as_ref() {
                c.set_deafened(deafened);
            }
        }
        UiCommand::ListAudioDevices => {
            if let Some(c) = client.as_ref() {
                emit_audio_devices(proxy, c);
            }
        }
        UiCommand::SetInputDevice { name } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.set_input_device(Some(name)) {
                    error_status(proxy, format!("Could not switch microphone: {e}"));
                }
                emit_audio_devices(proxy, c);
            }
        }
        UiCommand::SetOutputDevice { name } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.set_output_device(Some(name)) {
                    error_status(proxy, format!("Could not switch speaker: {e}"));
                }
                emit_audio_devices(proxy, c);
            }
        }
        UiCommand::OpenDm { handle } => {
            if let Some(c) = client.as_mut() {
                match c.open_dm(&handle).await {
                    Ok(_) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not open DM: {e}")),
                }
            }
        }
        UiCommand::OpenSelfNotes => {
            if let Some(c) = client.as_mut() {
                match c.open_self_notes() {
                    Ok(_) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not open notes: {e}")),
                }
            }
        }
        UiCommand::RequestSharedGroups { handle } => {
            if let Some(c) = client.as_ref() {
                emit(
                    proxy,
                    UiEvent::SharedGroups {
                        handle: handle.clone(),
                        groups: c.shared_groups(&handle),
                    },
                );
            }
        }
        UiCommand::CreateGroup { name, members } => {
            if let Some(c) = client.as_mut() {
                match c.create_group(&name, &members).await {
                    Ok(_) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not create group: {e}")),
                }
            }
        }
        UiCommand::AddToGroup { handle } => {
            if let Some(c) = client.as_mut() {
                match c.add_to_active_group(&handle).await {
                    Ok(()) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not add to group: {e}")),
                }
            }
        }
        UiCommand::DeleteConversation { conv } => {
            if let Some(c) = client.as_mut() {
                c.delete_conversation(&conv);
                emit_conversations(proxy, c);
            }
        }
        UiCommand::LeaveGroup { conv } => {
            if let Some(c) = client.as_mut() {
                c.leave_group(&conv);
                emit_conversations(proxy, c);
            }
        }
        UiCommand::ArchiveConversation { conv } => {
            if let Some(c) = client.as_mut() {
                c.archive_conversation(&conv);
                emit_conversations(proxy, c);
            }
        }
        UiCommand::UnarchiveConversation { conv } => {
            if let Some(c) = client.as_mut() {
                c.unarchive_conversation(&conv);
                emit_conversations(proxy, c);
            }
        }
        UiCommand::ClearHistory { conv } => {
            if let Some(c) = client.as_mut() {
                c.clear_history(&conv);
                emit(proxy, active_conversation_event(c));
            }
        }
        UiCommand::RemoveMember { conv, member } => {
            if let Some(c) = client.as_mut() {
                match c.remove_member(&conv, &member) {
                    Ok(()) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not remove member: {e}")),
                }
            }
        }
        UiCommand::SwitchConversation { conv } => {
            if let Some(c) = client.as_mut() {
                c.switch(&conv);
                // Switching can un-hide an archived/deleted conversation (moving it
                // back to the live list), so refresh the summaries too.
                emit_conversations(proxy, c);
            }
        }
        UiCommand::CloseConversation => {
            if let Some(c) = client.as_mut() {
                // Deselect only; the UI already moved itself to the home view, so
                // there is nothing to emit back.
                c.deselect();
            }
        }
        UiCommand::PickFiles => {
            // The native picker blocks; run it off the async loop's thread. Chosen
            // files are ATTACHED to the composer, not sent.
            let chosen = tokio::task::spawn_blocking(|| {
                rfd::FileDialog::new()
                    .set_title("Attach files")
                    .pick_files()
            })
            .await
            .ok()
            .flatten();
            if let Some(paths) = chosen {
                let strs: Vec<String> = paths
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                emit(
                    proxy,
                    UiEvent::AttachFiles {
                        files: stat_attachments(&strs),
                    },
                );
            }
        }
        UiCommand::AttachPaths { paths } => {
            emit(
                proxy,
                UiEvent::AttachFiles {
                    files: stat_attachments(&paths),
                },
            );
        }
        UiCommand::SendFilePath { path, live } => {
            // One attachment from the composer tray, offered on Send.
            if let Some(c) = client.as_mut() {
                if c.active_id().is_none() {
                    error_status(proxy, "Open a conversation first.".into());
                    return;
                }
                offer_file_from(c, proxy, path, live).await;
            }
        }
        UiCommand::OpenFile { path } => {
            // Best-effort open with the OS default handler. This runs a file
            // the peer sent, so it is only ever triggered by an explicit user
            // click, never automatically.
            let _ = tokio::task::spawn_blocking(move || {
                let _ = open::that_detached(&path);
            })
            .await;
        }
        UiCommand::OpenLink { url } => {
            // Open a link from a message in the default browser, only on an
            // explicit click. We open just http(s) URLs so a message can't smuggle
            // a "file:" or app-scheme link that does something surprising.
            if url.starts_with("https://") || url.starts_with("http://") {
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = open::that_detached(&url);
                })
                .await;
            }
        }
        UiCommand::AcceptFile { offer_id } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.accept_file(&offer_id) {
                    error_status(proxy, format!("Could not accept file: {e}"));
                }
            }
        }
        UiCommand::DeclineFile { offer_id } => {
            if let Some(c) = client.as_mut() {
                let _ = c.decline_file(&offer_id);
            }
        }
        UiCommand::AbortFile { offer_id } => {
            if let Some(c) = client.as_mut() {
                let _ = c.abort_file(&offer_id);
            }
        }
        UiCommand::DeleteMessage { conv, id, everyone } => {
            if let Some(c) = client.as_mut() {
                c.delete_message(&conv, &id, everyone);
            }
        }
        UiCommand::React { conv, id, emoji } => {
            if let Some(c) = client.as_mut() {
                if let Some(reactions) = c.react(&conv, &id, &emoji) {
                    emit(
                        proxy,
                        UiEvent::ReactionsChanged {
                            conv,
                            id,
                            reactions,
                        },
                    );
                }
            }
        }
        UiCommand::EditMessage { conv, id, text } => {
            if let Some(c) = client.as_mut() {
                if let Some(text) = c.edit_message(&conv, &id, &text) {
                    emit(proxy, UiEvent::MessageEdited { conv, id, text });
                }
            }
        }
        UiCommand::CreatePoll {
            question,
            options,
            multi,
            reveal,
            duration_ms,
            anonymous,
        } => {
            if let Some(c) = client.as_mut() {
                let conv = c.active_id();
                let from = c.display_name().to_string();
                let user = c.name().to_string();
                match c.create_poll(&question, &options, multi, reveal, duration_ms, anonymous) {
                    Some((id, ts, poll)) => {
                        if let Some(conv) = conv {
                            emit(
                                proxy,
                                UiEvent::PollPosted {
                                    conv,
                                    id,
                                    ts,
                                    from,
                                    user,
                                    mine: true,
                                    poll: poll.into(),
                                },
                            );
                        }
                    }
                    None => error_status(
                        proxy,
                        "Could not create the poll (check the question and options).".into(),
                    ),
                }
            }
        }
        UiCommand::VotePoll { conv, id, options } => {
            if let Some(c) = client.as_mut() {
                if let Some(poll) = c.vote_poll(&conv, &id, options) {
                    emit(
                        proxy,
                        UiEvent::PollUpdated {
                            conv,
                            id,
                            poll: poll.into(),
                        },
                    );
                }
            }
        }
        UiCommand::ClosePoll { conv, id } => {
            if let Some(c) = client.as_mut() {
                if let Some(poll) = c.close_poll(&conv, &id) {
                    emit(
                        proxy,
                        UiEvent::PollUpdated {
                            conv,
                            id,
                            poll: poll.into(),
                        },
                    );
                }
            }
        }
        UiCommand::PinMessage { conv, id, pinned } => {
            if let Some(c) = client.as_mut() {
                if let Some(pinned) = c.pin_message(&conv, &id, pinned) {
                    emit(proxy, UiEvent::PinsChanged { conv, id, pinned });
                }
            }
        }
        UiCommand::SearchMessages { query, conv } => {
            if let Some(c) = client.as_ref() {
                let hits = c
                    .search_messages(&query, conv.as_deref())
                    .into_iter()
                    .map(|h| SearchHitOut {
                        conv: h.conv,
                        conv_title: h.conv_title,
                        self_notes: h.self_notes,
                        id: h.id,
                        ts: h.ts,
                        user: h.user,
                        display: h.display,
                        text: h.text,
                        mine: h.mine,
                    })
                    .collect();
                emit(
                    proxy,
                    UiEvent::SearchResults {
                        query,
                        scoped: conv.is_some(),
                        hits,
                    },
                );
            }
        }
        UiCommand::SetDisappearing { conv, ms } => {
            if let Some(c) = client.as_mut() {
                c.set_disappearing(&conv, ms);
            }
        }
        UiCommand::SetGroupHistory { conv, enable } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.set_group_history(&conv, enable) {
                    error_status(proxy, format!("Could not change history sharing: {e}"));
                }
            }
        }
        UiCommand::StartVoice => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.start_voice() {
                    error_status(proxy, format!("Could not record: {e}"));
                }
            }
        }
        UiCommand::StopVoice => {
            if let Some(c) = client.as_mut() {
                match c.stop_voice() {
                    Ok((path, duration_ms, waveform)) => {
                        emit(
                            proxy,
                            UiEvent::VoicePreview {
                                path,
                                duration_ms,
                                waveform,
                            },
                        );
                    }
                    Err(e) => error_status(proxy, format!("Recording failed: {e}")),
                }
            }
        }
        UiCommand::CancelVoice => {
            if let Some(c) = client.as_mut() {
                c.cancel_voice();
            }
        }
        UiCommand::SendVoice => {
            if let Some(c) = client.as_mut() {
                let conv = c.active_id();
                let from = c.display_name().to_string();
                let user = c.name().to_string();
                match c.send_voice().await {
                    Ok((id, ts, duration_ms, waveform)) => {
                        if let Some(conv) = conv {
                            // Resolve our own clip path to hand back for playback.
                            let path = c.voice_clip_path(&id);
                            emit(
                                proxy,
                                UiEvent::VoiceMessage {
                                    conv,
                                    id,
                                    ts,
                                    from,
                                    user,
                                    path,
                                    duration_ms,
                                    waveform,
                                    mine: true,
                                },
                            );
                        }
                    }
                    Err(e) => error_status(proxy, format!("Could not send voice message: {e}")),
                }
            }
        }
        UiCommand::PlayVoice { path, offset_ms } => {
            if let Some(c) = client.as_mut() {
                c.play_voice(&path, offset_ms);
            }
        }
        UiCommand::StopVoicePlayback => {
            if let Some(c) = client.as_ref() {
                c.stop_voice_playback();
            }
        }
        UiCommand::CancelFile { offer_id } => {
            if let Some(c) = client.as_mut() {
                let _ = c.cancel_file(&offer_id);
            }
        }
        UiCommand::SendText { text, reply_to } => {
            if let Some(c) = client.as_mut() {
                let conv = c.active_id();
                let from = c.display_name().to_string();
                let user = c.name().to_string();
                let reply = if reply_to.is_empty() {
                    None
                } else {
                    Some(reply_to.as_str())
                };
                match c.send_text(&text, reply).await {
                    Ok((id, ts)) => {
                        if let Some(conv) = conv {
                            emit(
                                proxy,
                                UiEvent::Message {
                                    conv,
                                    id,
                                    ts,
                                    reply_to,
                                    from,
                                    user,
                                    text,
                                    mine: true,
                                },
                            );
                        }
                    }
                    Err(e) => error_status(proxy, format!("Send failed: {e}")),
                }
            }
        }
        UiCommand::AddFriend { user } => {
            if let Some(c) = client.as_ref() {
                c.send_friend_request(&user);
            }
        }
        UiCommand::AcceptFriend { handle } => {
            if let Some(c) = client.as_ref() {
                c.accept_friend(&handle);
            }
        }
        UiCommand::DeclineFriend { handle } => {
            if let Some(c) = client.as_ref() {
                c.decline_friend(&handle);
            }
        }
        UiCommand::RemoveFriend { handle } => {
            if let Some(c) = client.as_mut() {
                c.remove_friend(&handle);
            }
        }
        UiCommand::SetPresence { status } => {
            if let Some(c) = client.as_ref() {
                let status = match status.as_str() {
                    "away" => Presence::Away,
                    "offline" => Presence::Offline,
                    _ => Presence::Online,
                };
                c.set_status(status);
            }
        }

        // ---- Workspaces ----
        UiCommand::CreateWorkspace { name } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.create_workspace(&name) {
                    error_status(proxy, format!("Could not create workspace: {e}"));
                }
            }
        }
        UiCommand::CreateChannel {
            workspace,
            name,
            category,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.create_channel(&workspace, &name, category.as_deref()) {
                    error_status(proxy, format!("Could not create channel: {e}"));
                }
            }
        }
        UiCommand::CreateVoiceChannel {
            workspace,
            name,
            category,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.create_voice_channel(&workspace, &name, category.as_deref()) {
                    error_status(proxy, format!("Could not create channel: {e}"));
                }
            }
        }
        UiCommand::CreatePrivateChannel {
            workspace,
            name,
            category,
            voice,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) =
                    c.create_private_channel(&workspace, &name, category.as_deref(), voice)
                {
                    error_status(proxy, format!("Could not create channel: {e}"));
                }
            }
        }
        UiCommand::AddWorkspaceMember { workspace, handle } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.workspace_add_member(&workspace, &handle).await {
                    error_status(proxy, format!("Could not add member: {e}"));
                }
            }
        }
        UiCommand::RemoveWorkspaceMember { workspace, handle } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.workspace_remove_member(&workspace, &handle) {
                    error_status(proxy, format!("Could not remove member: {e}"));
                }
            }
        }
        UiCommand::AddChannelMember {
            workspace,
            channel,
            handle,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.add_channel_member(&workspace, &channel, &handle).await {
                    error_status(proxy, format!("Could not add to channel: {e}"));
                }
            }
        }
        UiCommand::CreateRole {
            workspace,
            name,
            permissions,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.create_role(&workspace, &name, &permissions) {
                    error_status(proxy, format!("Could not create role: {e}"));
                }
            }
        }
        UiCommand::EditRole {
            workspace,
            role,
            name,
            permissions,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.edit_role(&workspace, &role, &name, &permissions) {
                    error_status(proxy, format!("Could not edit role: {e}"));
                }
            }
        }
        UiCommand::DeleteRole { workspace, role } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.delete_role(&workspace, &role) {
                    error_status(proxy, format!("Could not delete role: {e}"));
                }
            }
        }
        UiCommand::AssignRole {
            workspace,
            handle,
            role,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.assign_role(&workspace, &handle, &role) {
                    error_status(proxy, format!("Could not assign role: {e}"));
                }
            }
        }
        UiCommand::UnassignRole {
            workspace,
            handle,
            role,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.unassign_role(&workspace, &handle, &role) {
                    error_status(proxy, format!("Could not remove role: {e}"));
                }
            }
        }
        UiCommand::CreateCategory { workspace, name } => {
            if let Some(c) = client.as_mut() {
                let mut cat = [0u8; 16];
                let _ = getrandom::getrandom(&mut cat);
                let op = enclave_protocol::WorkspaceOp::CreateCategory {
                    category: cat,
                    name,
                };
                if let Err(e) = c.workspace_submit(&workspace, op) {
                    error_status(proxy, format!("Could not create category: {e}"));
                }
            }
        }
        UiCommand::MoveChannel {
            workspace,
            channel,
            category,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.move_channel(&workspace, &channel, category.as_deref()) {
                    error_status(proxy, format!("Could not move channel: {e}"));
                }
            }
        }
        UiCommand::MoveCategory {
            workspace,
            category,
            parent,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.move_category(&workspace, &category, parent.as_deref()) {
                    error_status(proxy, format!("Could not move category: {e}"));
                }
            }
        }
        UiCommand::SendChannelPost {
            workspace,
            channel,
            text,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.send_channel_post(&workspace, &channel, &text) {
                    error_status(proxy, format!("Could not send: {e}"));
                }
            }
        }
        UiCommand::OpenChannel { workspace, channel } => {
            if let Some(c) = client.as_mut() {
                // Render what we already hold immediately, then fetch the newest
                // page to catch up on anything posted while we were offline (channel
                // posts are fan-out, not the reliable per-recipient queue). The
                // fetch reply arrives as ChannelHistoryChanged and re-renders.
                emit(proxy, channel_history_event(c, &workspace, &channel));
                c.refresh_channel_history(&workspace, &channel);
            }
        }
        UiCommand::LoadOlderChannel { workspace, channel } => {
            if let Some(c) = client.as_mut() {
                c.fetch_channel_history_older(&workspace, &channel);
            }
        }
        UiCommand::CreateInvite {
            workspace,
            ttl_secs,
            max_uses,
        } => {
            if let Some(c) = client.as_mut() {
                c.create_invite(&workspace, ttl_secs, max_uses);
            }
        }
        UiCommand::RedeemInvite { code } => {
            if let Some(c) = client.as_mut() {
                c.redeem_invite(&code);
            }
        }
        UiCommand::VoiceMoveMember {
            workspace,
            channel,
            member,
        } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.voice_move_member(&workspace, &channel, &member) {
                    error_status(proxy, format!("Could not move member: {e}"));
                }
            }
        }
        UiCommand::JoinVoice { workspace, channel } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.join_voice_channel(&workspace, &channel) {
                    error_status(proxy, format!("Could not join voice: {e}"));
                } else {
                    // Start the audio best-effort; presence already registered.
                    let _ = c.start_voice_media().await;
                }
            }
        }
        UiCommand::LeaveVoice => {
            if let Some(c) = client.as_mut() {
                c.leave_voice_channel();
            }
        }
    }
}
