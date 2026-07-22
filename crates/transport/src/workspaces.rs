//! Server-side workspace storage: the append-only **op-log** per workspace, plus
//! a membership/state index derived by replaying each log (for routing and for
//! rejecting invalid submissions at ingress), plus a durable, paginated store of
//! sealed channel messages for scrollback.
//!
//! The relay validates every submitted op through `enclave_crypto::workspace`
//! before appending -- it holds no signing key so it cannot forge an op, and it
//! refuses invalid ones (bad chain, bad signature, unauthorized) rather than
//! storing garbage. Authoritative authorization is still each client's own
//! replay; this store is defense in depth plus the index the relay needs to know
//! which accounts to deliver a workspace's traffic to. Both the op-log (JSON) and
//! the channel history (an append-only framed log per channel) are persisted, so
//! a relay restart keeps workspaces and their scrollback.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use enclave_crypto::workspace::{OpError, WorkspaceState};
use enclave_protocol::{ChannelId, Permission, Sealed, SignedOp, WorkspaceId, WorkspaceSummary};

/// Most stored messages kept per channel for scrollback. Beyond this the oldest
/// is evicted, so history is bounded (a late joiner still gets a deep backlog).
const MAX_HISTORY_PER_CHANNEL: usize = 5000;
/// Eviction slack: a channel is allowed to grow to `cap + slack` before it is
/// compacted back to `cap` in one rewrite, so the durable log is rewritten once
/// per `slack` messages rather than on every message past the cap.
const HISTORY_COMPACT_SLACK: usize = 512;
/// Largest history page the relay will return in one fetch (clamps a client's
/// requested limit), so a single fetch can never dump an unbounded backlog.
pub const HISTORY_PAGE_MAX: u32 = 500;

/// Why a submitted op was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// The op itself failed op-log verification (chain / signature / authz).
    Op(OpError),
    /// A non-genesis op referenced a workspace that does not exist.
    UnknownWorkspace,
    /// A genesis op (seq 0) targeted an id that already exists.
    WorkspaceExists,
}

impl SubmitError {
    /// A short reason for the client-facing `ServerMsg::Error`.
    pub fn reason(&self) -> &'static str {
        match self {
            SubmitError::Op(_) => "workspace op rejected (invalid or unauthorized)",
            SubmitError::UnknownWorkspace => "no such workspace",
            SubmitError::WorkspaceExists => "that workspace already exists",
        }
    }
}

/// One workspace's persisted log (the state is re-derived by replay on load).
#[derive(Serialize, Deserialize)]
struct PersistedLog {
    id: WorkspaceId,
    ops: Vec<SignedOp>,
}

/// A shareable workspace invite: a bearer code an admin mints and hands out,
/// which a user redeems to request admission. Persisted so a restart keeps live
/// invites.
#[derive(Clone, Serialize, Deserialize)]
struct InviteMeta {
    workspace: WorkspaceId,
    /// Unix seconds after which the code is dead (0 = never expires).
    expires_at: u64,
    /// Total redemptions allowed (0 = unlimited).
    max_uses: u32,
    uses: u32,
}

/// Why an invite redemption was refused. An exhausted or expired code is deleted
/// on its last use, so a later redemption simply reads as `Unknown`.
#[derive(Debug, PartialEq, Eq)]
pub enum InviteError {
    /// No such code (never existed, or used up / expired and cleaned away).
    Unknown,
    /// Still present but past its expiry.
    Expired,
}

impl InviteError {
    pub fn reason(&self) -> &'static str {
        match self {
            InviteError::Unknown => "invite code not recognized",
            InviteError::Expired => "invite code has expired",
        }
    }
}

/// One stored channel message. `seq` is a per-channel monotonic id assigned at
/// store time; it is stable across eviction (evicting the front never renumbers
/// what remains) and across restart, so a client can use it as a paging cursor.
#[derive(Clone, Serialize, Deserialize)]
struct StoredMsg {
    seq: u64,
    epoch: u64,
    sealed: Sealed,
}

/// One channel's scrollback: the retained messages (oldest first, ascending
/// `seq`) and the next seq to hand out.
#[derive(Default)]
struct ChannelLog {
    msgs: Vec<StoredMsg>,
    next_seq: u64,
}

/// The append-only op-logs of every workspace, with replayed state cached in
/// memory for routing, and durable per-channel scrollback.
#[derive(Default)]
pub struct WorkspaceStore {
    logs: BTreeMap<WorkspaceId, Vec<SignedOp>>,
    /// Cached replay of each log; never serialized (rebuilt from `logs`).
    states: BTreeMap<WorkspaceId, WorkspaceState>,
    /// Retained sealed channel messages per channel (sealed; the relay holds no
    /// key). Mirrored to disk under `history_dir` when durable.
    history: BTreeMap<(WorkspaceId, ChannelId), ChannelLog>,
    /// Live invite codes, keyed by code.
    invites: BTreeMap<String, InviteMeta>,
    /// JSON path for the op-log (`None` = in-memory, e.g. tests).
    path: Option<PathBuf>,
    /// Directory holding one append-only log file per channel (`None` =
    /// in-memory: history is kept in RAM but never persisted).
    history_dir: Option<PathBuf>,
    /// JSON path for the invite table (`None` = in-memory).
    invites_path: Option<PathBuf>,
}

impl WorkspaceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file (empty if absent), replaying each log to rebuild the
    /// state index, and load durable channel history from a sibling directory
    /// (`<stem>-history/` next to the op-log file). A log that fails to replay
    /// (corrupt on disk) is dropped rather than aborting startup.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let persisted: Vec<PersistedLog> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let history_dir = history_dir_for(&path);
        let _ = std::fs::create_dir_all(&history_dir);
        let invites_path = invites_path_for(&path);
        let invites: BTreeMap<String, InviteMeta> = std::fs::read_to_string(&invites_path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let mut store = Self {
            path: Some(path),
            history_dir: Some(history_dir.clone()),
            invites_path: Some(invites_path),
            invites,
            ..Self::default()
        };
        for entry in persisted {
            match enclave_crypto::workspace::replay(&entry.ops) {
                Ok(state) => {
                    store.logs.insert(entry.id, entry.ops);
                    store.states.insert(entry.id, state);
                }
                Err(e) => {
                    // A log that no longer replays -- corrupt on disk, or written by
                    // an incompatible older op-log format (e.g. before a WorkspaceOp
                    // change shifted variant indices). Drop it rather than crash the
                    // relay, and say so, since the symptom otherwise is a confusing
                    // "op rejected" for a workspace that half-loaded.
                    eprintln!(
                        "enclave: dropping workspace {} on load (incompatible or corrupt op-log: {e:?}); \
                         it was likely created by an older build -- recreate it",
                        hex::encode(entry.id)
                    );
                }
            }
        }
        store.load_history(&history_dir);
        store
    }

    /// Read every `<wshex>__<chhex>.log` in the history directory into memory.
    fn load_history(&mut self, dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some((ws, channel)) = name.to_str().and_then(parse_history_name) else {
                continue;
            };
            let mut msgs = read_history_file(&entry.path());
            if msgs.len() > MAX_HISTORY_PER_CHANNEL {
                let overflow = msgs.len() - MAX_HISTORY_PER_CHANNEL;
                msgs.drain(0..overflow);
            }
            let next_seq = msgs.last().map(|m| m.seq + 1).unwrap_or(0);
            self.history
                .insert((ws, channel), ChannelLog { msgs, next_seq });
        }
    }

    /// Validate and append one op. Genesis ops (seq 0) register a new workspace;
    /// all others extend an existing one. Returns the routing member set on
    /// success so the caller can broadcast the op to them.
    pub fn submit(&mut self, ws: WorkspaceId, op: SignedOp) -> Result<Vec<String>, SubmitError> {
        if op.seq == 0 {
            if self.logs.contains_key(&ws) {
                return Err(SubmitError::WorkspaceExists);
            }
            let mut state = WorkspaceState::default();
            state.apply(&op).map_err(SubmitError::Op)?;
            self.logs.insert(ws, vec![op]);
            let members = state.members.keys().cloned().collect();
            self.states.insert(ws, state);
            self.save();
            Ok(members)
        } else {
            let state = self
                .states
                .get_mut(&ws)
                .ok_or(SubmitError::UnknownWorkspace)?;
            state.apply(&op).map_err(SubmitError::Op)?;
            let members = state.members.keys().cloned().collect();
            self.logs
                .get_mut(&ws)
                .expect("log exists when state does")
                .push(op);
            self.save();
            Ok(members)
        }
    }

    /// The full op-log for a workspace (empty if unknown).
    pub fn log(&self, ws: &WorkspaceId) -> &[SignedOp] {
        self.logs.get(ws).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Whether `handle` is a current member of `ws` (per the replayed state).
    pub fn is_member(&self, ws: &WorkspaceId, handle: &str) -> bool {
        self.states
            .get(ws)
            .is_some_and(|s| s.members.contains_key(handle))
    }

    /// Whether `ws` is open-join (anyone with a valid invite may self-join).
    pub fn is_open_join(&self, ws: &WorkspaceId) -> bool {
        self.states.get(ws).is_some_and(|s| s.open_join)
    }

    /// The current member handles of `ws` (for routing).
    pub fn members(&self, ws: &WorkspaceId) -> Vec<String> {
        self.states
            .get(ws)
            .map(|s| s.members.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The effective members of a channel (a private channel's subset, or the
    /// whole workspace for a public one) -- who its traffic fans out to.
    pub fn channel_members(&self, ws: &WorkspaceId, channel: &ChannelId) -> Vec<String> {
        self.states
            .get(ws)
            .map(|s| s.channel_members(channel))
            .unwrap_or_default()
    }

    /// Whether `handle` may see `channel` in `ws`.
    pub fn is_channel_member(&self, ws: &WorkspaceId, channel: &ChannelId, handle: &str) -> bool {
        self.states
            .get(ws)
            .is_some_and(|s| s.is_channel_member(channel, handle))
    }

    /// Whether `channel` is a voice channel of `ws`.
    pub fn is_voice_channel(&self, ws: &WorkspaceId, channel: &ChannelId) -> bool {
        self.states
            .get(ws)
            .and_then(|s| s.channels.get(channel))
            .is_some_and(|ch| ch.kind == enclave_protocol::ChannelKind::Voice)
    }

    /// Store one sealed channel message for scrollback: assign it the channel's
    /// next seq, append it to the durable log, and evict the oldest past the cap
    /// (compacting the file in one rewrite once the slack fills).
    pub fn store_message(
        &mut self,
        ws: WorkspaceId,
        channel: ChannelId,
        epoch: u64,
        sealed: Sealed,
    ) {
        let log = self.history.entry((ws, channel)).or_default();
        let seq = log.next_seq;
        log.next_seq += 1;
        let record = StoredMsg { seq, epoch, sealed };
        log.msgs.push(record.clone());
        // Append to disk (O(1)); compact only when the slack fills, so the file
        // is rewritten once per `slack` messages, not on every message.
        if let Some(dir) = &self.history_dir {
            let file = history_file(dir, &ws, &channel);
            append_history_record(&file, &record);
            if log.msgs.len() > MAX_HISTORY_PER_CHANNEL + HISTORY_COMPACT_SLACK {
                let overflow = log.msgs.len() - MAX_HISTORY_PER_CHANNEL;
                log.msgs.drain(0..overflow);
                rewrite_history_file(&file, &log.msgs);
            }
        } else if log.msgs.len() > MAX_HISTORY_PER_CHANNEL + HISTORY_COMPACT_SLACK {
            let overflow = log.msgs.len() - MAX_HISTORY_PER_CHANNEL;
            log.msgs.drain(0..overflow);
        }
    }

    /// One page of a channel's scrollback, oldest-first within the page. `before`
    /// = `None` returns the newest `limit` messages; `Some(seq)` returns the page
    /// of messages with a smaller seq (the page just older than what the caller
    /// holds). Returns `(messages, has_more)` where each message is
    /// `(seq, epoch, sealed)` and `has_more` says whether still-older retained
    /// messages exist before this page.
    pub fn channel_history_page(
        &self,
        ws: &WorkspaceId,
        channel: &ChannelId,
        before: Option<u64>,
        limit: u32,
    ) -> (Vec<(u64, u64, Sealed)>, bool) {
        let limit = limit.clamp(1, HISTORY_PAGE_MAX) as usize;
        let Some(log) = self.history.get(&(*ws, *channel)) else {
            return (Vec::new(), false);
        };
        // `msgs` is ascending by seq, so the newest are at the end.
        let end = match before {
            Some(b) => log.msgs.partition_point(|m| m.seq < b),
            None => log.msgs.len(),
        };
        let start = end.saturating_sub(limit);
        let page = log.msgs[start..end]
            .iter()
            .map(|m| (m.seq, m.epoch, m.sealed.clone()))
            .collect();
        (page, start > 0)
    }

    /// Whether `handle` holds `perm` in `ws` (defense-in-depth for relay-side
    /// actions; the op-log replay is still the authority).
    pub fn has_permission(&self, ws: &WorkspaceId, handle: &str, perm: Permission) -> bool {
        self.states
            .get(ws)
            .is_some_and(|s| s.has_permission(handle, perm))
    }

    /// The current members of `ws` who hold `perm` -- e.g. those who can admit a
    /// join request (`ManageMembers`).
    pub fn members_with(&self, ws: &WorkspaceId, perm: Permission) -> Vec<String> {
        self.states
            .get(ws)
            .map(|s| {
                s.members
                    .keys()
                    .filter(|h| s.has_permission(h, perm))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Record a new invite code for `ws`.
    pub fn create_invite(&mut self, ws: WorkspaceId, code: String, expires_at: u64, max_uses: u32) {
        self.invites.insert(
            code,
            InviteMeta {
                workspace: ws,
                expires_at,
                max_uses,
                uses: 0,
            },
        );
        self.save_invites();
    }

    /// Validate a code without consuming it, returning its workspace. Lets the
    /// caller confirm an admin is reachable before spending a use.
    pub fn peek_invite(&self, code: &str, now: u64) -> Result<WorkspaceId, InviteError> {
        let inv = self.invites.get(code).ok_or(InviteError::Unknown)?;
        if inv.expires_at != 0 && now >= inv.expires_at {
            return Err(InviteError::Expired);
        }
        // Exhausted codes are removed on their last use, so this is a defensive
        // guard (e.g. a code loaded from disk at its limit): treat it as gone.
        if inv.max_uses != 0 && inv.uses >= inv.max_uses {
            return Err(InviteError::Unknown);
        }
        Ok(inv.workspace)
    }

    /// Spend one use of a code (call after a join request was actually routed),
    /// deleting it once exhausted or expired.
    pub fn consume_invite(&mut self, code: &str, now: u64) {
        if let Some(inv) = self.invites.get_mut(code) {
            inv.uses += 1;
            let dead = (inv.max_uses != 0 && inv.uses >= inv.max_uses)
                || (inv.expires_at != 0 && now >= inv.expires_at);
            if dead {
                self.invites.remove(code);
            }
        }
        self.save_invites();
    }

    /// The workspaces `handle` currently belongs to, summarized for the sidebar.
    pub fn workspaces_of(&self, handle: &str) -> Vec<WorkspaceSummary> {
        self.states
            .iter()
            .filter(|(_, s)| s.members.contains_key(handle))
            .map(|(id, s)| WorkspaceSummary {
                id: *id,
                name: s.name.clone(),
            })
            .collect()
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let persisted: Vec<PersistedLog> = self
            .logs
            .iter()
            .map(|(id, ops)| PersistedLog {
                id: *id,
                ops: ops.clone(),
            })
            .collect();
        if let Ok(text) = serde_json::to_string_pretty(&persisted) {
            let _ = std::fs::write(path, text);
        }
    }

    fn save_invites(&self) {
        let Some(path) = &self.invites_path else {
            return;
        };
        if let Ok(text) = serde_json::to_string_pretty(&self.invites) {
            let _ = std::fs::write(path, text);
        }
    }
}

/// The JSON file holding invite codes for an op-log at `path`:
/// `<parent>/<stem>-invites.json`.
fn invites_path_for(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("enclave-workspaces");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}-invites.json"))
}

/// The directory that holds per-channel history logs for an op-log at `path`:
/// `<parent>/<stem>-history/`.
fn history_dir_for(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("enclave-workspaces");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{stem}-history"))
}

fn history_file(dir: &Path, ws: &WorkspaceId, channel: &ChannelId) -> PathBuf {
    dir.join(format!("{}__{}.log", hex::encode(ws), hex::encode(channel)))
}

/// Parse a `<wshex>__<chhex>.log` filename back into its ids.
fn parse_history_name(name: &str) -> Option<(WorkspaceId, ChannelId)> {
    let base = name.strip_suffix(".log")?;
    let (ws_hex, ch_hex) = base.split_once("__")?;
    let ws = hex::decode(ws_hex).ok()?;
    let ch = hex::decode(ch_hex).ok()?;
    Some((ws.try_into().ok()?, ch.try_into().ok()?))
}

/// Append one length-framed bincode record to a channel's log file.
fn append_history_record(path: &Path, record: &StoredMsg) {
    let Ok(bytes) = bincode::serialize(record) else {
        return;
    };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let len = bytes.len() as u32;
        let _ = f.write_all(&len.to_le_bytes());
        let _ = f.write_all(&bytes);
    }
}

/// Rewrite a channel's log file from the retained records (compaction).
fn rewrite_history_file(path: &Path, msgs: &[StoredMsg]) {
    let tmp = path.with_extension("log.tmp");
    let Ok(mut f) = std::fs::File::create(&tmp) else {
        return;
    };
    for record in msgs {
        let Ok(bytes) = bincode::serialize(record) else {
            continue;
        };
        let len = bytes.len() as u32;
        if f.write_all(&len.to_le_bytes()).is_err() || f.write_all(&bytes).is_err() {
            return;
        }
    }
    let _ = f.sync_all();
    let _ = std::fs::rename(&tmp, path);
}

/// Read every length-framed record from a channel's log file (empty on any error,
/// stopping at the first truncated/corrupt frame so a partially-written tail is
/// tolerated rather than fatal).
fn read_history_file(path: &Path) -> Vec<StoredMsg> {
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= buf.len() {
        let len = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if i + len > buf.len() {
            break; // truncated tail
        }
        match bincode::deserialize::<StoredMsg>(&buf[i..i + len]) {
            Ok(record) => out.push(record),
            Err(_) => break,
        }
        i += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_crypto::workspace::sign_genesis;
    use enclave_crypto::workspace::{sign_op, WorkspaceState};
    use enclave_crypto::Identity;
    use enclave_protocol::WorkspaceOp;

    #[test]
    fn a_genesis_registers_a_workspace_and_a_second_is_rejected() {
        let owner = Identity::generate("owner").unwrap();
        let mut store = WorkspaceStore::new();
        let ws = [7u8; 16];

        let g = sign_genesis(&owner, "owner#1", "Team", 100).unwrap();
        let members = store.submit(ws, g.clone()).unwrap();
        assert_eq!(members, vec!["owner#1".to_string()]);
        assert!(store.is_member(&ws, "owner#1"));
        assert_eq!(store.workspaces_of("owner#1").len(), 1);

        // A second genesis on the same id is refused.
        assert_eq!(store.submit(ws, g), Err(SubmitError::WorkspaceExists));
    }

    #[test]
    fn ops_extend_the_log_and_membership_updates_for_routing() {
        let owner = Identity::generate("owner").unwrap();
        let bob = Identity::generate("bob").unwrap();
        let mut store = WorkspaceStore::new();
        let ws = [1u8; 16];

        store
            .submit(ws, sign_genesis(&owner, "owner#1", "Team", 100).unwrap())
            .unwrap();

        // Rebuild the current state to sign the next op against the right head.
        let state = enclave_crypto::workspace::replay(store.log(&ws)).unwrap();
        let add = sign_op(
            &owner,
            "owner#1",
            &state,
            101,
            WorkspaceOp::AddMember {
                member: "bob#2".into(),
                member_key: bob.identity_key(),
            },
        )
        .unwrap();
        let members = store.submit(ws, add).unwrap();
        assert!(members.contains(&"bob#2".to_string()));
        assert_eq!(store.log(&ws).len(), 2);
        assert_eq!(store.workspaces_of("bob#2").len(), 1);
    }

    #[test]
    fn an_op_for_an_unknown_workspace_is_refused() {
        let owner = Identity::generate("owner").unwrap();
        let mut store = WorkspaceStore::new();
        let state = WorkspaceState::default();
        let mut add = sign_op(
            &owner,
            "owner#1",
            &state,
            100,
            WorkspaceOp::AddMember {
                member: "x#2".into(),
                member_key: vec![0u8; 32],
            },
        )
        .unwrap();
        add.seq = 5; // not genesis, references a workspace that does not exist
        assert_eq!(
            store.submit([9u8; 16], add),
            Err(SubmitError::UnknownWorkspace)
        );
    }

    #[test]
    fn history_pages_newest_first_and_walks_older_by_cursor() {
        let mut store = WorkspaceStore::new();
        let ws = [3u8; 16];
        let ch = [4u8; 16];
        // 250 messages, epoch 0.
        for i in 0..250u64 {
            store.store_message(ws, ch, 0, Sealed(vec![i as u8]));
        }
        // Newest page of 100.
        let (page, more) = store.channel_history_page(&ws, &ch, None, 100);
        assert_eq!(page.len(), 100);
        assert!(more, "150 older messages remain");
        assert_eq!(page.first().unwrap().0, 150); // seq 150..249
        assert_eq!(page.last().unwrap().0, 249);
        // Older page before the oldest we hold (seq 150).
        let (older, more2) = store.channel_history_page(&ws, &ch, Some(150), 100);
        assert_eq!(older.len(), 100);
        assert!(more2, "50 older still remain");
        assert_eq!(older.first().unwrap().0, 50);
        assert_eq!(older.last().unwrap().0, 149);
        // The last page runs out.
        let (last, more3) = store.channel_history_page(&ws, &ch, Some(50), 100);
        assert_eq!(last.len(), 50);
        assert!(!more3, "reached the start");
        assert_eq!(last.first().unwrap().0, 0);
    }

    #[test]
    fn invites_validate_expiry_and_use_limits() {
        let owner = Identity::generate("owner").unwrap();
        let mut store = WorkspaceStore::new();
        let ws = [2u8; 16];
        store
            .submit(ws, sign_genesis(&owner, "owner#1", "Team", 100).unwrap())
            .unwrap();
        assert!(store.has_permission(&ws, "owner#1", Permission::ManageMembers));
        assert!(!store.has_permission(&ws, "bob#2", Permission::ManageMembers));

        // A single-use code expiring at t=1000.
        store.create_invite(ws, "code1".into(), 1000, 1);
        assert_eq!(store.peek_invite("code1", 500), Ok(ws));
        assert_eq!(store.peek_invite("nope", 500), Err(InviteError::Unknown));
        assert_eq!(store.peek_invite("code1", 1000), Err(InviteError::Expired));
        // Spend its one use: an exhausted code is deleted, so it reads as unknown.
        store.consume_invite("code1", 500);
        assert_eq!(store.peek_invite("code1", 500), Err(InviteError::Unknown));

        // An unlimited, never-expiring code stays valid across many uses.
        store.create_invite(ws, "forever".into(), 0, 0);
        for t in [0, 10_000, 999_999] {
            assert_eq!(store.peek_invite("forever", t), Ok(ws));
            store.consume_invite("forever", t);
        }
        assert_eq!(store.peek_invite("forever", 0), Ok(ws));
    }

    #[test]
    fn history_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("enclave-wstest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ws.json");
        let ws = [5u8; 16];
        let ch = [6u8; 16];
        {
            let mut store = WorkspaceStore::load(&path);
            for i in 0..30u64 {
                store.store_message(ws, ch, 0, Sealed(vec![i as u8, (i * 2) as u8]));
            }
        }
        // Reopen: the durable history is reloaded, seq and payloads intact.
        let store = WorkspaceStore::load(&path);
        let (page, more) = store.channel_history_page(&ws, &ch, None, 500);
        assert_eq!(page.len(), 30);
        assert!(!more);
        assert_eq!(page.first().unwrap().0, 0);
        assert_eq!(page.last().unwrap().0, 29);
        assert_eq!(page.last().unwrap().2 .0, vec![29u8, 58u8]);
        // A message stored after reload continues the seq, not restarts it.
        let mut store = store;
        store.store_message(ws, ch, 0, Sealed(vec![99u8]));
        let (page, _) = store.channel_history_page(&ws, &ch, None, 1);
        assert_eq!(page.last().unwrap().0, 30);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
