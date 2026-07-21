//! Server-side workspace storage: the append-only **op-log** per workspace, plus
//! a membership/state index derived by replaying each log (for routing and for
//! rejecting invalid submissions at ingress).
//!
//! The relay validates every submitted op through `enclave_crypto::workspace`
//! before appending -- it holds no signing key so it cannot forge an op, and it
//! refuses invalid ones (bad chain, bad signature, unauthorized) rather than
//! storing garbage. Authoritative authorization is still each client's own
//! replay; this store is defense in depth plus the index the relay needs to know
//! which accounts to deliver a workspace's traffic to. Persisted to JSON so
//! workspaces survive a restart.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use enclave_crypto::workspace::{OpError, WorkspaceState};
use enclave_protocol::{ChannelId, Sealed, SignedOp, WorkspaceId, WorkspaceSummary};

/// Most stored messages kept per channel for scrollback. Beyond this the oldest
/// is evicted, so history is bounded (a late joiner still gets a deep backlog).
/// In memory: a server restart loses stored history (a documented limitation,
/// like the ballot buffer); the op-log itself is persisted.
const MAX_HISTORY_PER_CHANNEL: usize = 5000;

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

/// The append-only op-logs of every workspace, with replayed state cached in
/// memory for routing.
#[derive(Default)]
pub struct WorkspaceStore {
    logs: BTreeMap<WorkspaceId, Vec<SignedOp>>,
    /// Cached replay of each log; never serialized (rebuilt from `logs`).
    states: BTreeMap<WorkspaceId, WorkspaceState>,
    /// Stored channel messages for scrollback: `(epoch, sealed)` per channel,
    /// oldest first. In memory; sealed (the relay holds no key).
    history: BTreeMap<(WorkspaceId, ChannelId), Vec<(u64, Sealed)>>,
    path: Option<PathBuf>,
}

impl WorkspaceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file (empty if absent), replaying each log to rebuild the
    /// state index. A log that fails to replay (corrupt on disk) is dropped rather
    /// than aborting startup.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let persisted: Vec<PersistedLog> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let mut store = Self {
            path: Some(path),
            ..Self::default()
        };
        for entry in persisted {
            match enclave_crypto::workspace::replay(&entry.ops) {
                Ok(state) => {
                    store.logs.insert(entry.id, entry.ops);
                    store.states.insert(entry.id, state);
                }
                Err(_) => {
                    // Corrupt persisted log; skip it (a fresh empty store is safer
                    // than crashing the whole relay on one bad file).
                }
            }
        }
        store
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

    /// Store one sealed channel message for scrollback, evicting the oldest past
    /// the per-channel cap so history stays bounded.
    pub fn store_message(
        &mut self,
        ws: WorkspaceId,
        channel: ChannelId,
        epoch: u64,
        sealed: Sealed,
    ) {
        let log = self.history.entry((ws, channel)).or_default();
        log.push((epoch, sealed));
        if log.len() > MAX_HISTORY_PER_CHANNEL {
            let overflow = log.len() - MAX_HISTORY_PER_CHANNEL;
            log.drain(0..overflow);
        }
    }

    /// A channel's stored history (`(epoch, sealed)` oldest first) for backfill.
    pub fn channel_history(&self, ws: &WorkspaceId, channel: &ChannelId) -> Vec<(u64, Sealed)> {
        self.history
            .get(&(*ws, *channel))
            .cloned()
            .unwrap_or_default()
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
        // A non-genesis op (seq forced >0 by signing against a non-empty state is
        // awkward; instead craft the simplest: submit a seq-0-less op). Use an
        // AddMember whose seq is 0 would be a genesis mismatch, so build against a
        // fake state with next_seq 1 is not reachable -- simplest: unknown ws with
        // any op that is not seq 0.
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
}
