//! The workspace **op-log**: a verifiable, append-only, identity-signed record
//! of a workspace's structure and membership. Replaying it from the genesis op
//! yields the authoritative [`WorkspaceState`] (owner, roles, members and their
//! identity keys, categories, channels), with every entry checked three ways:
//!
//! - **chain** -- each entry's `prev_hash` must equal the SHA-256 of the previous
//!   entry's body, so a reordered, dropped, or forked log is detected;
//! - **signature** -- the entry is signed by `author`'s identity key (verified via
//!   [`crate::verify_op`]), so the relay cannot forge an entry;
//! - **authorization** -- the author must hold the role the op requires *at that
//!   point in the log*, so a member cannot perform admin actions.
//!
//! Because authorization is decided by replay, not asserted by the server, the
//! untrusted relay can store and route the log but never forge who is a member or
//! an admin. This is the trust anchor for the whole workspace feature.
//!
//! PRIMITIVE: the single source of truth for workspace membership and roles.
//! Both the client (authoritative) and the relay (ingress validation) replay
//! through here; never re-derive membership elsewhere.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use enclave_protocol::{
    CategoryId, ChannelId, ChannelKind, Role, SignedOp, WorkspaceOp, WS_OP_CONTEXT,
};

use crate::{CryptoError, Identity};

/// Why an op-log entry was rejected. Precise so tests and callers can assert the
/// exact failure rather than a generic "bad op".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    /// `seq` was not the next expected position.
    BadSeq { expected: u64, got: u64 },
    /// `prev_hash` did not match the head of the log (a fork or reorder).
    BadChain,
    /// The signature did not verify against `author_key`.
    BadSignature,
    /// The first entry was not a well-formed genesis `Create`.
    BadGenesis,
    /// A non-genesis op tried to occupy seq 0, or a `Create` appeared after seq 0.
    MisplacedGenesis,
    /// The author is not a current member.
    UnknownAuthor,
    /// The author lacks the role this op requires.
    Unauthorized,
    /// The op referenced a channel/category/member that does not exist, or would
    /// duplicate one that does.
    BadTarget,
}

/// One channel's structure (not its content).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelInfo {
    pub id: ChannelId,
    pub name: String,
    pub kind: ChannelKind,
    pub private: bool,
    pub category: Option<CategoryId>,
}

/// The state produced by replaying a workspace's op-log. Authoritative for who
/// is a member, their roles and identity keys, and the channel/category tree.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceState {
    pub name: String,
    pub owner: String,
    owner_key: Vec<u8>,
    /// Members -> their identity public key (what their future ops verify against).
    pub members: BTreeMap<String, Vec<u8>>,
    /// Members -> role. Every member has an entry; absent means `Member`.
    pub roles: BTreeMap<String, Role>,
    pub categories: BTreeMap<CategoryId, String>,
    pub channels: BTreeMap<ChannelId, ChannelInfo>,
    /// Explicit member set of each **private** channel. Public channels are not
    /// tracked here -- their members are the whole workspace ([`channel_members`]).
    private_members: BTreeMap<ChannelId, BTreeSet<String>>,
    /// Next expected `seq`.
    next_seq: u64,
    /// SHA-256 of the last applied entry's body (chain head); all-zero at genesis.
    head_hash: [u8; 32],
}

/// The canonical bytes signed and hashed for an entry: every field except `sig`,
/// in a fixed order. Deterministic, so signer and verifier agree exactly.
fn body_bytes_of(
    seq: u64,
    prev_hash: &[u8; 32],
    author: &str,
    author_key: &[u8],
    ts: u64,
    op: &WorkspaceOp,
) -> Vec<u8> {
    bincode::serialize(&(seq, prev_hash, author, author_key, ts, op)).unwrap_or_default()
}

/// The canonical body bytes of a fully-formed entry.
pub fn body_bytes(op: &SignedOp) -> Vec<u8> {
    body_bytes_of(
        op.seq,
        &op.prev_hash,
        &op.author,
        &op.author_key,
        op.ts,
        &op.op,
    )
}

fn hash_body(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

impl WorkspaceState {
    /// The position the next appended op must occupy.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The chain head the next op must reference in `prev_hash`.
    pub fn head_hash(&self) -> [u8; 32] {
        self.head_hash
    }

    /// A member's effective role (`Member` if unspecified, nothing if not a member).
    pub fn role_of(&self, handle: &str) -> Option<Role> {
        self.members
            .contains_key(handle)
            .then(|| self.roles.get(handle).copied().unwrap_or(Role::Member))
    }

    /// Verify and apply one entry, advancing the state. On any failure the state
    /// is left unchanged and the precise [`OpError`] is returned.
    pub fn apply(&mut self, entry: &SignedOp) -> Result<(), OpError> {
        // 1. Position + chain.
        if entry.seq != self.next_seq {
            return Err(OpError::BadSeq {
                expected: self.next_seq,
                got: entry.seq,
            });
        }
        if entry.prev_hash != self.head_hash {
            return Err(OpError::BadChain);
        }
        // 2. Signature (self-contained: the entry carries the author's key, and
        //    authorization below ties that key to a member the log admitted).
        let body = body_bytes(entry);
        if !crate::verify_op(&entry.author_key, WS_OP_CONTEXT, &body, &entry.sig) {
            return Err(OpError::BadSignature);
        }
        // 3. Authorization + mutation (genesis is special).
        if entry.seq == 0 {
            self.apply_genesis(entry)?;
        } else {
            self.apply_op(entry)?;
        }
        // 4. Advance the chain.
        self.next_seq += 1;
        self.head_hash = hash_body(&body);
        Ok(())
    }

    fn apply_genesis(&mut self, entry: &SignedOp) -> Result<(), OpError> {
        let WorkspaceOp::Create {
            name,
            owner,
            owner_key,
        } = &entry.op
        else {
            return Err(OpError::MisplacedGenesis);
        };
        // The genesis author must be the owner it names, with the named key.
        if &entry.author != owner || &entry.author_key != owner_key {
            return Err(OpError::BadGenesis);
        }
        self.name = name.clone();
        self.owner = owner.clone();
        self.owner_key = owner_key.clone();
        self.members.insert(owner.clone(), owner_key.clone());
        self.roles.insert(owner.clone(), Role::Owner);
        Ok(())
    }

    fn apply_op(&mut self, entry: &SignedOp) -> Result<(), OpError> {
        // A Create after genesis is illegal; every other op requires the author
        // to be a current member whose key matches the one on record.
        if matches!(entry.op, WorkspaceOp::Create { .. }) {
            return Err(OpError::MisplacedGenesis);
        }
        match self.members.get(&entry.author) {
            Some(k) if k == &entry.author_key => {}
            Some(_) => return Err(OpError::BadSignature), // key changed under us
            None => return Err(OpError::UnknownAuthor),
        }
        let actor = self.role_of(&entry.author).ok_or(OpError::UnknownAuthor)?;

        match &entry.op {
            WorkspaceOp::Create { .. } => unreachable!("handled above"),

            WorkspaceOp::AddMember { member, member_key } => {
                require(actor >= Role::Admin)?;
                if self.members.contains_key(member) {
                    return Err(OpError::BadTarget);
                }
                self.members.insert(member.clone(), member_key.clone());
                self.roles.insert(member.clone(), Role::Member);
            }

            WorkspaceOp::RemoveMember { member } => {
                let target = self.role_of(member).ok_or(OpError::BadTarget)?;
                // You may remove someone strictly below you; nobody removes the
                // owner. (Owner > Admin > Member.)
                require(actor > target && target != Role::Owner)?;
                self.members.remove(member);
                self.roles.remove(member);
                // Drop them from every private channel too.
                for set in self.private_members.values_mut() {
                    set.remove(member);
                }
            }

            WorkspaceOp::GrantRole { member, role } => {
                // Only the owner grants Admin; Owner is never granted this way.
                require(*role == Role::Admin && actor == Role::Owner)?;
                if !self.members.contains_key(member) {
                    return Err(OpError::BadTarget);
                }
                self.roles.insert(member.clone(), Role::Admin);
            }

            WorkspaceOp::RevokeRole { member, role } => {
                require(*role == Role::Admin && actor == Role::Owner)?;
                match self.role_of(member) {
                    Some(Role::Admin) => {
                        self.roles.insert(member.clone(), Role::Member);
                    }
                    _ => return Err(OpError::BadTarget),
                }
            }

            WorkspaceOp::CreateCategory { category, name } => {
                require(actor >= Role::Admin)?;
                if self.categories.contains_key(category) {
                    return Err(OpError::BadTarget);
                }
                self.categories.insert(*category, name.clone());
            }

            WorkspaceOp::CreateChannel {
                channel,
                name,
                kind,
                private,
                category,
            } => {
                require(actor >= Role::Admin)?;
                if self.channels.contains_key(channel) {
                    return Err(OpError::BadTarget);
                }
                if let Some(cat) = category {
                    if !self.categories.contains_key(cat) {
                        return Err(OpError::BadTarget);
                    }
                }
                self.channels.insert(
                    *channel,
                    ChannelInfo {
                        id: *channel,
                        name: name.clone(),
                        kind: *kind,
                        private: *private,
                        category: *category,
                    },
                );
                // A private channel starts with just its creator as a member.
                if *private {
                    let mut set = BTreeSet::new();
                    set.insert(entry.author.clone());
                    self.private_members.insert(*channel, set);
                }
            }

            WorkspaceOp::RenameChannel { channel, name } => {
                require(actor >= Role::Admin)?;
                let ch = self.channels.get_mut(channel).ok_or(OpError::BadTarget)?;
                ch.name = name.clone();
            }

            WorkspaceOp::DeleteChannel { channel } => {
                require(actor >= Role::Admin)?;
                if self.channels.remove(channel).is_none() {
                    return Err(OpError::BadTarget);
                }
                self.private_members.remove(channel);
            }

            WorkspaceOp::AddChannelMember { channel, member } => {
                require(actor >= Role::Admin)?;
                // The channel must exist and be private, and the target must be a
                // workspace member.
                match self.channels.get(channel) {
                    Some(ch) if ch.private => {}
                    _ => return Err(OpError::BadTarget),
                }
                if !self.members.contains_key(member) {
                    return Err(OpError::BadTarget);
                }
                self.private_members
                    .entry(*channel)
                    .or_default()
                    .insert(member.clone());
            }

            WorkspaceOp::RemoveChannelMember { channel, member } => {
                require(actor >= Role::Admin)?;
                let removed = self
                    .private_members
                    .get_mut(channel)
                    .is_some_and(|set| set.remove(member));
                if !removed {
                    return Err(OpError::BadTarget);
                }
            }
        }
        Ok(())
    }

    /// The effective members of a channel: for a private channel, its explicit
    /// set; for a public channel (or an unknown id), the whole workspace.
    pub fn channel_members(&self, channel: &ChannelId) -> Vec<String> {
        match self.channels.get(channel) {
            Some(ch) if ch.private => self
                .private_members
                .get(channel)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default(),
            _ => self.members.keys().cloned().collect(),
        }
    }

    /// Whether `handle` may see `channel` (a member of a private channel, or any
    /// member for a public one).
    pub fn is_channel_member(&self, channel: &ChannelId, handle: &str) -> bool {
        match self.channels.get(channel) {
            Some(ch) if ch.private => self
                .private_members
                .get(channel)
                .is_some_and(|s| s.contains(handle)),
            Some(_) => self.members.contains_key(handle),
            None => false,
        }
    }
}

fn require(ok: bool) -> Result<(), OpError> {
    ok.then_some(()).ok_or(OpError::Unauthorized)
}

/// Replay a whole log from genesis, returning the final state or the first
/// entry's error. An empty log yields the default (empty) state.
pub fn replay(ops: &[SignedOp]) -> Result<WorkspaceState, OpError> {
    let mut state = WorkspaceState::default();
    for entry in ops {
        state.apply(entry)?;
    }
    Ok(state)
}

/// Build and sign the next op-log entry against `state`'s current head. The
/// author signs with their identity key; the result is ready to submit and will
/// replay cleanly on every member (assuming they hold `state`).
pub fn sign_op(
    identity: &Identity,
    author: &str,
    state: &WorkspaceState,
    ts: u64,
    op: WorkspaceOp,
) -> Result<SignedOp, CryptoError> {
    let seq = state.next_seq();
    let prev_hash = state.head_hash();
    let author_key = identity.identity_key();
    let body = body_bytes_of(seq, &prev_hash, author, &author_key, ts, &op);
    let sig = identity.sign_op(WS_OP_CONTEXT, &body)?;
    Ok(SignedOp {
        seq,
        prev_hash,
        author: author.to_string(),
        author_key,
        ts,
        op,
        sig,
    })
}

/// Build and sign the **genesis** entry that creates a workspace owned by
/// `identity`. Seq 0, empty chain head.
pub fn sign_genesis(
    identity: &Identity,
    owner: &str,
    name: &str,
    ts: u64,
) -> Result<SignedOp, CryptoError> {
    let op = WorkspaceOp::Create {
        name: name.to_string(),
        owner: owner.to_string(),
        owner_key: identity.identity_key(),
    };
    sign_op(identity, owner, &WorkspaceState::default(), ts, op)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (Identity, Identity, Identity) {
        (
            Identity::generate("owner").unwrap(),
            Identity::generate("admin").unwrap(),
            Identity::generate("member").unwrap(),
        )
    }

    // Build a small workspace: owner creates it, adds admin + member, promotes
    // admin, and makes a category + channel. Returns the replayed state.
    fn seed() -> (WorkspaceState, Identity, Identity, Identity) {
        let (owner, admin, member) = ids();
        let mut log = Vec::new();
        let mut st = WorkspaceState::default();

        let g = sign_genesis(&owner, "owner#1", "Team", 100).unwrap();
        st.apply(&g).unwrap();
        log.push(g);

        for (id, name, key) in [
            (&owner, "admin#2", admin.identity_key()),
            (&owner, "member#3", member.identity_key()),
        ] {
            let op = sign_op(
                id,
                "owner#1",
                &st,
                101,
                WorkspaceOp::AddMember {
                    member: name.into(),
                    member_key: key,
                },
            )
            .unwrap();
            st.apply(&op).unwrap();
            log.push(op);
        }

        let promote = sign_op(
            &owner,
            "owner#1",
            &st,
            102,
            WorkspaceOp::GrantRole {
                member: "admin#2".into(),
                role: Role::Admin,
            },
        )
        .unwrap();
        st.apply(&promote).unwrap();

        // Full replay must match the incremental state.
        assert_eq!(replay(&log).unwrap().members.len(), st.members.len());
        (st, owner, admin, member)
    }

    #[test]
    fn genesis_establishes_owner_and_roles() {
        let (st, ..) = seed();
        assert_eq!(st.owner, "owner#1");
        assert_eq!(st.role_of("owner#1"), Some(Role::Owner));
        assert_eq!(st.role_of("admin#2"), Some(Role::Admin));
        assert_eq!(st.role_of("member#3"), Some(Role::Member));
        assert_eq!(st.role_of("nobody"), None);
    }

    #[test]
    fn an_admin_can_manage_channels_a_member_cannot() {
        let (mut st, _owner, admin, member) = seed();
        let cat = [1u8; 16];
        let chan = [2u8; 16];

        // Admin creates a category + channel: allowed.
        let c1 = sign_op(
            &admin,
            "admin#2",
            &st,
            200,
            WorkspaceOp::CreateCategory {
                category: cat,
                name: "Text".into(),
            },
        )
        .unwrap();
        st.apply(&c1).unwrap();
        let c2 = sign_op(
            &admin,
            "admin#2",
            &st,
            200,
            WorkspaceOp::CreateChannel {
                channel: chan,
                name: "general".into(),
                kind: ChannelKind::Text,
                private: false,
                category: Some(cat),
            },
        )
        .unwrap();
        st.apply(&c2).unwrap();
        assert_eq!(st.channels.get(&chan).unwrap().name, "general");

        // Member tries to create a channel: rejected, state unchanged.
        let bad = sign_op(
            &member,
            "member#3",
            &st,
            201,
            WorkspaceOp::CreateChannel {
                channel: [9u8; 16],
                name: "sneaky".into(),
                kind: ChannelKind::Text,
                private: false,
                category: None,
            },
        )
        .unwrap();
        assert_eq!(st.apply(&bad), Err(OpError::Unauthorized));
        assert_eq!(st.channels.len(), 1);
    }

    #[test]
    fn only_the_owner_grants_admin_and_only_higher_roles_remove() {
        let (mut st, _owner, admin, _member) = seed();
        // An admin cannot promote the member to admin (owner-only).
        let bad_grant = sign_op(
            &admin,
            "admin#2",
            &st,
            300,
            WorkspaceOp::GrantRole {
                member: "member#3".into(),
                role: Role::Admin,
            },
        )
        .unwrap();
        assert_eq!(st.apply(&bad_grant), Err(OpError::Unauthorized));

        // An admin cannot remove another admin or the owner...
        let bad_rm = sign_op(
            &admin,
            "admin#2",
            &st,
            300,
            WorkspaceOp::RemoveMember {
                member: "owner#1".into(),
            },
        )
        .unwrap();
        assert_eq!(st.apply(&bad_rm), Err(OpError::Unauthorized));
        // ...but can remove a plain member.
        let ok_rm = sign_op(
            &admin,
            "admin#2",
            &st,
            300,
            WorkspaceOp::RemoveMember {
                member: "member#3".into(),
            },
        )
        .unwrap();
        st.apply(&ok_rm).unwrap();
        assert_eq!(st.role_of("member#3"), None);
    }

    #[test]
    fn a_private_channel_tracks_its_own_member_set() {
        let (mut st, owner, _admin, _member) = seed();
        let chan = [4u8; 16];
        // Owner creates a PRIVATE channel: starts with just the owner.
        let c = sign_op(
            &owner,
            "owner#1",
            &st,
            700,
            WorkspaceOp::CreateChannel {
                channel: chan,
                name: "secret".into(),
                kind: ChannelKind::Text,
                private: true,
                category: None,
            },
        )
        .unwrap();
        st.apply(&c).unwrap();
        assert_eq!(st.channel_members(&chan), vec!["owner#1".to_string()]);
        assert!(st.is_channel_member(&chan, "owner#1"));
        assert!(!st.is_channel_member(&chan, "member#3"));

        // Add member#3 to it.
        let add = sign_op(
            &owner,
            "owner#1",
            &st,
            701,
            WorkspaceOp::AddChannelMember {
                channel: chan,
                member: "member#3".into(),
            },
        )
        .unwrap();
        st.apply(&add).unwrap();
        assert!(st.is_channel_member(&chan, "member#3"));

        // Removing member#3 from the WORKSPACE drops them from the private channel.
        let rm = sign_op(
            &owner,
            "owner#1",
            &st,
            702,
            WorkspaceOp::RemoveMember {
                member: "member#3".into(),
            },
        )
        .unwrap();
        st.apply(&rm).unwrap();
        assert!(!st.is_channel_member(&chan, "member#3"));

        // A public channel's members are the whole workspace, untracked here.
        let pub_ch = [5u8; 16];
        let pc = sign_op(
            &owner,
            "owner#1",
            &st,
            703,
            WorkspaceOp::CreateChannel {
                channel: pub_ch,
                name: "general".into(),
                kind: ChannelKind::Text,
                private: false,
                category: None,
            },
        )
        .unwrap();
        st.apply(&pc).unwrap();
        assert!(st.is_channel_member(&pub_ch, "admin#2"));
    }

    #[test]
    fn a_forged_or_reordered_entry_is_rejected() {
        let (st, _owner, _admin, member) = seed();

        // Forge: the member signs an AddMember but claims to be the owner. The
        // author_key is the member's, which is not the owner's key on record.
        let mut forged = sign_op(
            &member,
            "owner#1", // lying about who they are
            &st,
            400,
            WorkspaceOp::AddMember {
                member: "ghost#9".into(),
                member_key: vec![0u8; 32],
            },
        )
        .unwrap();
        // The signature is over the member's key, but author claims owner#1 whose
        // recorded key differs -> BadSignature.
        let mut s2 = st.clone();
        assert_eq!(s2.apply(&forged), Err(OpError::BadSignature));

        // Reorder: a valid op at the wrong seq.
        forged.seq = 99;
        assert_eq!(
            s2.apply(&forged),
            Err(OpError::BadSeq {
                expected: st.next_seq(),
                got: 99
            })
        );
    }

    #[test]
    fn a_tampered_op_body_breaks_the_signature() {
        let (mut st, owner, ..) = seed();
        let mut op = sign_op(
            &owner,
            "owner#1",
            &st,
            500,
            WorkspaceOp::RenameChannel {
                channel: [7u8; 16],
                name: "x".into(),
            },
        )
        .unwrap();
        // Tamper with the op after signing.
        op.op = WorkspaceOp::DeleteChannel { channel: [7u8; 16] };
        assert_eq!(st.apply(&op), Err(OpError::BadSignature));
    }
}
