//! The workspace **op-log**: a verifiable, append-only, identity-signed record
//! of a workspace's structure and membership. Replaying it from the genesis op
//! yields the authoritative [`WorkspaceState`] (owner, roles, members and their
//! identity keys, categories, channels), with every entry checked three ways:
//!
//! - **chain** -- each entry's `prev_hash` must equal the SHA-256 of the previous
//!   entry's body, so a reordered, dropped, or forked log is detected;
//! - **signature** -- the entry is signed by `author`'s identity key (verified via
//!   [`crate::verify_op`]), so the relay cannot forge an entry;
//! - **authorization** -- the author must hold the *permission* the op requires
//!   *at that point in the log*, so a member cannot perform actions they lack.
//!   Permissions come only from assigned roles (deny by default, fail closed):
//!   the owner's authority is a protected built-in role, and no one may grant a
//!   permission they do not themselves hold.
//!
//! Because authorization is decided by replay, not asserted by the server, the
//! untrusted relay can store and route the log but never forge who is a member,
//! what roles they hold, or what those roles permit. This is the trust anchor for
//! the whole workspace feature.
//!
//! PRIMITIVE: the single source of truth for workspace membership and roles.
//! Both the client (authoritative) and the relay (ingress validation) replay
//! through here; never re-derive membership elsewhere.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use enclave_protocol::{
    CategoryId, ChannelId, ChannelKind, Permission, RoleId, SignedOp, WorkspaceOp, WS_OP_CONTEXT,
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

/// One category's structure: its name and (for nested categories) its parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryInfo {
    pub name: String,
    pub parent: Option<CategoryId>,
}

/// One role definition: a named bundle of permissions. Members are assigned roles;
/// their effective permissions are the union across their roles (the owner holds
/// all permissions implicitly, without a role).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDef {
    pub name: String,
    pub permissions: BTreeSet<Permission>,
}

/// How deep categories may nest (root is depth 0). Bounds the sidebar tree so a
/// pathological chain of parents cannot be built.
pub const MAX_CATEGORY_DEPTH: usize = 6;

/// The reserved id of the built-in **Owner** role (all permissions), created and
/// assigned to the owner at genesis. It is protected: it cannot be created again,
/// edited, deleted, or assigned/unassigned, and the owner cannot be a role target,
/// so the owner can never be stripped of authority and no one else can obtain it.
pub const OWNER_ROLE_ID: RoleId = [0u8; 16];

/// The state produced by replaying a workspace's op-log. Authoritative for who
/// is a member, their roles and identity keys, and the channel/category tree.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceState {
    pub name: String,
    pub owner: String,
    owner_key: Vec<u8>,
    /// Members -> their identity public key (what their future ops verify against).
    pub members: BTreeMap<String, Vec<u8>>,
    /// The workspace's role definitions (name + permission set), by id.
    pub roles: BTreeMap<RoleId, RoleDef>,
    /// Members -> the roles assigned to them. Absent/empty means no permissions
    /// (deny by default); the owner is never listed here (it holds all implicitly).
    pub member_roles: BTreeMap<String, BTreeSet<RoleId>>,
    pub categories: BTreeMap<CategoryId, CategoryInfo>,
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

    /// Whether `handle` is the workspace owner. Used for protection rules (the
    /// owner and their built-in role cannot be stripped) and for UI labelling --
    /// NOT for granting permissions, which flow only through role assignment.
    pub fn is_owner(&self, handle: &str) -> bool {
        handle == self.owner
    }

    /// A member's effective permissions: strictly the union of the permissions of
    /// the roles assigned to them. A member with no roles has none (deny by
    /// default -- fail closed). The owner's permissions come from the built-in
    /// Owner role assigned at genesis, not a special case here, so no code path
    /// grants a permission without an explicit, tamper-protected assignment.
    pub fn permissions_of(&self, handle: &str) -> BTreeSet<Permission> {
        let mut perms = BTreeSet::new();
        if !self.members.contains_key(handle) {
            return perms;
        }
        if let Some(role_ids) = self.member_roles.get(handle) {
            for rid in role_ids {
                if let Some(def) = self.roles.get(rid) {
                    perms.extend(def.permissions.iter().copied());
                }
            }
        }
        perms
    }

    /// Whether `handle` holds `perm` -- true only if some assigned role grants it.
    pub fn has_permission(&self, handle: &str, perm: Permission) -> bool {
        self.permissions_of(handle).contains(&perm)
    }

    /// No privilege escalation: `author` may only create/assign a role whose every
    /// permission they already hold. The owner passes automatically because their
    /// Owner role grants all -- there is no special case, just the subset check.
    fn require_grantable(&self, author: &str, perms: &BTreeSet<Permission>) -> Result<(), OpError> {
        let mine = self.permissions_of(author);
        if perms.iter().all(|p| mine.contains(p)) {
            Ok(())
        } else {
            Err(OpError::Unauthorized)
        }
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
        // The owner's authority is a real, protected role assignment (fail closed:
        // no assignment means no permissions, so a bypassed assignment grants
        // nothing rather than everything).
        self.roles.insert(
            OWNER_ROLE_ID,
            RoleDef {
                name: "Owner".into(),
                permissions: Permission::ALL.into_iter().collect(),
            },
        );
        self.member_roles
            .insert(owner.clone(), [OWNER_ROLE_ID].into_iter().collect());
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
        let author = entry.author.clone();

        match &entry.op {
            WorkspaceOp::Create { .. } => unreachable!("handled above"),

            WorkspaceOp::AddMember { member, member_key } => {
                require(self.has_permission(&author, Permission::ManageMembers))?;
                if self.members.contains_key(member) {
                    return Err(OpError::BadTarget);
                }
                self.members.insert(member.clone(), member_key.clone());
            }

            WorkspaceOp::RemoveMember { member } => {
                require(self.has_permission(&author, Permission::ManageMembers))?;
                // The owner is never removable; the target must be a member.
                if member == &self.owner || !self.members.contains_key(member) {
                    return Err(OpError::BadTarget);
                }
                self.members.remove(member);
                self.member_roles.remove(member);
                // Drop them from every private channel too.
                for set in self.private_members.values_mut() {
                    set.remove(member);
                }
            }

            WorkspaceOp::CreateRole {
                role,
                name,
                permissions,
            } => {
                require(self.has_permission(&author, Permission::ManageRoles))?;
                if self.roles.contains_key(role) {
                    return Err(OpError::BadTarget);
                }
                let perms: BTreeSet<Permission> = permissions.iter().copied().collect();
                self.require_grantable(&author, &perms)?;
                self.roles.insert(
                    *role,
                    RoleDef {
                        name: name.clone(),
                        permissions: perms,
                    },
                );
            }

            WorkspaceOp::EditRole {
                role,
                name,
                permissions,
            } => {
                require(self.has_permission(&author, Permission::ManageRoles))?;
                // The built-in Owner role is immutable.
                if *role == OWNER_ROLE_ID || !self.roles.contains_key(role) {
                    return Err(OpError::BadTarget);
                }
                let perms: BTreeSet<Permission> = permissions.iter().copied().collect();
                self.require_grantable(&author, &perms)?;
                let def = self.roles.get_mut(role).expect("role exists");
                def.name = name.clone();
                def.permissions = perms;
            }

            WorkspaceOp::DeleteRole { role } => {
                require(self.has_permission(&author, Permission::ManageRoles))?;
                // The built-in Owner role cannot be deleted.
                if *role == OWNER_ROLE_ID || self.roles.remove(role).is_none() {
                    return Err(OpError::BadTarget);
                }
                for set in self.member_roles.values_mut() {
                    set.remove(role);
                }
            }

            WorkspaceOp::AssignRole { member, role } => {
                require(self.has_permission(&author, Permission::ManageRoles))?;
                // The Owner role is the owner's alone; the owner is not a target.
                if *role == OWNER_ROLE_ID
                    || member == &self.owner
                    || !self.members.contains_key(member)
                {
                    return Err(OpError::BadTarget);
                }
                let perms = self
                    .roles
                    .get(role)
                    .ok_or(OpError::BadTarget)?
                    .permissions
                    .clone();
                // No escalation: a non-owner may only hand out a role whose every
                // permission they already hold.
                self.require_grantable(&author, &perms)?;
                self.member_roles
                    .entry(member.clone())
                    .or_default()
                    .insert(*role);
            }

            WorkspaceOp::UnassignRole { member, role } => {
                require(self.has_permission(&author, Permission::ManageRoles))?;
                // The Owner role cannot be unassigned (the owner stays all-powerful).
                if *role == OWNER_ROLE_ID {
                    return Err(OpError::BadTarget);
                }
                let removed = self
                    .member_roles
                    .get_mut(member)
                    .is_some_and(|s| s.remove(role));
                if !removed {
                    return Err(OpError::BadTarget);
                }
            }

            WorkspaceOp::CreateCategory { category, name } => {
                require(self.has_permission(&author, Permission::ManageChannels))?;
                if self.categories.contains_key(category) {
                    return Err(OpError::BadTarget);
                }
                self.categories.insert(
                    *category,
                    CategoryInfo {
                        name: name.clone(),
                        parent: None,
                    },
                );
            }

            WorkspaceOp::CreateChannel {
                channel,
                name,
                kind,
                private,
                category,
            } => {
                require(self.has_permission(&author, Permission::ManageChannels))?;
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
                require(self.has_permission(&author, Permission::ManageChannels))?;
                let ch = self.channels.get_mut(channel).ok_or(OpError::BadTarget)?;
                ch.name = name.clone();
            }

            WorkspaceOp::DeleteChannel { channel } => {
                require(self.has_permission(&author, Permission::ManageChannels))?;
                if self.channels.remove(channel).is_none() {
                    return Err(OpError::BadTarget);
                }
                self.private_members.remove(channel);
            }

            WorkspaceOp::AddChannelMember { channel, member } => {
                require(self.has_permission(&author, Permission::ManageChannelMembers))?;
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
                require(self.has_permission(&author, Permission::ManageChannelMembers))?;
                let removed = self
                    .private_members
                    .get_mut(channel)
                    .is_some_and(|set| set.remove(member));
                if !removed {
                    return Err(OpError::BadTarget);
                }
            }

            WorkspaceOp::SetChannelCategory { channel, category } => {
                require(self.has_permission(&author, Permission::ManageChannels))?;
                if let Some(cat) = category {
                    if !self.categories.contains_key(cat) {
                        return Err(OpError::BadTarget);
                    }
                }
                let ch = self.channels.get_mut(channel).ok_or(OpError::BadTarget)?;
                ch.category = *category;
            }

            WorkspaceOp::SetCategoryParent { category, parent } => {
                require(self.has_permission(&author, Permission::ManageChannels))?;
                if !self.categories.contains_key(category) {
                    return Err(OpError::BadTarget);
                }
                if let Some(p) = parent {
                    // Parent must exist, must not be the category itself or one of
                    // its descendants (a cycle), and the nesting must stay bounded.
                    if !self.categories.contains_key(p) {
                        return Err(OpError::BadTarget);
                    }
                    if self.category_reaches(p, category)
                        || self.category_depth(p) + 1 >= MAX_CATEGORY_DEPTH
                    {
                        return Err(OpError::BadTarget);
                    }
                }
                self.categories
                    .get_mut(category)
                    .ok_or(OpError::BadTarget)?
                    .parent = *parent;
            }
        }
        Ok(())
    }

    /// Whether `from` is `target` or has `target` among its ancestors (walking up
    /// the parent chain). Used to reject a category move that would form a cycle.
    fn category_reaches(&self, from: &CategoryId, target: &CategoryId) -> bool {
        let mut cur = Some(*from);
        // Bounded by the existing (acyclic) tree; the depth cap also stops here.
        for _ in 0..=MAX_CATEGORY_DEPTH {
            match cur {
                Some(c) if &c == target => return true,
                Some(c) => cur = self.categories.get(&c).and_then(|ci| ci.parent),
                None => return false,
            }
        }
        false
    }

    /// The depth of a category (root = 0), clamped so a corrupt chain terminates.
    fn category_depth(&self, cat: &CategoryId) -> usize {
        let mut depth = 0;
        let mut cur = self.categories.get(cat).and_then(|ci| ci.parent);
        while let Some(p) = cur {
            depth += 1;
            if depth > MAX_CATEGORY_DEPTH {
                break;
            }
            cur = self.categories.get(&p).and_then(|ci| ci.parent);
        }
        depth
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

        // A "Manager" role (everything except moving voice members) assigned to
        // admin#2 -- the RBAC stand-in for the old "admin".
        let mgr = [5u8; 16];
        let create = sign_op(
            &owner,
            "owner#1",
            &st,
            102,
            WorkspaceOp::CreateRole {
                role: mgr,
                name: "Manager".into(),
                permissions: vec![
                    Permission::ManageChannels,
                    Permission::ManageChannelMembers,
                    Permission::ManageMembers,
                    Permission::ManageRoles,
                ],
            },
        )
        .unwrap();
        st.apply(&create).unwrap();
        log.push(create);
        let assign = sign_op(
            &owner,
            "owner#1",
            &st,
            103,
            WorkspaceOp::AssignRole {
                member: "admin#2".into(),
                role: mgr,
            },
        )
        .unwrap();
        st.apply(&assign).unwrap();
        log.push(assign);

        // Full replay must match the incremental state.
        assert_eq!(replay(&log).unwrap().members.len(), st.members.len());
        (st, owner, admin, member)
    }

    #[test]
    fn genesis_establishes_owner_and_roles() {
        let (st, ..) = seed();
        assert_eq!(st.owner, "owner#1");
        assert!(st.is_owner("owner#1"));
        // The owner holds every permission -- via the built-in, protected Owner
        // role, not a special case.
        for p in Permission::ALL {
            assert!(st.has_permission("owner#1", p));
        }
        // The Manager role gives admin#2 most powers but not moving voice members.
        assert!(st.has_permission("admin#2", Permission::ManageChannels));
        assert!(st.has_permission("admin#2", Permission::ManageRoles));
        assert!(!st.has_permission("admin#2", Permission::MoveVoiceMembers));
        // A bare member (and a non-member) has nothing: deny by default.
        assert!(st.permissions_of("member#3").is_empty());
        assert!(st.permissions_of("nobody").is_empty());
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
    fn channels_and_categories_can_be_reparented() {
        let (mut st, owner, _admin, _member) = seed();
        let (a, b, chan) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let mk = |st: &WorkspaceState, op| sign_op(&owner, "owner#1", st, 200, op).unwrap();

        st.apply(&mk(
            &st,
            WorkspaceOp::CreateCategory {
                category: a,
                name: "A".into(),
            },
        ))
        .unwrap();
        st.apply(&mk(
            &st,
            WorkspaceOp::CreateCategory {
                category: b,
                name: "B".into(),
            },
        ))
        .unwrap();
        st.apply(&mk(
            &st,
            WorkspaceOp::CreateChannel {
                channel: chan,
                name: "general".into(),
                kind: ChannelKind::Text,
                private: false,
                category: None,
            },
        ))
        .unwrap();

        // Move the channel into A, then B, then back to the top level.
        st.apply(&mk(
            &st,
            WorkspaceOp::SetChannelCategory {
                channel: chan,
                category: Some(a),
            },
        ))
        .unwrap();
        assert_eq!(st.channels[&chan].category, Some(a));
        st.apply(&mk(
            &st,
            WorkspaceOp::SetChannelCategory {
                channel: chan,
                category: Some(b),
            },
        ))
        .unwrap();
        assert_eq!(st.channels[&chan].category, Some(b));
        st.apply(&mk(
            &st,
            WorkspaceOp::SetChannelCategory {
                channel: chan,
                category: None,
            },
        ))
        .unwrap();
        assert_eq!(st.channels[&chan].category, None);

        // Nest B under A.
        st.apply(&mk(
            &st,
            WorkspaceOp::SetCategoryParent {
                category: b,
                parent: Some(a),
            },
        ))
        .unwrap();
        assert_eq!(st.categories[&b].parent, Some(a));
        // Un-nest.
        st.apply(&mk(
            &st,
            WorkspaceOp::SetCategoryParent {
                category: b,
                parent: None,
            },
        ))
        .unwrap();
        assert_eq!(st.categories[&b].parent, None);
    }

    #[test]
    fn a_category_move_is_rejected_when_it_would_cycle_or_target_is_missing() {
        let (mut st, owner, _admin, _member) = seed();
        let (a, b) = ([1u8; 16], [2u8; 16]);
        let mk = |st: &WorkspaceState, op| sign_op(&owner, "owner#1", st, 200, op).unwrap();
        st.apply(&mk(
            &st,
            WorkspaceOp::CreateCategory {
                category: a,
                name: "A".into(),
            },
        ))
        .unwrap();
        st.apply(&mk(
            &st,
            WorkspaceOp::CreateCategory {
                category: b,
                name: "B".into(),
            },
        ))
        .unwrap();
        // B under A is fine.
        st.apply(&mk(
            &st,
            WorkspaceOp::SetCategoryParent {
                category: b,
                parent: Some(a),
            },
        ))
        .unwrap();
        // A under B would form a cycle: rejected, state unchanged.
        let bad = mk(
            &st,
            WorkspaceOp::SetCategoryParent {
                category: a,
                parent: Some(b),
            },
        );
        assert_eq!(st.apply(&bad), Err(OpError::BadTarget));
        assert_eq!(st.categories[&a].parent, None);
        // A category cannot be its own parent.
        let selfp = mk(
            &st,
            WorkspaceOp::SetCategoryParent {
                category: a,
                parent: Some(a),
            },
        );
        assert_eq!(st.apply(&selfp), Err(OpError::BadTarget));
        // A missing parent / a missing category / a missing channel are rejected.
        let missing_parent = mk(
            &st,
            WorkspaceOp::SetCategoryParent {
                category: a,
                parent: Some([9u8; 16]),
            },
        );
        assert_eq!(st.apply(&missing_parent), Err(OpError::BadTarget));
        let missing_cat = mk(
            &st,
            WorkspaceOp::SetCategoryParent {
                category: [8u8; 16],
                parent: None,
            },
        );
        assert_eq!(st.apply(&missing_cat), Err(OpError::BadTarget));
        let missing_chan = mk(
            &st,
            WorkspaceOp::SetChannelCategory {
                channel: [7u8; 16],
                category: Some(a),
            },
        );
        assert_eq!(st.apply(&missing_chan), Err(OpError::BadTarget));
    }

    #[test]
    fn category_nesting_is_depth_bounded() {
        let (mut st, owner, _admin, _member) = seed();
        let mk = |st: &WorkspaceState, op| sign_op(&owner, "owner#1", st, 200, op).unwrap();
        // Create a chain of categories and nest each under the previous, up to the
        // cap; the move that would exceed MAX_CATEGORY_DEPTH is rejected.
        let ids: Vec<[u8; 16]> = (0..(MAX_CATEGORY_DEPTH as u8 + 2))
            .map(|i| [i + 1; 16])
            .collect();
        for (i, id) in ids.iter().enumerate() {
            st.apply(&mk(
                &st,
                WorkspaceOp::CreateCategory {
                    category: *id,
                    name: format!("c{i}"),
                },
            ))
            .unwrap();
        }
        let mut last_ok = 0usize;
        for i in 1..ids.len() {
            let op = mk(
                &st,
                WorkspaceOp::SetCategoryParent {
                    category: ids[i],
                    parent: Some(ids[i - 1]),
                },
            );
            match st.apply(&op) {
                Ok(()) => last_ok = i,
                Err(OpError::BadTarget) => break,
                other => panic!("unexpected: {other:?}"),
            }
        }
        // The deepest child sits at depth MAX_CATEGORY_DEPTH - 1 (root is 0), so the
        // op that would push a child to MAX_CATEGORY_DEPTH is refused.
        assert!(
            last_ok >= 1 && last_ok < ids.len() - 1,
            "nesting stopped at the cap"
        );
    }

    #[test]
    fn a_bare_member_cannot_touch_roles_and_the_owner_is_unremovable() {
        let (mut st, _owner, admin, member) = seed();
        // member#3 holds no permissions: any role op is refused.
        let bad = sign_op(
            &member,
            "member#3",
            &st,
            300,
            WorkspaceOp::CreateRole {
                role: [6u8; 16],
                name: "x".into(),
                permissions: vec![Permission::ManageChannels],
            },
        )
        .unwrap();
        assert_eq!(st.apply(&bad), Err(OpError::Unauthorized));

        // Even admin#2 (holds ManageMembers) cannot remove the owner.
        let rm_owner = sign_op(
            &admin,
            "admin#2",
            &st,
            300,
            WorkspaceOp::RemoveMember {
                member: "owner#1".into(),
            },
        )
        .unwrap();
        assert_eq!(st.apply(&rm_owner), Err(OpError::BadTarget));
    }

    #[test]
    fn a_member_with_multiple_roles_gets_the_union_of_their_permissions() {
        let (mut st, owner, _admin, _member) = seed();
        let mk = |st: &WorkspaceState, op| sign_op(&owner, "owner#1", st, 400, op).unwrap();
        // Two disjoint single-permission roles.
        let a = [20u8; 16];
        let b = [21u8; 16];
        st.apply(&mk(
            &st,
            WorkspaceOp::CreateRole {
                role: a,
                name: "Channels".into(),
                permissions: vec![Permission::ManageChannels],
            },
        ))
        .unwrap();
        st.apply(&mk(
            &st,
            WorkspaceOp::CreateRole {
                role: b,
                name: "Voice".into(),
                permissions: vec![Permission::MoveVoiceMembers],
            },
        ))
        .unwrap();
        // member#3 holds neither yet.
        assert!(st.permissions_of("member#3").is_empty());
        // Assign both: effective permissions are the union.
        st.apply(&mk(
            &st,
            WorkspaceOp::AssignRole {
                member: "member#3".into(),
                role: a,
            },
        ))
        .unwrap();
        st.apply(&mk(
            &st,
            WorkspaceOp::AssignRole {
                member: "member#3".into(),
                role: b,
            },
        ))
        .unwrap();
        assert!(st.has_permission("member#3", Permission::ManageChannels));
        assert!(st.has_permission("member#3", Permission::MoveVoiceMembers));
        assert!(!st.has_permission("member#3", Permission::ManageRoles));
        // Removing one role drops only its permission; the other stays.
        st.apply(&mk(
            &st,
            WorkspaceOp::UnassignRole {
                member: "member#3".into(),
                role: a,
            },
        ))
        .unwrap();
        assert!(!st.has_permission("member#3", Permission::ManageChannels));
        assert!(st.has_permission("member#3", Permission::MoveVoiceMembers));
    }

    #[test]
    fn role_ops_prevent_privilege_escalation_and_protect_the_owner_role() {
        let (mut st, _owner, admin, _member) = seed();
        // admin#2 (Manager: everything except MoveVoiceMembers) has ManageRoles, so
        // it CAN create a role -- but only out of permissions it holds. A role that
        // includes MoveVoiceMembers (which admin#2 lacks) is refused.
        let escalate = sign_op(
            &admin,
            "admin#2",
            &st,
            300,
            WorkspaceOp::CreateRole {
                role: [10u8; 16],
                name: "Sneaky".into(),
                permissions: vec![Permission::MoveVoiceMembers],
            },
        )
        .unwrap();
        assert_eq!(st.apply(&escalate), Err(OpError::Unauthorized));

        // A role built from permissions admin#2 DOES hold is fine, and can be
        // assigned to the bare member.
        let ok = sign_op(
            &admin,
            "admin#2",
            &st,
            300,
            WorkspaceOp::CreateRole {
                role: [11u8; 16],
                name: "Helper".into(),
                permissions: vec![Permission::ManageChannels],
            },
        )
        .unwrap();
        st.apply(&ok).unwrap();
        let assign = sign_op(
            &admin,
            "admin#2",
            &st,
            301,
            WorkspaceOp::AssignRole {
                member: "member#3".into(),
                role: [11u8; 16],
            },
        )
        .unwrap();
        st.apply(&assign).unwrap();
        assert!(st.has_permission("member#3", Permission::ManageChannels));

        // The built-in Owner role cannot be deleted, edited, or assigned, and the
        // owner is never a role target.
        let del = sign_op(
            &admin,
            "admin#2",
            &st,
            302,
            WorkspaceOp::DeleteRole {
                role: OWNER_ROLE_ID,
            },
        )
        .unwrap();
        assert_eq!(st.apply(&del), Err(OpError::BadTarget));
        let grab = sign_op(
            &admin,
            "admin#2",
            &st,
            302,
            WorkspaceOp::AssignRole {
                member: "member#3".into(),
                role: OWNER_ROLE_ID,
            },
        )
        .unwrap();
        assert_eq!(st.apply(&grab), Err(OpError::BadTarget));
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
