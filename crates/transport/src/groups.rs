//! Server-side group routing membership: which devices should receive each
//! group's fan-out. This is delivery *metadata* -- visible to the server by the
//! accepted trust model (like the friend graph), never message content or keys.
//!
//! Persisted to JSON so conversations survive a server restart. Without it a
//! restart empties every group, and the deny-by-default self-join rule cannot
//! rebuild a multi-member group from empty (only the first device back in would
//! be admitted; every other member would be rejected as a stranger), so every
//! existing DM and group would silently stop routing until re-created.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use enclave_protocol::{DeviceId, GroupId};

/// One group's persisted membership. A `Vec` of these is the on-disk form,
/// because a JSON object cannot be keyed by a binary [`GroupId`].
#[derive(Serialize, Deserialize)]
struct GroupMembers {
    group: GroupId,
    members: Vec<DeviceId>,
}

/// A persistent group -> devices routing map.
#[derive(Default)]
pub struct GroupStore {
    members: HashMap<GroupId, HashSet<DeviceId>>,
    path: Option<PathBuf>,
}

impl GroupStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file (empty if absent); persist future changes back.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let members = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<Vec<GroupMembers>>(&t).ok())
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|e| (e.group, e.members.into_iter().collect()))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            members,
            path: Some(path),
        }
    }

    /// A device self-joining a group. Deny-by-default (ASVS V4): allowed only to
    /// bootstrap a new (empty) group as its creator, or to re-affirm membership a
    /// device already holds. Joining someone else's existing group is done via a
    /// Welcome ([`add`](Self::add)). Returns whether the device is a member after.
    pub fn join(&mut self, group: GroupId, device: DeviceId) -> bool {
        let set = self.members.entry(group).or_default();
        if set.is_empty() || set.contains(&device) {
            set.insert(device);
            self.save();
            true
        } else {
            false
        }
    }

    /// Add a device that a current member invited via a Welcome. The caller must
    /// have already checked the inviter is a member (deny-by-default).
    pub fn add(&mut self, group: &GroupId, device: DeviceId) {
        self.members
            .entry(group.clone())
            .or_default()
            .insert(device);
        self.save();
    }

    /// Whether `device` is a routing member of `group`.
    pub fn is_member(&self, group: &GroupId, device: &DeviceId) -> bool {
        self.members.get(group).is_some_and(|m| m.contains(device))
    }

    /// The devices in `group`, if any are known.
    pub fn members(&self, group: &GroupId) -> Option<&HashSet<DeviceId>> {
        self.members.get(group)
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let entries: Vec<GroupMembers> = self
            .members
            .iter()
            .map(|(group, members)| GroupMembers {
                group: group.clone(),
                members: members.iter().cloned().collect(),
            })
            .collect();
        if let Ok(text) = serde_json::to_string_pretty(&entries) {
            let _ = std::fs::write(path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str) -> DeviceId {
        DeviceId(name.into())
    }
    const G: GroupId = GroupId([7u8; 32]);

    #[test]
    fn join_bootstraps_then_reaffirms_but_rejects_strangers() {
        let mut s = GroupStore::new();
        // First device bootstraps the empty group.
        assert!(s.join(G, dev("alice")));
        // Alice may re-affirm.
        assert!(s.join(G, dev("alice")));
        // A stranger cannot self-join a non-empty group.
        assert!(!s.join(G, dev("mallory")));
        assert!(s.is_member(&G, &dev("alice")));
        assert!(!s.is_member(&G, &dev("mallory")));
    }

    #[test]
    fn welcome_add_is_unconditional() {
        let mut s = GroupStore::new();
        s.join(G, dev("alice"));
        // Alice welcomes Bob: he is added even though he could not self-join.
        s.add(&G, dev("bob"));
        assert!(s.is_member(&G, &dev("bob")));
    }

    #[test]
    fn membership_survives_reload_so_multi_member_groups_re_form() {
        // The regression this whole module exists to fix: a group with two
        // members must still have both members after a restart, so re-affirm is
        // not even needed and neither member is locked out.
        let path =
            std::env::temp_dir().join(format!("enclave-groups-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut s = GroupStore::load(&path);
            s.join(G, dev("alice"));
            s.add(&G, dev("bob"));
        }
        let s = GroupStore::load(&path);
        assert!(s.is_member(&G, &dev("alice")), "alice restored");
        assert!(s.is_member(&G, &dev("bob")), "bob restored");
        let _ = std::fs::remove_file(&path);
    }
}
