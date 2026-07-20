//! The server-side friend graph: who is friends with whom, plus pending
//! requests in each direction. Friendships are social *metadata* -- visible to
//! the server by the accepted trust model (see THREAT_MODEL) -- never content.
//! Persisted to JSON so they survive a restart.
//!
//! All identifiers are full `name#1234` handles.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One handle's relationships.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Relationships {
    /// Accepted, mutual friends.
    friends: BTreeSet<String>,
    /// Requests this handle has received and not yet answered.
    incoming: BTreeSet<String>,
    /// Requests this handle has sent and that are not yet accepted.
    outgoing: BTreeSet<String>,
    /// When each friendship was formed (friend handle -> unix seconds). Both
    /// sides store the same value. Absent for friendships that predate tracking.
    #[serde(default)]
    friend_since: BTreeMap<String, u64>,
}

/// The result of sending a friend request.
#[derive(Debug, PartialEq, Eq)]
pub enum RequestOutcome {
    /// Recorded; the other side must accept.
    Sent,
    /// The other side had already requested us, so we are now friends.
    NowFriends,
    /// Already friends.
    AlreadyFriends,
    /// A request in this direction was already pending.
    AlreadyPending,
    /// You cannot friend yourself.
    Yourself,
}

/// A persistent friend graph.
#[derive(Default)]
pub struct FriendStore {
    graph: BTreeMap<String, Relationships>,
    path: Option<PathBuf>,
}

impl FriendStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file (empty if absent); persist future changes back.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let graph = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            graph,
            path: Some(path),
        }
    }

    /// Record a friend request `from` -> `to`. If `to` had already requested
    /// `from`, they become friends immediately (the Discord "both added" case).
    pub fn request(&mut self, from: &str, to: &str, now: u64) -> RequestOutcome {
        if from == to {
            return RequestOutcome::Yourself;
        }
        if self.are_friends(from, to) {
            return RequestOutcome::AlreadyFriends;
        }
        // `to` already requested `from` iff `from` has `to` in its incoming set.
        if self
            .graph
            .get(from)
            .is_some_and(|r| r.incoming.contains(to))
        {
            self.make_friends(from, to, now);
            self.save();
            return RequestOutcome::NowFriends;
        }
        if self
            .graph
            .get(from)
            .is_some_and(|r| r.outgoing.contains(to))
        {
            return RequestOutcome::AlreadyPending;
        }
        self.graph
            .entry(from.to_string())
            .or_default()
            .outgoing
            .insert(to.to_string());
        self.graph
            .entry(to.to_string())
            .or_default()
            .incoming
            .insert(from.to_string());
        self.save();
        RequestOutcome::Sent
    }

    /// `who` accepts a pending request from `from`. Returns true if a pending
    /// request existed and they are now friends.
    pub fn accept(&mut self, who: &str, from: &str, now: u64) -> bool {
        if !self
            .graph
            .get(who)
            .is_some_and(|r| r.incoming.contains(from))
        {
            return false;
        }
        self.make_friends(who, from, now);
        self.save();
        true
    }

    /// Remove any pending request between `who` and `other`, in either
    /// direction (decline an incoming, or cancel an outgoing).
    pub fn decline(&mut self, who: &str, other: &str) {
        if let Some(r) = self.graph.get_mut(who) {
            r.incoming.remove(other);
            r.outgoing.remove(other);
        }
        if let Some(r) = self.graph.get_mut(other) {
            r.incoming.remove(who);
            r.outgoing.remove(who);
        }
        self.save();
    }

    /// Remove a friendship (bidirectional).
    pub fn remove(&mut self, a: &str, b: &str) {
        if let Some(r) = self.graph.get_mut(a) {
            r.friends.remove(b);
            r.friend_since.remove(b);
        }
        if let Some(r) = self.graph.get_mut(b) {
            r.friends.remove(a);
            r.friend_since.remove(a);
        }
        self.save();
    }

    pub fn are_friends(&self, a: &str, b: &str) -> bool {
        self.graph.get(a).is_some_and(|r| r.friends.contains(b))
    }

    pub fn friends_of(&self, handle: &str) -> Vec<String> {
        self.graph
            .get(handle)
            .map(|r| r.friends.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn incoming(&self, handle: &str) -> Vec<String> {
        self.graph
            .get(handle)
            .map(|r| r.incoming.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn outgoing(&self, handle: &str) -> Vec<String> {
        self.graph
            .get(handle)
            .map(|r| r.outgoing.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn make_friends(&mut self, a: &str, b: &str, now: u64) {
        {
            let ra = self.graph.entry(a.to_string()).or_default();
            ra.friends.insert(b.to_string());
            ra.friend_since.insert(b.to_string(), now);
            ra.incoming.remove(b);
            ra.outgoing.remove(b);
        }
        let rb = self.graph.entry(b.to_string()).or_default();
        rb.friends.insert(a.to_string());
        rb.friend_since.insert(a.to_string(), now);
        rb.incoming.remove(a);
        rb.outgoing.remove(a);
    }

    /// When `a` and `b` became friends (unix seconds), if recorded.
    pub fn friends_since(&self, a: &str, b: &str) -> Option<u64> {
        self.graph
            .get(a)
            .and_then(|r| r.friend_since.get(b).copied())
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Ok(text) = serde_json::to_string_pretty(&self.graph) {
            let _ = std::fs::write(path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_then_accept_makes_mutual_friends() {
        let mut s = FriendStore::new();
        assert_eq!(s.request("a#0001", "b#0002", 1000), RequestOutcome::Sent);
        assert!(!s.are_friends("a#0001", "b#0002"));
        assert_eq!(s.incoming("b#0002"), vec!["a#0001"]);
        assert_eq!(s.outgoing("a#0001"), vec!["b#0002"]);

        assert!(s.accept("b#0002", "a#0001", 1000));
        assert!(s.are_friends("a#0001", "b#0002"));
        assert!(s.are_friends("b#0002", "a#0001"));
        // The pending sets are cleared once accepted.
        assert!(s.incoming("b#0002").is_empty());
        assert!(s.outgoing("a#0001").is_empty());
    }

    #[test]
    fn records_when_a_friendship_formed() {
        let mut s = FriendStore::new();
        assert_eq!(s.friends_since("a#0001", "b#0002"), None);
        s.request("a#0001", "b#0002", 1000);
        // Still only a pending request: no friendship date yet.
        assert_eq!(s.friends_since("a#0001", "b#0002"), None);
        s.accept("b#0002", "a#0001", 4242);
        // Recorded, and identical from both sides.
        assert_eq!(s.friends_since("a#0001", "b#0002"), Some(4242));
        assert_eq!(s.friends_since("b#0002", "a#0001"), Some(4242));
        // Removing the friendship clears it.
        s.remove("a#0001", "b#0002");
        assert_eq!(s.friends_since("a#0001", "b#0002"), None);
    }

    #[test]
    fn mutual_requests_auto_accept() {
        let mut s = FriendStore::new();
        assert_eq!(s.request("a#0001", "b#0002", 1000), RequestOutcome::Sent);
        // b requests a back -> immediately friends.
        assert_eq!(
            s.request("b#0002", "a#0001", 1000),
            RequestOutcome::NowFriends
        );
        assert!(s.are_friends("a#0001", "b#0002"));
    }

    #[test]
    fn duplicate_and_self_and_existing() {
        let mut s = FriendStore::new();
        assert_eq!(
            s.request("a#0001", "a#0001", 1000),
            RequestOutcome::Yourself
        );
        assert_eq!(s.request("a#0001", "b#0002", 1000), RequestOutcome::Sent);
        assert_eq!(
            s.request("a#0001", "b#0002", 1000),
            RequestOutcome::AlreadyPending
        );
        s.accept("b#0002", "a#0001", 1000);
        assert_eq!(
            s.request("a#0001", "b#0002", 1000),
            RequestOutcome::AlreadyFriends
        );
    }

    #[test]
    fn decline_and_remove() {
        let mut s = FriendStore::new();
        s.request("a#0001", "b#0002", 1000);
        s.decline("b#0002", "a#0001");
        assert!(s.incoming("b#0002").is_empty());
        assert!(s.outgoing("a#0001").is_empty());
        assert!(!s.accept("b#0002", "a#0001", 1000)); // nothing to accept now

        s.request("a#0001", "b#0002", 1000);
        s.accept("b#0002", "a#0001", 1000);
        s.remove("a#0001", "b#0002");
        assert!(!s.are_friends("a#0001", "b#0002"));
        assert!(!s.are_friends("b#0002", "a#0001"));
    }

    #[test]
    fn persists_across_reload() {
        let path =
            std::env::temp_dir().join(format!("enclave-friends-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut s = FriendStore::load(&path);
            s.request("a#0001", "b#0002", 1000);
            s.accept("b#0002", "a#0001", 1000);
        }
        let s = FriendStore::load(&path);
        assert!(s.are_friends("a#0001", "b#0002"));
        let _ = std::fs::remove_file(&path);
    }
}
