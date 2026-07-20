//! Server-side accounts: the OPAQUE **envelope** (password file) plus the user's
//! public identity key. Zero-knowledge: the server never sees the password, only
//! an irreversible envelope produced by [`crate::opaque`]. Call content stays
//! sealed and unreadable regardless.
//!
//! The 12-char password minimum (ASVS V2) is enforced on the *client*: a
//! zero-knowledge server cannot measure a password it never receives. Login rate
//! limiting lives at the connection layer.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Minimum password length (ASVS V2). Enforced client-side (see module docs).
pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Clone, Serialize, Deserialize)]
struct Account {
    /// Serialized OPAQUE `ServerRegistration` -- opaque and irreversible; a leak
    /// forces a memory-hard (Argon2id) per-account offline attack, no more.
    envelope: Vec<u8>,
    identity_pub: Vec<u8>,
    /// Cosmetic display name; the username stays the unique login/add id.
    #[serde(default)]
    display: String,
    /// Account creation time (unix seconds). `0` for accounts registered before
    /// the server tracked it, which read back as "unknown".
    #[serde(default)]
    created: u64,
}

/// The result of a create-account attempt. Login is handled by the OPAQUE
/// handshake in the relay, not here, so there is no password-verify outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Account created and the caller is authenticated.
    Created,
    /// The username is already registered.
    UsernameTaken,
    /// The username was empty or otherwise invalid.
    InvalidUsername,
}

/// A persistent store of accounts.
#[derive(Default)]
pub struct AccountStore {
    accounts: HashMap<String, Account>,
    path: Option<PathBuf>,
}

impl AccountStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load accounts from a JSON file (empty store if it does not exist), and
    /// persist future changes back to it.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let accounts = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self {
            accounts,
            path: Some(path),
        }
    }

    /// Register a new account: store its OPAQUE envelope, identity key, and
    /// display name. The envelope was produced without the server ever seeing
    /// the password. An empty `display` defaults to the username.
    pub fn create_account(
        &mut self,
        username: &str,
        envelope: Vec<u8>,
        identity_pub: Vec<u8>,
        display: String,
        created: u64,
    ) -> AuthOutcome {
        if username.trim().is_empty() {
            return AuthOutcome::InvalidUsername;
        }
        if self.accounts.contains_key(username) {
            return AuthOutcome::UsernameTaken;
        }
        let display = if display.trim().is_empty() {
            username.to_string()
        } else {
            display
        };
        self.accounts.insert(
            username.to_string(),
            Account {
                envelope,
                identity_pub,
                display,
                created,
            },
        );
        self.save();
        AuthOutcome::Created
    }

    /// Account creation time (unix seconds), or `None` if it predates tracking.
    pub fn created_at(&self, username: &str) -> Option<u64> {
        self.accounts
            .get(username)
            .map(|a| a.created)
            .filter(|&c| c > 0)
    }

    /// The display name for `username` (falls back to the username itself).
    pub fn display(&self, username: &str) -> String {
        self.accounts
            .get(username)
            .map(|a| a.display.clone())
            .unwrap_or_else(|| username.to_string())
    }

    /// Change a user's display name. Returns false if there is no such account.
    pub fn set_display(&mut self, username: &str, display: &str) -> bool {
        let display = if display.trim().is_empty() {
            username.to_string()
        } else {
            display.to_string()
        };
        match self.accounts.get_mut(username) {
            Some(a) => {
                a.display = display;
                self.save();
                true
            }
            None => false,
        }
    }

    /// Whether a username is registered.
    pub fn contains(&self, username: &str) -> bool {
        self.accounts.contains_key(username)
    }

    /// The stored OPAQUE envelope for a user, if any. `None` drives OPAQUE dummy
    /// mode so a login attempt cannot reveal whether the username exists.
    pub fn envelope(&self, username: &str) -> Option<&[u8]> {
        self.accounts.get(username).map(|a| a.envelope.as_slice())
    }

    /// The stored public identity key for a user, if any.
    pub fn identity_pub(&self, username: &str) -> Option<&[u8]> {
        self.accounts
            .get(username)
            .map(|a| a.identity_pub.as_slice())
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Ok(text) = serde_json::to_string_pretty(&self.accounts) {
            let _ = std::fs::write(path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_stores_envelope_identity_and_display() {
        let mut store = AccountStore::new();
        assert_eq!(
            store.create_account(
                "alice",
                vec![1, 2, 3],
                vec![4, 5, 6],
                "Alice A".into(),
                1_700_000_000
            ),
            AuthOutcome::Created
        );
        assert!(store.contains("alice"));
        assert_eq!(store.envelope("alice"), Some(&[1, 2, 3][..]));
        assert_eq!(store.identity_pub("alice"), Some(&[4, 5, 6][..]));
        assert_eq!(store.display("alice"), "Alice A");
        // An empty display defaults to the username.
        store.create_account("bob", vec![], vec![], String::new(), 1_700_000_000);
        assert_eq!(store.display("bob"), "bob");
        // Changing it takes effect.
        assert!(store.set_display("bob", "Bobby"));
        assert_eq!(store.display("bob"), "Bobby");
        assert!(!store.set_display("nobody", "x"));
        // Unknown users fall back to their username.
        assert_eq!(store.display("nobody"), "nobody");
    }

    #[test]
    fn records_and_reports_account_creation_time() {
        let mut store = AccountStore::new();
        store.create_account("eve#0001", vec![1], vec![], String::new(), 1_700_000_000);
        assert_eq!(store.created_at("eve#0001"), Some(1_700_000_000));
        assert_eq!(store.created_at("nobody#0000"), None);
        // A legacy account (created == 0) reads back as unknown, not the epoch.
        store.create_account("old#0002", vec![], vec![], String::new(), 0);
        assert_eq!(store.created_at("old#0002"), None);
    }

    #[test]
    fn rejects_duplicate_and_empty() {
        let mut store = AccountStore::new();
        assert_eq!(
            store.create_account("bob", vec![1], vec![], String::new(), 1_700_000_000),
            AuthOutcome::Created
        );
        assert_eq!(
            store.create_account("bob", vec![2], vec![], String::new(), 1_700_000_000),
            AuthOutcome::UsernameTaken
        );
        assert_eq!(
            store.create_account("  ", vec![3], vec![], String::new(), 1_700_000_000),
            AuthOutcome::InvalidUsername
        );
    }

    #[test]
    fn persists_across_reload() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("enclave-accounts-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        {
            let mut store = AccountStore::load(&path);
            assert_eq!(
                store.create_account("dave", vec![9, 9], vec![7], "Dave".into(), 1_700_000_000),
                AuthOutcome::Created
            );
        }
        // A fresh store loading the same file sees the account.
        let store = AccountStore::load(&path);
        assert!(store.contains("dave"));
        assert_eq!(store.envelope("dave"), Some(&[9, 9][..]));
        assert_eq!(store.identity_pub("dave"), Some(&[7][..]));
        assert_eq!(store.display("dave"), "Dave");

        let _ = std::fs::remove_file(&path);
    }
}
