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

    /// Register a new account: store its OPAQUE envelope and identity key. The
    /// envelope was produced without the server ever seeing the password.
    pub fn create_account(
        &mut self,
        username: &str,
        envelope: Vec<u8>,
        identity_pub: Vec<u8>,
    ) -> AuthOutcome {
        if username.trim().is_empty() {
            return AuthOutcome::InvalidUsername;
        }
        if self.accounts.contains_key(username) {
            return AuthOutcome::UsernameTaken;
        }
        self.accounts.insert(
            username.to_string(),
            Account {
                envelope,
                identity_pub,
            },
        );
        self.save();
        AuthOutcome::Created
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
    fn create_stores_envelope_and_identity() {
        let mut store = AccountStore::new();
        assert_eq!(
            store.create_account("alice", vec![1, 2, 3], vec![4, 5, 6]),
            AuthOutcome::Created
        );
        assert!(store.contains("alice"));
        assert_eq!(store.envelope("alice"), Some(&[1, 2, 3][..]));
        assert_eq!(store.identity_pub("alice"), Some(&[4, 5, 6][..]));
        assert!(!store.contains("nobody"));
        assert_eq!(store.envelope("nobody"), None);
    }

    #[test]
    fn rejects_duplicate_and_empty() {
        let mut store = AccountStore::new();
        assert_eq!(
            store.create_account("bob", vec![1], vec![]),
            AuthOutcome::Created
        );
        assert_eq!(
            store.create_account("bob", vec![2], vec![]),
            AuthOutcome::UsernameTaken
        );
        assert_eq!(
            store.create_account("  ", vec![3], vec![]),
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
                store.create_account("dave", vec![9, 9], vec![7]),
                AuthOutcome::Created
            );
        }
        // A fresh store loading the same file sees the account.
        let store = AccountStore::load(&path);
        assert!(store.contains("dave"));
        assert_eq!(store.envelope("dave"), Some(&[9, 9][..]));
        assert_eq!(store.identity_pub("dave"), Some(&[7][..]));

        let _ = std::fs::remove_file(&path);
    }
}
