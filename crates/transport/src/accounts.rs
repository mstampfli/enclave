//! Server-side accounts: username + password (Argon2id, no email) plus the
//! user's public identity key. This is auth state the server legitimately holds
//! (password verifiers, not E2E keys); call content stays sealed and unreadable.
//!
//! ASVS V2: Argon2id with a per-password salt, a 12-char minimum, all characters
//! allowed, no composition rules, no forced rotation. Login rate limiting lives
//! at the connection layer.

use std::collections::HashMap;
use std::path::PathBuf;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

/// Minimum password length (ASVS V2).
pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Clone, Serialize, Deserialize)]
struct Account {
    password_hash: String,
    identity_pub: Vec<u8>,
}

/// The result of a create-account or login attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Account created and the caller is authenticated.
    Created,
    /// Password verified; the caller is authenticated.
    LoggedIn,
    /// The username is already registered.
    UsernameTaken,
    /// No such account.
    UnknownUser,
    /// The password did not match.
    WrongPassword,
    /// The password is shorter than [`MIN_PASSWORD_LEN`].
    PasswordTooShort,
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

    /// Create a new account and authenticate. The password is stored as an
    /// Argon2id verifier, never in the clear.
    pub fn create_account(
        &mut self,
        username: &str,
        password: &str,
        identity_pub: Vec<u8>,
    ) -> AuthOutcome {
        if username.trim().is_empty() {
            return AuthOutcome::InvalidUsername;
        }
        if password.len() < MIN_PASSWORD_LEN {
            return AuthOutcome::PasswordTooShort;
        }
        if self.accounts.contains_key(username) {
            return AuthOutcome::UsernameTaken;
        }
        let password_hash = hash_password(password);
        self.accounts.insert(
            username.to_string(),
            Account {
                password_hash,
                identity_pub,
            },
        );
        self.save();
        AuthOutcome::Created
    }

    /// Verify a login. Does not reveal whether the username exists to a timing
    /// observer beyond the coarse outcome enum.
    pub fn verify_login(&self, username: &str, password: &str) -> AuthOutcome {
        match self.accounts.get(username) {
            None => AuthOutcome::UnknownUser,
            Some(account) => {
                if verify_password(password, &account.password_hash) {
                    AuthOutcome::LoggedIn
                } else {
                    AuthOutcome::WrongPassword
                }
            }
        }
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

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_login() {
        let mut store = AccountStore::new();
        assert_eq!(
            store.create_account("alice", "correcthorsebattery", vec![1, 2, 3]),
            AuthOutcome::Created
        );
        assert_eq!(
            store.verify_login("alice", "correcthorsebattery"),
            AuthOutcome::LoggedIn
        );
        assert_eq!(
            store.verify_login("alice", "wrong-password"),
            AuthOutcome::WrongPassword
        );
        assert_eq!(
            store.verify_login("nobody", "whatever12345"),
            AuthOutcome::UnknownUser
        );
        assert_eq!(store.identity_pub("alice"), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn rejects_duplicate_and_short_and_empty() {
        let mut store = AccountStore::new();
        assert_eq!(
            store.create_account("bob", "longenoughpass", vec![]),
            AuthOutcome::Created
        );
        assert_eq!(
            store.create_account("bob", "anotherlongone", vec![]),
            AuthOutcome::UsernameTaken
        );
        assert_eq!(
            store.create_account("carol", "short", vec![]),
            AuthOutcome::PasswordTooShort
        );
        assert_eq!(
            store.create_account("  ", "longenoughpass", vec![]),
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
                store.create_account("dave", "longenoughpassword", vec![9]),
                AuthOutcome::Created
            );
        }
        // A fresh store loading the same file sees the account.
        let store = AccountStore::load(&path);
        assert_eq!(
            store.verify_login("dave", "longenoughpassword"),
            AuthOutcome::LoggedIn
        );
        assert_eq!(store.identity_pub("dave"), Some(&[9][..]));

        let _ = std::fs::remove_file(&path);
    }
}
