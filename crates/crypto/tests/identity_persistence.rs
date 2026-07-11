//! The identity key is encrypted at rest with a password-derived key: the same
//! identity is restored only with the correct password.

use enclave_crypto::Identity;

#[test]
fn identity_encrypts_at_rest_and_round_trips() {
    let path = std::env::temp_dir().join(format!("enclave-idtest-{}.id", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let id = Identity::generate("alice").unwrap();
    let pubkey = id.identity_key();
    id.save(&path, "a-correct-password").unwrap();

    // Correct password restores the exact same identity key.
    let loaded = Identity::load("alice", &path, "a-correct-password").unwrap();
    assert_eq!(loaded.identity_key(), pubkey);

    // A wrong password fails to decrypt -- it does NOT silently yield a different
    // identity, and the file is unusable without the password (i.e. encrypted).
    assert!(Identity::load("alice", &path, "wrong-password").is_err());

    let _ = std::fs::remove_file(&path);
}
