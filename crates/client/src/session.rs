//! Local session persistence: the MLS group state, the conversation list, and
//! per-conversation message history, encrypted at rest with a key derived from
//! the OPAQUE **export key** -- a stable, password-derived secret the server
//! never sees. This is how conversations and their history survive a restart
//! while keeping the "server sees nothing" guarantee: everything on disk is
//! sealed, and only the right password reproduces the key that opens it.
//!
//! Export/import is just moving this sealed file between devices; the importing
//! device opens it only with the same password.

use std::collections::HashMap;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One persisted conversation: its routing id, MLS-internal id (to reload the
/// group), kind, title, members, and scoped history.
#[derive(Serialize, Deserialize, Clone)]
pub struct PersistConv {
    pub routing_id: [u8; 32],
    pub mls_group_id: Vec<u8>,
    pub is_dm: bool,
    pub title: String,
    pub members: Vec<String>,
    pub history: Vec<PersistLine>,
    /// The safety number the user confirmed out of band, if any. Stored as the
    /// number itself, not a flag: a rekey changes the number, which correctly
    /// drops the conversation back to unverified rather than carrying a stale
    /// "trusted" mark across a membership change.
    #[serde(default)]
    pub verified: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PersistLine {
    pub from: String,
    pub text: String,
    pub mine: bool,
    /// Present when the line is a file rather than plain text. Old sessions
    /// without this field default to `None` (a text line).
    #[serde(default)]
    pub file: Option<PersistFile>,
}

/// A file line, persisted so file history survives a restart. The bytes are
/// on disk at `path`; only the descriptor is stored.
#[derive(Serialize, Deserialize, Clone)]
pub struct PersistFile {
    pub name: String,
    pub size: u64,
    pub path: String,
}

/// The full persisted session for one account on this device.
#[derive(Serialize, Deserialize, Default)]
pub struct SessionData {
    /// MLS provider storage snapshot (group states + private keys).
    pub mls: HashMap<Vec<u8>, Vec<u8>>,
    pub conversations: Vec<PersistConv>,
}

/// Derive the 32-byte at-rest key from the OPAQUE export key (domain-separated).
fn derive_key(export_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"enclave-session-v1");
    h.update(export_key);
    h.finalize().into()
}

/// Encrypt and write the session to `path`. Layout: nonce(12) || ciphertext.
/// Serialized with bincode (the MLS snapshot is a byte-keyed map, which JSON
/// cannot represent).
pub fn save(path: &Path, export_key: &[u8], data: &SessionData) {
    let Ok(plaintext) = bincode::serialize(data) else {
        return;
    };
    let cipher = ChaCha20Poly1305::new(&Key::from(derive_key(export_key)));
    let mut nonce = [0u8; 12];
    if getrandom::getrandom(&mut nonce).is_err() {
        return;
    }
    let Ok(ciphertext) = cipher.encrypt(&Nonce::from(nonce), plaintext.as_slice()) else {
        return;
    };
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    let _ = std::fs::write(path, out);
}

/// Load and decrypt the session, or a default if absent or undecryptable (e.g.
/// a wrong password, whose export key will not open it).
pub fn load(path: &Path, export_key: &[u8]) -> SessionData {
    let Ok(bytes) = std::fs::read(path) else {
        return SessionData::default();
    };
    if bytes.len() < 12 {
        return SessionData::default();
    }
    let nonce: [u8; 12] = bytes[0..12].try_into().expect("12 bytes");
    let cipher = ChaCha20Poly1305::new(&Key::from(derive_key(export_key)));
    match cipher.decrypt(&Nonce::from(nonce), &bytes[12..]) {
        Ok(plaintext) => bincode::deserialize(&plaintext).unwrap_or_default(),
        Err(_) => SessionData::default(),
    }
}
