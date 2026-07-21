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
use enclave_protocol::ClientMsg;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::transfer::Profile;

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
    /// Disappearing-messages duration (ms) for this conversation, if on.
    #[serde(default)]
    pub disappearing_ms: Option<u32>,
    /// Lifecycle state: shown, archived (hidden from the list), or deleted
    /// (group left, history kept for a future reconnect). Old sessions without
    /// this field default to `Active`.
    #[serde(default)]
    pub visibility: crate::Visibility,
    /// The local-only "Notes to self" scratchpad: no MLS group, one member (us),
    /// nothing ever sent. Old sessions without this field default to `false`.
    #[serde(default)]
    pub local_only: bool,
    /// Emoji reactions on this conversation's messages, keyed by message id (as
    /// `(id, reactions)` pairs). Old sessions without this field default to empty.
    #[serde(default)]
    pub reactions: Vec<([u8; 16], Vec<crate::transfer::Reaction>)>,
    /// Ids of messages that were edited (for the "edited" marker). Old sessions
    /// without this field default to empty.
    #[serde(default)]
    pub edited: Vec<[u8; 16]>,
    /// Polls in this conversation, keyed by the poll's message id. Old sessions
    /// without this field default to empty.
    #[serde(default)]
    pub polls: Vec<([u8; 16], PersistPoll)>,
    /// Ids of pinned messages. Old sessions without this field default to empty.
    #[serde(default)]
    pub pinned: Vec<[u8; 16]>,
    /// Group history-sharing epoch (`Some` = on). Old sessions default to off.
    #[serde(default)]
    pub history_epoch: Option<u64>,
    /// The per-epoch history keys held for this group. Old sessions default empty.
    #[serde(default)]
    pub history_keys: Vec<(u64, [u8; 32])>,
}

/// A persisted poll: its definition, state, and per-member votes.
#[derive(Serialize, Deserialize, Clone)]
pub struct PersistPoll {
    pub question: String,
    pub options: Vec<String>,
    pub multi: bool,
    pub reveal: u8,
    #[serde(default)]
    pub closed: bool,
    /// Absolute deadline (unix ms), or None for no time limit.
    #[serde(default)]
    pub closes_at: Option<u64>,
    pub author: String,
    /// Each voter's username paired with its chosen option indices.
    pub votes: Vec<(String, Vec<u8>)>,
    /// Content key for server-buffered ballots (reveal >= 2), or None.
    #[serde(default)]
    pub ballot_key: Option<[u8; 32]>,
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default)]
    pub ring: Vec<[u8; 32]>,
    /// For an anonymous poll, the key-image pseudonym our own ballot is filed
    /// under, so a restart still shows us our own choice.
    #[serde(default)]
    pub my_tag: Option<String>,
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
    /// A persisted system notice ("X declined foo"). Old sessions without this
    /// field default to `false` (an ordinary message line).
    #[serde(default)]
    pub system: bool,
    /// Stable message id (transfer/offer id). Old sessions default to all-zero
    /// (a line that predates message ids: no reply/delete target).
    #[serde(default)]
    pub id: [u8; 16],
    /// Creation time, unix milliseconds. Old sessions default to 0 (unknown).
    #[serde(default)]
    pub ts: u64,
    /// Whether the message was deleted (shows a placeholder). Default false.
    #[serde(default)]
    pub deleted: bool,
    /// The id of the message this replies to, if any. Default none.
    #[serde(default)]
    pub reply_to: Option<[u8; 16]>,
    /// Duration in ms if this line is a voice message (its clip is the `file`).
    #[serde(default)]
    pub voice_ms: Option<u32>,
    /// Amplitude envelope for a voice message's waveform (empty otherwise).
    #[serde(default)]
    pub waveform: Vec<u8>,
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
    /// Next reliable-delivery sequence number, persisted so a restart does not
    /// reuse ids for still-unacked messages.
    #[serde(default)]
    pub next_seq: u64,
    /// Reliable messages the server had not yet acked at save time, so that a
    /// message sent moments before the app closed is retransmitted on next
    /// launch rather than lost. Each is an already-sealed `ClientMsg`; the
    /// receiver dedups any that actually got through. Old sessions default this
    /// to empty.
    #[serde(default)]
    pub unacked: Vec<(u64, ClientMsg)>,
    /// Recently-delivered transfer ids, so receive-side dedup survives a restart
    /// -- a message resent after both peers restarted is still shown once.
    #[serde(default)]
    pub seen_ids: Vec<[u8; 16]>,
    /// Our own end-to-end profile (display name, status, avatar reference, ...).
    /// Persisted so it is broadcast unchanged after a restart. Old sessions
    /// default to an empty profile.
    #[serde(default)]
    pub my_profile: Profile,
    /// Cached profiles of people we share a group with, keyed by username, so
    /// their names and avatars render immediately on restart without waiting for
    /// a fresh broadcast. Old sessions default to empty.
    #[serde(default)]
    pub peer_profiles: Vec<(String, Profile)>,
    /// Handles that removed us (they initiated the un-friend). Persisted so the
    /// removal direction, and thus auto-reconnect eligibility, survives a restart.
    #[serde(default)]
    pub removed_me: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_protocol::{GroupId, Sealed};

    #[test]
    fn unacked_and_dedup_state_survive_a_session_round_trip() {
        let path = std::env::temp_dir().join(format!("enclave-sess-{}.enc", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let key = b"an-export-key-for-the-session-test";

        let data = SessionData {
            mls: HashMap::new(),
            conversations: Vec::new(),
            next_seq: 42,
            unacked: vec![(
                7,
                ClientMsg::Text {
                    group: GroupId([3u8; 32]),
                    message: Sealed(vec![1, 2, 3]),
                },
            )],
            seen_ids: vec![[9u8; 16], [10u8; 16]],
            my_profile: Profile {
                display_name: "Me".into(),
                version: 3,
                ..Profile::default()
            },
            peer_profiles: vec![(
                "bob".into(),
                Profile {
                    display_name: "Bob".into(),
                    version: 1,
                    ..Profile::default()
                },
            )],
            removed_me: vec!["carol#0003".into()],
        };
        save(&path, key, &data);

        let loaded = load(&path, key);
        assert_eq!(loaded.next_seq, 42, "sequence counter persisted");
        assert_eq!(loaded.unacked.len(), 1, "un-acked message persisted");
        assert_eq!(loaded.unacked[0].0, 7);
        assert!(matches!(
            &loaded.unacked[0].1,
            ClientMsg::Text { message, .. } if message.0 == vec![1, 2, 3]
        ));
        assert_eq!(
            loaded.seen_ids,
            vec![[9u8; 16], [10u8; 16]],
            "dedup ids persisted"
        );
        assert_eq!(
            loaded.my_profile.display_name, "Me",
            "own profile persisted"
        );
        assert_eq!(loaded.my_profile.version, 3);
        assert_eq!(
            loaded.peer_profiles.len(),
            1,
            "peer profile cache persisted"
        );
        assert_eq!(loaded.peer_profiles[0].0, "bob");
        assert_eq!(loaded.peer_profiles[0].1.display_name, "Bob");
        assert_eq!(
            loaded.removed_me,
            vec!["carol#0003"],
            "removal direction persisted"
        );

        // A wrong key yields a default (no leakage), including empty reliability state.
        let wrong = load(&path, b"the-wrong-export-key-entirely-here");
        assert!(wrong.unacked.is_empty());
        assert_eq!(wrong.next_seq, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn local_only_notes_conversation_survives_a_round_trip() {
        let path = std::env::temp_dir().join(format!("enclave-notes-{}.enc", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let key = b"an-export-key-for-the-notes-test";

        // A "Notes to self" scratchpad: no MLS group, one member (us), local_only.
        let notes = PersistConv {
            routing_id: [7u8; 32],
            mls_group_id: Vec::new(),
            is_dm: true,
            title: "Notes to self".into(),
            members: vec!["me".into()],
            history: vec![PersistLine {
                from: "me".into(),
                text: "remember the milk".into(),
                mine: true,
                file: None,
                system: false,
                id: [0u8; 16],
                ts: 0,
                deleted: false,
                reply_to: None,
                voice_ms: None,
                waveform: Vec::new(),
            }],
            verified: None,
            disappearing_ms: None,
            visibility: crate::Visibility::Active,
            local_only: true,
            reactions: Vec::new(),
            edited: Vec::new(),
            polls: Vec::new(),
            pinned: Vec::new(),
        };
        let data = SessionData {
            conversations: vec![notes],
            ..Default::default()
        };
        save(&path, key, &data);

        let loaded = load(&path, key);
        assert_eq!(
            loaded.conversations.len(),
            1,
            "the notes conversation persisted"
        );
        let c = &loaded.conversations[0];
        assert!(c.local_only, "the local-only flag round-tripped");
        assert!(
            c.mls_group_id.is_empty(),
            "no MLS group is stored for notes"
        );
        assert_eq!(c.members, vec!["me".to_string()], "just us");
        assert_eq!(c.history.len(), 1, "the note text was kept");
        assert_eq!(c.history[0].text, "remember the milk");
        let _ = std::fs::remove_file(&path);
    }
}
