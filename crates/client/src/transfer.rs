//! Chunked transfers: how a message or a file too large for one sealed frame
//! crosses the wire and is put back together.
//!
//! The relay only ever forwards a sealed blob that fits in one WebSocket frame
//! (`SIGNALING_MSG_LIMIT`, 1 MiB). Anything larger -- a long message or any file
//! -- is split here into [`Part`]s. Each part is serialized, sealed with the
//! group's MLS key exactly like an ordinary text message, and sent on its own,
//! so the server sees only a stream of opaque blobs and needs no protocol
//! change. The receiver feeds every decrypted part to a [`Reassembler`], which
//! hands back the whole payload once the last piece arrives.
//!
//! A small text message is simply a one-part transfer, so there is a single
//! code path: every message is `1..=N` parts.
//!
//! Every part carries the transfer's metadata (id, total, kind), not just the
//! first, so reassembly is order-independent and needs no separate header
//! frame -- the few hundred bytes of overhead are nothing against a 512 KiB
//! chunk. The reassembler bounds both the size of one transfer and the number
//! in flight, so a hostile or buggy peer cannot exhaust memory.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Payload bytes per part. Sealing adds MLS framing + a 256-byte pad, so the
/// sealed part stays well under the 1 MiB WebSocket frame limit.
pub const CHUNK_BYTES: usize = 512 * 1024;

/// Largest transfer we will reassemble. A file bigger than this is refused
/// rather than buffered: it is unusual for a chat and an obvious memory-DoS
/// vector. Sending is not capped here (the sender streams from disk), only
/// what a peer can make us hold in RAM.
pub const MAX_TRANSFER_BYTES: usize = 256 * 1024 * 1024;

/// Most partially-received transfers we keep per conversation at once. Beyond
/// this the oldest incomplete one is dropped, so a peer cannot open unbounded
/// half-transfers to pin memory.
pub const MAX_INFLIGHT: usize = 16;

/// What a transfer carries. Present on every part so any part identifies the
/// whole transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferMeta {
    /// A UTF-8 text message.
    Text,
    /// A file with its original name and MIME type (best-effort).
    File { name: String, mime: String },
    /// An end-to-end profile update (display name, status, avatar reference,
    /// ...). The part's `data` is a bincode [`Profile`]. The subject is always
    /// the sealed message's *authenticated sender* -- never a field in the
    /// payload -- so a peer can only ever set its own profile.
    Profile,
    /// A "delete this message for everyone" control. The part's `data` is the
    /// 16-byte id of the message to tombstone. The receiver only honors it if the
    /// target message's author equals this sealed message's *authenticated
    /// sender*, so a member can never delete another member's message.
    Delete,
    /// A voice message. The part's `data` is a bincode [`VoiceClip`] (Opus
    /// packets + duration). Sent inline like text (small: a handful of sealed
    /// parts), NOT through the file/consent flow, so it plays with one click.
    Voice,
    /// A "disappearing messages" setting change for this conversation. The part's
    /// `data` is the duration in milliseconds as a `u32` LE (0 = off). Both peers
    /// then delete their own copies on a local timer; only this on/off+duration is
    /// ever exposed -- never per-message read state.
    Disappear,
    /// An emoji reaction toggle on a message. The part's `data` is a bincode
    /// [`ReactBody`] (target message id + emoji + add/remove). The reactor is the
    /// sealed message's *authenticated sender* -- never a payload field -- so a
    /// member can only ever add or remove its OWN reaction.
    React,
    /// An "edit this message" control. The part's `data` is a bincode [`EditBody`]
    /// (target message id + new text). Honored ONLY if the target message's author
    /// equals this sealed message's *authenticated sender*, so a member can never
    /// edit another member's message.
    Edit,
    /// A poll message. The part's `data` is a bincode [`PollBody`] (question +
    /// options + single/multi + reveal mode). Sent inline like text (small), so it
    /// becomes a message line the recipients can vote on.
    Poll,
    /// A vote on a poll. The part's `data` is a bincode [`VoteBody`] (the poll's
    /// message id + the chosen option indices; empty = vote retracted). The voter
    /// is the sealed message's *authenticated sender*, so a member can only ever
    /// set its OWN vote (one vote-set per member, last write wins).
    Vote,
    /// A "close this poll" control. The part's `data` is the 16-byte poll message
    /// id. Honored only if the poll's author equals the authenticated sender, so
    /// only the creator can close (and thus reveal) their poll.
    PollClose,
    /// A "pin/unpin this message" control. The part's `data` is a bincode
    /// [`PinBody`] (target message id + pinned flag). Pins are shared: any member
    /// may pin or unpin a message for the whole conversation.
    Pin,
}

/// The payload of a [`TransferMeta::Pin`] control: set message `target`'s pinned
/// state to `pinned`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinBody {
    pub target: [u8; 16],
    pub pinned: bool,
}

impl PinBody {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<PinBody> {
        bincode::deserialize(bytes).ok()
    }
}

/// The largest number of options a poll may carry, and the longest a question or
/// an option may be (chars). Enforced on send AND receive.
pub const MAX_POLL_OPTIONS: usize = 10;
pub const MAX_POLL_TEXT: usize = 200;

/// A poll's definition, sealed when the poll is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollBody {
    pub question: String,
    pub options: Vec<String>,
    /// Whether a voter may select more than one option.
    pub multi: bool,
    /// When tallies are shown: 0 = always, 1 = after you vote, 2 = after the
    /// creator closes the poll.
    pub reveal: u8,
    /// Absolute deadline (unix ms) after which the poll auto-closes, or `None` for
    /// no time limit. Every peer stores the same value, so all agree when it ends.
    pub closes_at: Option<u64>,
    /// For a server-buffered poll (reveal >= 2): the shared content key that seals
    /// every ballot (off the MLS ratchet, so the untrusted server can't read votes
    /// yet a buffered ballot still opens after an epoch change). `None` for the
    /// immediate reveal modes, which vote over normal MLS instead.
    #[serde(default)]
    pub ballot_key: Option<[u8; 32]>,
    /// An anonymous poll: ballots are ring-signed so no one can attribute a vote.
    #[serde(default)]
    pub anonymous: bool,
    /// The ring for an anonymous poll: every eligible voter's ring public key, in
    /// a fixed order all verifiers agree on (assembled by the creator from members'
    /// profile voting keys). Empty for a non-anonymous poll.
    #[serde(default)]
    pub ring: Vec<[u8; 32]>,
}

impl PollBody {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<PollBody> {
        bincode::deserialize(bytes).ok()
    }
    /// Whether this poll definition is well-formed (bounded question, 2..=MAX
    /// bounded options, valid reveal mode).
    pub fn valid(&self) -> bool {
        !self.question.trim().is_empty()
            && self.question.len() <= MAX_POLL_TEXT
            && (2..=MAX_POLL_OPTIONS).contains(&self.options.len())
            && self
                .options
                .iter()
                .all(|o| !o.trim().is_empty() && o.len() <= MAX_POLL_TEXT)
            && self.reveal <= 2
    }
}

/// A vote on the poll identified by `target`: the chosen option indices (empty
/// retracts the vote).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteBody {
    pub target: [u8; 16],
    pub options: Vec<u8>,
}

/// An anonymous poll ballot: the sealed choice plus a linkable ring signature
/// proving a ring member cast it, without revealing which. The signature's key
/// image is the ballot's pseudonymous voter id (a re-vote by the same member
/// reuses it, so it replaces rather than double-counts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonBallot {
    pub sealed_choice: Vec<u8>,
    pub sig: enclave_crypto::RingSig,
}

impl AnonBallot {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<AnonBallot> {
        bincode::deserialize(bytes).ok()
    }
}

impl VoteBody {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<VoteBody> {
        bincode::deserialize(bytes).ok()
    }
}

/// The payload of a [`TransferMeta::Edit`] control: replace message `target`'s
/// text with `text`. The editor is the sealed message's authenticated sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditBody {
    pub target: [u8; 16],
    pub text: String,
}

impl EditBody {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<EditBody> {
        bincode::deserialize(bytes).ok()
    }
}

/// Emoji reactions on a single message: for each emoji, the usernames who
/// reacted with it. Kept as an annotation keyed by message id, not part of the
/// message content, so it can be updated after the fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Reaction {
    /// The emoji (a short grapheme sequence, e.g. "👍" or "🎉").
    pub emoji: String,
    /// Usernames (stable identity) that have reacted with this emoji.
    pub users: Vec<String>,
}

/// Largest reaction emoji we will accept, in bytes -- room for a couple of
/// graphemes with skin-tone/ZWJ modifiers, but not an arbitrary string. Enforced
/// on send AND receive so a hostile peer cannot smuggle a large payload as an
/// "emoji".
pub const MAX_REACTION_BYTES: usize = 32;

/// The payload of a [`TransferMeta::React`] control: toggle `emoji` on the
/// message `target` for the sealed message's authenticated sender. `add` = react,
/// `!add` = remove the reaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactBody {
    pub target: [u8; 16],
    pub emoji: String,
    pub add: bool,
}

impl ReactBody {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<ReactBody> {
        bincode::deserialize(bytes).ok()
    }
}

/// Largest avatar blob (encrypted bytes) we will upload or fetch. Enforced on
/// send (the image is downscaled + re-encoded first) and on receive (a peer's
/// oversized `AvatarRef` is ignored and its blob never fetched), so a hostile
/// peer cannot make us store or download a huge image.
pub const MAX_AVATAR_BYTES: usize = 512 * 1024;

/// A user's end-to-end profile: cosmetic identity data sealed and sent through
/// the groups they share, so the server never sees it. Distinct from the
/// server-visible username/presence; this is the private, self-set layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Profile {
    /// Chosen display name (empty falls back to the username).
    pub display_name: String,
    /// Status emoji (a single grapheme, e.g. "🎮"), or empty for none.
    pub status_emoji: String,
    /// Free-text status ("Working late"), or empty for none.
    pub status_text: String,
    /// Personal accent as "#rrggbb", or empty for the app default.
    pub accent: String,
    /// Short bio / about line, or empty.
    pub bio: String,
    /// Where the avatar image lives, or `None` for the initials fallback.
    pub avatar: Option<AvatarRef>,
    /// Monotonic per-user version. A receiver keeps only the highest it has seen
    /// (last-writer-wins), so a reordered or duplicated update never regresses a
    /// profile to an older state.
    pub version: u64,
    /// The user's ring-signature voting public key (Ristretto point, 32 bytes),
    /// broadcast so peers can build the ring for anonymous polls. `None` for a
    /// client that predates anonymous polls. Deterministic per account (from a
    /// persisted seed), so it is stable across sessions.
    #[serde(default)]
    pub voting_key: Option<[u8; 32]>,
}

/// Where a profile's avatar image lives: an encrypted, content-addressed blob on
/// the server. `addr` fetches it; `key` decrypts it (see [`enclave_crypto::blob`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvatarRef {
    /// SHA-256 of the ciphertext -- the server storage address + integrity check.
    pub addr: [u8; 32],
    /// One-time AEAD key for the blob. Only travels inside this sealed profile.
    pub key: [u8; 32],
    /// Image MIME type ("image/jpeg" etc), a rendering hint.
    pub mime: String,
    /// Ciphertext size in bytes; must be `<= MAX_AVATAR_BYTES`.
    pub size: u32,
}

impl Profile {
    /// Serialize for sealing as a [`TransferMeta::Profile`] part's data.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Parse a decrypted profile. `None` if the bytes are not a valid profile.
    pub fn decode(bytes: &[u8]) -> Option<Profile> {
        bincode::deserialize(bytes).ok()
    }
}

/// The sealed description of an offered file, sent with the offer so a recipient
/// can decide (name, size) *without* downloading. Sealed like any message, so
/// the server sees only its ciphertext length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifest {
    pub name: String,
    pub mime: String,
    /// Plaintext file size in bytes.
    pub size: u64,
    /// Fresh random 256-bit key the sender seals every chunk of this file under
    /// (see `crypto::seal_chunk`). It travels only inside this sealed manifest,
    /// so only group members ever learn it and the server still sees only
    /// ciphertext -- yet the bulk bytes stay off the MLS ratchet.
    pub content_key: [u8; 32],
}

impl FileManifest {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Option<FileManifest> {
        bincode::deserialize(bytes).ok()
    }
}

/// The payload of a `TransferMeta::Text` message: the text plus an optional id of
/// the message it replies to. Encoded with bincode so a reply reference travels
/// and survives, while the receiver looks up the quoted preview from its own copy
/// of the parent (nothing quoted is re-sent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TextBody {
    pub text: String,
    pub reply_to: Option<[u8; 16]>,
}

impl TextBody {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<TextBody> {
        bincode::deserialize(bytes).ok()
    }
}

/// A recorded voice message: its Opus packets (one per 20 ms frame, 48 kHz mono)
/// and the total duration. The receiver decodes the packets back to PCM to play.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VoiceClip {
    pub duration_ms: u32,
    pub packets: Vec<Vec<u8>>,
    /// Amplitude envelope for the UI waveform: one byte per bar (0-255), scaled
    /// to the clip's own loudest part. Old clips without it default to empty.
    #[serde(default)]
    pub waveform: Vec<u8>,
}

impl VoiceClip {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<VoiceClip> {
        bincode::deserialize(bytes).ok()
    }
}

/// Build a compact amplitude envelope (one byte per bar, 0-255) from mono PCM,
/// for the UI waveform. ALWAYS returns exactly `bars` values (each maps to a
/// proportional slice of the clip, so a long clip is coarser but the bar count
/// and width stay identical), scaled so the loudest bar is full height.
pub fn waveform_bars(pcm: &[i16], bars: usize) -> Vec<u8> {
    if pcm.is_empty() || bars == 0 {
        return Vec::new();
    }
    let peaks: Vec<u32> = (0..bars)
        .map(|i| {
            let start = i * pcm.len() / bars;
            let end = (((i + 1) * pcm.len() / bars).max(start + 1)).min(pcm.len());
            pcm[start..end]
                .iter()
                .map(|s| (*s as i32).unsigned_abs())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let max = peaks.iter().copied().max().unwrap_or(1).max(1);
    peaks.iter().map(|&p| ((p * 255) / max) as u8).collect()
}

/// One piece of a transfer. Serialized with bincode, then MLS-sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Part {
    /// Random transfer id shared by every part of one message/file.
    pub id: [u8; 16],
    /// This part's position, `0..total`.
    pub index: u32,
    /// How many parts the transfer has. `1` for a message that fits in a frame.
    pub total: u32,
    /// The transfer's metadata (repeated on every part).
    pub meta: TransferMeta,
    /// This part's bytes.
    pub data: Vec<u8>,
}

impl Part {
    /// Serialize for sealing.
    pub fn encode(&self) -> Vec<u8> {
        // bincode of a bounded struct cannot fail in practice; fall back to an
        // empty vec, which the receiver rejects as a malformed part.
        bincode::serialize(self).unwrap_or_default()
    }

    /// Parse a decrypted part. `None` if the bytes are not a valid part.
    pub fn decode(bytes: &[u8]) -> Option<Part> {
        bincode::deserialize(bytes).ok()
    }
}

/// Split `data` into serialized [`Part`]s under one fresh transfer id. `id` is
/// supplied (not generated here) so the caller controls randomness and can echo
/// the same id in its own history. Always returns at least one part, even for
/// empty data, so an empty message still round-trips.
pub fn split(id: [u8; 16], meta: TransferMeta, data: &[u8]) -> Vec<Vec<u8>> {
    let total = data.len().div_ceil(CHUNK_BYTES).max(1) as u32;
    (0..total)
        .map(|index| {
            let start = index as usize * CHUNK_BYTES;
            let end = (start + CHUNK_BYTES).min(data.len());
            Part {
                id,
                index,
                total,
                meta: meta.clone(),
                data: data.get(start..end).unwrap_or(&[]).to_vec(),
            }
            .encode()
        })
        .collect()
}

/// A transfer being reassembled: its fixed metadata plus the parts seen so far.
struct Partial {
    meta: TransferMeta,
    total: u32,
    /// `parts[i]` is `Some` once part `i` has arrived. Sized to `total` up front.
    parts: Vec<Option<Vec<u8>>>,
    /// Bytes buffered so far, for the running size bound.
    have_bytes: usize,
    /// How many distinct parts have arrived (to detect completion in O(1)).
    have_count: u32,
    /// Monotonic arrival order, so the oldest incomplete transfer is evictable.
    seq: u64,
}

/// A finished transfer handed back by the reassembler.
pub struct Complete {
    /// The transfer id, so a caller can dedup a message that was fully resent
    /// (e.g. after a retransmit whose earlier delivery's ack was lost).
    pub id: [u8; 16],
    pub meta: TransferMeta,
    pub data: Vec<u8>,
}

/// Reassembles parts into whole transfers, keyed by transfer id. Bounds memory
/// by capping both one transfer's size and the number in flight.
///
/// PRIMITIVE: bounded chunk reassembly (size/in-flight/index/duplicate all
/// capped by construction).
#[derive(Default)]
pub struct Reassembler {
    inflight: HashMap<[u8; 16], Partial>,
    next_seq: u64,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one decoded part. Returns the whole transfer once its last part has
    /// arrived, `None` while it is still incomplete, and drops (returns `None`
    /// on) a part that is malformed, inconsistent, or over a bound. Reordering
    /// and duplicates are tolerated.
    pub fn accept(&mut self, part: Part) -> Option<Complete> {
        // Reject structurally impossible parts outright.
        if part.total == 0 || part.index >= part.total || part.data.len() > CHUNK_BYTES {
            return None;
        }
        // A transfer whose declared size (total * chunk) exceeds the cap is
        // refused before we allocate anything for it.
        let declared = part.total as usize * CHUNK_BYTES;
        if declared > MAX_TRANSFER_BYTES {
            return None;
        }

        let seq = self.next_seq;
        let entry = self.inflight.entry(part.id);
        let existing = matches!(entry, std::collections::hash_map::Entry::Occupied(_));
        let partial = entry.or_insert_with(|| Partial {
            meta: part.meta.clone(),
            total: part.total,
            parts: vec![None; part.total as usize],
            have_bytes: 0,
            have_count: 0,
            seq,
        });
        if !existing {
            self.next_seq += 1;
        }

        // Every part of a transfer must agree on its shape; a peer that changes
        // total or meta mid-transfer is dropped, not trusted.
        if partial.total != part.total || partial.meta != part.meta {
            self.inflight.remove(&part.id);
            return None;
        }

        let slot = &mut partial.parts[part.index as usize];
        if slot.is_none() {
            partial.have_bytes += part.data.len();
            partial.have_count += 1;
            *slot = Some(part.data);
        } // a duplicate index is ignored, not re-counted

        // The running total (real bytes, not the declared upper bound) must also
        // stay under the cap.
        if partial.have_bytes > MAX_TRANSFER_BYTES {
            self.inflight.remove(&part.id);
            return None;
        }

        let done = partial.have_count == partial.total;
        if done {
            let partial = self.inflight.remove(&part.id).expect("just inserted");
            let mut data = Vec::with_capacity(partial.have_bytes);
            for piece in partial.parts {
                data.extend_from_slice(&piece.expect("all parts present when complete"));
            }
            return Some(Complete {
                id: part.id,
                meta: partial.meta,
                data,
            });
        }

        // Not done: enforce the in-flight cap by evicting the oldest partial.
        self.evict_over_cap();
        None
    }

    fn evict_over_cap(&mut self) {
        while self.inflight.len() > MAX_INFLIGHT {
            if let Some(oldest) = self
                .inflight
                .iter()
                .min_by_key(|(_, p)| p.seq)
                .map(|(id, _)| *id)
            {
                self.inflight.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

/// PRIMITIVE: a bounded set of recently-seen ids, for deduping a message that
/// was fully resent (e.g. a retransmit whose earlier delivery's ack was lost).
/// `insert` returns `true` the first time an id is seen and `false` on a
/// duplicate; past `cap` the oldest id is evicted (a recent window, not a
/// forever-growing set -- retransmits happen within seconds). FOR at-least-once
/// receive-side dedup; NOT a durable, complete history of every message.
pub struct SeenSet {
    seen: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
    cap: usize,
}

impl SeenSet {
    pub fn new(cap: usize) -> SeenSet {
        SeenSet {
            seen: HashSet::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    /// Record `id`. Returns `false` if it was already present (a duplicate to be
    /// ignored), `true` the first time (recorded, evicting the oldest past `cap`).
    pub fn insert(&mut self, id: [u8; 16]) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    pub fn clear(&mut self) {
        self.seen.clear();
        self.order.clear();
    }

    /// The remembered ids in insertion order, for persistence.
    pub fn snapshot(&self) -> Vec<[u8; 16]> {
        self.order.iter().copied().collect()
    }

    /// Re-seed from a persisted snapshot (in order), so dedup survives a restart
    /// and a message resent after both peers restarted is still shown once.
    pub fn restore(&mut self, ids: Vec<[u8; 16]>) {
        for id in ids {
            self.insert(id);
        }
    }
}

/// Largest file we will accept and stream to disk. Received files (unlike sent
/// ones) are written to the user's disk, so this bounds the disk a single
/// accepted transfer can consume. Generous: it covers any stored file (<=250MB)
/// and a large live one.
pub const MAX_RECEIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Streams an accepted file straight to disk, one decrypted [`Part`] at a time,
/// so a large (or live, arbitrary-size) transfer never buffers the whole file
/// in memory. Both the stored and live delivery paths hand the receiver chunks
/// in upload order over a reliable channel, so parts are written sequentially;
/// a part that arrives out of order (index != the next expected) fails the
/// transfer rather than silently corrupting the file.
///
/// The sink is constructed over a file the caller has already reserved under a
/// safe, unique, contained name (see the client's `reserve_download`), so this
/// module holds none of the path-safety logic -- it only writes bytes.
/// PRIMITIVE: streams a received file to disk with a hard size cap; never
/// buffers the whole file in memory.
pub struct FileSink {
    file: std::fs::File,
    path: PathBuf,
    name: String,
    /// Total parts expected (from the manifest size).
    total: u32,
    /// Next part index expected (parts arrive in order).
    next: u32,
    /// Bytes written so far.
    bytes: u64,
    /// Hard ceiling on bytes: the manifest size the recipient consented to when
    /// accepting the offer. The sink refuses anything beyond it, so a sender can
    /// never stream more than was declared and agreed to -- that consent is the
    /// gate, so there is no separate arbitrary byte limit (a live share can be
    /// any size the recipient accepts, streamed straight to disk).
    cap: u64,
}

impl FileSink {
    /// Build a sink over an already-reserved, opened file. `total` comes from
    /// the manifest size; `cap` bounds how many bytes will be written (the
    /// declared, consented size).
    pub fn new(file: std::fs::File, path: PathBuf, name: String, total: u32, cap: u64) -> FileSink {
        FileSink {
            file,
            path,
            name,
            total,
            next: 0,
            bytes: 0,
            cap,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Write one decrypted chunk in sequence by its 0-based `index`. Returns
    /// `Ok(true)` when the last chunk has been written (the file is complete),
    /// `Ok(false)` while more are expected, and `Err` if the chunk is out of
    /// order, oversized, or would exceed the size bound -- in which case the
    /// caller aborts the transfer. The chunk is already authenticated (its index
    /// is bound by the AEAD), so an out-of-order index here means a broken stream,
    /// not a spoof.
    pub fn write_chunk(&mut self, index: u32, data: &[u8]) -> std::io::Result<bool> {
        if index != self.next {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file chunk arrived out of order",
            ));
        }
        if data.len() > CHUNK_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file chunk is larger than one chunk",
            ));
        }
        let new_bytes = self.bytes.saturating_add(data.len() as u64);
        if new_bytes > self.cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file exceeds the maximum receive size",
            ));
        }
        // Seek to this chunk's offset (defensive: sequential writes already land
        // here) and write it.
        self.file
            .seek(SeekFrom::Start(self.next as u64 * CHUNK_BYTES as u64))?;
        self.file.write_all(data)?;
        self.next += 1;
        self.bytes = new_bytes;
        Ok(self.next == self.total)
    }

    /// Write one decrypted [`Part`] (used by tests and the reassembly path):
    /// checks the part's declared `total` matches, then delegates to
    /// [`write_chunk`](Self::write_chunk).
    #[cfg(test)]
    pub fn write_part(&mut self, part: &Part) -> std::io::Result<bool> {
        if part.total != self.total {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file part has a changed shape",
            ));
        }
        self.write_chunk(part.index, &part.data)
    }

    /// Flush the file to disk. Call once the last part has been written.
    pub fn finish(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }

    /// Abandon a partial transfer: drop the handle and delete the partial file.
    pub fn abort(self) {
        drop(self.file);
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_clip_round_trips() {
        let clip = VoiceClip {
            duration_ms: 3200,
            packets: vec![vec![1, 2, 3], vec![], vec![9; 80]],
            waveform: vec![0, 128, 255, 64],
        };
        let bytes = clip.encode();
        let back = VoiceClip::decode(&bytes).expect("decode");
        assert_eq!(back, clip, "a voice clip survives encode/decode exactly");
        assert!(VoiceClip::decode(b"not a clip").is_none() || VoiceClip::decode(&[]).is_none());
    }

    #[test]
    fn waveform_bars_are_scaled_to_the_loudest_part() {
        // A ramp: the peak segment should hit 255, quieter ones proportionally less.
        let pcm: Vec<i16> = (0..800).map(|i| (i as i16) * 40).collect();
        let bars = waveform_bars(&pcm, 8);
        assert_eq!(bars.len(), 8);
        assert_eq!(*bars.last().unwrap(), 255, "the loudest bar is full height");
        assert!(bars[0] < bars[7], "quieter segments are shorter");
        assert!(waveform_bars(&[], 8).is_empty(), "no PCM, no bars");
        // ALWAYS exactly `bars` values, even for a clip shorter than the bar count,
        // so every waveform is the same width with the same number of bars.
        assert_eq!(waveform_bars(&[100, 200], 40).len(), 40);
        assert_eq!(waveform_bars(&pcm, 40).len(), 40);
    }

    #[test]
    fn text_body_carries_a_reply_reference() {
        let b = TextBody {
            text: "hi".into(),
            reply_to: Some([7u8; 16]),
        };
        let back = TextBody::decode(&b.encode()).expect("decode");
        assert_eq!(back.text, "hi");
        assert_eq!(back.reply_to, Some([7u8; 16]));
        let plain = TextBody {
            text: "no reply".into(),
            reply_to: None,
        };
        assert_eq!(TextBody::decode(&plain.encode()).unwrap().reply_to, None);
    }

    fn reassemble(parts: Vec<Vec<u8>>) -> Option<Complete> {
        let mut r = Reassembler::new();
        let mut last = None;
        for bytes in parts {
            last = r.accept(Part::decode(&bytes).expect("decode"));
        }
        last
    }

    #[test]
    fn single_part_round_trips() {
        let parts = split([1u8; 16], TransferMeta::Text, b"hello");
        assert_eq!(parts.len(), 1);
        let c = reassemble(parts).expect("complete");
        assert_eq!(c.data, b"hello");
        assert_eq!(c.meta, TransferMeta::Text);
    }

    #[test]
    fn empty_message_is_one_part() {
        let parts = split([2u8; 16], TransferMeta::Text, b"");
        assert_eq!(parts.len(), 1);
        assert_eq!(reassemble(parts).expect("complete").data, b"");
    }

    #[test]
    fn large_payload_splits_and_reassembles_exactly() {
        // 5 chunks + a tail.
        let data: Vec<u8> = (0..(CHUNK_BYTES * 5 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        let parts = split([3u8; 16], TransferMeta::Text, &data);
        assert_eq!(parts.len(), 6);
        let c = reassemble(parts).expect("complete");
        assert_eq!(c.data, data, "reassembled bytes must match exactly");
    }

    #[test]
    fn out_of_order_and_duplicates_are_tolerated() {
        let data: Vec<u8> = (0..(CHUNK_BYTES * 3)).map(|i| (i % 251) as u8).collect();
        let mut parts = split(
            [4u8; 16],
            TransferMeta::File {
                name: "a.bin".into(),
                mime: "application/octet-stream".into(),
            },
            &data,
        );
        parts.reverse();
        parts.insert(0, parts[1].clone()); // a duplicate
        let mut r = Reassembler::new();
        let mut done = None;
        for bytes in parts {
            done = r.accept(Part::decode(&bytes).unwrap()).or(done);
        }
        let c = done.expect("complete despite reorder + dup");
        assert_eq!(c.data, data);
        assert!(matches!(c.meta, TransferMeta::File { .. }));
    }

    #[test]
    fn a_part_claiming_too_many_chunks_is_refused() {
        let bad = Part {
            id: [5u8; 16],
            index: 0,
            total: (MAX_TRANSFER_BYTES / CHUNK_BYTES) as u32 + 2,
            meta: TransferMeta::Text,
            data: vec![0u8; 10],
        };
        assert!(Reassembler::new().accept(bad).is_none());
    }

    #[test]
    fn inconsistent_total_drops_the_transfer() {
        let id = [6u8; 16];
        let mut r = Reassembler::new();
        // First part says total 3.
        assert!(r
            .accept(Part {
                id,
                index: 0,
                total: 3,
                meta: TransferMeta::Text,
                data: vec![1]
            })
            .is_none());
        // A second part for the same id claims total 2: the transfer is dropped.
        assert!(r
            .accept(Part {
                id,
                index: 1,
                total: 2,
                meta: TransferMeta::Text,
                data: vec![2]
            })
            .is_none());
        // The original is gone, so re-sending its parts cannot complete the
        // bogus one; a fresh, consistent transfer still works.
        let ok = split([7u8; 16], TransferMeta::Text, b"fresh");
        assert!(reassemble(ok).is_some());
    }

    #[test]
    fn out_of_range_index_is_refused() {
        let bad = Part {
            id: [8u8; 16],
            index: 5,
            total: 3,
            meta: TransferMeta::Text,
            data: vec![0],
        };
        assert!(Reassembler::new().accept(bad).is_none());
    }

    #[test]
    fn too_many_inflight_transfers_evicts_the_oldest() {
        let mut r = Reassembler::new();
        // Open MAX_INFLIGHT + 4 distinct incomplete transfers (each 2 parts,
        // send only part 0). The map never exceeds the cap.
        for n in 0..(MAX_INFLIGHT as u32 + 4) {
            let mut id = [0u8; 16];
            id[0..4].copy_from_slice(&n.to_le_bytes());
            r.accept(Part {
                id,
                index: 0,
                total: 2,
                meta: TransferMeta::Text,
                data: vec![0],
            });
            assert!(r.inflight.len() <= MAX_INFLIGHT);
        }
    }

    #[test]
    fn oversized_real_bytes_are_refused_even_if_declared_small() {
        // A part that declares total=1 but carries more than one chunk of data
        // is rejected by the per-part data-length check.
        let bad = Part {
            id: [9u8; 16],
            index: 0,
            total: 1,
            meta: TransferMeta::Text,
            data: vec![0u8; CHUNK_BYTES + 1],
        };
        assert!(Reassembler::new().accept(bad).is_none());
    }

    fn sink_at(tag: &str, total: u32, cap: u64) -> (FileSink, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("enclave-sink-{}-{}.bin", std::process::id(), tag));
        let _ = std::fs::remove_file(&path);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("reserve");
        (
            FileSink::new(file, path.clone(), "f.bin".into(), total, cap),
            path,
        )
    }

    fn file_part(id: u8, index: u32, total: u32, data: Vec<u8>) -> Part {
        Part {
            id: [id; 16],
            index,
            total,
            meta: TransferMeta::File {
                name: "f.bin".into(),
                mime: "application/octet-stream".into(),
            },
            data,
        }
    }

    #[test]
    fn a_streamed_file_is_written_to_disk_exactly() {
        let (mut sink, path) = sink_at("ok", 3, MAX_RECEIVE_BYTES);
        let a = vec![1u8; CHUNK_BYTES];
        let b = vec![2u8; CHUNK_BYTES];
        let c = vec![3u8; 100];
        assert!(
            !sink.write_part(&file_part(1, 0, 3, a.clone())).unwrap(),
            "not done"
        );
        assert!(
            !sink.write_part(&file_part(1, 1, 3, b.clone())).unwrap(),
            "not done"
        );
        assert!(
            sink.write_part(&file_part(1, 2, 3, c.clone())).unwrap(),
            "last part completes"
        );
        sink.finish().unwrap();
        let got = std::fs::read(&path).unwrap();
        let mut want = a;
        want.extend_from_slice(&b);
        want.extend_from_slice(&c);
        assert_eq!(got, want, "bytes on disk match the stream exactly");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_out_of_order_part_fails_the_transfer() {
        let (mut sink, path) = sink_at("ooo", 3, MAX_RECEIVE_BYTES);
        sink.write_part(&file_part(1, 0, 3, vec![0u8; 10])).unwrap();
        // Skipping index 1 (sending 2) is rejected, not silently accepted.
        assert!(sink.write_part(&file_part(1, 2, 3, vec![0u8; 10])).is_err());
        sink.abort();
        assert!(!path.exists(), "aborted partial is deleted");
    }

    #[test]
    fn a_file_over_the_receive_cap_is_refused() {
        // cap of 5 bytes; a 10-byte part cannot be written.
        let (mut sink, path) = sink_at("cap", 1, 5);
        assert!(sink.write_part(&file_part(1, 0, 1, vec![0u8; 10])).is_err());
        sink.abort();
        let _ = std::fs::remove_file(path);
    }

    fn seen_id(n: u8) -> [u8; 16] {
        let mut i = [0u8; 16];
        i[0] = n;
        i
    }

    #[test]
    fn seen_set_reports_duplicates_and_admits_new_ids() {
        let mut s = SeenSet::new(8);
        assert!(s.insert(seen_id(1)), "first sighting is new");
        assert!(!s.insert(seen_id(1)), "a repeat is a duplicate");
        assert!(s.insert(seen_id(2)), "a different id is new");
        assert!(!s.insert(seen_id(2)));
    }

    #[test]
    fn seen_set_evicts_the_oldest_past_its_cap() {
        let mut s = SeenSet::new(3);
        for n in 0..3 {
            assert!(s.insert(seen_id(n)));
        }
        // Inserting a 4th evicts id 0 (the oldest); id 0 then reads as "new".
        assert!(s.insert(seen_id(3)));
        assert!(s.insert(seen_id(0)), "evicted id is no longer remembered");
        // A still-remembered recent id is still a duplicate.
        assert!(!s.insert(seen_id(3)));
    }
}
