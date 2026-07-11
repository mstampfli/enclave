//! Enclave wire protocol: the types that cross the network.
//!
//! # The load-bearing invariant
//!
//! The signaling/SFU server is *semi-trusted*: it routes and stays up, but it
//! must never be able to read call content. This crate encodes that invariant
//! in the type system -- every field the server inspects or forwards is either
//! routing metadata (ids, presence) or an opaque [`Sealed`] blob it cannot open.
//! There is deliberately no variant that hands the server plaintext media, text,
//! or key material. If a future change needs the server to read content, it has
//! to break this type on purpose, in review.
//!
//! Metadata (who is in a call, when, packet timing/sizes) IS visible to the
//! server. That is an accepted tradeoff of the self-hosted-SFU topology; see
//! THREAT_MODEL.md ("Information disclosure").

use serde::{Deserialize, Serialize};

/// Stable identity of a person. Bound to their long-term identity public key.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct UserId(pub String);

/// A single device/client belonging to a user. MLS membership is per-device.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct DeviceId(pub String);

/// Identifies one MLS group == one call or one DM thread.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

/// Opaque, end-to-end-encrypted bytes. The server can store and forward these
/// but cannot open them: it holds no key. Newtype (not a bare `Vec<u8>`) so the
/// "server never sees plaintext" boundary is visible at every call site.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Sealed(pub Vec<u8>);

/// Kind of real-time media a frame carries. Drives jitter-buffer/codec routing
/// only; the payload is always [`Sealed`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MediaKind {
    Audio,
    Video,
    Screen,
}

/// One end-to-end-encrypted media frame as it appears on the wire.
///
/// The header is plaintext (the SFU needs it to route + order); the `payload`
/// is SFrame-style AEAD ciphertext of an already-encoded Opus/video frame. The
/// `(sender, epoch, counter)` triple is the AEAD nonce source and must be unique
/// per media key -- see `enclave-crypto` for the enforced counter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MediaFrame {
    pub group: GroupId,
    pub sender: DeviceId,
    pub kind: MediaKind,
    /// MLS epoch the sending key was derived from; receivers reject stale epochs.
    pub epoch: u64,
    /// Per-sender, per-epoch monotonic counter. Never reused. Nonce input.
    pub counter: u64,
    pub payload: Sealed,
}

/// Client -> server messages over the (TLS) signaling channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientMsg {
    /// Announce this device's identity public key + signed MLS KeyPackage so
    /// others can add it to a group. `key_package` is verifiable by peers, not
    /// by the server.
    Register {
        user: UserId,
        device: DeviceId,
        identity_pub: Vec<u8>,
        key_package: Vec<u8>,
    },
    /// Ask for a peer's published KeyPackages in order to add them to a group.
    FetchKeyPackages { user: UserId },
    /// Announce that this device is now a routing member of `group` (sent after
    /// creating or joining it). Lets the server fan group traffic out to it.
    /// Membership is routing metadata, visible to the server by design.
    JoinGroup { group: GroupId },
    /// Deliver a Welcome directly to a new member's device. The server also
    /// records `to` as a routing member of `group`. The payload is opaque.
    Welcome {
        to: DeviceId,
        group: GroupId,
        message: Sealed,
    },
    /// An MLS handshake message (Proposal/Commit) the server blindly relays to
    /// group members. Opaque to the server.
    Mls { group: GroupId, message: Sealed },
    /// An end-to-end-encrypted application message (text DM). Opaque.
    Text { group: GroupId, message: Sealed },
    /// A real-time encrypted media frame destined for the SFU to fan out.
    Media(MediaFrame),
    /// Coarse presence the user chooses to expose. Metadata, visible to server.
    Presence { status: Presence },
}

/// Server -> client messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServerMsg {
    KeyPackages { user: UserId, packages: Vec<Vec<u8>> },
    Welcome {
        group: GroupId,
        from: DeviceId,
        message: Sealed,
    },
    Mls { group: GroupId, from: DeviceId, message: Sealed },
    Text { group: GroupId, from: DeviceId, message: Sealed },
    Media(MediaFrame),
    Presence { user: UserId, status: Presence },
    Error { detail: String },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Presence {
    Online,
    Away,
    Offline,
}

/// Protocol-level errors shared across crates.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("malformed frame: {0}")]
    MalformedFrame(&'static str),
    #[error("unknown group")]
    UnknownGroup,
    #[error("stale epoch: frame {frame} < current {current}")]
    StaleEpoch { frame: u64, current: u64 },
}
