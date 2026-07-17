//! Content-addressed encrypted blobs -- the transport for profile avatars.
//!
//! An avatar image is encrypted once, under a **fresh random 256-bit key**, with
//! ChaCha20-Poly1305 and a fixed all-zero nonce. The fixed nonce is sound *only*
//! because the key is generated here, used for exactly one blob, and never
//! reused: one key seals one blob, so there is exactly one (key, nonce) pair and
//! nonce reuse is unrepresentable. The blob is addressed by the SHA-256 of its
//! **ciphertext**, which gives three properties at once:
//!
//! - the untrusted server stores the ciphertext under that address and can
//!   neither read it (it has no key) nor substitute it -- a recipient re-hashes
//!   the fetched bytes against the address it asked for and rejects a mismatch;
//! - identical images dedupe to one blob (content addressing);
//! - the 256-bit address doubles as a bearer capability: only a sealed profile
//!   carries `{addr, key}`, so only someone you shared a group with can fetch and
//!   decrypt it.
//!
//! NOT for: encrypting more than one payload under the same key (the zero nonce
//! would then repeat, breaking confidentiality). One [`SealedBlob`] == one fresh
//! key == one image; call [`seal_blob`] again for every new image.
//!
//! PRIMITIVE: the single source of truth for encrypting/addressing avatar blobs.
//! Never hand-roll an ad-hoc "encrypt an image and hash it" elsewhere; reuse this.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Digest, Sha256};

use crate::CryptoError;

/// Fixed nonce, sound because each key seals exactly one blob (see module docs).
const BLOB_NONCE: [u8; 12] = [0u8; 12];

/// Bytes the AEAD tag adds to each sealed chunk (Poly1305).
pub const CHUNK_OVERHEAD: usize = 16;

/// Per-chunk nonce: the chunk index in the low 4 bytes, the rest zero. Sound
/// because the content key is fresh per offer and each index appears once, so
/// every (key, nonce) pair is unique -- nonce reuse is unrepresentable.
fn chunk_nonce(index: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&index.to_le_bytes());
    n
}

/// Associated data binding a chunk to its exact place: `offer_id || index`. A
/// chunk sealed for one (offer, position) fails to open at any other, so a
/// server (or group peer) cannot reorder, duplicate across offers, or splice
/// chunks without the AEAD tag rejecting it.
fn chunk_aad(offer_id: &[u8; 16], index: u32) -> [u8; 20] {
    let mut aad = [0u8; 20];
    aad[0..16].copy_from_slice(offer_id);
    aad[16..20].copy_from_slice(&index.to_le_bytes());
    aad
}

/// Seal one file chunk under a per-offer content key. Bulk file data is sealed
/// this way -- NOT as MLS application messages -- so streaming (and dropping, on
/// a cancel) chunks never touches the group's message ratchet. The content key
/// is random per offer and travels only inside the offer's MLS-sealed manifest,
/// so the untrusted server still sees only ciphertext.
///
/// `index` is the chunk's 0-based position; `offer_id` scopes the key. Returns
/// ciphertext + tag (`plaintext.len() + CHUNK_OVERHEAD` bytes).
///
/// NOT for: sealing under a key reused across offers (index-only nonces would
/// then repeat). One offer == one fresh content key.
pub fn seal_chunk(
    key: &[u8; 32],
    offer_id: &[u8; 16],
    index: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let aad = chunk_aad(offer_id, index);
    cipher
        .encrypt(
            &Nonce::from(chunk_nonce(index)),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Blob("chunk seal failed".into()))
}

/// Open a file chunk sealed by [`seal_chunk`]. Rejects a chunk that was tampered
/// with, sealed under a different key, or presented at the wrong (offer, index)
/// -- the AAD binding fails the authentication in every one of those cases.
pub fn open_chunk(
    key: &[u8; 32],
    offer_id: &[u8; 16],
    index: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let aad = chunk_aad(offer_id, index);
    cipher
        .decrypt(
            &Nonce::from(chunk_nonce(index)),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Blob("chunk authentication failed".into()))
}

/// Seal a poll ballot under the poll's shared `ballot_key`. That key is reused
/// across every ballot in the poll (so any member can open any ballot at reveal),
/// so the 96-bit nonce MUST be fresh per ballot: a random nonce is generated and
/// prepended (`nonce(12) || ciphertext`). The AAD binds the ballot to its poll id,
/// so it cannot be replayed into another poll. The (untrusted) server, which
/// buffers ballots until the poll's release time, holds only this ciphertext -- it
/// has no key and cannot read the vote. Epoch-independent (off the MLS ratchet),
/// so a ballot held for days still opens even if the group re-keyed meanwhile.
pub fn seal_ballot(
    key: &[u8; 32],
    poll_id: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| CryptoError::Blob(format!("rng: {e}")))?;
    let ct = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: poll_id,
            },
        )
        .map_err(|_| CryptoError::Blob("ballot seal failed".into()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a ballot sealed by [`seal_ballot`]. Rejects a wrong key, a tampered
/// ballot, or one bound to a different poll (the AAD authentication fails).
pub fn open_ballot(
    key: &[u8; 32],
    poll_id: &[u8; 16],
    bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if bytes.len() < 12 {
        return Err(CryptoError::Blob("ballot too short".into()));
    }
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce: [u8; 12] = bytes[0..12].try_into().expect("12 bytes");
    cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &bytes[12..],
                aad: poll_id,
            },
        )
        .map_err(|_| CryptoError::Blob("ballot authentication failed".into()))
}

/// A freshly sealed blob. `ciphertext` is what the (untrusted) server stores;
/// `addr` and `key` are what the sender places in its sealed profile so a
/// recipient can fetch and decrypt.
pub struct SealedBlob {
    /// SHA-256 of `ciphertext`: the server storage address and integrity check.
    pub addr: [u8; 32],
    /// One-time AEAD key; shared only inside the sealed profile.
    pub key: [u8; 32],
    /// The bytes to upload to the server.
    pub ciphertext: Vec<u8>,
}

/// SHA-256 content address of a ciphertext -- how the server keys and verifies
/// storage without any key, and how a recipient detects a substituted blob.
pub fn blob_addr(ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ciphertext);
    hasher.finalize().into()
}

/// Encrypt `plaintext` under a fresh random key. Returns the ciphertext to
/// upload, its content address, and the key to place in the sealed profile.
pub fn seal_blob(plaintext: &[u8]) -> Result<SealedBlob, CryptoError> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| CryptoError::Blob(format!("rng: {e}")))?;
    let cipher = ChaCha20Poly1305::new(&Key::from(key));
    let ciphertext = cipher
        .encrypt(&Nonce::from(BLOB_NONCE), plaintext)
        .map_err(|_| CryptoError::Blob("seal failed".into()))?;
    let addr = blob_addr(&ciphertext);
    Ok(SealedBlob {
        addr,
        key,
        ciphertext,
    })
}

/// Verify a fetched `ciphertext` matches `addr`, then decrypt it with `key`.
/// Rejects a server-substituted blob (address mismatch) before spending any
/// decryption work, and a tampered blob (AEAD authentication failure).
pub fn open_blob(
    ciphertext: &[u8],
    addr: &[u8; 32],
    key: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    if &blob_addr(ciphertext) != addr {
        return Err(CryptoError::Blob(
            "address mismatch (wrong or substituted blob)".into(),
        ));
    }
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(&Nonce::from(BLOB_NONCE), ciphertext)
        .map_err(|_| CryptoError::Blob("authentication failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let image = b"\xff\xd8\xff\xe0 pretend-jpeg bytes \x00\x01\x02";
        let sealed = seal_blob(image).unwrap();
        assert_eq!(
            sealed.addr,
            blob_addr(&sealed.ciphertext),
            "addr is ciphertext hash"
        );
        assert_ne!(
            &sealed.ciphertext[..],
            &image[..],
            "stored bytes are encrypted"
        );
        let opened = open_blob(&sealed.ciphertext, &sealed.addr, &sealed.key).unwrap();
        assert_eq!(opened, image, "decrypts back to the original");
    }

    #[test]
    fn each_seal_uses_a_fresh_key() {
        let a = seal_blob(b"same image").unwrap();
        let b = seal_blob(b"same image").unwrap();
        assert_ne!(
            a.key, b.key,
            "a fresh key per seal (so the zero nonce is safe)"
        );
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "different key => different ciphertext"
        );
    }

    #[test]
    fn rejects_a_substituted_blob() {
        let real = seal_blob(b"real avatar").unwrap();
        let fake = seal_blob(b"attacker avatar").unwrap();
        // Server hands back a different blob than the address we asked for.
        let err = open_blob(&fake.ciphertext, &real.addr, &real.key);
        assert!(err.is_err(), "address mismatch must be rejected");
    }

    #[test]
    fn rejects_a_tampered_blob() {
        let mut sealed = seal_blob(b"avatar").unwrap();
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0x01; // flip a bit
        let addr = blob_addr(&sealed.ciphertext); // re-address so it passes the hash check
        let err = open_blob(&sealed.ciphertext, &addr, &sealed.key);
        assert!(err.is_err(), "AEAD must reject tampered ciphertext");
    }

    #[test]
    fn rejects_the_wrong_key() {
        let sealed = seal_blob(b"avatar").unwrap();
        let wrong = [0x11u8; 32];
        let err = open_blob(&sealed.ciphertext, &sealed.addr, &wrong);
        assert!(err.is_err(), "the wrong key must not decrypt");
    }

    #[test]
    fn chunks_round_trip_in_place() {
        let key = [7u8; 32];
        let offer = [3u8; 16];
        let a = seal_chunk(&key, &offer, 0, b"first chunk of a file").unwrap();
        let b = seal_chunk(&key, &offer, 1, b"second chunk").unwrap();
        assert_eq!(
            open_chunk(&key, &offer, 0, &a).unwrap(),
            b"first chunk of a file"
        );
        assert_eq!(open_chunk(&key, &offer, 1, &b).unwrap(), b"second chunk");
        assert_eq!(a.len(), b"first chunk of a file".len() + CHUNK_OVERHEAD);
    }

    #[test]
    fn a_chunk_will_not_open_at_the_wrong_index() {
        let key = [7u8; 32];
        let offer = [3u8; 16];
        let c = seal_chunk(&key, &offer, 5, b"payload").unwrap();
        assert!(
            open_chunk(&key, &offer, 6, &c).is_err(),
            "index is bound by the AAD"
        );
        assert!(
            open_chunk(&key, &offer, 5, &c).is_ok(),
            "the right index opens"
        );
    }

    #[test]
    fn a_chunk_will_not_open_under_another_offer() {
        let key = [7u8; 32];
        let c = seal_chunk(&key, &[1u8; 16], 0, b"payload").unwrap();
        assert!(
            open_chunk(&key, &[2u8; 16], 0, &c).is_err(),
            "offer_id is bound by the AAD"
        );
    }

    #[test]
    fn a_tampered_chunk_is_rejected() {
        let key = [7u8; 32];
        let offer = [3u8; 16];
        let mut c = seal_chunk(&key, &offer, 0, b"payload").unwrap();
        c[0] ^= 0x01;
        assert!(
            open_chunk(&key, &offer, 0, &c).is_err(),
            "AEAD rejects tampering"
        );
    }
}
