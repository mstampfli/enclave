//! Media frame sealing: SFrame-style per-frame AEAD, keyed from the MLS media
//! root secret. This is what makes a wiretap hear garbage while the far end
//! hears clear voice -- each *encoded* audio/video frame is encrypted before it
//! touches the wire, so there is no lossy stage after encryption.
//!
//! ## Keying
//! Each sender gets its own key derived from the group's media root secret
//! (which itself rotates every MLS epoch) via HKDF, bound to the group id, the
//! epoch, and the sender's identity key. Every member can derive any sender's
//! key (they know the roster), so anyone can open a frame; only members have
//! the root secret, so outsiders and the relay cannot.
//!
//! ## Nonce safety (unrepresentable reuse)
//! [`MediaSealer`] owns a monotonic per-sender counter; the AEAD nonce is
//! `salt(4) || counter(8)`. Because the key is unique per (sender, epoch) and
//! the counter never repeats or wraps (it errors first), a (key, nonce) pair is
//! never reused. The counter is private to the sealer, so reuse cannot be
//! introduced by a caller.
//!
//! ## Replay protection
//! [`MediaOpener`] authenticates first, then runs a 64-frame sliding
//! [`ReplayWindow`] (RFC 6479 style) so out-of-order real-time frames are
//! accepted once but duplicates and too-old frames are rejected.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use enclave_protocol::{DeviceId, GroupId, MediaFrame, MediaKind, Sealed};

use crate::CryptoError;

/// Derive the 32-byte AEAD key and 4-byte nonce salt for one sender, bound to
/// the group, epoch, and sender identity.
fn derive_key_salt(
    root_secret: &[u8],
    group: &GroupId,
    epoch: u64,
    sender_identity_key: &[u8],
) -> Result<([u8; 32], [u8; 4]), CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, root_secret);
    let mut info = Vec::with_capacity(24 + group.0.len() + sender_identity_key.len());
    info.extend_from_slice(b"enclave/sframe/v1");
    info.extend_from_slice(&group.0);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(&(sender_identity_key.len() as u32).to_be_bytes());
    info.extend_from_slice(sender_identity_key);

    let mut okm = [0u8; 36];
    hk.expand(&info, &mut okm)
        .map_err(|_| CryptoError::Media("hkdf expand failed".into()))?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[0..32]);
    let mut salt = [0u8; 4];
    salt.copy_from_slice(&okm[32..36]);
    okm.zeroize();
    Ok((key, salt))
}

/// Build the AEAD associated data binding every routing header field, so a
/// relay cannot move a frame to another sender/kind/epoch/counter undetected.
fn media_aad(
    group: &GroupId,
    sender: &DeviceId,
    kind: MediaKind,
    epoch: u64,
    counter: u64,
) -> Vec<u8> {
    let sender_bytes = sender.0.as_bytes();
    let mut aad = Vec::with_capacity(32 + 4 + sender_bytes.len() + 1 + 8 + 8);
    aad.extend_from_slice(&group.0);
    aad.extend_from_slice(&(sender_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(sender_bytes);
    aad.push(kind as u8);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

fn nonce_bytes(salt: &[u8; 4], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(salt);
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Seals outgoing media frames for one sender. Owns the monotonic counter.
pub struct MediaSealer {
    cipher: ChaCha20Poly1305,
    salt: [u8; 4],
    group: GroupId,
    sender: DeviceId,
    epoch: u64,
    counter: u64,
}

impl MediaSealer {
    pub fn new(
        root_secret: &[u8],
        group: GroupId,
        sender: DeviceId,
        sender_identity_key: &[u8],
        epoch: u64,
    ) -> Result<Self, CryptoError> {
        let (mut key, salt) = derive_key_salt(root_secret, &group, epoch, sender_identity_key)?;
        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        key.zeroize();
        Ok(Self {
            cipher,
            salt,
            group,
            sender,
            epoch,
            counter: 0,
        })
    }

    /// Seal one encoded frame into a [`MediaFrame`] ready for the wire.
    pub fn seal(&mut self, kind: MediaKind, plaintext: &[u8]) -> Result<MediaFrame, CryptoError> {
        let counter = self.counter;
        // Refuse to reuse a nonce: exhaust rather than wrap.
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| CryptoError::Media("nonce counter exhausted; rekey required".into()))?;

        let nonce = nonce_bytes(&self.salt, counter);
        let aad = media_aad(&self.group, &self.sender, kind, self.epoch, counter);
        let ciphertext = self
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Media("seal failed".into()))?;

        Ok(MediaFrame {
            group: self.group.clone(),
            sender: self.sender.clone(),
            kind,
            epoch: self.epoch,
            counter,
            payload: Sealed(ciphertext),
        })
    }
}

/// Opens incoming media frames from one sender. Authenticates, then enforces
/// replay protection.
pub struct MediaOpener {
    cipher: ChaCha20Poly1305,
    salt: [u8; 4],
    epoch: u64,
    window: ReplayWindow,
}

impl MediaOpener {
    pub fn new(
        root_secret: &[u8],
        group: &GroupId,
        sender_identity_key: &[u8],
        epoch: u64,
    ) -> Result<Self, CryptoError> {
        let (mut key, salt) = derive_key_salt(root_secret, group, epoch, sender_identity_key)?;
        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        key.zeroize();
        Ok(Self {
            cipher,
            salt,
            epoch,
            window: ReplayWindow::new(),
        })
    }

    /// Authenticate and decrypt a frame, returning the encoded plaintext.
    /// Rejects wrong-epoch, tampered, forged, duplicate, and too-old frames.
    pub fn open(&mut self, frame: &MediaFrame) -> Result<Vec<u8>, CryptoError> {
        if frame.epoch != self.epoch {
            return Err(CryptoError::Media(format!(
                "epoch mismatch: frame {} != opener {}",
                frame.epoch, self.epoch
            )));
        }
        let nonce = nonce_bytes(&self.salt, frame.counter);
        let aad = media_aad(
            &frame.group,
            &frame.sender,
            frame.kind,
            frame.epoch,
            frame.counter,
        );
        // Authenticate BEFORE touching replay state, so a forged frame cannot
        // poison the window and cause a real frame to be dropped.
        let plaintext = self
            .cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &frame.payload.0,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Media("authentication failed".into()))?;

        if !self.window.accept(frame.counter) {
            return Err(CryptoError::Media("replay or too-old frame".into()));
        }
        Ok(plaintext)
    }
}

/// A 64-entry sliding replay window over frame counters (RFC 6479 style). Bit
/// `i` of `bitmap` records that counter `highest - i` has been accepted.
struct ReplayWindow {
    highest: u64,
    bitmap: u64,
    seen_any: bool,
}

impl ReplayWindow {
    const WIDTH: u64 = 64;

    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            seen_any: false,
        }
    }

    /// Record `counter` as accepted; return false if it is a duplicate or older
    /// than the window (a replay / too-old frame).
    fn accept(&mut self, counter: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = counter;
            self.bitmap = 1;
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            self.bitmap = if shift >= Self::WIDTH {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = counter;
            true
        } else {
            let diff = self.highest - counter;
            if diff >= Self::WIDTH {
                return false; // older than the window
            }
            let mask = 1u64 << diff;
            if self.bitmap & mask != 0 {
                false // already seen
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}

#[cfg(test)]
mod replay_window_tests {
    use super::ReplayWindow;

    #[test]
    fn accepts_in_order() {
        let mut w = ReplayWindow::new();
        for c in 0..1000 {
            assert!(w.accept(c), "in-order counter {c} must be accepted");
        }
    }

    #[test]
    fn rejects_duplicates() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(!w.accept(5), "duplicate must be rejected");
        assert!(w.accept(6));
        assert!(!w.accept(6));
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(10));
        assert!(w.accept(8), "recent out-of-order frame accepted");
        assert!(w.accept(9));
        assert!(!w.accept(8), "but not twice");
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(100));
        assert!(!w.accept(100 - 64), "exactly window width away is too old");
        assert!(!w.accept(0), "far too old");
        assert!(w.accept(100 - 63), "just inside the window is fine");
    }

    #[test]
    fn large_jump_forward_resets_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(1));
        assert!(w.accept(1_000_000), "big forward jump accepted");
        assert!(!w.accept(1), "old counter now outside window");
        assert!(!w.accept(1_000_000), "no duplicate of the new highest");
    }
}
