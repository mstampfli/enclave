//! Media frame sealing: SFrame-style per-frame AEAD, keyed from the MLS media
//! root secret. This is what makes a wiretap hear garbage while the far end
//! hears clear voice -- each *encoded* audio/video frame is encrypted before it
//! touches the wire, so there is no lossy stage after encryption.
//!
//! ## Keying (confidentiality)
//! Each sender gets its own key derived from the group's media root secret
//! (which itself rotates every MLS epoch) via HKDF, bound to the group id, the
//! epoch, and the sender's identity key. Every member can derive any sender's
//! key (they know the roster), so anyone can open a frame; only members have
//! the root secret, so outsiders and the relay cannot.
//!
//! ## Source authentication (anti-impersonation)
//! Because every member can derive every other member's *symmetric* media key,
//! the AEAD tag alone only proves "some group member made this" -- not who. So
//! each frame is also signed with the sender's **Ed25519 identity key** (the
//! same key MLS binds to their credential and the safety number covers). Only
//! the key owner holds the private half, so no other member can forge a frame
//! attributed to them. The receiver verifies the signature against the claimed
//! sender's roster public key ([`MediaOpener`] does this before AEAD), and the
//! signature is domain-separated ([`MEDIA_SIG_CONTEXT`]) so it can never be
//! confused with an MLS handshake signature made with the same key. Each frame
//! carries its own complete signature and is verified independently, so a lost
//! packet never orphans the authentication of any other.
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
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use sha2::Sha256;
use zeroize::Zeroize;

use enclave_protocol::{DeviceId, GroupId, MediaFrame, MediaKind, Sealed};

use crate::CryptoError;

/// Domain separator for media-frame signatures. Prefixing the signed bytes with
/// this label (and a distinct byte layout) means a media signature can never be
/// reinterpreted as an MLS handshake signature made with the same Ed25519
/// credential key, or vice versa -- no cross-protocol signature confusion.
pub const MEDIA_SIG_CONTEXT: &[u8] = b"enclave/media-sig/v1";

/// The exact bytes a frame signature covers: the routing header (AEAD associated
/// data) and the ciphertext, under the domain-separation prefix. Signing the
/// ciphertext (encrypt-then-sign) lets a receiver reject a forgery before
/// spending any work decrypting. The `aad` is length-prefixed so the boundary
/// between it and the ciphertext is unambiguous.
fn signing_input(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MEDIA_SIG_CONTEXT.len() + 4 + aad.len() + ciphertext.len());
    m.extend_from_slice(MEDIA_SIG_CONTEXT);
    m.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    m.extend_from_slice(aad);
    m.extend_from_slice(ciphertext);
    m
}

/// Signs outgoing media frames with a sender's Ed25519 identity key. Wraps the
/// MLS signature keypair and signs through it (the private key is never read
/// out), and is plain `Send` bytes so it can move onto the capture thread. Build
/// one from a device [`Identity`](crate::Identity) via
/// [`Identity::media_signer`](crate::Identity::media_signer).
pub struct MediaSigner {
    keypair: SignatureKeyPair,
}

impl MediaSigner {
    pub(crate) fn from_keypair(keypair: SignatureKeyPair) -> Self {
        Self { keypair }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.keypair
            .sign(message)
            .map_err(|_| CryptoError::Media("media frame signing failed".into()))
    }
}

/// Verifies a sender's media-frame signatures against their Ed25519 identity
/// (public) key -- the same key the MLS roster and safety number bind to that
/// member. A frame that does not verify was not produced by that member.
struct MediaVerifier {
    key: VerifyingKey,
}

impl MediaVerifier {
    fn from_ed25519_public(public_key: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| CryptoError::Media("ed25519 public key must be 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| CryptoError::Media("invalid ed25519 public key".into()))?;
        Ok(Self { key })
    }

    /// True only if `sig` is this key's signature over `message`. Uses
    /// `verify_strict`, which rejects non-canonical signatures and small-order
    /// public keys (signature-malleability defense).
    fn verify(&self, message: &[u8], sig: &[u8]) -> bool {
        let Ok(bytes) = <[u8; 64]>::try_from(sig) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&bytes);
        self.key.verify_strict(message, &sig).is_ok()
    }
}

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

/// Seals outgoing media frames for one sender. Owns the monotonic counter and
/// the sender's [`MediaSigner`], so every frame is both encrypted and signed.
pub struct MediaSealer {
    cipher: ChaCha20Poly1305,
    salt: [u8; 4],
    group: GroupId,
    sender: DeviceId,
    epoch: u64,
    counter: u64,
    signer: MediaSigner,
}

impl MediaSealer {
    /// `sender_identity_key` keys the symmetric layer (per-sender nonce-space
    /// separation); `signer` is the sender's private Ed25519 key that authorizes
    /// the frame. In honest use they are the two halves of one identity key --
    /// they are separate inputs precisely because the impersonation an attacker
    /// would attempt is to key the symmetric side to a victim (which any member
    /// can do) while being unable to produce the victim's signature.
    pub fn new(
        root_secret: &[u8],
        group: GroupId,
        sender: DeviceId,
        sender_identity_key: &[u8],
        epoch: u64,
        signer: MediaSigner,
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
            signer,
        })
    }

    /// Seal one encoded frame into a [`MediaFrame`] ready for the wire:
    /// encrypt-then-sign.
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

        let sig = self.signer.sign(&signing_input(&aad, &ciphertext))?;

        Ok(MediaFrame {
            group: self.group.clone(),
            sender: self.sender.clone(),
            kind,
            epoch: self.epoch,
            counter,
            payload: Sealed(ciphertext),
            sig,
        })
    }
}

/// Opens incoming media frames from one sender. Verifies the sender's signature
/// and the AEAD, then enforces replay protection. `sender_identity_key` is the
/// claimed sender's roster public key -- it both keys the symmetric layer and is
/// the verification key, so a frame that names a sender but is not signed by
/// that sender's private key is rejected.
pub struct MediaOpener {
    cipher: ChaCha20Poly1305,
    salt: [u8; 4],
    epoch: u64,
    window: ReplayWindow,
    verifier: MediaVerifier,
}

impl MediaOpener {
    pub fn new(
        root_secret: &[u8],
        group: &GroupId,
        sender_identity_key: &[u8],
        epoch: u64,
    ) -> Result<Self, CryptoError> {
        let verifier = MediaVerifier::from_ed25519_public(sender_identity_key)?;
        let (mut key, salt) = derive_key_salt(root_secret, group, epoch, sender_identity_key)?;
        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        key.zeroize();
        Ok(Self {
            cipher,
            salt,
            epoch,
            window: ReplayWindow::new(),
            verifier,
        })
    }

    /// Verify, authenticate, and decrypt a frame, returning the encoded
    /// plaintext. Rejects wrong-epoch, impersonated (bad signature), tampered,
    /// duplicate, and too-old frames.
    pub fn open(&mut self, frame: &MediaFrame) -> Result<Vec<u8>, CryptoError> {
        if frame.epoch != self.epoch {
            return Err(CryptoError::Media(format!(
                "epoch mismatch: frame {} != opener {}",
                frame.epoch, self.epoch
            )));
        }
        let aad = media_aad(
            &frame.group,
            &frame.sender,
            frame.kind,
            frame.epoch,
            frame.counter,
        );
        // Source authentication FIRST: only the claimed sender's private key can
        // sign this. A member who re-derives the (shared) symmetric key and
        // forges a frame under another sender's identity is caught here, before
        // any decryption work. Done before the replay window so a forgery cannot
        // poison it and drop a real frame.
        if !self
            .verifier
            .verify(&signing_input(&aad, &frame.payload.0), &frame.sig)
        {
            return Err(CryptoError::Media("sender signature invalid".into()));
        }
        let nonce = nonce_bytes(&self.salt, frame.counter);
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
