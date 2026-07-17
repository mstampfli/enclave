//! Linkable spontaneous anonymous group (LSAG) signatures over Ristretto255 --
//! the primitive behind anonymous polls.
//!
//! A voter signs their ballot as *"one of the members of this ring cast this"*
//! without revealing WHICH member (anonymity), while a deterministic **key image**
//! bound to the poll lets everyone detect two votes from the same member
//! (linkability / no double-voting) -- again without learning who. Only a real ring
//! member can produce a valid signature (unforgeability), so outsiders cannot stuff
//! a poll.
//!
//! Scheme: Liu-Wei-Wong LSAG. `scope` is the linkability context (the poll id), so
//! key images link within one poll but not across polls. The message is bound into
//! every hash, and the whole ring is hashed in, so a signature is tied to its exact
//! `(message, ring, scope)`.
//!
//! PRIMITIVE: the single source of truth for anonymous ballots. Never hand-roll a
//! ring signature elsewhere; reuse this. Vetted building blocks only (curve25519-
//! dalek constant-time group ops, SHA-512); we assemble, we do not invent curves.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::CryptoError;

const KEY_DOMAIN: &[u8] = b"enclave-ring-key-v1";
const H2P_DOMAIN: &[u8] = b"enclave-ring-h2p-v1";
const HS_DOMAIN: &[u8] = b"enclave-ring-hs-v1";

/// A linkable ring signature. `s` has one scalar per ring member; `key_image`
/// links two signatures by the same signer under the same scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingSig {
    pub c0: [u8; 32],
    pub s: Vec<[u8; 32]>,
    pub key_image: [u8; 32],
}

/// A member's ring keypair. `public` (compressed point) is broadcast to the group;
/// `secret` is kept on the device. Distinct from the identity/MLS keys.
pub struct RingKeypair {
    secret: Scalar,
    pub public: [u8; 32],
}

impl RingKeypair {
    /// Derive the keypair deterministically from a persisted 32-byte seed, so the
    /// same account always presents the same voting public key.
    pub fn from_seed(seed: &[u8; 32]) -> RingKeypair {
        let secret = scalar_from_hash(&[KEY_DOMAIN, seed]);
        let public = (secret * G).compress().to_bytes();
        RingKeypair { secret, public }
    }

    /// Ring-sign `msg` for this keypair, finding our own position in `ring`
    /// automatically. Fails if our public key is not one of the ring's keys.
    pub fn sign(
        &self,
        msg: &[u8],
        scope: &[u8],
        ring: &[[u8; 32]],
    ) -> Result<RingSig, CryptoError> {
        let index = ring
            .iter()
            .position(|k| k == &self.public)
            .ok_or_else(|| CryptoError::Blob("we are not in this ring".into()))?;
        ring_sign(msg, scope, ring, &self.secret, index)
    }
}

/// Hash arbitrary parts to a scalar (SHA-512 wide-reduced), domain-separated.
fn scalar_from_hash(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&d);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Deterministically map the linkability `scope` (the poll id) to a ristretto
/// point, so a member's key image `x*H(scope)` is the same for every ballot they
/// cast in that poll but unrelated to any other poll.
fn hash_to_point(scope: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(H2P_DOMAIN);
    h.update(scope);
    let d = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&d);
    RistrettoPoint::from_uniform_bytes(&wide)
}

fn random_scalar() -> Result<Scalar, CryptoError> {
    let mut b = [0u8; 64];
    getrandom::getrandom(&mut b).map_err(|e| CryptoError::Blob(format!("rng: {e}")))?;
    Ok(Scalar::from_bytes_mod_order_wide(&b))
}

fn decompress(b: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(b)
        .ok()
        .and_then(|c| c.decompress())
}

fn scalar_from_canonical(b: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_canonical_bytes(*b))
}

/// The challenge hash `c_{i+1}` for one ring step. Binds the message, the whole
/// ring, the key image, and the two step points.
fn challenge(
    msg: &[u8],
    ring_bytes: &[u8],
    ki: &[u8; 32],
    l: &RistrettoPoint,
    r: &RistrettoPoint,
) -> Scalar {
    scalar_from_hash(&[
        HS_DOMAIN,
        msg,
        ring_bytes,
        ki,
        l.compress().as_bytes(),
        r.compress().as_bytes(),
    ])
}

fn ring_bytes(ring: &[[u8; 32]]) -> Vec<u8> {
    ring.iter().flat_map(|b| b.iter().copied()).collect()
}

/// Sign `msg` as ring member `index` (whose secret is `secret`), linkable within
/// `scope`. `ring` is the compressed public keys of every eligible signer, in a
/// fixed order all verifiers agree on. Fails if the index is out of range, the
/// secret does not match `ring[index]`, or a ring key does not decompress.
pub fn ring_sign(
    msg: &[u8],
    scope: &[u8],
    ring: &[[u8; 32]],
    secret: &Scalar,
    index: usize,
) -> Result<RingSig, CryptoError> {
    let n = ring.len();
    if n == 0 || index >= n {
        return Err(CryptoError::Blob("ring index out of range".into()));
    }
    let mut pubs = Vec::with_capacity(n);
    for b in ring {
        pubs.push(decompress(b).ok_or_else(|| CryptoError::Blob("bad ring key".into()))?);
    }
    if pubs[index] != secret * G {
        return Err(CryptoError::Blob(
            "secret does not match ring position".into(),
        ));
    }
    let h = hash_to_point(scope);
    let key_image = secret * h;
    let ki = key_image.compress().to_bytes();
    let rb = ring_bytes(ring);

    let mut c = vec![Scalar::ZERO; n];
    let mut s = vec![Scalar::ZERO; n];
    let u = random_scalar()?;
    let start = (index + 1) % n;
    c[start] = challenge(msg, &rb, &ki, &(u * G), &(u * h));
    let mut i = start;
    while i != index {
        s[i] = random_scalar()?;
        let l = s[i] * G + c[i] * pubs[i];
        let r = s[i] * h + c[i] * key_image;
        let next = (i + 1) % n;
        c[next] = challenge(msg, &rb, &ki, &l, &r);
        i = next;
    }
    // Close the ring at the real signer: only the secret can produce this.
    s[index] = u - c[index] * secret;
    Ok(RingSig {
        c0: c[0].to_bytes(),
        s: s.iter().map(|x| x.to_bytes()).collect(),
        key_image: ki,
    })
}

/// Verify a ring signature over `(msg, ring, scope)`. Returns false on any bad
/// input rather than erroring, so a hostile ballot is simply rejected.
pub fn ring_verify(msg: &[u8], scope: &[u8], ring: &[[u8; 32]], sig: &RingSig) -> bool {
    let n = ring.len();
    if n == 0 || sig.s.len() != n {
        return false;
    }
    let mut pubs = Vec::with_capacity(n);
    for b in ring {
        match decompress(b) {
            Some(p) => pubs.push(p),
            None => return false,
        }
    }
    let key_image = match decompress(&sig.key_image) {
        Some(p) => p,
        None => return false,
    };
    let c0 = match scalar_from_canonical(&sig.c0) {
        Some(x) => x,
        None => return false,
    };
    let h = hash_to_point(scope);
    let rb = ring_bytes(ring);
    let mut c = c0;
    for i in 0..n {
        let si = match scalar_from_canonical(&sig.s[i]) {
            Some(x) => x,
            None => return false,
        };
        let l = si * G + c * pubs[i];
        let r = si * h + c * key_image;
        c = challenge(msg, &rb, &sig.key_image, &l, &r);
    }
    c == c0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_of(n: usize) -> (Vec<RingKeypair>, Vec<[u8; 32]>) {
        let kps: Vec<RingKeypair> = (0..n)
            .map(|i| RingKeypair::from_seed(&[i as u8 + 1; 32]))
            .collect();
        let pubs: Vec<[u8; 32]> = kps.iter().map(|k| k.public).collect();
        (kps, pubs)
    }

    #[test]
    fn a_valid_signature_verifies_and_a_tampered_one_does_not() {
        let (kps, ring) = ring_of(5);
        let sig = ring_sign(b"vote:2", b"poll-A", &ring, &kps[3].secret, 3).unwrap();
        assert!(
            ring_verify(b"vote:2", b"poll-A", &ring, &sig),
            "genuine signature verifies"
        );
        // Wrong message, wrong scope, wrong ring order all fail.
        assert!(!ring_verify(b"vote:1", b"poll-A", &ring, &sig));
        assert!(!ring_verify(b"vote:2", b"poll-B", &ring, &sig));
        let mut shuffled = ring.clone();
        shuffled.swap(0, 1);
        assert!(!ring_verify(b"vote:2", b"poll-A", &shuffled, &sig));
        // A flipped signature scalar fails.
        let mut bad = sig.clone();
        bad.s[0][0] ^= 1;
        assert!(!ring_verify(b"vote:2", b"poll-A", &ring, &bad));
    }

    #[test]
    fn the_signer_stays_hidden_but_double_votes_link() {
        let (kps, ring) = ring_of(6);
        // Two ballots by the SAME member in the SAME poll share a key image.
        let a = ring_sign(b"vote:0", b"poll-X", &ring, &kps[2].secret, 2).unwrap();
        let b = ring_sign(b"vote:4", b"poll-X", &ring, &kps[2].secret, 2).unwrap();
        assert_eq!(a.key_image, b.key_image, "same signer + poll => linked");
        // A different member's ballot does NOT link.
        let c = ring_sign(b"vote:0", b"poll-X", &ring, &kps[5].secret, 5).unwrap();
        assert_ne!(a.key_image, c.key_image, "different signer => unlinked");
        // The same member in a DIFFERENT poll does not link (scoped key image).
        let d = ring_sign(b"vote:0", b"poll-Y", &ring, &kps[2].secret, 2).unwrap();
        assert_ne!(a.key_image, d.key_image, "different poll => unlinked");
        // Every one of them is a valid ring signature.
        for (m, s) in [(b"vote:0".as_slice(), &a), (b"vote:4", &b), (b"vote:0", &c)] {
            assert!(ring_verify(m, b"poll-X", &ring, s));
        }
        assert!(ring_verify(b"vote:0", b"poll-Y", &ring, &d));
    }

    #[test]
    fn a_non_member_cannot_forge() {
        let (_kps, ring) = ring_of(4);
        // An outsider's key is not in the ring: signing with a claimed index fails
        // (the secret does not match that ring position).
        let outsider = RingKeypair::from_seed(&[99u8; 32]);
        assert!(ring_sign(b"x", b"p", &ring, &outsider.secret, 0).is_err());
        assert!(
            outsider.sign(b"x", b"p", &ring).is_err(),
            "outsider is not in the ring"
        );
        // A signature made over a DIFFERENT ring does not verify against this one.
        let other: Vec<RingKeypair> = [50u8, 51, 52, 53]
            .iter()
            .map(|i| RingKeypair::from_seed(&[*i; 32]))
            .collect();
        let other_ring: Vec<[u8; 32]> = other.iter().map(|k| k.public).collect();
        let sig = other[0].sign(b"x", b"p", &other_ring).unwrap();
        assert!(
            ring_verify(b"x", b"p", &other_ring, &sig),
            "valid for its own ring"
        );
        assert!(
            !ring_verify(b"x", b"p", &ring, &sig),
            "the original ring rejects it"
        );
    }
}
