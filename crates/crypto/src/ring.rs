//! Linkable spontaneous anonymous group (LSAG) signatures over the Ed25519
//! group -- the primitive behind anonymous polls.
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
//! ## Why Ed25519 and not Ristretto
//!
//! The ring is built from the members' **existing MLS identity keys**, which are
//! Ed25519, and which every member already holds locally in their group state.
//! That is the entire point: a ring can be assembled offline, for any group, with
//! no key distribution step and nobody needing to be reachable -- and those keys
//! are already what the safety number verifies, so there is no new thing to trust
//! or to check. A separate Ristretto voting key would have to travel somewhere
//! first, which is exactly the requirement we are removing.
//!
//! Ed25519's group has cofactor 8, which Ristretto exists to abstract away, so the
//! cofactor is handled explicitly and in one place here:
//!
//! - **Every ring key must be torsion-free.** A genuine Ed25519 public key is
//!   `a*B` and therefore in the prime-order subgroup; anything else is rejected.
//!   This is what stops a crafted small-order key from yielding a malleable key
//!   image (which would let one member vote twice without linking).
//! - **The hash-to-point result is cofactor-cleared**, so the key image `x*H(scope)`
//!   is prime-order by construction.
//! - **The key image is re-checked on verify**, so a hand-built signature cannot
//!   smuggle a torsion component past us.
//!
//! With every point constrained to the prime-order subgroup, the algebra is the
//! same as it would be over any prime-order group.
//!
//! PRIMITIVE: the single source of truth for anonymous ballots. Never hand-roll a
//! ring signature elsewhere; reuse this. Vetted building blocks only (curve25519-
//! dalek constant-time group ops, SHA-512); we assemble, we do not invent curves.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::CryptoError;

const H2P_DOMAIN: &[u8] = b"enclave-ring-h2p-v2";
const HS_DOMAIN: &[u8] = b"enclave-ring-hs-v2";

/// A linkable ring signature. `s` has one scalar per ring member; `key_image`
/// links two signatures by the same signer under the same scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingSig {
    pub c0: [u8; 32],
    pub s: Vec<[u8; 32]>,
    pub key_image: [u8; 32],
}

/// A member's ring keypair. `public` is the member's **Ed25519 identity key** --
/// the very key their MLS credential and safety number are bound to -- so a ring
/// is assembled from group state alone, with nothing to publish or fetch.
pub struct RingKeypair {
    secret: Scalar,
    pub public: [u8; 32],
}

impl RingKeypair {
    /// Derive from a 32-byte Ed25519 private seed (what `SignatureKeyPair` stores).
    /// Applies the standard Ed25519 clamp, so `public` is byte-identical to the
    /// identity's verifying key and the holder can sign for their own ring slot.
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> RingKeypair {
        let h = Sha512::digest(seed);
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        // Ed25519 clamping: clear the low 3 bits, clear the top bit, set bit 254.
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        // Reduce mod L. The clamped value may exceed the group order, and the
        // reduced scalar is congruent, so it yields the same public point.
        let secret = Scalar::from_bytes_mod_order(s);
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

/// Deterministically map the linkability `scope` (the poll id) to a prime-order
/// Edwards point, so a member's key image `x*H(scope)` is the same for every
/// ballot they cast in that poll but unrelated to any other poll.
///
/// Try-and-increment: hash, attempt to decompress, bump a counter on failure.
/// The input is public (a poll id), so the variable iteration count leaks nothing.
/// The result is cofactor-cleared, putting it in the prime-order subgroup.
fn hash_to_point(scope: &[u8]) -> EdwardsPoint {
    for counter in 0u16..=u16::MAX {
        let mut h = Sha512::new();
        h.update(H2P_DOMAIN);
        h.update(scope);
        h.update(counter.to_le_bytes());
        let d = h.finalize();
        let mut c = [0u8; 32];
        c.copy_from_slice(&d[..32]);
        if let Some(p) = CompressedEdwardsY(c).decompress() {
            let p = p.mul_by_cofactor();
            // Cofactor clearing can land on the identity; that point is useless
            // as a key-image base (every key image would collapse to it).
            if p != EdwardsPoint::default() {
                return p;
            }
        }
    }
    // Unreachable in practice: ~50% of candidates decompress, so exhausting
    // 65536 of them has probability ~2^-65536.
    unreachable!("no hash-to-point candidate succeeded")
}

fn random_scalar() -> Result<Scalar, CryptoError> {
    let mut b = [0u8; 64];
    getrandom::getrandom(&mut b).map_err(|e| CryptoError::Blob(format!("rng: {e}")))?;
    Ok(Scalar::from_bytes_mod_order_wide(&b))
}

/// Decompress a ring point, REJECTING anything outside the prime-order subgroup.
/// Genuine Ed25519 public keys are `a*B` and always pass; a crafted key with a
/// torsion component would make the key image malleable, so it never gets in.
fn decompress(b: &[u8; 32]) -> Option<EdwardsPoint> {
    let p = CompressedEdwardsY(*b).decompress()?;
    (p.is_torsion_free() && p != EdwardsPoint::default()).then_some(p)
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
    l: &EdwardsPoint,
    r: &EdwardsPoint,
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
/// secret does not match `ring[index]`, or a ring key is unusable.
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
    // The key image must be prime-order too: a torsion component would let the
    // same signer produce several distinct images and vote more than once.
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
            .map(|i| RingKeypair::from_ed25519_seed(&[i as u8 + 1; 32]))
            .collect();
        let pubs: Vec<[u8; 32]> = kps.iter().map(|k| k.public).collect();
        (kps, pubs)
    }

    /// The property the whole design rests on: a ring key IS the member's Ed25519
    /// identity key, so a ring needs no key distribution at all.
    #[test]
    fn a_ring_key_is_exactly_the_ed25519_identity_key() {
        let seed = [7u8; 32];
        let kp = RingKeypair::from_ed25519_seed(&seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(
            kp.public,
            signing.verifying_key().to_bytes(),
            "the ring public key is byte-identical to the Ed25519 verifying key"
        );
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
        let outsider = RingKeypair::from_ed25519_seed(&[99u8; 32]);
        assert!(ring_sign(b"x", b"p", &ring, &outsider.secret, 0).is_err());
        assert!(
            outsider.sign(b"x", b"p", &ring).is_err(),
            "outsider is not in the ring"
        );
        // A signature made over a DIFFERENT ring does not verify against this one.
        let other: Vec<RingKeypair> = [50u8, 51, 52, 53]
            .iter()
            .map(|i| RingKeypair::from_ed25519_seed(&[*i; 32]))
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

    /// The cofactor defence. A point with a torsion component must never be
    /// accepted as a ring key or a key image: that is precisely what would make a
    /// key image malleable and let one member vote twice without linking.
    #[test]
    fn small_order_points_are_refused_everywhere() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        let (kps, mut ring) = ring_of(3);
        let good = ring_sign(b"v", b"poll", &ring, &kps[0].secret, 0).unwrap();
        assert!(ring_verify(b"v", b"poll", &ring, &good));

        // A torsion point smuggled into the ring is rejected outright.
        for t in EIGHT_TORSION.iter().skip(1) {
            let mut poisoned = ring.clone();
            poisoned[1] = t.compress().to_bytes();
            assert!(
                !ring_verify(b"v", b"poll", &poisoned, &good),
                "a ring containing a torsion point is refused"
            );
            assert!(
                ring_sign(b"v", b"poll", &poisoned, &kps[0].secret, 0).is_err(),
                "and cannot be signed against either"
            );
        }

        // A key image with a torsion component is rejected.
        for t in EIGHT_TORSION.iter().skip(1) {
            let mut bad = good.clone();
            let ki = decompress(&good.key_image).expect("genuine image is prime-order");
            bad.key_image = (ki + t).compress().to_bytes();
            assert!(
                !ring_verify(b"v", b"poll", &ring, &bad),
                "a torsion-tainted key image is refused"
            );
        }

        // The identity point is not a usable key either.
        ring[1] = EdwardsPoint::default().compress().to_bytes();
        assert!(!ring_verify(b"v", b"poll", &ring, &good));
    }
}
