//! Phase 3 (security crux): media frame sealing. Proves the wiretap-hears-garbage
//! / far-end-hears-clear property at the frame level, and that tampering,
//! forgery, impersonation, replay, and cross-epoch frames are all rejected.

use enclave_crypto::{Group, Identity, MediaOpener, MediaSealer};
use enclave_protocol::{DeviceId, GroupId, MediaKind};

const ROOT: [u8; 32] = [0x42; 32];
const GID: GroupId = GroupId([9u8; 32]);

/// A sealer for `id`, keyed and signed by that identity. The symmetric side and
/// the signer are the two halves of the same real Ed25519 identity key.
fn sealer(id: &Identity, epoch: u64) -> MediaSealer {
    MediaSealer::new(
        &ROOT,
        GID,
        DeviceId("alice-1".into()),
        &id.identity_key(),
        epoch,
        id.media_signer().unwrap(),
    )
    .unwrap()
}

/// An opener that expects frames from `id` (its public key both derives the
/// symmetric key and verifies the sender signature).
fn opener(id: &Identity, epoch: u64) -> MediaOpener {
    MediaOpener::new(&ROOT, &GID, &id.identity_key(), epoch).unwrap()
}

#[test]
fn round_trips_and_wire_bytes_are_opaque() {
    let id = Identity::generate("alice").unwrap();
    let mut s = sealer(&id, 1);
    let mut o = opener(&id, 1);
    let encoded = b"pretend this is an encoded Opus frame";

    let frame = s.seal(MediaKind::Audio, encoded).unwrap();
    assert!(
        !frame.payload.0.windows(encoded.len()).any(|w| w == encoded),
        "sealed frame must not contain the plaintext"
    );

    assert_eq!(o.open(&frame).unwrap(), encoded);
}

#[test]
fn counters_are_monotonic_so_nonces_never_repeat() {
    let id = Identity::generate("alice").unwrap();
    let mut s = sealer(&id, 1);
    for expected in 0..2000u64 {
        let f = s.seal(MediaKind::Audio, b"x").unwrap();
        assert_eq!(f.counter, expected);
    }
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let id = Identity::generate("alice").unwrap();
    let mut s = sealer(&id, 1);
    let mut o = opener(&id, 1);
    let mut f = s.seal(MediaKind::Audio, b"hello voice frame").unwrap();
    let mid = f.payload.0.len() / 2;
    f.payload.0[mid] ^= 0xff;
    assert!(o.open(&f).is_err());
}

#[test]
fn tampered_signature_is_rejected() {
    let id = Identity::generate("alice").unwrap();
    let mut s = sealer(&id, 1);
    let mut o = opener(&id, 1);
    let mut f = s.seal(MediaKind::Audio, b"authentic frame").unwrap();
    f.sig[0] ^= 0xff;
    let err = o.open(&f).unwrap_err();
    assert!(
        err.to_string().contains("signature"),
        "a mangled signature must be rejected, got: {err}"
    );
}

#[test]
fn tampered_header_is_rejected() {
    let id = Identity::generate("alice").unwrap();
    let mut s = sealer(&id, 1);
    let mut o = opener(&id, 1);

    // The media kind is bound in both the signature and the AEAD associated data.
    let mut f = s.seal(MediaKind::Audio, b"frame").unwrap();
    f.kind = MediaKind::Video;
    assert!(o.open(&f).is_err(), "signature + AAD bind the media kind");

    // So is the counter (also the nonce).
    let mut f2 = s.seal(MediaKind::Audio, b"frame2").unwrap();
    f2.counter = f2.counter.wrapping_add(7);
    assert!(
        o.open(&f2).is_err(),
        "signature + AAD + nonce bind the counter"
    );
}

#[test]
fn wrong_sender_key_cannot_open() {
    let alice = Identity::generate("alice").unwrap();
    let bob = Identity::generate("bob").unwrap();
    let mut s = sealer(&alice, 1);
    let f = s.seal(MediaKind::Audio, b"frame").unwrap();
    // An opener that expects Bob rejects a frame signed and keyed by Alice.
    let mut wrong = MediaOpener::new(&ROOT, &GID, &bob.identity_key(), 1).unwrap();
    assert!(wrong.open(&f).is_err());
}

#[test]
fn a_member_cannot_forge_another_senders_frame() {
    // The core anti-impersonation guarantee. Alice and Bob share the group media
    // root secret, so Bob CAN derive Alice's symmetric key and produce a frame
    // whose AEAD opens under her identity. The ONLY thing stopping him from
    // impersonating her is the per-frame signature, which needs her private key.
    let alice = Identity::generate("alice").unwrap();
    let bob = Identity::generate("bob").unwrap();

    // Baseline: an honest Alice frame opens under an Alice-keyed opener.
    let mut honest = MediaSealer::new(
        &ROOT,
        GID,
        DeviceId("alice-1".into()),
        &alice.identity_key(),
        1,
        alice.media_signer().unwrap(),
    )
    .unwrap();
    let mut o = MediaOpener::new(&ROOT, &GID, &alice.identity_key(), 1).unwrap();
    let good = honest.seal(MediaKind::Audio, b"real alice").unwrap();
    assert_eq!(o.open(&good).unwrap(), b"real alice");

    // Forgery: Bob keys the symmetric layer to ALICE's identity (which he can,
    // since every member derives every member's key) and labels himself
    // "alice-1", but he can only sign with HIS key.
    let mut forge = MediaSealer::new(
        &ROOT,
        GID,
        DeviceId("alice-1".into()),
        &alice.identity_key(),
        1,
        bob.media_signer().unwrap(),
    )
    .unwrap();
    let forged = forge.seal(MediaKind::Audio, b"i am not alice").unwrap();

    // The symmetric key matches (same as the honest frame above), so the AEAD
    // layer alone WOULD accept it. The signature is what rejects it.
    let mut victim = MediaOpener::new(&ROOT, &GID, &alice.identity_key(), 1).unwrap();
    let err = victim.open(&forged).unwrap_err();
    assert!(
        err.to_string().contains("signature"),
        "forgery must be rejected at signature verification, got: {err}"
    );
}

#[test]
fn cross_epoch_cannot_open() {
    let id = Identity::generate("alice").unwrap();
    let mut s = sealer(&id, 1);
    let f = s.seal(MediaKind::Audio, b"frame").unwrap();
    let mut next_epoch = opener(&id, 2);
    assert!(next_epoch.open(&f).is_err());
}

#[test]
fn replay_is_rejected() {
    let id = Identity::generate("alice").unwrap();
    let mut s = sealer(&id, 1);
    let mut o = opener(&id, 1);
    let f = s.seal(MediaKind::Audio, b"once").unwrap();
    assert!(o.open(&f).is_ok());
    assert!(o.open(&f).is_err(), "the same frame twice is a replay");
}

#[test]
fn out_of_order_within_window_is_accepted_once() {
    let id = Identity::generate("alice").unwrap();
    let mut s = sealer(&id, 1);
    let mut o = opener(&id, 1);
    let f0 = s.seal(MediaKind::Audio, b"a").unwrap();
    let f1 = s.seal(MediaKind::Audio, b"b").unwrap();
    let f2 = s.seal(MediaKind::Audio, b"c").unwrap();

    // Delivered 2, 0, 1 -- all accepted.
    assert_eq!(o.open(&f2).unwrap(), b"c");
    assert_eq!(o.open(&f0).unwrap(), b"a");
    assert_eq!(o.open(&f1).unwrap(), b"b");
    // But none a second time.
    assert!(o.open(&f0).is_err());
}

#[test]
fn integrates_with_group_media_root_secret() {
    // Alice seals with the group's exported media root secret; Bob opens using
    // Alice's identity key and the same secret -- the real end-to-end keying.
    let alice = Identity::generate("alice").unwrap();
    let bob = Identity::generate("bob").unwrap();
    let mut alice_group = Group::create(&alice).unwrap();
    let welcome = alice_group
        .add_member(&alice, &bob.new_key_package().unwrap())
        .unwrap()
        .welcome;
    let bob_group = Group::join(&bob, &welcome).unwrap();

    let root_a = alice_group.media_root_secret(&alice).unwrap();
    let root_b = bob_group.media_root_secret(&bob).unwrap();
    assert_eq!(root_a, root_b);

    let group = GroupId([1u8; 32]);
    let mut s = MediaSealer::new(
        &root_a,
        group.clone(),
        DeviceId("alice-1".into()),
        &alice.identity_key(),
        1,
        alice.media_signer().unwrap(),
    )
    .unwrap();
    let mut o = MediaOpener::new(&root_b, &group, &alice.identity_key(), 1).unwrap();

    let frame = s.seal(MediaKind::Audio, b"clear voice frame").unwrap();
    assert_eq!(o.open(&frame).unwrap(), b"clear voice frame");
}
