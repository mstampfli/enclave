//! Phase 4: multi-party groups and rekey on join/leave.
//!
//! Proves that a third member joins and all three agree on the secret and
//! safety number; that adding and removing members rekeys the group; and that a
//! removed member is cryptographically cut off from the new epoch's media.

use enclave_crypto::{Group, Identity, MediaOpener, MediaSealer};
use enclave_protocol::{DeviceId, GroupId, MediaKind};

const GID: GroupId = GroupId([4u8; 32]);

#[test]
fn three_members_agree_then_rekey_on_leave() {
    let alice = Identity::generate("alice").unwrap();
    let bob = Identity::generate("bob").unwrap();
    let charlie = Identity::generate("charlie").unwrap();

    // Alice creates, adds Bob (2 members: no other existing member to update).
    let mut alice_group = Group::create(&alice).unwrap();
    let add_bob = alice_group
        .add_member(&alice, &bob.new_key_package().unwrap())
        .unwrap();
    let mut bob_group = Group::join(&bob, &add_bob.welcome).unwrap();

    // Alice adds Charlie (3 members): Bob, an existing member, applies the
    // commit to advance to the same epoch.
    let add_charlie = alice_group
        .add_member(&alice, &charlie.new_key_package().unwrap())
        .unwrap();
    bob_group.apply_commit(&bob, &add_charlie.commit).unwrap();
    let mut charlie_group = Group::join(&charlie, &add_charlie.welcome).unwrap();

    // All three agree on the media root secret and the safety number.
    let s_alice = alice_group.media_root_secret(&alice).unwrap();
    let s_bob = bob_group.media_root_secret(&bob).unwrap();
    let s_charlie = charlie_group.media_root_secret(&charlie).unwrap();
    assert_eq!(s_alice, s_bob);
    assert_eq!(s_bob, s_charlie);
    assert_eq!(alice_group.safety_number(), bob_group.safety_number());
    assert_eq!(bob_group.safety_number(), charlie_group.safety_number());
    assert_eq!(alice_group.member_count(), 3);

    let secret_with_bob = alice_group.media_root_secret(&alice).unwrap();

    // Alice removes Bob; Charlie applies the removal commit.
    let removal = alice_group
        .remove_member(&alice, &bob.identity_key())
        .unwrap();
    charlie_group.apply_commit(&charlie, &removal).unwrap();

    let s_alice_after = alice_group.media_root_secret(&alice).unwrap();
    let s_charlie_after = charlie_group.media_root_secret(&charlie).unwrap();
    assert_eq!(alice_group.member_count(), 2);
    assert_eq!(
        s_alice_after, s_charlie_after,
        "remaining members rekey together"
    );
    assert_ne!(
        s_alice_after, secret_with_bob,
        "removal rekeys the group (forward secrecy)"
    );

    // Bob is stuck on the old epoch: his secret is not the new one.
    let s_bob_stale = bob_group.media_root_secret(&bob).unwrap();
    assert_ne!(
        s_bob_stale, s_alice_after,
        "removed member cannot derive the new epoch secret"
    );

    // Concretely: media Alice seals under the new epoch is unreadable to Bob but
    // readable to Charlie.
    let new_epoch = 3;
    let mut sealer = MediaSealer::new(
        &s_alice_after,
        GID,
        DeviceId("alice-1".into()),
        &alice.identity_key(),
        new_epoch,
    )
    .unwrap();
    let frame = sealer
        .seal(MediaKind::Audio, b"after bob was removed")
        .unwrap();

    let mut bob_opener =
        MediaOpener::new(&s_bob_stale, &GID, &alice.identity_key(), new_epoch).unwrap();
    assert!(
        bob_opener.open(&frame).is_err(),
        "removed member cannot open post-removal media"
    );

    let mut charlie_opener =
        MediaOpener::new(&s_charlie_after, &GID, &alice.identity_key(), new_epoch).unwrap();
    assert_eq!(
        charlie_opener.open(&frame).unwrap(),
        b"after bob was removed"
    );
}
