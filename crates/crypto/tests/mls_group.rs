//! Phase 1 verification: two identities form an MLS group by exchanging only
//! serialized bytes (as they would through the untrusted server), agree on the
//! media root secret and the safety number, and reject a forged key package.

use enclave_crypto::{Group, Identity};

/// The happy path: Alice creates a group, adds Bob using his published key
/// package bytes, and hands him the Welcome bytes. Both sides then derive the
/// identical media root secret and the identical safety number.
#[test]
fn two_members_agree_on_secret_and_safety_number() {
    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");

    // Bob publishes a key package; only bytes cross the (simulated) wire.
    let bob_kp = bob.new_key_package().expect("bob key package");

    let mut alice_group = Group::create(&alice).expect("create group");
    let welcome = alice_group.add_member(&alice, &bob_kp).expect("add bob");

    let bob_group = Group::join(&bob, &welcome).expect("bob joins");

    let alice_secret = alice_group.media_root_secret(&alice).expect("alice secret");
    let bob_secret = bob_group.media_root_secret(&bob).expect("bob secret");

    assert_eq!(alice_secret.len(), 32);
    assert_eq!(
        alice_secret, bob_secret,
        "both members must derive the same media root secret"
    );
    assert_eq!(
        alice_group.safety_number(),
        bob_group.safety_number(),
        "honest members must see the same safety number"
    );
    assert_eq!(alice_group.member_count(), 2);
    assert_eq!(bob_group.member_count(), 2);
}

/// A member silently inserted by the server changes the safety number, so two
/// honest members comparing it out-of-band would detect the ghost. Here we
/// prove the number is sensitive to membership: adding a third member changes
/// it, and the derived secret rekeys to a fresh value.
#[test]
fn safety_number_and_secret_change_when_membership_changes() {
    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");
    let charlie = Identity::generate("charlie").expect("charlie");

    let mut group = Group::create(&alice).expect("create");
    group
        .add_member(&alice, &bob.new_key_package().expect("bob kp"))
        .expect("add bob");

    let two_members = group.safety_number();
    let secret_at_two = group.media_root_secret(&alice).expect("secret@2");

    group
        .add_member(&alice, &charlie.new_key_package().expect("charlie kp"))
        .expect("add charlie");

    let three_members = group.safety_number();
    let secret_at_three = group.media_root_secret(&alice).expect("secret@3");

    assert_ne!(
        two_members, three_members,
        "adding a member must change the safety number"
    );
    assert_ne!(
        secret_at_two, secret_at_three,
        "adding a member must rekey the media root secret (post-compromise security)"
    );
    assert_eq!(group.member_count(), 3);
}

/// A forged / tampered key package must be rejected before it can become a
/// member -- this is the defense against a server (or attacker) trying to admit
/// an identity it does not actually control.
#[test]
fn tampered_key_package_is_rejected() {
    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");

    let mut group = Group::create(&alice).expect("create");

    let mut forged = bob.new_key_package().expect("bob kp");
    // Corrupt the trailing bytes (the signature region) so the key package no
    // longer verifies under Bob's identity key.
    let last = forged.len() - 1;
    forged[last] ^= 0xff;

    let result = group.add_member(&alice, &forged);
    assert!(
        result.is_err(),
        "a tampered key package must not be admitted, got {result:?}"
    );

    // The group must be untouched: still just Alice.
    assert_eq!(group.member_count(), 1);
}

/// Two independently generated identities must have distinct identity keys and
/// therefore distinct-looking single-member groups.
#[test]
fn distinct_identities_have_distinct_keys() {
    let a = Identity::generate("same-name").expect("a");
    let b = Identity::generate("same-name").expect("b");
    assert_ne!(
        a.identity_key(),
        b.identity_key(),
        "identity is the key, not the name"
    );
}
