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
    let welcome = alice_group
        .add_member(&alice, &bob_kp, "bob")
        .expect("add bob")
        .welcome;

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
        .add_member(&alice, &bob.new_key_package().expect("bob kp"), "bob")
        .expect("add bob");

    let two_members = group.safety_number();
    let secret_at_two = group.media_root_secret(&alice).expect("secret@2");

    group
        .add_member(
            &alice,
            &charlie.new_key_package().expect("charlie kp"),
            "charlie",
        )
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

    let result = group.add_member(&alice, &forged, "bob");
    assert!(
        result.is_err(),
        "a tampered key package must not be admitted, got {result:?}"
    );

    // The group must be untouched: still just Alice.
    assert_eq!(group.member_count(), 1);
}

/// A malicious server that returns a DIFFERENT user's (validly signed) key
/// package than the one requested must not be able to slip a ghost member into
/// the group: `add_member` binds the add to the intended identity and rejects a
/// mismatch (fail closed), so the substitution never becomes a member.
#[test]
fn add_member_rejects_a_substituted_identity() {
    let alice = Identity::generate("alice").expect("alice");
    let mallory = Identity::generate("mallory").expect("mallory");
    let mut group = Group::create(&alice).expect("create");

    // We asked for "bob"; the server hands back mallory's valid key package.
    let mallory_kp = mallory.new_key_package().expect("mallory kp");
    let result = group.add_member(&alice, &mallory_kp, "bob");
    assert!(
        result.is_err(),
        "a key package whose identity is not the intended member must be rejected"
    );
    assert_eq!(group.member_count(), 1, "no ghost member was added");

    // The correctly-identified add still works.
    let bob = Identity::generate("bob").expect("bob");
    group
        .add_member(&alice, &bob.new_key_package().expect("bob kp"), "bob")
        .expect("the intended member is added");
    assert_eq!(group.member_count(), 2);
}

/// `key_package_identity` validates a key package and reports the identity it is
/// bound to, so a caller can confirm the server returned the intended peer before
/// making an irreversible membership change (the fork-heal uses this).
#[test]
fn key_package_identity_reports_the_bound_identity() {
    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");
    let bob_kp = bob.new_key_package().expect("bob kp");
    let id = Group::key_package_identity(&alice, &bob_kp).expect("valid package");
    assert_eq!(
        id, "bob",
        "the bound identity is reported for the pre-check"
    );
    // Garbage is rejected, not silently accepted as some identity.
    assert!(Group::key_package_identity(&alice, b"not a key package").is_err());
}

/// A member removed from a group can apply the removing commit and then detect,
/// via `is_member`, that they are no longer in the roster. This underpins the
/// client marking a kicked-from group read-only while keeping its history.
#[test]
fn a_removed_member_can_detect_they_are_out() {
    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");
    let mut ag = Group::create(&alice).expect("create");
    let welcome = ag
        .add_member(&alice, &bob.new_key_package().expect("bob kp"), "bob")
        .expect("add bob")
        .welcome;
    let mut bg = Group::join(&bob, &welcome).expect("bob joins");
    assert!(bg.is_member("bob"), "bob starts as a member");

    // Alice removes bob and hands him the commit (as the server would relay it).
    let bob_key = ag
        .member_keys()
        .into_iter()
        .find(|(l, _)| l == "bob")
        .map(|(_, k)| k)
        .expect("bob is in the roster");
    let commit = ag
        .remove_member(&alice, &bob_key)
        .expect("alice removes bob");

    let applied = bg.apply_commit(&bob, &commit);
    assert!(
        applied.is_ok(),
        "bob can apply the commit removing him: {applied:?}"
    );
    assert!(
        !bg.is_member("bob"),
        "after applying, bob sees he is no longer a member"
    );
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

/// A conversation that fell far behind must catch up on its next message rather
/// than die "generation too far in the future". Alice sends more messages than
/// the openmls default forward distance (1000) while Bob receives none; Bob then
/// decrypts only Alice's latest. This skip must succeed under Enclave's raised
/// recovery-margin tolerance -- it is exactly how a conversation desynced by the
/// old file-chunk-on-the-ratchet design heals once both sides run the fix.
#[test]
fn a_backlogged_receiver_skips_forward_to_the_latest_message() {
    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");

    let mut alice_group = Group::create(&alice).expect("create");
    let welcome = alice_group
        .add_member(&alice, &bob.new_key_package().expect("bob kp"), "bob")
        .expect("add bob")
        .welcome;
    let mut bob_group = Group::join(&bob, &welcome).expect("bob joins");

    // Alice sends 1500 messages (past the 1000 default) that Bob never sees,
    // then one more that he does.
    let gap = 1500u32;
    for i in 0..gap {
        let _ = alice_group
            .encrypt_text(&alice, format!("skipped {i}").as_bytes())
            .expect("alice encrypts");
    }
    let latest = alice_group
        .encrypt_text(&alice, b"catch up to me")
        .expect("alice encrypts latest");

    // Bob, still at generation 0, must ratchet forward past the gap and decrypt.
    let got = bob_group
        .decrypt_text(&bob, &latest)
        .expect("backlogged receiver heals and decrypts the latest message");
    assert_eq!(got.plaintext, b"catch up to me");
}

/// A conversation whose application-message ratchet desynced heals when the stuck
/// member commits a self-update (rekey): the new epoch resets both members'
/// message ratchets, so they talk again both ways regardless of how far behind
/// one had fallen. The rekey commit rides the separate handshake ratchet, so the
/// peer can apply it even while application messages are undecryptable.
#[test]
fn a_rekey_heals_a_desynced_conversation() {
    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");

    let mut alice_group = Group::create(&alice).expect("create");
    let welcome = alice_group
        .add_member(&alice, &bob.new_key_package().expect("bob kp"), "bob")
        .expect("add bob")
        .welcome;
    let mut bob_group = Group::join(&bob, &welcome).expect("bob joins");

    // Bob races his application ratchet far ahead; Alice sees none of it, so she
    // is desynced on Bob's ratchet (this is the file-chunk desync in miniature).
    for i in 0..50 {
        let _ = bob_group
            .encrypt_text(&bob, format!("unseen {i}").as_bytes())
            .unwrap();
    }

    // Alice (the stuck receiver) rekeys; her commit is a handshake message Bob
    // can still apply even though his application messages are ahead.
    let commit = alice_group.rekey(&alice).expect("alice rekeys");
    bob_group
        .apply_commit(&bob, &commit)
        .expect("bob applies the rekey");

    // New epoch: both directions decrypt again, from generation 0.
    let m1 = bob_group
        .encrypt_text(&bob, b"can you hear me now")
        .unwrap();
    assert_eq!(
        alice_group.decrypt_text(&alice, &m1).unwrap().plaintext,
        b"can you hear me now"
    );
    let m2 = alice_group.encrypt_text(&alice, b"loud and clear").unwrap();
    assert_eq!(
        bob_group.decrypt_text(&bob, &m2).unwrap().plaintext,
        b"loud and clear"
    );

    // And they still agree on the group (same epoch, same secret).
    assert_eq!(alice_group.safety_number(), bob_group.safety_number());
}

/// Open-join foundation: a newcomer self-joins by external commit using only the
/// group's exported public GroupInfo -- no member online, no Welcome, no admin
/// signing. Alice creates a group and publishes its GroupInfo; Charlie (a fresh
/// identity Alice never added) self-joins; Alice applies Charlie's commit like
/// any other; and they then exchange an end-to-end message, proving they share
/// the same group secret.
#[test]
fn a_newcomer_self_joins_by_external_commit_and_shares_the_key() {
    let alice = Identity::generate("alice").expect("alice");
    let charlie = Identity::generate("charlie").expect("charlie");

    let mut alice_group = Group::create(&alice).expect("create");
    assert_eq!(alice_group.member_count(), 1);

    // Alice publishes the group's public state (as the relay would store it).
    let group_info = alice_group.export_group_info(&alice).expect("export info");

    // Charlie self-joins from the bytes alone -- Alice is not involved yet.
    let (mut charlie_group, commit) =
        Group::join_by_external_commit(&charlie, &group_info).expect("external join");

    // Alice catches up by applying Charlie's external commit (same path as an add).
    alice_group
        .apply_commit(&alice, &commit)
        .expect("apply external commit");

    assert_eq!(alice_group.member_count(), 2);
    assert_eq!(charlie_group.member_count(), 2);

    // The real proof they share the key: a message each way opens on the other side.
    let sealed = alice_group
        .encrypt_text(&alice, b"welcome, charlie")
        .expect("encrypt");
    assert_eq!(
        charlie_group
            .decrypt_text(&charlie, &sealed)
            .expect("decrypt")
            .plaintext,
        b"welcome, charlie"
    );
    let back = charlie_group
        .encrypt_text(&charlie, b"thanks")
        .expect("encrypt back");
    assert_eq!(
        alice_group
            .decrypt_text(&alice, &back)
            .expect("decrypt back")
            .plaintext,
        b"thanks"
    );
}

/// A tampered GroupInfo blob is rejected -- an external join cannot be bootstrapped
/// from forged public state.
#[test]
fn external_join_rejects_a_tampered_group_info() {
    let alice = Identity::generate("alice").expect("alice");
    let mallory = Identity::generate("mallory").expect("mallory");
    let alice_group = Group::create(&alice).expect("create");
    let mut info = alice_group.export_group_info(&alice).expect("export");
    // Flip bytes in the middle (the signed body), not the length prefix.
    let mid = info.len() / 2;
    info[mid] ^= 0xff;
    assert!(Group::join_by_external_commit(&mallory, &info).is_err());
}
