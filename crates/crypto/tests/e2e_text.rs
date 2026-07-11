//! Phase 2 (crypto layer): E2E text over MLS. Proves a relayed text message
//! decrypts for a group member, that the relayed bytes do not contain the
//! plaintext (a relay sees only ciphertext), and that tampering is rejected.

use enclave_crypto::{Group, Identity};

/// True if `haystack` contains `needle` as a contiguous byte subsequence.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn two_member_group() -> (Identity, Group, Identity, Group) {
    let alice = Identity::generate("alice").expect("alice");
    let bob = Identity::generate("bob").expect("bob");
    let mut alice_group = Group::create(&alice).expect("create");
    let welcome = alice_group
        .add_member(&alice, &bob.new_key_package().expect("bob kp"))
        .expect("add bob")
        .welcome;
    let bob_group = Group::join(&bob, &welcome).expect("bob joins");
    (alice, alice_group, bob, bob_group)
}

#[test]
fn text_round_trips_and_relayed_bytes_are_opaque() {
    let (alice, mut alice_group, bob, mut bob_group) = two_member_group();

    let plaintext = b"meet at the docks at midnight";
    let sealed = alice_group
        .encrypt_text(&alice, plaintext)
        .expect("encrypt");

    // A relay forwarding these bytes must not be able to see the plaintext.
    assert!(
        !contains(&sealed, plaintext),
        "relayed ciphertext must not contain the plaintext"
    );

    let received = bob_group.decrypt_text(&bob, &sealed).expect("decrypt");
    assert_eq!(received.plaintext, plaintext);
    // MLS authenticates the sender as Alice.
    assert_eq!(received.sender, b"alice");
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let (alice, mut alice_group, bob, mut bob_group) = two_member_group();

    let mut sealed = alice_group
        .encrypt_text(&alice, b"authentic message")
        .expect("encrypt");
    // Flip a byte in the ciphertext body.
    let mid = sealed.len() / 2;
    sealed[mid] ^= 0xff;

    let result = bob_group.decrypt_text(&bob, &sealed);
    assert!(
        result.is_err(),
        "a tampered ciphertext must not decrypt, got {result:?}"
    );
}

#[test]
fn an_outsider_cannot_decrypt() {
    let (alice, mut alice_group, _bob, _bob_group) = two_member_group();

    // Mallory is a valid identity but not a member of Alice & Bob's group.
    let mallory = Identity::generate("mallory").expect("mallory");
    let mut mallory_group = Group::create(&mallory).expect("mallory group");

    let sealed = alice_group.encrypt_text(&alice, b"secret").expect("encrypt");
    let result = mallory_group.decrypt_text(&mallory, &sealed);
    assert!(
        result.is_err(),
        "a non-member must not decrypt the group's message, got {result:?}"
    );
}
