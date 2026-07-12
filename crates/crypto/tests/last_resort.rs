//! One published (last-resort) key package can be reused to join unlimited
//! groups: openmls keeps the private key material for last-resort packages, so a
//! peer stays addable without any single-use pool. This proves our
//! `new_key_package` + capabilities produce a genuinely reusable key package.

use enclave_crypto::{Group, Identity};

#[test]
fn one_key_package_joins_multiple_groups() {
    let alice = Identity::generate("alice").unwrap();
    let bob = Identity::generate("bob").unwrap();

    // Bob publishes exactly ONE key package.
    let bob_kp = bob.new_key_package().unwrap();

    // Alice adds Bob to three separate groups, each time reusing the SAME key
    // package. Every join must succeed -- that is the last-resort property.
    let mut groups = Vec::new();
    for _ in 0..3 {
        let mut alice_g = Group::create(&alice).unwrap();
        let add = alice_g.add_member(&alice, &bob_kp).unwrap();
        let bob_g = Group::join(&bob, &add.welcome).unwrap();
        groups.push((alice_g, bob_g));
    }

    // Every group works end to end and independently: Alice sends, Bob decrypts.
    for (i, (alice_g, bob_g)) in groups.iter_mut().enumerate() {
        let msg = format!("hello group {i}");
        let sealed = alice_g.encrypt_text(&alice, msg.as_bytes()).unwrap();
        let got = bob_g.decrypt_text(&bob, &sealed).unwrap();
        assert_eq!(got.plaintext, msg.as_bytes());
    }
}
