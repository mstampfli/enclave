//! Phase 7 hardening: the parsers that handle untrusted input (key packages,
//! Welcomes, application messages, commits) must reject malformed bytes with an
//! error, never a panic (ASVS V5/V12). Feeds garbage and truncated real data.

use enclave_crypto::{Group, Identity};

/// Deterministic xorshift, so the fuzz corpus is reproducible without a rand dep.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() & 0xff) as u8).collect()
    }
}

#[test]
fn parsers_reject_garbage_without_panicking() {
    let alice = Identity::generate("alice").unwrap();
    let bob = Identity::generate("bob").unwrap();

    let mut alice_group = Group::create(&alice).unwrap();
    let add = alice_group
        .add_member(&alice, &bob.new_key_package().unwrap())
        .unwrap();
    let mut bob_group = Group::join(&bob, &add.welcome).unwrap();

    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..1000 {
        let len = (rng.next_u64() % 400) as usize;
        let junk = rng.bytes(len);

        // Every untrusted-input entry point must error, never panic. Success is
        // simply that the test process reaches the end.
        let _ = alice_group.add_member(&alice, &junk);
        let _ = Group::join(&bob, &junk);
        let _ = bob_group.decrypt_text(&bob, &junk);
        let _ = bob_group.apply_commit(&bob, &junk);
    }

    // Truncated prefixes of a real Welcome are a classic parser trap.
    for cut in 0..add.welcome.len().min(256) {
        let _ = Group::join(&bob, &add.welcome[..cut]);
    }

    // The group is still usable after all that abuse.
    let sealed = alice_group.encrypt_text(&alice, b"still works").unwrap();
    assert_eq!(
        bob_group.decrypt_text(&bob, &sealed).unwrap().plaintext,
        b"still works"
    );
}
