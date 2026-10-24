//! Enclave speaks exactly one MLS ciphersuite, and refuses every other one at
//! ingress, before openmls does any crypto in it. openmls's provider ships all
//! suites (P-256 included, whose crypto-bigint arithmetic carries
//! RUSTSEC-2026-0387), so an attacker who builds a group in a foreign suite must
//! not be able to make an Enclave member generate or use keys in it.
//!
//! Every hostile input here is genuinely built by the attacker with openmls, not
//! hand-crafted bytes, except the Welcome: a P-256 Welcome to our member cannot
//! be produced honestly (our only key packages are X25519), so the attack is a
//! real Welcome with its suite field rewritten -- what a malicious inviter would
//! have to send.

use enclave_crypto::{CryptoError, Group, Identity, CIPHERSUITE};
use openmls::prelude::{tls_codec::Serialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const FOREIGN: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

/// An attacker's own openmls stack, signing in the foreign suite.
struct Mallory {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Mallory {
    fn new(name: &str) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(FOREIGN.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Self {
            provider,
            signer,
            credential,
        }
    }
}

fn assert_refused_as_foreign(err: &CryptoError) {
    assert!(
        err.to_string().contains("unsupported ciphersuite"),
        "must be refused by the ciphersuite guard, got: {err}"
    );
}

#[test]
fn external_join_refuses_a_foreign_suite_group() {
    let mallory = Mallory::new("mallory");
    let group = MlsGroup::builder()
        .ciphersuite(FOREIGN)
        .use_ratchet_tree_extension(true)
        .build(
            &mallory.provider,
            &mallory.signer,
            mallory.credential.clone(),
        )
        .unwrap();
    let group_info = group
        .export_group_info(mallory.provider.crypto(), &mallory.signer, true)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();

    let victim = Identity::generate("victim").unwrap();
    let err = Group::join_by_external_commit(&victim, &group_info)
        .err()
        .expect("a P-256 GroupInfo must not be joinable");
    assert!(matches!(err, CryptoError::Join(_)), "{err}");
    assert_refused_as_foreign(&err);
}

#[test]
fn add_member_refuses_a_foreign_suite_key_package() {
    let mallory = Mallory::new("bob");
    let foreign_kp = KeyPackage::builder()
        .build(
            FOREIGN,
            &mallory.provider,
            &mallory.signer,
            mallory.credential,
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap();

    let alice = Identity::generate("alice").unwrap();
    let mut group = Group::create(&alice).unwrap();
    let err = group
        .add_member(&alice, &foreign_kp, "bob")
        .expect_err("a P-256 key package must not be addable");
    assert!(matches!(err, CryptoError::KeyPackageInvalid(_)), "{err}");
    assert_refused_as_foreign(&err);
    assert_eq!(group.member_count(), 1, "nothing may have been added");
}

#[test]
fn welcome_rewritten_to_a_foreign_suite_is_refused() {
    let alice = Identity::generate("alice").unwrap();
    let bob = Identity::generate("bob").unwrap();
    let mut group = Group::create(&alice).unwrap();
    let mut welcome = group
        .add_member(&alice, &bob.new_key_package().unwrap(), "bob")
        .unwrap()
        .welcome;

    // MLSMessage = version(u16) wire_format(u16) Welcome{ cipher_suite(u16) ..}.
    let ours = u16::from(CIPHERSUITE).to_be_bytes();
    assert_eq!(welcome[4..6], ours, "suite field must sit at bytes 4..6");
    welcome[4..6].copy_from_slice(&u16::from(FOREIGN).to_be_bytes());

    let err = Group::join(&bob, &welcome)
        .err()
        .expect("a Welcome in a foreign suite must not be joinable");
    assert!(matches!(err, CryptoError::Join(_)), "{err}");
}

/// Control: the guard is not simply refusing everything.
#[test]
fn our_own_suite_still_joins_by_external_commit() {
    let alice = Identity::generate("alice").unwrap();
    let group = Group::create(&alice).unwrap();
    let info = group.export_group_info(&alice).unwrap();
    let carol = Identity::generate("carol").unwrap();
    Group::join_by_external_commit(&carol, &info).expect("our suite must join");
}
