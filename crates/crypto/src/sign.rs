//! Detached Ed25519 signatures over a device's long-term **identity** key, for
//! signing application-level operations that must be attributable to a specific
//! member and unforgeable by the untrusted relay -- e.g. every entry in a
//! workspace op-log (create/delete a channel, grant/revoke a role, add/remove a
//! member).
//!
//! The key is the same Ed25519 identity key the MLS roster and safety number
//! bind to a member, so "this op was signed by Alice" means the same Alice a peer
//! already verified. Signatures are **domain-separated** by a global context
//! ([`OP_SIG_CONTEXT`]) plus a caller-supplied per-op `context` tag, so an op
//! signature can never be replayed as an MLS handshake, a media-frame signature,
//! or a different op type made with the same key.
//!
//! PRIMITIVE: the single signer/verifier for identity-attributed operations.
//! Never hand-roll Ed25519 signing elsewhere; sign via [`crate::Identity::sign_op`]
//! and verify via [`verify_op`]. Vetted building blocks only (ed25519-dalek
//! `verify_strict`, which rejects malleable signatures and small-order keys).

use ed25519_dalek::VerifyingKey;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;

use crate::CryptoError;

/// Global domain tag: separates op signatures from every other use of the
/// identity key (MLS handshakes, media frames). Bumping the version invalidates
/// all prior op signatures by construction.
pub const OP_SIG_CONTEXT: &[u8] = b"enclave/op-sig/v1";

/// Build the exact bytes that get signed: the global tag, then the length-framed
/// per-op `context`, then the message. Length-framing `context` stops a crafted
/// `(context, msg)` split from colliding with a different `(context', msg')`.
fn signing_input(context: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(OP_SIG_CONTEXT.len() + 4 + context.len() + msg.len());
    m.extend_from_slice(OP_SIG_CONTEXT);
    m.extend_from_slice(&(context.len() as u32).to_le_bytes());
    m.extend_from_slice(context);
    m.extend_from_slice(msg);
    m
}

/// Sign `msg` under `context` with `keypair` (a device's identity keypair).
/// Crate-internal; callers reach it through [`crate::Identity::sign_op`].
pub(crate) fn sign_detached(
    keypair: &SignatureKeyPair,
    context: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    keypair
        .sign(&signing_input(context, msg))
        .map_err(|_| CryptoError::Identity("op signing failed".into()))
}

/// Verify that `sig` is `identity_public`'s signature over `(context, msg)`.
/// Returns false -- never errors -- on any malformed input, so a hostile op is
/// simply rejected. Uses `verify_strict` (rejects non-canonical signatures and
/// small-order keys).
pub fn verify_op(identity_public: &[u8], context: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk_bytes) = <[u8; 32]>::try_from(identity_public) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    key.verify_strict(&signing_input(context, msg), &sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use crate::Identity;

    #[test]
    fn a_signed_op_verifies_only_for_its_signer_context_and_message() {
        let alice = Identity::generate("alice").unwrap();
        let bob = Identity::generate("bob").unwrap();
        let ctx = b"ws-op/channel-create/v1";
        let msg = b"create #general";

        let sig = alice.sign_op(ctx, msg).unwrap();
        assert!(super::verify_op(&alice.identity_key(), ctx, msg, &sig));

        // Wrong signer, wrong context, wrong message, tampered signature all fail.
        assert!(!super::verify_op(&bob.identity_key(), ctx, msg, &sig));
        assert!(!super::verify_op(
            &alice.identity_key(),
            b"ws-op/other/v1",
            msg,
            &sig
        ));
        assert!(!super::verify_op(
            &alice.identity_key(),
            ctx,
            b"create #dev",
            &sig
        ));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!super::verify_op(&alice.identity_key(), ctx, msg, &bad));
    }

    #[test]
    fn length_framing_stops_context_message_boundary_collision() {
        let alice = Identity::generate("alice").unwrap();
        // ("ab","c") and ("a","bc") must not produce interchangeable signatures.
        let sig = alice.sign_op(b"ab", b"c").unwrap();
        assert!(super::verify_op(&alice.identity_key(), b"ab", b"c", &sig));
        assert!(!super::verify_op(&alice.identity_key(), b"a", b"bc", &sig));
    }

    #[test]
    fn garbage_inputs_are_rejected_not_panicked() {
        assert!(!super::verify_op(&[0u8; 10], b"c", b"m", &[0u8; 64]));
        assert!(!super::verify_op(&[0u8; 32], b"c", b"m", &[0u8; 10]));
    }
}
