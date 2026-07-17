//! An MLS group == one call or one DM. Wraps `openmls::MlsGroup` with the small
//! surface Enclave needs: create, add a member (validating their key package),
//! join from a Welcome, derive the media root secret, and compute the
//! out-of-band safety number.
//!
//! Wire crossings are bytes: key packages and Welcomes are serialized here and
//! travel through the (untrusted) server, which only ever sees these opaque
//! blobs -- it holds no group state and no keys.

use openmls::prelude::{tls_codec::*, *};
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};

use crate::identity::Identity;
use crate::CryptoError;

/// Label bound into the exported media root secret. Every member of an epoch
/// must use the identical label + context + length to derive the same secret.
const MEDIA_ROOT_LABEL: &str = "enclave media root";
/// Media root secret length in bytes (Phase 3 derives per-sender keys from it).
const MEDIA_ROOT_LEN: usize = 32;

/// How many past message keys a receiver retains for late/reordered messages.
/// Kept at the openmls default: retaining fewer past keys is better for forward
/// secrecy, and text/handshake messages arrive in order over the reliable
/// transport, so reordering is minimal.
const OUT_OF_ORDER_TOLERANCE: u32 = 5;

/// How far ahead of its last-decrypted message a sender ratchet will skip to
/// decrypt the next one. openmls defaults to 1000; we raise it so a conversation
/// that fell behind -- a peer offline across many messages, or (before file
/// bytes were moved off the ratchet) a large file transfer whose chunks were
/// never decrypted -- catches up on the next real message instead of dying with
/// "generation too far in the future".
///
/// This is a bounded recovery margin, not a hot path: bulk file data no longer
/// rides the message ratchet at all (see `crypto::seal_chunk`), so legitimate
/// traffic never approaches it. The bound matters because a group member can
/// force up to this many key derivations with a single crafted, never-decrypting
/// message (it names a far-future generation, openmls ratchets forward to it,
/// then decryption fails). 16384 is a few milliseconds of KDF and well under a
/// megabyte of transient state per such message -- negligible, and the message
/// rate is capped server-side -- while healing any realistic backlog.
const MAX_FORWARD_DISTANCE: u32 = 16384;

/// The join configuration every Enclave group uses: carry the ratchet tree in
/// Welcomes, pad every message to a fixed multiple (so ciphertext length leaks
/// nothing), and use the recovery-margin ratchet tolerance above. One source of
/// truth, applied identically on create, join, and load, so no member's config
/// can drift from the others'.
fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .padding_size(crate::PADDING)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            OUT_OF_ORDER_TOLERANCE,
            MAX_FORWARD_DISTANCE,
        ))
        .build()
}

/// An MLS group instance held by one member.
pub struct Group {
    inner: MlsGroup,
}

impl Group {
    /// Create a new group owned by `owner`. `owner` is its first member.
    pub fn create(owner: &Identity) -> Result<Self, CryptoError> {
        let inner = MlsGroup::builder()
            .ciphersuite(crate::CIPHERSUITE)
            // Carry the ratchet tree in Welcomes so joiners need no side channel.
            .use_ratchet_tree_extension(true)
            // Pad every application message up to a multiple of PADDING, so the
            // ciphertext length says nothing about what was typed.
            .padding_size(crate::PADDING)
            // Recovery margin so a backlogged conversation self-heals (see
            // MAX_FORWARD_DISTANCE) instead of dying "too far in the future".
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                OUT_OF_ORDER_TOLERANCE,
                MAX_FORWARD_DISTANCE,
            ))
            .build(&owner.provider, &owner.signer, owner.credential.clone())
            .map_err(|e| CryptoError::GroupCreate(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Add a member from their published key package bytes.
    ///
    /// The key package signature is validated first, so a forged or tampered
    /// identity is rejected ([`CryptoError::KeyPackageInvalid`]) before it can
    /// become a member. The commit is merged immediately, advancing this member
    /// to the new epoch, and both artifacts are returned in a [`MemberAdd`]:
    /// deliver `welcome` to the new member and fan `commit` out to every
    /// *existing* member so they advance to the same epoch via [`apply_commit`].
    /// (In a 2-member group there is no other existing member, so `commit` is
    /// simply unused.)
    ///
    /// [`apply_commit`]: Group::apply_commit
    pub fn add_member(
        &mut self,
        owner: &Identity,
        key_package_bytes: &[u8],
        expected_identity: &str,
    ) -> Result<MemberAdd, CryptoError> {
        let key_package_in = KeyPackageIn::tls_deserialize(&mut &key_package_bytes[..])
            .map_err(|e| CryptoError::KeyPackage(format!("deserialize: {e}")))?;
        let key_package = key_package_in
            .validate(owner.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| CryptoError::KeyPackageInvalid(e.to_string()))?;

        // SECURITY (bind the add to the INTENDED peer): `validate` only proves the
        // package is self-consistently signed by its own credential -- NOT that it
        // is the person we asked for. A malicious (or buggy) server that returns a
        // different user's validly-signed key package could otherwise silently
        // insert a ghost member. Reject any identity mismatch: fail closed, never
        // add whoever the server handed back.
        let got =
            String::from_utf8_lossy(key_package.leaf_node().credential().serialized_content());
        if got != expected_identity {
            return Err(CryptoError::KeyPackageInvalid(format!(
                "key package identity {got:?} does not match the intended member {expected_identity:?}"
            )));
        }

        let (commit, welcome, _group_info) = self
            .inner
            .add_members(&owner.provider, &owner.signer, &[key_package])
            .map_err(|e| CryptoError::AddMember(e.to_string()))?;

        self.inner
            .merge_pending_commit(&owner.provider)
            .map_err(|e| CryptoError::AddMember(format!("merge: {e}")))?;

        Ok(MemberAdd {
            commit: commit
                .tls_serialize_detached()
                .map_err(|e| CryptoError::Serialize(e.to_string()))?,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|e| CryptoError::Serialize(e.to_string()))?,
        })
    }

    /// Apply a relayed commit produced by another member's add/remove, advancing
    /// this member to the new epoch. Rejects anything that is not a commit.
    pub fn apply_commit(
        &mut self,
        member: &Identity,
        commit_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(|e| CryptoError::Commit(format!("deserialize: {e}")))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|e| CryptoError::Commit(format!("not a protocol message: {e}")))?;
        let processed = self
            .inner
            .process_message(&member.provider, protocol_message)
            .map_err(|e| CryptoError::Commit(e.to_string()))?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.inner
                    .merge_staged_commit(&member.provider, *staged)
                    .map_err(|e| CryptoError::Commit(format!("merge: {e}")))?;
                Ok(())
            }
            _ => Err(CryptoError::Commit("expected a commit message".into())),
        }
    }

    /// Validate a key package and return the identity it is bound to, WITHOUT
    /// adding it to any group. Lets a caller confirm the server returned the
    /// INTENDED peer's package before making a membership change it cannot easily
    /// undo (e.g. the DM fork-heal, which removes then re-adds).
    pub fn key_package_identity(
        owner: &Identity,
        key_package_bytes: &[u8],
    ) -> Result<String, CryptoError> {
        let kp_in = KeyPackageIn::tls_deserialize(&mut &key_package_bytes[..])
            .map_err(|e| CryptoError::KeyPackage(format!("deserialize: {e}")))?;
        let kp = kp_in
            .validate(owner.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| CryptoError::KeyPackageInvalid(e.to_string()))?;
        Ok(String::from_utf8_lossy(kp.leaf_node().credential().serialized_content()).into_owned())
    }

    /// Rekey the group by committing a self-update: start a fresh epoch whose
    /// secret tree resets every member's message ratchets to generation 0. Used
    /// to HEAL a conversation whose application-message ratchet desynced (a
    /// receiver fell so far behind that openmls rejects new messages as "too far
    /// in the future"). The returned commit is a handshake message on the
    /// SEPARATE handshake ratchet -- which the desync never touches -- so the peer
    /// can still apply it via [`apply_commit`] even while application messages are
    /// undecryptable, and both sides then talk again in the new epoch. Merges our
    /// own side immediately; the caller fans the commit out to the other members.
    ///
    /// [`apply_commit`]: Group::apply_commit
    pub fn rekey(&mut self, member: &Identity) -> Result<Vec<u8>, CryptoError> {
        let bundle = self
            .inner
            .self_update(
                &member.provider,
                &member.signer,
                LeafNodeParameters::default(),
            )
            .map_err(|e| CryptoError::Commit(format!("self-update: {e}")))?;
        self.inner
            .merge_pending_commit(&member.provider)
            .map_err(|e| CryptoError::Commit(format!("merge self-update: {e}")))?;
        bundle
            .into_commit()
            .tls_serialize_detached()
            .map_err(|e| CryptoError::Serialize(e.to_string()))
    }

    /// Remove the member whose identity key is `target_identity_key`, rekeying
    /// the group so the removed member cannot read the new epoch (forward
    /// secrecy). Returns the commit to fan out to the remaining members.
    pub fn remove_member(
        &mut self,
        remover: &Identity,
        target_identity_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let leaf = self
            .inner
            .members()
            .find(|m| m.signature_key.as_slice() == target_identity_key)
            .map(|m| m.index)
            .ok_or_else(|| CryptoError::RemoveMember("target is not a member".into()))?;

        let (commit, _welcome, _group_info) = self
            .inner
            .remove_members(&remover.provider, &remover.signer, &[leaf])
            .map_err(|e| CryptoError::RemoveMember(e.to_string()))?;

        self.inner
            .merge_pending_commit(&remover.provider)
            .map_err(|e| CryptoError::RemoveMember(format!("merge: {e}")))?;

        commit
            .tls_serialize_detached()
            .map_err(|e| CryptoError::Serialize(e.to_string()))
    }

    /// Join a group from a serialized Welcome. `joiner` must be the identity
    /// whose key package was consumed to produce this Welcome (its provider
    /// holds the matching private keys).
    pub fn join(joiner: &Identity, welcome_bytes: &[u8]) -> Result<Self, CryptoError> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| CryptoError::Join(format!("deserialize: {e}")))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(CryptoError::Join("message was not a Welcome".into())),
        };

        // A joiner must pad exactly like the creator, or its messages would be
        // the only ones in the group whose length leaks; it also adopts the same
        // recovery-margin ratchet tolerance as every other member.
        let config = join_config();

        let staged = StagedWelcome::new_from_welcome(&joiner.provider, &config, welcome, None)
            .map_err(|e| CryptoError::Join(e.to_string()))?;
        let inner = staged
            .into_group(&joiner.provider)
            .map_err(|e| CryptoError::Join(format!("into_group: {e}")))?;

        Ok(Self { inner })
    }

    /// This group's MLS-internal id, used to reload it from persisted storage.
    pub fn mls_group_id(&self) -> Vec<u8> {
        self.inner.group_id().as_slice().to_vec()
    }

    /// Delete this group's state from the provider storage. Call when tearing a
    /// conversation's channel down (leaving, or being removed) so that a later
    /// rejoin -- a fresh Welcome for the SAME group id -- can recreate the group
    /// instead of failing with "a group with this GroupId already exists". The
    /// retained chat history lives outside MLS, so this loses no messages.
    pub fn delete(mut self, member: &Identity) -> Result<(), CryptoError> {
        self.inner
            .delete(member.provider.storage())
            .map_err(|e| CryptoError::Commit(format!("delete group state: {e}")))
    }

    /// Reload a group from `member`'s (already restored) MLS storage by its
    /// MLS-internal id. Used to bring conversations back after a restart.
    pub fn load(member: &Identity, mls_group_id: &[u8]) -> Result<Self, CryptoError> {
        let group_id = GroupId::from_slice(mls_group_id);
        let mut inner = MlsGroup::load(member.provider.storage(), &group_id)
            .map_err(|e| CryptoError::Join(format!("load: {e}")))?
            .ok_or_else(|| CryptoError::Join("group not present in storage".into()))?;
        // Upgrade a group created before the recovery-margin tolerance existed,
        // so a conversation that desynced under the old (default) forward
        // distance heals on its next message. Best-effort: the in-memory config
        // is applied even if persisting it fails, and a failure must never block
        // loading a conversation.
        let _ = inner.set_configuration(member.provider.storage(), &join_config());
        Ok(Self { inner })
    }

    /// Derive this epoch's media root secret. Every member of the same epoch
    /// derives the identical value; Phase 3 derives per-sender AEAD keys from
    /// it. `member` supplies the crypto backend.
    pub fn media_root_secret(&self, member: &Identity) -> Result<Vec<u8>, CryptoError> {
        self.inner
            .export_secret(
                member.provider.crypto(),
                MEDIA_ROOT_LABEL,
                &[],
                MEDIA_ROOT_LEN,
            )
            .map_err(|e| CryptoError::Export(e.to_string()))
    }

    /// The human-verifiable safety number over the sorted set of member
    /// identity keys. Two honest members compute the same number; a member
    /// silently inserted by the server changes it, so comparing it out-of-band
    /// detects a ghost-member attack.
    pub fn safety_number(&self) -> SafetyNumber {
        let mut keys: Vec<Vec<u8>> = self.inner.members().map(|m| m.signature_key).collect();
        keys.sort_unstable();

        let mut hasher = Sha256::new();
        // Length-prefix each key so distinct member sets can't collide.
        hasher.update((keys.len() as u32).to_be_bytes());
        for key in &keys {
            hasher.update((key.len() as u32).to_be_bytes());
            hasher.update(key);
        }
        SafetyNumber(hasher.finalize().into())
    }

    /// Current number of members in the group.
    pub fn member_count(&self) -> usize {
        self.inner.members().count()
    }

    /// Whether `label` (a credential username) is currently in the roster. After
    /// applying a commit that removed us, our own label is gone, so the caller
    /// can detect "I was removed from this group" and move it to read-only.
    pub fn is_member(&self, label: &str) -> bool {
        self.inner
            .members()
            .any(|m| String::from_utf8_lossy(m.credential.serialized_content()) == label)
    }

    /// Each member's (credential label, identity/signature key). Used to key a
    /// media opener per sender: a received frame names its sender, and this maps
    /// that sender to the identity key their media key is derived from.
    pub fn member_keys(&self) -> Vec<(String, Vec<u8>)> {
        self.inner
            .members()
            .map(|m| {
                let label = String::from_utf8_lossy(m.credential.serialized_content()).into_owned();
                (label, m.signature_key.as_slice().to_vec())
            })
            .collect()
    }

    /// Encrypt a text message as an MLS application message. Returns opaque
    /// bytes to relay through the server, which cannot read them.
    pub fn encrypt_text(
        &mut self,
        sender: &Identity,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let out = self
            .inner
            .create_message(&sender.provider, &sender.signer, plaintext)
            .map_err(|e| CryptoError::Text(e.to_string()))?;
        out.to_bytes()
            .map_err(|e| CryptoError::Serialize(e.to_string()))
    }

    /// Decrypt a relayed text message. Returns the MLS-authenticated sender and
    /// the plaintext. Fails if the bytes are not a valid application message
    /// for this member's current epoch (tampering, wrong group, replay).
    pub fn decrypt_text(
        &mut self,
        receiver: &Identity,
        sealed: &[u8],
    ) -> Result<TextMessage, CryptoError> {
        let message = MlsMessageIn::tls_deserialize_exact(sealed)
            .map_err(|e| CryptoError::Text(format!("deserialize: {e}")))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|e| CryptoError::Text(format!("not a protocol message: {e}")))?;
        // openmls fires a `debug_assert!(false)` when AEAD open fails on a
        // tampered ciphertext, so a hostile peer's garbage would panic a debug
        // build instead of erroring (release compiles the assert out, but a
        // crash class must not depend on the profile). Contain it: a message
        // that does not decrypt is a rejection, never a panic. `&mut self` is
        // unwind-safe here because a failed process_message does not advance
        // the group's ratchet state.
        let processed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.inner
                .process_message(&receiver.provider, protocol_message)
        }))
        .map_err(|_| CryptoError::Text("message rejected (decryption failed)".into()))?
        .map_err(|e| CryptoError::Text(e.to_string()))?;

        // Capture the authenticated sender before consuming the message.
        let sender = processed.credential().serialized_content().to_vec();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(TextMessage {
                sender,
                plaintext: app.into_bytes(),
            }),
            _ => Err(CryptoError::Text(
                "expected an application message, got a handshake message".into(),
            )),
        }
    }
}

/// A decrypted text message and its MLS-authenticated sender.
#[derive(Debug, Clone)]
pub struct TextMessage {
    /// The sender's credential identity (display-name bytes), authenticated by
    /// MLS -- not attacker-spoofable within the group.
    pub sender: Vec<u8>,
    pub plaintext: Vec<u8>,
}

/// The two artifacts of adding a member: the `welcome` for the new member and
/// the `commit` to fan out to existing members.
#[derive(Debug, Clone)]
pub struct MemberAdd {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// A 256-bit fingerprint of a group's membership, for out-of-band comparison.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SafetyNumber([u8; 32]);

impl SafetyNumber {
    /// Raw bytes of the fingerprint.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for SafetyNumber {
    /// Uppercase hex grouped in blocks of four for reading aloud.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode_upper(self.0);
        for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{}", std::str::from_utf8(chunk).unwrap())?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SafetyNumber({self})")
    }
}
