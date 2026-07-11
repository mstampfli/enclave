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
    ) -> Result<MemberAdd, CryptoError> {
        let key_package_in = KeyPackageIn::tls_deserialize(&mut &key_package_bytes[..])
            .map_err(|e| CryptoError::KeyPackage(format!("deserialize: {e}")))?;
        let key_package = key_package_in
            .validate(owner.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| CryptoError::KeyPackageInvalid(e.to_string()))?;

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

        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let staged = StagedWelcome::new_from_welcome(&joiner.provider, &config, welcome, None)
            .map_err(|e| CryptoError::Join(e.to_string()))?;
        let inner = staged
            .into_group(&joiner.provider)
            .map_err(|e| CryptoError::Join(format!("into_group: {e}")))?;

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
        let processed = self
            .inner
            .process_message(&receiver.provider, protocol_message)
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
