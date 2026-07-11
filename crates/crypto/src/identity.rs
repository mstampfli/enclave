//! A device identity: a long-term Ed25519 signature key plus the openmls
//! provider that stores this device's private key material.
//!
//! The private identity key and all MLS secrets live inside `provider`'s
//! storage and never leave the device. What goes on the wire is only the
//! *public* key package produced by [`Identity::new_key_package`].

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::{CryptoError, CIPHERSUITE};

/// One device's identity and its MLS crypto/storage provider.
pub struct Identity {
    /// Holds this device's private keys and MLS group state. Never serialized
    /// to the server.
    pub(crate) provider: OpenMlsRustCrypto,
    /// Long-term Ed25519 signing key; the root of this device's identity.
    pub(crate) signer: SignatureKeyPair,
    /// The credential (display name) bound to `signer`'s public key.
    pub(crate) credential: CredentialWithKey,
}

impl Identity {
    /// Generate a fresh identity for `name`. `name` is a human label bound into
    /// the credential; identity is anchored by the Ed25519 key, not the name.
    pub fn generate(name: &str) -> Result<Self, CryptoError> {
        let provider = OpenMlsRustCrypto::default();

        let credential = BasicCredential::new(name.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| CryptoError::Identity(e.to_string()))?;
        // Persist the private key in this device's storage so later group
        // operations (join, commit) can find it.
        signer
            .store(provider.storage())
            .map_err(|e| CryptoError::Identity(format!("store signer: {e}")))?;

        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };

        Ok(Self {
            provider,
            signer,
            credential,
        })
    }

    /// This device's long-term public identity (signature) key. This is what a
    /// peer pins and what the safety number is computed over.
    pub fn identity_key(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// Produce a fresh, serialized public key package for this identity. Publish
    /// it so a group owner can add this device. The matching private keys are
    /// stored in `self.provider`, so this identity must be the one that later
    /// joins the group the key package was consumed into.
    pub fn new_key_package(&self) -> Result<Vec<u8>, CryptoError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|e| CryptoError::KeyPackage(e.to_string()))?;

        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| CryptoError::Serialize(e.to_string()))
    }
}
