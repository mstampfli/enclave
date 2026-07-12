//! A device identity: a long-term Ed25519 signature key plus the openmls
//! provider that stores this device's private key material.
//!
//! The private identity key and all MLS secrets live inside `provider`'s
//! storage and never leave the device. What goes on the wire is only the
//! *public* key package produced by [`Identity::new_key_package`].

use std::collections::HashMap;
use std::path::Path;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use zeroize::Zeroize;

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

    /// A [`MediaSigner`] over this device's Ed25519 identity key, for signing
    /// outgoing media frames. It signs through a clone of the MLS keypair; the
    /// private key never leaves the crypto crate. Fails if the identity is not
    /// Ed25519 (the fixed ciphersuite is, so this only guards a future change).
    pub fn media_signer(&self) -> Result<crate::MediaSigner, CryptoError> {
        if self.signer.signature_scheme() != CIPHERSUITE.signature_algorithm() {
            return Err(CryptoError::Identity("identity is not Ed25519".into()));
        }
        Ok(crate::MediaSigner::from_keypair(self.signer.clone()))
    }

    /// Snapshot this device's entire MLS storage (all group states and private
    /// keys) so a session can be persisted. It contains private key material and
    /// MUST be encrypted before it touches disk.
    pub fn storage_snapshot(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.provider
            .storage()
            .values
            .read()
            .expect("storage lock")
            .clone()
    }

    /// Merge a previously captured MLS storage snapshot back in, so groups can be
    /// reloaded (see [`crate::Group::load`]). Called once after login.
    pub fn restore_storage(&self, snapshot: HashMap<Vec<u8>, Vec<u8>>) {
        let mut values = self
            .provider
            .storage()
            .values
            .write()
            .expect("storage lock");
        for (k, v) in snapshot {
            values.insert(k, v);
        }
    }

    /// Produce a serialized **last-resort** public key package for this identity.
    /// Publish it once; a group owner adds this device by consuming it. Because
    /// it is marked last-resort, openmls keeps the matching private key after a
    /// join, so the *same* key package can be reused to join unlimited groups
    /// (no single-use pool to exhaust). The private keys live in `self.provider`.
    pub fn new_key_package(&self) -> Result<Vec<u8>, CryptoError> {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(crate::enclave_capabilities())
            .mark_as_last_resort()
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

    /// Persist this identity's signing key to `path`, encrypted at rest with a
    /// key derived from `password` (Argon2id -> ChaCha20-Poly1305). The private
    /// key never leaves the device and is useless on disk without the password.
    /// File layout: salt(16) || nonce(12) || ciphertext.
    pub fn save(&self, path: &Path, password: &str) -> Result<(), CryptoError> {
        let mut plaintext = serde_json::to_vec(&self.signer)
            .map_err(|e| CryptoError::Identity(format!("serialize: {e}")))?;

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|e| CryptoError::Identity(format!("rng: {e}")))?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| CryptoError::Identity(format!("rng: {e}")))?;

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|e| CryptoError::Identity(format!("kdf: {e}")))?;
        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        key.zeroize();

        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), plaintext.as_slice())
            .map_err(|_| CryptoError::Identity("encrypt failed".into()))?;
        plaintext.zeroize();

        let mut out = Vec::with_capacity(28 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        std::fs::write(path, out).map_err(|e| CryptoError::Identity(format!("write: {e}")))?;
        Ok(())
    }

    /// Load an identity for `name`, decrypting the file with `password`. Fails
    /// (not silently succeeds) on a wrong password or a tampered file.
    pub fn load(name: &str, path: &Path, password: &str) -> Result<Self, CryptoError> {
        let bytes = std::fs::read(path).map_err(|e| CryptoError::Identity(format!("read: {e}")))?;
        if bytes.len() < 28 {
            return Err(CryptoError::Identity("identity file too short".into()));
        }
        let salt = &bytes[0..16];
        let nonce: [u8; 12] = bytes[16..28].try_into().expect("12 bytes");
        let ciphertext = &bytes[28..];

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| CryptoError::Identity(format!("kdf: {e}")))?;
        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        key.zeroize();

        let mut plaintext = cipher
            .decrypt(&Nonce::from(nonce), ciphertext)
            .map_err(|_| CryptoError::Identity("wrong password or corrupt identity".into()))?;
        let signer: SignatureKeyPair = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Identity(format!("deserialize: {e}")))?;
        plaintext.zeroize();

        let provider = OpenMlsRustCrypto::default();
        signer
            .store(provider.storage())
            .map_err(|e| CryptoError::Identity(format!("store: {e}")))?;
        let credential = BasicCredential::new(name.as_bytes().to_vec());
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
}
