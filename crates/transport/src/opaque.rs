//! Zero-knowledge password authentication via **OPAQUE** (RFC 9807).
//!
//! OPAQUE is an augmented PAKE: the password never leaves the client, not even
//! during registration, and the server stores only an opaque *envelope* it
//! cannot reverse. Authentication is a challenge/response in which the server
//! learns nothing about the password and only whether the client proved
//! knowledge of it. This is the property that makes the server zero-knowledge on
//! credentials (it still sees routing metadata: usernames, identity pubkeys).
//!
//! Why OPAQUE over sending a password (even hashed): a hash over the wire is a
//! replayable credential the server (or a MITM past TLS) can capture and reuse.
//! OPAQUE's login proof is per-session and reveals nothing reusable. See
//! THREAT_MODEL.md ("Account authentication").
//!
//! This module is the single, tested primitive for OPAQUE in Enclave. Everything
//! else deals only in `Vec<u8>` wire blobs and the opaque state handles below;
//! the `opaque_ke` types never leak past this boundary.
//!
//! Cipher suite: Ristretto255 OPRF + Triple-DH key exchange (SHA-512) + **Argon2id**
//! as the key-stretching function (so an envelope leak still forces a memory-hard
//! per-account offline attack).

use std::path::Path;

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

/// The Enclave OPAQUE cipher suite. Argon2id KSF is the load-bearing choice: it
/// is what a stolen envelope must be brute-forced through.
pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

/// An OPAQUE operation failed. Deliberately coarse: the wire never carries a
/// reason that would help an attacker distinguish "wrong password" from "no such
/// user" (see login dummy mode below).
#[derive(Debug, thiserror::Error)]
#[error("opaque: {0}")]
pub struct OpaqueError(String);

fn err(e: impl std::fmt::Display) -> OpaqueError {
    OpaqueError(e.to_string())
}

/// Serialize a fixed-length OPAQUE message to owned bytes for the wire.
fn bytes(msg: impl AsRef<[u8]>) -> Vec<u8> {
    msg.as_ref().to_vec()
}

// --- Server side (held by the relay) ---

/// The server's long-term OPAQUE state (OPRF seed + static keypair). This is
/// critical persistent state: losing it makes every stored envelope unusable;
/// leaking it enables the (still Argon2id-hard) per-account offline attack.
/// Treated like a server private key -- generated once, persisted, gitignored.
pub struct OpaqueServer {
    setup: ServerSetup<Suite>,
}

impl Default for OpaqueServer {
    /// A fresh, ephemeral setup. Real deployments use
    /// [`OpaqueServer::load_or_generate`] so the setup persists across restarts;
    /// this default is for tests and throwaway relays.
    fn default() -> Self {
        Self::generate()
    }
}

impl OpaqueServer {
    /// Generate a fresh server setup. Do this once per deployment.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            setup: ServerSetup::new(&mut rng),
        }
    }

    /// Restore a server setup from its serialized bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, OpaqueError> {
        Ok(Self {
            setup: ServerSetup::deserialize(data).map_err(err)?,
        })
    }

    /// Serialize the server setup for persistence.
    pub fn to_bytes(&self) -> Vec<u8> {
        bytes(self.setup.serialize())
    }

    /// Load the server setup from `path`, generating and persisting a new one if
    /// the file does not exist or cannot be read.
    pub fn load_or_generate(path: &Path) -> Self {
        if let Ok(data) = std::fs::read(path) {
            if let Ok(server) = Self::from_bytes(&data) {
                return server;
            }
        }
        let server = Self::generate();
        let _ = std::fs::write(path, server.to_bytes());
        server
    }

    /// Registration step 1: answer the client's blinded request. Stateless on
    /// the server side (only the long-term setup is used).
    pub fn register_start(&self, username: &str, request: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        let request = RegistrationRequest::<Suite>::deserialize(request).map_err(err)?;
        let result =
            ServerRegistration::start(&self.setup, request, username.as_bytes()).map_err(err)?;
        Ok(bytes(result.message.serialize()))
    }

    /// Registration step 2: turn the client's upload into the stored envelope
    /// (the "password file"). Uses no server secret, so it is a free function in
    /// spirit; kept here for cohesion.
    pub fn register_finish(&self, upload: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        let upload = RegistrationUpload::<Suite>::deserialize(upload).map_err(err)?;
        let password_file = ServerRegistration::<Suite>::finish(upload);
        Ok(bytes(password_file.serialize()))
    }

    /// Login step 1: produce the credential response and the per-login server
    /// state. `envelope` is the stored password file, or `None` for an unknown
    /// user -- in which case OPAQUE runs in **dummy mode** so the response is
    /// indistinguishable and login never reveals whether the username exists.
    pub fn login_start(
        &self,
        username: &str,
        envelope: Option<&[u8]>,
        request: &[u8],
    ) -> Result<(Vec<u8>, ServerLoginState), OpaqueError> {
        let password_file = match envelope {
            Some(bytes) => Some(ServerRegistration::<Suite>::deserialize(bytes).map_err(err)?),
            None => None,
        };
        let request = CredentialRequest::<Suite>::deserialize(request).map_err(err)?;
        let mut rng = OsRng;
        let result = ServerLogin::start(
            &mut rng,
            &self.setup,
            password_file,
            request,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(err)?;
        Ok((
            bytes(result.message.serialize()),
            ServerLoginState(result.state),
        ))
    }
}

/// Per-login server state, held between the two login round-trips.
pub struct ServerLoginState(ServerLogin<Suite>);

impl ServerLoginState {
    /// Login step 2 (server): verify the client's finalization. `Ok(())` means
    /// the client proved knowledge of the password; an error means it did not
    /// (wrong password, unknown user via dummy mode, or a tampered exchange).
    pub fn finish(self, finalization: &[u8]) -> Result<(), OpaqueError> {
        let finalization =
            CredentialFinalization::<Suite>::deserialize(finalization).map_err(err)?;
        self.0
            .finish(finalization, ServerLoginParameters::default())
            .map_err(err)?;
        Ok(())
    }
}

// --- Client side (held by the controller) ---

/// Client registration state, held between the two registration round-trips.
pub struct ClientRegisterState(ClientRegistration<Suite>);

/// Registration step 1 (client): blind the password into a request. The
/// password is consumed locally and never sent.
pub fn client_register_start(
    password: &str,
) -> Result<(Vec<u8>, ClientRegisterState), OpaqueError> {
    let mut rng = OsRng;
    let result = ClientRegistration::<Suite>::start(&mut rng, password.as_bytes()).map_err(err)?;
    Ok((
        bytes(result.message.serialize()),
        ClientRegisterState(result.state),
    ))
}

impl ClientRegisterState {
    /// Registration step 2 (client): finalize against the server response,
    /// producing the upload the server will store as the envelope.
    pub fn finish(self, password: &str, response: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        let response = RegistrationResponse::<Suite>::deserialize(response).map_err(err)?;
        let mut rng = OsRng;
        let result = self
            .0
            .finish(
                &mut rng,
                password.as_bytes(),
                response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(err)?;
        Ok(bytes(result.message.serialize()))
    }
}

/// Client login state, held between the two login round-trips.
pub struct ClientLoginState(ClientLogin<Suite>);

/// Login step 1 (client): blind the password into a credential request.
pub fn client_login_start(password: &str) -> Result<(Vec<u8>, ClientLoginState), OpaqueError> {
    let mut rng = OsRng;
    let result = ClientLogin::<Suite>::start(&mut rng, password.as_bytes()).map_err(err)?;
    Ok((
        bytes(result.message.serialize()),
        ClientLoginState(result.state),
    ))
}

impl ClientLoginState {
    /// Login step 2 (client): finalize against the server response. Fails if the
    /// password was wrong (the server response will not validate), which is how
    /// the client learns its own auth outcome. Returns the finalization the
    /// server needs to confirm.
    pub fn finish(self, password: &str, response: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        let response = CredentialResponse::<Suite>::deserialize(response).map_err(err)?;
        let mut rng = OsRng;
        let result = self
            .0
            .finish(
                &mut rng,
                password.as_bytes(),
                response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(err)?;
        Ok(bytes(result.message.serialize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full register-then-login round trip authenticates; the server never
    /// touches the password bytes.
    fn register(server: &OpaqueServer, username: &str, password: &str) -> Vec<u8> {
        let (req, state) = client_register_start(password).unwrap();
        let resp = server.register_start(username, &req).unwrap();
        let upload = state.finish(password, &resp).unwrap();
        server.register_finish(&upload).unwrap()
    }

    fn login(
        server: &OpaqueServer,
        username: &str,
        password: &str,
        envelope: Option<&[u8]>,
    ) -> Result<(), OpaqueError> {
        let (req, cstate) = client_login_start(password).unwrap();
        let (resp, sstate) = server.login_start(username, envelope, &req)?;
        let finalization = cstate.finish(password, &resp)?;
        sstate.finish(&finalization)
    }

    #[test]
    fn correct_password_authenticates() {
        let server = OpaqueServer::generate();
        let envelope = register(&server, "alice", "correct-horse-battery");
        assert!(login(&server, "alice", "correct-horse-battery", Some(&envelope)).is_ok());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let server = OpaqueServer::generate();
        let envelope = register(&server, "alice", "correct-horse-battery");
        // A wrong password must fail somewhere in the handshake, never authenticate.
        assert!(login(&server, "alice", "wrong-password-123456", Some(&envelope)).is_err());
    }

    #[test]
    fn unknown_user_dummy_mode_does_not_authenticate() {
        let server = OpaqueServer::generate();
        // No envelope (unknown user): dummy mode runs a full-looking handshake
        // that never authenticates, so login cannot enumerate usernames.
        assert!(login(&server, "ghost", "any-password-at-all", None).is_err());
    }

    #[test]
    fn server_setup_round_trips_through_bytes() {
        let server = OpaqueServer::generate();
        let restored = OpaqueServer::from_bytes(&server.to_bytes()).unwrap();
        // An envelope registered under the original verifies under the restored
        // setup: persistence preserves the server's identity.
        let envelope = register(&server, "bob", "another-long-password");
        assert!(login(&restored, "bob", "another-long-password", Some(&envelope)).is_ok());
    }
}
