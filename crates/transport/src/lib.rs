//! Transport: how bytes move between client and server.
//!
//! Two channels, both terminating at the self-hosted server:
//! - **Signaling** (Phase 2): reliable, ordered WebSocket. Carries
//!   [`ClientMsg`] / [`ServerMsg`] -- registration, key-package fetch, MLS
//!   handshake relay, Welcomes, text, presence. TLS on this hop is a Phase 7
//!   hardening item; the E2E content guarantee does not depend on it.
//! - **Media** (Phase 3): low-latency, loss-tolerant, carrying [`MediaFrame`]s.
//!
//! The routing brain is [`relay::Relay`], a pure state machine. The async
//! WebSocket [`server`] owns one and drives it; [`client`] is the client-side
//! connection.
//!
//! [`ClientMsg`]: enclave_protocol::ClientMsg
//! [`ServerMsg`]: enclave_protocol::ServerMsg
//! [`MediaFrame`]: enclave_protocol::MediaFrame

pub mod accounts;
pub mod client;
pub mod error;
pub mod friends;
pub mod groups;
pub mod media_socket;
pub mod opaque;
pub mod ratelimit;
pub mod relay;
pub mod server;

pub use accounts::{AccountStore, AuthOutcome};
pub use client::Connection;
pub use error::TransportError;
pub use friends::{FriendStore, RequestOutcome};
pub use groups::GroupStore;
pub use media_socket::MediaSocket;
pub use ratelimit::TokenBucket;
pub use relay::{ConnId, Outgoing, Relay};
pub use server::{serve, Server, ServerHandle};
