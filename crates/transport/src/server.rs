//! The self-hosted server: a reliable WebSocket signaling channel and a
//! low-latency UDP media channel, both driving one shared [`Relay`]. It only
//! ever moves opaque `Sealed` payloads plus routing metadata; it holds no keys.
//!
//! Signaling (`serve_signaling`) carries registration, key packages, MLS
//! handshake, Welcomes, and text. Media (`serve_media`) fans out sealed frames
//! over UDP. Both share group membership through the same `Relay`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bincode::Options;
use enclave_protocol::{ClientMsg, ServerMsg, UdpMsg};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use crate::error::TransportError;
use crate::media_socket::media_codec;
use crate::ratelimit::TokenBucket;
use crate::relay::{ConnId, Relay};

/// Cap on a signaling message. Key packages and Welcomes are small; this bounds
/// memory a malicious client can force the server to allocate (ASVS V5/V12).
const SIGNALING_MSG_LIMIT: usize = 1 << 20; // 1 MiB

/// Per-connection signaling rate limit (ASVS V11): a burst then a sustained
/// rate, both far above what a human client needs.
const SIGNALING_BURST: f64 = 40.0;
const SIGNALING_RATE_PER_SEC: f64 = 25.0;

/// Per-source UDP media rate limit (ASVS V11). Audio is ~50 frames/sec; this
/// allows bursts and several concurrent streams while capping a flood.
const MEDIA_BURST: f64 = 400.0;
const MEDIA_RATE_PER_SEC: f64 = 250.0;

/// Shared server state: the routing brain plus a per-connection outbound queue.
struct ServerState {
    relay: Relay,
    txs: HashMap<ConnId, mpsc::UnboundedSender<ServerMsg>>,
}

/// A server instance. Start the signaling and/or media channels on it; they
/// share one routing brain, so group membership is consistent across both.
pub struct Server {
    state: Arc<Mutex<ServerState>>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState {
                relay: Relay::new(),
                txs: HashMap::new(),
            })),
        }
    }

    /// Create a server backed by a persistent account store (ephemeral OPAQUE
    /// setup). Prefer [`Server::with_auth`] for a real deployment so accounts
    /// survive a restart.
    pub fn with_accounts(accounts: crate::accounts::AccountStore) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState {
                relay: Relay::with_accounts(accounts),
                txs: HashMap::new(),
            })),
        }
    }

    /// Create a server backed by a persistent account store, OPAQUE server
    /// setup, and friend graph.
    pub fn with_auth(
        accounts: crate::accounts::AccountStore,
        opaque: crate::opaque::OpaqueServer,
        friends: crate::friends::FriendStore,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState {
                relay: Relay::with_auth(accounts, opaque, friends),
                txs: HashMap::new(),
            })),
        }
    }

    /// Bind and start the reliable WebSocket signaling channel. Returns the
    /// bound address; the accept loop runs on a background task.
    pub async fn serve_signaling(&self, addr: &str) -> Result<SocketAddr, TransportError> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let state = self.state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                tokio::spawn(handle_conn(stream, state.clone()));
            }
        });
        Ok(local)
    }

    /// Bind and start the low-latency UDP media channel. Returns the bound
    /// address; the receive/forward loop runs on a background task.
    pub async fn serve_media(&self, addr: &str) -> Result<SocketAddr, TransportError> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let local = socket.local_addr()?;
        let state = self.state.clone();
        let sock = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            let mut buckets: HashMap<SocketAddr, TokenBucket> = HashMap::new();
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                // Per-source rate limit (ASVS V11): drop a flooding sender. Only
                // group members' frames are forwarded anyway (access control),
                // so this bounds member-side abuse.
                let now = Instant::now();
                if !buckets
                    .entry(src)
                    .or_insert_with(|| TokenBucket::new(MEDIA_BURST, MEDIA_RATE_PER_SEC, now))
                    .try_take(now)
                {
                    continue;
                }
                let Ok(msg) = media_codec().deserialize::<UdpMsg>(&buf[..n]) else {
                    continue;
                };
                let targets: Vec<SocketAddr> = {
                    let mut s = state.lock().unwrap();
                    match &msg {
                        UdpMsg::Hello { device, group } => {
                            s.relay.udp_hello(src, device.clone(), group.clone());
                            Vec::new()
                        }
                        UdpMsg::Frame(frame) => {
                            s.relay.udp_media_targets(src, &frame.group, &frame.sender)
                        }
                    }
                };
                // Forward the original datagram unchanged (no re-serialization).
                if matches!(msg, UdpMsg::Frame(_)) {
                    for target in targets {
                        let _ = sock.send_to(&buf[..n], target).await;
                    }
                }
            }
        });
        Ok(local)
    }

    /// Like [`serve_signaling`](Self::serve_signaling) but over TLS (wss).
    /// Provide the server certificate chain and private key (DER). This
    /// protects signaling metadata in transit (ASVS V9); the E2E content
    /// guarantee does not depend on it.
    pub async fn serve_signaling_tls(
        &self,
        addr: &str,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<SocketAddr, TransportError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TransportError::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| TransportError::Tls(e.to_string()))?;
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let state = self.state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        handle_conn(tls, state).await;
                    }
                });
            }
        });
        Ok(local)
    }
}

/// A running signaling server. Dropping it does not stop the accept loop.
pub struct ServerHandle {
    pub addr: SocketAddr,
}

/// Convenience: start a signaling-only server (used by the binary and tests
/// that do not need the media channel).
pub async fn serve(addr: &str) -> Result<ServerHandle, TransportError> {
    let server = Server::new();
    let addr = server.serve_signaling(addr).await?;
    Ok(ServerHandle { addr })
}

/// Decode one WebSocket frame into raw payload bytes, or `None` for control /
/// non-data frames the relay ignores.
fn frame_bytes(msg: Message) -> Option<Vec<u8>> {
    match msg {
        Message::Binary(b) => Some(b.to_vec()),
        Message::Text(t) => Some(t.as_bytes().to_vec()),
        _ => None,
    }
}

async fn handle_conn<S>(stream: S, state: Arc<Mutex<ServerState>>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let config = WebSocketConfig::default()
        .max_message_size(Some(SIGNALING_MSG_LIMIT))
        .max_frame_size(Some(SIGNALING_MSG_LIMIT));
    let ws = match tokio_tungstenite::accept_async_with_config(stream, Some(config)).await {
        Ok(ws) => ws,
        Err(_) => return,
    };
    let (mut write, mut read) = ws.split();

    // Register the connection and its outbound queue.
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();
    let conn = {
        let mut s = state.lock().unwrap();
        let conn = s.relay.connect();
        s.txs.insert(conn, tx);
        conn
    };

    // Writer task: serialize queued ServerMsgs to the socket.
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Ok(bytes) = serde_json::to_vec(&msg) else {
                continue;
            };
            if write.send(Message::binary(bytes)).await.is_err() {
                break;
            }
        }
    });

    // Reader loop: decode ClientMsgs, route, dispatch.
    let mut bucket = TokenBucket::new(SIGNALING_BURST, SIGNALING_RATE_PER_SEC, Instant::now());
    while let Some(Ok(msg)) = read.next().await {
        if matches!(msg, Message::Close(_)) {
            break;
        }
        let Some(bytes) = frame_bytes(msg) else {
            continue;
        };
        // Drop messages from a connection that is over its rate (ASVS V11).
        if !bucket.try_take(Instant::now()) {
            continue;
        }
        let Ok(client_msg) = serde_json::from_slice::<ClientMsg>(&bytes) else {
            continue;
        };

        // Route under the lock; resolve target senders; release before sending.
        let sends: Vec<(mpsc::UnboundedSender<ServerMsg>, ServerMsg)> = {
            let mut s = state.lock().unwrap();
            let outgoing = s.relay.handle(conn, client_msg);
            outgoing
                .into_iter()
                .filter_map(|o| s.txs.get(&o.to).cloned().map(|tx| (tx, o.msg)))
                .collect()
        };
        for (tx, msg) in sends {
            let _ = tx.send(msg);
        }
    }

    // Cleanup: disconnect may produce presence-offline broadcasts to deliver.
    let sends: Vec<(mpsc::UnboundedSender<ServerMsg>, ServerMsg)> = {
        let mut s = state.lock().unwrap();
        let outgoing = s.relay.disconnect(conn);
        s.txs.remove(&conn);
        outgoing
            .into_iter()
            .filter_map(|o| s.txs.get(&o.to).cloned().map(|tx| (tx, o.msg)))
            .collect()
    };
    for (tx, msg) in sends {
        let _ = tx.send(msg);
    }
    writer.abort();
}
