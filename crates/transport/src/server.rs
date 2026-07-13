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
use enclave_protocol::{ClientMsg, Sealed, ServerMsg, UdpMsg};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use crate::error::TransportError;
use crate::filestore::BlobReader;
use crate::media_socket::media_codec;
use crate::ratelimit::TokenBucket;
use crate::relay::{BlobDelivery, ConnId, Relay};

/// How often the server sweeps lapsed file offers (stored TTL and the live
/// accept window). Frequent enough that a live offer's ~90s window is honored.
const FILE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Cap on a signaling message. Key packages and Welcomes are small; this bounds
/// memory a malicious client can force the server to allocate (ASVS V5/V12).
const SIGNALING_MSG_LIMIT: usize = 1 << 20; // 1 MiB

/// Per-connection signaling rate limit (ASVS V11): a burst then a sustained
/// rate, both far above what a human client needs.
const SIGNALING_BURST: f64 = 40.0;
const SIGNALING_RATE_PER_SEC: f64 = 25.0;

/// Per-connection high gate applied to every message (mainly file chunks). The
/// burst exceeds the number of chunks in one maximum-size file (256 MiB /
/// 512 KiB = 512), so an entire file can be uploaded in one burst without a
/// drop; the sustained rate then allows a healthy multi-file throughput. File
/// chunk volume is separately bounded by the store quota and by consent, so a
/// high message rate here is safe.
const FILE_BURST: f64 = 600.0;
const FILE_RATE_PER_SEC: f64 = 300.0;

/// Per-source UDP media rate limit (ASVS V11). Audio is ~50 datagrams/sec, but
/// a screen-share stream is fragmented video: ~30 fps at several Mbps is many
/// hundreds of ~1 KB fragments per second, with larger keyframe bursts. This
/// allows a healthy video stream plus audio while still capping a flood.
const MEDIA_BURST: f64 = 8000.0;
const MEDIA_RATE_PER_SEC: f64 = 4000.0;

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
    /// setup, friend graph, and group routing membership.
    pub fn with_auth(
        accounts: crate::accounts::AccountStore,
        opaque: crate::opaque::OpaqueServer,
        friends: crate::friends::FriendStore,
        groups: crate::groups::GroupStore,
        queue: crate::msgqueue::MessageQueue,
        files_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState {
                relay: Relay::with_auth(accounts, opaque, friends, groups, queue, files_dir),
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
        spawn_file_sweeper(state.clone());
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
                        // A fragment routes exactly like a frame, by its group and
                        // sender; the relay never reassembles (it stays opaque).
                        UdpMsg::Fragment { group, sender, .. } => {
                            s.relay.udp_media_targets(src, group, sender)
                        }
                    }
                };
                // Forward the original datagram unchanged (no re-serialization).
                if matches!(msg, UdpMsg::Frame(_) | UdpMsg::Fragment { .. }) {
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
        spawn_file_sweeper(state.clone());
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

    // Reader loop: decode ClientMsgs, route, dispatch. Two rate budgets:
    //  - a high gate on *every* message, to bound decode cost and absorb a whole
    //    file's chunk burst (its burst exceeds the chunks in one max-size file,
    //    so a legitimate upload is never throttled into a corrupting drop);
    //  - the tight signaling budget on top, for control-plane messages only.
    // File chunks pay only the high gate: dropping one would corrupt a transfer,
    // and their volume is already bounded by the store quota and consent.
    let mut file_gate = TokenBucket::new(FILE_BURST, FILE_RATE_PER_SEC, Instant::now());
    let mut bucket = TokenBucket::new(SIGNALING_BURST, SIGNALING_RATE_PER_SEC, Instant::now());
    while let Some(Ok(msg)) = read.next().await {
        if matches!(msg, Message::Close(_)) {
            break;
        }
        let Some(bytes) = frame_bytes(msg) else {
            continue;
        };
        // High gate on all traffic (bounds decode cost even under a flood).
        if !file_gate.try_take(Instant::now()) {
            continue;
        }
        let Ok(client_msg) = serde_json::from_slice::<ClientMsg>(&bytes) else {
            continue;
        };
        // Control-plane messages additionally obey the tight signaling budget;
        // file chunks are exempt (see above).
        if !matches!(client_msg, ClientMsg::FileChunk { .. }) && !bucket.try_take(Instant::now()) {
            continue;
        }

        // Route under the lock; resolve target senders; release before sending.
        // Also collect any stored-blob deliveries scheduled by this message, to
        // stream off-lock (a large blob read must never hold the global lock).
        let (sends, deliveries) = {
            let mut s = state.lock().unwrap();
            let outgoing = s.relay.handle(conn, client_msg);
            let sends: Vec<(mpsc::UnboundedSender<ServerMsg>, ServerMsg)> = outgoing
                .into_iter()
                .filter_map(|o| s.txs.get(&o.to).cloned().map(|tx| (tx, o.msg)))
                .collect();
            let deliveries: Vec<(BlobDelivery, mpsc::UnboundedSender<ServerMsg>)> = s
                .relay
                .take_blob_deliveries()
                .into_iter()
                .filter_map(|d| s.txs.get(&d.to).cloned().map(|tx| (d, tx)))
                .collect();
            (sends, deliveries)
        };
        for (tx, msg) in sends {
            let _ = tx.send(msg);
        }
        for (delivery, tx) in deliveries {
            let state = state.clone();
            // The blob read is blocking I/O and can be large, so it runs on a
            // blocking thread, off the async workers and off the relay lock.
            tokio::task::spawn_blocking(move || stream_blob(state, delivery, tx));
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

/// Stream one stored blob to an accepting recipient off the relay lock, one
/// sealed chunk at a time (never the whole file in memory), then mark the
/// delivery done so the store can reclaim the blob once every recipient has
/// resolved. If the recipient's connection drops mid-stream, the delivery is
/// aborted (the offer stays pending, so it can be retried).
fn stream_blob(
    state: Arc<Mutex<ServerState>>,
    d: BlobDelivery,
    tx: mpsc::UnboundedSender<ServerMsg>,
) {
    let ok = match BlobReader::open(&d.blob) {
        Ok(mut reader) => loop {
            match reader.next_chunk() {
                Ok(Some(chunk)) => {
                    let msg = ServerMsg::FileChunk {
                        offer_id: d.offer_id,
                        from: d.from.clone(),
                        data: Sealed(chunk),
                    };
                    if tx.send(msg).is_err() {
                        break false; // recipient disconnected
                    }
                }
                Ok(None) => break true, // end of blob
                Err(_) => break false,  // read error
            }
        },
        Err(_) => false,
    };
    let mut s = state.lock().unwrap();
    if ok {
        let _ = tx.send(ServerMsg::FileComplete {
            offer_id: d.offer_id,
            from: d.from.clone(),
        });
        s.relay.finish_stored_delivery(&d.offer_id, &d.recipient);
    } else {
        s.relay.abort_stored_delivery(&d.offer_id, &d.recipient);
    }
}

/// Periodically sweep lapsed file offers and deliver the resulting notifications.
fn spawn_file_sweeper(state: Arc<Mutex<ServerState>>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(FILE_SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            let sends: Vec<(mpsc::UnboundedSender<ServerMsg>, ServerMsg)> = {
                let mut s = state.lock().unwrap();
                let outgoing = s.relay.sweep_files();
                outgoing
                    .into_iter()
                    .filter_map(|o| s.txs.get(&o.to).cloned().map(|tx| (tx, o.msg)))
                    .collect()
            };
            for (tx, msg) in sends {
                let _ = tx.send(msg);
            }
        }
    });
}
