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
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use crate::error::TransportError;
use crate::media_socket::media_codec;
use crate::ratelimit::TokenBucket;
use crate::relay::{BlobDelivery, ConnId, Outgoing, Relay};

/// How often the server sweeps lapsed file offers (stored TTL and the live
/// accept window). Frequent enough that a live offer's ~90s window is honored.
const FILE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-connection outbound memory is capped in two independent budgets (ASVS
/// V11), so a slow or stalled reader can never make the server buffer more than
/// their sum, and a bulk file delivery can never starve the reader's control and
/// text traffic:
///  - `MAX_OUTBOUND_FILE_BYTES` bounds an in-flight stored-file stream, which
///    *backpressures* at this bound (the streamer awaits room), so a slow reader
///    paces its own download instead of growing memory.
///  - `MAX_OUTBOUND_CTRL_BYTES` bounds everything else (control, text, relayed
///    live chunks). These never block a sender's connection, so on overflow the
///    message is dropped -- but only once even this budget is full, which means
///    the reader is not draining tiny messages either, i.e. effectively dead.
///
/// Because the two budgets are separate, a maxed-out file stream leaves the full
/// control budget available, so ordinary messages to a mid-download reader are
/// not dropped. Each is kept within `u32` so a message's size fits one permit.
/// (Offline recipients are a different path entirely: their messages go to the
/// persistent `msgqueue`, never here, and are not subject to these caps.)
const MAX_OUTBOUND_FILE_BYTES: usize = 12 * 1024 * 1024;
const MAX_OUTBOUND_CTRL_BYTES: usize = 4 * 1024 * 1024;

/// How long a relayed live file chunk waits for room in a slow recipient's file
/// budget before the sender's connection gives up on that recipient. A merely
/// slow-but-progressing reader never reaches it (each chunk drains within the
/// window); only a reader making no progress at all is dropped from the live
/// stream, so a dead recipient cannot wedge the sender. Stored delivery needs no
/// such timeout: it runs in its own task and self-heals when the reader's socket
/// closes.
const LIVE_BACKPRESSURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
    txs: HashMap<ConnId, Outbound>,
}

/// PRIMITIVE: a per-connection outbound queue bounded by bytes in flight, in two
/// independent budgets. The single mechanism that caps server memory per
/// connection and paces a slow reader. FOR every server->client message; NOT a
/// general channel -- it carries pre-serialized frames each coupled to a byte
/// permit (from one of the two budgets), so each cap is exact.
///
/// - `send` (async) draws on the *file* budget and AWAITS room -- true
///   backpressure. Use it for the file producers: the stored-blob streamer (its
///   own task) and relayed live chunks (the reader loop, bounded by
///   `LIVE_BACKPRESSURE_TIMEOUT` so a dead recipient cannot wedge the sender).
///   A slow reader paces the producer rather than growing server memory.
/// - `try_send` draws on the *control* budget and never blocks; it DROPS the
///   message if that budget is full. Use it for control/text, where blocking
///   would stall an unrelated sender's whole connection. Because it is a
///   separate budget, a maxed-out file stream cannot cause a control/text drop;
///   a drop here means even the small control budget is full, i.e. the reader is
///   not draining at all (effectively dead).
///
/// A frame's permit is released only after the writer hands it to the socket, so
/// each budget accounts its frames' bytes for their whole lifetime in memory.
#[derive(Clone)]
struct Outbound {
    tx: mpsc::UnboundedSender<Framed>,
    file_quota: Arc<Semaphore>,
    ctrl_quota: Arc<Semaphore>,
}

/// A serialized frame plus the byte permit it holds until it is written out.
struct Framed {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

impl Outbound {
    fn new() -> (Outbound, mpsc::UnboundedReceiver<Framed>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Outbound {
                tx,
                file_quota: Arc::new(Semaphore::new(MAX_OUTBOUND_FILE_BYTES)),
                ctrl_quota: Arc::new(Semaphore::new(MAX_OUTBOUND_CTRL_BYTES)),
            },
            rx,
        )
    }

    /// Serialize `msg` and the permit count it needs (its on-wire byte size,
    /// clamped to `cap` so a lone oversize frame can never wait for more permits
    /// than the budget holds).
    fn frame(msg: &ServerMsg, cap: usize) -> Option<(Vec<u8>, u32)> {
        let bytes = serde_json::to_vec(msg).ok()?;
        let n = bytes.len().min(cap) as u32;
        Some((bytes, n))
    }

    /// Await room in the file budget, then queue. Backpressure; errs only if the
    /// connection is gone. For the stored-blob streamer.
    async fn send(&self, msg: &ServerMsg) -> Result<(), ()> {
        let (bytes, n) = Self::frame(msg, MAX_OUTBOUND_FILE_BYTES).ok_or(())?;
        let permit = self
            .file_quota
            .clone()
            .acquire_many_owned(n)
            .await
            .map_err(|_| ())?;
        self.tx
            .send(Framed {
                bytes,
                _permit: permit,
            })
            .map_err(|_| ())
    }

    /// Queue without waiting on the control budget. Returns `false` (without
    /// queuing) if the budget is full or the connection is gone, so the caller
    /// can preserve a reliable message elsewhere instead of dropping it.
    fn try_send(&self, msg: &ServerMsg) -> bool {
        let Some((bytes, n)) = Self::frame(msg, MAX_OUTBOUND_CTRL_BYTES) else {
            return false;
        };
        let Ok(permit) = self.ctrl_quota.clone().try_acquire_many_owned(n) else {
            return false;
        };
        self.tx
            .send(Framed {
                bytes,
                _permit: permit,
            })
            .is_ok()
    }
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

    // Register the connection and its byte-bounded outbound queue.
    let (out, mut rx) = Outbound::new();
    let conn = {
        let mut s = state.lock().unwrap();
        let conn = s.relay.connect();
        s.txs.insert(conn, out);
        conn
    };

    // Writer task: write already-serialized frames to the socket. Each frame's
    // byte permit is released here, after the write, so the outbound byte cap
    // accounts a frame from the moment it is queued until it leaves for the wire.
    let writer = tokio::spawn(async move {
        while let Some(framed) = rx.recv().await {
            if write.send(Message::binary(framed.bytes)).await.is_err() {
                break;
            }
            // framed._permit drops here, releasing its bytes back to the quota.
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
        // Unwrap a reliability envelope: route the inner message exactly as if it
        // were bare, then acknowledge it below once it has been durably accepted
        // (delivered to online members and persisted for offline ones), so the
        // sender can stop retransmitting it. `reliable_seq` is `Some` when an ack
        // is owed.
        let (reliable_seq, client_msg) = match client_msg {
            ClientMsg::Reliable { seq, msg } => (Some(seq), *msg),
            other => (None, other),
        };
        // A legit client never double-wraps; reject a nested envelope so the
        // relay never recurses on attacker-controlled nesting (serde_json's
        // 128-deep parse limit already bounds it, this makes the intent explicit).
        if matches!(client_msg, ClientMsg::Reliable { .. }) {
            continue;
        }
        // Control-plane messages additionally obey the tight signaling budget;
        // file chunks are exempt (see above).
        if !matches!(client_msg, ClientMsg::FileChunk { .. }) && !bucket.try_take(Instant::now()) {
            continue;
        }

        // Route under the lock; resolve target queues; release before sending.
        // Also collect any stored-blob deliveries scheduled by this message, to
        // stream off-lock (a large blob read must never hold the global lock).
        let (sends, deliveries) = {
            let mut s = state.lock().unwrap();
            let outgoing = s.relay.handle(conn, client_msg);
            let sends: Vec<(ConnId, Outbound, ServerMsg)> = outgoing
                .into_iter()
                .filter_map(|o| s.txs.get(&o.to).cloned().map(|out| (o.to, out, o.msg)))
                .collect();
            let deliveries: Vec<(BlobDelivery, Outbound)> = s
                .relay
                .take_blob_deliveries()
                .into_iter()
                .filter_map(|d| s.txs.get(&d.to).cloned().map(|out| (d, out)))
                .collect();
            (sends, deliveries)
        };
        // Dispatch. A relayed live file chunk backpressures on the recipient's
        // file budget so a slow reader paces the sender instead of the chunk
        // being dropped; the wait is bounded by a timeout so a dead reader
        // cannot wedge the sender's connection (it is dropped from the live
        // stream, and its in-order sink then aborts cleanly). Everything else is
        // low-volume control/text; if the recipient's control budget is full
        // (they are stuck), a reliable message is preserved in their offline
        // queue rather than dropped, and only if even that is at its global cap
        // is the sender told. A real-time / latest-wins message is fine to drop.
        // Whether every reliable (spillable) recipient of this message was
        // accepted -- delivered live or persisted to their offline queue. Only
        // then is a `Reliable` sender acked; a global-queue-cap failure leaves it
        // un-acked so the sender retransmits when space frees.
        let mut all_accepted = true;
        for (to_conn, out, msg) in sends {
            if matches!(msg, ServerMsg::FileChunk { .. }) {
                if tokio::time::timeout(LIVE_BACKPRESSURE_TIMEOUT, out.send(&msg))
                    .await
                    .map(|r| r.is_ok())
                    != Ok(true)
                {
                    // The recipient made no progress within the window (too slow
                    // or gone): drop them from the live stream so later chunks
                    // skip them, and tell the sender precisely which offer failed.
                    if let ServerMsg::FileChunk { offer_id, .. } = msg {
                        let notify = {
                            let mut s = state.lock().unwrap();
                            s.relay.drop_live_recipient(offer_id, to_conn)
                        };
                        dispatch_now(&state, notify);
                    }
                }
                continue;
            }
            if out.try_send(&msg) {
                continue; // delivered live
            }
            if crate::relay::spillable(&msg) {
                // Preserve it in the recipient's offline queue rather than drop.
                let queued = {
                    let mut s = state.lock().unwrap();
                    s.relay.spill_offline(to_conn, msg)
                };
                if !queued {
                    // The offline queue is at its global cap (true exhaustion):
                    // withhold the ack so the sender's reliable-delivery layer
                    // keeps retransmitting until space frees. No separate failure
                    // notice is needed -- retransmit-until-acked supersedes it.
                    all_accepted = false;
                }
            }
        }
        // Acknowledge a durably-accepted reliable message so the sender can drop
        // it from its retransmit buffer. Withheld if any recipient could not be
        // accepted, so the sender keeps retrying until it can be.
        if let Some(seq) = reliable_seq {
            if all_accepted {
                let s = state.lock().unwrap();
                if let Some(sender) = s.txs.get(&conn) {
                    sender.try_send(&ServerMsg::Ack { seq });
                }
            }
        }
        for (delivery, out) in deliveries {
            let state = state.clone();
            // A stored blob is streamed off the relay lock with backpressure, so
            // a slow recipient stalls its own download instead of buffering the
            // whole file in server memory.
            tokio::spawn(stream_blob(state, delivery, out));
        }
    }

    // Cleanup: disconnect may produce presence-offline broadcasts to deliver.
    let sends: Vec<(Outbound, ServerMsg)> = {
        let mut s = state.lock().unwrap();
        let outgoing = s.relay.disconnect(conn);
        s.txs.remove(&conn);
        outgoing
            .into_iter()
            .filter_map(|o| s.txs.get(&o.to).cloned().map(|out| (out, o.msg)))
            .collect()
    };
    for (out, msg) in sends {
        out.try_send(&msg);
    }
    writer.abort();
}

/// Stream one stored blob to an accepting recipient off the relay lock, one
/// sealed chunk at a time (never the whole file in memory) and with backpressure
/// (the recipient's outbound cap paces the read), then mark the delivery done so
/// the store can reclaim the blob once every recipient has resolved. If the
/// recipient's connection drops mid-stream, the delivery is aborted (the offer
/// stays pending, so it can be retried).
async fn stream_blob(state: Arc<Mutex<ServerState>>, d: BlobDelivery, out: Outbound) {
    let ok = match tokio::fs::File::open(&d.blob).await {
        Ok(mut f) => stream_blob_chunks(&mut f, &d, &out).await,
        Err(_) => false,
    };
    if ok {
        // Ordered after the chunks (same queue); tiny, so it is not dropped.
        out.try_send(&ServerMsg::FileComplete {
            offer_id: d.offer_id,
            from: d.from.clone(),
        });
    }
    let mut s = state.lock().unwrap();
    if ok {
        s.relay.finish_stored_delivery(&d.offer_id, &d.recipient);
    } else {
        s.relay.abort_stored_delivery(&d.offer_id, &d.recipient);
    }
}

/// Read the length-prefixed sealed chunks of a blob and stream each one to the
/// recipient, awaiting outbound room between chunks. Returns whether the whole
/// blob was delivered (`false` on read error, corrupt length, or a dropped
/// recipient). The blob format matches `filestore`'s writer: a `u32` LE length
/// then that many bytes, per chunk.
async fn stream_blob_chunks(f: &mut tokio::fs::File, d: &BlobDelivery, out: &Outbound) -> bool {
    loop {
        let mut len_buf = [0u8; 4];
        match f.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return true,
            Err(_) => return false,
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        // A single sealed chunk is under the frame limit; a larger length means
        // a corrupt blob, so refuse it rather than allocate a huge buffer.
        if len > SIGNALING_MSG_LIMIT {
            return false;
        }
        let mut buf = vec![0u8; len];
        if f.read_exact(&mut buf).await.is_err() {
            return false;
        }
        let msg = ServerMsg::FileChunk {
            offer_id: d.offer_id,
            from: d.from.clone(),
            data: Sealed(buf),
        };
        // Backpressure: awaits until the recipient's outbound has room.
        if out.send(&msg).await.is_err() {
            return false; // recipient disconnected
        }
    }
}

/// Deliver a batch of `Outgoing` to their connections' outbound queues
/// (non-blocking), for notifications produced outside the main dispatch loop.
fn dispatch_now(state: &Arc<Mutex<ServerState>>, outgoing: Vec<Outgoing>) {
    if outgoing.is_empty() {
        return;
    }
    let s = state.lock().unwrap();
    for o in outgoing {
        if let Some(out) = s.txs.get(&o.to) {
            out.try_send(&o.msg);
        }
    }
}

/// Periodically sweep lapsed file offers and deliver the resulting notifications.
fn spawn_file_sweeper(state: Arc<Mutex<ServerState>>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(FILE_SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            let sends: Vec<(Outbound, ServerMsg)> = {
                let mut s = state.lock().unwrap();
                let outgoing = s.relay.sweep_files();
                outgoing
                    .into_iter()
                    .filter_map(|o| s.txs.get(&o.to).cloned().map(|out| (out, o.msg)))
                    .collect()
            };
            for (out, msg) in sends {
                out.try_send(&msg);
            }
        }
    });
}

#[cfg(test)]
mod outbound_tests {
    use super::*;
    use enclave_protocol::ServerMsg;

    // A control message whose serialized size is about `bytes`.
    fn msg(bytes: usize) -> ServerMsg {
        ServerMsg::Error {
            detail: "x".repeat(bytes),
        }
    }

    // Count (and drop) everything currently queued, releasing its permits.
    fn drain(rx: &mut mpsc::UnboundedReceiver<Framed>) -> usize {
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        n
    }

    #[tokio::test]
    async fn try_send_bounds_the_control_budget_and_drops_the_rest() {
        let (out, mut rx) = Outbound::new();
        // ~1 MiB each; the 4 MiB control budget holds a few, the rest are dropped
        // (never blocks, never grows without bound).
        for _ in 0..16 {
            out.try_send(&msg(1024 * 1024));
        }
        let queued = drain(&mut rx);
        assert!(
            (1..=4).contains(&queued),
            "control budget bounded the queue, got {queued}"
        );
    }

    #[tokio::test]
    async fn draining_frames_frees_the_budget_again() {
        let (out, mut rx) = Outbound::new();
        for _ in 0..16 {
            out.try_send(&msg(1024 * 1024));
        }
        assert!(drain(&mut rx) > 0);
        // Permits are released as the frames drop, so there is room once more.
        out.try_send(&msg(1024 * 1024));
        assert_eq!(drain(&mut rx), 1, "budget freed after draining");
    }

    #[tokio::test]
    async fn a_saturated_file_stream_never_starves_control() {
        let (out, mut rx) = Outbound::new();
        // Hold the entire file budget, as the blob streamer would while a reader
        // is stalled mid-download.
        let _held = out
            .file_quota
            .clone()
            .acquire_many_owned(MAX_OUTBOUND_FILE_BYTES as u32)
            .await
            .unwrap();
        // Control still flows: the two budgets are independent.
        out.try_send(&msg(1024));
        assert_eq!(
            drain(&mut rx),
            1,
            "control not starved by a full file budget"
        );
    }

    #[tokio::test]
    async fn the_file_budget_backpressures_instead_of_dropping() {
        let (out, mut rx) = Outbound::new();
        // Fill the file budget so no permits remain.
        let _held = out
            .file_quota
            .clone()
            .acquire_many_owned(MAX_OUTBOUND_FILE_BYTES as u32)
            .await
            .unwrap();
        // A file send now blocks (backpressure) rather than dropping; it must not
        // complete until room frees up.
        let m = msg(1024);
        let send = out.send(&m);
        tokio::pin!(send);
        tokio::select! {
            _ = &mut send => panic!("file send should block while the budget is full"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
        // Free the budget; the send now completes.
        drop(_held);
        send.await.expect("send completes once room frees");
        assert_eq!(drain(&mut rx), 1);
    }
}
