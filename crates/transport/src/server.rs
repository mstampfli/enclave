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

use enclave_protocol::{ClientMsg, ServerMsg, UdpMsg};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::error::TransportError;
use crate::relay::{ConnId, Relay};

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
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let Ok(msg) = bincode::deserialize::<UdpMsg>(&buf[..n]) else {
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

async fn handle_conn(stream: TcpStream, state: Arc<Mutex<ServerState>>) {
    let ws = match tokio_tungstenite::accept_async(stream).await {
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
    while let Some(Ok(msg)) = read.next().await {
        if matches!(msg, Message::Close(_)) {
            break;
        }
        let Some(bytes) = frame_bytes(msg) else {
            continue;
        };
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

    // Cleanup.
    {
        let mut s = state.lock().unwrap();
        s.relay.disconnect(conn);
        s.txs.remove(&conn);
    }
    writer.abort();
}
