//! Async WebSocket signaling + relay server. Owns one [`Relay`] and drives it:
//! decode each client's [`ClientMsg`], route it through the relay, and ship the
//! resulting [`ServerMsg`]s to the addressed connections. It only ever moves
//! opaque `Sealed` payloads plus routing metadata -- it holds no keys.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use enclave_protocol::{ClientMsg, ServerMsg};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::error::TransportError;
use crate::relay::{ConnId, Relay};

/// Shared server state: the routing brain plus a per-connection outbound queue.
struct ServerState {
    relay: Relay,
    txs: HashMap<ConnId, mpsc::UnboundedSender<ServerMsg>>,
}

/// A running server. Dropping it does not stop the accept loop (it runs on a
/// detached task); keep the process alive to keep serving.
pub struct ServerHandle {
    pub addr: SocketAddr,
}

/// Bind and start serving on `addr` (e.g. `"127.0.0.1:0"` for an ephemeral
/// port). Returns once bound; the accept loop runs on a background task.
pub async fn serve(addr: &str) -> Result<ServerHandle, TransportError> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    let state = Arc::new(Mutex::new(ServerState {
        relay: Relay::new(),
        txs: HashMap::new(),
    }));

    tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            tokio::spawn(handle_conn(stream, state.clone()));
        }
    });

    Ok(ServerHandle { addr: local })
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

        // Route under the lock; resolve target senders; release before sending
        // so we never hold the lock across a channel operation.
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
