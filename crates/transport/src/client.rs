//! Async client side of the signaling channel: connect to the server, send
//! [`ClientMsg`]s, and receive [`ServerMsg`]s. Reader and writer run on their
//! own tasks; the public API is a simple send / async-recv pair.

use enclave_protocol::{ClientMsg, ServerMsg};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::error::TransportError;

/// A live signaling connection to the server.
pub struct Connection {
    out_tx: mpsc::UnboundedSender<ClientMsg>,
    in_rx: mpsc::UnboundedReceiver<ServerMsg>,
}

impl Connection {
    /// Connect to a signaling server at `url` (e.g. `"ws://127.0.0.1:9000"`).
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        let (ws, _resp) = tokio_tungstenite::connect_async(url).await?;
        let (mut write, mut read) = ws.split();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<ServerMsg>();

        // Writer task.
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                let Ok(bytes) = serde_json::to_vec(&msg) else {
                    continue;
                };
                if write.send(Message::binary(bytes)).await.is_err() {
                    break;
                }
            }
        });

        // Reader task.
        tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                let bytes = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Text(t) => t.as_bytes().to_vec(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                if let Ok(server_msg) = serde_json::from_slice::<ServerMsg>(&bytes) {
                    if in_tx.send(server_msg).is_err() {
                        break;
                    }
                }
            }
        });

        Ok(Self { out_tx, in_rx })
    }

    /// Queue a message to the server. Non-blocking.
    pub fn send(&self, msg: ClientMsg) {
        let _ = self.out_tx.send(msg);
    }

    /// Await the next message from the server, or `None` if the connection
    /// closed.
    pub async fn recv(&mut self) -> Option<ServerMsg> {
        self.in_rx.recv().await
    }
}
