//! Async client side of the signaling channel: connect to the server (plain
//! `ws://` or TLS `wss://`), send [`ClientMsg`]s, and receive [`ServerMsg`]s.
//! Reader and writer run on their own tasks; the public API is a simple send /
//! async-recv pair.

use std::sync::Arc;

use enclave_protocol::{ClientMsg, ServerMsg};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::error::TransportError;

/// A live signaling connection to the server.
pub struct Connection {
    out_tx: mpsc::UnboundedSender<ClientMsg>,
    in_rx: mpsc::UnboundedReceiver<ServerMsg>,
}

impl Connection {
    /// Connect over plaintext `ws://`.
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        let (ws, _resp) = tokio_tungstenite::connect_async(url).await?;
        Ok(Self::from_ws(ws))
    }

    /// Connect over TLS `wss://`, verifying the server against `config` (ASVS
    /// V9). For a self-hosted self-signed server, put its certificate in the
    /// config's root store.
    pub async fn connect_tls(
        url: &str,
        config: rustls::ClientConfig,
    ) -> Result<Self, TransportError> {
        let (host, port) = parse_wss_authority(url)?;
        let tcp = TcpStream::connect((host.as_str(), port)).await?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name =
            ServerName::try_from(host).map_err(|e| TransportError::Tls(e.to_string()))?;
        let tls = connector.connect(server_name, tcp).await?;
        let (ws, _resp) = tokio_tungstenite::client_async(url, tls).await?;
        Ok(Self::from_ws(ws))
    }

    /// Spawn the reader/writer tasks over an established WebSocket stream,
    /// whatever the underlying transport (plaintext or TLS).
    fn from_ws<S>(ws: WebSocketStream<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut write, mut read) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<ServerMsg>();

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

        Self { out_tx, in_rx }
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

/// Split `wss://host:port/...` into `(host, port)`.
fn parse_wss_authority(url: &str) -> Result<(String, u16), TransportError> {
    let rest = url
        .strip_prefix("wss://")
        .ok_or_else(|| TransportError::Tls("url must start with wss://".into()))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| TransportError::Tls("wss url needs host:port".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TransportError::Tls("invalid port in wss url".into()))?;
    Ok((host.to_string(), port))
}
