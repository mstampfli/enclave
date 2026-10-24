//! Async client side of the signaling channel: connect to the server (plain
//! `ws://` or TLS `wss://`), send [`ClientMsg`]s, and receive [`ServerMsg`]s.
//! Reader and writer run on their own tasks; the public API is a simple send /
//! async-recv pair.

use std::sync::{Arc, OnceLock};

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

/// Outbound file-chunk queue depth. A large file upload is paced against this
/// bound (see [`Connection::file_capacity`]) so the whole file is never buffered
/// in the client's memory: the sender fills the queue, the writer drains it to
/// the socket at the network's rate, and TCP backpressure from a slow server (or
/// a slow relayed recipient) stalls the fill instead of growing memory. At
/// ~0.5 MiB per sealed chunk this bounds in-flight upload memory to a few MiB.
const FILE_QUEUE_DEPTH: usize = 8;

/// A live signaling connection to the server. Dropping it closes the socket
/// (both I/O tasks are aborted), so the server promptly sees the disconnect.
///
/// Outbound uses two channels: an unbounded one for low-volume control/text, and
/// a bounded one for file chunks so a large upload backpressures (is paced by the
/// socket) rather than buffering the whole file in memory.
pub struct Connection {
    ctrl_tx: mpsc::UnboundedSender<ClientMsg>,
    file_tx: mpsc::Sender<ClientMsg>,
    in_rx: mpsc::UnboundedReceiver<ServerMsg>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

impl Connection {
    /// Connect to `ws://` (plaintext) or `wss://` (TLS, verified against the
    /// operating system's trust store -- see [`system_tls_config`]).
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        if url.starts_with("wss://") {
            return Self::connect_tls_shared(url, system_tls_config()?).await;
        }
        if !url.starts_with("ws://") {
            return Err(TransportError::Tls(
                "server url must start with ws:// or wss://".into(),
            ));
        }
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
        Self::connect_tls_shared(url, Arc::new(config)).await
    }

    async fn connect_tls_shared(
        url: &str,
        config: Arc<rustls::ClientConfig>,
    ) -> Result<Self, TransportError> {
        let (host, port) = parse_wss_authority(url)?;
        let tcp = TcpStream::connect((host.as_str(), port)).await?;
        let connector = TlsConnector::from(config);
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
        let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let (file_tx, mut file_rx) = mpsc::channel::<ClientMsg>(FILE_QUEUE_DEPTH);
        let (in_tx, in_rx) = mpsc::unbounded_channel::<ServerMsg>();

        let writer = tokio::spawn(async move {
            // Drain both queues to the socket, control biased ahead of file
            // chunks so a bulk upload never starves latency-sensitive messages.
            // Each channel is FIFO, so a file's chunks stay ordered and its
            // FileComplete lands after them. `write.send().await` is the point
            // where TCP backpressure reaches back to the bounded file queue.
            loop {
                let msg = tokio::select! {
                    biased;
                    Some(m) = ctrl_rx.recv() => m,
                    Some(m) = file_rx.recv() => m,
                    else => break, // both queues closed
                };
                let Ok(bytes) = serde_json::to_vec(&msg) else {
                    continue;
                };
                if write.send(Message::binary(bytes)).await.is_err() {
                    break;
                }
            }
        });

        let reader = tokio::spawn(async move {
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

        Self {
            ctrl_tx,
            file_tx,
            in_rx,
            reader,
            writer,
        }
    }

    /// Queue a control/text message to the server. Non-blocking.
    pub fn send(&self, msg: ClientMsg) {
        let _ = self.ctrl_tx.send(msg);
    }

    /// Free slots in the bounded file-chunk queue right now. Zero means the
    /// upload should pause (backpressure) until the writer drains to the socket.
    /// The upload pump is the only producer, so a non-zero reading guarantees the
    /// next [`try_send_file`](Self::try_send_file) is accepted.
    pub fn file_capacity(&self) -> usize {
        self.file_tx.capacity()
    }

    /// Queue one file chunk (or a file's `FileComplete`). Returns `false` without
    /// queuing if the bounded file queue is full -- the caller pauses and retries
    /// once [`file_capacity`](Self::file_capacity) frees. Non-blocking.
    pub fn try_send_file(&self, msg: ClientMsg) -> bool {
        self.file_tx.try_send(msg).is_ok()
    }

    /// Await the next message from the server, or `None` if the connection
    /// closed.
    pub async fn recv(&mut self) -> Option<ServerMsg> {
        self.in_rx.recv().await
    }
}

/// The TLS client config for `wss://` servers: the operating system's trust
/// store (Windows certificate store, the distro CA bundle on Linux), so a relay
/// behind a public CA works out of the box and an operator's private CA works
/// once it is installed system-wide. Built once: reconnects reuse it rather than
/// re-reading the store.
fn system_tls_config() -> Result<Arc<rustls::ClientConfig>, TransportError> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            // Unreadable individual certificates are skipped, not fatal; only
            // an empty store is, since it would reject every server.
            let (added, _ignored) =
                roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            if added == 0 {
                return Err("no trusted root certificates found on this system".into());
            }
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
        .map_err(TransportError::Tls)
}

/// Split `wss://host[:port]/...` into `(host, port)`; the port defaults to 443.
/// An IPv6 literal must be bracketed (`wss://[::1]:8443`), as in any URL.
fn parse_wss_authority(url: &str) -> Result<(String, u16), TransportError> {
    let rest = url
        .strip_prefix("wss://")
        .ok_or_else(|| TransportError::Tls("url must start with wss://".into()))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6
            .split_once(']')
            .ok_or_else(|| TransportError::Tls("unterminated [ in wss url".into()))?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(TransportError::Tls("wss url has no host".into()));
    }
    let port = match port {
        Some(p) => p
            .parse()
            .map_err(|_| TransportError::Tls("invalid port in wss url".into()))?,
        None => 443,
    };
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::parse_wss_authority;

    fn parse(url: &str) -> Option<(String, u16)> {
        parse_wss_authority(url).ok()
    }

    #[test]
    fn explicit_port() {
        assert_eq!(
            parse("wss://localhost:8443"),
            Some(("localhost".into(), 8443))
        );
    }

    #[test]
    fn port_defaults_to_443() {
        let want = Some(("relay.example.com".into(), 443));
        assert_eq!(parse("wss://relay.example.com"), want);
        assert_eq!(parse("wss://relay.example.com/"), want);
        assert_eq!(parse("wss://relay.example.com/ws?x=1"), want);
    }

    #[test]
    fn bracketed_ipv6() {
        assert_eq!(parse("wss://[::1]:8443"), Some(("::1".into(), 8443)));
        assert_eq!(parse("wss://[fd7a::1]/"), Some(("fd7a::1".into(), 443)));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse("ws://host:1"), None);
        assert_eq!(parse("wss://"), None);
        assert_eq!(parse("wss://:443"), None);
        assert_eq!(parse("wss://host:notaport"), None);
        assert_eq!(parse("wss://host:70000"), None);
        assert_eq!(parse("wss://[::1"), None);
    }
}
