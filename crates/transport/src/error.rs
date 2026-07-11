//! Transport-layer errors (socket + WebSocket handshake failures).

/// Errors from establishing or running a signaling connection.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("media codec error: {0}")]
    Codec(#[from] bincode::Error),

    #[error("tls error: {0}")]
    Tls(String),
}
