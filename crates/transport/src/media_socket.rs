//! Client side of the real-time UDP media channel.
//!
//! Frames are already E2E-sealed by `enclave-crypto` before they get here, so
//! UDP just needs to carry the opaque bytes to the relay with low latency; it
//! is loss-tolerant by design (a dropped frame is a dropped 20 ms of audio, not
//! a stall). On connect the socket announces its endpoint so the relay learns
//! where to forward group frames.

use std::net::SocketAddr;

use enclave_protocol::{DeviceId, GroupId, MediaFrame, UdpMsg};
use tokio::net::UdpSocket;

use crate::error::TransportError;

/// A UDP media channel to the relay for one device in one group.
pub struct MediaSocket {
    sock: UdpSocket,
}

impl MediaSocket {
    /// Bind an ephemeral UDP socket, connect it to the relay, and announce this
    /// device's endpoint and group.
    pub async fn connect(
        server: SocketAddr,
        device: DeviceId,
        group: GroupId,
    ) -> Result<Self, TransportError> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(server).await?;
        let hello = bincode::serialize(&UdpMsg::Hello { device, group })?;
        sock.send(&hello).await?;
        Ok(Self { sock })
    }

    /// Send one sealed frame to the relay for fan-out to the group.
    pub async fn send_frame(&self, frame: &MediaFrame) -> Result<(), TransportError> {
        let bytes = bincode::serialize(&UdpMsg::Frame(frame.clone()))?;
        self.sock.send(&bytes).await?;
        Ok(())
    }

    /// Receive the next media frame forwarded by the relay.
    pub async fn recv_frame(&self) -> Result<MediaFrame, TransportError> {
        let mut buf = vec![0u8; 65_536];
        loop {
            let n = self.sock.recv(&mut buf).await?;
            if let UdpMsg::Frame(frame) = bincode::deserialize::<UdpMsg>(&buf[..n])? {
                return Ok(frame);
            }
            // Ignore anything that is not a frame (the relay only sends frames).
        }
    }
}
