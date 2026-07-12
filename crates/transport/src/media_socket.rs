//! Client side of the real-time UDP media channel.
//!
//! Frames are already E2E-sealed by `enclave-crypto` before they get here, so
//! UDP just needs to carry the opaque bytes to the relay with low latency; it
//! is loss-tolerant by design (a dropped frame is a dropped 20 ms of audio, not
//! a stall). On connect the socket announces its endpoint so the relay learns
//! where to forward group frames.
//!
//! Audio frames fit one datagram; video keyframes do not, so a frame larger
//! than [`FRAGMENT_THRESHOLD`] is split into [`UdpMsg::Fragment`]s and
//! reassembled by the receiver. A frame with a missing fragment is simply
//! dropped -- the next keyframe recovers -- so no retransmission is needed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use bincode::Options;
use enclave_protocol::{DeviceId, GroupId, MediaFrame, UdpMsg};
use tokio::net::UdpSocket;

use crate::error::TransportError;

/// Max size of a UDP media datagram. A frame is a small Opus packet plus a
/// header; this cap keeps a malicious datagram from triggering a huge
/// allocation on deserialize (ASVS V5/V12). Used on both ends so encode and
/// decode agree.
pub(crate) const MEDIA_DATAGRAM_LIMIT: u64 = 64 * 1024;

/// Serialized frames at or below this go in one datagram; larger ones are
/// fragmented. Kept well under a typical MTU so fragments are not IP-fragmented.
const FRAGMENT_THRESHOLD: usize = 1100;
/// Payload bytes per fragment (leaves room for the fragment header).
const FRAGMENT_PAYLOAD: usize = 1024;
/// A reassembled frame may not exceed the datagram limit either.
const MAX_REASSEMBLED: usize = MEDIA_DATAGRAM_LIMIT as usize;
/// How many partially received frames to track before evicting the oldest --
/// bounds memory against a sender who never completes a frame.
const MAX_INFLIGHT: usize = 32;

/// Size-limited bincode config for the UDP media channel.
pub(crate) fn media_codec() -> impl Options {
    bincode::DefaultOptions::new().with_limit(MEDIA_DATAGRAM_LIMIT)
}

/// Reassembles fragmented frames per (sender, frame id). Pure and testable.
#[derive(Default)]
struct Reassembler {
    inflight: HashMap<(String, u32), Partial>,
    /// Insertion order of keys, for oldest-first eviction.
    order: Vec<(String, u32)>,
}

struct Partial {
    count: u16,
    chunks: Vec<Option<Vec<u8>>>,
    have: u16,
    total_len: usize,
}

impl Reassembler {
    /// Add one fragment; returns the reassembled frame bytes once the last
    /// fragment of that frame arrives (order-independent, duplicate-safe).
    fn add(
        &mut self,
        sender: String,
        id: u32,
        index: u16,
        count: u16,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        if count == 0 || index >= count {
            return None;
        }
        let key = (sender, id);
        let entry = self.inflight.entry(key.clone()).or_insert_with(|| {
            self.order.push(key.clone());
            Partial {
                count,
                chunks: (0..count).map(|_| None).collect(),
                have: 0,
                total_len: 0,
            }
        });
        // A mismatched count for the same id is a corrupt/hostile stream: reset.
        if entry.count != count {
            self.inflight.remove(&key);
            self.order.retain(|k| k != &key);
            return None;
        }
        if entry.chunks[index as usize].is_none() {
            entry.total_len += data.len();
            if entry.total_len > MAX_REASSEMBLED {
                self.inflight.remove(&key);
                self.order.retain(|k| k != &key);
                return None;
            }
            entry.chunks[index as usize] = Some(data);
            entry.have += 1;
        }
        if entry.have == entry.count {
            let partial = self.inflight.remove(&key)?;
            self.order.retain(|k| k != &key);
            let mut out = Vec::with_capacity(partial.total_len);
            for chunk in partial.chunks {
                out.extend_from_slice(&chunk?);
            }
            return Some(out);
        }
        // Bound memory: evict the oldest partial if too many are in flight.
        while self.order.len() > MAX_INFLIGHT {
            let oldest = self.order.remove(0);
            self.inflight.remove(&oldest);
        }
        None
    }
}

/// A UDP media channel to the relay for one device in one group.
pub struct MediaSocket {
    sock: UdpSocket,
    next_frag_id: AtomicU32,
    reasm: Mutex<Reassembler>,
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
        let hello = media_codec().serialize(&UdpMsg::Hello { device, group })?;
        sock.send(&hello).await?;
        Ok(Self {
            sock,
            next_frag_id: AtomicU32::new(0),
            reasm: Mutex::new(Reassembler::default()),
        })
    }

    /// Send one sealed frame to the relay for fan-out to the group. Small frames
    /// go in one datagram; a large frame (video) is split into fragments.
    pub async fn send_frame(&self, frame: &MediaFrame) -> Result<(), TransportError> {
        let one = media_codec().serialize(&UdpMsg::Frame(frame.clone()))?;
        if one.len() <= FRAGMENT_THRESHOLD {
            self.sock.send(&one).await?;
            return Ok(());
        }
        let frame_bytes = media_codec().serialize(frame)?;
        let id = self.next_frag_id.fetch_add(1, Ordering::Relaxed);
        let count = frame_bytes.len().div_ceil(FRAGMENT_PAYLOAD) as u16;
        for (i, chunk) in frame_bytes.chunks(FRAGMENT_PAYLOAD).enumerate() {
            let msg = UdpMsg::Fragment {
                group: frame.group.clone(),
                sender: frame.sender.clone(),
                id,
                index: i as u16,
                count,
                data: chunk.to_vec(),
            };
            let dg = media_codec().serialize(&msg)?;
            self.sock.send(&dg).await?;
        }
        Ok(())
    }

    /// Receive the next media frame forwarded by the relay, reassembling
    /// fragments as needed.
    pub async fn recv_frame(&self) -> Result<MediaFrame, TransportError> {
        let mut buf = vec![0u8; 65_536];
        loop {
            let n = self.sock.recv(&mut buf).await?;
            match media_codec().deserialize::<UdpMsg>(&buf[..n])? {
                UdpMsg::Frame(frame) => return Ok(frame),
                UdpMsg::Fragment {
                    sender,
                    id,
                    index,
                    count,
                    data,
                    ..
                } => {
                    let done = self
                        .reasm
                        .lock()
                        .unwrap()
                        .add(sender.0, id, index, count, data);
                    if let Some(bytes) = done {
                        if let Ok(frame) = media_codec().deserialize::<MediaFrame>(&bytes) {
                            return Ok(frame);
                        }
                    }
                }
                UdpMsg::Hello { .. } => {} // the relay never sends Hello to us
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_out_of_order_and_ignores_duplicates() {
        let mut r = Reassembler::default();
        // 3 fragments of "HELLOWORLD!!" split as HELLO / WORLD / !!.
        assert_eq!(r.add("a".into(), 1, 2, 3, b"WORLD".to_vec()), None);
        assert_eq!(r.add("a".into(), 1, 2, 3, b"WORLD".to_vec()), None, "dup");
        assert_eq!(r.add("a".into(), 1, 0, 3, b"HELLO".to_vec()), None);
        let done = r.add("a".into(), 1, 1, 3, b"WORLD".to_vec());
        // index 1 is still missing (we sent index 2 twice, index 0, now index 1).
        assert_eq!(done, Some(b"HELLOWORLDWORLD".to_vec()));
    }

    #[test]
    fn separate_senders_and_ids_do_not_mix() {
        let mut r = Reassembler::default();
        assert_eq!(r.add("a".into(), 1, 0, 2, b"aa".to_vec()), None);
        assert_eq!(r.add("b".into(), 1, 0, 2, b"bb".to_vec()), None);
        assert_eq!(
            r.add("a".into(), 2, 0, 1, b"z".to_vec()),
            Some(b"z".to_vec())
        );
        assert_eq!(
            r.add("a".into(), 1, 1, 2, b"AA".to_vec()),
            Some(b"aaAA".to_vec())
        );
        assert_eq!(
            r.add("b".into(), 1, 1, 2, b"BB".to_vec()),
            Some(b"bbBB".to_vec())
        );
    }

    #[test]
    fn rejects_bad_indices() {
        let mut r = Reassembler::default();
        assert_eq!(r.add("a".into(), 1, 0, 0, b"x".to_vec()), None, "count 0");
        assert_eq!(
            r.add("a".into(), 1, 5, 3, b"x".to_vec()),
            None,
            "index>=count"
        );
    }
}
