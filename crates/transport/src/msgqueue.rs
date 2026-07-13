//! Store-and-forward queue for members who are offline. When the relay fans a
//! group message (text, MLS handshake, or a Welcome) to a member who is not
//! connected, it parks the message here and delivers it on that member's next
//! login. Every queued payload is opaque [`Sealed`](enclave_protocol::Sealed)
//! ciphertext -- the server stores it but cannot read it.
//!
//! # Bounds (DoS mitigation, ASVS V11)
//!
//! The queue is bounded so a peer cannot pin unbounded server memory/disk by
//! spamming an offline victim (or many victims). Each device has a byte and a
//! message-count cap; when a new message would overflow the victim's queue, the
//! *oldest* queued messages are evicted to make room (recent delivery matters
//! more than old). A global byte cap is a backstop: once the whole queue is
//! full, new messages are refused rather than evicting another device's data.
//!
//! Large payloads do not belong here: files use the on-disk file store and the
//! live streaming path, never this queue, so in normal use it holds only small
//! text and control messages and the caps never bite.
//!
//! Persisted to JSON so an offline member's messages survive a server restart.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use enclave_protocol::ServerMsg;

/// Bytes one device may hold queued before its oldest messages are evicted.
pub const MAX_QUEUE_BYTES_PER_DEVICE: usize = 4 * 1024 * 1024;
/// Messages one device may hold queued before its oldest are evicted.
pub const MAX_QUEUE_MSGS_PER_DEVICE: usize = 2000;
/// Total bytes across all devices before new messages are refused.
pub const MAX_QUEUE_BYTES_TOTAL: usize = 128 * 1024 * 1024;

/// A device's queue plus its running byte size (kept in sync with `messages`
/// so bounds are O(1) to check, never recomputed per enqueue).
#[derive(Default)]
struct DeviceQueue {
    messages: Vec<ServerMsg>,
    bytes: usize,
}

/// On-disk form: a JSON object cannot key by an arbitrary type cleanly, so the
/// per-device queues are a list.
#[derive(Serialize, Deserialize)]
struct QueuedFor {
    device: String,
    messages: Vec<ServerMsg>,
}

/// A persistent, bounded per-device outbound queue for offline delivery.
#[derive(Default)]
pub struct MessageQueue {
    by_device: HashMap<String, DeviceQueue>,
    total_bytes: usize,
    path: Option<PathBuf>,
}

/// Approximate on-wire size of a queued message, for byte accounting.
fn msg_size(msg: &ServerMsg) -> usize {
    serde_json::to_vec(msg).map(|v| v.len()).unwrap_or(0)
}

impl MessageQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file (empty if absent); persist future changes back.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut total_bytes = 0;
        let by_device: HashMap<String, DeviceQueue> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<Vec<QueuedFor>>(&t).ok())
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|e| {
                        let bytes: usize = e.messages.iter().map(msg_size).sum();
                        total_bytes += bytes;
                        (
                            e.device,
                            DeviceQueue {
                                messages: e.messages,
                                bytes,
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            by_device,
            total_bytes,
            path: Some(path),
        }
    }

    /// Park `msg` for `device`, to deliver when it next comes online. Returns
    /// `false` if the message was refused (the whole queue is at its global
    /// cap); enforcing the per-device cap evicts that device's oldest messages
    /// rather than refusing.
    pub fn enqueue(&mut self, device: &str, msg: ServerMsg) -> bool {
        let size = msg_size(&msg);
        // A single message larger than a whole device budget can never fit; it
        // is refused outright (in practice only a pathological control message).
        if size > MAX_QUEUE_BYTES_PER_DEVICE {
            return false;
        }
        // Global backstop: if even after evicting this device's own history the
        // total would exceed the global cap, refuse rather than evict a
        // different, innocent device's queue.
        let q = self.by_device.entry(device.to_string()).or_default();
        // Evict this device's oldest until the new message fits its caps.
        while q.messages.len() >= MAX_QUEUE_MSGS_PER_DEVICE
            || q.bytes + size > MAX_QUEUE_BYTES_PER_DEVICE
        {
            let Some(old) = q.messages.first().cloned() else {
                break;
            };
            let osz = msg_size(&old);
            q.messages.remove(0);
            q.bytes = q.bytes.saturating_sub(osz);
            self.total_bytes = self.total_bytes.saturating_sub(osz);
        }
        if self.total_bytes + size > MAX_QUEUE_BYTES_TOTAL {
            // Clean up an empty entry we may have just created.
            if q.messages.is_empty() {
                self.by_device.remove(device);
            }
            return false;
        }
        let q = self.by_device.entry(device.to_string()).or_default();
        q.messages.push(msg);
        q.bytes += size;
        self.total_bytes += size;
        self.save();
        true
    }

    /// Remove and return everything queued for `device` (its delivery, in order).
    pub fn take(&mut self, device: &str) -> Vec<ServerMsg> {
        let Some(q) = self.by_device.remove(device) else {
            return Vec::new();
        };
        self.total_bytes = self.total_bytes.saturating_sub(q.bytes);
        if !q.messages.is_empty() {
            self.save();
        }
        q.messages
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let entries: Vec<QueuedFor> = self
            .by_device
            .iter()
            .map(|(device, q)| QueuedFor {
                device: device.clone(),
                messages: q.messages.clone(),
            })
            .collect();
        if let Ok(text) = serde_json::to_string(&entries) {
            let _ = std::fs::write(path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_protocol::{GroupId, Sealed};

    fn text(byte: u8) -> ServerMsg {
        ServerMsg::Text {
            group: GroupId([1u8; 32]),
            from: enclave_protocol::DeviceId("alice".into()),
            message: Sealed(vec![byte]),
        }
    }

    #[test]
    fn enqueue_then_take_delivers_in_order_once() {
        let mut q = MessageQueue::new();
        q.enqueue("bob", text(1));
        q.enqueue("bob", text(2));
        let got = q.take("bob");
        assert_eq!(got.len(), 2);
        assert!(matches!(&got[0], ServerMsg::Text { message, .. } if message.0 == vec![1]));
        assert!(matches!(&got[1], ServerMsg::Text { message, .. } if message.0 == vec![2]));
        // Draining is one-shot.
        assert!(q.take("bob").is_empty());
    }

    #[test]
    fn queue_survives_reload() {
        let path =
            std::env::temp_dir().join(format!("enclave-queue-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut q = MessageQueue::load(&path);
            q.enqueue("bob", text(7));
        }
        let mut q = MessageQueue::load(&path);
        let got = q.take("bob");
        assert_eq!(got.len(), 1);
        assert!(matches!(&got[0], ServerMsg::Text { message, .. } if message.0 == vec![7]));
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    use enclave_protocol::{DeviceId, GroupId, Sealed};

    fn sized(bytes: usize) -> ServerMsg {
        ServerMsg::Text {
            group: GroupId([1u8; 32]),
            from: DeviceId("a".into()),
            message: Sealed(vec![0u8; bytes]),
        }
    }

    #[test]
    fn per_device_byte_cap_evicts_oldest() {
        let mut q = MessageQueue::new();
        // Each message is ~ (base64 of N bytes) plus JSON framing. Push enough
        // ~1 MiB messages that the 4 MiB per-device cap must evict the oldest.
        for i in 0..10u8 {
            let mut m = sized(1024 * 1024);
            // Tag the first byte so we can identify which survive.
            if let ServerMsg::Text { message, .. } = &mut m {
                message.0[0] = i;
            }
            assert!(q.enqueue("victim", m), "under the global cap");
        }
        let got = q.take("victim");
        let total: usize = got.iter().map(msg_size).sum();
        assert!(
            total <= MAX_QUEUE_BYTES_PER_DEVICE,
            "queue stayed under the per-device byte cap, was {total}"
        );
        // The survivors are the most recent, so the last message pushed is kept.
        let last_tag = got
            .last()
            .and_then(|m| match m {
                ServerMsg::Text { message, .. } => Some(message.0[0]),
                _ => None,
            })
            .unwrap();
        assert_eq!(last_tag, 9, "the newest message survives eviction");
    }

    #[test]
    fn per_device_count_cap_is_enforced() {
        let mut q = MessageQueue::new();
        for _ in 0..(MAX_QUEUE_MSGS_PER_DEVICE + 50) {
            q.enqueue("v", sized(1));
        }
        assert!(q.take("v").len() <= MAX_QUEUE_MSGS_PER_DEVICE);
    }

    #[test]
    fn global_cap_refuses_when_full_without_evicting_other_devices() {
        let mut q = MessageQueue::new();
        // Fill many devices near the global cap with ~1 MiB each.
        let per = 1024 * 1024;
        let devices = MAX_QUEUE_BYTES_TOTAL / per + 8;
        let mut accepted = 0;
        for d in 0..devices {
            if q.enqueue(&format!("dev{d}"), sized(per)) {
                accepted += 1;
            }
        }
        assert!(q.total_bytes <= MAX_QUEUE_BYTES_TOTAL, "global cap held");
        assert!(
            accepted < devices,
            "some enqueues were refused once the global cap was reached"
        );
        // An early device's data was not evicted to make room for a later one.
        assert!(
            !q.take("dev0").is_empty(),
            "an innocent device kept its data"
        );
    }

    #[test]
    fn an_oversized_single_message_is_refused() {
        let mut q = MessageQueue::new();
        assert!(!q.enqueue("v", sized(MAX_QUEUE_BYTES_PER_DEVICE + 1)));
        assert!(q.take("v").is_empty());
    }
}
