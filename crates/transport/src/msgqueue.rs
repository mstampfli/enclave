//! Store-and-forward queue for members who are offline. When the relay fans a
//! group message (text, MLS handshake, or a Welcome) to a member who is not
//! connected, it parks the message here and delivers it on that member's next
//! login. Every queued payload is opaque [`Sealed`](enclave_protocol::Sealed)
//! ciphertext -- the server stores it but cannot read it.
//!
//! Persisted to JSON so an offline member's messages survive a server restart.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use enclave_protocol::ServerMsg;

/// On-disk form: a JSON object cannot key by an arbitrary type cleanly, so the
/// per-device queues are a list.
#[derive(Serialize, Deserialize)]
struct QueuedFor {
    device: String,
    messages: Vec<ServerMsg>,
}

/// A persistent per-device outbound queue for offline delivery.
#[derive(Default)]
pub struct MessageQueue {
    by_device: HashMap<String, Vec<ServerMsg>>,
    path: Option<PathBuf>,
}

impl MessageQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file (empty if absent); persist future changes back.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let by_device = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<Vec<QueuedFor>>(&t).ok())
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|e| (e.device, e.messages))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            by_device,
            path: Some(path),
        }
    }

    /// Park `msg` for `device`, to deliver when it next comes online.
    pub fn enqueue(&mut self, device: &str, msg: ServerMsg) {
        self.by_device
            .entry(device.to_string())
            .or_default()
            .push(msg);
        self.save();
    }

    /// Remove and return everything queued for `device` (its delivery, in order).
    pub fn take(&mut self, device: &str) -> Vec<ServerMsg> {
        let msgs = self.by_device.remove(device).unwrap_or_default();
        if !msgs.is_empty() {
            self.save();
        }
        msgs
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let entries: Vec<QueuedFor> = self
            .by_device
            .iter()
            .map(|(device, messages)| QueuedFor {
                device: device.clone(),
                messages: messages.clone(),
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
