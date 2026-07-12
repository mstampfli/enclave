//! Voice call wiring for one conversation:
//!   mic -> Opus encode -> SFrame seal -> UDP   (outbound)
//!   UDP -> SFrame open -> Opus decode -> speaker (inbound)
//!
//! Threading: cpal streams and the Opus codec are `!Send`, so the encode/seal
//! and decode/play work runs on dedicated OS threads; two async tasks bridge
//! those threads to the (async) UDP media socket. The cpal `Stream` handles
//! stay in [`Call`] on the controller thread.
//!
//! HARDWARE PATH: the mic/speaker path cannot be exercised headlessly; it is
//! compile-verified and must be validated on a real device.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;

use enclave_crypto::{MediaOpener, MediaSealer};
use enclave_media::{AudioCapture, AudioDecoder, AudioEncoder, AudioPlayback};
use enclave_protocol::{DeviceId, GroupId, MediaFrame, MediaKind};
use enclave_transport::MediaSocket;
use tokio::task::JoinHandle;

use crate::ClientError;

/// Everything a call needs, gathered from the live conversation before the
/// (non-`Send`) audio parts are spun up. All fields are plain `Send` bytes so
/// the crypto can be built on the worker threads.
pub struct CallParams {
    pub media_addr: SocketAddr,
    pub group: GroupId,
    pub me: String,
    pub root_secret: Vec<u8>,
    pub my_identity_key: Vec<u8>,
    /// username -> identity key, to derive each sender's media key on receive.
    pub member_keys: HashMap<String, Vec<u8>>,
}

/// An in-progress voice call. Dropping it tears the whole pipeline down.
pub struct Call {
    // cpal streams are !Send; they live here, on the controller thread.
    _capture: AudioCapture,
    _playback: AudioPlayback,
    send_task: JoinHandle<()>,
    recv_task: JoinHandle<()>,
}

impl Call {
    pub async fn start(p: CallParams) -> Result<Self, ClientError> {
        let (capture, mic_rx) = AudioCapture::start().map_err(audio)?;
        let playback = AudioPlayback::start().map_err(audio)?;
        let sink = playback.sink();

        let socket = Arc::new(
            MediaSocket::connect(p.media_addr, DeviceId(p.me.clone()), p.group.clone()).await?,
        );

        // Outbound: a fresh per-call media epoch so keys never repeat across
        // calls; the receiver reads it from each frame.
        let mut epoch_bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut epoch_bytes);
        let epoch = u64::from_le_bytes(epoch_bytes);

        // Capture thread: build the (non-Send) encoder + sealer here and never
        // move them across a thread boundary.
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<MediaFrame>();
        let out_group = p.group.clone();
        let out_me = p.me.clone();
        let out_root = p.root_secret.clone();
        let out_key = p.my_identity_key.clone();
        std::thread::spawn(move || {
            let mut sealer =
                match MediaSealer::new(&out_root, out_group, DeviceId(out_me), &out_key, epoch) {
                    Ok(s) => s,
                    Err(_) => return,
                };
            let mut encoder = match AudioEncoder::new() {
                Ok(e) => e,
                Err(_) => return,
            };
            while let Ok(pcm) = mic_rx.recv() {
                let Ok(packet) = encoder.encode(&pcm) else {
                    continue;
                };
                match sealer.seal(MediaKind::Audio, &packet) {
                    Ok(frame) => {
                        if frame_tx.send(frame).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Send task: forward sealed frames to the relay over UDP.
        let send_sock = socket.clone();
        let send_task = tokio::spawn(async move {
            while let Some(frame) = frame_rx.recv().await {
                let _ = send_sock.send_frame(&frame).await;
            }
        });

        // Decode thread: build the (non-Send) decoder + per-sender openers here.
        let (raw_tx, raw_rx) = std_mpsc::channel::<MediaFrame>();
        let in_root = p.root_secret;
        let in_group = p.group;
        let members = p.member_keys;
        let in_me = p.me;
        std::thread::spawn(move || {
            let Ok(mut decoder) = AudioDecoder::new() else {
                return;
            };
            let mut openers: HashMap<(String, u64), MediaOpener> = HashMap::new();
            while let Ok(frame) = raw_rx.recv() {
                let sender = frame.sender.0.clone();
                if sender == in_me {
                    continue;
                }
                let Some(sender_key) = members.get(&sender) else {
                    continue;
                };
                let entry = (sender.clone(), frame.epoch);
                if !openers.contains_key(&entry) {
                    match MediaOpener::new(&in_root, &in_group, sender_key, frame.epoch) {
                        Ok(o) => {
                            openers.insert(entry.clone(), o);
                        }
                        Err(_) => continue,
                    }
                }
                let opener = openers.get_mut(&entry).expect("just inserted");
                if let Ok(packet) = opener.open(&frame) {
                    if let Ok(pcm) = decoder.decode(&packet) {
                        sink.push(&pcm);
                    }
                }
            }
        });

        // Recv task: pull frames off the UDP socket and hand them to the decode
        // thread. Only touches `Send` types, so it can be a tokio task.
        let recv_sock = socket;
        let recv_task = tokio::spawn(async move {
            while let Ok(frame) = recv_sock.recv_frame().await {
                if raw_tx.send(frame).is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            _capture: capture,
            _playback: playback,
            send_task,
            recv_task,
        })
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        // Stop the async tasks; dropping the cpal streams stops capture (which
        // closes the mic channel and ends the capture thread) and playback.
        self.send_task.abort();
        self.recv_task.abort();
    }
}

fn audio(e: enclave_media::MediaError) -> ClientError {
    ClientError::Audio(e.to_string())
}
