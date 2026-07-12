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
use std::sync::{Arc, Mutex};

use enclave_crypto::{MediaOpener, MediaSealer, MediaSigner};
use enclave_media::{AudioCapture, AudioDecoder, AudioEncoder, AudioPlayback, PlaybackSink};
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
    /// This sender's private signer, to authenticate every outgoing frame.
    pub signer: MediaSigner,
    /// username -> identity key, to derive each sender's media key on receive.
    pub member_keys: HashMap<String, Vec<u8>>,
    /// Selected input device name, or `None` for the host default.
    pub input_device: Option<String>,
    /// Selected output device name, or `None` for the host default.
    pub output_device: Option<String>,
}

/// An in-progress voice call. Dropping it tears the whole pipeline down.
pub struct Call {
    // cpal streams are !Send; they live here, on the controller thread. Both are
    // swappable while the call runs (live device switching): the capture feeds a
    // stable channel and the decode thread pushes through a swappable sink slot,
    // so replacing either device never disturbs the worker threads or the crypto.
    capture: AudioCapture,
    playback: AudioPlayback,
    /// Kept open so the capture device can be swapped without the capture thread
    /// (which owns the receiving end) ever seeing the channel close.
    mic_tx: std_mpsc::Sender<Vec<i16>>,
    /// The decode thread pushes decoded audio through this; swapping the output
    /// device just replaces the sink inside.
    sink_slot: Arc<Mutex<PlaybackSink>>,
    send_task: JoinHandle<()>,
    recv_task: JoinHandle<()>,
    input_device: Option<String>,
    output_device: Option<String>,
}

impl Call {
    pub async fn start(p: CallParams) -> Result<Self, ClientError> {
        // A stable mic channel owned by the call: the capture device sends into a
        // clone of `mic_tx`, and the capture thread reads `mic_rx`. Swapping the
        // device replaces only the sender clone, so the thread never restarts.
        let (mic_tx, mic_rx) = std_mpsc::channel::<Vec<i16>>();
        let capture = AudioCapture::start_on_into(p.input_device.as_deref(), mic_tx.clone())
            .map_err(audio)?;
        let playback = AudioPlayback::start_on(p.output_device.as_deref()).map_err(audio)?;
        let sink_slot = Arc::new(Mutex::new(playback.sink()));

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
        let out_signer = p.signer;
        std::thread::spawn(move || {
            let mut sealer = match MediaSealer::new(
                &out_root,
                out_group,
                DeviceId(out_me),
                &out_key,
                epoch,
                out_signer,
            ) {
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
        let decode_sink = sink_slot.clone();
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
                        decode_sink.lock().unwrap().push(&pcm);
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
            capture,
            playback,
            mic_tx,
            sink_slot,
            send_task,
            recv_task,
            input_device: p.input_device,
            output_device: p.output_device,
        })
    }

    /// Switch the microphone mid-call. Builds the new capture before dropping the
    /// old one, so a device that fails to open leaves the current call untouched.
    /// The capture thread and crypto are undisturbed -- only the device feeding
    /// the stable mic channel changes.
    pub fn set_input_device(&mut self, name: Option<&str>) -> Result<(), ClientError> {
        if self.input_device.as_deref() == name {
            return Ok(());
        }
        let new_capture = AudioCapture::start_on_into(name, self.mic_tx.clone()).map_err(audio)?;
        self.capture = new_capture; // old capture drops -> its input stream stops
        self.input_device = name.map(str::to_owned);
        Ok(())
    }

    /// Switch the speaker mid-call. Builds the new output before dropping the old
    /// one, then swaps the sink the decode thread pushes through.
    pub fn set_output_device(&mut self, name: Option<&str>) -> Result<(), ClientError> {
        if self.output_device.as_deref() == name {
            return Ok(());
        }
        let new_playback = AudioPlayback::start_on(name).map_err(audio)?;
        *self.sink_slot.lock().unwrap() = new_playback.sink();
        self.playback = new_playback; // old playback drops -> its output stream stops
        self.output_device = name.map(str::to_owned);
        Ok(())
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        // Stop the async tasks; dropping the cpal streams and `mic_tx` closes the
        // mic channel (ending the capture thread) and stops playback. Aborting
        // recv_task drops the raw-frame sender, ending the decode thread.
        self.send_task.abort();
        self.recv_task.abort();
    }
}

fn audio(e: enclave_media::MediaError) -> ClientError {
    ClientError::Audio(e.to_string())
}
