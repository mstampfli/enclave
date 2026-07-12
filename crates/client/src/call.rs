//! The real-time media session for one conversation: audio (a call) and,
//! optionally, screen share -- both over the same UDP media socket.
//!
//!   mic   -> Opus encode  -> SFrame seal -> UDP   (outbound audio)
//!   screen-> H.264 encode -> SFrame seal -> UDP   (outbound screen)
//!   UDP -> SFrame open -> demux by kind: Opus decode -> speaker, or
//!                                        H.264 -> the UI (WebCodecs decodes)
//!
//! One [`MediaSealer`] is shared (behind a mutex) by the audio and screen
//! senders so both use one per-sender key + counter sequence; the receiver's
//! per-sender opener handles both, and the frame's [`MediaKind`] selects the
//! path. cpal streams and the codecs are `!Send`, so the work runs on dedicated
//! OS threads bridged to the async socket by two tokio tasks.
//!
//! HARDWARE PATH: the mic/speaker and screen paths cannot be exercised
//! headlessly; they are compile-verified and validated on a real device.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};

use enclave_crypto::{MediaOpener, MediaSealer, MediaSigner};
use enclave_media::{AudioCapture, AudioDecoder, AudioEncoder, AudioPlayback, PlaybackSink};
use enclave_protocol::{DeviceId, GroupId, MediaFrame, MediaKind};
use enclave_transport::MediaSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::ClientError;

/// An H.264 screen frame received from a peer, forwarded to the UI (which
/// decodes it with WebCodecs).
#[derive(Debug, Clone)]
pub struct ScreenFrameOut {
    pub from: String,
    pub h264: Vec<u8>,
    pub keyframe: bool,
}

/// Everything a media session needs, gathered from the live conversation before
/// the (non-`Send`) audio parts are spun up. All fields are plain `Send` bytes.
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
    pub input_device: Option<String>,
    pub output_device: Option<String>,
}

/// A running screen-share sender.
struct ScreenSender {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ScreenSender {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// An in-progress media session (a call, optionally sharing screen). Dropping it
/// tears the whole pipeline down.
pub struct Call {
    capture: AudioCapture,
    playback: AudioPlayback,
    mic_tx: std_mpsc::Sender<Vec<i16>>,
    sink_slot: Arc<Mutex<PlaybackSink>>,
    /// Shared by the audio and screen senders (one key + counter per sender).
    sealer: Arc<Mutex<MediaSealer>>,
    /// Sealed frames go here to be sent over UDP; cloned for the screen sender.
    frame_tx: UnboundedSender<MediaFrame>,
    send_task: JoinHandle<()>,
    recv_task: JoinHandle<()>,
    input_device: Option<String>,
    output_device: Option<String>,
    screen: Option<ScreenSender>,
}

impl Call {
    /// Start the session (audio). Returns the [`Call`] and a receiver of incoming
    /// screen frames for the controller to forward to the UI.
    pub async fn start(
        p: CallParams,
    ) -> Result<(Self, UnboundedReceiver<ScreenFrameOut>), ClientError> {
        let (mic_tx, mic_rx) = std_mpsc::channel::<Vec<i16>>();
        let capture = AudioCapture::start_on_into(p.input_device.as_deref(), mic_tx.clone())
            .map_err(audio)?;
        let playback = AudioPlayback::start_on(p.output_device.as_deref()).map_err(audio)?;
        let sink_slot = Arc::new(Mutex::new(playback.sink()));

        let socket = Arc::new(
            MediaSocket::connect(p.media_addr, DeviceId(p.me.clone()), p.group.clone()).await?,
        );

        // A fresh per-session media epoch so keys never repeat across sessions.
        let mut epoch_bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut epoch_bytes);
        let epoch = u64::from_le_bytes(epoch_bytes);

        // The one sealer for this sender, shared by audio + screen.
        let sealer = MediaSealer::new(
            &p.root_secret,
            p.group.clone(),
            DeviceId(p.me.clone()),
            &p.my_identity_key,
            epoch,
            p.signer,
        )
        .map_err(|e| ClientError::Audio(e.to_string()))?;
        let sealer = Arc::new(Mutex::new(sealer));

        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<MediaFrame>();

        // Audio capture thread: Opus-encode mic frames and seal them.
        let audio_sealer = sealer.clone();
        let audio_frame_tx = frame_tx.clone();
        std::thread::spawn(move || {
            let mut encoder = match AudioEncoder::new() {
                Ok(e) => e,
                Err(_) => return,
            };
            while let Ok(pcm) = mic_rx.recv() {
                let Ok(packet) = encoder.encode(&pcm) else {
                    continue;
                };
                let sealed = audio_sealer.lock().unwrap().seal(MediaKind::Audio, &packet);
                match sealed {
                    Ok(frame) => {
                        if audio_frame_tx.send(frame).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Send task: forward sealed frames (audio + screen) to the relay.
        let send_sock = socket.clone();
        let send_task = tokio::spawn(async move {
            while let Some(frame) = frame_rx.recv().await {
                let _ = send_sock.send_frame(&frame).await;
            }
        });

        // Decode thread: open each frame and demux by kind -- audio to the
        // speaker, screen to the UI.
        let (raw_tx, raw_rx) = std_mpsc::channel::<MediaFrame>();
        let (screen_tx, screen_rx) = tokio::sync::mpsc::unbounded_channel::<ScreenFrameOut>();
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
                let Ok(packet) = opener.open(&frame) else {
                    continue;
                };
                match frame.kind {
                    MediaKind::Audio => {
                        if let Ok(pcm) = decoder.decode(&packet) {
                            decode_sink.lock().unwrap().push(&pcm);
                        }
                    }
                    MediaKind::Screen | MediaKind::Video => {
                        let keyframe = is_h264_keyframe(&packet);
                        let _ = screen_tx.send(ScreenFrameOut {
                            from: sender.clone(),
                            h264: packet,
                            keyframe,
                        });
                    }
                }
            }
        });

        // Recv task: pull frames off the UDP socket into the decode thread.
        let recv_sock = socket;
        let recv_task = tokio::spawn(async move {
            while let Ok(frame) = recv_sock.recv_frame().await {
                if raw_tx.send(frame).is_err() {
                    break;
                }
            }
        });

        let call = Self {
            capture,
            playback,
            mic_tx,
            sink_slot,
            sealer,
            frame_tx,
            send_task,
            recv_task,
            input_device: p.input_device,
            output_device: p.output_device,
            screen: None,
        };
        Ok((call, screen_rx))
    }

    /// Whether we are currently sharing our screen.
    pub fn is_sharing(&self) -> bool {
        self.screen.is_some()
    }

    /// Switch the microphone mid-session (see the device-swap notes on capture).
    pub fn set_input_device(&mut self, name: Option<&str>) -> Result<(), ClientError> {
        if self.input_device.as_deref() == name {
            return Ok(());
        }
        let new_capture = AudioCapture::start_on_into(name, self.mic_tx.clone()).map_err(audio)?;
        self.capture = new_capture;
        self.input_device = name.map(str::to_owned);
        Ok(())
    }

    /// Switch the speaker mid-session.
    pub fn set_output_device(&mut self, name: Option<&str>) -> Result<(), ClientError> {
        if self.output_device.as_deref() == name {
            return Ok(());
        }
        let new_playback = AudioPlayback::start_on(name).map_err(audio)?;
        *self.sink_slot.lock().unwrap() = new_playback.sink();
        self.playback = new_playback;
        self.output_device = name.map(str::to_owned);
        Ok(())
    }

    /// Start sharing the primary screen: capture -> H.264 -> seal (via the shared
    /// sealer) -> send, on a dedicated thread. A keyframe is emitted periodically
    /// so a viewer who joins mid-share recovers within a couple of seconds.
    #[cfg(windows)]
    pub fn start_screen(&mut self) -> Result<(), ClientError> {
        use enclave_media::{H264Encoder, ScreenCapture};
        use std::time::{Duration, Instant};

        if self.screen.is_some() {
            return Ok(());
        }
        let capture = ScreenCapture::start_primary().map_err(audio)?;
        let sealer = self.sealer.clone();
        let frame_tx = self.frame_tx.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut encoder = match H264Encoder::new(6_000_000, 30.0) {
                Ok(e) => e,
                Err(_) => return,
            };
            let target = Duration::from_millis(33); // ~30 fps
            let mut n: u64 = 0;
            while !s.load(Ordering::Relaxed) {
                let started = Instant::now();
                if let Some(cf) = capture.latest() {
                    // Crop to even dimensions, de-stride if the width is odd.
                    let w = cf.width & !1;
                    let h = cf.height & !1;
                    let tight = if w == cf.width {
                        cf.bgra[..w * h * 4].to_vec()
                    } else {
                        let mut t = Vec::with_capacity(w * h * 4);
                        for row in 0..h {
                            let off = row * cf.width * 4;
                            t.extend_from_slice(&cf.bgra[off..off + w * 4]);
                        }
                        t
                    };
                    let force_key = n.is_multiple_of(60); // keyframe every ~2 s and at start
                    if let Ok((h264, _key)) = encoder.encode(&tight, w, h, force_key) {
                        if !h264.is_empty() {
                            let sealed = sealer.lock().unwrap().seal(MediaKind::Screen, &h264);
                            if let Ok(frame) = sealed {
                                if frame_tx.send(frame).is_err() {
                                    break;
                                }
                            }
                            n += 1;
                        }
                    }
                }
                let elapsed = started.elapsed();
                if elapsed < target {
                    std::thread::sleep(target - elapsed);
                }
            }
        });
        self.screen = Some(ScreenSender {
            stop,
            thread: Some(thread),
        });
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn start_screen(&mut self) -> Result<(), ClientError> {
        Err(ClientError::Audio("screen share is Windows-only".into()))
    }

    /// Stop sharing the screen (keeps the call running).
    pub fn stop_screen(&mut self) {
        self.screen = None; // Drop stops the thread and the capture.
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        self.send_task.abort();
        self.recv_task.abort();
        // Dropping the fields stops capture/playback/screen and closes channels.
    }
}

/// Whether an Annex-B H.264 access unit contains a keyframe NAL (IDR type 5 or
/// SPS type 7), so the viewer can tag the WebCodecs chunk as `key`.
fn is_h264_keyframe(annexb: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 < annexb.len() {
        if annexb[i] == 0 && annexb[i + 1] == 0 && annexb[i + 2] == 1 {
            let nal_type = annexb[i + 3] & 0x1f;
            if nal_type == 5 || nal_type == 7 {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

fn audio(e: enclave_media::MediaError) -> ClientError {
    ClientError::Audio(e.to_string())
}
