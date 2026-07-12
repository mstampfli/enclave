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

/// An H.264 video frame to show in the UI (which decodes it with WebCodecs).
/// Either a peer's frame (received + opened) or our own camera, looped back for
/// a local self-preview. `camera` picks the destination: a webcam tile
/// (`true`) or the full-screen share viewer (`false`).
#[derive(Debug, Clone)]
pub struct ScreenFrameOut {
    pub from: String,
    pub h264: Vec<u8>,
    pub keyframe: bool,
    pub camera: bool,
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

/// A running video sender (screen share or camera). Dropping it stops the
/// capture thread.
struct VideoSender {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for VideoSender {
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
    screen: Option<VideoSender>,
    camera: Option<VideoSender>,
    /// Our own username, tagged on locally looped-back camera preview frames.
    me: String,
    /// A clone of the UI frame channel so the camera sender can loop our own
    /// video back for a local self-preview (peers never see themselves).
    local_frame_tx: UnboundedSender<ScreenFrameOut>,
    /// When set, the mic is not transmitted (local mute).
    muted: Arc<AtomicBool>,
    /// When set, incoming audio is not played (deafen).
    deafened: Arc<AtomicBool>,
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
        let muted = Arc::new(AtomicBool::new(false));
        let audio_muted = muted.clone();
        std::thread::spawn(move || {
            let mut encoder = match AudioEncoder::new() {
                Ok(e) => e,
                Err(_) => return,
            };
            while let Ok(pcm) = mic_rx.recv() {
                // Muted: keep draining the mic but transmit nothing.
                if audio_muted.load(Ordering::Relaxed) {
                    continue;
                }
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
        // The camera sender loops our own preview back through the same channel.
        let local_frame_tx = screen_tx.clone();
        let in_root = p.root_secret;
        let in_group = p.group;
        let members = p.member_keys;
        let in_me = p.me;
        let me = in_me.clone();
        let decode_sink = sink_slot.clone();
        let deafened = Arc::new(AtomicBool::new(false));
        let decode_deafened = deafened.clone();
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
                        if decode_deafened.load(Ordering::Relaxed) {
                            continue;
                        }
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
                            camera: frame.kind == MediaKind::Video,
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
            camera: None,
            me,
            local_frame_tx,
            muted,
            deafened,
        };
        Ok((call, screen_rx))
    }

    /// Whether we are currently sharing our screen.
    pub fn is_sharing(&self) -> bool {
        self.screen.is_some()
    }

    /// Mute or unmute the microphone (stops/resumes transmitting our voice).
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    /// Whether the microphone is currently muted.
    pub fn is_muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    /// Deafen or undeafen (stop/resume playing incoming audio).
    pub fn set_deafened(&self, deafened: bool) {
        self.deafened.store(deafened, Ordering::Relaxed);
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

    /// Start sharing a monitor (`monitor_index` is a zero-based index from
    /// [`enclave_media::monitor_sources`]): capture -> H.264 -> seal (via the
    /// shared sealer) -> send, on a dedicated thread. A keyframe is emitted
    /// periodically so a viewer who joins mid-share recovers within a couple of
    /// seconds. Screen frames go out as [`MediaKind::Screen`] (the full-screen
    /// viewer); camera frames use [`MediaKind::Video`] (per-user tiles), so a
    /// user may share screen and camera at once without the two streams
    /// colliding on the receiver's decoder.
    #[cfg(windows)]
    pub fn start_screen(&mut self, monitor_index: usize) -> Result<(), ClientError> {
        use enclave_media::ScreenCapture;

        if self.screen.is_some() {
            return Ok(());
        }
        let capture = ScreenCapture::start_index(monitor_index).map_err(audio)?;
        let sealer = self.sealer.clone();
        let frame_tx = self.frame_tx.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let thread = std::thread::spawn(move || {
            video_encode_loop(
                &s,
                MediaKind::Screen,
                &sealer,
                &frame_tx,
                None,
                || capture.latest().map(|cf| (cf.bgra, cf.width, cf.height)),
            );
        });
        self.screen = Some(VideoSender {
            stop,
            thread: Some(thread),
        });
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn start_screen(&mut self, _monitor_index: usize) -> Result<(), ClientError> {
        Err(ClientError::Audio("screen share is Windows-only".into()))
    }

    /// Stop sharing the screen (keeps the call running).
    pub fn stop_screen(&mut self) {
        self.screen = None; // Drop stops the thread and the capture.
    }

    /// Whether our camera is currently being shared.
    pub fn is_camera_on(&self) -> bool {
        self.camera.is_some()
    }

    /// Start sharing a camera (`camera_index` from
    /// [`enclave_media::camera_sources`], 0 = default): capture -> H.264 -> seal
    /// as [`MediaKind::Video`] -> send, on a dedicated thread. The same frames
    /// are looped back locally (tagged with our own name) so we see our own
    /// preview tile without opening the camera twice.
    pub fn start_camera(&mut self, camera_index: u32) -> Result<(), ClientError> {
        use enclave_media::CameraCapture;

        if self.camera.is_some() {
            return Ok(());
        }
        let sealer = self.sealer.clone();
        let frame_tx = self.frame_tx.clone();
        let preview_tx = self.local_frame_tx.clone();
        let me = self.me.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        // The camera device is !Send: open and pump it entirely on this thread,
        // reporting an open failure (bad index / busy device) back to the caller.
        let (init_tx, init_rx) = std_mpsc::channel::<Result<(), String>>();
        let thread = std::thread::spawn(move || {
            let mut capture = match CameraCapture::open(camera_index) {
                Ok(c) => {
                    let _ = init_tx.send(Ok(()));
                    c
                }
                Err(e) => {
                    let _ = init_tx.send(Err(e.to_string()));
                    return;
                }
            };
            video_encode_loop(
                &s,
                MediaKind::Video,
                &sealer,
                &frame_tx,
                Some((preview_tx, me)),
                move || capture.next_bgra().ok().map(|(b, w, h)| (b.to_vec(), w, h)),
            );
        });
        match init_rx.recv() {
            Ok(Ok(())) => {
                self.camera = Some(VideoSender {
                    stop,
                    thread: Some(thread),
                });
                Ok(())
            }
            Ok(Err(e)) => Err(ClientError::Audio(e)),
            Err(_) => Err(ClientError::Audio("camera thread died".into())),
        }
    }

    /// Stop sharing the camera (keeps the call running).
    pub fn stop_camera(&mut self) {
        self.camera = None; // Drop stops the thread and closes the device.
    }
}

/// The shared video send loop for both screen share and camera. Pulls BGRA
/// frames from `next_frame`, crops to even dimensions, H.264-encodes with a
/// periodic keyframe, seals with `kind`, and sends. If `preview` is set (camera
/// only), each encoded frame is also looped back locally for a self-preview.
/// Paced to ~30 fps: a source whose read already blocks for the frame interval
/// (a camera) incurs no extra sleep; an instant source (screen) is throttled.
fn video_encode_loop<F>(
    stop: &AtomicBool,
    kind: MediaKind,
    sealer: &Arc<Mutex<MediaSealer>>,
    frame_tx: &UnboundedSender<MediaFrame>,
    preview: Option<(UnboundedSender<ScreenFrameOut>, String)>,
    mut next_frame: F,
) where
    F: FnMut() -> Option<(Vec<u8>, usize, usize)>,
{
    use enclave_media::H264Encoder;
    use std::time::{Duration, Instant};

    let mut encoder = match H264Encoder::new(6_000_000, 30.0) {
        Ok(e) => e,
        Err(_) => return,
    };
    let target = Duration::from_millis(33); // ~30 fps
    let mut n: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        if let Some((bgra, cw, ch)) = next_frame() {
            // Crop to even dimensions (H.264 needs them); de-stride if odd.
            let w = cw & !1;
            let h = ch & !1;
            if w != 0 && h != 0 && bgra.len() >= cw * ch * 4 {
                let tight = if w == cw {
                    bgra[..w * h * 4].to_vec()
                } else {
                    let mut t = Vec::with_capacity(w * h * 4);
                    for row in 0..h {
                        let off = row * cw * 4;
                        t.extend_from_slice(&bgra[off..off + w * 4]);
                    }
                    t
                };
                let force_key = n.is_multiple_of(60); // keyframe every ~2 s and at start
                if let Ok((h264, key)) = encoder.encode(&tight, w, h, force_key) {
                    if !h264.is_empty() {
                        // Camera self-preview: show our own frames locally
                        // without transmitting them back to ourselves.
                        if let Some((preview_tx, me)) = &preview {
                            let _ = preview_tx.send(ScreenFrameOut {
                                from: me.clone(),
                                h264: h264.clone(),
                                keyframe: key,
                                camera: kind == MediaKind::Video,
                            });
                        }
                        let sealed = sealer.lock().unwrap().seal(kind, &h264);
                        match sealed {
                            Ok(frame) => {
                                if frame_tx.send(frame).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                        n += 1;
                    }
                }
            }
        }
        let elapsed = started.elapsed();
        if elapsed < target {
            std::thread::sleep(target - elapsed);
        }
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        self.send_task.abort();
        self.recv_task.abort();
        // Dropping the fields stops capture/playback/screen/camera and channels.
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
