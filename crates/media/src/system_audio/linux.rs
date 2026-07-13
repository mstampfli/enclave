//! PipeWire loopback capture of system audio (Linux).
//!
//! - [`LoopbackMode::System`]: a capture stream with `stream.capture.sink`
//!   set, which PipeWire connects to the default sink's monitor -- the whole
//!   output mix, exactly what WASAPI endpoint loopback gives on Windows.
//! - [`LoopbackMode::Process`]: find the application's own output stream node
//!   via a registry roundtrip -- the pid lives on the owning *Client* object
//!   (kernel-verified `pipewire.sec.pid`), joined to its nodes by `client.id`
//!   -- then capture that node alone by targeting its `object.serial`: true
//!   per-app, echo-free loopback. Fails cleanly if the app is not playing
//!   audio.
//!
//! The stream negotiates S16LE / 48 kHz / stereo and PipeWire's stream adapter
//! converts/resamples whatever the graph runs at; samples go through
//! [`super::mix_in_stereo_i16`] into the shared mono ring.
//!
//! Everything PipeWire is `!Send`, so one dedicated thread owns the main loop;
//! [`SystemAudioCapture::start`] blocks only until the stream reports
//! streaming (or fails), mirroring the WASAPI backend's init handshake.
//!
//! HARDWARE PATH: exercised for real by `examples/system_audio_probe.rs`
//! (plays a tone, captures it back through the monitor).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;

use pipewire as pw;
use pw::{properties::properties, spa};

use super::{mix_in_stereo_i16, AudioMix, LoopbackMode};
use crate::MediaError;

/// A running system-audio loopback capture. Dropping it stops the thread.
pub struct SystemAudioCapture {
    stop: Arc<AtomicBool>,
    stop_tx: Option<pw::channel::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl SystemAudioCapture {
    /// Start capturing `mode` into `mix`. Returns once capture is streaming,
    /// or an error if PipeWire is unreachable, the target app is not playing
    /// audio, or the stream fails to start.
    pub fn start(mode: LoopbackMode, mix: AudioMix) -> Result<Self, MediaError> {
        let stop = Arc::new(AtomicBool::new(false));
        let (stop_tx, stop_rx) = pw::channel::channel::<()>();
        let (init_tx, init_rx) = mpsc::channel::<Result<(), String>>();

        let t_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("enclave-sysaudio".into())
            .spawn(move || {
                let tx = init_tx.clone();
                if let Err(e) = run_loopback(mode, mix, &t_stop, stop_rx, init_tx) {
                    let _ = tx.send(Err(e));
                }
            })
            .map_err(|e| MediaError::Codec(format!("spawn audio thread: {e}")))?;

        let capture = Self {
            stop,
            stop_tx: Some(stop_tx),
            thread: Some(thread),
        };
        match init_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(capture),
            // Dropping `capture` on the error paths stops + joins the thread.
            Ok(Err(e)) => Err(MediaError::Codec(format!("system audio: {e}"))),
            Err(_) => Err(MediaError::Codec(
                "system audio: timed out waiting for PipeWire".into(),
            )),
        }
    }
}

impl Drop for SystemAudioCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Per-stream state the PipeWire callbacks share.
struct StreamData {
    /// Confirmed S16LE stereo by `param_changed`; gates `process`.
    format_ok: bool,
    /// Scratch for byte -> i16 conversion, reused across callbacks.
    scratch: Vec<i16>,
}

/// The capture thread body: connect, (for `Process`) find the target node,
/// then stream until stopped. Sends `Ok(())` on `init_tx` once streaming.
fn run_loopback(
    mode: LoopbackMode,
    mix: AudioMix,
    stop: &AtomicBool,
    stop_rx: pw::channel::Receiver<()>,
    init_tx: mpsc::Sender<Result<(), String>>,
) -> Result<(), String> {
    pw::init();
    let mainloop =
        pw::main_loop::MainLoopRc::new(None).map_err(|e| format!("pipewire loop: {e}"))?;
    let context = pw::context::ContextRc::new(&mainloop, None)
        .map_err(|e| format!("pipewire context: {e}"))?;
    let core = context
        .connect_rc(None)
        .map_err(|e| format!("pipewire connect: {e}"))?;

    // Cross-thread stop: attached once, effective in every run() below.
    let loop_quit = mainloop.downgrade();
    let _stop_attached = stop_rx.attach(mainloop.loop_(), move |_| {
        if let Some(ml) = loop_quit.upgrade() {
            ml.quit();
        }
    });

    // Per-app capture targets the app's output node by serial.
    let target_serial = match mode {
        LoopbackMode::System => None,
        LoopbackMode::Process(pid) => {
            let serial = find_app_output_serial(&mainloop, &core, pid)?;
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            match serial {
                Some(s) => Some(s),
                None => return Err(format!("the shared app (pid {pid}) is not playing audio")),
            }
        }
    };

    let mut props = properties! {
        *pw::keys::MEDIA_TYPE => "Audio",
        *pw::keys::MEDIA_CATEGORY => "Capture",
        *pw::keys::MEDIA_ROLE => "Music",
    };
    match &target_serial {
        Some(serial) => props.insert(*pw::keys::TARGET_OBJECT, serial.as_str()),
        None => props.insert(*pw::keys::STREAM_CAPTURE_SINK, "true"),
    }

    let stream = pw::stream::StreamBox::new(&core, "enclave-audio-share", props)
        .map_err(|e| format!("pipewire stream: {e}"))?;

    let data = StreamData {
        format_ok: false,
        scratch: Vec::new(),
    };

    let state_tx = init_tx.clone();
    let err_quit = mainloop.downgrade();
    let _listener = stream
        .add_local_listener_with_user_data(data)
        .state_changed(move |_, _, _old, new| match new {
            pw::stream::StreamState::Streaming => {
                let _ = state_tx.send(Ok(()));
            }
            pw::stream::StreamState::Error(e) => {
                let _ = state_tx.send(Err(format!("stream failed: {e}")));
                if let Some(ml) = err_quit.upgrade() {
                    ml.quit();
                }
            }
            _ => {}
        })
        .param_changed(|_, data, id, param| {
            let Some(param) = param else { return };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(param)
            else {
                return;
            };
            if media_type != spa::param::format::MediaType::Audio
                || media_subtype != spa::param::format::MediaSubtype::Raw
            {
                return;
            }
            let mut info = spa::param::audio::AudioInfoRaw::new();
            data.format_ok = info.parse(param).is_ok()
                && info.format() == spa::param::audio::AudioFormat::S16LE
                && info.channels() == 2;
        })
        .process(move |stream, data| {
            if !data.format_ok {
                return;
            }
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            if datas.is_empty() {
                return;
            }
            let d = &mut datas[0];
            let n_bytes = d.chunk().size() as usize;
            let Some(bytes) = d.data() else { return };
            let bytes = &bytes[..n_bytes.min(bytes.len())];
            data.scratch.clear();
            data.scratch.extend(
                bytes
                    .chunks_exact(2)
                    .map(|b| i16::from_le_bytes([b[0], b[1]])),
            );
            mix_in_stereo_i16(&mix, &data.scratch);
        })
        .register()
        .map_err(|e| format!("pipewire listener: {e}"))?;

    // Fixed S16LE / 48 kHz / stereo; the stream adapter converts the graph
    // format to this, so the mix ring's contract holds on any setup.
    let mut audio_info = spa::param::audio::AudioInfoRaw::new();
    audio_info.set_format(spa::param::audio::AudioFormat::S16LE);
    audio_info.set_rate(48_000);
    audio_info.set_channels(2);
    let obj = spa::pod::Object {
        type_: spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: spa::param::ParamType::EnumFormat.as_raw(),
        properties: audio_info.into(),
    };
    let values: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    )
    .map_err(|e| format!("format pod: {e:?}"))?
    .0
    .into_inner();
    let mut params = [spa::pod::Pod::from_bytes(&values).ok_or("format pod parse")?];

    stream
        .connect(
            spa::utils::Direction::Input,
            None,
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .map_err(|e| format!("pipewire stream connect: {e}"))?;

    mainloop.run();
    Ok(())
}

/// One registry roundtrip: the `object.serial` of the audio-output stream node
/// owned by `pid`, or `None` if that app is not playing audio right now.
fn find_app_output_serial(
    mainloop: &pw::main_loop::MainLoopRc,
    core: &pw::core::CoreRc,
    pid: u32,
) -> Result<Option<String>, String> {
    let registry = core
        .get_registry_rc()
        .map_err(|e| format!("pipewire registry: {e}"))?;

    // The pid lives on the *Client* object, not the node: native clients
    // self-report `application.process.id` there and the server stamps the
    // kernel-verified `pipewire.sec.pid` (SO_PEERCRED); nodes carry only a
    // `client.id` back-reference. (ALSA-compat clients -- cpal apps, aplay --
    // put nothing pid-like on the node itself.) So collect both object kinds
    // and join them after the roundtrip, preferring the unforgeable sec pid.
    #[derive(Default)]
    struct Snapshot {
        /// client id -> that client's process id.
        client_pids: std::collections::HashMap<u32, u32>,
        /// (client id, node-level pid if self-reported, object.serial).
        nodes: Vec<(Option<u32>, Option<u32>, String)>,
    }
    let snap: Rc<RefCell<Snapshot>> = Rc::new(RefCell::new(Snapshot::default()));
    let done = Rc::new(Cell::new(false));

    let reg_snap = snap.clone();
    let _reg_listener = registry
        .add_listener_local()
        .global(move |global| {
            let Some(props) = global.props else { return };
            let get_u32 = |key: &str| props.get(key).and_then(|v| v.parse::<u32>().ok());
            match global.type_ {
                pw::types::ObjectType::Client => {
                    let pid =
                        get_u32("pipewire.sec.pid").or_else(|| get_u32("application.process.id"));
                    if let Some(pid) = pid {
                        reg_snap.borrow_mut().client_pids.insert(global.id, pid);
                    }
                }
                pw::types::ObjectType::Node => {
                    if props.get("media.class") != Some("Stream/Output/Audio") {
                        return;
                    }
                    let Some(serial) = props.get("object.serial") else {
                        return;
                    };
                    reg_snap.borrow_mut().nodes.push((
                        get_u32("client.id"),
                        get_u32("application.process.id"),
                        serial.to_owned(),
                    ));
                }
                _ => {}
            }
        })
        .register();

    // `done` fires once the server has flushed every existing global to us.
    let pending = core.sync(0).map_err(|e| format!("pipewire sync: {e}"))?;
    let done_quit = mainloop.downgrade();
    let done_flag = done.clone();
    let _core_listener = core
        .add_listener_local()
        .done(move |id, seq| {
            if id == pw::core::PW_ID_CORE && seq == pending {
                done_flag.set(true);
                if let Some(ml) = done_quit.upgrade() {
                    ml.quit();
                }
            }
        })
        .register();

    mainloop.run();

    if !done.get() {
        // The loop was quit by stop (or an error) before the roundtrip ended.
        return Ok(None);
    }
    let snap = snap.borrow();
    // First match wins; an app rarely has several output streams and any of
    // them identifies the client to capture.
    let serial = snap.nodes.iter().find_map(|(client_id, node_pid, serial)| {
        let owner_pid = client_id
            .and_then(|c| snap.client_pids.get(&c).copied())
            .or(*node_pid);
        (owner_pid == Some(pid)).then(|| serial.clone())
    });
    Ok(serial)
}
