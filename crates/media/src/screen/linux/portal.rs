//! Wayland screen and window capture: XDG desktop portal + PipeWire.
//!
//! On Wayland an app cannot enumerate or grab other windows -- by design, the
//! compositor only shares what the user picks in the *system* dialog (the XDG
//! ScreenCast portal). The flow is:
//!
//!   CreateSession -> SelectSources (monitor|window) -> Start (system dialog)
//!   -> PipeWire node id + remote fd -> a pw video stream delivers frames.
//!
//! So the dispatcher ([`super`]) offers a single "choose in the system dialog"
//! entry and no window list on Wayland; the portal dialog is the real picker.
//! Starting is asynchronous (a human sits between "start" and "frames" and may
//! cancel), which the shared [`SharedStatus`] reports: `Starting` while the
//! dialog is up, `Live` at the first frame, `Ended` on cancel/revoke/death.
//!
//! One dedicated thread per capture owns everything: a tiny tokio
//! current-thread runtime for the portal D-Bus calls (kept alive for the whole
//! capture -- dropping it would close the D-Bus connection and with it the
//! portal session), then the (`!Send`) PipeWire main loop. Frames are
//! negotiated as BGRx/BGRA/RGBx/RGBA shared-memory buffers, de-padded (and
//! swizzled when RGB-ordered) into the shared tight-BGRA slot.
//!
//! The portal's restore token is kept for the process lifetime, so re-sharing
//! in the same run can skip straight past the dialog if the user told their
//! compositor to remember the choice.
//!
//! HARDWARE PATH: the portal dialog needs a human click; the PipeWire leg is
//! exercised headlessly via `ScreenCapture::start_node` (see
//! `examples/screen_probe.rs`), the dialog leg on a real desktop.

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions};
use ashpd::desktop::PersistMode;
use pipewire as pw;
use pw::{properties::properties, spa};

use super::super::{
    store, tighten_to_bgra, CaptureStatus, CapturedFrame, EndedReason, SharedStatus, Slot,
};
use crate::MediaError;

/// The portal restore token from the last approved share, kept for this
/// process's lifetime so a re-share can skip the dialog if the compositor
/// remembered the user's choice. (Persisting it across runs would need a
/// state file; a fresh run re-asks, which is the common desktop behavior.)

/// Captures the portal-picked monitor or window on a dedicated thread,
/// exposing the latest frame. Dropping it stops the capture.
pub struct PortalCapture {
    latest: Slot,
    status: SharedStatus,
    /// Flags the capture thread to wind down at its next phase boundary.
    stop: Arc<AtomicBool>,
    /// Wakes the PipeWire loop so it notices `stop` (present once the loop
    /// may be running; the handshake phase polls `stop` instead).
    stop_tx: Mutex<Option<pw::channel::Sender<()>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl PortalCapture {
    /// Start capturing whatever the user picks in the system dialog. Returns
    /// immediately; watch [`Self::status`] for `Live`/`Ended`.
    pub fn start_portal() -> Result<Self, MediaError> {
        Self::spawn(None)
    }

    /// Capture a specific PipeWire video node on the default remote, skipping
    /// the portal. Hardware-validation hook (`examples/screen_probe.rs`) --
    /// real shares always go through the portal.
    pub fn start_node(node_id: u32) -> Result<Self, MediaError> {
        Self::spawn(Some(node_id))
    }

    fn spawn(direct_node: Option<u32>) -> Result<Self, MediaError> {
        let latest: Slot = Arc::new(Mutex::new(None));
        let status = SharedStatus::starting();
        let stop = Arc::new(AtomicBool::new(false));
        let (stop_tx, stop_rx) = pw::channel::channel::<()>();

        let t_latest = latest.clone();
        let t_status = status.clone();
        let t_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("enclave-screen-cap".into())
            .spawn(move || {
                capture_thread(direct_node, t_latest, t_status.clone(), t_stop, stop_rx);
                // Whatever path got us here, the capture is over. (First cause
                // wins, so a real error or cancel set earlier stays visible.)
                t_status.set_ended(EndedReason::Failed("capture stopped".into()));
            })
            .map_err(|e| MediaError::Codec(format!("spawn capture thread: {e}")))?;

        Ok(Self {
            latest,
            status,
            stop,
            stop_tx: Mutex::new(Some(stop_tx)),
            thread: Mutex::new(Some(thread)),
        })
    }

    /// The most recently captured frame, if any has arrived yet.
    pub fn latest(&self) -> Option<CapturedFrame> {
        self.latest.lock().unwrap().clone()
    }

    /// This capture's life-cycle status.
    pub fn status(&self) -> CaptureStatus {
        self.status.get()
    }

    /// The shared status cell, for supervising the share after the capture has
    /// been moved into its encode thread.
    pub fn status_handle(&self) -> SharedStatus {
        self.status.clone()
    }
}

impl Drop for PortalCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake the PipeWire loop if it is running; harmless if not yet there.
        if let Some(tx) = self.stop_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        // While the portal dialog is up the thread is blocked on a human;
        // joining would hang the caller until they answer. Detach instead --
        // the thread sees `stop` right after the handshake and exits. Once
        // live (or ended), teardown is prompt, so join to release resources.
        if !matches!(self.status.get(), CaptureStatus::Starting) {
            if let Some(t) = self.thread.lock().unwrap().take() {
                let _ = t.join();
            }
        }
    }
}

/// The capture thread: portal handshake (unless probing a direct node), then
/// the PipeWire stream loop. The end reason lands in `status`; frames land in
/// `latest`.
fn capture_thread(
    direct_node: Option<u32>,
    latest: Slot,
    status: SharedStatus,
    stop: Arc<AtomicBool>,
    stop_rx: pw::channel::Receiver<()>,
) {
    let target = match direct_node {
        // Probe path: default remote, no portal, no session to keep alive.
        Some(node_id) => Ok(PwTarget {
            node_id,
            grant: None,
        }),
        None => portal_handshake(),
    };
    let target = match target {
        Ok(t) => t,
        Err(reason) => {
            status.set_ended(reason);
            return;
        }
    };

    // The user may have closed the share while the dialog was up.
    if stop.load(Ordering::Relaxed) {
        status.set_ended(EndedReason::Cancelled);
        return;
    }

    if let Err(e) = pw_video_loop(target, latest, &status, stop_rx) {
        status.set_ended(EndedReason::Failed(e));
    }
}

/// A PipeWire capture target: the video node and, for portal captures, the
/// remote fd plus the objects whose lifetime keeps the grant alive.
struct PwTarget {
    node_id: u32,
    grant: Option<(OwnedFd, PortalSession)>,
}

/// Keep-alive for an approved portal share: the session proxy and the runtime
/// owning its D-Bus connection. Dropping either ends the compositor's stream,
/// so this rides along until the capture stops.
struct PortalSession {
    _session: ashpd::desktop::Session<Screencast>,
    _runtime: tokio::runtime::Runtime,
}

/// Run the blocking portal handshake on a private current-thread runtime.
/// Returns the granted stream plus the keep-alives that must stay alive.
fn portal_handshake() -> Result<PwTarget, EndedReason> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| EndedReason::Failed(format!("portal runtime: {e}")))?;

    let failed = |what: &'static str| {
        move |e: ashpd::Error| match e {
            ashpd::Error::Response(ashpd::desktop::ResponseError::Cancelled) => {
                EndedReason::Cancelled
            }
            other => EndedReason::Failed(format!("{what}: {other}")),
        }
    };
    let result = runtime.block_on(async {
        let portal = Screencast::new().await.map_err(|e| {
            EndedReason::Failed(format!("screen sharing needs the desktop portal: {e}"))
        })?;
        let session = portal
            .create_session(Default::default())
            .await
            .map_err(failed("portal session"))?;

        let options = SelectSourcesOptions::default()
            .set_multiple(false)
            .set_cursor_mode(CursorMode::Embedded)
            .set_sources(
                ashpd::enumflags2::BitFlags::from(ashpd::desktop::screencast::SourceType::Monitor)
                    | ashpd::desktop::screencast::SourceType::Window,
            )
            // Do NOT persist a restore token: with it, the compositor silently
            // restores the previous selection on the next share with no dialog,
            // and a restored-but-stale session left re-sharing broken (no picker,
            // no frames). A fresh dialog + fresh session every time is reliable.
            .set_persist_mode(PersistMode::DoNot);
        portal
            .select_sources(&session, options)
            .await
            .map_err(failed("portal source selection"))?
            .response()
            .map_err(failed("portal source selection"))?;

        // Start pops the system picker dialog; Cancelled means the user
        // dismissed it, which the UI treats calmly rather than as an error.
        let streams = portal
            .start(&session, None, Default::default())
            .await
            .map_err(failed("portal start"))?
            .response()
            .map_err(failed("portal start"))?;

        let stream = streams
            .streams()
            .first()
            .ok_or_else(|| EndedReason::Failed("the portal granted no stream".into()))?;
        let node_id = stream.pipe_wire_node_id();

        let fd = portal
            .open_pipe_wire_remote(&session, Default::default())
            .await
            .map_err(failed("portal PipeWire remote"))?;

        // The session is NOT closed here: the compositor streams for as long
        // as it lives, so it rides back to the caller as a keep-alive.
        Ok::<_, EndedReason>((node_id, fd, session))
    });

    result.map(|(node_id, fd, session)| PwTarget {
        node_id,
        grant: Some((
            fd,
            PortalSession {
                _session: session,
                _runtime: runtime,
            },
        )),
    })
}

/// Per-stream state the PipeWire callbacks share.
struct StreamData {
    format: spa::param::video::VideoInfoRaw,
    have_format: bool,
    /// Scratch for de-padding, reused across frames.
    scratch: Vec<u8>,
}

/// A serialized `SPA_PARAM_Buffers` pod asking for whole-frame shared-memory
/// buffers (`width*4`-byte rows, 2..16 buffers). Sent in answer to the
/// negotiated video format.
fn video_buffers_pod(width: u32, height: u32) -> Result<Vec<u8>, String> {
    let stride = width as i32 * 4;
    let size = stride.checked_mul(height as i32).ok_or("frame too large")?;
    let range_int = |default: i32, min: i32, max: i32| {
        spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(spa::utils::Choice(
            spa::utils::ChoiceFlags::empty(),
            spa::utils::ChoiceEnum::Range { default, min, max },
        )))
    };
    let obj = spa::pod::Object {
        type_: spa::utils::SpaTypes::ObjectParamBuffers.as_raw(),
        id: spa::param::ParamType::Buffers.as_raw(),
        properties: vec![
            spa::pod::Property::new(spa::sys::SPA_PARAM_BUFFERS_buffers, range_int(4, 2, 16)),
            spa::pod::Property::new(spa::sys::SPA_PARAM_BUFFERS_blocks, spa::pod::Value::Int(1)),
            spa::pod::Property::new(spa::sys::SPA_PARAM_BUFFERS_size, spa::pod::Value::Int(size)),
            spa::pod::Property::new(
                spa::sys::SPA_PARAM_BUFFERS_stride,
                spa::pod::Value::Int(stride),
            ),
            spa::pod::Property::new(
                spa::sys::SPA_PARAM_BUFFERS_dataType,
                spa::pod::Value::Choice(spa::pod::ChoiceValue::Int(spa::utils::Choice(
                    spa::utils::ChoiceFlags::empty(),
                    spa::utils::ChoiceEnum::Flags {
                        default: (1 << spa::sys::SPA_DATA_MemPtr) | (1 << spa::sys::SPA_DATA_MemFd),
                        flags: vec![],
                    },
                ))),
            ),
        ],
    };
    let values = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    )
    .map_err(|e| format!("buffers pod: {e:?}"))?
    .0
    .into_inner();
    Ok(values)
}

/// Connect to the video node and pump frames into `latest` until stopped or
/// the stream dies. Blocks on the PipeWire main loop.
fn pw_video_loop(
    target: PwTarget,
    latest: Slot,
    status: &SharedStatus,
    stop_rx: pw::channel::Receiver<()>,
) -> Result<(), String> {
    pw::init();
    let mainloop =
        pw::main_loop::MainLoopRc::new(None).map_err(|e| format!("pipewire loop: {e}"))?;
    let context = pw::context::ContextRc::new(&mainloop, None)
        .map_err(|e| format!("pipewire context: {e}"))?;
    // Keep the portal session alive for the whole loop; the fd goes to pw.
    let mut _portal_keepalive: Option<PortalSession> = None;
    let core = match target.grant {
        Some((fd, session)) => {
            _portal_keepalive = Some(session);
            context
                .connect_fd_rc(fd, None)
                .map_err(|e| format!("pipewire connect (portal fd): {e}"))?
        }
        None => context
            .connect_rc(None)
            .map_err(|e| format!("pipewire connect: {e}"))?,
    };

    // Cross-thread stop: Drop sends on the channel, we quit the loop.
    let loop_quit = mainloop.downgrade();
    let _stop_attached = stop_rx.attach(mainloop.loop_(), move |_| {
        if let Some(ml) = loop_quit.upgrade() {
            ml.quit();
        }
    });

    let stream = pw::stream::StreamBox::new(
        &core,
        "enclave-screen",
        properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )
    .map_err(|e| format!("pipewire stream: {e}"))?;

    let data = StreamData {
        format: Default::default(),
        have_format: false,
        scratch: Vec::new(),
    };

    // If the compositor kills the stream (share revoked from the system tray,
    // source window closed), it drops back to Unconnected without an error;
    // flag it and quit the loop so the share ends visibly instead of freezing.
    let err_status = status.clone();
    let err_quit = mainloop.downgrade();
    let frame_status = status.clone();

    let _listener = stream
        .add_local_listener_with_user_data(data)
        .state_changed(move |_, _, old, new| {
            use pw::stream::StreamState;
            let reason = match (&old, &new) {
                (_, StreamState::Error(e)) => {
                    Some(EndedReason::Failed(format!("screen stream failed: {e}")))
                }
                (StreamState::Paused | StreamState::Streaming, StreamState::Unconnected) => Some(
                    EndedReason::Failed("the share was ended by the system".into()),
                ),
                _ => None,
            };
            if let Some(reason) = reason {
                err_status.set_ended(reason);
                if let Some(ml) = err_quit.upgrade() {
                    ml.quit();
                }
            }
        })
        .param_changed(|stream, data, id, param| {
            let Some(param) = param else { return };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(param)
            else {
                return;
            };
            if media_type != spa::param::format::MediaType::Video
                || media_subtype != spa::param::format::MediaSubtype::Raw
            {
                return;
            }
            data.have_format = data.format.parse(param).is_ok();
            // Answer the format with a Buffers param sized for whole frames.
            // Without it, buffer negotiation can fall back to a tiny default
            // (8 KiB) that cannot carry a frame, and capture yields nothing.
            if data.have_format {
                let size = data.format.size();
                if let Ok(values) = video_buffers_pod(size.width, size.height) {
                    if let Some(pod) = spa::pod::Pod::from_bytes(&values) {
                        let _ = stream.update_params(&mut [pod]);
                    }
                }
            }
        })
        .process(move |stream, data| {
            if !data.have_format {
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
            let chunk_size = d.chunk().size() as usize;
            let chunk_stride = d.chunk().stride() as usize;
            let size = data.format.size();
            let (w, h) = (size.width as usize, size.height as usize);
            let swap_rb = matches!(
                data.format.format(),
                spa::param::video::VideoFormat::RGBx | spa::param::video::VideoFormat::RGBA
            );
            // A stride of 0 means "tightly packed" in practice; malformed
            // strides are caught by tighten_to_bgra's bounds checks.
            let stride = if chunk_stride == 0 {
                w * 4
            } else {
                chunk_stride
            };
            let Some(bytes) = d.data() else { return };
            let bytes = &bytes[..chunk_size.min(bytes.len())];
            // Split-borrow around data: scratch is separate from format reads.
            let scratch = &mut data.scratch;
            if tighten_to_bgra(bytes, stride, w, h, swap_rb, scratch) {
                store(&latest, w, h, scratch);
                frame_status.set_live();
            }
        })
        .register()
        .map_err(|e| format!("pipewire listener: {e}"))?;

    // Offer the formats we can turn into tight BGRA; the compositor picks.
    let obj = spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaType,
            Id,
            spa::param::format::MediaType::Video
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaSubtype,
            Id,
            spa::param::format::MediaSubtype::Raw
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            spa::param::video::VideoFormat::BGRx,
            spa::param::video::VideoFormat::BGRx,
            spa::param::video::VideoFormat::BGRA,
            spa::param::video::VideoFormat::RGBx,
            spa::param::video::VideoFormat::RGBA,
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            spa::utils::Rectangle {
                width: 1920,
                height: 1080
            },
            spa::utils::Rectangle {
                width: 1,
                height: 1
            },
            spa::utils::Rectangle {
                width: 16384,
                height: 16384
            }
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: 30, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction {
                num: 1000,
                denom: 1
            }
        ),
    );
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
            Some(target.node_id),
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .map_err(|e| format!("pipewire stream connect: {e}"))?;

    mainloop.run();
    Ok(())
}
