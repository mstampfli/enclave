//! X11 screen and window capture: raw grabs, the native approach there.
//!
//! X11 has no capture permission model -- any client may read the screen --
//! so, like every X11 screen sharer, the app enumerates and grabs directly:
//!
//! - Monitors come from RandR and are grabbed off the root window with
//!   MIT-SHM `GetImage` (one shared-memory round trip per frame, no pixel
//!   data on the wire).
//! - Single windows are named to an offscreen pixmap via XComposite, so they
//!   capture correctly even while obscured; a minimized window keeps its
//!   last-known contents. A closed window ends the share visibly.
//! - `_NET_WM_PID` resolves the window's process for per-app audio share.
//!
//! Starting is synchronous (fails fast like the Windows backends, status
//! `Live` from the start); a capture thread polls at ~30 fps into the shared
//! frame slot.
//!
//! Only little-endian X servers with 24/32-bit ZPixmap roots are supported
//! (i.e. every real desktop); anything else fails cleanly.
//!
//! HARDWARE PATH: exercised pixel-exactly against a live X server by
//! `examples/screen_probe.rs --x11-self-test` (works under Xvfb too).

use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use x11rb::connection::Connection;
use x11rb::protocol::composite::{self, ConnectionExt as _, Redirect};
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm;
use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, ImageFormat, ImageOrder};
use x11rb::rust_connection::RustConnection;

use super::super::{store, CaptureStatus, CapturedFrame, EndedReason, SharedStatus, Slot};
use super::super::{ScreenSource, WindowSource};
use crate::MediaError;

/// ~30 fps polling, matching the encoder's pace.
const FRAME_INTERVAL: Duration = Duration::from_millis(33);

/// Consecutive grab failures tolerated before the share is declared dead
/// (covers transient server hiccups without masking a gone display).
const MAX_GRAB_FAILURES: u32 = 3;

/// Enumerate RandR monitors: index + "name (WxH)". Best-effort empty on error.
pub(super) fn monitor_sources() -> Vec<ScreenSource> {
    let Ok(monitors) = monitors() else {
        return Vec::new();
    };
    monitors
        .into_iter()
        .enumerate()
        .map(|(index, m)| ScreenSource {
            index,
            name: format!("{} ({}x{})", m.name, m.width, m.height),
        })
        .collect()
}

/// Enumerate shareable top-level windows (EWMH `_NET_CLIENT_LIST`): titled,
/// and not our own (sharing yourself is a hall of mirrors). Best-effort.
pub(super) fn window_sources() -> Vec<WindowSource> {
    fn list(
        conn: &RustConnection,
        root: u32,
    ) -> Result<Vec<WindowSource>, Box<dyn std::error::Error>> {
        let client_list = intern(conn, "_NET_CLIENT_LIST")?;
        let net_wm_name = intern(conn, "_NET_WM_NAME")?;
        let utf8_string = intern(conn, "UTF8_STRING")?;
        let reply = conn
            .get_property(false, root, client_list, AtomEnum::WINDOW, 0, u32::MAX)?
            .reply()?;
        let my_pid = std::process::id();
        let mut out = Vec::new();
        for win in reply.value32().into_iter().flatten() {
            // Prefer the UTF-8 EWMH title, fall back to the legacy one.
            let title = read_string_property(conn, win, net_wm_name, utf8_string).or_else(|| {
                read_string_property(conn, win, AtomEnum::WM_NAME.into(), AtomEnum::STRING.into())
            });
            let Some(name) = title.filter(|t| !t.trim().is_empty()) else {
                continue;
            };
            if pid_property(conn, win) == Some(my_pid) {
                continue;
            }
            out.push(WindowSource {
                hwnd: win as isize,
                name,
            });
        }
        Ok(out)
    }
    let Ok((conn, screen_num)) = RustConnection::connect(None) else {
        return Vec::new();
    };
    let root = conn.setup().roots[screen_num].root;
    list(&conn, root).unwrap_or_default()
}

/// The process id owning a window (`_NET_WM_PID`), for per-app audio share.
/// `None` if the app did not set the hint or the window is gone.
pub(super) fn window_pid(hwnd: isize) -> Option<u32> {
    let (conn, _) = RustConnection::connect(None).ok()?;
    pid_property(&conn, hwnd as u32)
}

fn intern(conn: &RustConnection, name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(conn.intern_atom(false, name.as_bytes())?.reply()?.atom)
}

fn read_string_property(conn: &RustConnection, win: u32, prop: u32, ty: u32) -> Option<String> {
    let reply = conn
        .get_property(false, win, prop, ty, 0, 1024)
        .ok()?
        .reply()
        .ok()?;
    (reply.value_len > 0).then(|| String::from_utf8_lossy(&reply.value).into_owned())
}

fn pid_property(conn: &RustConnection, win: u32) -> Option<u32> {
    let atom = conn
        .intern_atom(false, b"_NET_WM_PID")
        .ok()?
        .reply()
        .ok()?
        .atom;
    let reply = conn
        .get_property(false, win, atom, AtomEnum::CARDINAL, 0, 1)
        .ok()?
        .reply()
        .ok()?;
    let pid = reply.value32()?.next();
    pid
}

struct MonitorGeom {
    name: String,
    x: i16,
    y: i16,
    width: u16,
    height: u16,
}

/// The RandR monitor list on the default screen.
fn monitors() -> Result<Vec<MonitorGeom>, String> {
    let (conn, screen_num) = RustConnection::connect(None).map_err(|e| e.to_string())?;
    let root = conn.setup().roots[screen_num].root;
    let reply = conn
        .randr_get_monitors(root, true)
        .map_err(|e| e.to_string())?
        .reply()
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for m in reply.monitors {
        let name = conn
            .get_atom_name(m.name)
            .ok()
            .and_then(|c| c.reply().ok())
            .map(|r| String::from_utf8_lossy(&r.name).into_owned())
            .unwrap_or_else(|| format!("Display {}", out.len()));
        out.push(MonitorGeom {
            name,
            x: m.x,
            y: m.y,
            width: m.width,
            height: m.height,
        });
    }
    Ok(out)
}

/// A shared-memory buffer the X server writes grabbed frames into (MIT-SHM
/// over a memfd: no pixel data crosses the socket). The mapping stays valid
/// after the fd is handed to the server.
struct ShmBuf {
    ptr: *mut u8,
    len: usize,
    seg: shm::Seg,
}

impl ShmBuf {
    fn new(conn: &RustConnection, len: usize) -> Result<Self, String> {
        // SAFETY: plain libc memfd + mmap; every return value is checked.
        unsafe {
            let fd = libc::memfd_create(c"enclave-x11-shm".as_ptr(), libc::MFD_CLOEXEC);
            if fd < 0 {
                return Err("memfd_create failed".into());
            }
            let fd = OwnedFd::from_raw_fd(fd);
            if libc::ftruncate(std::os::fd::AsRawFd::as_raw_fd(&fd), len as libc::off_t) != 0 {
                return Err("ftruncate failed".into());
            }
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err("mmap failed".into());
            }
            let seg = conn.generate_id().map_err(|e| e.to_string())?;
            shm::attach_fd(conn, seg, fd, false)
                .map_err(|e| e.to_string())?
                .check()
                .map_err(|e| format!("X server rejected MIT-SHM attach: {e}"))?;
            Ok(Self {
                ptr: ptr.cast(),
                len,
                seg,
            })
        }
    }

    /// The first `len` bytes the server last wrote.
    fn bytes(&self, len: usize) -> &[u8] {
        // SAFETY: the mapping is len bytes long and lives as long as self.
        unsafe { std::slice::from_raw_parts(self.ptr, len.min(self.len)) }
    }
}

impl Drop for ShmBuf {
    fn drop(&mut self) {
        // The server-side segment dies with the connection; only unmap here.
        // SAFETY: ptr/len are the exact mapping created in new().
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
        }
    }
}

/// What a capture thread grabs each tick.
enum Target {
    /// A region of the root window (a RandR monitor).
    Monitor {
        root: u32,
        x: i16,
        y: i16,
        w: u16,
        h: u16,
    },
    /// A composite-redirected window, grabbed via its named pixmap.
    Window {
        win: u32,
        pixmap: u32,
        w: u16,
        h: u16,
    },
}

/// Captures an X11 monitor or window on a background thread, exposing the
/// latest frame. Dropping it stops the capture.
pub(super) struct X11Capture {
    latest: Slot,
    status: SharedStatus,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl X11Capture {
    /// Start grabbing the RandR monitor at `index` (see [`monitor_sources`]).
    pub(super) fn start_monitor(index: usize) -> Result<Self, MediaError> {
        Self::start(move |conn, screen_num| {
            let mons = monitors()?;
            let m = mons
                .get(index)
                .ok_or_else(|| format!("no monitor {index}"))?;
            let root = conn.setup().roots[screen_num].root;
            Ok(Target::Monitor {
                root,
                x: m.x,
                y: m.y,
                w: m.width,
                h: m.height,
            })
        })
    }

    /// Start grabbing a single window by its X id (see [`window_sources`]).
    pub(super) fn start_window(hwnd: isize) -> Result<Self, MediaError> {
        let win = hwnd as u32;
        Self::start(move |conn, _| {
            composite::query_version(conn, 0, 4)
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|_| "the X server lacks the Composite extension".to_string())?;
            // Automatic redirection is shareable (a compositor's manual
            // redirect coexists); it gives the window an offscreen pixmap.
            conn.composite_redirect_window(win, Redirect::AUTOMATIC)
                .map_err(|e| e.to_string())?
                .check()
                .map_err(|_| "that window is no longer available".to_string())?;
            let geom = conn
                .get_geometry(win)
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|_| "that window is no longer available".to_string())?;
            let pixmap = name_pixmap(conn, win)?;
            Ok(Target::Window {
                win,
                pixmap,
                w: geom.width,
                h: geom.height,
            })
        })
    }

    /// Shared start: connect, run `setup` to resolve the target, size the shm
    /// buffer, then poll frames on a dedicated thread. Fails synchronously.
    fn start<F>(setup: F) -> Result<Self, MediaError>
    where
        F: FnOnce(&RustConnection, usize) -> Result<Target, String> + Send + 'static,
    {
        let latest: Slot = Arc::new(Mutex::new(None));
        let status = SharedStatus::live();
        let stop = Arc::new(AtomicBool::new(false));

        let (init_tx, init_rx) = mpsc::channel::<Result<(), String>>();
        let t_latest = latest.clone();
        let t_status = status.clone();
        let t_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("enclave-x11-cap".into())
            .spawn(move || {
                let init = (|| -> Result<(RustConnection, Target, ShmBuf), String> {
                    let (conn, screen_num) =
                        RustConnection::connect(None).map_err(|e| e.to_string())?;
                    if conn.setup().image_byte_order != ImageOrder::LSB_FIRST {
                        return Err("unsupported X server byte order (big-endian)".into());
                    }
                    let target = setup(&conn, screen_num)?;
                    // Size the buffer to the whole screen: covers any monitor
                    // and any window size a resize can reach.
                    let screen = &conn.setup().roots[screen_num];
                    let len =
                        screen.width_in_pixels as usize * screen.height_in_pixels as usize * 4;
                    let shm = ShmBuf::new(&conn, len.max(4096))?;
                    Ok((conn, target, shm))
                })();
                match init {
                    Ok((conn, mut target, shm)) => {
                        let _ = init_tx.send(Ok(()));
                        capture_loop(&conn, &mut target, &shm, &t_latest, &t_status, &t_stop);
                    }
                    Err(e) => {
                        let _ = init_tx.send(Err(e));
                    }
                }
            })
            .map_err(|e| MediaError::Codec(format!("spawn capture thread: {e}")))?;

        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                latest,
                status,
                stop,
                thread: Some(thread),
            }),
            Ok(Err(e)) => Err(MediaError::Codec(format!("screen capture: {e}"))),
            Err(_) => Err(MediaError::Codec("screen capture thread died".into())),
        }
    }

    pub(super) fn latest(&self) -> Option<CapturedFrame> {
        self.latest.lock().unwrap().clone()
    }

    pub(super) fn status(&self) -> CaptureStatus {
        self.status.get()
    }

    pub(super) fn status_handle(&self) -> SharedStatus {
        self.status.clone()
    }
}

impl Drop for X11Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn name_pixmap(conn: &RustConnection, win: u32) -> Result<u32, String> {
    let pixmap = conn.generate_id().map_err(|e| e.to_string())?;
    conn.composite_name_window_pixmap(win, pixmap)
        .map_err(|e| e.to_string())?
        .check()
        .map_err(|_| "the window has no contents to capture (is it mapped?)".to_string())?;
    Ok(pixmap)
}

/// Poll the target at ~30 fps into `latest` until stopped or the target dies.
fn capture_loop(
    conn: &RustConnection,
    target: &mut Target,
    shm: &ShmBuf,
    latest: &Slot,
    status: &SharedStatus,
    stop: &AtomicBool,
) {
    let mut failures = 0u32;
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();

        let grabbed = grab_frame(conn, target, shm);
        match grabbed {
            Ok(Some((w, h))) => {
                failures = 0;
                store(
                    latest,
                    w as usize,
                    h as usize,
                    shm.bytes(w as usize * h as usize * 4),
                );
            }
            Ok(None) => {} // nothing new to show (e.g. minimized); keep the last frame
            Err(GrabError::TargetGone(reason)) => {
                status.set_ended(EndedReason::Failed(reason));
                return;
            }
            Err(GrabError::Transient) => {
                failures += 1;
                if failures >= MAX_GRAB_FAILURES {
                    status.set_ended(EndedReason::Failed(
                        "screen capture lost the display".into(),
                    ));
                    return;
                }
            }
        }

        let elapsed = started.elapsed();
        if elapsed < FRAME_INTERVAL {
            std::thread::sleep(FRAME_INTERVAL - elapsed);
        }
    }
}

enum GrabError {
    /// The shared window/display is gone for good; end the share.
    TargetGone(String),
    /// A hiccup worth retrying (server busy, pixmap being replaced).
    Transient,
}

/// Grab one frame into the shm buffer. `Ok(Some((w, h)))` on success,
/// `Ok(None)` when there is legitimately nothing new (unmapped window).
fn grab_frame(
    conn: &RustConnection,
    target: &mut Target,
    shm: &ShmBuf,
) -> Result<Option<(u16, u16)>, GrabError> {
    match target {
        Target::Monitor { root, x, y, w, h } => {
            let reply = shm::get_image(
                conn,
                *root,
                *x,
                *y,
                *w,
                *h,
                u32::MAX,
                ImageFormat::Z_PIXMAP.into(),
                shm.seg,
                0,
            )
            .map_err(|_| GrabError::Transient)?
            .reply()
            .map_err(|_| GrabError::Transient)?;
            if reply.depth != 24 && reply.depth != 32 {
                return Err(GrabError::TargetGone(format!(
                    "unsupported screen depth {}",
                    reply.depth
                )));
            }
            Ok(Some((*w, *h)))
        }
        Target::Window { win, pixmap, w, h } => {
            // Track resizes: a new size invalidates the named pixmap.
            let geom = conn
                .get_geometry(*win)
                .map_err(|_| GrabError::Transient)?
                .reply()
                .map_err(|_| GrabError::TargetGone("the shared window closed".into()))?;
            if geom.width != *w || geom.height != *h {
                let _ = conn.free_pixmap(*pixmap);
                match name_pixmap(conn, *win) {
                    Ok(p) => {
                        *pixmap = p;
                        *w = geom.width;
                        *h = geom.height;
                    }
                    // Unmapped (minimized) windows cannot be re-named; keep
                    // showing the last frame until they come back.
                    Err(_) => return Ok(None),
                }
            }
            let reply = shm::get_image(
                conn,
                *pixmap,
                0,
                0,
                *w,
                *h,
                u32::MAX,
                ImageFormat::Z_PIXMAP.into(),
                shm.seg,
                0,
            )
            .map_err(|_| GrabError::Transient)?
            .reply();
            match reply {
                Ok(r) if r.depth == 24 || r.depth == 32 => Ok(Some((*w, *h))),
                Ok(r) => Err(GrabError::TargetGone(format!(
                    "unsupported window depth {}",
                    r.depth
                ))),
                // The pixmap can die between our geometry check and the grab
                // (server-side resize); re-name it next tick.
                Err(_) => match name_pixmap(conn, *win) {
                    Ok(p) => {
                        *pixmap = p;
                        Ok(None)
                    }
                    Err(_) => Ok(None),
                },
            }
        }
    }
}
