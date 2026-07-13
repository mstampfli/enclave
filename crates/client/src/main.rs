//! Enclave client: a self-contained native window (wry: WebView2 on Windows,
//! WebKitGTK on Linux). The UI is bundled into the binary and driven over an
//! IPC bridge; all crypto, keys, and transport live in Rust
//! ([`enclave_client::Client`]).
//!
//! The controller runs on its own thread with a Tokio runtime; the tao event
//! loop owns the WebView on the main thread and shuttles events between them.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use enclave_client::{Client, Event};
use enclave_protocol::{Friend, Presence};
use std::borrow::Cow;

use tao::event::{Event as TaoEvent, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
#[cfg(target_os = "linux")]
use tao::platform::unix::WindowExtUnix;
use tao::window::WindowBuilder;
use tokio::sync::mpsc;
use wry::http::Request;
use wry::WebViewBuilder;
#[cfg(target_os = "linux")]
use wry::WebViewBuilderExtUnix;
#[cfg(windows)]
use wry::WebViewBuilderExtWindows;

const UI_HTML: &str = include_str!("ui/index.html");

/// Commands the UI sends to the core.
#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum UiCommand {
    /// The UI booted; `webcodecs` reports whether the WebView can decode
    /// H.264 (WebCodecs), i.e. whether watching shares/cameras will work.
    UiReady {
        webcodecs: bool,
    },
    CreateAccount {
        server: String,
        username: String,
        display: String,
        password: String,
    },
    Login {
        server: String,
        username: String,
        password: String,
    },
    Logout,
    /// Change our display name.
    SetDisplayName {
        display: String,
    },
    /// Back up the encrypted session to a discoverable file.
    ExportSession,
    /// Import a session file (same account + password) from `path`.
    ImportSession {
        path: String,
    },
    /// The user compared the safety number out of band and it matched.
    MarkVerified,
    /// Join the active conversation's voice call.
    StartCall,
    /// Leave the current voice call.
    LeaveCall,
    /// Decline an incoming call in conversation `conv` (hex id).
    DeclineCall {
        conv: String,
    },
    /// Report the shareable screens, windows, and cameras for the source picker.
    ListShareSources,
    /// Start sharing a chosen source: "monitor:N", "window:HWND", or "camera:N".
    /// `audio` also shares that source's audio (per-app for a window, whole
    /// system for a monitor); ignored for cameras.
    StartShare {
        source: String,
        audio: bool,
    },
    /// Stop sharing the screen or window (and any shared audio).
    StopScreenShare,
    /// Stop sharing the camera.
    StopCamera,
    /// Mute or unmute the microphone.
    SetMuted {
        muted: bool,
    },
    /// Deafen or undeafen (mute incoming audio).
    SetDeafened {
        deafened: bool,
    },
    /// Report the available audio devices + current selection (settings modal).
    ListAudioDevices,
    /// Choose the microphone (empty string = host default).
    SetInputDevice {
        name: String,
    },
    /// Choose the speaker (empty string = host default).
    SetOutputDevice {
        name: String,
    },
    /// Open (or focus) a 1:1 DM with a friend handle.
    OpenDm {
        handle: String,
    },
    /// Create a named group with the given member handles.
    CreateGroup {
        name: String,
        members: Vec<String>,
    },
    /// Add a friend to the active named group.
    AddToGroup {
        handle: String,
    },
    /// Leave / delete a conversation (hex id).
    LeaveConversation {
        conv: String,
    },
    /// Remove a member (username) from a group (hex id).
    RemoveMember {
        conv: String,
        member: String,
    },
    /// Focus a conversation by its id.
    SwitchConversation {
        conv: String,
    },
    SendText {
        text: String,
    },
    /// Send a friend request to a full handle.
    AddFriend {
        user: String,
    },
    AcceptFriend {
        handle: String,
    },
    DeclineFriend {
        handle: String,
    },
    RemoveFriend {
        handle: String,
    },
    SetPresence {
        status: String,
    },
}

/// A message line for the UI.
#[derive(serde::Serialize, Clone)]
struct Line {
    from: String,
    text: String,
    mine: bool,
}

/// A shareable video source for the picker. `id` is an opaque token the UI
/// echoes back in `StartShare`: "monitor:N", "window:HWND", or "camera:N".
#[derive(serde::Serialize, Clone)]
struct ShareSource {
    id: String,
    name: String,
}

/// A conversation summary for the sidebar.
#[derive(serde::Serialize, Clone)]
struct ConvSummary {
    id: String,
    title: String,
    is_dm: bool,
    pending: bool,
    members: Vec<String>,
}

/// Events the core sends to the UI (serialized straight into `onEnclaveEvent`).
#[derive(serde::Serialize, Clone)]
#[serde(tag = "type")]
enum UiEvent {
    LoggedIn {
        username: String,
        display: String,
    },
    LoggedOut,
    /// The full conversation list for the sidebar.
    Conversations {
        conversations: Vec<ConvSummary>,
    },
    /// The active conversation changed: its id, title, safety number, and history.
    ActiveConversation {
        conv: Option<String>,
        title: String,
        safety: Option<String>,
        /// Whether this conversation's *current* safety number was confirmed
        /// out of band. Comes from the core, and survives a restart.
        verified: bool,
        history: Vec<Line>,
    },
    /// A single message arrived (or was sent) in conversation `conv`.
    Message {
        conv: String,
        from: String,
        text: String,
        mine: bool,
    },
    Presence {
        user: String,
        status: String,
    },
    /// Whether a voice call is currently active.
    CallState {
        in_call: bool,
    },
    /// The available audio devices and current selection for the settings modal.
    AudioDevices {
        inputs: Vec<String>,
        outputs: Vec<String>,
        input: Option<String>,
        output: Option<String>,
    },
    /// An incoming call started in `conv`, from display name `from`: ring.
    CallOffer {
        conv: String,
        from: String,
    },
    /// The participants of `conv`'s call (display names); empty = call ended.
    CallParticipants {
        conv: String,
        participants: Vec<String>,
    },
    /// `from` declined our call in `conv`.
    CallDeclined {
        conv: String,
        from: String,
    },
    /// An H.264 video frame (base64 Annex-B) from `from` to render via
    /// WebCodecs. `camera` routes it: a per-user webcam tile or the share viewer.
    ScreenFrame {
        from: String,
        data: String,
        keyframe: bool,
        camera: bool,
    },
    /// Whether we are currently sharing our own screen.
    ScreenShareState {
        sharing: bool,
    },
    /// Whether our own camera is currently on.
    CameraState {
        on: bool,
    },
    /// The monitors, windows, and cameras this machine can share, for the picker.
    /// `per_app_audio` tells the UI whether a window share can carry only that
    /// app's audio (Windows) or shared audio is always the whole mix (Linux).
    ShareSources {
        screens: Vec<ShareSource>,
        windows: Vec<ShareSource>,
        cameras: Vec<ShareSource>,
        per_app_audio: bool,
    },
    /// Someone sent us a friend request.
    FriendRequest {
        from: String,
    },
    /// The current friends + pending-requests snapshot (username + display).
    Friends {
        friends: Vec<Friend>,
        incoming: Vec<Friend>,
        outgoing: Vec<Friend>,
    },
    Status {
        message: String,
        error: bool,
    },
    /// Connection state to the server: "online" | "reconnecting" | "offline".
    Connection {
        state: String,
    },
}

fn main() -> wry::Result<()> {
    let event_loop = EventLoopBuilder::<UiEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("Enclave")
        .with_inner_size(tao::dpi::LogicalSize::new(1000.0, 680.0))
        .build(&event_loop)
        .expect("build window");

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<UiCommand>();

    // Whether the window is focused, so the core only raises OS toasts when the
    // user is not already looking at Enclave.
    let focused = Arc::new(AtomicBool::new(true));

    // Each process gets its own WebView user-data folder. Two instances sharing
    // the default folder collide with a WebView2 "invalid parameter" error, so
    // running multiple windows (e.g. two accounts on one machine) would fail.
    let wv_data = std::env::temp_dir().join(format!("enclave-webview-{}", std::process::id()));
    let mut web_context = wry::WebContext::new(Some(wv_data));
    // Serve the UI from a custom-protocol origin (https://enclave.localhost/ on
    // Windows, enclave://localhost/ on WebKitGTK) instead of NavigateToString.
    // That origin is a *secure context*, which the opaque about:blank origin of
    // with_html is not -- and WebCodecs (the H.264 screen-share decoder) is
    // only available in a secure context.
    let builder = WebViewBuilder::new_with_web_context(&mut web_context);
    // WebView2 can only register custom protocols under an http(s) mapping.
    #[cfg(windows)]
    let builder = builder.with_https_scheme(true);
    let builder = builder
        .with_custom_protocol("enclave".to_string(), |_id, _req| {
            wry::http::Response::builder()
                .header("Content-Type", "text/html")
                .body(Cow::Borrowed(UI_HTML.as_bytes()))
                .unwrap()
        })
        .with_url("enclave://localhost/")
        .with_ipc_handler(move |req: Request<String>| {
            if let Ok(cmd) = serde_json::from_str::<UiCommand>(req.body()) {
                let _ = cmd_tx.send(cmd);
            }
        });
    // On Linux, tao windows are GTK windows and wry attaches to the GTK
    // widget tree (a raw Wayland/X11 handle is unsupported). The webview must
    // land in tao's default vbox: the window itself is a GtkBin that already
    // holds that box and can take no second child.
    #[cfg(target_os = "linux")]
    let webview = builder.build_gtk(
        window
            .default_vbox()
            .expect("tao always adds a default GtkBox"),
    )?;
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window)?;

    let core_focused = focused.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(run_client(cmd_rx, proxy, core_focused));
    });

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            TaoEvent::UserEvent(ui) => {
                if let Ok(json) = serde_json::to_string(&ui) {
                    let _ = webview.evaluate_script(&format!("window.onEnclaveEvent({json})"));
                }
            }
            TaoEvent::WindowEvent {
                event: WindowEvent::Focused(f),
                ..
            } => focused.store(f, Ordering::Relaxed),
            TaoEvent::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {}
        }
    });
}

/// Standard base64 (no line breaks) for shipping a binary H.264 frame to the
/// WebView as a JSON string. Small dependency-free encoder for the hot path.
fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Raise an OS desktop notification (toast) off the async loop.
fn notify_os(title: String, body: String) {
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .summary(&title)
            .body(&body)
            .appname("Enclave")
            .show();
    });
}

fn emit(proxy: &EventLoopProxy<UiEvent>, event: UiEvent) {
    let _ = proxy.send_event(event);
}

fn error_status(proxy: &EventLoopProxy<UiEvent>, message: String) {
    emit(
        proxy,
        UiEvent::Status {
            message,
            error: true,
        },
    );
}

/// The sidebar conversation list.
fn conv_summaries(c: &Client) -> Vec<ConvSummary> {
    c.conversations()
        .into_iter()
        .map(|i| ConvSummary {
            id: i.id,
            title: i.title,
            is_dm: i.is_dm,
            pending: i.pending,
            members: i.members,
        })
        .collect()
}

/// The active-conversation snapshot (id, title, safety number, scoped history).
fn active_conversation_event(c: &Client) -> UiEvent {
    let conv = c.active_id();
    let (title, history) = match &conv {
        Some(id) => {
            let title = c
                .conversations()
                .into_iter()
                .find(|i| &i.id == id)
                .map(|i| i.title)
                .unwrap_or_default();
            let history = c
                .conversation_history(id)
                .into_iter()
                .map(|(from, text, mine)| Line { from, text, mine })
                .collect();
            (title, history)
        }
        None => (String::new(), Vec::new()),
    };
    UiEvent::ActiveConversation {
        conv,
        title,
        safety: c.safety_number(),
        verified: c.is_verified(),
        history,
    }
}

/// Push both the sidebar list and the active-conversation snapshot.
fn emit_conversations(proxy: &EventLoopProxy<UiEvent>, c: &Client) {
    emit(
        proxy,
        UiEvent::Conversations {
            conversations: conv_summaries(c),
        },
    );
    emit(proxy, active_conversation_event(c));
}

fn emit_audio_devices(proxy: &EventLoopProxy<UiEvent>, c: &Client) {
    let info = c.audio_devices();
    emit(
        proxy,
        UiEvent::AudioDevices {
            inputs: info.inputs,
            outputs: info.outputs,
            input: info.input,
            output: info.output,
        },
    );
}

/// Parse a share-source token ("monitor:N", "window:HWND", or "camera:N") and
/// start that share, optionally also sharing its audio, reporting the new state
/// or an error to the UI.
///
/// Picking a source while one is already live switches to it: the core replaces
/// the capture, and any shared audio is restarted, because the new source has a
/// different owning process (or none at all).
fn start_share(c: &mut Client, proxy: &EventLoopProxy<UiEvent>, source: &str, audio: bool) {
    let Some((kind, id)) = source.split_once(':') else {
        error_status(proxy, format!("Bad share source: {source}"));
        return;
    };
    match kind {
        "monitor" => match id.parse::<usize>() {
            Ok(m) => match c.start_screen_share(m) {
                Ok(()) => {
                    emit(proxy, UiEvent::ScreenShareState { sharing: true });
                    // A monitor has no single owning process: whole-endpoint
                    // loopback (the UI already warned about the echo).
                    c.stop_system_audio();
                    if audio {
                        share_audio(c, proxy, None);
                    }
                }
                Err(e) => error_status(proxy, format!("Could not share screen: {e}")),
            },
            Err(_) => error_status(proxy, format!("Bad monitor id: {id}")),
        },
        "window" => match id.parse::<isize>() {
            Ok(h) => match c.start_window_share(h) {
                Ok(()) => {
                    emit(proxy, UiEvent::ScreenShareState { sharing: true });
                    // Per-app audio: capture only this window's process (echo-free).
                    c.stop_system_audio();
                    if audio {
                        match c.window_pid(h) {
                            Some(pid) => share_audio(c, proxy, Some(pid)),
                            None => error_status(
                                proxy,
                                "Sharing the window, but could not find its audio".into(),
                            ),
                        }
                    }
                }
                Err(e) => error_status(proxy, format!("Could not share window: {e}")),
            },
            Err(_) => error_status(proxy, format!("Bad window id: {id}")),
        },
        "camera" => match id.parse::<u32>() {
            Ok(n) => match c.start_camera(n) {
                Ok(()) => emit(proxy, UiEvent::CameraState { on: true }),
                Err(e) => error_status(proxy, format!("Could not share camera: {e}")),
            },
            Err(_) => error_status(proxy, format!("Bad camera id: {id}")),
        },
        _ => error_status(proxy, format!("Unknown share kind: {kind}")),
    }
}

/// Start system-audio sharing (per-app if `pid` is set, else whole endpoint),
/// surfacing any failure without tearing down the already-running video share.
fn share_audio(c: &mut Client, proxy: &EventLoopProxy<UiEvent>, pid: Option<u32>) {
    if let Err(e) = c.start_system_audio(pid) {
        error_status(proxy, format!("Sharing screen, but audio failed: {e}"));
    }
}

fn app_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

async fn run_client(
    mut cmd_rx: mpsc::UnboundedReceiver<UiCommand>,
    proxy: EventLoopProxy<UiEvent>,
    focused: Arc<AtomicBool>,
) {
    let mut client: Option<Client> = None;
    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_command(&mut client, &proxy, cmd).await;
        }

        // A share can end without a command: the user cancels the system
        // picker (Linux portal), the compositor revokes the share, or the
        // capture dies. Reap it so the UI reflects reality.
        if let Some(c) = client.as_mut() {
            if let Some(reason) = c.reap_ended_share() {
                emit(&proxy, UiEvent::ScreenShareState { sharing: false });
                match reason {
                    enclave_client::ShareEnded::Cancelled => emit(
                        &proxy,
                        UiEvent::Status {
                            message: "Share cancelled.".into(),
                            error: false,
                        },
                    ),
                    enclave_client::ShareEnded::Failed(e) => {
                        error_status(&proxy, format!("Screen share ended: {e}"))
                    }
                }
            }
        }

        let next = async {
            match client.as_mut() {
                Some(c) => c.next_event().await,
                None => std::future::pending::<Option<Event>>().await,
            }
        };
        match tokio::time::timeout(Duration::from_millis(50), next).await {
            Ok(Some(event)) => match event {
                Event::Message {
                    conv,
                    from,
                    text,
                    mine,
                } => {
                    // Toast an incoming message only when the user is not looking
                    // at Enclave (unfocused); the in-app ding + unread badge cover
                    // the focused-but-other-conversation case.
                    if !mine && !focused.load(Ordering::Relaxed) {
                        notify_os(from.clone(), text.clone());
                    }
                    emit(
                        &proxy,
                        UiEvent::Message {
                            conv,
                            from,
                            text,
                            mine,
                        },
                    );
                }
                Event::ConversationsChanged => {
                    if let Some(c) = client.as_ref() {
                        emit_conversations(&proxy, c);
                    }
                }
                Event::Presence { user, status } => {
                    emit(&proxy, UiEvent::Presence { user, status })
                }
                Event::FriendRequest { from } => emit(&proxy, UiEvent::FriendRequest { from }),
                Event::CallOffer { conv, from } => {
                    if !focused.load(Ordering::Relaxed) {
                        notify_os("Incoming call".into(), format!("{from} is calling"));
                    }
                    emit(&proxy, UiEvent::CallOffer { conv, from })
                }
                Event::CallParticipants { conv, participants } => {
                    emit(&proxy, UiEvent::CallParticipants { conv, participants })
                }
                Event::CallDeclined { conv, from } => {
                    emit(&proxy, UiEvent::CallDeclined { conv, from })
                }
                Event::ScreenFrame {
                    from,
                    data,
                    keyframe,
                    camera,
                } => emit(
                    &proxy,
                    UiEvent::ScreenFrame {
                        from,
                        data: base64_encode(&data),
                        keyframe,
                        camera,
                    },
                ),
                Event::FriendsChanged => {
                    if let Some(c) = client.as_ref() {
                        emit(
                            &proxy,
                            UiEvent::Friends {
                                friends: c.friends().to_vec(),
                                incoming: c.incoming_requests().to_vec(),
                                outgoing: c.outgoing_requests().to_vec(),
                            },
                        );
                    }
                }
                Event::Error(message) => error_status(&proxy, message),
            },
            Ok(None) => {
                // The socket dropped (server restart, network blip). Try to
                // reconnect with backoff, re-authenticating with the retained
                // credentials, before giving up and logging out.
                let reconnected = if client.is_some() {
                    emit(
                        &proxy,
                        UiEvent::Connection {
                            state: "reconnecting".into(),
                        },
                    );
                    let mut ok = false;
                    let mut delay = 1u64;
                    for _ in 0..6 {
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                        if let Some(c) = client.as_mut() {
                            if c.reconnect().await.is_ok() {
                                ok = true;
                                break;
                            }
                        }
                        delay = (delay * 2).min(15);
                    }
                    ok
                } else {
                    false
                };
                if reconnected {
                    emit(
                        &proxy,
                        UiEvent::Connection {
                            state: "online".into(),
                        },
                    );
                    if let Some(c) = client.as_ref() {
                        emit_conversations(&proxy, c);
                    }
                } else {
                    client = None;
                    emit(&proxy, UiEvent::LoggedOut);
                    error_status(&proxy, "Lost connection to the server.".into());
                }
            }
            Err(_) => {}
        }
    }
}

/// Connect + authenticate (creating the account or logging in), then wire up the
/// roster and report the logged-in state.
async fn authenticate(
    client: &mut Option<Client>,
    proxy: &EventLoopProxy<UiEvent>,
    server: &str,
    username: &str,
    display: &str,
    password: &str,
    create: bool,
) {
    let mut c = match Client::connect(server).await {
        Ok(c) => c,
        Err(_) => {
            error_status(proxy, format!("Could not reach {server}."));
            return;
        }
    };
    c.set_keystore_dir(app_dir());
    let result = if create {
        c.create_account(username, display, password).await
    } else {
        c.login(username, password).await
    };
    match result {
        Ok(()) => {
            // The server pushes our friends + presence automatically on login.
            let username = c.name().to_string();
            let display = c.display_name().to_string();
            *client = Some(c);
            emit(proxy, UiEvent::LoggedIn { username, display });
            // Login restores the saved conversations, but nothing told the UI:
            // it started empty and stayed empty, so a restart looked like the
            // chats were gone. Push the restored list.
            if let Some(c) = client.as_ref() {
                emit_conversations(proxy, c);
            }
        }
        Err(e) => error_status(proxy, e.to_string()),
    }
}

async fn handle_command(
    client: &mut Option<Client>,
    proxy: &EventLoopProxy<UiEvent>,
    cmd: UiCommand,
) {
    match cmd {
        UiCommand::UiReady { webcodecs } => {
            eprintln!("enclave: UI ready; WebCodecs H.264 decode: {webcodecs}");
            if !webcodecs {
                error_status(
                    proxy,
                    "This system's WebView cannot decode H.264 (WebCodecs missing); \
                     watching screen shares and cameras will not work. On Linux, \
                     install the GStreamer H.264 decoder (gstreamer1.0-libav)."
                        .into(),
                );
            }
        }
        UiCommand::CreateAccount {
            server,
            username,
            display,
            password,
        } => authenticate(client, proxy, &server, &username, &display, &password, true).await,
        UiCommand::Login {
            server,
            username,
            password,
        } => authenticate(client, proxy, &server, &username, "", &password, false).await,
        UiCommand::Logout => {
            if let Some(c) = client.as_mut() {
                c.logout();
            }
            *client = None;
            emit(proxy, UiEvent::LoggedOut);
        }
        UiCommand::SetDisplayName { display } => {
            if let Some(c) = client.as_mut() {
                c.set_display_name(&display);
                emit_conversations(proxy, c);
            }
        }
        UiCommand::ExportSession => {
            if let Some(c) = client.as_ref() {
                let dst = app_dir().join(format!("enclave-{}-backup.enc", c.name()));
                match c.export_session(&dst) {
                    Ok(()) => emit(
                        proxy,
                        UiEvent::Status {
                            message: format!("Exported your encrypted chats to {}", dst.display()),
                            error: false,
                        },
                    ),
                    Err(e) => error_status(proxy, format!("Export failed: {e}")),
                }
            }
        }
        UiCommand::ImportSession { path } => {
            if let Some(c) = client.as_mut() {
                match c.import_session(&path) {
                    Ok(()) => {
                        emit_conversations(proxy, c);
                        emit(
                            proxy,
                            UiEvent::Status {
                                message: "Imported chats from backup.".into(),
                                error: false,
                            },
                        );
                    }
                    Err(e) => error_status(proxy, format!("Import failed: {e}")),
                }
            }
        }
        UiCommand::MarkVerified => {
            if let Some(c) = client.as_mut() {
                c.mark_verified();
                emit(proxy, active_conversation_event(c));
            }
        }
        UiCommand::StartCall => {
            if let Some(c) = client.as_mut() {
                match c.start_call().await {
                    Ok(()) => emit(proxy, UiEvent::CallState { in_call: true }),
                    Err(e) => error_status(proxy, format!("Could not start call: {e}")),
                }
            }
        }
        UiCommand::LeaveCall => {
            if let Some(c) = client.as_mut() {
                c.leave_call();
                emit(proxy, UiEvent::CallState { in_call: false });
            }
        }
        UiCommand::DeclineCall { conv } => {
            if let Some(c) = client.as_mut() {
                c.decline_call(&conv);
            }
        }
        UiCommand::ListShareSources => {
            if let Some(c) = client.as_ref() {
                let screens = c
                    .screen_sources()
                    .into_iter()
                    .map(|(id, name)| ShareSource {
                        id: format!("monitor:{id}"),
                        name,
                    })
                    .collect();
                let windows = c
                    .window_sources()
                    .into_iter()
                    .map(|(id, name)| ShareSource {
                        id: format!("window:{id}"),
                        name,
                    })
                    .collect();
                let cameras = c
                    .camera_sources()
                    .into_iter()
                    .map(|(id, name)| ShareSource {
                        id: format!("camera:{id}"),
                        name,
                    })
                    .collect();
                emit(
                    proxy,
                    UiEvent::ShareSources {
                        screens,
                        windows,
                        cameras,
                        per_app_audio: c.per_window_audio(),
                    },
                );
            }
        }
        UiCommand::StartShare { source, audio } => {
            if let Some(c) = client.as_mut() {
                start_share(c, proxy, &source, audio);
            }
        }
        UiCommand::StopScreenShare => {
            if let Some(c) = client.as_mut() {
                c.stop_screen_share();
                emit(proxy, UiEvent::ScreenShareState { sharing: false });
            }
        }
        UiCommand::StopCamera => {
            if let Some(c) = client.as_mut() {
                c.stop_camera();
                emit(proxy, UiEvent::CameraState { on: false });
            }
        }
        UiCommand::SetMuted { muted } => {
            if let Some(c) = client.as_ref() {
                c.set_muted(muted);
            }
        }
        UiCommand::SetDeafened { deafened } => {
            if let Some(c) = client.as_ref() {
                c.set_deafened(deafened);
            }
        }
        UiCommand::ListAudioDevices => {
            if let Some(c) = client.as_ref() {
                emit_audio_devices(proxy, c);
            }
        }
        UiCommand::SetInputDevice { name } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.set_input_device(Some(name)) {
                    error_status(proxy, format!("Could not switch microphone: {e}"));
                }
                emit_audio_devices(proxy, c);
            }
        }
        UiCommand::SetOutputDevice { name } => {
            if let Some(c) = client.as_mut() {
                if let Err(e) = c.set_output_device(Some(name)) {
                    error_status(proxy, format!("Could not switch speaker: {e}"));
                }
                emit_audio_devices(proxy, c);
            }
        }
        UiCommand::OpenDm { handle } => {
            if let Some(c) = client.as_mut() {
                match c.open_dm(&handle).await {
                    Ok(_) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not open DM: {e}")),
                }
            }
        }
        UiCommand::CreateGroup { name, members } => {
            if let Some(c) = client.as_mut() {
                match c.create_group(&name, &members).await {
                    Ok(_) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not create group: {e}")),
                }
            }
        }
        UiCommand::AddToGroup { handle } => {
            if let Some(c) = client.as_mut() {
                match c.add_to_active_group(&handle).await {
                    Ok(()) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not add to group: {e}")),
                }
            }
        }
        UiCommand::LeaveConversation { conv } => {
            if let Some(c) = client.as_mut() {
                c.leave_conversation(&conv);
                emit_conversations(proxy, c);
            }
        }
        UiCommand::RemoveMember { conv, member } => {
            if let Some(c) = client.as_mut() {
                match c.remove_member(&conv, &member) {
                    Ok(()) => emit_conversations(proxy, c),
                    Err(e) => error_status(proxy, format!("Could not remove member: {e}")),
                }
            }
        }
        UiCommand::SwitchConversation { conv } => {
            if let Some(c) = client.as_mut() {
                c.switch(&conv);
                emit(proxy, active_conversation_event(c));
            }
        }
        UiCommand::SendText { text } => {
            if let Some(c) = client.as_mut() {
                let conv = c.active_id();
                let from = c.display_name().to_string();
                match c.send_text(&text).await {
                    Ok(()) => {
                        if let Some(conv) = conv {
                            emit(
                                proxy,
                                UiEvent::Message {
                                    conv,
                                    from,
                                    text,
                                    mine: true,
                                },
                            );
                        }
                    }
                    Err(e) => error_status(proxy, format!("Send failed: {e}")),
                }
            }
        }
        UiCommand::AddFriend { user } => {
            if let Some(c) = client.as_ref() {
                c.send_friend_request(&user);
            }
        }
        UiCommand::AcceptFriend { handle } => {
            if let Some(c) = client.as_ref() {
                c.accept_friend(&handle);
            }
        }
        UiCommand::DeclineFriend { handle } => {
            if let Some(c) = client.as_ref() {
                c.decline_friend(&handle);
            }
        }
        UiCommand::RemoveFriend { handle } => {
            if let Some(c) = client.as_ref() {
                c.remove_friend(&handle);
            }
        }
        UiCommand::SetPresence { status } => {
            if let Some(c) = client.as_ref() {
                let status = match status.as_str() {
                    "away" => Presence::Away,
                    "offline" => Presence::Offline,
                    _ => Presence::Online,
                };
                c.set_status(status);
            }
        }
    }
}
