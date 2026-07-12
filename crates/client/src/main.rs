//! Enclave client: a self-contained native window (wry/WebView2). The UI is
//! bundled into the binary and driven over an IPC bridge; all crypto, keys, and
//! transport live in Rust ([`enclave_client::Client`]).
//!
//! The controller runs on its own thread with a Tokio runtime; the tao event
//! loop owns the WebView on the main thread and shuttles events between them.

use std::path::PathBuf;
use std::time::Duration;

use enclave_client::{Client, Event};
use enclave_protocol::{Friend, Presence};
use tao::event::{Event as TaoEvent, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::WindowBuilder;
use tokio::sync::mpsc;
use wry::http::Request;
use wry::WebViewBuilder;

const UI_HTML: &str = include_str!("ui/index.html");

/// Commands the UI sends to the core.
#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum UiCommand {
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
    /// Join the active conversation's voice call.
    StartCall,
    /// Leave the current voice call.
    LeaveCall,
    /// Decline an incoming call in conversation `conv` (hex id).
    DeclineCall {
        conv: String,
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

    let webview = WebViewBuilder::new()
        .with_html(UI_HTML)
        .with_ipc_handler(move |req: Request<String>| {
            if let Ok(cmd) = serde_json::from_str::<UiCommand>(req.body()) {
                let _ = cmd_tx.send(cmd);
            }
        })
        .build(&window)?;

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(run_client(cmd_rx, proxy));
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
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {}
        }
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

fn app_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

async fn run_client(
    mut cmd_rx: mpsc::UnboundedReceiver<UiCommand>,
    proxy: EventLoopProxy<UiEvent>,
) {
    let mut client: Option<Client> = None;
    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_command(&mut client, &proxy, cmd).await;
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
                } => emit(
                    &proxy,
                    UiEvent::Message {
                        conv,
                        from,
                        text,
                        mine,
                    },
                ),
                Event::ConversationsChanged => {
                    if let Some(c) = client.as_ref() {
                        emit_conversations(&proxy, c);
                    }
                }
                Event::Presence { user, status } => {
                    emit(&proxy, UiEvent::Presence { user, status })
                }
                Event::FriendRequest { from } => emit(&proxy, UiEvent::FriendRequest { from }),
                Event::CallOffer { conv, from } => emit(&proxy, UiEvent::CallOffer { conv, from }),
                Event::CallParticipants { conv, participants } => {
                    emit(&proxy, UiEvent::CallParticipants { conv, participants })
                }
                Event::CallDeclined { conv, from } => {
                    emit(&proxy, UiEvent::CallDeclined { conv, from })
                }
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
                client = None;
                emit(&proxy, UiEvent::LoggedOut);
                error_status(&proxy, "Disconnected from server.".into());
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
