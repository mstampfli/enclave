//! Enclave client: a self-contained native window (wry/WebView2). The UI is
//! bundled into the binary and driven over an IPC bridge; all crypto, keys, and
//! transport live in Rust ([`enclave_client::Client`]).
//!
//! The controller runs on its own thread with a Tokio runtime; the tao event
//! loop owns the WebView on the main thread and shuttles events between them.

use std::path::PathBuf;
use std::time::Duration;

use enclave_client::{Client, Event};
use enclave_protocol::Presence;
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
        password: String,
    },
    Login {
        server: String,
        username: String,
        password: String,
    },
    Logout,
    StartGroup,
    Invite {
        peer: String,
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

/// Events the core sends to the UI (serialized straight into `onEnclaveEvent`).
#[derive(serde::Serialize, Clone)]
#[serde(tag = "type")]
enum UiEvent {
    LoggedIn {
        username: String,
        safety_number: Option<String>,
    },
    LoggedOut,
    Membership {
        safety_number: Option<String>,
    },
    Text {
        from: String,
        text: String,
        mine: bool,
    },
    Presence {
        user: String,
        status: String,
    },
    /// Someone sent us a friend request.
    FriendRequest {
        from: String,
    },
    /// The current friends + pending-requests snapshot.
    Friends {
        friends: Vec<String>,
        incoming: Vec<String>,
        outgoing: Vec<String>,
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
                Event::Text { from, text } => emit(
                    &proxy,
                    UiEvent::Text {
                        from,
                        text,
                        mine: false,
                    },
                ),
                Event::MembershipChanged => {
                    let safety_number = client.as_ref().and_then(|c| c.safety_number());
                    emit(&proxy, UiEvent::Membership { safety_number });
                }
                Event::Presence { user, status } => {
                    emit(&proxy, UiEvent::Presence { user, status })
                }
                Event::FriendRequest { from } => emit(&proxy, UiEvent::FriendRequest { from }),
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
        c.create_account(username, password).await
    } else {
        c.login(username, password).await
    };
    match result {
        Ok(()) => {
            // The server pushes our friends + presence automatically on login.
            let safety_number = c.safety_number();
            let username = c.name().to_string();
            *client = Some(c);
            emit(
                proxy,
                UiEvent::LoggedIn {
                    username,
                    safety_number,
                },
            );
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
            password,
        } => authenticate(client, proxy, &server, &username, &password, true).await,
        UiCommand::Login {
            server,
            username,
            password,
        } => authenticate(client, proxy, &server, &username, &password, false).await,
        UiCommand::Logout => {
            if let Some(c) = client.as_mut() {
                c.logout();
            }
            *client = None;
            emit(proxy, UiEvent::LoggedOut);
        }
        UiCommand::StartGroup => {
            if let Some(c) = client.as_mut() {
                match c.start_group() {
                    Ok(()) => emit(
                        proxy,
                        UiEvent::Membership {
                            safety_number: c.safety_number(),
                        },
                    ),
                    Err(e) => error_status(proxy, format!("Could not start group: {e}")),
                }
            }
        }
        UiCommand::Invite { peer } => {
            if let Some(c) = client.as_mut() {
                match c.invite(&peer).await {
                    Ok(()) => emit(
                        proxy,
                        UiEvent::Membership {
                            safety_number: c.safety_number(),
                        },
                    ),
                    Err(e) => error_status(proxy, format!("Invite failed: {e}")),
                }
            }
        }
        UiCommand::SendText { text } => {
            if let Some(c) = client.as_mut() {
                match c.send_text(&text).await {
                    Ok(()) => emit(
                        proxy,
                        UiEvent::Text {
                            from: c.name().to_string(),
                            text,
                            mine: true,
                        },
                    ),
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
