//! Enclave client: a self-contained native window (wry/WebView2, never a
//! browser or localhost) whose UI is bundled into the binary and driven over an
//! IPC bridge. All crypto, keys, capture, and transport live in Rust
//! ([`enclave_client::Client`]); the WebView renders UI only.
//!
//! Threading: the tao event loop owns the WebView on the main thread. The
//! non-`Send` client controller runs on its own thread with a Tokio runtime,
//! receiving UI commands over a channel and pushing events back to the main
//! thread (which evaluates them into the WebView) via an event-loop proxy.

use std::time::Duration;

use enclave_client::{Client, Event};
use tao::event::{Event as TaoEvent, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::WindowBuilder;
use tokio::sync::mpsc;
use wry::http::Request;
use wry::WebViewBuilder;

/// The UI, bundled into the binary. No file or network fetch at runtime.
const UI_HTML: &str = include_str!("ui/index.html");

/// Commands the UI sends to the core.
#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum UiCommand {
    Connect { server: String, name: String },
    StartGroup,
    Invite { peer: String },
    SendText { text: String },
}

/// Events the core sends to the UI (serialized straight into `onEnclaveEvent`).
#[derive(serde::Serialize, Clone)]
#[serde(tag = "type")]
enum UiEvent {
    Connected {
        name: String,
    },
    Membership {
        safety_number: Option<String>,
    },
    Text {
        from: String,
        text: String,
        mine: bool,
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
        .with_inner_size(tao::dpi::LogicalSize::new(960.0, 640.0))
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

    // The controller is not Send, so it stays on its own thread; only the
    // command channel and the proxy (both Send) cross the boundary.
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

async fn run_client(
    mut cmd_rx: mpsc::UnboundedReceiver<UiCommand>,
    proxy: EventLoopProxy<UiEvent>,
) {
    let mut client: Option<Client> = None;
    loop {
        // Drain queued commands first (no borrow held across event polling).
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_command(&mut client, &proxy, cmd).await;
        }

        // Poll for one incoming event, waking periodically to re-check commands.
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
                Event::Error(message) => emit(
                    &proxy,
                    UiEvent::Status {
                        message,
                        error: true,
                    },
                ),
            },
            Ok(None) => {
                emit(
                    &proxy,
                    UiEvent::Status {
                        message: "Disconnected from server.".into(),
                        error: true,
                    },
                );
                return;
            }
            Err(_) => {} // timed out; loop to re-check commands
        }
    }
}

async fn handle_command(
    client: &mut Option<Client>,
    proxy: &EventLoopProxy<UiEvent>,
    cmd: UiCommand,
) {
    match cmd {
        UiCommand::Connect { server, name } => match Client::connect(&server, &name).await {
            Ok(c) => {
                let name = c.name().to_string();
                *client = Some(c);
                emit(proxy, UiEvent::Connected { name });
            }
            Err(e) => emit(
                proxy,
                UiEvent::Status {
                    message: format!("Connect failed: {e}"),
                    error: true,
                },
            ),
        },
        UiCommand::StartGroup => {
            if let Some(c) = client.as_mut() {
                match c.start_group() {
                    Ok(()) => emit(
                        proxy,
                        UiEvent::Membership {
                            safety_number: c.safety_number(),
                        },
                    ),
                    Err(e) => emit(
                        proxy,
                        UiEvent::Status {
                            message: format!("Could not start group: {e}"),
                            error: true,
                        },
                    ),
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
                    Err(e) => emit(
                        proxy,
                        UiEvent::Status {
                            message: format!("Invite failed: {e}"),
                            error: true,
                        },
                    ),
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
                    Err(e) => emit(
                        proxy,
                        UiEvent::Status {
                            message: format!("Send failed: {e}"),
                            error: true,
                        },
                    ),
                }
            }
        }
    }
}
