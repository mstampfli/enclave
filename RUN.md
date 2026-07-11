# Running Enclave

Everything below builds on Windows (WebView2) and Linux/macOS for the server.
Nothing here is audited or safe to rely on yet.

## 1. Build

```
cargo build
cargo test        # 40+ headless tests
```

## 2. Run the relay server

```
cargo run -p enclave-server                 # ws on 127.0.0.1:8443, UDP media on :8444
cargo run -p enclave-server 0.0.0.0:8443    # bind all interfaces to reach it remotely
```

For TLS (wss), point it at a PEM certificate and key:

```
ENCLAVE_TLS_CERT=cert.pem ENCLAVE_TLS_KEY=key.pem cargo run -p enclave-server
```

## 3. Run the client (self-contained window)

```
cargo run -p enclave-client --bin enclave
```

A native window opens (no browser). Steps in the UI:

1. Enter the server (`ws://127.0.0.1:8443`) and a name, then **Connect**.
2. **Start a group**, then **Invite** a friend by their name (they must be
   connected too).
3. Type in the message box. The **safety number** in the sidebar should match on
   both machines -- read it aloud to confirm no one is in the middle.
4. Add friends by name to see their online/away/offline presence; set your own
   status from the **Status** dropdown.

Run two clients (two names) against one server to talk to yourself across
windows.

## 4. Check the audio device path on real hardware

The audio capture/playback code compiles but cannot be exercised in CI. This
example runs the mic -> Opus -> speaker loop locally so you can confirm it works
on your machine (use headphones to avoid feedback):

```
cargo run -p enclave-media --example mic_loopback
```

## Still to come

Live in-call audio wiring (feeding captured frames through the network and the
jitter buffer to playback) and video/screenshare. The crypto, transport,
presence, and relay are done and tested; see `ARCHITECTURE.md`.
