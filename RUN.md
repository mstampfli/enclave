# Running Enclave

The client builds and runs on Windows (WebView2) and Linux (WebKitGTK +
PipeWire); the server also runs on macOS. Nothing here is audited or safe to
rely on yet.

## 0. Linux build dependencies

Debian/Ubuntu names; the Windows build needs no extra system packages.

```
sudo apt install build-essential clang nasm cmake pkg-config \
    libwebkit2gtk-4.1-dev libgtk-3-dev libasound2-dev libpipewire-0.3-dev
```

At runtime the desktop needs PipeWire, an XDG desktop portal with a ScreenCast
backend (KDE, GNOME, wlr, ... -- present on any mainstream desktop), and
WebKitGTK's GStreamer H.264 decoder (`gstreamer1.0-libav` or
`gstreamer1.0-plugins-bad`) to *watch* shares; the app tells you at startup if
that decoder is missing.

## 1. Build

```
cargo build
cargo test        # 60+ headless tests
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

### Sharing on Linux vs Windows

- **Windows** lists every monitor and window in the share picker; sharing a
  window can carry just that app's audio (echo-free).
- **Linux** shows one "Screen or window (choose in the system dialog)" entry:
  the desktop portal's own picker chooses what to share (that is the only way
  a Wayland app may see other windows). Shared audio is the whole system mix,
  so the picker warns that others may hear the call echo back.

## 4. Check the capture paths on real hardware

Device capture cannot be exercised in CI; these probes verify each leg on your
machine (all `[PASS]`/`[FAIL]`-scored, non-zero exit on failure):

```
cargo run -p enclave-media --example mic_probe            # mic frames flow
cargo run -p enclave-media --example camera_probe         # webcam -> BGRA frames
cargo run -p enclave-media --example system_audio_probe   # Linux: loopback hears a tone (audible!)
cargo run -p enclave-media --example screen_probe -- --self-test  # Linux: PipeWire video leg, pixel-exact
cargo run -p enclave-media --example screen_probe         # Linux: interactive portal dialog leg
cargo run -p enclave-media --example mic_loopback         # hear yourself via Opus (headphones!)
```

## Still to come

Presence broadcast polish and a persistent friends roster beyond
invite-by-name; a macOS capture backend (the media API stubs cleanly there).
The crypto, transport, calls, screen/window/camera share, and per-app or
system audio share are done and tested; see `ARCHITECTURE.md`.
