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

1. Enter the server (`ws://127.0.0.1:8443`), pick a username and password,
   and **Create account** (or **Sign in** on later runs).
2. In the **People** tab, add a friend by username; they accept the request
   on their side. Click the message action (or double-click them) to open a
   DM; the **+** by Conversations starts a named group.
3. Type in the message box. Click the **seal** next to the conversation title
   (or "verify now") to see the safety number: read it aloud on both machines,
   then confirm with "We compared, it matches" -- the seal turns solid.
4. **Call** starts or joins a call; the stage docks into the conversation
   with labeled mute/deafen/camera/share controls. Your own status lives on
   the menu under your name (Online/Away/Offline, with an optional duration).
5. `Ctrl+K` opens the command palette for jumping and actions.

Run two clients (two usernames) against one server to talk to yourself
across windows.

### Sharing on Linux vs Windows

- **Windows** lists every monitor and window in the share picker; sharing a
  window can carry just that app's audio (echo-free).
- **Linux on X11** works like Windows: the picker lists RandR monitors and
  every titled window, captured with raw X grabs (MIT-SHM / XComposite), and
  a window share can carry just that app's audio (`_NET_WM_PID` + PipeWire).
- **Linux on Wayland** shows one "Screen or window (choose in the system
  dialog)" entry: the desktop portal's own picker chooses what to share (that
  is the only way a Wayland app may see other windows). Shared audio is the
  whole system mix, so the picker warns that others may hear the call echo
  back.

## 4. Check the capture paths on real hardware

Device capture cannot be exercised in CI; these probes verify each leg on your
machine (all `[PASS]`/`[FAIL]`-scored, non-zero exit on failure):

```
cargo run -p enclave-media --example mic_probe            # mic frames flow
cargo run -p enclave-media --example camera_probe         # webcam -> BGRA frames
cargo run -p enclave-media --example system_audio_probe   # Linux: loopback hears a tone (audible!)
cargo run -p enclave-media --example screen_probe -- --self-test      # Linux: PipeWire video leg, pixel-exact
cargo run -p enclave-media --example screen_probe -- --x11-self-test  # Linux: raw X11 leg, pixel-exact (works under Xvfb)
cargo run -p enclave-media --example screen_probe         # Linux/Wayland: interactive portal dialog leg
cargo run -p enclave-media --example mic_loopback         # hear yourself via Opus (headphones!)
```

## Sending files and large messages

The paperclip in the composer opens a menu -- **Send a file** or **Live share** --
then a native file picker. A file is never pushed to anyone: it is **offered**.
The recipient sees a prompt with the name and size (decrypted from a sealed
manifest, so the server never learns them) and chooses **Download** or
**Decline** -- nothing touches their disk until they accept. On accept the file
streams straight to disk in their `enclave-downloads/` directory (under the
keystore) under a sanitized name, never buffered whole in memory.

The offer stays in the chat as a labelled row whatever happens to it -- nothing
is ever silently removed:

- **Cancel** a download in progress and it is marked *aborted* but kept, with
  **Download again**: cancelling stops the transfer promptly (even a multi-GB
  one) without giving the file up.
- **Decline** is final -- the row stays, marked declined.
- If the sender **stops sharing** (a button on their own sent file) or goes
  offline, the recipient's row is marked *no longer available*, still in the chat.

Two delivery modes:

- **Stored** (Send a file, up to 250 MB): the server buffers the encrypted file
  on disk so it reaches a recipient who is currently offline. It is deleted after
  24 hours, or once the sender withdraws it. The server enforces a per-file
  (250 MB) and whole-store (2 GB) quota and refuses new files when free disk would
  drop below 4 GB -- a peer cannot fill the server.
- **Live share** (explicit, or automatically when a file is too big to store):
  the file streams in real time to whoever accepts within about 90 seconds, is
  never stored, and has no size cap. This needs the recipient online.

File bytes travel under a per-file content key, not the group message ratchet, so
cancelling a transfer never disturbs the conversation. A text message larger than
one frame is split and reassembled the same way. Transfers show a progress bar
while in flight. A received file is inert until you click **Open**, which hands it
to the OS default application; Enclave never opens or executes it automatically.
See THREAT_MODEL.md for the full file-sharing threat model.

## Still to come

- **Message timestamps.** The wire format has no time field, so the UI cannot
  show one.
- **Presence rules live in the UI.** Idle-to-away, status durations, and
  "a set status never upgrades" should be enforced by the core, with idle
  measured at the OS level rather than from window events.
- **A macOS capture backend.** The media API stubs cleanly there today.
- **A real two-machine call.** Everything below the portal dialog is verified
  on one box; two boxes over a network is not.

Chat messages are delivered reliably: text and MLS handshakes are acked by the
server, retransmitted (on reconnect and on a timer) until acked, and deduped on
the receiver, with the retransmit buffer persisted across restarts, so a
connection drop, a server restart, or the app closing mid-send does not lose a
message. A brief blip is invisible (the retransmit delivers it); if delivery is
persistently stuck, the client flushes the pending messages to disk and warns
you rather than retrying silently -- the messages keep trying and are never
dropped.

The crypto, transport, calls, screen/window/camera share, per-app and system
audio share, friends, presence, groups, large messages, consent-gated file
transfer, and reliable delivery are done and tested; see `ARCHITECTURE.md`.
