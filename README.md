# Enclave

End-to-end-encrypted voice, video, and text. Self-hosted relay: it forwards
ciphertext and never holds your keys. You verify your friends' identities
yourself, so no server -- not even your own -- can slip a listener into a call.

Not a feature-for-feature clone of the big chat apps. Better on the one axis
that matters: **trust**.

## Status

The whole premise runs end to end on **Windows and Linux** (`cargo test`, 101
tests): audio is Opus-encoded, sealed per-frame, relayed through the live server
(which sees only ciphertext), then opened and decoded back to clear audio;
groups rekey on join/leave, cutting departed members off; sealed frames stream
over a low-latency UDP carrier. Calls carry **screen share, window share, and
camera**, plus system or per-app audio, with capture backends per platform
(WGC/DXGI and WASAPI on Windows; the XDG portal with PipeWire on Wayland, raw
MIT-SHM/XComposite grabs on X11) -- all validated on real hardware, not just
compiled. Friends, requests, presence, and named groups are in; the relay has
deny-by-default access control, size-bounded panic-safe parsing, optional TLS
(wss) on the signaling hop, and per-connection rate limiting; and CI gates every
push on both platforms (fmt, clippy, tests, dependency audit, secret scan). The
ASVS L2 review is complete.

The client is a self-contained native window (WebView2 on Windows, WebKitGTK on
Linux) with its own interface; `design/redesign.html` is a runnable prototype
of it.

**Remaining:** message timestamps on the wire, verification marks persisted in
the keystore, presence rules moved into the core, a macOS capture backend, and a
real two-machine call. See `ARCHITECTURE.md` for the roadmap and
`THREAT_MODEL.md` for the STRIDE + ASVS analysis. Nothing here is audited or
secure to rely on yet.

## Workspace

| Crate | Job |
|---|---|
| `enclave-protocol` | Wire types; encodes "server sees only ciphertext" |
| `enclave-crypto` | Identity, MLS groups, media-key schedule, fingerprints |
| `enclave-media` | Capture / encode / decode (real-time hot path) |
| `enclave-transport` | TLS signaling + WebRTC/QUIC media transport |
| `enclave-client` | The app (`enclave`), WebView UI |
| `enclave-server` | Self-hosted signaling + SFU (`enclave-server`) |

## Build

```
cargo build
cargo run -p enclave-client   # prints the Phase 0 scaffold banner
```

## License

AGPL-3.0-or-later. A privacy tool should stay open and stay free; the AGPL keeps
any hosted fork open too.
