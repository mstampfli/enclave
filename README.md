# Enclave

End-to-end-encrypted voice, video, and text. Self-hosted relay: it forwards
ciphertext and never holds your keys. You verify your friends' identities
yourself, so no server -- not even your own -- can slip a listener into a call.

Not a feature-for-feature clone of the big chat apps. Better on the one axis
that matters: **trust**.

## Status

Phase 6 -- the full premise proven end to end, multi-party groups, and a
self-contained window (`cargo test`, 36 tests): audio is Opus-encoded, sealed
per-frame, relayed through the live server (which sees only ciphertext), then
opened and decoded back to clear audio; groups rekey on join/leave, cutting
departed members off; sealed frames stream over a low-latency UDP carrier; and a
`Client` controller (connect, group, invite, E2E text, safety number) drives a
wry/WebView2 window whose UI is bundled into the binary. Remaining: presence and
a persistent friends roster, on-hardware validation of audio devices and the
window, video/screenshare, and hardening. See `ARCHITECTURE.md` for the roadmap
and `THREAT_MODEL.md` for the STRIDE analysis. Nothing here is secure to rely on
yet.

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
