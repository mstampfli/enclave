# Enclave

End-to-end-encrypted voice, video, and text. Self-hosted relay: it forwards
ciphertext and never holds your keys. You verify your friends' identities
yourself, so no server -- not even your own -- can slip a listener into a call.

Not a feature-for-feature clone of the big chat apps. Better on the one axis
that matters: **trust**.

## Status

Phase 3 -- the full premise, proven end to end (`cargo test`, 29 tests): a tone
is Opus-encoded, sealed per-frame, relayed through the live server (which sees
only ciphertext), then opened and decoded back to clear audio on the far end.
Remaining Phase 3 glue: mic/speaker device I/O (`cpal`) and a low-latency UDP
media carrier. See `ARCHITECTURE.md` for the roadmap and `THREAT_MODEL.md` for
the STRIDE analysis. Nothing here is secure to rely on yet.

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
