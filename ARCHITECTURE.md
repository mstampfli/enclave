# Enclave -- architecture

End-to-end-encrypted voice/video/text, self-hosted. The server relays
ciphertext and never holds media keys. Better than the mainstream option on one
axis that matters: **trust** -- no third party in your trust base, identities you
verify yourself.

## Theory of operation

Each call and each DM is an **MLS group**. Members agree on a group secret via
MLS (`openmls`); from its exporter secret each sender derives a media key and
seals every *encoded* frame with an AEAD (ChaCha20-Poly1305), SFrame-style. The
self-hosted server routes those sealed frames (SFU fan-out) and relays MLS
handshake messages, encrypted text, and presence -- all opaque to it except
routing metadata.

Encrypting the *encoded* frame (not raw samples) is the key move: there is no
lossy codec stage after encryption to corrupt the ciphertext, so the wire
carries opaque bytes end to end.

## Trust model

- **Server: semi-trusted.** Trusted to route and stay available; untrusted for
  content. Sees metadata (who is in a call, when, packet sizes/timing) -- an
  accepted tradeoff of the SFU topology.
- **Peers: authenticated, then verified.** Identity = Ed25519 long-term key.
  Keys pinned on first use; a safety-number lets users confirm out-of-band that
  the server did not insert a ghost member.
- **Accounts: zero-knowledge.** Registration and login use OPAQUE (RFC 9807): the
  server stores only an irreversible per-account envelope and never sees the
  password, even at signup. See THREAT_MODEL.md ("Account authentication").
- **No hand-rolled crypto.** We assemble audited primitives (see
  `docs/PRIMITIVES.md`) and wire them together correctly.

## Codemap (dependency DAG -- arrows point to dependencies)

```
protocol   (wire types; the "server sees only ciphertext" invariant lives here)
   ^  ^  ^  ^
crypto  media  transport
   ^      ^      ^
   +------+------+---- client (bin: enclave)      -> WebView UI (Phase 6)
          transport <- server (bin: enclave-server) -> signaling + SFU
```

- `enclave-protocol` -- shared wire types. Every server-visible payload is
  `Sealed` (opaque) or routing metadata. Depends on nothing internal.
- `enclave-crypto` -- identity keystore, MLS groups, media-key schedule, the
  nonce-safe frame sealer/opener, safety numbers.
- `enclave-media` -- the audio pipeline: Opus codec (`audio`), tested
  framing/format helpers (`frame`), and cpal mic/speaker device I/O (`device`).
- `enclave-transport` -- signaling + media transport. A pure `relay` routing
  core (metadata only; every payload opaque) drives both a reliable WebSocket
  signaling channel and a low-latency UDP media channel (`Server` runs both over
  shared state; `Connection` and `MediaSocket` are the client sides). TLS (wss)
  on the signaling hop and zero-knowledge account auth (OPAQUE, the `opaque`
  module) are implemented here.
- `enclave-client` -- lib + bin. The lib is the high-level `Client` controller
  (the app-logic API the UI drives); the bin is the self-contained WebView
  window (see "UI" below) that bridges IPC to the controller.
- `enclave-server` -- signaling relay + SFU fan-out; holds no media keys.

## UI (self-contained window -- hard requirement)

The client is **always a native, self-contained desktop window**, never a browser
and never a localhost web service. It embeds a system WebView (`wry`/`tao` ->
WebView2 on Windows, WebKit elsewhere) inside a single app window.

- The front end may be whatever web stack we like -- TypeScript, React, Svelte,
  or plain HTML/CSS. It is **bundled into the binary** (today a single
  `src/ui/index.html` via `include_str!` + wry `with_html`; a custom `enclave://`
  protocol when it grows to multiple assets), never served over `http://localhost`
  and never opened in the user's browser.
- The Rust core and the front end talk over `wry`'s IPC bridge (typed
  request/response), so all crypto, keys, capture, and transport stay in Rust;
  the WebView renders UI only and never touches key material.
- Media rendering: decoded audio plays via the Rust side (`cpal`); video frames
  are handed to the WebView as an offscreen surface / canvas. The WebView is a
  view layer, not a media authority.

**A browser build MAY exist, but is not the default.** To keep that door open,
the portable core (`protocol`, `crypto`) stays `wasm32`-clean -- no native-only
deps -- and the platform layers (`media`, `transport`) sit behind traits with
swappable backends:

| Layer | Native window (default) | Browser (optional) |
|---|---|---|
| Core (protocol, crypto/MLS/SFrame) | Rust native | same Rust, compiled to WASM |
| Capture/playback | `cpal` / `nokhwa` | `getUserMedia` + WebAudio |
| Media transport | WebRTC/QUIC (Rust) | browser WebRTC + **Encoded Transform** (per-frame E2E, same SFrame bytes) |
| Signaling | Rust TLS WebSocket | browser `WebSocket` |

The wire protocol and the sealed-frame format are identical across both, so a
native client and a browser client can be in the same call. We build the native
window by default and only add the WASM/browser target when we choose to.

## Invariants

1. The server never possesses a media key or plaintext. Enforced by the type
   system: server-facing payloads are `enclave_protocol::Sealed`.
2. An AEAD nonce is never reused under one media key. Enforced by a monotonic
   per-sender counter owned by the frame sealer (Phase 3).
3. Group membership changes only via a client-signed MLS Commit. The server
   cannot add a member.
4. Docs update in the same commit as the change they describe.

## Dependency plan (added per-phase, in the crate that first uses them)

| Phase | Crate | Adds |
|---|---|---|
| 1 | crypto | `openmls`, `ed25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize` |
| 2 | transport, server | async runtime + TLS WebSocket signaling |
| 3 | media | `cpal`, `opus`; transport gains WebRTC/QUIC media |
| 5 | media | `nokhwa` (camera), a video codec (VP9/AV1), screen capture |
| 6 | client | `wry`/`tao` (self-contained WebView window) |

## Roadmap

0. [DONE] Scaffold + design docs.
1. [DONE] Identity + MLS group + safety-number verification. `enclave-crypto`
   (`Identity`, `Group`, `SafetyNumber`); tests in `crates/crypto/tests/mls_group.rs`
   prove two members agree on the media root secret + safety number over a
   bytes-only exchange, that membership changes rekey + change the number, and
   that a tampered key package is rejected.
2. [DONE] E2E text over MLS + the relay server. `enclave-transport` has a pure
   routing core (`Relay`) and an async WebSocket `server`/`Connection`;
   `enclave-crypto::Group` gained `encrypt_text`/`decrypt_text`. Tests:
   `crates/crypto/tests/e2e_text.rs` (text round-trips, ciphertext hides the
   plaintext, tampering/non-member rejected) and
   `crates/transport/tests/{relay_core,relay_e2e}.rs` (routing correctness; two
   clients exchange text through a live server, which forwards ciphertext
   unchanged and never sees the plaintext).
3. [DONE, minus device I/O] Audio pipeline end to end. `enclave-crypto::media`
   (SFrame-style per-frame ChaCha20-Poly1305 keyed from the media root secret;
   monotonic-counter `MediaSealer`, anti-replay `MediaOpener`) +
   `enclave-media::audio` (Opus 48 kHz/20 ms). Proven by
   `crates/crypto/tests/media_seal.rs` (14 cases: opaque wire, tamper/forgery/
   replay/cross-epoch rejected, out-of-order tolerated) and
   `crates/transport/tests/audio_full_stack.rs` (tone -> encode -> seal -> relay
   -> open -> decode -> clear voice; wire carries only ciphertext).
   **Media carrier:** a low-latency UDP path (`serve_media` + `MediaSocket`)
   fans sealed frames out over UDP; the reliable WebSocket path remains as a
   fallback. See `crates/transport/tests/udp_media.rs`.
   **Device I/O:** `cpal` mic capture and speaker playback are built on tested
   framing/format helpers (`crates/media/src/frame.rs`); the device streams
   themselves are compile-verified only (no audio hardware in CI) and need
   on-device validation.
4. [DONE] Multi-party groups with rekey on join/leave. `Group::add_member` now
   returns the commit (to fan out to existing members) plus the welcome;
   `apply_commit` advances an existing member; `remove_member` rekeys and cuts
   the removed member off. The relay already fans out to N members. Proven by
   `crates/crypto/tests/multiparty.rs` (three members agree; add/remove rekey;
   a removed member cannot open post-removal media) and the larger-group relay
   fan-out test.
5. Video + screenshare.
6. [MOSTLY DONE] Self-contained window + client controller. `enclave-client` is
   now a lib + bin: the lib is a high-level `Client` controller (connect, start
   group, invite, send text, safety number, event pump) proven by
   `crates/client/tests/client_flow.rs` (two clients chat via the API); the bin
   is a wry/WebView2 window whose UI is bundled into the binary (`src/ui/`,
   never a browser or localhost) and driven over an IPC bridge. **Remaining:**
   presence broadcast and a persistent friends roster (currently invite-by-name),
   and on-hardware validation of the window (it compiles; GUI can't run in CI).
7. [DONE] Hardening. ASVS L2 review (`THREAT_MODEL.md`); relay access control is
   deny-by-default (non-members cannot join/invite/inject); untrusted
   deserialization is size-bounded (UDP 64 KiB, WS 1 MiB); parsers fuzzed for
   panic-safety; optional TLS (wss) on the signaling hop; per-connection rate
   limiting; a CI gate runs fmt + clippy(-D warnings) + tests + `cargo audit` +
   secret scan on every push (`.github/workflows/ci.yml`). One upstream advisory
   (RUSTSEC-2026-0124) is waived as verified
   non-exploitable and tracked.

Each phase ends compiling and tested; no half-done work carried forward.
