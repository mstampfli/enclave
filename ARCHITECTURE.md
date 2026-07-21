# Enclave -- architecture

End-to-end-encrypted voice/video/text, self-hosted. The server relays
ciphertext and never holds media keys. Better than the mainstream option on one
axis that matters: **trust** -- no third party in your trust base, identities you
verify yourself.

## Theory of operation

Each call and each DM is an **MLS group**. Members agree on a group secret via
MLS (`openmls`); from its exporter secret each sender derives a media key and
seals every *encoded* frame with an AEAD (ChaCha20-Poly1305), SFrame-style, then
**signs it with their Ed25519 identity key** so no other member can impersonate
them at the media layer (the AEAD key is group-derivable; the signature is not).
The self-hosted server routes those sealed frames (SFU fan-out) and relays MLS
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
  nonce-safe frame sealer/opener, safety numbers, the off-ratchet file-chunk
  sealer (`seal_chunk`/`open_chunk`), the off-ratchet ballot sealer
  (`seal_ballot`/`open_ballot`) and the linkable ring signatures (`ring`) that
  make an anonymous poll unattributable -- keyed by each member's existing Ed25519
  identity key, so a ring is assembled from local group state with no key
  distribution and nobody needing to be reachable -- and the self-update `rekey`
  that heals a desynced group.
- `enclave-media` -- the audio/video pipeline: Opus codec (`audio`), tested
  framing/format helpers (`frame`), cpal mic/speaker device I/O (`device`),
  H.264 encode (`video`), webcam capture (`camera`), and the per-platform
  capture backends (`screen`, `system_audio`) behind one platform-neutral API:

  | Capability | Windows | Linux (Wayland) | Linux (X11) |
  |---|---|---|---|
  | Screen/window share | DXGI duplication / WGC; the app enumerates sources | XDG portal ScreenCast: the *system* dialog picks, frames arrive over a PipeWire video stream | Raw grabs: RandR/EWMH enumeration in-app (same picker experience as Windows), MIT-SHM root grabs for monitors, XComposite pixmaps for windows |
  | System audio share | WASAPI endpoint loopback | PipeWire capture of the default sink monitor | same |
  | Per-app audio share | WASAPI process loopback (pid from the shared window) | not possible: the portal hides the picked window's identity, so shared audio falls back to the system mix | works: `_NET_WM_PID` gives the pid, PipeWire captures that app's output node (matched via the client's kernel-verified `pipewire.sec.pid`) |
  | Camera | Media Foundation (via nokhwa) | V4L2 (via nokhwa; metadata nodes filtered by `device_caps`) | same |

  The session type picks the Linux backend (`WAYLAND_DISPLAY` else `DISPLAY`).
  Starting a Wayland share is asynchronous (a human sits behind the portal
  dialog and may cancel), so every `ScreenCapture` carries a shared
  `CaptureStatus` (`Starting -> Live -> Ended(reason)`); the client polls it
  and reaps a share that ended on its own (cancel, compositor revoke, closed
  window, death), tearing down the paired system-audio capture with it.
- `enclave-transport` -- signaling + media transport. A pure `relay` routing
  core (metadata only; every payload opaque) drives both a reliable WebSocket
  signaling channel and a low-latency UDP media channel (`Server` runs both over
  shared state; `Connection` and `MediaSocket` are the client sides). TLS (wss)
  on the signaling hop and zero-knowledge account auth (OPAQUE, the `opaque`
  module) are implemented here. `msgqueue` is the bounded store-and-forward queue
  for offline members; `filestore` is the on-disk, quota-and-TTL-bounded store
  for offered files awaiting a recipient's consent (see THREAT_MODEL.md,
  "File sharing and large messages").
- `enclave-client` -- lib + bin. The lib is the high-level `Client` controller
  (the app-logic API the UI drives); the bin is the self-contained WebView
  window (see "UI" below) that bridges IPC to the controller. `transfer` splits a
  message or file too large for one 1 MiB frame into chunks. Text and profiles
  travel as MLS-sealed `Part`s reassembled in memory (bounded `Reassembler`); a
  file's bulk bytes instead ride a **per-file content key** (`crypto::seal_chunk`,
  never the MLS message ratchet -- see invariant 6) and stream straight to disk
  via `FileSink` (never buffered whole) under a sanitized name in a downloads
  directory (see THREAT_MODEL.md).
- `enclave-server` -- signaling relay + SFU fan-out; holds no media keys.
- **Workspaces** (Discord/Slack-style text + voice channels with members, roles,
  categories, and private channels) are an organizational and key-coordination
  layer over the existing group machinery -- *a channel is a group* -- spread
  across the crates above, not a new cryptosystem. `protocol` defines the op
  types (`WorkspaceOp`, the identity-signed `SignedOp`, the ids); `crypto::sign`
  signs/verifies ops over identity Ed25519 keys and `crypto::workspace` is the
  op-log state machine (`WorkspaceState::apply`); `transport::workspaces`
  (`WorkspaceStore`) stores the signed logs, the durable per-channel `HK`-sealed
  history (append-only, capped, paged by seq), and the admin-minted invite codes,
  and re-validates every op at ingress; `client` coordinates the one workspace
  MLS group (keys all public channels), a separate MLS group per private channel,
  the per-channel history-key epochs, a serialized op-submission queue, and a
  per-workspace add queue that drains member-add bursts without dropping any.
  Design and keying: docs/WORKSPACES.md; threat posture: THREAT_MODEL.md
  "Workspaces".

## UI (self-contained window -- hard requirement)

The client is **always a native, self-contained desktop window**, never a browser
and never a localhost web service. It embeds a system WebView (`wry`/`tao` ->
WebView2 on Windows, WebKitGTK on Linux -- where the webview mounts into the
tao window's GTK box and H.264 WebCodecs decode rides WebKit's GStreamer,
checked at UI boot) inside a single app window.

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
4. A file is never delivered to a recipient without their explicit consent. An
   incoming file is only ever an offer (a sealed manifest); its bytes are
   requested only by an explicit accept, and a file smuggled over the text
   channel is dropped rather than written. Consent is re-entrant: aborting a
   download (`FileAbort`) keeps the offer, declining (`FileDecline`) gives it up.
5. A chat message is not silently lost. Text and MLS handshakes are sent
   reliably (`ClientMsg::Reliable`): the server acks a message only once it has
   delivered it to online members and persisted it for offline ones, and the
   sender retransmits (on reconnect and on a timer) until acked. The unacked
   buffer, its sequence counter, and the receive-side dedup set are persisted in
   the encrypted session, so a message sent moments before the app closed is
   still retransmitted on next launch, and a resent message is shown once even
   if both peers restarted. The receiver dedups a resent message by its transfer
   id, so at-least-once + dedup is effectively exactly-once. A persistent failure
   (retrying past a threshold) warns the user rather than retrying forever
   silently. TCP handles bytes-to-socket; this handles message-to-recipient,
   which TCP does not.
6. Bulk file data never rides the MLS message ratchet. A file's chunks are sealed
   under a per-file content key (`crypto::seal_chunk`/`open_chunk`; the key
   travels only inside the MLS-sealed manifest), so a file of any size costs
   exactly one MLS message (the manifest) and a dropped chunk -- from a cancelled
   or declined download -- never desyncs the group's ratchet. Enforced by the
   chunk paths calling `seal_chunk`/`open_chunk`, never `encrypt_text`
   (`client/src/lib.rs`), and proven end to end by
   `client_flow::large_message_and_file_transfer_between_two_clients` (a
   multi-chunk file) plus `mls_group::a_backlogged_receiver_skips_forward_to_the_latest_message`
   (a conversation that fell behind still heals).
7. A ballot never reveals its content through its shape. Votes on buffered and
   anonymous polls are sealed off the ratchet under a per-poll content key
   (`crypto::seal_ballot`) and encoded at a fixed width -- the poll id plus a
   256-bit selection bitmask (`transfer::VOTE_BODY_BYTES`) -- so every ballot the
   relay holds is the same size whatever it says, and the mask is canonical so
   index ordering carries nothing either. A variable-length encoding (a list of
   chosen indices) would let the untrusted relay count a voter's selections with
   no key at all. Enforced by `VoteBody::encode`/`decode` being the only ballot
   codec, and proven by
   `transfer::tests::a_sealed_ballot_is_the_same_size_whatever_it_says` and
   `the_anonymous_ballot_the_relay_stores_is_size_invariant`.
8. Workspace authority is a signed, append-only op-log, not the server, and it is
   permission-based (RBAC), deny-by-default. Every structural change is an
   identity-signed `SignedOp` chained by sequence number + SHA-256 `prev_hash`;
   clients replay the log and authorize each op against the author's **effective
   permissions** -- the union of the roles assigned to them. A member with no role
   can do nothing; the owner's power is a protected built-in `Owner` role assigned
   at genesis (not a special case: `permissions_of` grants nothing without an
   assignment, so a bypassed check fails closed). No one may create or assign a
   role carrying a permission they do not themselves hold (no privilege
   escalation), the Owner role and owner are tamper-protected, and a category move
   that would cycle or exceed `MAX_CATEGORY_DEPTH` is refused. So the relay,
   holding no signing key, cannot forge membership, roles, or what a role permits.
   Enforced by `crypto::workspace::WorkspaceState::apply` (rejecting `BadSeq` /
   `BadChain` / `BadSignature` / `Unauthorized` / `BadTarget`) and `crypto::sign`,
   re-validated at the relay's ingress (`transport::workspaces`), and proven by the
   crypto workspace tests (`genesis_establishes_owner_and_roles`,
   `role_ops_prevent_privilege_escalation_and_protect_the_owner_role`,
   `a_bare_member_cannot_touch_roles_and_the_owner_is_unremovable`,
   `a_forged_or_reordered_entry_is_rejected`, `a_tampered_op_body_breaks_the_signature`,
   `a_category_move_is_rejected_when_it_would_cycle_or_target_is_missing`,
   `category_nesting_is_depth_bounded`).
9. A private channel's content is its own MLS group, not a server-filtered view.
   Public channels key off the single workspace group (one commit rekeys them
   all); a private channel gets a separate MLS group over its subset, so a
   misrouting or malicious relay cannot leak its messages to a workspace member
   who was never added -- they hold no key. Enforced by `client` giving each
   private channel its own group and history epoch; proven by
   `a_private_channel_is_readable_only_by_its_members` and (at the state-machine
   level) `a_private_channel_tracks_its_own_member_set`.
10. Docs update in the same commit as the change they describe.

## Dependency plan (added per-phase, in the crate that first uses them)

| Phase | Crate | Adds |
|---|---|---|
| 1 | crypto | `openmls`, `ed25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize` |
| 2 | transport, server | async runtime + TLS WebSocket signaling |
| 3 | media | `cpal`, `opus`; transport gains WebRTC/QUIC media |
| 5 | media | `nokhwa` (camera), a video codec (VP9/AV1), screen capture |
| 6 | client | `wry`/`tao` (self-contained WebView window) |
| Linux port | media | `ashpd` (XDG portal), `pipewire` (video + loopback streams), `v4l` (capture-node filter) -- Linux-only target deps |

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
   monotonic-counter `MediaSealer`, anti-replay `MediaOpener`; every frame also
   Ed25519-signed by the sender and verified against the roster key, so a member
   cannot impersonate another sender at the media layer -- see `MediaSigner`) +
   `enclave-media::audio` (Opus 48 kHz/20 ms). Proven by
   `crates/crypto/tests/media_seal.rs` (opaque wire; tamper/forgery/
   impersonation/replay/cross-epoch rejected, out-of-order tolerated) and
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
5. [DONE] Video + screenshare, on both desktop platforms. Sent as H.264
   inside the same sealed-frame path as audio (`MediaKind::Screen` for the
   share viewer, `MediaKind::Video` for camera tiles); decoded in the UI by
   WebCodecs. Capture backends per platform (see the `enclave-media` table):
   WGC/DXGI + WASAPI loopback on Windows; XDG portal + PipeWire (Wayland) and
   raw MIT-SHM/XComposite grabs (X11) on Linux (validated end to end by
   `crates/media/examples/{screen,system_audio,camera,mic}_probe` on real
   hardware; the interactive portal-dialog leg on a real desktop session).
6. [DONE] Self-contained window + client controller. `enclave-client` is a lib +
   bin: the lib is a high-level `Client` controller (connect, start group,
   invite, send text, safety number, event pump) proven by
   `crates/client/tests/client_flow.rs` (two clients chat via the API); the bin
   is a wry window whose UI is bundled into the binary (`src/ui/index.html`,
   never a browser or localhost) and driven over an IPC bridge. Presence and a
   persistent friends roster (requests, accept/decline, per-user status) are
   served by the relay (`transport::friends`, disk-backed) and rendered by the
   client. The window runs on Windows and Linux; only CI cannot open a GUI.
   A runnable prototype of the interface lives in `design/redesign.html`.
7. [DONE] Hardening. ASVS L2 review (`THREAT_MODEL.md`); relay access control is
   deny-by-default (non-members cannot join/invite/inject); untrusted
   deserialization is size-bounded (UDP 64 KiB, WS 1 MiB); parsers fuzzed for
   panic-safety; optional TLS (wss) on the signaling hop; per-connection rate
   limiting; a CI gate runs fmt + clippy(-D warnings) + tests + `cargo audit` +
   secret scan on every push (`.github/workflows/ci.yml`). One upstream advisory
   (RUSTSEC-2026-0124) is waived as verified
   non-exploitable and tracked.
8. [DONE] Workspaces (text + voice channels, roles, categories, private
   channels). Milestones M0-M6 per docs/WORKSPACES.md: the signed op-log and
   role-chain (`crypto::workspace`, `crypto::sign`); public text channels keyed
   off the workspace MLS group; scrollback under rotating per-channel history-key
   epochs, persisted to disk and served in bounded pages (`transport::workspaces`);
   private channels each in their own MLS group; persistent per-channel voice with
   presence; the workspace UI (rail, channel tree, channel view, voice stage),
   which reuses the direct-message message renderer and the app's modal system
   rather than a parallel one; admin-minted invite codes with a concurrent-add
   queue so a burst of redemptions is admitted without drops; a collapsible,
   drag-to-nest sidebar hierarchy (channels and categories reparent by drag,
   cycle- and depth-bounded in the op-log); and an admin drag to move a member
   between voice channels. Proven by `crates/crypto` workspace/sign tests (incl.
   reparent / cycle / depth), the `transport::workspaces` store tests (history
   paging, restart durability, invite validation), and the
   `crates/client/tests/client_flow.rs` workspace tests (create + add member,
   members exchange in a channel, a non-member sees nothing, a late joiner reads
   pre-join history, a private channel is readable only by its members, voice
   presence, an invite admits a redeemer, a burst of redemptions all get in, a
   channel is created inside a category, and an admin moves a member between
   voice channels).

Each phase ends compiling and tested; no half-done work carried forward.
