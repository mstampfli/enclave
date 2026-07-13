# Working on Enclave

Read `ARCHITECTURE.md` first: it explains what each crate is for and which
invariants must not break. This file is the day-to-day loop.

## The dev loop

```
cargo build                 # whole workspace
cargo test                  # ~100 tests, all headless
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

CI runs exactly those four on **Windows and Linux**, plus `cargo audit` and a
secret scan, and every one of them must be green before a merge. Run them
locally rather than discovering it on the push.

Linux needs a few system libraries first; see "Build dependencies" in `RUN.md`.

### Trying it for real

```
cargo run -p enclave-server                       # relay on 127.0.0.1:8443
cargo run --release -p enclave-client --bin enclave   # a client window
```

Run two clients with two usernames against one server to talk to yourself.
Use `--release` for anything involving video: the H.264 encoder is slow in a
debug build.

### Hardware paths CI cannot reach

Capture devices do not exist on a CI runner, so they are covered by scored
probes you run yourself. They print `[PASS]`/`[FAIL]` and exit non-zero on
failure:

```
cargo run -p enclave-media --example mic_probe
cargo run -p enclave-media --example camera_probe
cargo run -p enclave-media --example system_audio_probe          # audible
cargo run -p enclave-media --example screen_probe -- --self-test      # Wayland/PipeWire
cargo run -p enclave-media --example screen_probe -- --x11-self-test  # X11 (works under Xvfb)
cargo run -p enclave-media --example screen_probe                     # the real portal dialog
```

If you touch `crates/media`, run the ones your change can break, and say in the
commit which of them you ran.

## The front end

The UI is a single file, `crates/client/src/ui/index.html`, bundled into the
binary with `include_str!`. It talks to Rust over wry's IPC bridge: the UI sends
`UiCommand`s and receives `UiEvent`s, both defined in
`crates/client/src/main.rs`. No key material ever reaches the WebView.

`design/redesign.html` is the same interface as a standalone prototype with a
state simulator; open it in a browser to try call, ring, share, and verification
states without a server. Changes to the design language should land in both
files.

## Conventions

- **Commits** are conventional and descriptive (`feat(media):`, `fix(ui):`,
  `docs:`), explain *why* in the body, and stay small.
- **Docs change in the same commit as the code they describe.** A stale
  `ARCHITECTURE.md` is a bug.
- **Plain ASCII** in code, comments, and docs. No em dashes.
- **Comments say why, not what.** Do not narrate the code; explain the
  constraint the code cannot show.
- **Invariants are not negotiable** (see `ARCHITECTURE.md`): the server never
  holds a key or a plaintext; an AEAD nonce is never reused under one media key;
  group membership changes only via a client-signed MLS commit.

## Adding a dependency

Heavy dependencies are added in the crate that first needs them, and recorded in
the dependency table in `ARCHITECTURE.md`. Anything platform-specific goes under
a `[target.'cfg(...)'.dependencies]` block so the other platform does not pay
for it. `cargo audit` gates the result.
