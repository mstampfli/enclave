# Enclave -- threat model (STRIDE)

Living document. Re-run when a trust boundary moves, a feature ships, or after
any incident.

## 1. What are we working on?

E2E-encrypted voice/video/text with a self-hosted signaling+SFU server. v1
scope: 1:1 and small-group calls, E2E text DMs, presence, friends list.

## 2. Decomposition

- **External entities:** users (each with an Ed25519 identity key).
- **Processes:** client app; signaling+SFU server.
- **Data stores:** server directory (user->identity pubkey, published
  KeyPackages, presence); client keystore (private identity key, MLS state).
- **Data flows:** client<->server signaling (MLS messages, text ciphertext,
  presence); client<->SFU media (sealed frames); client<->client via the SFU.
- **Trust boundary:** the server. Trusted for availability/routing, **untrusted
  for content and for honest group membership.**

## 3. Threats and mitigations (client <-> untrusted server)

| STRIDE | Threat | Decision | Mitigation / note |
|---|---|---|---|
| **S** Spoofing | Server or attacker inserts a ghost member to obtain group keys | Mitigate | MLS membership authenticated by identity-signed KeyPackages; out-of-band **safety-number** verification; TOFU key pinning |
| **T** Tampering | Server/MITM alters media, text, or handshake | Mitigate | AEAD auth tag on every frame; MLS message integrity; TLS on signaling hop; reject on auth failure |
| **R** Repudiation | No proof of who said what | Accept | Private-comms product; no audit log by design. MLS still authenticates sender within a group |
| **I** Info disclosure (content) | Server reads media/text | Mitigate | E2E encryption; keys never leave client; server sees only `Sealed` bytes |
| **I** Info disclosure (metadata) | Server sees who/when/sizes | **Accept** | Inherent to self-hosted SFU; documented, chosen tradeoff. (Metadata resistance was explicitly out of scope for v1) |
| **D** Denial of service | Peer/server floods or drops traffic | Mitigate | Auth-required connections; rate limits; per-call resource caps; timeouts. Availability depends on your server (single point, self-owned) |
| **E** Elevation | Participant/server gains rights or reads past traffic | Mitigate | MLS forward secrecy + post-compromise security (epoch ratchet) bounds compromise; deny-by-default authz; only signed Commits change membership |

## 4. Validation

Each mitigation gets a test as its phase lands (see ARCHITECTURE.md roadmap):
- Phase 1 [DONE]: tampered key package rejected; honest members agree on the
  safety number; membership change alters it. See `crates/crypto/tests/mls_group.rs`.
- Phase 2 [DONE]: relayed text bytes do not contain plaintext and are forwarded
  unchanged by the server; tampering and non-members rejected. See
  `crates/crypto/tests/e2e_text.rs`, `crates/transport/tests/relay_e2e.rs`.
- Phase 3 [DONE]: sealed frames are opaque and do not contain the Opus packet;
  monotonic counter proves nonces never repeat; tamper/forgery/replay/cross-epoch
  rejected. See `crates/crypto/tests/media_seal.rs`,
  `crates/transport/tests/audio_full_stack.rs`.
- Phase 4 [DONE]: add/remove rekey the group; a removed member cannot derive the
  new epoch secret or open post-removal media. See `crates/crypto/tests/multiparty.rs`.
- Phase 7 [DONE]: ASVS L2 review complete (see below). Relay access control and
  deserialization bounds fixed and tested; parsers fuzzed for panic-safety; TLS
  on the signaling hop and per-connection rate limiting implemented and tested;
  CI gate (fmt/clippy/test/audit/secret-scan) in `.github/workflows/ci.yml`. One
  upstream advisory waived as verified non-exploitable.

## Accepted risks (explicit)

- **Metadata visible to the server** (who/when/sizes). Chosen for v1.
- **Availability depends on the self-hosted server.** It is a single point, but
  it is yours; no third-party dependency.
- **Repudiation** is not provided (no audit log), by design.

## Local capture surface (screen/window/audio share)

Capture happens entirely on the user's machine, before the sealed-frame
boundary; the wire story is unchanged (captured frames are H.264/Opus encoded,
then sealed and signed like all media). What the capture layer itself trusts:

- **User consent.** On Wayland, screen/window selection is *mediated by the
  OS*: the XDG portal's own dialog picks the source and the compositor
  enforces the grant (spoofing the picker is out of our reach by design; the
  restore token is kept in-process only, never on disk). On Windows and on
  X11 the app enumerates sources and grabs directly, as is native there --
  X11 in particular has no capture permission model at all (any client may
  read the screen), so the in-app picker *is* the consent step, same as every
  X11 screen sharer. Shared system/app audio is opt-in per share and stops
  with it.
- **The media daemons are in the user's trust domain.** PipeWire (Linux) and
  the audio engine (Windows) run as the same user; a compromised daemon could
  already read the screen and mic, so we defend integrity, not against them:
  every buffer they hand us is bounds-checked (`tighten_to_bgra` rejects
  short/degenerate buffers instead of over-reading; chunk sizes are clamped to
  the mapped length) and a dead/revoked stream ends the share visibly instead
  of freezing it silently.
- **Per-app audio matching** (Linux) uses the *kernel-verified*
  `pipewire.sec.pid` on the owning client object (SO_PEERCRED), not the
  client's self-reported process id, so one local app cannot trivially
  impersonate another's audio stream to get itself captured; the self-reported
  id is only a fallback for stacks that lack the sec pid.

## ASVS L2 review (Phase 7)

Target level L2 (private communications). Chapters touched and status:

- **V4 Access Control** [FIXED]: the relay is deny-by-default. A device can only
  bootstrap an empty group or be added via a Welcome from a current member;
  non-members cannot join, invite, or inject traffic (WS and UDP). See
  `crates/transport/tests/relay_core.rs::non_member_cannot_join_or_inject`.
- **V5/V12 Untrusted deserialization** [FIXED]: UDP frames use a size-limited
  bincode config (64 KiB) on both ends; the WS signaling channel caps messages
  at 1 MiB. The crypto parsers reject malformed/truncated input with errors, not
  panics -- fuzzed by `crates/crypto/tests/robustness.rs`.
- **V6 Stored Cryptography** [OK]: approved AEADs only (ChaCha20-Poly1305 for
  media, AES-128-GCM via MLS); media-key derivation intermediates are zeroized.
  The long-term identity key is written to disk only encrypted under a
  password-derived key (Argon2id -> ChaCha20-Poly1305); see the account section.
- **V7 Error Handling & Logging** [OK]: the server drops bad input silently and
  logs no key material; errors carry no secrets.
- **V9 Communications** [FIXED]: optional TLS (wss) on the signaling hop via
  `Server::serve_signaling_tls` + `Connection::connect_tls` (rustls/ring); the
  server binary serves wss when `ENCLAVE_TLS_CERT`/`ENCLAVE_TLS_KEY` are set. See
  `crates/transport/tests/tls_signaling.rs`.
- **V11 Business Logic** [FIXED]: a per-connection token bucket
  (`ratelimit::TokenBucket`) throttles signaling floods; unit-tested with an
  injected clock.

### Known advisory (waived: verified not exploitable, tracked)

- **RUSTSEC-2026-0124** -- `libcrux-chacha20poly1305` < 0.0.8. The advisory (read
  in full) is an **encryption-side** bug: `libcrux_chacha20poly1305::encrypt`
  (and the xchacha variant) panic when the *caller* passes an output buffer
  longer than `plaintext.len() + TAG_LEN`, and only where that length is
  attacker-controlled. It is **not** a decrypt/open bug. Severity 8.2. **Not
  exploitable in Enclave**, verified four independent ways:
  1. **Wrong operation, caller-controlled buffer.** The panic is on `encrypt`,
     driven by a caller-chosen oversized output buffer. hpke-rs / libcrux-aead
     size their own buffers to exactly `ptxt + TAG`; that length is never
     attacker-controlled in library usage. A received attacker-crafted message
     is *decrypted*, which cannot reach the affected function at all.
  2. **Wrong AEAD.** Our ciphersuite is `...AES128GCM...`; libcrux routes AES-GCM
     to its AES-GCM code, never to ChaCha, so ChaCha `encrypt` is never called.
  3. **Structurally excluded.** Our KeyPackage advertises only the AES-GCM
     ciphersuite (`enclave_capabilities`), so a peer cannot add us to a ChaCha
     group even by choosing one -- ChaCha can never be negotiated for us.
  4. **Not present where it runs.** `libcrux-chacha20poly1305` is absent from the
     Windows client build graph (`cargo tree -i` is empty), and `enclave-server`
     does not depend on `enclave-crypto`, so the relay never pulls libcrux.

  The correct remediation is an upstream bump, not forking a formally-verified
  crypto crate (which would void its verification provenance). No upstream fix is
  available yet: `openmls_rust_crypto` 0.5.1 and `hpke-rs-libcrux` 0.6.1 are the
  latest and exact-pin `libcrux-aead 0.0.7`. Waived in CI with this
  justification; re-checked on every build.

## Account authentication (STRIDE + ASVS L2) -- zero-knowledge via OPAQUE

Target level **L2**. Scope: account create / login / logout, credential storage,
and the identity key at rest.

Auth uses **OPAQUE** (RFC 9807), an augmented PAKE, via the `opaque-ke` crate
(Meta's reference implementation; protocol audited by NCC Group). The server
stores only a per-account **envelope** it cannot reverse, and the password never
leaves the client -- not at login and not even at registration. Cipher suite:
Ristretto255 OPRF + Triple-DH (SHA-512) + **Argon2id** as the key-stretching
function. Implemented as one tested primitive in `enclave-transport::opaque`.

### Data flow and trust boundaries

- **External entity:** the user. The password never leaves their device.
- **Process:** the relay's OPAQUE handler (`AccountStore` + `OpaqueServer`).
- **Data stores:** server account file (`enclave-accounts.json`: OPAQUE envelope +
  identity pubkey per user); server OPAQUE setup (`enclave-opaque.setup`: the
  server's long-term OPRF seed + keypair); client identity file
  (`enclave-<user>.id`: the Ed25519 signing key, encrypted at rest).
- **Flows crossing the client->server boundary:** the OPAQUE registration
  (request/response/upload) and login (credential request/response/finalization).
  None reveal the password to the server.

### What the server sees (and does not)

- **Never:** the password, nor any reversible/replayable function of it.
  Registration blinds the password through an OPRF; the server contributes its
  seed without learning the input. This is the core zero-knowledge property.
- **Sees (metadata):** the username, the identity pubkey, connection timing --
  the accepted routing-metadata tradeoff.

### STRIDE

| Threat | Concrete risk | Status / mitigation |
|---|---|---|
| **S** Spoofing | Impersonate a user | OPAQUE mutual auth: only the password holder completes login (the key-confirmation MAC only validates on the true password). Identity pubkey pinned per account. **GAP: MFA not offered.** |
| **T** Tampering | Alter account / identity / setup file | Identity file is AEAD-sealed (below). Server files are server-trusted; tampering an envelope or the setup only breaks login (fails closed), never leaks the password. |
| **R** Repudiation | Deny an action | Not a goal (private-comms); accepted. |
| **I** Info disclosure (password) | Server learns the password | **CLOSED: OPAQUE -- the password never crosses the trust boundary, at registration or login.** |
| **I** Info disclosure (server DB leak) | Offline crack after envelope theft | Forces a per-account, Argon2id-hard offline attack. OPAQUE is precomputation-resistant (unlike SRP): no shared salt to precompute against. |
| **I** Info disclosure (identity at rest) | Private key read off disk | **CLOSED: `enclave-<user>.id` is Argon2id + ChaCha20-Poly1305 sealed under the password.** |
| **D** Denial of service | Login flooding / online guessing | Per-connection lockout after 5 failures + per-connection rate limit; each guess costs a full OPAQUE round trip + Argon2id. |
| **E** Elevation | Act before/without auth | Deny-by-default auth gate: only OPAQUE handshake messages route before a session exists (ASVS V4). |

### Accepted / residual risks

- **Password policy is client-enforced.** A zero-knowledge server cannot measure a
  password it never receives; the client enforces the 12-char minimum before
  registration. A patched client could bypass it, weakening only that user's own
  account. Accepted (inherent to ZK auth).
- **Registration reveals username existence** ("that name is taken"). Unavoidable
  without email/confirmation; accepted. **Login does not:** unknown users take the
  same path via OPAQUE dummy mode, so a login attempt cannot enumerate usernames.
- **The OPAQUE `ServerSetup` is critical persistent state.** Lose it and every
  envelope becomes unusable (no one can log in); leak it and the per-account
  offline attack above becomes possible (still Argon2id-hard). Treated like a
  server private key: generated once, persisted, gitignored.

### ASVS L2 status

- **V2 Authentication** [MET]: password never sent (OPAQUE); Argon2id KSF; 12-char
  minimum (client-enforced); per-connection lockout. Remaining, tracked, not
  L2-blocking: no breach-corpus check, no MFA.
- **V6 Stored Cryptography** [MET]: credential stored as an irreversible OPAQUE
  envelope (not a reversible or replayable secret); identity key AEAD-sealed at
  rest; Argon2id KSF; approved AEADs only.
- **V8 Data Protection** [MET]: the identity key at rest is encrypted under a
  password-derived key.
- **V9 Communications** [PARTIAL]: TLS is available (`serve_signaling_tls`); the
  default local run is `ws://`. OPAQUE does not rely on TLS for password secrecy,
  but TLS still protects metadata and gives channel binding -- use `wss` in
  production.

### Validation

- OPAQUE round trip authenticates; a wrong password and an unknown user (dummy
  mode) both fail; the server setup survives a serialize/restore. See
  `crates/transport/src/opaque.rs` tests.
- End-to-end over a live relay: a wrong password is rejected by the controller.
  See `crates/client/tests/client_flow.rs::wrong_password_is_rejected`.
- Identity key is unreadable on disk without the password. See
  `crates/crypto/tests/identity_persistence.rs`.

## Deferred mitigations (scheduled, not skipped)

The ASVS L2 chapters above are addressed (TLS and rate limiting are
implemented), and the only tracked upstream item is the waived,
verified-non-exploitable advisory above. One security-relevant gap remains in
the client:

- **Presence rules are enforced in the UI, not the core.** Idle-to-away, status
  durations, and the invariant that a set status never upgrades (a disconnect
  always shows offline) are implemented in the front end. They are privacy
  behaviour, not access control, so a bug leaks activity metadata to friends
  rather than content to strangers. They still belong in the controller, where
  the front end cannot get them wrong, with idle measured at the OS level.

Verification persistence, previously listed here, is now done: a confirmed
safety number is stored with the encrypted session (`enclave-crypto` keys it to
the number itself, so a rekey resets it) and survives a restart.

Neither the above nor anything below weakens the sealed-frame or MLS
invariants: the server still never possesses a key or a plaintext.

## Metadata the server sees, and what hides it

The SFU topology means the relay sees routing metadata: which accounts share a
conversation, when a message is sent, and its size. Two of those are now
addressed at the wire:

- **Message size.** Every encrypted text message is padded to a multiple of 256
  bytes before it is sealed (MLS `padding_size`, applied identically at group
  create and join, proven by `crates/crypto/tests/e2e_text.rs`). The relay
  learns only which 256-byte bucket a message fell into, not its length. This
  does *not* pad media: audio and video frame sizes are set by their codecs, and
  hiding those means constant-bitrate padding, a much more expensive tradeoff
  left for later.

- **Recipient set.** The relay routes a group's traffic to exactly that group's
  members (`Relay` fan-out sets), so it learns the social graph of who talks to
  whom. The obvious hardening -- broadcast every message to *every* account and
  let clients discard what they cannot decrypt -- is **not viable** and is
  deliberately not done:
  - It is O(N) per message in server bandwidth and O(N) client work for N
    accounts, so it does not scale past a tiny server, and a flood trivially
    DoSes everyone.
  - It hides the recipient set only if the anonymity set is *everyone* and cover
    traffic is constant; with real servers where users come and go, timing and
    online-set correlation re-identify pairs quickly.
  - It trades a metadata leak for a much larger denial-of-service and
    battery/bandwidth cost, i.e. it makes the accepted SFU tradeoff worse, not
    better.

  The honest way to shrink recipient-set metadata is a different transport
  (a mixnet, or sealed-sender with per-message tokens the server cannot link to
  an account), which is a separate design, not a routing tweak. Recorded here as
  a known, accepted limitation of the SFU model.

## File sharing and large messages (STRIDE + ASVS L2)

A message too large for one sealed frame, and any file, is split into chunks
(`crates/client/src/transfer.rs`), each sealed with the group's MLS key exactly
like an ordinary text message and relayed as an opaque blob. The receiver
reassembles the chunks and, for a file, writes it to a downloads directory. This
adds two trust boundaries worth modeling explicitly: the **relay** (semi-trusted)
now forwards more, larger blobs, and the **receiving client** now writes
attacker-influenced bytes and an attacker-controlled *filename* to its own disk.

Target level **L2**. Chapters touched: V1 (design), V4 (access control), V5
(validation), V8 (data protection), V11 (business logic / anti-automation), V12
(files).

### Trust boundaries

```
sender client ──seal(chunk)──▶ RELAY (semi-trusted) ──fan-out──▶ receiver client
   (reads a file                 sees: chunk count,               (reassembles,
    from disk)                    sizes, timing; never             writes to disk)
                                  the plaintext or name)
```

The filename and content are inside the sealed plaintext, so the relay never
learns either. The dangerous flow is the last arrow: bytes and a name chosen by
another group member, landing on the receiver's filesystem.

### STRIDE at the receiving client (the new attack surface)

- **Tampering / Elevation of privilege -- path traversal via the filename.** A
  malicious (or compromised) group member names a file `../../.ssh/authorized_keys`
  or `/etc/cron.d/x` to write outside the downloads directory and gain code
  execution or persistence. *Mitigation (V5, V12):* the filename is never used as
  a path. `safe_file_name` reduces it to the final component only, strips path
  separators, control characters, and NUL, and rejects `.`/`..`/empty with a
  `file` fallback. `write_received_file` then joins the sanitized name to the
  canonicalized downloads directory and re-checks that the target's parent is
  still that directory before writing (defense in depth). Proven by
  `file_security_tests::{path_traversal_names_are_neutralized,
  a_written_file_never_escapes_the_downloads_dir}`.
- **Tampering -- overwriting an existing file.** A peer sends `doc.txt` twice, or
  a name matching a file already there, to clobber it. *Mitigation (V12):* writes
  use `create_new` (atomic O_EXCL); a name collision appends ` (1)`, ` (2)`, ...
  so nothing is ever overwritten, and two arrivals cannot race onto one name.
  Proven by `an_existing_file_is_never_overwritten`.
- **Denial of service -- memory exhaustion.** A peer opens a transfer declaring
  a huge `total`, or streams unbounded chunks, to exhaust RAM. *Mitigation (V11):*
  the reassembler refuses a transfer whose declared or actual size exceeds
  `MAX_TRANSFER_BYTES` (256 MiB), caps concurrent in-flight transfers
  (`MAX_INFLIGHT`, evicting the oldest), and rejects a chunk larger than
  `CHUNK_BYTES`. Proven by the `transfer::tests` bound cases.
- **Denial of service -- disk exhaustion.** A peer sends many large files to fill
  the disk. *Accepted / partial:* the per-transfer cap bounds any single file;
  a cumulative download quota is future work, recorded below. In practice the
  sender is an accepted friend in a group the user joined, which raises the bar.
- **Tampering -- MIME spoofing / dangerous content.** A peer sends an executable
  named `photo.png`, or a malformed file to exploit a viewer. *Mitigation (V5):*
  the MIME type is a display hint only; a received file is **never** opened or
  executed automatically. `OpenFile` runs only on an explicit user click, and
  hands the path to the OS default handler (`open::that_detached`) rather than
  interpreting the content itself. The user, not Enclave, decides to open it.
- **Information disclosure -- the content is E2E encrypted.** Each chunk is
  MLS-sealed and Ed25519-signed like any message (V8), so the relay and any
  non-member see only ciphertext. A tampered chunk fails AEAD and is dropped
  (the panic-in-debug openmls behavior is contained in `decrypt_text`).

### STRIDE at the relay (semi-trusted, unchanged trust level)

- **Denial of service -- chunk floods / amplification.** Splitting a file into
  many chunks is many `Text` sends. *Mitigation (V11):* the existing
  per-connection signaling token bucket (`SIGNALING_BURST`/`RATE`) already caps
  message rate, and each sealed chunk still must fit the 1 MiB frame limit; a
  flood is throttled exactly like a text flood. No relay change was needed.
- **Information disclosure -- metadata.** The relay sees the number and sizes of
  chunks and their timing, which reveals the approximate file size and that a
  transfer happened (not its name or content). *Accepted:* this is the same
  metadata tradeoff as the SFU topology already documents above; chunk sizes are
  uniform (`CHUNK_BYTES`) except the tail, so only a coarse size leaks. Constant
  size would need constant-rate cover traffic, out of scope.
- **Access control (V4).** A chunk is a `Text` to a group; the relay's existing
  deny-by-default routing already forwards it only to members who have
  (re)affirmed membership. A non-member can neither inject nor receive chunks.
  No new authorization path was added.

### Base64 on the wire (introduced with this feature)

Sealed blobs now serialize as base64 in the JSON signaling channel rather than a
numeric array (`enclave_protocol::Sealed`), so a 512 KiB chunk stays under the
1 MiB frame limit. This is an encoding change, not a security one: the bytes are
already ciphertext, base64 is not a confidentiality measure, and the binary
media path still gets raw bytes. Noted so the change is not mistaken for a
control.

### Residual / accepted risks

- **No cumulative download quota.** A single file is bounded (256 MiB) and the
  sender must be a group member, but a determined member could send many files to
  fill disk. A per-conversation or per-day byte quota is future work.
- **No malware scanning.** Enclave does not (and by its E2E design cannot at the
  server) scan file content. Received files are inert on disk until the user
  chooses to open them with an external application, which is where OS-level
  protections apply. This is the same model as any E2E messenger.
