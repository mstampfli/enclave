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
  CI gate (fmt/clippy/test/audit/secret-scan) in `ci/ci.yml` (activate under
  `.github/workflows/`). One upstream advisory waived as verified non-exploitable.

## Accepted risks (explicit)

- **Metadata visible to the server** (who/when/sizes). Chosen for v1.
- **Availability depends on the self-hosted server.** It is a single point, but
  it is yours; no third-party dependency.
- **Repudiation** is not provided (no audit log), by design.

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
  media, AES-128-GCM via MLS); media-key derivation intermediates are zeroized;
  private identity/MLS keys live only in the in-memory provider for the session
  and are never written to disk.
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

- **RUSTSEC-2026-0124** -- `libcrux-chacha20poly1305` < 0.0.8: a potential panic
  on an overlong ciphertext buffer (a DoS in ChaCha20-Poly1305 `open`). Severity
  8.2. **Not exploitable in Enclave**, verified three ways:
  1. **Not compiled on the client target.** The client is the only binary that
     uses crypto, and it ships for Windows/WebView2, where
     `libcrux-chacha20poly1305` is not in the normal dependency graph
     (`cargo tree -i libcrux-chacha20poly1305` prints nothing).
  2. **Not reachable by our ciphersuite.** `MLS_128_DHKEMX25519_AES128GCM_...`
     uses AES-128-GCM for HPKE, so libcrux's ChaCha20-Poly1305 `open` is never
     called, on any target.
  3. **Absent from the server.** `enclave-server` does not depend on
     `enclave-crypto`, so the (Linux) relay never pulls libcrux.

  The correct remediation is an upstream bump, not forking a formally-verified
  crypto crate (which would void its verification provenance). No upstream fix is
  available yet: `openmls_rust_crypto` 0.5.1 and `hpke-rs-libcrux` 0.6.1 are the
  latest and exact-pin the vulnerable `libcrux-aead 0.0.7`. Waived in CI with
  this justification; re-checked on every build for an upstream release.

## Deferred mitigations (scheduled, not skipped)

No outstanding security mitigations: the ASVS L2 chapters above are addressed
(TLS and rate limiting are now implemented). The only tracked security item is
the waived, verified-non-exploitable upstream advisory above. Remaining work is
product features (presence, a persistent friends roster, video) plus on-hardware
validation of the audio devices and the window.
