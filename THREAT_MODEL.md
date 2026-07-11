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
- Phase 7 [PARTIAL]: ASVS L2 review done (see below); relay access control and
  deserialization bounds fixed and tested; parsers fuzzed for panic-safety; CI
  gate (fmt/clippy/test/audit/secret-scan) added in `ci/ci.yml` (activate under
  `.github/workflows/`). Remaining: TLS on the
  signaling hop, rate limiting, and the waived upstream advisory.

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
- **V9 Communications** [REMAINING]: TLS on the signaling hop (see below).
- **V11 Business Logic** [REMAINING]: no rate limiting yet; a client can flood
  the relay. Planned: per-connection token-bucket limits.

### Known advisory (waived, tracked)

- **RUSTSEC-2026-0124** -- `libcrux-chacha20poly1305` < 0.0.8: a potential panic
  on an overlong ciphertext buffer (HPKE decryption path, reachable via a
  malicious MLS Welcome, i.e. DoS). Severity 8.2. The fix is blocked upstream:
  `libcrux-aead 0.0.7` (pulled through `openmls_rust_crypto -> hpke-rs`) pins the
  vulnerable patch exactly. Waived in CI with written justification; re-check on
  each build for an openmls/hpke-rs release that bumps libcrux. Impact is a crash
  (panic = abort), not a confidentiality break; partial mitigations in place are
  the signaling message-size cap and the join-path fuzz test.

## Deferred mitigations (scheduled, not skipped)

- **TLS on the signaling hop** (defense-in-depth for metadata in transit) is
  deferred. The E2E content guarantee does not depend on it: content is already
  sealed before it reaches the socket. Tracked in `crates/transport/Cargo.toml`
  and the roadmap.
- **Rate limiting** on the relay (ASVS V11): planned per-connection token bucket.
