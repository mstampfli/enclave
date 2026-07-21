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
| **I** Info disclosure (metadata) | Server sees who/when/sizes | **Accept (forced)** | Not a deferred choice: async delivery to an offline peer needs a server to hold and route the mail, and that server is a single box you host, so it sees routing metadata by construction. Content stays E2E. See "Metadata the server sees". |
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

- **Metadata visible to the server** (who/when/sizes). Not a deferred choice but
  a consequence of the design: async delivery to an offline peer needs a server
  to hold and route the mail, and Enclave's is a single box you host, so it sees
  the routing metadata by construction. Content stays end-to-end encrypted
  regardless. See "Metadata the server sees" for the full argument.
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

- **RUSTSEC-2026-0194 / RUSTSEC-2026-0195** -- `quick-xml` < 0.41 (parsing DoS on
  malicious XML: quadratic duplicate-attribute check and a related parser flaw).
  **Not exploitable in Enclave:** quick-xml appears only as a dependency of the
  `wayland-scanner` proc-macro (via ashpd/rfd), which runs at BUILD time and
  parses only the trusted Wayland protocol XML vendored inside those crates.
  It is not compiled into any shipped binary, and no attacker-supplied XML can
  ever reach it. No upstream fix exists: `wayland-scanner` 0.31.10 is the latest
  release and pins quick-xml 0.39. Waived in CI with this justification; drop
  the ignores when wayland-scanner releases against quick-xml >= 0.41.

- **RUSTSEC-2026-0207 / 0208 / 0209 / 0211 / 0212** -- the `libcrux-{sha3,aesgcm,secrets}`
  crates pulled transitively by openmls's crypto provider (`openmls_rust_crypto`
  -> `hpke-rs` -> `libcrux-*`), the same exact-pinned chain as 0124 with no
  upgrade path yet. The two that touch the AEAD directly (0209, AES-GCM not
  enforcing AAD length; 0211, non-constant-time tag check on decrypt) are **not
  remotely reachable in Enclave's model:** the relay holds no key and never
  decrypts, so there is no attacker-observable timing oracle on tag verification,
  and Enclave's MLS uses small fixed AAD. 0212 (constant-time swap/select) is
  Aarch64-only and 0208 is an AVX2 SHAKE-256 DoS panic of the same class as 0124.
  Waived in CI; drop the ignores when openmls ships a provider on patched
  libcrux. (Residual risk acknowledged: these are in the MLS AEAD path, so track
  the upstream fix and re-evaluate rather than treat the waiver as permanent.)

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

- **Ballot size.** A vote on a buffered or anonymous poll does not travel as an
  MLS message, so it does not inherit the padding above: it is sealed with a
  stream cipher (`crypto::seal_ballot`) and handed straight to the relay, where
  ciphertext length is plaintext length plus a constant. A ballot is therefore
  encoded at a **fixed width** -- the poll id plus a 256-bit selection bitmask
  (`transfer::VOTE_BODY_BYTES`), never a variable list of chosen indices -- so
  every ballot is the same size whatever it says. Without this the relay could
  read the *number* of options a voter picked straight off the wire while
  holding no key at all; on a pick-everything ballot, or on a single-choice poll
  where the only distinction is "voted" vs "retracted", that count identifies
  the vote outright. The mask is also canonical, so index ordering cannot carry
  a signal either. Proven by `a_sealed_ballot_is_the_same_size_whatever_it_says`
  and `the_anonymous_ballot_the_relay_stores_is_size_invariant`.

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

  Hiding who-talks-to-whom is not a routing tweak bolted on later; it is a
  different class of system, and it is **incompatible with two of Enclave's
  requirements held at once**:

  - **Async delivery.** You can text someone who is offline, so a server must
    hold the ciphertext until they return. Holding and addressing mail *is*
    seeing routing metadata: that a message exists, its size, its timing, and who
    collects it.
  - **A single self-hosted server.** Every metadata-hiding technique needs either
    a crowd to hide in (a mixnet or constant cover traffic drowns your message
    among many others) or several independent, non-colluding relays (Tor-style
    onion routing). A box you run for yourself and a few friends is neither: with
    a handful of users the anonymity set *is* those few people, and there is no
    second operator to split trust across. Manufacturing a crowd means borrowing
    other people's servers, which is no longer self-hosted.

  The systems that genuinely hide the social graph (Tor hidden-service messengers
  like Ricochet) get there by being **synchronous** -- both parties online on a
  live circuit -- which trades away the async delivery above. The one
  single-server exception, computational PIR (a recipient fetches mail without
  the server learning which mailbox), costs the server work proportional to the
  whole mailbox per fetch, hides only *which* mailbox is read rather than who
  deposited into it or that the friendship exists, and is meaningless with a
  handful of users.

  So the server seeing routing metadata is **forced by the requirements, not a
  tradeoff we settled for**: content is end-to-end encrypted and stays that way,
  but the fact that two accounts correspond cannot be hidden from the single box
  you deliberately chose to hold and route their mail. This includes the friend
  graph and the account/friendship dates the profile shows -- social metadata the
  same box already holds to route requests, never message content. Metadata
  resistance is a goal for a different product (untrusted third-party servers, a
  large user base, synchronous or high-latency delivery), not a missing feature
  of this one.

## Polls and ballots (STRIDE + ASVS L2)

A poll is an ordinary sealed message; how its votes travel depends on the reveal
mode its creator picked:

- **Immediate modes** (tally always visible, or visible once you vote) send each
  vote as a normal MLS-sealed control, padded like any other message.
- **Buffered modes** (tally only after close, owner-only, or anonymous) cannot
  use the message ratchet: a ballot must still open after an epoch change, and
  the whole point is that nobody -- the creator included -- sees a tally early.
  Ballots are instead sealed under a per-poll **content key**, minted by the
  creator and distributed only inside the MLS-sealed poll body, then held by the
  relay and released at the deadline or on an authenticated close by the owner.

**What the relay holds.** Sealed ballots it cannot open (it never sees the
content key), each a fixed-width body under a random nonce. It enforces release
timing and membership, nothing else.

**What the relay learns.** That a given connection submitted a ballot, and when.
It does **not** learn what the ballot says: the choice is AEAD-sealed under a key
it does not hold, and the ciphertext is a constant size, so no part of the
selection is recoverable from the wire (see "Metadata the server sees").

**Anonymity is orthogonal to audience.** Who receives the ballots (the group, or
the creator alone) and whether they are attributed are separate flags on
`BallotOpen`, not points on one scale, so "only the creator sees the tally, and
even they cannot tell who voted for what" is expressible. It is offered only for
the two modes that release ballots as a single batch when the poll closes. The
live modes hand each ballot on as it arrives, so its arrival time would identify
the voter in a small group however the ballot is signed: batching does as much
work here as the ring signature, and a "live anonymous" poll would not keep the
promise on its label.

**Anonymous polls.** Ballots carry a linkable ring signature (LSAG,
`crypto::ring`) over the ring of members' **Ed25519 identity keys**, so a verifier learns only
that *some* ring member cast it. The signature's key image is a stable pseudonym
per (voter, poll), which lets a re-vote replace the earlier one without ever
naming the voter, and stops one member stuffing the ballot box. On release the
relay strips the submitting device id.

**The ring needs no key distribution.** A poll's ring is the members' existing
MLS identity keys, read out of the creator's own local group state
(`Group::member_keys`). Nothing is published, nothing is fetched from the server,
and no member has to be reachable at any point for a ring to exist -- it is
available the moment a conversation does. This is also why the ring is not worth
attacking: those keys arrive with group membership itself and are already the keys
the safety number verifies, so substituting one is exactly the attack the existing
verification catches. Putting voting keys on the server instead would have handed
the relay the ability to insert itself into a ring and stuff ballots, buying an
availability win for a trust loss.

Ed25519 has cofactor 8, so `crypto::ring` constrains every point to the
prime-order subgroup: ring keys and key images must be torsion-free, and the
hash-to-point result is cofactor-cleared. Without that, a crafted small-order key
would make a key image malleable and let one member vote repeatedly without
linking. Proven by `ring::tests::small_order_points_are_refused_everywhere`.

**Denial of service.** A buffered poll costs the relay memory until it is
released, so the ballot buffer is bounded on every axis: at most
`MAX_OPEN_POLLS_PER_DEVICE` open polls per owner, `MAX_OPEN_POLLS_TOTAL` across
the whole server, a `MAX_BALLOT_BYTES` ceiling on any single sealed ballot (a
real one is ~76 bytes), and a `POLL_TTL` after which a poll nobody ever closed is
reclaimed, so an abandoned one cannot hold memory -- or its owner's quota --
forever. Ballots are keyed by submitting device, so re-voting replaces rather
than accumulates, and only a group member may open a poll or submit to one.
Every refusal returns a `ServerMsg::Error` the client displays, so a user is told
why rather than seeing a vote vanish. Re-using an already-open poll id is refused
outright: otherwise any member could reset another member's poll and discard the
ballots already cast in it. Proven by `relay_core::one_device_cannot_open_unbounded_polls`,
`an_oversized_ballot_is_refused`, `an_abandoned_poll_is_reclaimed_and_frees_its_quota`
and `reopening_a_poll_id_is_refused_and_cannot_discard_cast_ballots`.

### Residual / accepted risks

- **Anonymity is from peers, not from an operator who is also a member.** The
  relay by itself learns nothing about a vote: it holds no ballot key, the
  ciphertext is a constant size, and it strips the submitter id on release. But
  the ballot key travels in the poll body to *every* member (they all need it to
  tally), while the relay sees which connection submitted which ciphertext.
  Anyone holding both -- i.e. any group member who also runs the server, which on
  a self-hosted box is one person -- can decrypt each ballot and attribute it to
  its submitter, deanonymizing the whole poll. The ring signature does not
  prevent this, because the link is made at the transport layer (which connection
  delivered which ciphertext), not inside the signature.

  This is **not cleanly fixable in this architecture**, and is recorded rather
  than papered over. The textbook alternative is an additively homomorphic tally
  (exponential ElGamal / Paillier) where individual ballots are *never* decrypted
  and only the aggregate is opened, under threshold keys split across members,
  plus a verifiable re-encryption mixnet so an input ciphertext cannot be linked
  to an output one, plus ZK validity proofs so a voter cannot encrypt a thousand
  votes. It is deliberately **not** adopted here, and it is worth being precise
  about why, because it is a fix for a different availability model rather than a
  strictly better one:

  - Threshold decryption needs a quorum **online when the poll closes**. The whole
    point of the buffered design is that nobody need be. Weakening it so a tally
    can be opened with everyone offline means one party holds the key (or the
    server holds a share), which reconstructs exactly the situation above with far
    more machinery.
  - It does not make deanonymization impossible, only more expensive: nothing
    forces a quorum to run the decryption protocol against the *product* rather
    than against a single ballot. It buys "no fewer than `t` colluding members"
    in place of "one member who also runs the server".
  - Re-randomization needs an algebraic cipher rather than the AEAD used
    everywhere else here.
  - It does nothing at all for the tally-inference leaks below.

  So the honest scope of "anonymous poll" is: **anonymous from the other people in
  the chat**, which is what it is for. It is not a secret ballot against the person
  who owns the server. Where that matters, do not use this for the vote.

- **Turnout bounds what unanimity reveals.** The tally leak below is total only at
  full turnout: if 3 of 5 members vote and the result is 3-0, members learn three
  people chose that option but not *which* three, so no individual is pinned.
- **Unanimity leaks regardless of the crypto.** If every voter picks the same
  option, the published tally tells everyone how each of them voted. No ballot
  scheme prevents this; it is a property of publishing a tally over a small
  group, and the same is true of any near-unanimous split.
- **Owner-live mode is disclosed, not hidden.** In the mode where the creator may
  see results before close, voters are shown that the creator can do so before
  they vote.

## File sharing and large messages (STRIDE + ASVS L2)

A file is never pushed to anyone. The sender **offers** it: a sealed manifest
(name, mime, size) that each recipient decrypts to decide, then explicitly
**accepts** or **declines**. Nothing is written to a recipient's disk until they
accept. Delivery then takes one of two modes:

- **Stored** (file up to 250 MB): the sender uploads the already-sealed chunks
  to an on-disk store on the server (`crates/transport/src/filestore.rs`), which
  buffers them so the file reaches a recipient who is offline. On accept the
  server streams the blob to that recipient; the offer is deleted when every
  recipient has resolved, or after a 24 h TTL.
- **Live** (larger, or when the store refuses): the sealed chunks stream in real
  time to whoever accepts within ~90 s and are **never** stored; this needs the
  recipient online.

The manifest is one MLS-sealed message. The bulk **chunks are NOT MLS messages**:
each is sealed under a per-file **content key** with ChaCha20-Poly1305
(`crypto/src/blob.rs` `seal_chunk`/`open_chunk`), the key being a fresh 256-bit
random value that travels only inside the sealed manifest (`FileManifest.content_key`).
The server still sees only ciphertext. This decoupling is deliberate and load-bearing
(see "Availability -- MLS ratchet integrity" below): putting thousands of file
chunks through the group's message ratchet let a dropped chunk (a cancelled
download) desync the ratchet and silently kill the whole conversation, and it made
re-download impossible (MLS ciphertext is bound to one-time generations). This
design adds trust boundaries worth modeling: the **server** now buffers (transient,
on-disk) sealed blobs and their sizes and enforces the store quota; the **receiving
client** writes attacker-influenced bytes and an attacker-controlled *filename* to
its disk, but only after the user consents.

Target level **L2**. Chapters touched: V1 (design), V4 (access control), V5
(validation), V8 (data protection), V11 (business logic / anti-automation), V12
(files).

### Trust boundaries

```
sender ──offer(sealed manifest)──▶ SERVER ──offer──▶ recipient (decrypts name/size,
  (reads file                       (sees size for      NO download yet)
   from disk)                        quota; never             │ accept / decline
                                     name or bytes)           ▼
        ◀── accept ──────────────────────────────────  consent gate
sender ──seal(chunk)──▶ SERVER ─(stored: buffer on disk, then stream on accept)─▶ recipient
                              └─(live: relay in real time to accepters)──────────▶ (streams to disk)
```

The filename and content are inside sealed plaintext, so the server never learns
either. It does see the file **size** (stored offers only -- needed for the
quota; live offers send size 0). The dangerous flow remains the last arrow, now
gated by explicit consent.

### STRIDE at the receiving client

- **Elevation of privilege -- unwanted / hostile files auto-landing on disk.**
  The primary risk this feature is designed around: a member dropping malware,
  or simply unwanted files, straight onto peers' disks. *Mitigation (V4, by
  design):* no auto-download. An incoming file is only ever an *offer*
  (`ServerMsg::FileOffered` -> `Event::FileOffered`); the bytes are requested
  only by an explicit `accept_file`. As defense in depth, a `File`-metadata part
  smuggled over the plain text channel is dropped, never written, so files cannot
  bypass the consent flow. Proven end-to-end by
  `client_flow::large_message_and_file_transfer_between_two_clients` (Bob must
  see the offer and accept before anything is written) and at the relay by
  `relay_core::a_stored_file_is_offered_not_pushed_and_delivered_only_on_accept`.
- **Tampering / Elevation of privilege -- path traversal via the filename.** A
  member names a file `../../.ssh/authorized_keys` to write outside the downloads
  directory. *Mitigation (V5, V12):* the filename is never used as a path.
  `safe_file_name` reduces it to the final component, strips separators, control
  chars, and NUL, and rejects `.`/`..`/empty with a `file` fallback.
  `reserve_download` joins the sanitized name to the *canonicalized* downloads
  directory and re-checks the target's parent is still that directory before
  creating it. Proven by `file_security_tests::{path_traversal_names_are_neutralized,
  a_written_file_never_escapes_the_downloads_dir}`.
- **Tampering -- overwriting an existing file.** *Mitigation (V12):* the download
  is reserved with `create_new` (atomic O_EXCL); a name collision appends ` (1)`,
  ` (2)`, ..., so nothing is overwritten and two arrivals cannot race onto one
  name. Proven by `an_existing_file_is_never_overwritten`.
- **Denial of service -- memory exhaustion on receive.** *Mitigation (V11):* an
  accepted file streams straight to disk one chunk at a time via `FileSink`; the
  whole file is never buffered in RAM (this is what makes arbitrary-size live
  transfers safe). The sink writes parts strictly in order, rejects a chunk
  larger than `CHUNK_BYTES` or one that arrives out of order, and caps total
  bytes at `MAX_RECEIVE_BYTES` (4 GiB), aborting and deleting the partial file on
  any violation. Proven by `transfer::tests::{a_streamed_file_is_written_to_disk_exactly,
  an_out_of_order_part_fails_the_transfer, a_file_over_the_receive_cap_is_refused}`.
- **Tampering -- MIME spoofing / dangerous content.** *Mitigation (V5):* the MIME
  type is a display hint only; a received file is **never** opened or executed
  automatically. `OpenFile` runs only on an explicit user click and hands the
  path to the OS default handler (`open::that_detached`). The consent prompt shows
  the name and size before any download, so the user decides with the file's real
  name in view.
- **Information disclosure -- content is E2E encrypted.** The manifest is
  MLS-sealed and Ed25519-signed; each chunk is sealed under the per-file content
  key carried inside that manifest (V8), so the server and non-members see only
  ciphertext. A tampered chunk fails AEAD and is dropped.
- **Tampering / Spoofing -- forged, reordered, or replayed chunks.** A chunk's
  AEAD binds `offer_id || index` as associated data, so a chunk cannot be moved to
  a different position or offer without failing authentication, and the sink writes
  strictly in order. The content key is shared by the group, but the **server
  enforces that only the offer's own sender may push its chunks** (see Access
  control below), so a different group member cannot inject chunks under someone
  else's offer. A malicious server can at most reorder/drop (a denial of service
  that aborts the download); it can never corrupt the file undetected. Proven by
  `blob::tests::{a_chunk_will_not_open_at_the_wrong_index,
  a_chunk_will_not_open_under_another_offer, a_tampered_chunk_is_rejected}`.
- **Availability -- MLS ratchet integrity (the decoupling rationale).** Bulk file
  data must not ride the group message ratchet: at 512 KiB/chunk a large transfer
  advances the sender's generation by thousands, and a chunk dropped un-decrypted
  (a cancelled/declined download hits the consent gate before decrypt) desyncs the
  ratchet so far that openmls rejects every later message ("generation too far in
  the future") -- silently killing the conversation. *Mitigation:* chunks use the
  content key, never the ratchet, so a file of any size is exactly one MLS message
  (the manifest) and dropping chunks is harmless. As recovery for a conversation
  already desynced by the old design, the sender-ratchet `maximum_forward_distance`
  is raised to a bounded 16384 (a receiver skips forward on the next message);
  bounded because a crafted never-decrypting message forces at most that many key
  derivations, and the message rate is capped. A per-offer content key is fresh, so
  the index-based nonce never repeats.

### STRIDE at the server file store (the DoS surface)

The store buffers sealed blobs on disk to reach offline recipients. Because a
peer can make the server hold bytes, it is the main new denial-of-service
surface, and every axis is bounded (`filestore.rs`, `relay.rs`).

- **Denial of service -- disk / store exhaustion.** A peer uploads huge or many
  files to fill the server's disk. *Mitigation (V11, V12):* admission is gated
  three ways before a byte is written -- per file (`PER_FILE_MAX`, 250 MB), whole
  store (`STORE_TOTAL_MAX`, 2 GB), and a free-disk floor (`DISK_FREE_FLOOR`, 4 GB:
  an upload that would drop free space below it is refused). The blob is on disk,
  not in RAM, so many concurrent offers cost disk (floor-bounded), not memory.
  Proven by `filestore::tests::{a_file_over_the_per_file_cap_is_refused,
  the_store_total_cap_is_enforced_across_offers, the_disk_floor_refuses_when_space_is_low}`
  and `relay_core::{an_over_cap_stored_file_is_rejected_before_upload,
  a_low_disk_server_refuses_to_store_a_file}`.
- **Denial of service -- unbounded retention.** Offers that are never answered
  accumulate. *Mitigation (V11):* every offer has a 24 h TTL swept periodically,
  and is deleted immediately once all recipients accept/decline. Metadata is in
  memory and not persisted, so a restart drops pending offers (safe: the sender
  re-offers) and state cannot accumulate across restarts.
- **Denial of service -- under-declaring the size.** A peer declares a small size
  to pass admission, then uploads far more. *Mitigation (V11):* the store enforces
  a per-offer sealed write ceiling (declared size + a bounded sealing slack) and
  drops the whole offer on overrun. Proven by
  `filestore::tests::under_declaring_the_size_is_caught_on_overrun`.
- **Denial of service -- offer spam.** A peer opens thousands of tiny offers to
  exhaust store metadata/inodes. *Mitigation (V11):* at most
  `MAX_OFFERS_PER_SENDER` (32) concurrent offers per sender; offer creation is on
  the rate-limited control path.
- **Denial of service -- head-of-line blocking on delivery.** A 250 MB blob read
  must not stall every other connection. *Mitigation:* on accept the blob is
  streamed off the global relay lock on a blocking thread, one chunk at a time;
  the lock is only re-taken to resolve the delivery. A TTL sweep never unlinks a
  blob with a delivery in flight.
- **Denial of service -- chunk-rate throttle would corrupt transfers.** File
  chunks cannot share the tight signaling rate limit, since dropping one corrupts
  the file. *Mitigation (V11):* a separate per-connection budget (`FILE_BURST`
  600 / `FILE_RATE` 300/s) gates all traffic and bounds decode cost; its burst
  exceeds the chunks in one maximum-size file, so a legitimate upload never
  drops, while control-plane messages still obey the tight signaling budget on
  top. Chunk *volume* is already bounded by the store quota (stored) or by
  consent (live), so a high message rate here is safe.
- **Access control (V4).** Only a routing member of the group may offer a file;
  only the offer's own sender may upload its chunks or cancel it; only a targeted
  recipient may accept/decline/abort; a stored blob is readable only by a pending
  recipient. A recipient's `FileAbort` only affects its own delivery (the cancel
  token and live-accepted set are keyed by that recipient's device), so it cannot
  stop or affect another recipient's download. A live sender's disconnect tears
  down its offers and tells the recipients. Proven by
  `relay_core::{a_non_member_cannot_offer_a_file_to_a_group,
  a_chunk_from_someone_who_is_not_the_sender_is_ignored}`.
- **Availability -- cancel must stop promptly and stay re-downloadable.** A
  recipient cancelling a multi-gigabyte download must not keep draining the whole
  file, and must be able to retry. *Mitigation:* `FileAbort` sets a per-delivery
  cancel flag the off-lock streamer checks between chunks, so it stops within one
  chunk and calls `abort_stored_delivery`, which leaves the recipient **pending**
  (not resolved) so a later `FileAccept` re-streams from the start. Declining
  (`FileDecline`) is the final path that gives the offer up. Proven by
  `filestore::tests::an_aborted_delivery_stays_downloadable`.
- **Information disclosure -- the server sees the file size.** Enforcing a 250 MB
  quota requires knowing the size, so a stored offer's plaintext size is visible
  to the server (unlike padded text messages). *Accepted, deliberate:* it is the
  minimum needed for DoS control; the name and content stay sealed, and a live
  offer sends size 0 (the server stores nothing, so needs no size).

### Denial of service -- per-connection outbound memory (bounded)

Server->client delivery is bounded per connection so a slow or stalled reader
cannot make the server buffer unbounded memory for it. Each online connection has
an `Outbound` queue (`server.rs`) with two independent byte budgets:

- a **file budget** (12 MiB) for both the stored-blob stream *and* relayed live
  chunks, which *backpressures* -- the producer awaits room, so a slow reader
  paces the sender instead of growing memory. A relayed live chunk waits on this
  budget in the sender's dispatch, bounded by `LIVE_BACKPRESSURE_TIMEOUT` (10 s)
  so a reader making no progress at all cannot wedge the sender's connection: it
  is dropped from the live stream and its in-order sink aborts cleanly (never
  corrupt). A slow-but-progressing reader never hits the timeout.
- a **control budget** (4 MiB) for everything else (control, text), which never
  blocks a sender's connection and drops a message only once even this budget is
  full (the reader is then not draining at all -- effectively dead).

The budgets are separate, so a maxed-out file stream to a mid-download reader
cannot starve that reader's control/text. Total buffered per connection is capped
at their sum (16 MiB). Proven by `server::outbound_tests::{try_send_bounds_the_control_budget_and_drops_the_rest,
a_saturated_file_stream_never_starves_control,
the_file_budget_backpressures_instead_of_dropping}`.

**Nothing reliable is dropped short of true exhaustion.** A reliable message
(text, MLS, Welcome, file offer) that will not fit a stuck online reader's
control budget is not dropped: it is spilled into that recipient's persistent
offline queue and delivered on their next reconnect
(`relay::{spill_offline, queue_for_offline}`, proven by
`relay_core::a_spilled_message_reaches_the_recipient_on_reconnect`). Even at a
genuine global resource cap -- the offline queue's 128 MiB total -- a reliable
message is not dropped: the server withholds its ack, so the sender's
reliable-delivery layer (below) keeps retransmitting until space frees and the
message lands. The offline queue itself is the separately-bounded `msgqueue`
(4 MiB/device, 2000 msgs/device, 128 MiB total): below the global cap it evicts a
device's *own* oldest to make room. Real-time / latest-wins messages (media,
presence, call/friend state) are still dropped when a stuck reader's budget is
full, since a stale one is superseded by the next update.

**The sender is paced, not buffered.** The client's outbound has a bounded
file-chunk queue: a large (or arbitrary-size live) upload is a pump that seals
and sends one chunk at a time only while the queue has room, so TCP backpressure
from a slow server or slow relayed recipient stalls the pump instead of buffering
the whole file in the sender's memory. Control/text keep a separate latency-first
channel.

### Message delivery reliability (integrity/availability, not censorship)

Text and MLS handshakes are delivered with an application-level ack + retransmit
+ dedup layer (`ClientMsg::Reliable`, `ServerMsg::Ack`): the server acks a
message only after durably accepting it (delivered to online members, persisted
for offline ones); the sender retransmits until acked, replaying on reconnect and
from a persisted buffer on restart; the receiver dedups a resent message by its
transfer id. This defends against **faults** -- a dropped connection, a server
restart, the app closing mid-send, a transient queue-full -- so no chat message
is silently lost to them. A *transient* failure is invisible (the retransmit
delivers it), but a *persistent* one is not silent: if a message keeps retrying
past a threshold (or the un-acked backlog grows), the client warns the user that
delivery is stuck rather than retransmitting forever with no feedback.

It is explicitly **not** a defense against a malicious relay. Delivery ultimately
depends on the semi-trusted server, which by its nature can refuse to route
(censor) a message; the ack layer does not, and cannot, prevent that, and a
server that lies with an `Ack` it did not honor is no worse than one that simply
drops -- both are the existing "the relay can censor" property of the trust
model. E2E encryption protects the *content* of what is delivered; it does not
promise *availability* against an adversarial server. What the reliability layer
buys is that an honest server plus an unreliable network never loses a message.

### Residual / accepted risks

- **Group + live: a late accepter misses the stream.** A live transfer is
  one-shot: the sender streams once to whoever has accepted. A group member who
  accepts after the stream finished does not receive it (they can be re-offered).
  Stored transfers do not have this limitation.
- **No malware scanning.** Enclave does not (and by its E2E design cannot at the
  server) scan file content. Received files are inert on disk until the user
  chooses to open them externally, where OS protections apply. The consent gate
  and name-in-prompt are the user's first line of defense.

## Group history sharing (STRIDE + ASVS L2)

By default a new group member reads nothing sent before they joined -- MLS forward
secrecy means they cannot decrypt earlier messages, so old messages (pinned or not)
never appear for them. An opt-in per-group setting lets a group choose otherwise:
while it is on, each text message is *also* off-ratchet-sealed under a per-epoch
**history key** and stored by the relay, so a future member can backfill it.

- **The key is shared, so those stored copies have no forward secrecy** -- the same
  key opens every message in its epoch. This is the deliberate, stated tradeoff
  (surfaced in the UI when the user turns it on), identical in spirit to the
  workspace scrollback tradeoff.
- **Opt-in and reversible with clean epochs.** Off by default. Enabling starts a
  fresh epoch with a new key; only messages from that point on are stored. Disable
  stops storing; re-enable starts a *new* epoch, and a new member is handed only the
  **current** epoch's key, so the earlier enabled stretch and the disabled gap stay
  hidden ("only from here on out").
- **Confidentiality / integrity.** The relay stores only sealed blobs (it holds no
  key), and each stored line is identity-signed by its sender and verified against
  the group roster on backfill, so the relay cannot forge or read group history. The
  setting and its key travel MLS-sealed to members; a new member's key is delivered
  directed, only after they are in the MLS group. Proven by
  `group_history_sharing_backfills_a_new_member_from_when_it_was_enabled`.

## Workspaces (STRIDE + ASVS L2)

A workspace is a Discord/Slack-style container of text and voice channels with
members, roles, categories, and private channels. It adds **no new cryptosystem**:
a channel is a group. Public channels key off one workspace MLS group; a private
channel is its own MLS group over a subset; a voice channel is a persistent call.
The design and keying live in docs/WORKSPACES.md (its section 8 is the design-time
STRIDE pass); this section records the posture **as built** and where each control
is enforced.

Target level **L2**. Chapters touched: V1 (design), V4 (access control), V7
(logging / accountability, via the op-log), V8 (data protection), V11 (business
logic / anti-automation).

### Trust boundary and the authority question

Same boundary as everywhere else: **client <-> untrusted relay**. Channel content
is E2E; the workspace's *structure* (name, channel tree, roster, voice presence)
is server-visible metadata. The new question a workspace raises is **authority**:
who may add a member, grant an admin, delete a channel? The answer must not be
"whoever the server says", or a malicious relay could quietly promote itself into
any room.

**The op-log is the trust anchor.** Every structural change is an identity-signed
`SignedOp` (`enclave-protocol`), chained by sequence number + SHA-256 `prev_hash`
into an append-only log. A client replays the log and **authorizes each op
locally**: the genesis establishes the owner; only the owner grants admin; a
remove requires the actor to outrank a non-owner target. The relay stores and
orders the log but holds no signing key, so it cannot mint a grant, forge
membership, or splice the chain without detection. Enforced by
`crypto::workspace::WorkspaceState::apply` (rejecting `BadSeq` / `BadChain` /
`BadSignature` / `Unauthorized`) and `crypto::sign`, and re-validated at the
relay's own ingress (`transport::workspaces`, `SubmitError::Op`) so one malformed
op cannot brick a log's chain for everyone. Proven by the crypto workspace tests
`genesis_establishes_owner_and_roles`,
`only_the_owner_grants_admin_and_only_higher_roles_remove`,
`a_forged_or_reordered_entry_is_rejected`, and
`a_tampered_op_body_breaks_the_signature`.

### STRIDE (as built)

- **Spoofing -- relay injects a ghost into a channel to read it.** *Mitigate.*
  Read access is the MLS roster, not the server's convenience roster: a member
  with no signed Welcome holds no key. Posting is MLS-authenticated to the sender,
  as in any group.
- **Tampering -- relay forges roles/membership, or reorders/drops log entries.**
  *Mitigate.* The signed, hash-chained op-log above; a fork or reorder shows up as
  a `prev_hash` mismatch. Withholding entries is a liveness issue (see DoS), not
  an integrity one.
- **Repudiation -- "who kicked or promoted whom?"** *Mitigate.* Every admin op is
  signed and timestamped in the log: accountability (V7) without trusting the
  server.
- **Information disclosure -- relay reads channel content.** *Mitigate.* E2E; the
  relay sees only sealed blobs and `HK`-sealed backfill history it cannot open.
- **Information disclosure -- a private channel leaks to a non-member.**
  *Mitigate.* A private channel is its own MLS group, so even if the relay
  misroutes its ciphertext to a workspace member who was never added, that member
  holds no key. Proven by `a_private_channel_is_readable_only_by_its_members` (and
  at the state-machine level `a_private_channel_tracks_its_own_member_set`). The
  relay still sees the channel *exists* in order to route it: metadata tier below.
- **Information disclosure -- workspace structure, roster, voice presence.**
  *Accept -- forced, not chosen.* These are the same self-hosted-relay metadata as
  the rest of the app; see "Metadata the server sees, and what hides it". Hiding
  the roster by broadcasting to everyone is the same non-viable tradeoff rejected
  there.
- **Denial of service -- op / message spam, add bursts, unbounded history.**
  *Mitigate.* The client serializes structural ops through a per-workspace
  submission queue (re-signing on a sequence conflict) instead of racing the log;
  a burst of member adds (several redemptions of one invite link at once) queues
  and drains one per freed op-log slot rather than dropping all but the first; and
  channel history is bounded per channel on disk with oldest-first eviction
  (`transport::workspaces`, `MAX_HISTORY_PER_CHANNEL`) and served in bounded pages
  rather than one unbounded dump.
- **Spoofing / Elevation -- an invite code used to bypass role authority.**
  *Mitigate.* An invite is a bearer code an admin mints (the relay checks the
  minter's role and validates the code's expiry / use limit) that only lets its
  holder *request* admission; the admission itself is a signed AddMember op by an
  online admin, so a redeemer never joins without an admin's authority and never
  escapes the op-log's record of who added them. The code is a bearer secret
  (residual risk below).
- **Denial of service -- relay censors (drops ops or messages).** *Accept.* A
  liveness limit inherent to depending on a server you host; it can withhold but
  cannot forge or read.
- **Elevation of privilege -- a member performs an action they lack.** *Mitigate.*
  Authorization is permission-based (RBAC) and deny-by-default: each op requires a
  specific permission, and a member's permissions are only the union of their
  assigned roles. A member with no role can do nothing, and the server cannot
  elevate (it holds no signing key). The design is **fail closed** -- the owner's
  all-permissions come from a protected built-in role assigned at genesis, not a
  special case, so a bypassed authorization check grants nothing rather than
  everything. Proven by `a_bare_member_cannot_touch_roles_and_the_owner_is_unremovable`.
- **Elevation of privilege -- privilege escalation via role management.**
  *Mitigate.* Someone who can manage roles still cannot mint or assign a role
  carrying a permission they do not themselves hold, and the built-in Owner role
  cannot be edited, deleted, assigned, or unassigned, so no one can bootstrap
  themselves (or another member) past their own authority or seize the owner's.
  Proven by `role_ops_prevent_privilege_escalation_and_protect_the_owner_role`.
- **Elevation of privilege -- a removed member keeps reading.** *Mitigate.*
  Removal drives an MLS commit (public channels rekey in one commit; each private
  channel rekeys its own group) **and** rotates every channel's history-key epoch,
  so the removed member holds no post-removal key
  (`client::workspace_remove_member`).
- **Tampering / DoS -- sidebar reorganization (drag-to-nest).** *Mitigate.*
  Moving a channel to a category (`SetChannelCategory`) or nesting a category
  under another (`SetCategoryParent`) is an admin-only signed op like any other,
  and the op-log refuses a category move that would form a cycle or exceed
  `MAX_CATEGORY_DEPTH`, so a malicious or buggy client cannot build a
  non-terminating tree. Proven by the crypto category-move tests.
- **Elevation of privilege -- moving a member between voice channels.**
  *Mitigate.* Only an admin may drag another member to a voice channel; the relay
  checks the mover's role and that the target is a voice channel the member may
  enter, then merely *directs* the member's client, which switches via its own
  join/leave (`ClientMsg::VoiceMoveMember` -> `ServerMsg::VoiceMoved`). A
  non-admin's attempt is refused; proven by
  `an_admin_moves_a_member_between_voice_channels`.
- **Spoofing / DoS -- announcing voice mute/deafen state.** *Mitigate.* A client
  announces only its *own* mute/deafen via `ClientMsg::VoiceState`; the relay
  attributes it to the authenticated sender (never a handle in the message) and
  drops it unless that sender is currently present in the named channel, so no one
  can forge another member's indicator. Rebroadcast is suppressed when the flags
  are unchanged, so a client cannot amplify by resending. The state is broadcast
  to co-occupants (an accepted, cosmetic disclosure, same tier as presence).
  Proven by `voice_mute_and_deafen_state_reaches_co_occupants`.

### Residual / accepted risks

- **Scrollback weakens forward secrecy for backfilled history** -- a per-channel
  symmetric epoch key shared with a channel's members, the deliberate cost of
  Discord-style history (docs/WORKSPACES.md section 3). The server never holds it.
- **Workspace structure is visible to the relay you host** -- forced by
  self-hosted async delivery, not a gap (the metadata theorem above).
- **An invite code is a bearer secret** -- anyone who obtains a live code can
  request to join until it expires or its uses run out. Admission still needs an
  online admin and is recorded in the op-log, so the blast radius is a join
  request, not silent membership. Codes are admin-minted, expiry/use-bounded, and
  deleted once spent (`transport::workspaces`).
