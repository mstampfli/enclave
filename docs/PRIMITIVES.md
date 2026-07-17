# Enclave -- primitives (single source of truth)

We assemble vetted primitives and hand-roll none, for cryptography **and** for
the recurring safety concerns (bounds, dedup, backpressure, path safety). Each
one is the single tested home of its concern; the hand-rolled form of anything
below is a smell to convert. Crypto choices are in the first table; the
runtime-safety primitives are cataloged after it (each tagged `// PRIMITIVE` in
code, so `grep -rn PRIMITIVE crates/` finds them).

## Cryptographic primitives

Every crypto choice lives here; if it is not in this table, we do not use it.

| Concern | Primitive | Library | Why |
|---|---|---|---|
| Identity + media-frame signature | Ed25519 | `ed25519-dalek` (verify) / `openmls_basic_credential` (sign) | Fast, misuse-resistant, widely reviewed; one key is the MLS credential AND the media-frame signer |
| Group key agreement | MLS | `openmls` | Scalable rekey, forward secrecy, post-compromise security, authenticated membership |
| Media/text AEAD | ChaCha20-Poly1305 | `chacha20poly1305` | Fast in software, no timing-side-channel table lookups, nonce-misuse-visible |
| Key derivation | HKDF-SHA256 | `hkdf` + `sha2` | Standard exporter->media-key derivation |
| Password authentication | OPAQUE (RFC 9807) aPAKE | `opaque-ke` | Server never sees the password; precomputation-resistant; audited reference impl (Ristretto255 + Triple-DH) |
| Password key-stretching | Argon2id | `argon2` | Memory-hard; the OPAQUE KSF and the at-rest identity-key wrap |
| Safety number | SHA-256 over sorted member identity keys | `sha2` | Deterministic, comparable out-of-band |
| Secret zeroing | `zeroize` | `zeroize` | Wipe key material on drop |

## Rules

- **Nonces:** per-sender monotonic counter, never reused under one key. Owned by
  the frame sealer (`enclave-crypto::media::MediaSealer`) so reuse is
  unrepresentable, not merely avoided.
- **Media source authentication:** the per-sender AEAD key is derivable by every
  group member (they share the media root), so the AEAD tag alone does not prove
  *who* sent a frame. Each frame is therefore also Ed25519-signed by the sender
  (`MediaSigner`, the MLS credential key) over the header + ciphertext under a
  domain-separation prefix (`MEDIA_SIG_CONTEXT`), and verified against the claimed
  sender's roster public key before decryption. This is what stops one member
  impersonating another; each frame is signed independently, so packet loss never
  orphans authentication.
- **Anti-replay:** a 64-entry sliding window (`ReplayWindow`, RFC 6479 style) in
  `MediaOpener` accepts out-of-order real-time frames once and rejects
  duplicates / too-old frames. Verify the signature and AEAD first, then update
  the window, so a forged frame cannot poison it.
- **Keys:** private identity + MLS secrets never leave the client, are never
  logged, and are never serialized to the server. The long-term identity key,
  when persisted on the device, is encrypted under a password-derived key
  (Argon2id -> ChaCha20-Poly1305); session secrets are wrapped in `zeroize` types.
- **Frame layout:** encrypt the *encoded* frame (Opus/video), never raw samples
  -- there is no lossy stage after encryption to corrupt ciphertext.
- **No new primitive** without adding it here first, with a justification.

## Runtime-safety primitives

Not cryptography, but the same rule: one tested, safe-by-construction home per
recurring concern, reused everywhere, never re-derived inline. Each guarantees a
bug class cannot occur for any caller.

| Concern | Primitive | Where | Makes impossible / replaces |
|---|---|---|---|
| Nonce reuse (media AEAD) | `MediaSealer` monotonic counter | `crypto/src/media.rs` | A reused AEAD nonce under one key -- the counter owns the nonce, so reuse is unrepresentable, not merely avoided |
| Replay of real-time frames | `ReplayWindow` (RFC 6479, 64-entry) | `crypto/src/media.rs` | Accepting a duplicate/too-old media frame; hand-rolled seen-checks |
| Per-connection / per-source flood | `TokenBucket` | `transport/src/ratelimit.rs` | Ad-hoc rate math; an unbounded message/datagram rate exhausting CPU |
| Chunk reassembly | `Reassembler` | `client/src/transfer.rs` | A hand-rolled buffer with unbounded size, too-many-in-flight, bad indices, or duplicate chunks (all capped/deduped by construction) |
| Deliver-once dedup | `SeenSet` | `client/src/transfer.rs` | Showing a retransmitted message twice; an unbounded seen-set |
| Streaming a received file to disk | `FileSink` | `client/src/transfer.rs` | Buffering a whole (arbitrary-size) file in RAM; out-of-order or over-cap writes |
| Per-connection outbound memory | `Outbound` (two byte budgets, backpressure) | `transport/src/server.rs` | An unbounded outbound channel a slow/hostile reader can grow without limit |
| Offline store-and-forward | `MessageQueue` (per-device + global byte/count caps, persisted) | `transport/src/msgqueue.rs` | An unbounded queue a peer can fill by spamming an offline victim |
| Offered-file store | `FileStore` (per-file + total + free-disk-floor quota, TTL) | `transport/src/filestore.rs` | A peer filling server disk/RAM with buffered files |
| Received-file naming | `safe_file_name` + `reserve_download` | `client/src/lib.rs` | Using an attacker-controlled filename as a path (traversal) or overwriting an existing file |
| Content-addressed avatar blob | `seal_blob` / `open_blob` (fresh one-time key, addr = SHA-256 of ciphertext) | `crypto/src/blob.rs` | A hand-rolled "encrypt an image and hash it"; a fixed nonce reused across images; a recipient trusting a server-substituted blob (the address is re-hashed on open) |
| File chunk seal (off the MLS ratchet) | `seal_chunk` / `open_chunk` (per-file content key, nonce = chunk index, AAD = `offer_id \|\| index`) | `crypto/src/blob.rs` | Sealing file chunks as MLS application messages (thousands of them desync the group's message ratchet, and a dropped chunk kills the conversation); reordering/splicing/replaying a chunk across offers or positions; nonce reuse (a fresh key per offer makes the index-nonce unique) |
| Heal a desynced conversation | `Group::rekey` (self-update commit -> fresh epoch, ratchets reset to gen 0) | `crypto/src/group.rs` | Leaving a conversation dead after its message ratchet fell "too far in the future"; the commit rides the separate handshake ratchet, so it applies even while application messages are undecryptable |
| Server avatar store | `AvatarStore` (per-user ring, `addr == hash(data)` verified, persistent) | `transport/src/avatarstore.rs` | One user overwriting another's blob (poisoning), an unbounded avatar history, path traversal (content-addressed hex names) |
| H.264 decode for WebCodecs | `makeH264Decoder` (Annex-B -> AVC/avcC adaptor) | `client/src/ui/index.html` | Handing raw Annex-B to WebKitGTK's `VideoDecoder`, which silently fails ("Decode error") while `isConfigSupported` reports success; one adaptor builds the avcC `description` from the in-band SPS/PPS and length-prefixes each NAL, reused by both the screen viewer and the camera tiles |

- **No new runtime-safety primitive** without adding it here, with the bug class
  it removes; and once one exists, the hand-rolled form (a bare bound, a raw
  filename-as-path, an unbounded channel/queue, an inline dedup) is a smell to
  convert, one site at a time, each with a test.
