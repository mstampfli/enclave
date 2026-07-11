# Enclave -- cryptographic primitives (single source of truth)

We assemble vetted primitives and hand-roll none. Every crypto choice lives
here; if it is not in this table, we do not use it.

| Concern | Primitive | Library | Why |
|---|---|---|---|
| Identity signature | Ed25519 | `ed25519-dalek` | Fast, misuse-resistant, widely reviewed |
| Group key agreement | MLS | `openmls` | Scalable rekey, forward secrecy, post-compromise security, authenticated membership |
| Media/text AEAD | ChaCha20-Poly1305 | `chacha20poly1305` | Fast in software, no timing-side-channel table lookups, nonce-misuse-visible |
| Key derivation | HKDF-SHA256 | `hkdf` + `sha2` | Standard exporter->media-key derivation |
| Safety number | SHA-256 over sorted member identity keys | `sha2` | Deterministic, comparable out-of-band |
| Secret zeroing | `zeroize` | `zeroize` | Wipe key material on drop |

## Rules

- **Nonces:** per-sender monotonic counter, never reused under one key. Owned by
  the frame sealer (`enclave-crypto::media::MediaSealer`) so reuse is
  unrepresentable, not merely avoided.
- **Anti-replay:** a 64-entry sliding window (`ReplayWindow`, RFC 6479 style) in
  `MediaOpener` accepts out-of-order real-time frames once and rejects
  duplicates / too-old frames. Authenticate first, then update the window, so a
  forged frame cannot poison it.
- **Keys:** private identity + MLS secrets never leave the client; wrapped in
  `zeroize` types; never logged, never serialized to the server.
- **Frame layout:** encrypt the *encoded* frame (Opus/video), never raw samples
  -- there is no lossy stage after encryption to corrupt ciphertext.
- **No new primitive** without adding it here first, with a justification.
