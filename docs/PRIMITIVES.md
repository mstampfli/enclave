# Enclave -- cryptographic primitives (single source of truth)

We assemble vetted primitives and hand-roll none. Every crypto choice lives
here; if it is not in this table, we do not use it.

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
