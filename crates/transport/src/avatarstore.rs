//! Server-side content-addressed store for encrypted profile avatars.
//!
//! Unlike the [file store](crate::filestore) (consent-gated, TTL'd, deleted once
//! recipients resolve), avatars back a long-lived profile, so this store is:
//!
//! - **persistent** -- blobs are files on disk and the ownership index is a JSON
//!   side-file, so avatars survive a server restart;
//! - **content-addressed** -- the address a client uploads MUST equal the
//!   SHA-256 of its ciphertext. The store verifies this, so an address can only
//!   ever name its own bytes: one user can never overwrite another's blob, and a
//!   recipient can prove the server did not substitute a blob by re-hashing it.
//!   Because each avatar is sealed under a fresh random key, identical images
//!   still get distinct addresses, so every address has exactly one owner;
//! - **bounded per user** -- only the last [`AVATARS_PER_USER`] uploads are kept;
//!   a newer upload evicts the user's oldest. A recipient always fetches the
//!   *current* avatar (its address rides the latest sealed profile they got), so
//!   evicting older blobs is safe -- anyone who needed an older one already
//!   fetched and cached it.
//!
//! The bytes are opaque ciphertext; the key lives only in the sealed profile, so
//! the server can neither read an avatar nor forge one.
//!
//! PRIMITIVE: quota- and content-address-bounded store for profile avatars; the
//! one home for avatar blob storage. The hash-equals-address check is the single
//! guard against blob poisoning -- never store an avatar without it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Largest avatar blob (encrypted bytes) the server will store. Mirrors the
/// client's `transfer::MAX_AVATAR_BYTES`; the client downscales below this.
pub const MAX_AVATAR_BYTES: usize = 512 * 1024;

/// Avatar blobs kept per user before the oldest is evicted. More than one so a
/// just-superseded avatar is still fetchable by a recipient mid-update.
pub const AVATARS_PER_USER: usize = 3;

/// Outcome of a [`AvatarStore::put`].
#[derive(Debug, PartialEq, Eq)]
pub enum PutResult {
    /// Stored (or already present -- puts are idempotent).
    Stored,
    /// `addr` did not equal the SHA-256 of `data`: rejected (poisoning attempt
    /// or corruption). Nothing is written.
    AddrMismatch,
    /// The blob exceeds [`MAX_AVATAR_BYTES`].
    TooLarge,
    /// A filesystem error prevented the write.
    Io,
}

/// One stored avatar's ownership record (the bytes live in a file named by the
/// address). Order in [`AvatarStore::index`] is insertion order, oldest first.
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    /// Hex of the 32-byte content address (also the blob's filename).
    addr: String,
    /// The user who uploaded it, for per-user eviction.
    owner: String,
}

/// Persistent, content-addressed avatar store. Blobs live under `dir` as files
/// named by their hex address; `index` (owner order) persists to `index.json`.
pub struct AvatarStore {
    dir: PathBuf,
    index: Vec<Entry>,
}

impl AvatarStore {
    /// Open (or create) a store rooted at `dir`, loading any existing index.
    pub fn load(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let _ = std::fs::create_dir_all(&dir);
        let index = std::fs::read_to_string(dir.join("index.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self { dir, index }
    }

    fn blob_path(&self, addr_hex: &str) -> PathBuf {
        self.dir.join(format!("{addr_hex}.blob"))
    }

    /// Store `data` under `addr` on behalf of `owner`. Rejects a mismatched
    /// address (poisoning) or an oversized blob without writing anything. On
    /// success, enforces the per-user ring, evicting `owner`'s oldest blobs.
    pub fn put(&mut self, addr: &[u8; 32], data: &[u8], owner: &str) -> PutResult {
        if data.len() > MAX_AVATAR_BYTES {
            return PutResult::TooLarge;
        }
        // The address MUST be the content hash: this is what stops one user from
        // overwriting another's blob and the server from being fed a lie.
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest: [u8; 32] = hasher.finalize().into();
        if &digest != addr {
            return PutResult::AddrMismatch;
        }
        let addr_hex = hex(addr);
        // Idempotent: a re-upload of an existing blob is a no-op success.
        if self.index.iter().any(|e| e.addr == addr_hex) {
            return PutResult::Stored;
        }
        if std::fs::write(self.blob_path(&addr_hex), data).is_err() {
            return PutResult::Io;
        }
        self.index.push(Entry {
            addr: addr_hex,
            owner: owner.to_string(),
        });
        self.evict_over_limit(owner);
        self.save();
        PutResult::Stored
    }

    /// Fetch the ciphertext stored under `addr`, or `None` if absent (never
    /// uploaded, or evicted). The address is validated to be exactly the blob's
    /// own hex filename, so it can never escape `dir` (content-addressed names
    /// are hex only -- no path traversal is representable).
    pub fn get(&self, addr: &[u8; 32]) -> Option<Vec<u8>> {
        std::fs::read(self.blob_path(&hex(addr))).ok()
    }

    /// Evict `owner`'s oldest blobs beyond [`AVATARS_PER_USER`].
    fn evict_over_limit(&mut self, owner: &str) {
        loop {
            let owned: Vec<usize> = self
                .index
                .iter()
                .enumerate()
                .filter(|(_, e)| e.owner == owner)
                .map(|(i, _)| i)
                .collect();
            if owned.len() <= AVATARS_PER_USER {
                break;
            }
            // Oldest is the first (insertion order); remove file + index entry.
            let oldest = owned[0];
            let entry = self.index.remove(oldest);
            let _ = std::fs::remove_file(self.blob_path(&entry.addr));
        }
    }

    fn save(&self) {
        if let Ok(text) = serde_json::to_string_pretty(&self.index) {
            let _ = std::fs::write(self.dir.join("index.json"), text);
        }
    }

    /// How many blobs `owner` currently has stored (for tests / accounting).
    #[cfg(test)]
    fn count_for(&self, owner: &str) -> usize {
        self.index.iter().filter(|e| e.owner == owner).count()
    }
}

fn hex(addr: &[u8; 32]) -> String {
    addr.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (AvatarStore, PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "enclave-avatars-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        (AvatarStore::load(&dir), dir)
    }

    fn addr_of(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    #[test]
    fn stores_and_fetches_by_address() {
        let (mut s, dir) = store();
        let data = b"encrypted-avatar-bytes";
        let addr = addr_of(data);
        assert_eq!(s.put(&addr, data, "alice"), PutResult::Stored);
        assert_eq!(s.get(&addr).as_deref(), Some(&data[..]));
        // Absent address -> None.
        assert_eq!(s.get(&[0u8; 32]), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_a_wrong_address_no_write() {
        let (mut s, dir) = store();
        let data = b"real bytes";
        let wrong = addr_of(b"different bytes"); // does not match data
        assert_eq!(s.put(&wrong, data, "eve"), PutResult::AddrMismatch);
        assert_eq!(s.get(&wrong), None, "nothing was written");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_oversized() {
        let (mut s, dir) = store();
        let big = vec![0u8; MAX_AVATAR_BYTES + 1];
        let addr = addr_of(&big);
        assert_eq!(s.put(&addr, &big, "alice"), PutResult::TooLarge);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn per_user_ring_evicts_oldest() {
        let (mut s, dir) = store();
        let mut addrs = Vec::new();
        for i in 0..(AVATARS_PER_USER + 2) {
            let data = format!("avatar-{i}").into_bytes();
            let addr = addr_of(&data);
            assert_eq!(s.put(&addr, &data, "alice"), PutResult::Stored);
            addrs.push(addr);
        }
        assert_eq!(s.count_for("alice"), AVATARS_PER_USER, "ring bounded");
        // The two oldest were evicted; the newest AVATARS_PER_USER remain.
        assert!(s.get(&addrs[0]).is_none(), "oldest evicted");
        assert!(s.get(&addrs[1]).is_none(), "second oldest evicted");
        assert!(s.get(addrs.last().unwrap()).is_some(), "newest kept");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eviction_is_per_user_not_global() {
        let (mut s, dir) = store();
        for i in 0..AVATARS_PER_USER {
            let a = format!("a-{i}").into_bytes();
            let b = format!("b-{i}").into_bytes();
            s.put(&addr_of(&a), &a, "alice");
            s.put(&addr_of(&b), &b, "bob");
        }
        assert_eq!(s.count_for("alice"), AVATARS_PER_USER);
        assert_eq!(s.count_for("bob"), AVATARS_PER_USER);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn idempotent_reupload() {
        let (mut s, dir) = store();
        let data = b"same";
        let addr = addr_of(data);
        assert_eq!(s.put(&addr, data, "alice"), PutResult::Stored);
        assert_eq!(s.put(&addr, data, "alice"), PutResult::Stored);
        assert_eq!(s.count_for("alice"), 1, "no double count");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn persists_across_reload() {
        let (mut s, dir) = store();
        let data = b"persist me";
        let addr = addr_of(data);
        s.put(&addr, data, "alice");
        drop(s);
        let s2 = AvatarStore::load(&dir);
        assert_eq!(s2.get(&addr).as_deref(), Some(&data[..]), "survives reload");
        assert_eq!(s2.count_for("alice"), 1, "index reloaded");
        let _ = std::fs::remove_dir_all(dir);
    }
}
