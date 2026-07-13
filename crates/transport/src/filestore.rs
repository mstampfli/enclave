//! Server-side store for offered files awaiting the recipient's consent.
//!
//! A file is never pushed to a recipient. The sender uploads it here (only when
//! it needs to survive the recipient being offline; a both-online transfer
//! streams live and never touches this store), the recipient is *offered* it,
//! and the bytes are delivered only if they explicitly accept. On accept or
//! decline by every targeted recipient, or when the time-to-live expires, the
//! blob is deleted.
//!
//! Everything held here is opaque sealed ciphertext: the store buffers the
//! sender's already-MLS-sealed chunks and replays them to an accepting
//! recipient, so the server never sees the file's bytes or (the manifest being
//! sealed too) its name. It sees only the size, which it needs to enforce
//! quotas.
//!
//! # DoS bounds (ASVS V11, V12)
//!
//! Admission is gated three ways before a single byte is written:
//! - **per file** (`PER_FILE_MAX`): one file cannot be arbitrarily large;
//! - **whole store** (`STORE_TOTAL_MAX`): all offers together are capped;
//! - **free disk** (`DISK_FREE_FLOOR`): an upload is refused if completing it
//!   would drop the disk below a reserve, so file offers can never fill the
//!   disk out from under the rest of the server.
//!
//! The blob is written to disk (not RAM) so many concurrent offers cost disk,
//! which the free-disk floor bounds, rather than memory. Metadata is in memory
//! and deliberately not persisted: a server restart drops pending offers, which
//! is safe (the sender re-offers) and cannot be abused to accumulate state.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use enclave_protocol::{GroupId, Sealed};

/// Largest single file that may be stored for offline delivery. A file larger
/// than this can still be sent, but only live (both parties online), never
/// buffered on the server.
pub const PER_FILE_MAX: u64 = 250 * 1024 * 1024;
/// Total bytes the whole file store may hold across all pending offers.
pub const STORE_TOTAL_MAX: u64 = 2 * 1024 * 1024 * 1024;
/// Free disk the store keeps in reserve: an upload that would drop free space
/// below this is refused.
pub const DISK_FREE_FLOOR: u64 = 4 * 1024 * 1024 * 1024;
/// How long an unanswered offer is kept before it is swept.
pub const OFFER_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Why an upload was refused. Returned to the sender so the UI can explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// The file exceeds `PER_FILE_MAX`; it can only be sent live.
    TooLarge,
    /// The whole store is full (`STORE_TOTAL_MAX`).
    StoreFull,
    /// Storing it would drop free disk below `DISK_FREE_FLOOR`.
    DiskLow,
    /// The offer id is already in use, or the store had an I/O error.
    Unavailable,
}

impl Rejected {
    pub fn as_str(&self) -> &'static str {
        match self {
            Rejected::TooLarge => "file is too large to store for offline delivery",
            Rejected::StoreFull => "the server's file store is full, try again later",
            Rejected::DiskLow => "the server is low on disk space",
            Rejected::Unavailable => "the file could not be stored",
        }
    }
}

/// Result of a recipient resolving (accepting or declining) an offer.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Recorded; other recipients still have the offer.
    Recorded,
    /// The last recipient resolved, so the blob was deleted.
    Deleted,
    /// No such offer (already gone / expired).
    Unknown,
}

/// One offered file and its delivery state.
struct Offer {
    group: GroupId,
    sender: String,
    /// Everyone who may still accept. Shrinks as recipients resolve.
    pending: HashSet<String>,
    /// Declared total size, used for the quota and to detect overrun.
    declared: u64,
    /// Bytes written so far.
    written: u64,
    /// Set once the sender finishes uploading and the offer is deliverable.
    complete: bool,
    manifest: Option<Sealed>,
    expires_at: SystemTime,
    blob: PathBuf,
}

/// The file store. Blobs live under `dir`; metadata is in memory.
pub struct FileStore {
    dir: PathBuf,
    offers: HashMap<[u8; 16], Offer>,
    used_bytes: u64,
    /// Injected free-disk query, so the quota logic is testable without a real
    /// full disk. Production uses `fs2::available_space`.
    available: Box<dyn Fn() -> u64 + Send>,
}

impl FileStore {
    /// A store rooted at `dir`, using the real filesystem's free space.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let probe = dir.clone();
        Self::with_disk_probe(dir, move || {
            fs2::available_space(&probe).unwrap_or(u64::MAX)
        })
    }

    /// A store with an injected free-disk query (for tests).
    pub fn with_disk_probe(dir: impl Into<PathBuf>, available: impl Fn() -> u64 + Send + 'static) -> Self {
        let dir = dir.into();
        let _ = std::fs::create_dir_all(&dir);
        Self {
            dir,
            offers: HashMap::new(),
            used_bytes: 0,
            available: Box::new(available),
        }
    }

    /// Check whether a `size`-byte upload would be admitted, without reserving.
    pub fn would_admit(&self, size: u64) -> Result<(), Rejected> {
        if size > PER_FILE_MAX {
            return Err(Rejected::TooLarge);
        }
        if self.used_bytes.saturating_add(size) > STORE_TOTAL_MAX {
            return Err(Rejected::StoreFull);
        }
        // Refuse if writing this file would leave less than the floor free.
        if (self.available)().saturating_sub(size) < DISK_FREE_FLOOR {
            return Err(Rejected::DiskLow);
        }
        Ok(())
    }

    /// Begin an upload: admit `declared` bytes and open the blob for writing.
    pub fn begin(
        &mut self,
        id: [u8; 16],
        group: GroupId,
        sender: String,
        recipients: Vec<String>,
        declared: u64,
        now: SystemTime,
    ) -> Result<(), Rejected> {
        if self.offers.contains_key(&id) {
            return Err(Rejected::Unavailable);
        }
        self.would_admit(declared)?;
        let blob = self.dir.join(format!("{}.blob", hex(&id)));
        // Truncate/create the blob now so a partial upload is bounded on disk.
        std::fs::File::create(&blob).map_err(|_| Rejected::Unavailable)?;
        self.offers.insert(
            id,
            Offer {
                group,
                sender,
                pending: recipients.into_iter().collect(),
                declared,
                written: 0,
                complete: false,
                manifest: None,
                expires_at: now + OFFER_TTL,
                blob,
            },
        );
        self.used_bytes = self.used_bytes.saturating_add(declared);
        Ok(())
    }

    /// Append one sealed chunk to an in-progress upload. Rejects (and drops the
    /// whole offer) if the running total exceeds what was declared, so a sender
    /// cannot under-declare to slip past admission.
    pub fn append(&mut self, id: &[u8; 16], chunk: &[u8]) -> Result<(), Rejected> {
        let Some(offer) = self.offers.get_mut(id) else {
            return Err(Rejected::Unavailable);
        };
        if offer.complete {
            return Err(Rejected::Unavailable);
        }
        let new_written = offer.written.saturating_add(chunk.len() as u64);
        if new_written > offer.declared {
            // Overrun: the sender lied about the size. Drop the whole offer.
            self.remove(id);
            return Err(Rejected::TooLarge);
        }
        // Length-prefix each chunk so the exact sealed boundaries replay on read.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&offer.blob)
            .map_err(|_| Rejected::Unavailable)?;
        let len = (chunk.len() as u32).to_le_bytes();
        f.write_all(&len).and_then(|_| f.write_all(chunk)).map_err(|_| Rejected::Unavailable)?;
        offer.written = new_written;
        Ok(())
    }

    /// Finish an upload: attach the sealed manifest and make it deliverable.
    /// Reclaims any over-reserved bytes (declared minus actually written).
    pub fn finish(&mut self, id: &[u8; 16], manifest: Sealed) -> Result<(), Rejected> {
        let Some(offer) = self.offers.get_mut(id) else {
            return Err(Rejected::Unavailable);
        };
        // Return the difference between what we reserved and what arrived.
        let slack = offer.declared.saturating_sub(offer.written);
        self.used_bytes = self.used_bytes.saturating_sub(slack);
        offer.declared = offer.written;
        offer.manifest = Some(manifest);
        offer.complete = true;
        Ok(())
    }

    /// The group, sender, size, manifest, and recipients of a completed offer,
    /// for building the `FileOffered` notifications.
    pub fn offer_meta(&self, id: &[u8; 16]) -> Option<(GroupId, String, u64, Sealed, Vec<String>)> {
        let o = self.offers.get(id)?;
        if !o.complete {
            return None;
        }
        Some((
            o.group.clone(),
            o.sender.clone(),
            o.written,
            o.manifest.clone()?,
            o.pending.iter().cloned().collect(),
        ))
    }

    /// Read the stored sealed chunks back, in upload order, streamed from disk
    /// (one chunk in memory at a time). `None` if the offer is unknown or
    /// incomplete. `recipient` must be a pending recipient of the offer.
    pub fn read_chunks(&self, id: &[u8; 16], recipient: &str) -> Option<Vec<Vec<u8>>> {
        let offer = self.offers.get(id)?;
        if !offer.complete || !offer.pending.contains(recipient) {
            return None;
        }
        let mut f = std::fs::File::open(&offer.blob).ok()?;
        let mut chunks = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            match f.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => return None,
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf).ok()?;
            chunks.push(buf);
        }
        Some(chunks)
    }

    /// Mark one recipient as having accepted or declined. When the last pending
    /// recipient resolves, the blob is deleted.
    pub fn resolve(&mut self, id: &[u8; 16], recipient: &str) -> Resolution {
        let Some(offer) = self.offers.get_mut(id) else {
            return Resolution::Unknown;
        };
        offer.pending.remove(recipient);
        if offer.pending.is_empty() {
            self.remove(id);
            Resolution::Deleted
        } else {
            Resolution::Recorded
        }
    }

    /// The group of an offer, so a resolution can be announced to the sender.
    pub fn offer_group(&self, id: &[u8; 16]) -> Option<(GroupId, String)> {
        self.offers.get(id).map(|o| (o.group.clone(), o.sender.clone()))
    }

    /// Delete every offer past its TTL, returning their ids (to notify).
    pub fn sweep(&mut self, now: SystemTime) -> Vec<[u8; 16]> {
        let expired: Vec<[u8; 16]> = self
            .offers
            .iter()
            .filter(|(_, o)| o.expires_at <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.remove(id);
        }
        expired
    }

    /// Delete an offer's blob and metadata, reclaiming its quota.
    pub fn remove(&mut self, id: &[u8; 16]) {
        if let Some(offer) = self.offers.remove(id) {
            let _ = std::fs::remove_file(&offer.blob);
            self.used_bytes = self.used_bytes.saturating_sub(offer.declared);
        }
    }

    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }
}

fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(free: u64) -> (FileStore, PathBuf) {
        // A unique dir per store so parallel tests never share blob files.
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "enclave-fstore-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        (FileStore::with_disk_probe(dir.clone(), move || free), dir)
    }

    fn id(n: u8) -> [u8; 16] {
        let mut i = [0u8; 16];
        i[0] = n;
        i
    }

    #[test]
    fn upload_then_read_replays_the_exact_chunks() {
        let (mut s, dir) = store(u64::MAX);
        let i = id(1);
        s.begin(i, GroupId([0; 32]), "alice".into(), vec!["bob".into()], 30, SystemTime::UNIX_EPOCH)
            .unwrap();
        s.append(&i, b"hello ").unwrap();
        s.append(&i, b"world").unwrap();
        s.finish(&i, Sealed(vec![9, 9])).unwrap();
        let chunks = s.read_chunks(&i, "bob").expect("readable");
        assert_eq!(chunks, vec![b"hello ".to_vec(), b"world".to_vec()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_over_the_per_file_cap_is_refused() {
        let (s, _d) = store(u64::MAX);
        assert_eq!(s.would_admit(PER_FILE_MAX + 1), Err(Rejected::TooLarge));
        assert_eq!(s.would_admit(PER_FILE_MAX), Ok(()));
    }

    #[test]
    fn the_disk_floor_refuses_when_space_is_low() {
        // Only just above the floor free: a file that would cross it is refused.
        let (s, _d) = store(DISK_FREE_FLOOR + 10);
        assert_eq!(s.would_admit(100), Err(Rejected::DiskLow));
        assert_eq!(s.would_admit(5), Ok(())); // stays above the floor
    }

    #[test]
    fn the_store_total_cap_is_enforced_across_offers() {
        let (mut s, dir) = store(u64::MAX);
        // Fill the store with per-file-max offers until the next one would cross
        // the total cap. A single offer cannot exceed PER_FILE_MAX, so the total
        // cap is only reachable across several offers.
        let mut n = 0u8;
        loop {
            if s.would_admit(PER_FILE_MAX).is_err() {
                break;
            }
            n += 1;
            s.begin(id(n), GroupId([0; 32]), "a".into(), vec!["b".into()], PER_FILE_MAX, SystemTime::UNIX_EPOCH)
                .unwrap();
        }
        assert!(n >= 1, "at least one offer fit");
        assert_eq!(s.would_admit(PER_FILE_MAX), Err(Rejected::StoreFull));
        assert!(s.used_bytes() + PER_FILE_MAX > STORE_TOTAL_MAX, "genuinely at the cap");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn under_declaring_the_size_is_caught_on_overrun() {
        let (mut s, dir) = store(u64::MAX);
        let i = id(1);
        s.begin(i, GroupId([0; 32]), "a".into(), vec!["b".into()], 4, SystemTime::UNIX_EPOCH)
            .unwrap();
        s.append(&i, b"ok").unwrap();
        // Declared 4, this pushes to 6: rejected, offer dropped.
        assert_eq!(s.append(&i, b"toolong"), Err(Rejected::TooLarge));
        assert!(s.read_chunks(&i, "b").is_none(), "offer was dropped");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deletes_only_after_every_recipient_resolves() {
        let (mut s, dir) = store(u64::MAX);
        let i = id(1);
        s.begin(i, GroupId([0; 32]), "a".into(), vec!["b".into(), "c".into()], 5, SystemTime::UNIX_EPOCH)
            .unwrap();
        s.append(&i, b"data!").unwrap();
        s.finish(&i, Sealed(vec![1])).unwrap();
        assert_eq!(s.resolve(&i, "b"), Resolution::Recorded, "c still pending");
        assert!(s.read_chunks(&i, "c").is_some(), "c can still download");
        assert_eq!(s.resolve(&i, "c"), Resolution::Deleted, "last recipient");
        assert!(s.read_chunks(&i, "c").is_none(), "blob gone");
        assert_eq!(s.used_bytes(), 0, "quota reclaimed");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ttl_sweep_deletes_expired_offers() {
        let (mut s, dir) = store(u64::MAX);
        let i = id(1);
        let t0 = SystemTime::UNIX_EPOCH;
        s.begin(i, GroupId([0; 32]), "a".into(), vec!["b".into()], 5, t0).unwrap();
        s.finish(&i, Sealed(vec![1])).unwrap();
        assert!(s.sweep(t0 + Duration::from_secs(60)).is_empty(), "not yet expired");
        let expired = s.sweep(t0 + OFFER_TTL + Duration::from_secs(1));
        assert_eq!(expired, vec![i], "swept after TTL");
        assert!(s.read_chunks(&i, "b").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_non_recipient_cannot_read() {
        let (mut s, dir) = store(u64::MAX);
        let i = id(1);
        s.begin(i, GroupId([0; 32]), "a".into(), vec!["b".into()], 3, SystemTime::UNIX_EPOCH)
            .unwrap();
        s.append(&i, b"xyz").unwrap();
        s.finish(&i, Sealed(vec![1])).unwrap();
        assert!(s.read_chunks(&i, "eve").is_none(), "non-recipient refused");
        assert!(s.read_chunks(&i, "b").is_some());
        let _ = std::fs::remove_dir_all(dir);
    }
}
