use heed::byteorder::BE;
use heed::types::{Bytes, Str, Unit};
use heed::{Database, Env, EnvOpenOptions, WithoutTls};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Constants ──────────────────────────────────────────────────────────
/// Default virtual map size: 1 GB virtual address reservation (not physical RAM).
/// Increased from 256 MB to reduce MapFull occurrences under sustained log output.
/// LMDB only uses physical pages for actually written data.
const DEFAULT_MAP_SIZE: usize = 1_073_741_824;

/// Database name for log entries.
const LOG_DB_NAME: &str = "logs";

/// Database name for seen targets (set).
const TARGETS_DB_NAME: &str = "targets";

/// Maximum resize attempts when LMDB reports MapFull while a reader holds a txn
/// (EBUSY). The TUI's spawn_blocking readers are brief, so backoff is short.
const RESIZE_MAX_ATTEMPTS: u32 = 5;

// ── Types ──────────────────────────────────────────────────────────────

/// Big-endian u64 key type for heed — sort order matches chronological order.
type U64BE = heed::types::U64<BE>;

/// A single log entry stored in LMDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessage {
    pub level: String,
    pub target: String,
    pub message: String,
    /// Timestamp in nanoseconds since UNIX epoch — used as storage key,
    /// not serialized inside the value. Stored here so `LogMessage` can
    /// be returned standalone from read queries.
    pub timestamp_nanos: u64,
}

// ── HeedLogStorage ─────────────────────────────────────────────────────

/// Persistent log storage backed by heed (LMDB).
///
/// ## Architecture
///
/// Two LMDB databases:
/// - `logs`: key = `u64` big-endian timestamp_ns, value = postcard-encoded `LogMessage`
/// - `targets`: key = target string, value = () — a set of seen targets
///
/// All reads/writes are synchronous (heed uses mmap). Callers should wrap
/// this in `Arc` for shared access across async tasks.
pub struct HeedLogStorage {
    env: Env<WithoutTls>,
    /// Key = u64 timestamp_ns (big-endian), Value = postcard(LogMessage)
    logs: Database<U64BE, Bytes>,
    /// Key = target string, Value = () — a set of seen targets
    targets: Database<Str, Unit>,
    /// Counter of MapFull events encountered (incremented instead of emitting tracing events).
    pub mapsize_full_count: AtomicU64,
}

impl HeedLogStorage {
    /// Open or create the heed environment at `path`.
    ///
    /// # Safety
    ///
    /// LMDB uses a memory-mapped file which comes with safety precautions
    /// regarding concurrent access.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB environment cannot be opened or the
    /// databases cannot be created.
    pub fn new(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path).map_err(|e| HeedError::Io(e.to_string()))?;

        let mut options = EnvOpenOptions::new().read_txn_without_tls();
        options.map_size(DEFAULT_MAP_SIZE);
        options.max_dbs(2);

        // SAFETY: We use default flags (no unsafe flags like NO_SYNC).
        let env = unsafe { options.open(path) }.map_err(|e| HeedError::Env(e.to_string()))?;

        let mut wtxn = env.write_txn().map_err(|e| HeedError::Txn(e.to_string()))?;

        let logs: Database<U64BE, Bytes> = env
            .create_database(&mut wtxn, Some(LOG_DB_NAME))
            .map_err(|e| HeedError::Db(e.to_string()))?;

        let targets: Database<Str, Unit> = env
            .create_database(&mut wtxn, Some(TARGETS_DB_NAME))
            .map_err(|e| HeedError::Db(e.to_string()))?;

        wtxn.commit().map_err(|e| HeedError::Txn(e.to_string()))?;

        Ok(Self {
            env,
            logs,
            targets,
            mapsize_full_count: AtomicU64::new(0),
        })
    }

    /// Write a single log entry to the storage.
    ///
    /// Convenience wrapper around [`Self::write_log_batch`].
    pub fn write_log(
        &self,
        timestamp_nanos: u64,
        level: &str,
        target: &str,
        message: &str,
    ) -> Result<()> {
        let msg = LogMessage {
            level: level.to_owned(),
            target: target.to_owned(),
            message: message.to_owned(),
            timestamp_nanos,
        };
        self.write_log_batch(&[msg])
    }

    /// Write a batch of log entries in a single transaction.
    ///
    /// If the map is full, retries doubling the map size (up to 8 GB max) with
    /// short backoff (resize can fail with EBUSY while a reader holds a txn),
    /// then retries the batch once. On persistent failure, increments
    /// [`mapsize_full_count`] instead of emitting tracing events.
    pub fn write_log_batch(&self, messages: &[LogMessage]) -> Result<()> {
        if messages.is_empty() {
            return Ok(());
        }

        match self.try_write_batch(messages) {
            Ok(()) => Ok(()),
            Err(HeedError::MapFull) => {
                // MapFull — grow the map with backoff, then retry the batch
                let current = self.env.info().map_size;
                let new_size = current.saturating_mul(2).min(8_589_934_592); // cap at 8 GB
                if new_size <= current {
                    self.mapsize_full_count.fetch_add(1, Ordering::Relaxed);
                    return Ok(()); // can't grow further, swallow
                }
                let mut attempt = 0u32;
                loop {
                    match resize_backoff(attempt) {
                        Some(delay) => {
                            // Readers are brief spawn_blocking reads; give them time to drop.
                            std::thread::sleep(delay);
                            // SAFETY: no active transactions at this point (the failed write_txn
                            // was already dropped when `try_write_batch` returned the MapFull
                            // error), and no other thread holds a write txn (write_log_batch is
                            // only called from the single background writer task).
                            match unsafe { self.env.resize(new_size) } {
                                Ok(()) => break,
                                Err(_e) => {
                                    if attempt + 1 >= RESIZE_MAX_ATTEMPTS {
                                        self.mapsize_full_count.fetch_add(1, Ordering::Relaxed);
                                        return Ok(()); // swallow after exhaustion (see doc comment)
                                    }
                                    attempt += 1;
                                }
                            }
                        }
                        None => {
                            self.mapsize_full_count.fetch_add(1, Ordering::Relaxed);
                            return Ok(());
                        }
                    }
                }
                // Retry once after resize; keep the batch if it still fails.
                if self.try_write_batch(messages).is_err() {
                    self.mapsize_full_count.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
            Err(other) => Err(other),
        }
    }

    /// Internal: write a batch in one transaction. Returns [`HeedError::MapFull`] on MapFull.
    fn try_write_batch(&self, messages: &[LogMessage]) -> Result<()> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| HeedError::Txn(e.to_string()))?;

        // One 4 KiB scratch reused for every message in the batch (postcard
        // writes into it, heed copies out on `put`): 1 alloc per batch instead
        // of 1 per message. Oversized messages fall back to a heap vec.
        let mut scratch = vec![0u8; 4096];
        for msg in messages {
            // Scratch reused across the batch; the oversized fallback owns its
            // vec for exactly one iteration (declared uninit, assigned only on
            // the overflow path, so the hot path pays no extra alloc).
            let fallback: Option<Vec<u8>>;
            let encoded: &[u8] = match postcard::to_slice(msg, &mut scratch) {
                Ok(used) => used,
                Err(_) => {
                    fallback = Some(
                        postcard::to_allocvec(msg).map_err(|e| HeedError::Serde(e.to_string()))?,
                    );
                    fallback.as_deref().unwrap_or(&[])
                }
            };

            if let Err(e) = self.logs.put(&mut wtxn, &msg.timestamp_nanos, encoded) {
                return Err(match e {
                    heed::Error::Mdb(heed::MdbError::MapFull) => HeedError::MapFull,
                    other => HeedError::Db(other.to_string()),
                });
            }

            // Upsert target (put with existing key is a no-op for Unit values)
            if let Err(_e) = self.targets.put(&mut wtxn, &msg.target, &()) {
                // Non-critical — ignore individual target upsert failures
            }
        }

        wtxn.commit().map_err(|e| HeedError::Txn(e.to_string()))?;
        Ok(())
    }

    /// Read the most recent `limit` log entries (newest first).
    pub fn read_recent(&self, limit: usize) -> Result<Vec<LogMessage>> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| HeedError::Txn(e.to_string()))?;

        let mut results = Vec::with_capacity(limit);
        let iter = self
            .logs
            .rev_iter(&rtxn)
            .map_err(|e| HeedError::Db(e.to_string()))?;

        for item in iter.take(limit) {
            let (key, value) = item.map_err(|e| HeedError::Db(e.to_string()))?;
            if let Some(msg) = decode_entry(key, value) {
                results.push(msg);
            }
        }
        Ok(results)
    }

    /// Read entries strictly older than `before_ns` (newest-first within range).
    pub fn read_older_than(&self, before_ns: u64, limit: usize) -> Result<Vec<LogMessage>> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| HeedError::Txn(e.to_string()))?;

        let mut results = Vec::with_capacity(limit);
        // rev_range(0..before_ns) iterates from before_ns-1 down to 0
        let range = 0u64..before_ns;
        let iter = self
            .logs
            .rev_range(&rtxn, &range)
            .map_err(|e| HeedError::Db(e.to_string()))?;

        for item in iter.take(limit) {
            let (key, value) = item.map_err(|e| HeedError::Db(e.to_string()))?;
            if let Some(msg) = decode_entry(key, value) {
                results.push(msg);
            }
        }
        Ok(results)
    }

    /// Read EVERY entry strictly older than `before_ns`, paging backwards by
    /// `page` so one call cannot build an unbounded `Vec`, and returning them in
    /// **chronological order** (oldest first).
    ///
    /// This exists for EXPORT. `read_older_than` is a paged backward read for the
    /// Logs panel's scrollback and is fine for that, but nothing could read the
    /// whole store in one go — so an export had to be built from the in-memory
    /// cache, which is seeded with the 500 newest entries and only grows
    /// forward. The 2026-10-01 dump was 575 of 1,313 stored lines (44%) with no
    /// indication that anything was missing.
    ///
    /// `cap` bounds the WORK, not just the result: paging **stops** once the cap
    /// is reached, so a store larger than `cap` is never materialized in full.
    /// The result is truncated to `cap`; a caller that cares can tell by
    /// comparing `len()` against it.
    pub fn read_all_older_than(
        &self,
        before_ns: u64,
        page: usize,
        cap: usize,
    ) -> Result<Vec<LogMessage>> {
        let page = page.max(1);
        let mut out: Vec<LogMessage> = Vec::new();
        let mut cursor = before_ns;
        while out.len() < cap {
            let want = page.min(cap - out.len());
            let batch = self.read_older_than(cursor, want)?;
            if batch.is_empty() {
                break;
            }
            // `read_older_than` is newest-first within its range, so the LAST
            // element is the oldest of the page and the next cursor.
            let oldest = batch.last().map_or(0, |m| m.timestamp_nanos);
            out.extend(batch);
            if oldest == 0 || oldest >= cursor {
                break; // reached the start of the store, or no progress
            }
            cursor = oldest;
        }
        out.truncate(cap);
        out.reverse();
        Ok(out)
    }

    /// Async wrapper for [`Self::read_all_older_than`], for the export path.
    pub async fn read_all_older_than_async(
        self: &Arc<Self>,
        before_ns: u64,
        page: usize,
        cap: usize,
    ) -> Result<Vec<LogMessage>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.read_all_older_than(before_ns, page, cap))
            .await
            .map_err(|e| HeedError::Txn(e.to_string()))?
    }

    /// Read entries strictly newer than `after_ns` (newest-first within range).
    pub fn read_newer_than(&self, after_ns: u64, limit: usize) -> Result<Vec<LogMessage>> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| HeedError::Txn(e.to_string()))?;

        let mut results = Vec::with_capacity(limit);
        // rev_range(after_ns+1..=MAX) gives us newest entries > after_ns first
        let start = after_ns.saturating_add(1);
        let range = start..=u64::MAX;
        let iter = self
            .logs
            .rev_range(&rtxn, &range)
            .map_err(|e| HeedError::Db(e.to_string()))?;

        for item in iter.take(limit) {
            let (key, value) = item.map_err(|e| HeedError::Db(e.to_string()))?;
            if let Some(msg) = decode_entry(key, value) {
                results.push(msg);
            }
        }
        Ok(results)
    }

    /// List all known target names (from the targets set).
    pub fn get_targets(&self) -> Result<Vec<String>> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| HeedError::Txn(e.to_string()))?;

        let mut results = Vec::new();
        let iter = self
            .targets
            .iter(&rtxn)
            .map_err(|e| HeedError::Db(e.to_string()))?;

        for item in iter {
            let (key, _value) = item.map_err(|e| HeedError::Db(e.to_string()))?;
            results.push(key.to_owned());
        }
        Ok(results)
    }

    /// Delete all log entries with keys strictly less than `cutoff_ns`.
    /// Returns the count of deleted entries.
    pub fn delete_older_than(&self, cutoff_ns: u64) -> Result<usize> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| HeedError::Txn(e.to_string()))?;

        let range = 0u64..cutoff_ns;
        let deleted = self
            .logs
            .delete_range(&mut wtxn, &range)
            .map_err(|e| HeedError::Db(e.to_string()))?;

        wtxn.commit().map_err(|e| HeedError::Txn(e.to_string()))?;
        Ok(deleted)
    }

    /// Clear all log entries and targets from the database.
    /// This empties both the `logs` and `targets` databases.
    pub fn clear_all(&self) -> Result<()> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| HeedError::Txn(e.to_string()))?;

        self.logs
            .clear(&mut wtxn)
            .map_err(|e| HeedError::Db(e.to_string()))?;
        self.targets
            .clear(&mut wtxn)
            .map_err(|e| HeedError::Db(e.to_string()))?;

        wtxn.commit().map_err(|e| HeedError::Txn(e.to_string()))?;
        Ok(())
    }
    // ── Async wrappers (spawn_blocking for use from async context) ──

    /// Async version of [`Self::read_recent`] that wraps the heed call in `spawn_blocking`.
    pub async fn read_recent_async(self: &Arc<Self>, limit: usize) -> Result<Vec<LogMessage>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.read_recent(limit))
            .await
            .map_err(|e| HeedError::Io(e.to_string()))?
    }

    /// Async version of [`Self::read_newer_than`] that wraps the heed call in `spawn_blocking`.
    pub async fn read_newer_than_async(
        self: &Arc<Self>,
        after_ns: u64,
        limit: usize,
    ) -> Result<Vec<LogMessage>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.read_newer_than(after_ns, limit))
            .await
            .map_err(|e| HeedError::Io(e.to_string()))?
    }

    /// Async version of [`Self::read_older_than`] that wraps the heed call in `spawn_blocking`.
    pub async fn read_older_than_async(
        self: &Arc<Self>,
        before_ns: u64,
        limit: usize,
    ) -> Result<Vec<LogMessage>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.read_older_than(before_ns, limit))
            .await
            .map_err(|e| HeedError::Io(e.to_string()))?
    }

    /// Async version of [`Self::get_targets`] that wraps the heed call in `spawn_blocking`.
    pub async fn get_targets_async(self: &Arc<Self>) -> Result<Vec<String>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.get_targets())
            .await
            .map_err(|e| HeedError::Io(e.to_string()))?
    }

    /// Async version of [`Self::clear_all`] that wraps the heed call in `spawn_blocking`.
    pub async fn clear_all_async(self: &Arc<Self>) -> Result<()> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.clear_all())
            .await
            .map_err(|e| HeedError::Io(e.to_string()))?
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn decode_entry(key: u64, value: &[u8]) -> Option<LogMessage> {
    let mut msg: LogMessage = postcard::from_bytes(value).ok()?;
    msg.timestamp_nanos = key;
    Some(msg)
}

/// Backoff delay before resize attempt `attempt` (0-based), or `None` once the
/// attempt budget is exhausted. Delays grow 50ms per attempt: 50..=250ms.
fn resize_backoff(attempt: u32) -> Option<std::time::Duration> {
    if attempt >= RESIZE_MAX_ATTEMPTS {
        None
    } else {
        Some(std::time::Duration::from_millis(
            50 * (u64::from(attempt) + 1),
        ))
    }
}

// ── Error type ─────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum HeedError {
    #[error("heed env error: {0}")]
    Env(String),
    #[error("heed txn error: {0}")]
    Txn(String),
    #[error("heed db error: {0}")]
    Db(String),
    #[error("heed map full")]
    MapFull,
    #[error("I/O error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serde(String),
}

/// Convenience alias.
pub type Result<T, E = HeedError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_msg(ts: u64, i: usize) -> LogMessage {
        LogMessage {
            level: "info".to_string(),
            target: format!("target_{}", i),
            message: format!("message_{}", i),
            timestamp_nanos: ts,
        }
    }
    #[test]
    fn many_worker_thread_reads_release_reader_slots() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(HeedLogStorage::new(dir.path()).unwrap());
        storage
            .write_log(1000, "info", "target", "message")
            .unwrap();

        for _ in 0..160 {
            let worker_storage = Arc::clone(&storage);
            let worker = std::thread::spawn(move || {
                let recent = worker_storage.read_recent(1).unwrap();
                assert_eq!(recent.len(), 1);
                assert_eq!(recent[0].message, "message");
            });
            worker.join().unwrap();
        }
    }

    #[test]
    fn resize_retries_until_success_or_exhaustion() {
        // Pure helper: attempt count / backoff decisions.
        assert_eq!(
            resize_backoff(0),
            Some(std::time::Duration::from_millis(50))
        );
        assert_eq!(
            resize_backoff(1),
            Some(std::time::Duration::from_millis(100))
        );
        assert_eq!(
            resize_backoff(2),
            Some(std::time::Duration::from_millis(150))
        );
        assert_eq!(
            resize_backoff(3),
            Some(std::time::Duration::from_millis(200))
        );
        assert_eq!(
            resize_backoff(4),
            Some(std::time::Duration::from_millis(250))
        );
        assert_eq!(resize_backoff(5), None); // give up after 5
    }

    #[test]
    fn write_and_read_batch() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        let msgs: Vec<_> = (0..10).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();

        let recent = storage.read_recent(100).unwrap();
        // read_recent returns newest-first
        assert_eq!(recent.len(), 10);
        for (i, msg) in recent.iter().enumerate() {
            assert_eq!(msg.message, format!("message_{}", 9 - i));
            assert_eq!(msg.target, format!("target_{}", 9 - i));
        }
    }

    #[test]
    fn write_single_log() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        storage
            .write_log(500, "error", "my_target", "test error")
            .unwrap();

        let recent = storage.read_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].level, "error");
        assert_eq!(recent[0].target, "my_target");
        assert_eq!(recent[0].message, "test error");
        assert_eq!(recent[0].timestamp_nanos, 500);
    }

    /// The EXPORT read must return the WHOLE store in chronological order,
    /// across page boundaries — that is the property the 2026-10-01 export
    /// lacked, when it copied a 500-entry cache and produced 575 of 1,313
    /// stored lines.
    #[test]
    fn read_all_older_than_spans_every_page_in_order() {
        let dir = tempdir().expect("tempdir");
        let store = HeedLogStorage::new(dir.path()).expect("new");
        // 1,250 entries in 5 pages of 250 — deliberately NOT a page multiple.
        for i in 0..1_250u64 {
            store
                .write_log_batch(&[make_msg(1_000 + i, i as usize)])
                .expect("write");
        }
        let all = store
            .read_all_older_than(u64::MAX, 250, 10_000)
            .expect("read all");
        assert_eq!(
            all.len(),
            1_250,
            "every stored entry must be returned, not one page of it",
        );
        // Chronological: oldest first, ascending.
        assert!(
            all.windows(2)
                .all(|w| w[0].timestamp_nanos < w[1].timestamp_nanos),
            "results must be in ascending timestamp order",
        );
        assert_eq!(all.first().map(|m| m.timestamp_nanos), Some(1_000));
        assert_eq!(all.last().map(|m| m.timestamp_nanos), Some(2_249));
    }

    /// The RESULT is capped, so an export of a store far larger than the cap
    /// does not hand the clipboard a multi-million-line string.
    ///
    /// What this does NOT pin: that paging *stops* (the work bound). With
    /// `out.truncate(cap)` still in place, replacing the loop's `out.len() < cap`
    /// with an unbounded condition leaves this test green — verified by
    /// falsification. The work bound is the loop condition, so it is a reading
    /// claim, not a tested one.
    #[test]
    fn read_all_older_than_stops_at_the_cap() {
        let dir = tempdir().expect("tempdir");
        let store = HeedLogStorage::new(dir.path()).expect("new");
        for i in 0..600u64 {
            store
                .write_log_batch(&[make_msg(1_000 + i, i as usize)])
                .expect("write");
        }
        let capped = store
            .read_all_older_than(u64::MAX, 100, 250)
            .expect("read capped");
        assert_eq!(capped.len(), 250, "the cap must bound the result");
        // The KEPT entries are the NEWEST ones (the cap stops the backward walk),
        // still in ascending order.
        assert!(
            capped
                .windows(2)
                .all(|w| w[0].timestamp_nanos < w[1].timestamp_nanos),
            "still chronological",
        );
        assert_eq!(
            capped.last().map(|m| m.timestamp_nanos),
            Some(1_599),
            "the walk stops at the cap, keeping the newest entries",
        );
    }

    /// A one-page store must terminate rather than loop: the cursor must stop
    /// when it can no longer move backwards.
    #[test]
    fn read_all_older_than_terminates_on_a_small_store() {
        let dir = tempdir().expect("tempdir");
        let store = HeedLogStorage::new(dir.path()).expect("new");
        store.write_log_batch(&[make_msg(10, 0)]).expect("write");
        let all = store
            .read_all_older_than(u64::MAX, 5_000, 10_000)
            .expect("read");
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn read_recent_respects_limit() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        let msgs: Vec<_> = (0..20).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();

        // Request fewer than total
        let recent = storage.read_recent(5).unwrap();
        assert_eq!(recent.len(), 5);
        // Newest entries first: indices 19, 18, 17, 16, 15
        assert_eq!(recent[0].timestamp_nanos, 1019);
        assert_eq!(recent[4].timestamp_nanos, 1015);
    }

    #[test]
    fn read_newer_than() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        let msgs: Vec<_> = (0..10).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();

        // Entries newer than ts=1004 (i.e. ts >= 1005)
        let newer = storage.read_newer_than(1004, 10).unwrap();
        assert_eq!(newer.len(), 5);
        // Newest-first: 1009, 1008, 1007, 1006, 1005
        assert_eq!(newer[0].timestamp_nanos, 1009);
        assert_eq!(newer[4].timestamp_nanos, 1005);
        // No entries newer than the newest
        let empty = storage.read_newer_than(1009, 10).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn read_older_than() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        let msgs: Vec<_> = (0..10).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();

        // Entries older than ts=1004 (i.e. ts < 1004)
        let older = storage.read_older_than(1004, 10).unwrap();
        assert_eq!(older.len(), 4);
        // Newest-first: 1003, 1002, 1001, 1000
        assert_eq!(older[0].timestamp_nanos, 1003);
        assert_eq!(older[3].timestamp_nanos, 1000);
        // No entries older than the oldest
        let empty = storage.read_older_than(1000, 10).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn delete_older_than() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        // Write entries with controlled timestamps
        let msgs: Vec<_> = (0..10).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();

        // Delete entries older than ts=1005 (i.e. ts < 1005)
        let deleted = storage.delete_older_than(1005).unwrap();
        assert_eq!(deleted, 5); // removed ts 1000-1004

        let remaining = storage.read_recent(100).unwrap();
        assert_eq!(remaining.len(), 5);
        // Remaining: 1005, 1006, 1007, 1008, 1009
        assert_eq!(remaining[0].timestamp_nanos, 1009);
        assert_eq!(remaining[4].timestamp_nanos, 1005);
    }

    #[test]
    fn clear_all() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        let msgs: Vec<_> = (0..5).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();
        assert_eq!(storage.read_recent(100).unwrap().len(), 5);

        storage.clear_all().unwrap();
        assert!(storage.read_recent(100).unwrap().is_empty());
    }

    #[test]
    fn get_targets() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        let msgs: Vec<_> = (0..5)
            .map(|i| {
                LogMessage {
                    level: "info".to_string(),
                    target: format!("target_{}", i % 3), // 3 unique targets
                    message: format!("msg_{}", i),
                    timestamp_nanos: 1000 + i as u64,
                }
            })
            .collect();
        storage.write_log_batch(&msgs).unwrap();

        let mut targets = storage.get_targets().unwrap();
        targets.sort();
        assert_eq!(targets, vec!["target_0", "target_1", "target_2"]);
    }

    #[tokio::test]
    async fn async_read_recent() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(HeedLogStorage::new(dir.path()).unwrap());

        let msgs: Vec<_> = (0..5).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();

        let recent = storage.read_recent_async(10).await.unwrap();
        assert_eq!(recent.len(), 5);
    }

    #[tokio::test]
    async fn async_read_newer_than() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(HeedLogStorage::new(dir.path()).unwrap());

        let msgs: Vec<_> = (0..5).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();

        let newer = storage.read_newer_than_async(1002, 10).await.unwrap();
        // ts > 1002: 1003, 1004
        assert_eq!(newer.len(), 2);
        assert_eq!(newer[0].timestamp_nanos, 1004);
    }

    #[tokio::test]
    async fn async_read_older_than() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(HeedLogStorage::new(dir.path()).unwrap());

        let msgs: Vec<_> = (0..5).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();

        let older = storage.read_older_than_async(1003, 10).await.unwrap();
        // ts < 1003: 1000, 1001, 1002
        assert_eq!(older.len(), 3);
    }

    #[tokio::test]
    async fn async_clear_all() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(HeedLogStorage::new(dir.path()).unwrap());

        let msgs: Vec<_> = (0..5).map(|i| make_msg(1000 + i as u64, i)).collect();
        storage.write_log_batch(&msgs).unwrap();
        assert_eq!(storage.read_recent(100).unwrap().len(), 5);

        storage.clear_all_async().await.unwrap();
        assert!(storage.read_recent(100).unwrap().is_empty());
    }

    #[tokio::test]
    async fn async_get_targets() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(HeedLogStorage::new(dir.path()).unwrap());

        storage
            .write_log(500, "warn", "async_target", "async test")
            .unwrap();

        let targets = storage.get_targets_async().await.unwrap();
        assert!(targets.contains(&"async_target".to_string()));
    }

    #[test]
    fn empty_batch_is_noop() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();
        storage.write_log_batch(&[]).unwrap();
        assert!(storage.read_recent(10).unwrap().is_empty());
    }

    #[test]
    fn overwrite_same_timestamp() {
        let dir = tempdir().unwrap();
        let storage = HeedLogStorage::new(dir.path()).unwrap();

        // Write two entries with same key (same timestamp)
        storage.write_log(100, "info", "dup", "first").unwrap();
        storage.write_log(100, "error", "dup", "second").unwrap();

        let recent = storage.read_recent(10).unwrap();
        // LMDB put with same key overwrites — we should only see the latest
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].level, "error");
        assert_eq!(recent[0].message, "second");
    }
}
