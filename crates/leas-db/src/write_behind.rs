//! Generic write-behind drain driver shared by every write path.
//!
//! A [`WriteBehind<S>`] holds staged rows in a [`DashMap`], kept authoritative
//! while a batch runs, and turns them into chunked transactions on a background
//! task. It is the systematized form of `LinkWriter` (see
//! `docs/aegis/specs/2026-10-05-rowcache-write-behind-design.md`): the same
//! four-trigger policy and re-stage contract, with the per-table parts — the key,
//! the coalesce rule, the write and the rank refresh — supplied by a
//! [`CacheSpec`].
//!
//! Why this exists: concurrent single-row writers on one Turso/SQLite
//! connection produced `query failed [5000ms]` timeouts and `snapshot stale`
//! rollbacks during a 51,087-link import (2026-10-05). Batching the writes into
//! one transaction per window, off the caller's task, is the fix.
//!
//! The driver owns the transaction: [`WriteBehind::flush`] opens one
//! connection + transaction per chunk, calls [`CacheSpec::write_window`] then
//! [`CacheSpec::refresh`], and commits — all inside [`crate::retry_on_busy`].
//! Both spec hooks therefore take `&mut impl toasty::Executor` and never open a
//! transaction of their own.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

/// Default flush trigger: rows.
pub const DEFAULT_FLUSH_ROWS: usize = 512;

/// Default flush trigger: time.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(200);

/// The timer path's floor is `flush_rows / TIMER_FLOOR_DIVISOR`.
///
/// **The measured trade, 2026-10-01 (WAL, 74,014 endpoints).** The old loop
/// flushed on a single staged row, so a 4,028-row batch trickling over 327 s
/// committed **1,167 times — 3.45 rows per transaction**. This divisor is what
/// fixes it, and the cost is real:
///
/// | divisor | floor (of 512) | commits for 4,028 | staging latency @ 12 rows/s |
/// | --- | --- | --- | --- |
/// | 1 (old behaviour) | 1 | **1,167** | ~0.2 s |
/// | **4** | **128** | **~32** | **~10.7 s** |
/// | 2 | 256 | ~16 | ~21.3 s |
///
/// So durability moves from **200 ms to ~10.7 s**. Nothing is *lost* — batch
/// end, quit and reload flush explicitly — but results are delayed, and that
/// delay is what this constant buys.
pub const TIMER_FLOOR_DIVISOR: usize = 4;

/// The timer path's staleness deadline, as a multiple of `flush_interval`.
///
/// Deliberately LONGER than the time to reach the floor at the observed trickle
/// rate, so the floor decides each commit's size and the deadline is only the
/// net for a trickle too slow to ever reach it. A **tick count cannot express
/// this**: the wait to reach N ticks is rate-dependent, and an 8-tick backoff at
/// 12 rows/s forced a write at ~89 rows — under the floor — pre-empting the
/// coalescing it was meant to back up (measured 46 commits, 87.6 rows each).
/// At the 200 ms default this is a 15 s ceiling on how long a staged row may sit
/// unpersisted.
pub const MAX_STAGED_AGE_TICKS: u32 = 75;

/// One drained row: its map key, the source row it came from, and the coalesced
/// patch built from it.
///
/// The triple is what makes the failure path exact: [`WriteBehind::flush`]
/// removes rows from the pending map as it drains, so a failed chunk must be
/// able to re-stage its rows. Reconstructing rows from patches would be lossy
/// (a patch carries only what the write needs), so `coalesce` returns the row
/// alongside the patch instead.
#[derive(Debug, Clone)]
pub struct Coalesced<K, R, P> {
    /// The pending map key this row was staged under.
    pub key: K,
    /// The source row, retained for re-staging after a failed write.
    pub row: R,
    /// The coalesced patch the write path consumes.
    pub patch: P,
}

/// The per-table half of the driver: identity, coalescing, write and refresh.
///
/// `Send + Sync + 'static` (and the same on its associated types) because a
/// driver is shared behind an `Arc` and its flush task is spawned: every value
/// that crosses the staging boundary or rides a transaction future is moved
/// between threads.
pub trait CacheSpec: Send + Sync + 'static {
    /// Staged-row identity in the pending map.
    type Key: Eq + Hash + Clone + Copy + Send + Sync + 'static;
    /// The caller's snapshot of one row.
    type Row: Clone + Send + Sync + 'static;
    /// One coalesced write.
    type Patch: Send + Sync + 'static;

    /// The pending-map key of `row`.
    fn key_of(row: &Self::Row) -> Self::Key;

    /// Fold the drained rows into one patch per identity.
    ///
    /// The returned triples keep the source row so a failed flush can re-stage
    /// it; the driver calls this while holding the flush gate, so the result is
    /// the exact set it will write.
    fn coalesce(rows: Vec<Self::Row>) -> Vec<Coalesced<Self::Key, Self::Row, Self::Patch>>;

    /// Write `patches` on the driver's transaction. Returns rows written.
    ///
    /// The driver opened `tx` and owns the commit; this must not commit or open
    /// its own transaction.
    fn write_window<'a>(
        tx: &'a mut impl toasty::Executor,
        patches: &'a [Self::Patch],
    ) -> impl Future<Output = crate::Result<usize>> + Send + 'a;

    /// Refresh derived state (rank keys, etc.) for the flushed rows, on the same
    /// transaction, after [`Self::write_window`]. A spec with nothing derived
    /// returns `Ok(())`.
    fn refresh<'a>(
        tx: &'a mut impl toasty::Executor,
        patches: &'a [Self::Patch],
    ) -> impl Future<Output = crate::Result<()>> + Send + 'a;

    /// The pending entries a drained row is re-staged as after a failed write.
    ///
    /// Defaults to the identity: one row, under the key it was drained from.
    /// A spec whose staging key is FINER than its patch identity overrides
    /// this, because re-staging under the patch's own key would insert an
    /// entry no later push or drain would ever match — the rows would sit in
    /// the map forever and be written by nothing.
    fn restage_entries(row: &Self::Row) -> Vec<(Self::Key, Self::Row)> {
        vec![(Self::key_of(row), row.clone())]
    }
}

/// A coalescing write-behind drain for one table.
///
/// `push` records the caller's snapshot; the flush task (or an end-of-op call)
/// writes a whole window in chunked transactions. The pending entries — not the
/// database — are the source of truth while a batch is running.
pub struct WriteBehind<S: CacheSpec> {
    /// One snapshot per key. Keyed by [`CacheSpec::key_of`], so a later push
    /// for the same identity replaces the earlier one.
    pending: DashMap<S::Key, S::Row>,
    /// Number of entries in `pending`, kept exactly in step with it because
    /// every insert and remove goes through `put`/`take`.
    ///
    /// A flush trigger that read `pending.len()` would walk EVERY shard of the
    /// map (measured 1.06 µs per call — 95% of `stage`'s 1.12 µs).
    staged: AtomicU64,
    /// Rows a `wake` trigger or a full window carries.
    flush_rows: usize,
    /// Rows a **bare timer tick** must have staged before it writes anything.
    timer_flush_floor: usize,
    /// The timer tick period.
    flush_interval: Duration,
    /// Ceiling on how long a staged row may sit unpersisted.
    max_staged_age: Duration,
    /// The database the flush task opens its transactions against.
    db: Arc<crate::Database>,
    /// Serializes drain-and-write, so an end-of-op flush and the flush task
    /// cannot write the same snapshot twice.
    gate: tokio::sync::Mutex<()>,
    /// Wakes the flush task when a push crosses `flush_rows`.
    wake: tokio::sync::Notify,
    /// Transactions performed (diagnostics and tests).
    flushes: AtomicU64,
    /// Rows committed by every `flush` this driver has ever run, including the
    /// windows of a flush that later FAILED.
    ///
    /// A flush that commits windows 1..k and fails on k+1 returns `Err` and
    /// re-stages k+1.. — so the `Ok` count it would have returned is lost, and
    /// a caller retrying sees only the remainder. Reading the DELTA of this
    /// counter across a whole retry sequence recovers every committed row
    /// exactly once: a row is only ever counted when its transaction commits.
    committed_total: AtomicU64,
    /// Ties the spec's types to the driver without storing a value.
    _spec: std::marker::PhantomData<S>,
}

impl<S: CacheSpec> WriteBehind<S> {
    /// Build a driver with the default staleness deadline.
    ///
    /// `flush_rows` is clamped to at least 1; the timer floor is a quarter of
    /// it (see [`TIMER_FLOOR_DIVISOR`]) and the staleness deadline is
    /// [`MAX_STAGED_AGE_TICKS`] intervals. A spec whose loss window must be
    /// shorter than that product uses [`Self::new_with_deadline`].
    #[must_use]
    pub fn new(db: Arc<crate::Database>, flush_rows: usize, flush_interval: Duration) -> Arc<Self> {
        let max_staged_age = flush_interval.saturating_mul(MAX_STAGED_AGE_TICKS);
        Self::new_with_deadline(db, flush_rows, flush_interval, max_staged_age)
    }

    /// Build a driver whose staleness deadline is stated outright.
    ///
    /// The default deadline is a MULTIPLE of the tick — 75 of them — because
    /// the tick is the coarsest knob a caller usually has. That is right for a
    /// table whose loss window is "minutes at worst" and wrong for one that
    /// promises seconds: at a 5 s tick the default is **375 s**, sixty-odd times
    /// the old hard ceiling. Naming the deadline keeps the durability contract
    /// visible at the call site instead of leaving it to a multiplication.
    ///
    /// `max_staged_age` is clamped to at least one tick, so a deadline shorter
    /// than the tick degrades to "write every tick" rather than to a busy loop
    /// that writes on every wake.
    #[must_use]
    pub fn new_with_deadline(
        db: Arc<crate::Database>,
        flush_rows: usize,
        flush_interval: Duration,
        max_staged_age: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            pending: DashMap::new(),
            staged: AtomicU64::new(0),
            flush_rows: flush_rows.max(1),
            timer_flush_floor: (flush_rows.max(1) / TIMER_FLOOR_DIVISOR).max(1),
            flush_interval,
            max_staged_age: max_staged_age.max(flush_interval),
            db,
            gate: tokio::sync::Mutex::new(()),
            wake: tokio::sync::Notify::new(),
            flushes: AtomicU64::new(0),
            committed_total: AtomicU64::new(0),
            _spec: std::marker::PhantomData,
        })
    }

    /// Insert one staged entry, keeping `staged` in step with the map.
    fn put(&self, row: S::Row) {
        if self.pending.insert(S::key_of(&row), row).is_none() {
            self.staged.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Stage a row's current state. Never touches the database and never
    /// awaits, so callers on the UI task stay responsive.
    pub fn push(&self, row: S::Row) {
        self.put(row);
        if self.staged_len() >= self.flush_rows {
            self.wake.notify_one();
        }
    }

    /// Remove one staged entry, keeping `staged` in step with the map.
    fn take(&self, key: &S::Key) -> Option<S::Row> {
        let removed = self.pending.remove(key).map(|(_, row)| row);
        if removed.is_some() {
            self.staged.fetch_sub(1, Ordering::Relaxed);
        }
        removed
    }

    /// Drop every staged entry whose key matches `pred`, keeping `staged` in
    /// step with the map. Returns the number of entries dropped.
    ///
    /// The maintenance merge's guard: a patch staged for an endpoint that the
    /// merge is about to DELETE must never reach the flush window — the write
    /// would hit a live-FK error and the failure path would re-stage it,
    /// retrying forever. The caller flushes first, then discards by absorbed
    /// endpoint id, then merges.
    pub fn discard_where<F: Fn(&S::Key) -> bool>(&self, pred: F) -> usize {
        let keys: Vec<S::Key> = self.pending.iter().map(|entry| *entry.key()).collect();
        let mut dropped = 0usize;
        for key in keys {
            if pred(&key) && self.take(&key).is_some() {
                dropped += 1;
            }
        }
        dropped
    }

    /// Take every staged row out of the map, coalesced to one triple per
    /// identity.
    ///
    /// The drain is a **remove**, never a snapshot copy: a `push` that lands
    /// while the flush is writing inserts a fresh entry that the next window
    /// picks up. Removing the key a second time after the write would drop that
    /// state.
    fn drain(&self) -> Vec<Coalesced<S::Key, S::Row, S::Patch>> {
        let keys: Vec<S::Key> = self.pending.iter().map(|entry| *entry.key()).collect();
        let rows: Vec<S::Row> = keys.iter().filter_map(|key| self.take(key)).collect();
        S::coalesce(rows)
    }

    /// Write everything staged so far, in `flush_rows`-sized transactions.
    ///
    /// Called by the flush task, at batch end, and on quit. Returns the number
    /// of rows written.
    ///
    /// A failed transaction re-stages that window **and every window after it**
    /// (the drain already removed them from the pending map): the caller retries
    /// the whole remainder on the next tick. Re-staging only the failing window
    /// would drop the rest of the drained batch — silent loss for any window
    /// wider than one chunk.
    ///
    /// The span is the ATTRIBUTION for every statement this flush issues, so it
    /// carries `target = "db_method"` (the literal `DbMonitorLayer`'s
    /// `on_new_span` gate matches on) and the `retries` field
    /// `retry_on_busy` records into.
    ///
    /// Without it the driver is invisible to the monitor: the tx-scoped
    /// callees (`apply_link_patches_tx`, `set_endpoint_ip_countries_once`)
    /// deliberately carry no span of their own, and the flush runs on a
    /// background task with no enclosing `Database` method — so every
    /// write-behind `toasty::query` event landed in the `unattributed`
    /// bucket and the public `apply_link_patches` /
    /// `set_endpoint_ip_countries` rows read zero in production.
    #[tracing::instrument(
        target = "db_method",
        name = "write_behind_flush",
        skip_all,
        fields(retries = tracing::field::Empty)
    )]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the transaction must hold the connection guard across its window, refresh and commit; dropping the guard early would release the transaction before COMMIT"
    )]
    pub async fn flush(&self) -> crate::Result<usize> {
        let _guard = self.gate.lock().await;
        let drained = self.drain();
        if drained.is_empty() {
            return Ok(0);
        }
        // Split the triples into the patches the write path consumes and the
        // (key, row) pairs the failure path re-stages. The two vectors stay
        // index-aligned, so chunk `i` of `patches` corresponds to `rows`
        // starting at `i * flush_rows`.
        let mut patches = Vec::with_capacity(drained.len());
        let mut rows = Vec::with_capacity(drained.len());
        for entry in drained {
            patches.push(entry.patch);
            rows.push((entry.key, entry.row));
        }

        let mut written = 0usize;
        for (index, chunk) in patches.chunks(self.flush_rows).enumerate() {
            let db = Arc::clone(&self.db);
            let result = crate::retry_on_busy(
                move || {
                    let db = Arc::clone(&db);
                    async move {
                        let mut conn = db.connection().await?;
                        let mut tx = conn.transaction().await?;
                        let n = S::write_window(&mut tx, chunk).await?;
                        S::refresh(&mut tx, chunk).await?;
                        tx.commit().await?;
                        Ok::<usize, crate::DatabaseError>(n)
                    }
                },
                5,
            )
            .await;
            match result {
                Ok(n) => {
                    written += n;
                    // Recorded HERE, not on the success return, so the windows
                    // a later failure discards are still counted — see
                    // [`Self::committed_total`].
                    self.committed_total
                        .fetch_add(usize_to_u64(n), Ordering::Relaxed);
                    self.flushes.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    // Re-stage the failing window AND every later window. A row
                    // pushed while this flush was writing already holds a NEWER
                    // snapshot than the drained one, so re-stage leaves it
                    // alone — see [`Self::restage`].
                    self.restage(&rows[index * self.flush_rows..]);
                    return Err(err);
                }
            }
        }
        Ok(written)
    }

    /// Re-insert drained rows that a failed flush did not write.
    ///
    /// The drain REMOVED them from `pending`, so a row still absent is put back
    /// and counted. A key that was pushed again while the flush was writing is
    /// already [`Entry::Occupied`] with a **newer** snapshot than the drained
    /// one — overwriting it would roll the row back and could re-write a value
    /// the caller has since replaced, so it is left untouched.
    ///
    /// One row may expand into several entries — see
    /// [`CacheSpec::restage_entries`].
    fn restage(&self, rows: &[(S::Key, S::Row)]) {
        for (key, row) in rows.iter().flat_map(|(_, row)| S::restage_entries(row)) {
            match self.pending.entry(key) {
                Entry::Occupied(_) => {}
                Entry::Vacant(slot) => {
                    slot.insert(row);
                    self.staged.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// The snapshot currently staged under `key`, if any.
    ///
    /// A read-through view of the pending map, for a caller that must see a
    /// staged row BEFORE it is committed. Never awaits: it is a single
    /// `DashMap` read (one shard, one hash), which is what makes it safe on
    /// the UI task — the same reason [`Self::push`] does not await either.
    #[must_use]
    pub fn get(&self, key: &S::Key) -> Option<S::Row> {
        self.pending.get(key).map(|entry| entry.value().clone())
    }

    /// Number of staged entries.
    #[must_use]
    pub fn staged_len(&self) -> usize {
        usize::try_from(self.staged.load(Ordering::Relaxed)).unwrap_or(usize::MAX)
    }

    /// Transactions performed so far.
    #[must_use]
    pub fn flush_count(&self) -> u64 {
        self.flushes.load(Ordering::Relaxed)
    }

    /// Rows this driver has committed, counting the windows of a flush that
    /// went on to fail.
    ///
    /// [`Self::flush`] returns `Err` for a flush that committed some windows
    /// and then failed, and its retry writes only the re-staged remainder — so
    /// neither the `Err` nor the retry's `Ok` accounts for the windows in
    /// between. A caller that must report an exact stored count takes the DELTA
    /// of this counter across its whole flush sequence instead:
    ///
    /// ```ignore
    /// let before = driver.committed_total();
    /// let _ = driver.flush().await;             // Err, or Ok
    /// let stored = driver.committed_total() - before;
    /// ```
    ///
    /// A row is counted only when its transaction commits, so the delta never
    /// double-counts a window a retry re-writes.
    #[must_use]
    pub fn committed_total(&self) -> u64 {
        self.committed_total.load(Ordering::Relaxed)
    }

    /// Wake the flush task so it writes on its next loop iteration.
    ///
    /// This is how a **single, user-initiated** row gets prompt persistence
    /// without a commit on the caller's task: it is far below
    /// [`Self::timer_flush_floor`], so the timer path would otherwise hold it
    /// until [`Self::max_staged_age`]. The loop's size-trigger arm always
    /// writes, so a notification is enough.
    pub fn flush_soon(&self) {
        self.wake.notify_one();
    }

    /// Rows a bare timer tick needs staged before it writes.
    #[must_use]
    pub const fn timer_flush_floor(&self) -> usize {
        self.timer_flush_floor
    }

    /// Ceiling on how long a staged row may sit unpersisted.
    #[must_use]
    pub const fn max_staged_age(&self) -> Duration {
        self.max_staged_age
    }

    /// The flush decision as a pure function — no `self`, no clock, no runtime,
    /// no database.
    ///
    /// Extracted so the RULE is testable deterministically. The loop itself is
    /// a real-time race against real DB transactions: under full-suite load it
    /// can miss a tick and observe one floor crossing where two were expected —
    /// a flaky integration test, not a floor bug. This function carries the
    /// contract; the loop carries the plumbing.
    ///
    /// - `woken` — the size trigger or an explicit [`Self::flush_soon`]. Always
    ///   writes, at any depth: it is an explicit "there is a full window" signal.
    /// - `staged >= floor` — the timer path's coalescing rule.
    /// - `stale` — `max_staged_age` elapsed since the last write. The net for a
    ///   trickle too slow to ever reach the floor, so a row is never stranded.
    #[must_use]
    pub const fn should_flush(floor: usize, woken: bool, staged: usize, stale: bool) -> bool {
        woken || staged >= floor || stale
    }

    /// Run the flush loop until the handle is dropped/aborted.
    ///
    /// Two triggers, deliberately asymmetric:
    ///
    /// * **Size trigger** (`wake`, fired by [`Self::push`] at `flush_rows`) —
    ///   always writes. It is an explicit "there is a full window" signal.
    /// * **Timer tick** — writes once `timer_flush_floor` rows are staged, or
    ///   once `max_staged_age` has elapsed since the last write. The floor
    ///   decides how much a transaction carries; the deadline is only the net
    ///   for a trickle too slow to ever reach the floor.
    pub async fn run(self: Arc<Self>) {
        let mut since_write = tokio::time::Instant::now();
        loop {
            let woken = tokio::select! {
                () = self.wake.notified() => true,
                () = tokio::time::sleep(self.flush_interval) => false,
            };
            let staged = self.staged_len();
            if staged == 0 {
                since_write = tokio::time::Instant::now();
                continue;
            }
            let stale = since_write.elapsed() >= self.max_staged_age;
            if !Self::should_flush(self.timer_flush_floor, woken, staged, stale) {
                continue;
            }
            let written = match self.flush().await {
                Ok(n) => n,
                Err(err) => {
                    tracing::warn!(target: "leas_db", "write-behind flush failed: {err}");
                    0
                }
            };
            // A failed flush does NOT reset the clock, so a busy database is
            // retried on the deadline rather than spinning on every tick.
            if written > 0 {
                since_write = tokio::time::Instant::now();
            }
        }
    }

    /// Spawn [`Self::run`] as a background task.
    #[must_use]
    pub fn spawn_flush_task(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let driver = Arc::clone(self);
        tokio::spawn(driver.run())
    }
}

/// A row count as the counter's width. A count that does not fit is a bug, not
/// a runtime condition, so the counter saturates rather than wrapping — a wrap
/// would report a negative delta to the caller taking it.
fn usize_to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// One staged country write: the endpoint, the address its country belongs to,
/// and the ISO code.
///
/// The staging identity is the ENDPOINT, not the address: the queue this
/// replaced keyed `endpoint_id → (ip, iso)` and an insert overwrote, so a
/// second resolution of the same endpoint replaced the first. That is
/// [`CountrySpec`]'s coalesce rule.
#[derive(Debug, Clone)]
pub struct CountryRow {
    /// The endpoint whose address carries the country.
    pub endpoint_id: crate::models_toasty::EndpointId,
    /// The resolved address the country belongs to.
    pub ip: std::net::IpAddr,
    /// ISO 3166-1 alpha-2 code from mmdb.
    pub iso: String,
}

/// The write side of a country row: 1:1 with [`CountryRow`], so the patch IS
/// the row.
///
/// Kept as its own type because the driver hands the write path a patch slice
/// and the re-stage path the row — the shapes must not be able to drift apart
/// by accident.
#[derive(Debug, Clone)]
pub struct CountryPatch {
    /// The endpoint whose address carries the country.
    pub endpoint_id: crate::models_toasty::EndpointId,
    /// The resolved address the country belongs to.
    pub ip: std::net::IpAddr,
    /// ISO 3166-1 alpha-2 code from mmdb.
    pub iso: String,
}

/// The write-behind spec for resolved-address countries (`endpoint_ip.country`).
///
/// The first migrated table, and the simplest: one upsert per row, no derived
/// state. `refresh` is a no-op because a country write touches `endpoint_ip`
/// only — rank keys are a function of an endpoint's links and protocols, not of
/// which country its address resolved to.
pub struct CountrySpec;

impl CacheSpec for CountrySpec {
    type Key = crate::models_toasty::EndpointId;
    type Row = CountryRow;
    type Patch = CountryPatch;

    fn key_of(row: &Self::Row) -> Self::Key {
        row.endpoint_id
    }

    fn coalesce(rows: Vec<Self::Row>) -> Vec<Coalesced<Self::Key, Self::Row, Self::Patch>> {
        // Last-writer-wins per endpoint, first-seen order preserved: the queue's
        // `DashMap::insert` overwrote an existing entry in place, and its key
        // order is not part of any contract.
        let mut latest: HashMap<Self::Key, CountryRow> = HashMap::new();
        let mut order: Vec<Self::Key> = Vec::new();
        for row in rows {
            let key = row.endpoint_id;
            if latest.insert(key, row).is_none() {
                order.push(key);
            }
        }
        order
            .into_iter()
            .filter_map(|key| {
                let row = latest.remove(&key)?;
                let patch = CountryPatch {
                    endpoint_id: row.endpoint_id,
                    ip: row.ip,
                    iso: row.iso.clone(),
                };
                Some(Coalesced { key, row, patch })
            })
            .collect()
    }

    async fn write_window<'a>(
        tx: &'a mut impl toasty::Executor,
        patches: &'a [Self::Patch],
    ) -> crate::Result<usize> {
        if patches.is_empty() {
            return Ok(0);
        }
        let rows: Vec<(crate::models_toasty::EndpointId, std::net::IpAddr, String)> = patches
            .iter()
            .map(|patch| (patch.endpoint_id, patch.ip, patch.iso.clone()))
            .collect();
        crate::database::set_endpoint_ip_countries_once(tx, &rows).await?;
        Ok(patches.len())
    }

    // The trait mandates a future; a country write derives nothing, so the
    // async-ness is the contract, not a bug.
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "trait-mandated async signature"
    )]
    async fn refresh<'a>(
        _tx: &'a mut impl toasty::Executor,
        _patches: &'a [Self::Patch],
    ) -> crate::Result<()> {
        Ok(())
    }
}

/// One staged import batch: all four row families a parse produced, under one
/// monotonic sequence number.
///
/// The identity is the BATCH, not the row: an import window is atomic in one
/// transaction, and a row-level key would let a later batch overwrite a
/// still-pending earlier one (whose rows would then never be written). Callers
/// mint `seq` from an `AtomicU64`, so every staged batch is its own pending
/// entry and nothing is lost.
#[derive(Debug, Clone)]
pub struct SourceBatch {
    /// Monotonic batch id — the pending-map key.
    pub seq: u64,
    /// `endpoints` rows parsed from this batch.
    pub endpoints: Vec<crate::models_toasty::Endpoint>,
    /// `protocols` rows parsed from this batch.
    pub protocols: Vec<crate::models_toasty::Protocol>,
    /// `profile_stats` rows parsed from this batch.
    pub links: Vec<crate::models_toasty::ProfileStats>,
    /// `endpoint_groups` rows parsed from this batch.
    pub group_links: Vec<crate::models_toasty::EndpointGroup>,
    /// IP-literal endpoints in this batch: `(endpoint, its literal address)`.
    /// With `endpoints.host` gone (db-rewamp D10) the literal's ONLY home is
    /// `endpoint_ip`, so the import writes it here alongside the row.
    pub ip_literals: Vec<(crate::models_toasty::EndpointId, std::net::IpAddr)>,
}

/// The write side of an import batch: 1:1 with [`SourceBatch`], so the patch IS
/// the row.
///
/// Same split as [`CountryPatch`], for the same reason (the driver hands the
/// write path a patch slice and the failure path the row).
#[derive(Debug, Clone)]
pub struct SourcePatch {
    /// Monotonic batch id.
    pub seq: u64,
    /// `endpoints` rows to upsert.
    pub endpoints: Vec<crate::models_toasty::Endpoint>,
    /// `protocols` rows to upsert.
    pub protocols: Vec<crate::models_toasty::Protocol>,
    /// `profile_stats` rows to upsert.
    pub links: Vec<crate::models_toasty::ProfileStats>,
    /// `endpoint_groups` rows to upsert.
    pub group_links: Vec<crate::models_toasty::EndpointGroup>,
    /// IP-literal endpoints to write into `endpoint_ip` (db-rewamp D10).
    pub ip_literals: Vec<(crate::models_toasty::EndpointId, std::net::IpAddr)>,
}

impl From<&SourceBatch> for SourcePatch {
    fn from(batch: &SourceBatch) -> Self {
        Self {
            seq: batch.seq,
            endpoints: batch.endpoints.clone(),
            protocols: batch.protocols.clone(),
            links: batch.links.clone(),
            group_links: batch.group_links.clone(),
            ip_literals: batch.ip_literals.clone(),
        }
    }
}

/// The write-behind spec for the subscription/import bulk path.
///
/// ONE driver, not four: today's persist issues
/// `upsert_endpoints_bulk` / `upsert_protocols_bulk` / `upsert_links_bulk` /
/// `upsert_endpoint_group_links_bulk` in a SINGLE transaction, and this
/// driver's `write_window` runs all four in the transaction IT opened. So a
/// committed window never contains an endpoint without its link — the
/// linkless-endpoint state a per-table driver would produce is only ever the
/// one the input batch itself contains.
pub struct SourceSpec;

impl CacheSpec for SourceSpec {
    type Key = u64;
    type Row = SourceBatch;
    type Patch = SourcePatch;

    fn key_of(row: &Self::Row) -> Self::Key {
        row.seq
    }

    fn coalesce(rows: Vec<Self::Row>) -> Vec<Coalesced<Self::Key, Self::Row, Self::Patch>> {
        // Identity: every batch carries its own unique `seq`, so nothing is
        // merged and drain order is preserved.
        rows.into_iter()
            .map(|row| {
                let key = row.seq;
                let patch = SourcePatch::from(&row);
                Coalesced { key, row, patch }
            })
            .collect()
    }

    /// Write every family in the window on the driver's transaction, and
    /// report the LINK rows written — the count the import outcome reports.
    async fn write_window<'a>(
        tx: &'a mut impl toasty::Executor,
        patches: &'a [Self::Patch],
    ) -> crate::Result<usize> {
        if patches.is_empty() {
            return Ok(0);
        }
        let mut endpoints = Vec::new();
        let mut protocols = Vec::new();
        let mut links = Vec::new();
        let mut group_links = Vec::new();
        let mut ip_literals = Vec::new();
        for patch in patches {
            endpoints.extend_from_slice(&patch.endpoints);
            protocols.extend_from_slice(&patch.protocols);
            links.extend_from_slice(&patch.links);
            group_links.extend_from_slice(&patch.group_links);
            ip_literals.extend_from_slice(&patch.ip_literals);
        }
        let stored_links = links.len();
        crate::database::upsert_endpoints_bulk(tx, &endpoints).await?;
        crate::database::upsert_protocols_bulk(tx, &protocols).await?;
        crate::database::upsert_links_bulk(tx, &links).await?;
        crate::database::upsert_endpoint_group_links_bulk(tx, &group_links).await?;
        crate::endpoint_ip::insert_literals_bulk(tx, &ip_literals).await?;
        Ok(stored_links)
    }

    /// Nothing to do: `upsert_links_bulk` already calls `endpoint_rank::refresh`
    /// for the endpoints it touched, inside this same transaction — so the rank
    /// keys are already atomic with the write, and a second refresh here would
    /// double the import's per-window cost for the same result.
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "trait-mandated async signature"
    )]
    async fn refresh<'a>(
        _tx: &'a mut impl toasty::Executor,
        _patches: &'a [Self::Patch],
    ) -> crate::Result<()> {
        Ok(())
    }
}

/// The pending-map key of a staged link row: the link, plus the ONE column
/// group the row carries.
///
/// The group is part of the key, not just the patch: `profile_stats` has three
/// independent writers (ping results, the traffic poller, the classifier), and
/// keying on the link alone would let a traffic tick overwrite the result
/// staged a millisecond earlier. One entry per `(link, group)` is what makes
/// the disjointness the write already relies on visible in the staging map.
pub type LinkStageKey = (
    crate::models_toasty::ProtocolId,
    crate::models_toasty::EndpointId,
    crate::LinkGroups,
);

/// One staged link snapshot, for one column group (or for the union of them,
/// after a failed flush re-staged a merged patch).
#[derive(Debug, Clone)]
pub struct LinkRow {
    /// The caller's snapshot of the `profile_stats` row.
    pub link: crate::models_toasty::ProfileStats,
    /// The column groups this snapshot is authoritative for.
    pub groups: crate::LinkGroups,
}

/// Fold one staged column group onto `base`.
///
/// The groups are disjoint by construction, so the order they are applied in
/// never matters: RESULT owns latency/speed/error, PURGE the verdict, TRAFFIC
/// the four counters.
fn merge_group(
    base: &mut crate::models_toasty::ProfileStats,
    flag: crate::LinkGroups,
    staged: &crate::models_toasty::ProfileStats,
) {
    use crate::LinkGroups;
    // An EXPLICIT arm per group — no catch-all `else`. A catch-all silently
    // routed a newly added group into whichever arm it fell through to, which
    // for a fourth bit writes TRAFFIC columns from a STAB snapshot (the
    // disjointness these groups exist to guarantee).
    if flag == LinkGroups::RESULT {
        base.latency.clone_from(&staged.latency);
        base.speed_bps = staged.speed_bps;
        base.error.clone_from(&staged.error);
    } else if flag == LinkGroups::PURGE {
        base.purge_reason = staged.purge_reason;
    } else if flag == LinkGroups::TRAFFIC {
        base.traffic = staged.traffic;
    } else if flag == LinkGroups::STAB {
        base.stab_mask = staged.stab_mask;
        base.stab_len = staged.stab_len;
    }
}

/// The write-behind spec for `profile_stats` — the per-link result, verdict and
/// traffic patches.
///
/// One patch per link per flush: the map holds one entry per `(link, group)`,
/// so a link touched by a result, its traffic poll and the gate's transition
/// would otherwise be written three times. `coalesce` folds those entries into
/// ONE patch carrying the union of their groups, with the same overlay
/// [`merge_group`] applies, so the two writers stay disjoint.
///
/// The staging key is per `(link, group)` while the patch is per link, so a
/// re-staged merged row carries the union — see [`LinkSpec::coalesce`], which
/// reads a union bit as "this snapshot is authoritative for that group".
pub struct LinkSpec;

impl CacheSpec for LinkSpec {
    type Key = LinkStageKey;
    type Row = LinkRow;
    type Patch = crate::LinkPatch;

    fn key_of(row: &Self::Row) -> Self::Key {
        (row.link.protocol_id, row.link.endpoint_id, row.groups)
    }

    /// The old `LinkWriter::drain` merge, verbatim: one patch per link, the
    /// union of its staged groups, and the merged snapshot carrying every
    /// column those groups own.
    ///
    /// A re-staged row holds a union of groups and ONE snapshot that is
    /// already the merge of its per-group sources, so each bit it carries is
    /// overlaid from that same snapshot — which is exactly what the per-group
    /// rows it replaced would have contributed.
    fn coalesce(rows: Vec<Self::Row>) -> Vec<Coalesced<Self::Key, Self::Row, Self::Patch>> {
        use crate::LinkGroups;
        let mut order: Vec<(
            crate::models_toasty::ProtocolId,
            crate::models_toasty::EndpointId,
        )> = Vec::new();
        let mut merged: HashMap<
            (
                crate::models_toasty::ProtocolId,
                crate::models_toasty::EndpointId,
            ),
            (crate::LinkGroups, crate::models_toasty::ProfileStats),
        > = HashMap::new();
        for row in rows {
            let link_key = (row.link.protocol_id, row.link.endpoint_id);
            match merged.entry(link_key) {
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    let (groups, base) = slot.get_mut();
                    for flag in [
                        LinkGroups::RESULT,
                        LinkGroups::PURGE,
                        LinkGroups::TRAFFIC,
                        LinkGroups::STAB,
                    ] {
                        if row.groups.contains(flag) {
                            merge_group(base, flag, &row.link);
                        }
                    }
                    *groups = groups.union(row.groups);
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    let mut link = row.link.clone();
                    for flag in [
                        LinkGroups::RESULT,
                        LinkGroups::PURGE,
                        LinkGroups::TRAFFIC,
                        LinkGroups::STAB,
                    ] {
                        if row.groups.contains(flag) {
                            merge_group(&mut link, flag, &row.link);
                        }
                    }
                    order.push(link_key);
                    slot.insert((row.groups, link));
                }
            }
        }

        order
            .into_iter()
            .filter_map(|link_key| {
                let (groups, link) = merged.remove(&link_key)?;
                Some(Coalesced {
                    key: (link_key.0, link_key.1, groups),
                    row: LinkRow {
                        link: link.clone(),
                        groups,
                    },
                    patch: crate::LinkPatch { link, groups },
                })
            })
            .collect()
    }

    /// Re-stage a merged row as ONE ENTRY PER FLAG.
    ///
    /// The default would re-stage under the union key — a key neither
    /// [`WriteBehind::<LinkSpec>::stage`] nor [`Self::key_of`] ever produces,
    /// so the retry would write nothing and the drained results would be lost.
    /// Per-flag entries are addressable again, which is the whole reason the
    /// staging key is finer than the patch identity.
    fn restage_entries(row: &Self::Row) -> Vec<(Self::Key, Self::Row)> {
        use crate::LinkGroups;
        [
            LinkGroups::RESULT,
            LinkGroups::PURGE,
            LinkGroups::TRAFFIC,
            LinkGroups::STAB,
        ]
        .into_iter()
        .filter(|flag| row.groups.contains(*flag))
        .map(|flag| {
            let single = LinkRow {
                link: row.link.clone(),
                groups: flag,
            };
            (Self::key_of(&single), single)
        })
        .collect()
    }

    /// The chunked upsert of [`Database::apply_link_patches`], on the driver's
    /// transaction: this is `apply_link_patches_tx`, so the driver owns the
    /// commit and the retry.
    async fn write_window<'a>(
        tx: &'a mut impl toasty::Executor,
        patches: &'a [Self::Patch],
    ) -> crate::Result<usize> {
        if patches.is_empty() {
            return Ok(0);
        }
        crate::database::Database::apply_link_patches_tx(
            tx,
            patches,
            crate::models_toasty::now_epoch(),
        )
        .await
    }

    /// Refresh the ordering keys of every endpoint a window touched.
    ///
    /// NOT a no-op, unlike [`SourceSpec::refresh`]: `apply_link_patches_once`
    /// refreshed rank AFTER its commit, on a separate connection, and only
    /// logged a failure. The driver calls `refresh` on the transaction it is
    /// about to commit, so the rank keys become ATOMIC with the write that
    /// invalidated them — a reader can no longer observe a link with stale
    /// keys, and a refresh that fails now fails the window instead of being
    /// swallowed.
    async fn refresh<'a>(
        tx: &'a mut impl toasty::Executor,
        patches: &'a [Self::Patch],
    ) -> crate::Result<()> {
        let mut touched: Vec<crate::models_toasty::EndpointId> =
            patches.iter().map(|p| p.link.endpoint_id).collect();
        touched.sort_unstable();
        touched.dedup();
        crate::endpoint_rank::refresh(tx, &touched).await?;
        Ok(())
    }
}

impl WriteBehind<LinkSpec> {
    /// Stage a link's current snapshot for `groups`.
    ///
    /// Never touches the database and never awaits, so callers on the UI task
    /// stay responsive. `groups` is normalised to one entry per flag, so a
    /// stage of `ALL` and a later stage of `RESULT` do not shadow each other.
    pub fn stage(&self, link: &crate::models_toasty::ProfileStats, groups: crate::LinkGroups) {
        use crate::LinkGroups;
        for flag in [
            LinkGroups::RESULT,
            LinkGroups::PURGE,
            LinkGroups::TRAFFIC,
            LinkGroups::STAB,
        ] {
            if groups.contains(flag) {
                self.push(LinkRow {
                    link: link.clone(),
                    groups: flag,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::{CacheSpec, Coalesced, WriteBehind};
    use crate::models_toasty::EndpointId;
    use crate::{CountryRow, CountrySpec};

    /// A fake spec backed by a real in-memory table: `write_window` runs one
    /// upsert per patch on the driver's transaction, `refresh` is a no-op.
    ///
    /// A patch with a negative value is a deterministic, NON-busy failure (so
    /// `retry_on_busy` does not retry it), which is how the re-stage path is
    /// exercised without holding a write lock for the retry backoff.
    struct FakeSpec;

    #[derive(Debug, Clone)]
    struct FakeRow {
        key: i64,
        value: i64,
    }

    #[derive(Debug, Clone)]
    struct FakePatch {
        key: i64,
        value: i64,
    }

    impl CacheSpec for FakeSpec {
        type Key = i64;
        type Row = FakeRow;
        type Patch = FakePatch;

        fn key_of(row: &Self::Row) -> Self::Key {
            row.key
        }

        fn coalesce(rows: Vec<Self::Row>) -> Vec<Coalesced<Self::Key, Self::Row, Self::Patch>> {
            // Last-writer-wins per key, preserving first-seen order.
            let mut map = HashMap::new();
            let mut order = Vec::new();
            for row in rows {
                if !map.contains_key(&row.key) {
                    order.push(row.key);
                }
                map.insert(row.key, row);
            }
            order
                .into_iter()
                .map(|key| {
                    let row = map.remove(&key).expect("key was just inserted");
                    let patch = FakePatch {
                        key: row.key,
                        value: row.value,
                    };
                    Coalesced { key, row, patch }
                })
                .collect()
        }

        async fn write_window<'a>(
            tx: &'a mut impl toasty::Executor,
            patches: &'a [Self::Patch],
        ) -> crate::Result<usize> {
            if let Some(poison) = patches.iter().find(|patch| patch.value < 0) {
                return Err(crate::DatabaseError::Generic(format!(
                    "injected failure at key {}",
                    poison.key
                )));
            }
            for patch in patches {
                toasty::sql::query(format!(
                    "INSERT INTO fake_state(key, value) VALUES ({}, {}) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    patch.key, patch.value
                ))
                .exec(&mut *tx)
                .await?;
            }
            Ok(patches.len())
        }

        // The trait mandates a future; a spec with no derived state has nothing
        // to await, so the async-ness is the contract, not a bug.
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "trait-mandated async signature"
        )]
        async fn refresh<'a>(
            _tx: &'a mut impl toasty::Executor,
            _patches: &'a [Self::Patch],
        ) -> crate::Result<()> {
            Ok(())
        }
    }

    /// How many `write_window` calls [`FailingWindowSpec`] has seen.
    ///
    /// The spec hooks are associated functions — the driver holds only a
    /// `PhantomData` — so the ordinal cannot live in the spec VALUE and lives
    /// in a test-local static instead.
    static WINDOW_CALLS: AtomicUsize = AtomicUsize::new(0);
    /// The ordinal [`FailingWindowSpec`] fails on.
    static FAIL_AT: AtomicUsize = AtomicUsize::new(1);

    /// A spec whose Nth `write_window` call fails, so the windows AROUND a
    /// mid-flush failure are deterministic: the failure is keyed to the window
    /// ordinal, not to row contents (whose drain order is not a contract).
    ///
    /// The error is a plain `Generic`, so `retry_on_busy` returns it at once and
    /// the window ordinal advances exactly once per flush attempt.
    struct FailingWindowSpec;

    #[derive(Debug, Clone)]
    struct WindowPatch {
        key: i64,
    }

    impl CacheSpec for FailingWindowSpec {
        type Key = i64;
        type Row = i64;
        type Patch = WindowPatch;

        fn key_of(row: &Self::Row) -> Self::Key {
            *row
        }

        fn coalesce(rows: Vec<Self::Row>) -> Vec<Coalesced<Self::Key, Self::Row, Self::Patch>> {
            rows.into_iter()
                .map(|key| Coalesced {
                    key,
                    row: key,
                    patch: WindowPatch { key },
                })
                .collect()
        }

        async fn write_window<'a>(
            tx: &'a mut impl toasty::Executor,
            patches: &'a [Self::Patch],
        ) -> crate::Result<usize> {
            let ordinal = WINDOW_CALLS.fetch_add(1, Ordering::Relaxed);
            if ordinal == FAIL_AT.load(Ordering::Relaxed) {
                return Err(crate::DatabaseError::Generic(format!(
                    "injected failure on window {ordinal}"
                )));
            }
            for patch in patches {
                toasty::sql::query(format!(
                    "INSERT INTO fake_state(key, value) VALUES ({}, 1) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    patch.key
                ))
                .exec(&mut *tx)
                .await?;
            }
            Ok(patches.len())
        }

        // The trait mandates a future; this spec derives nothing to await.
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "trait-mandated async signature"
        )]
        async fn refresh<'a>(
            _tx: &'a mut impl toasty::Executor,
            _patches: &'a [Self::Patch],
        ) -> crate::Result<()> {
            Ok(())
        }
    }

    /// `discard_where` removes only matching staged entries and keeps the
    /// `staged` counter in step — the maintenance merge's guard against a
    /// staged patch outliving its (deleted) endpoint row.
    #[tokio::test]
    async fn discard_where_drops_only_matching_keys() {
        let db = fake_db().await;
        let driver: Arc<WriteBehind<FailingWindowSpec>> = WriteBehind::new_with_deadline(
            Arc::clone(&db),
            100,
            Duration::from_millis(200),
            Duration::from_millis(200),
        );
        driver.push(1);
        driver.push(2);
        driver.push(3);
        assert_eq!(driver.staged_len(), 3);

        assert_eq!(driver.discard_where(|key| *key == 2), 1);
        assert_eq!(driver.staged_len(), 2);
        assert!(driver.get(&2).is_none(), "matching entry gone");
        assert!(driver.get(&1).is_some(), "non-matching entry survives");
        assert!(driver.get(&3).is_some(), "non-matching entry survives");
        // An idempotent re-run drops nothing.
        assert_eq!(driver.discard_where(|key| *key == 2), 0);
    }

    /// A flush that commits windows 1..k and fails on k+1 returns `Err`, and the
    /// committed count is NOT in that error — so a caller reconciling
    /// "parsed vs stored" from the `Ok` values alone counts the stored rows as
    /// lost. `committed_total` is what carries them across the failure.
    #[tokio::test]
    async fn committed_total_keeps_the_windows_a_failed_flush_discards() {
        WINDOW_CALLS.store(0, Ordering::Relaxed);
        FAIL_AT.store(1, Ordering::Relaxed);

        let db = fake_db().await;
        // flush_rows = 2, so six staged rows are three windows.
        let driver: Arc<WriteBehind<FailingWindowSpec>> = WriteBehind::new_with_deadline(
            Arc::clone(&db),
            2,
            Duration::from_millis(200),
            Duration::from_millis(200),
        );
        for key in 1..=6 {
            driver.push(key);
        }

        assert_eq!(driver.staged_len(), 6);
        assert_eq!(
            driver.committed_total(),
            0,
            "nothing is committed before the first flush"
        );

        assert!(
            driver.flush().await.is_err(),
            "the second window fails, so the flush must report Err"
        );
        assert_eq!(
            driver.committed_total(),
            2,
            "the FIRST window committed, and the Err must not hide it"
        );
        assert_eq!(
            driver.staged_len(),
            4,
            "the failing window and every later one are re-staged"
        );

        // The retry drains the re-staged remainder, so both remaining windows
        // write: the counter moves by exactly what that attempt committed.
        let before_retry = driver.committed_total();
        assert_eq!(driver.flush().await.expect("retry writes the remainder"), 4);
        assert_eq!(driver.committed_total(), 6);
        assert_eq!(driver.committed_total() - before_retry, 4);
        assert_eq!(driver.staged_len(), 0, "the remainder is drained");
    }

    fn row(key: i64, value: i64) -> FakeRow {
        FakeRow { key, value }
    }

    async fn fake_db() -> Arc<crate::Database> {
        let db = Arc::new(crate::Database::in_memory().await.expect("in-memory db"));
        let mut conn = db.connection().await.expect("conn");
        toasty::sql::statement(
            "CREATE TABLE IF NOT EXISTS fake_state \
             (key INTEGER PRIMARY KEY, value INTEGER NOT NULL)",
        )
        .exec(&mut conn)
        .await
        .expect("create fake_state");
        db
    }

    async fn stored(db: &crate::Database) -> HashMap<i64, i64> {
        let mut conn = db.connection().await.expect("conn");
        let rows = toasty::sql::query("SELECT key, value FROM fake_state")
            .exec(&mut conn)
            .await
            .expect("read fake_state");
        rows.iter()
            .filter_map(|value| match value {
                toasty::stmt::Value::Record(fields) => match (fields.first(), fields.get(1)) {
                    (
                        Some(toasty::stmt::Value::I64(key)),
                        Some(toasty::stmt::Value::I64(value)),
                    ) => Some((*key, *value)),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    #[test]
    fn should_flush_truth_table() {
        // woken always writes
        assert!(WriteBehind::<FakeSpec>::should_flush(128, true, 0, false));
        // timer floor
        assert!(WriteBehind::<FakeSpec>::should_flush(
            128, false, 128, false
        ));
        assert!(!WriteBehind::<FakeSpec>::should_flush(
            128, false, 127, false
        ));
        // staleness net
        assert!(WriteBehind::<FakeSpec>::should_flush(128, false, 1, true));
        // nothing staged, not woken, not stale
        assert!(!WriteBehind::<FakeSpec>::should_flush(128, false, 0, false));
    }

    /// The coalesce rule is last-writer-wins per key, and `flush` reports the
    /// rows written.
    #[tokio::test]
    async fn push_coalesces_and_flushes() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));

        driver.push(row(1, 10));
        driver.push(row(1, 20)); // replaces the row above
        driver.push(row(2, 30));
        assert_eq!(driver.staged_len(), 2, "one entry per key");

        assert_eq!(driver.flush().await.expect("flush"), 2);
        assert_eq!(driver.flush_count(), 1, "one transaction per window");
        assert_eq!(driver.staged_len(), 0);

        let stored = stored(&db).await;
        assert_eq!(stored.get(&1), Some(&20), "last writer wins");
        assert_eq!(stored.get(&2), Some(&30));
    }

    /// Flushing an empty driver is a no-op that opens no transaction.
    #[tokio::test]
    async fn flush_with_nothing_staged_is_a_noop() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));
        assert_eq!(driver.flush().await.expect("flush"), 0);
        assert_eq!(driver.flush_count(), 0);
    }

    /// The default deadline is a multiple of the tick, which is the wrong
    /// contract for a table that promises a seconds-long loss window: 75 ticks
    /// of 5 s is 375 s.
    #[tokio::test]
    async fn the_default_deadline_is_the_tick_times_the_tick_budget() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new(Arc::clone(&db), 512, Duration::from_secs(5));
        assert_eq!(
            driver.max_staged_age(),
            Duration::from_secs(5) * super::MAX_STAGED_AGE_TICKS,
        );
    }

    /// Naming the deadline keeps the durability contract at the call site, and
    /// it is what the country driver uses: a 15 s ceiling under a 5 s tick,
    /// three ticks rather than seventy-five.
    #[tokio::test]
    async fn an_explicit_deadline_is_kept_verbatim() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new_with_deadline(
            Arc::clone(&db),
            256,
            Duration::from_secs(5),
            Duration::from_secs(15),
        );
        assert_eq!(driver.max_staged_age(), Duration::from_secs(15));
        assert_eq!(
            driver.timer_flush_floor(),
            64,
            "the floor is still a quarter of the window, deadline or not",
        );
    }

    /// A deadline shorter than the tick would otherwise be unreachable — the
    /// loop only observes the clock once per tick — so it degrades to "write
    /// every tick", which is the tightest window the cadence can express.
    #[tokio::test]
    async fn a_deadline_shorter_than_the_tick_clamps_to_one_tick() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new_with_deadline(
            Arc::clone(&db),
            256,
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        assert_eq!(driver.max_staged_age(), Duration::from_secs(5));
    }

    /// A flush wider than `flush_rows` becomes one transaction per chunk.
    #[tokio::test]
    async fn flush_chunks_at_flush_rows() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new(Arc::clone(&db), 1, Duration::from_millis(200));
        for key in 1..=3 {
            driver.push(row(key, key * 10));
        }
        assert_eq!(driver.flush().await.expect("flush"), 3);
        assert_eq!(driver.flush_count(), 3, "one transaction per chunk");
    }

    /// A failed window re-stages that window AND every later one: the drain
    /// already removed them, so re-staging only the failing window would drop
    /// the rest of the batch.
    ///
    /// Windows are drained in `DashMap` order, so the failing window's index —
    /// and therefore how many windows were written before it — is not fixed.
    /// The invariant under test is order-independent: **nothing is lost** — every
    /// drained row is either persisted or re-staged — and the retry lands the
    /// whole remainder.
    #[tokio::test]
    async fn a_failed_window_restages_the_whole_remainder() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new(Arc::clone(&db), 1, Duration::from_millis(200));

        driver.push(row(1, -1)); // poison: its window fails
        driver.push(row(2, 2));
        driver.push(row(3, 3));
        assert!(driver.flush().await.is_err(), "the poison patch fails");

        let persisted = stored(&db).await;
        assert_eq!(
            persisted.len() + driver.staged_len(),
            3,
            "every row is either persisted or re-staged — none is lost"
        );
        assert!(
            driver.staged_len() >= 1,
            "the failing window is re-staged, not dropped"
        );

        // Replace the poison. The Occupied path keeps the count unchanged.
        driver.push(row(1, 1));
        let remainder = driver.staged_len();
        assert_eq!(
            driver
                .flush()
                .await
                .expect("retry after the poison is gone"),
            remainder,
            "the re-staged remainder lands on the next flush"
        );
        assert_eq!(driver.staged_len(), 0);

        let stored = stored(&db).await;
        assert_eq!(stored.get(&1), Some(&1));
        assert_eq!(stored.get(&2), Some(&2));
        assert_eq!(stored.get(&3), Some(&3));
    }

    /// The drain removes: a push landing while the drained snapshot is being
    /// written must survive for the next window.
    #[tokio::test]
    async fn stage_during_an_in_flight_flush_survives() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));

        driver.push(row(1, 10));
        let drained = driver.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(driver.staged_len(), 0);

        // Lands "during" the write of the drained snapshot.
        driver.push(row(1, 20));
        assert_eq!(driver.staged_len(), 1, "the newer push survives the drain");

        let patches: Vec<FakePatch> = drained.into_iter().map(|entry| entry.patch).collect();
        let mut conn = db.connection().await.expect("conn");
        FakeSpec::write_window(&mut conn, &patches)
            .await
            .expect("in-flight write");

        assert_eq!(driver.flush().await.expect("flush"), 1);
        assert_eq!(stored(&db).await.get(&1), Some(&20), "the newer value wins");
    }

    /// A re-stage must not clobber a newer push that landed during the failed
    /// flush: the drained snapshot is stale, so the entry the caller has since
    /// staged wins.
    #[tokio::test]
    async fn restage_does_not_clobber_a_newer_push() {
        let db = fake_db().await;
        let driver = WriteBehind::<FakeSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));

        driver.push(row(1, 10));
        let drained = driver.drain();
        assert_eq!(driver.staged_len(), 0);

        // The newer value lands while the drained snapshot is (unsuccessfully)
        // being written.
        driver.push(row(1, 99));
        let rows: Vec<(i64, FakeRow)> = drained
            .into_iter()
            .map(|entry| (entry.key, entry.row))
            .collect();
        driver.restage(&rows);

        assert_eq!(
            driver.staged_len(),
            1,
            "the newer push stays the single pending entry"
        );
        assert_eq!(driver.flush().await.expect("flush"), 1);
        assert_eq!(
            stored(&db).await.get(&1),
            Some(&99),
            "the re-stage did not roll the row back to the stale drained value"
        );
    }

    fn country_row(id: i64, ip: &str, iso: &str) -> CountryRow {
        CountryRow {
            endpoint_id: EndpointId::new(id),
            ip: ip.parse().expect("ip"),
            iso: iso.to_owned(),
        }
    }

    /// The country buffer's identity is the ENDPOINT, and the queue's insert
    /// overwrote: two resolutions of one endpoint must collapse to the last,
    /// not write both.
    #[test]
    fn country_coalesce_last_writer_wins() {
        let rows = vec![
            country_row(1, "1.1.1.1", "US"),
            country_row(1, "1.1.1.1", "DE"),
            country_row(2, "2.2.2.2", "FR"),
        ];
        let patches = CountrySpec::coalesce(rows);
        assert_eq!(patches.len(), 2);
        let one = patches
            .iter()
            .find(|p| p.key == EndpointId::new(1))
            .expect("endpoint 1 survived");
        assert_eq!(one.patch.iso, "DE");
        assert_eq!(one.row.iso, "DE");
    }

    // ── SourceSpec (import bulk path) ────────────────────────────────────

    use super::{SourceBatch, SourceSpec};
    use crate::models_toasty::{
        Endpoint, HostType, ProfileStats, Protocol, ProtocolId, Security, TrafficStats, Transport,
    };
    use leas_proto::proto_spec::common::TransportConfig;
    use leas_proto::proto_spec::{
        ProtocolConfig, ProtocolKind, SecurityConfig, SecurityType, TransportType, VlessConfig,
    };
    use toasty::{Deferred, Json};

    /// A protocol row with its JSON columns LOADED — `upsert_protocols_bulk`
    /// rejects a deferred one.
    fn loaded_protocol(id: i64) -> Protocol {
        Protocol {
            id: ProtocolId::new(id),
            sig: id,
            proto_kind: ProtocolKind::Vless,
            transport: Transport {
                r#type: TransportType::Tcp,
            },
            security: Security {
                r#type: SecurityType::None,
                sni: None,
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(ProtocolConfig::Vless(VlessConfig {
                uuid: "00000000-0000-0000-0000-000000000000".to_owned(),
                uuid_origin: None,
                security: SecurityConfig::default(),
                transport: TransportConfig::Tcp,
                encryption: None,
                flow: None,
                path: None,
                splice: None,
                remarks: None,
                mux: None,
            }))),
            created_at: 0,
            links: Deferred::default(),
        }
    }

    fn endpoint_row(id: i64) -> Endpoint {
        Endpoint {
            id: EndpointId::new(id),
            domain: Endpoint::derive_domain(&format!("host{id}.example"), HostType::Dns).0,
            sub_domain: Endpoint::derive_domain(&format!("host{id}.example"), HostType::Dns).1,
            port: 443,
            ports: Vec::new(),
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
            created_at: 0,
            links: Deferred::default(),
            group_links: Deferred::default(),
        }
    }

    fn link_row(endpoint_id: i64) -> ProfileStats {
        ProfileStats {
            protocol_id: ProtocolId::new(1),
            endpoint_id: EndpointId::new(endpoint_id),
            last_used_at: None,
            last_seen_at: 0,
            latency: None,
            speed_bps: None,
            error: None,
            purge_reason: None,
            stab_mask: 0,
            stab_len: 0,
            traffic: TrafficStats {
                today_up: 0,
                today_down: 0,
                total_up: 0,
                total_down: 0,
            },
            created_at: 0,
            updated_at: 0,
            version: 1,
            protocol: Deferred::default(),
            endpoint: Deferred::default(),
        }
    }

    /// A batch of `endpoints` endpoint rows whose FIRST `links` of them carry
    /// a link. `links < endpoints` therefore builds an orphan endpoint on
    /// purpose — the state the brief's probe measures.
    fn source_batch(seq: u64, endpoints: usize, links: usize) -> SourceBatch {
        let ids: Vec<i64> = (1..=i64::try_from(endpoints).expect("small count")).collect();
        SourceBatch {
            seq,
            endpoints: ids.iter().copied().map(endpoint_row).collect(),
            protocols: vec![loaded_protocol(1)],
            links: ids.iter().copied().take(links).map(link_row).collect(),
            group_links: Vec::new(),
            ip_literals: Vec::new(),
        }
    }

    /// Endpoints with no link row at all.
    async fn linkless_endpoint_count(db: &crate::Database) -> usize {
        let mut conn = db.connection().await.expect("conn");
        let rows = toasty::sql::query(
            "SELECT COUNT(*) FROM endpoints e \
             WHERE NOT EXISTS (SELECT 1 FROM profile_stats p WHERE p.endpoint_id = e.id)",
        )
        .exec(&mut conn)
        .await
        .expect("count linkless endpoints");
        rows.first()
            .and_then(|row| match row {
                toasty::stmt::Value::Record(record) => match record.fields.first() {
                    Some(toasty::stmt::Value::I64(n)) => usize::try_from(*n).ok(),
                    _ => None,
                },
                _ => None,
            })
            .expect("count is a row")
    }

    /// The accepted state after a coordinated flush: orphans come only from the
    /// INPUT batch, never from a split commit. One driver writes all four
    /// families in one transaction, so the endpoint a window wrote without a
    /// link is exactly one the caller handed it.
    #[tokio::test]
    async fn import_flush_leaves_only_the_input_batchs_own_orphans() {
        let db = Arc::new(crate::Database::in_memory().await.expect("db"));
        let driver =
            WriteBehind::<SourceSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));

        driver.push(source_batch(1, 3, 2)); // 3 endpoints, 2 links
        assert_eq!(driver.flush().await.expect("flush"), 2, "link rows written");

        assert_eq!(
            linkless_endpoint_count(&db).await,
            1,
            "the orphan is the batch's own third endpoint, not a split commit"
        );
    }

    /// A well-formed batch leaves NO orphans: the endpoint and its link commit
    /// together.
    #[tokio::test]
    async fn import_flush_leaves_no_linkless_endpoints() {
        let db = Arc::new(crate::Database::in_memory().await.expect("db"));
        let driver =
            WriteBehind::<SourceSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));

        driver.push(source_batch(1, 3, 3));
        assert_eq!(driver.flush().await.expect("flush"), 3);

        assert_eq!(linkless_endpoint_count(&db).await, 0);
    }

    /// The batch id is the staging identity, so two staged batches are TWO
    /// pending entries and both are written — a content-derived or constant key
    /// would silently drop one.
    #[tokio::test]
    async fn source_batches_stage_under_their_own_ids() {
        let db = Arc::new(crate::Database::in_memory().await.expect("db"));
        let driver =
            WriteBehind::<SourceSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));

        driver.push(source_batch(1, 2, 2));
        driver.push(source_batch(2, 4, 4));
        assert_eq!(driver.staged_len(), 2, "one pending entry per batch id");
        assert_eq!(
            driver.flush().await.expect("flush"),
            6,
            "links of both batches"
        );

        assert_eq!(linkless_endpoint_count(&db).await, 0);
    }

    /// Every staged entry is drained even when the window spans several
    /// batches: `flush` reports the sum of the per-window link counts.
    #[tokio::test]
    async fn source_flush_sums_across_windows() {
        let db = Arc::new(crate::Database::in_memory().await.expect("db"));
        // flush_rows = 1 → one transaction per batch.
        let driver = WriteBehind::<SourceSpec>::new(Arc::clone(&db), 1, Duration::from_millis(200));

        driver.push(source_batch(1, 2, 2));
        driver.push(source_batch(2, 3, 3));
        assert_eq!(driver.flush().await.expect("flush"), 5);
        assert_eq!(driver.staged_len(), 0, "everything drained");
    }

    /// A poisoned batch fails the window, and the rows are RE-STAGED so the
    /// next flush writes them — the driver's failure contract, on the real
    /// four-family write.
    #[tokio::test]
    async fn a_failed_source_flush_restages_the_window() {
        let db = Arc::new(crate::Database::in_memory().await.expect("db"));
        let driver =
            WriteBehind::<SourceSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));

        // A protocol row with an UNLOADED config: `upsert_protocols_bulk`
        // rejects it outright, which is a deterministic NON-busy error, so
        // `retry_on_busy` does not spin on it.
        driver.push(source_batch(1, 2, 2));
        let mut poisoned = source_batch(2, 1, 1);
        poisoned.protocols[0].config = Deferred::default();
        driver.push(poisoned);

        assert!(driver.flush().await.is_err(), "the window must fail");
        assert_eq!(
            driver.staged_len(),
            2,
            "the failed window is re-staged, not dropped"
        );
    }

    // ── LinkSpec (profile_stats write-behind) ─────────────────────────────

    use super::{LinkRow, LinkSpec};
    use crate::LinkGroups;
    use crate::models_toasty::{Latency, ProfileErr, PurgeReason};

    /// A database with one endpoint, one protocol and one link row — the shape
    /// a link patch writes.
    async fn seeded_links() -> (Arc<crate::Database>, Arc<WriteBehind<LinkSpec>>) {
        let db = Arc::new(crate::Database::in_memory().await.expect("db"));
        db.upsert_endpoint(&endpoint_row(1))
            .await
            .expect("endpoint");
        db.upsert_protocol(&loaded_protocol(1))
            .await
            .expect("protocol");
        db.upsert_link(&link_row(1)).await.expect("link");
        let driver = WriteBehind::<LinkSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));
        (db, driver)
    }

    fn with_latency(base: &ProfileStats, delay: i32) -> ProfileStats {
        let mut row = base.clone();
        row.latency = Some(Latency::Fast { delay });
        row
    }

    /// A FILE db's link window writes the staged values.
    ///
    /// A file db is the only configuration that opens a pooled driver over an
    /// on-disk database (with its WAL/sidecar handling), so it is the one path
    /// the in-memory tests do not exercise. Asserted directly, since there is
    /// only one write path now.
    #[tokio::test]
    async fn file_db_link_window_writes_the_staged_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_db = Arc::new(
            crate::Database::open(dir.path().join("file.db"))
                .await
                .expect("file db"),
        );
        file_db
            .upsert_endpoint(&endpoint_row(1))
            .await
            .expect("endpoint");
        file_db
            .upsert_protocol(&loaded_protocol(1))
            .await
            .expect("protocol");
        file_db.upsert_link(&link_row(1)).await.expect("link");

        let seeded = link_row(1);
        let mut row = link_row(1);
        row.latency = Some(Latency::Fast { delay: 42 });
        row.error = Some(crate::models_toasty::ErrorInfo {
            kind: ProfileErr::Fast,
            text: "boom".to_owned(),
        });
        row.last_seen_at = 1_700_000_123;
        row.purge_reason = Some(PurgeReason::NotTls);

        let driver =
            WriteBehind::<LinkSpec>::new(Arc::clone(&file_db), 512, Duration::from_millis(200));
        driver.stage(&row, LinkGroups::RESULT.union(LinkGroups::PURGE));
        assert_eq!(driver.flush().await.expect("flush"), 1, "one link written");

        let stored = stored_link(&file_db, 1).await;
        assert_eq!(stored.latency, Some(Latency::Fast { delay: 42 }));
        assert_eq!(stored.error.as_ref().map(|e| e.text.as_str()), Some("boom"));
        assert_eq!(stored.purge_reason, Some(PurgeReason::NotTls));
        assert_eq!(
            stored.last_seen_at, seeded.last_seen_at,
            "a RESULT|PURGE patch does not own last_seen_at, so it is untouched"
        );
    }

    /// The stored `profile_stats` row, read back through the model.
    async fn stored_link(db: &crate::Database, endpoint_id: i64) -> ProfileStats {
        let mut conn = db.connection().await.expect("conn");
        ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(1),
            EndpointId::new(endpoint_id),
        )
        .first()
        .exec(&mut conn)
        .await
        .expect("read")
        .expect("row")
    }

    /// Hold the write lock on a second connection, so every write the flush
    /// attempts fails with "database is locked".
    async fn hold_write_lock(conn: &mut toasty::Connection) -> toasty::Transaction<'_> {
        let mut lock = conn.transaction().await.expect("lock transaction");
        toasty::sql::statement("UPDATE profile_stats SET version = version + 0")
            .exec(&mut lock)
            .await
            .expect("take the write lock");
        lock
    }

    /// The drain's MERGE, verbatim from `LinkWriter::drain`: one patch per
    /// link, the union of its staged groups, and a snapshot carrying every
    /// column those groups own.
    #[test]
    fn link_coalesce_unions_groups_per_link() {
        let base = link_row(7);
        let result = LinkRow {
            link: with_latency(&base, 100),
            groups: LinkGroups::RESULT,
        };
        let mut traffic_link = base;
        traffic_link.traffic.total_up = 9;
        let traffic = LinkRow {
            link: traffic_link,
            groups: LinkGroups::TRAFFIC,
        };

        let out = LinkSpec::coalesce(vec![result, traffic]);
        assert_eq!(out.len(), 1, "one patch per link");
        assert_eq!(
            out[0].patch.groups,
            LinkGroups::RESULT.union(LinkGroups::TRAFFIC),
            "the union of the staged groups"
        );
        assert_eq!(
            out[0].patch.link.latency,
            Some(Latency::Fast { delay: 100 }),
            "the RESULT columns are carried"
        );
        assert_eq!(
            out[0].patch.link.traffic.total_up, 9,
            "and so are the TRAFFIC counters"
        );
    }

    /// A group staged for one link must not leak its bit onto another's patch,
    /// nor onto a second drain.
    #[test]
    fn link_coalesce_keeps_each_links_groups_to_itself() {
        let base = link_row(1);
        let rows = vec![
            LinkRow {
                link: with_latency(&base, 5),
                groups: LinkGroups::RESULT,
            },
            LinkRow {
                link: with_latency(&link_row(2), 6),
                groups: LinkGroups::PURGE,
            },
        ];
        let out = LinkSpec::coalesce(rows);
        assert_eq!(out.len(), 2, "one patch per link");
        assert!(
            out.iter().all(
                |e| e.patch.groups == LinkGroups::RESULT || e.patch.groups == LinkGroups::PURGE
            ),
            "no union across links"
        );
    }

    /// Every staged group must leave the map when the window drains. A group
    /// the fold skipped stayed behind and re-added its bit to the next drain's
    /// union — which is how a PURGE-only entry wrote a verdict from a snapshot
    /// that never classified one.
    #[tokio::test]
    async fn a_purge_verdict_survives_the_drain_and_empties_the_window() {
        let (db, driver) = seeded_links().await;
        let mut row = with_latency(&link_row(1), 44);
        row.purge_reason = Some(PurgeReason::NotTls);
        driver.stage(&row, LinkGroups::RESULT.union(LinkGroups::PURGE));
        assert_eq!(driver.staged_len(), 2, "one entry per group");

        driver.flush().await.expect("flush");
        assert_eq!(
            driver.staged_len(),
            0,
            "the drain removes EVERY group's entry, not just the ones it folds"
        );

        let stored = stored_link(&db, 1).await;
        assert_eq!(stored.purge_reason, Some(PurgeReason::NotTls));
        assert_eq!(
            stored.latency,
            Some(Latency::Fast { delay: 44 }),
            "and the result half landed too"
        );
    }

    /// A real probe stages `RESULT | PURGE`, so the re-staged remainder must be
    /// findable by the next drain. Re-staging under the UNION key would insert
    /// a key neither `stage` nor `key_of` ever matches: the retry would write
    /// nothing and the result would be lost.
    #[tokio::test]
    async fn a_failed_window_restages_a_multi_group_patch_so_the_retry_lands() {
        let (db, driver) = seeded_links().await;
        let mut row = with_latency(&link_row(1), 33);
        row.purge_reason = Some(PurgeReason::RealityFallback);
        driver.stage(&row, LinkGroups::RESULT.union(LinkGroups::PURGE));

        let mut blocker = db.connection().await.expect("blocker connection");
        let lock = hold_write_lock(&mut blocker).await;
        assert!(
            driver.flush().await.is_err(),
            "the write lock fails the flush"
        );
        assert_eq!(driver.staged_len(), 2, "one entry per group, re-staged");
        lock.rollback().await.expect("release the lock");
        drop(blocker);

        assert_eq!(
            driver.flush().await.expect("retry after contention"),
            1,
            "the re-staged patch is found and written by the retry"
        );
        assert_eq!(driver.staged_len(), 0);
        let stored = stored_link(&db, 1).await;
        assert_eq!(stored.latency, Some(Latency::Fast { delay: 33 }));
        assert_eq!(
            stored.purge_reason,
            Some(PurgeReason::RealityFallback),
            "both groups land, not just the first"
        );
    }

    /// The LINK-shaped floor values: `flush_rows = 1` makes three staged links
    /// three windows, and each link's three column groups coalesce into ONE
    /// patch. Three groups staged per link must still be three entries.
    #[tokio::test]
    async fn link_flush_chunks_one_patch_per_link_at_flush_rows_one() {
        let (db, _) = seeded_links().await;
        let driver = WriteBehind::<LinkSpec>::new(Arc::clone(&db), 1, Duration::from_millis(200));
        let base = link_row(1);
        for idx in 0..3 {
            let mut link = with_latency(&base, idx);
            link.endpoint_id = EndpointId::new(i64::from(idx) + 2);
            link.protocol_id = ProtocolId::new(i64::from(idx) + 202);
            driver.stage(&link, LinkGroups::ALL);
        }
        assert_eq!(
            driver.staged_len(),
            12,
            "ALL normalises to one entry per group (RESULT/PURGE/TRAFFIC/STAB), per link"
        );
        assert_eq!(
            driver.flush().await.expect("flush"),
            3,
            "one patch per link"
        );
        assert_eq!(driver.flush_count(), 3, "one transaction per chunk");
    }

    /// Both groups belong to the same link: they coalesce into ONE write whose
    /// merged row carries both the result and the counters.
    #[tokio::test]
    async fn link_flush_writes_both_groups_in_one_transaction() {
        let (db, driver) = seeded_links().await;
        let base = link_row(1);
        let mut result = with_latency(&base, 44);
        result.speed_bps = Some(1_000_000);
        let mut traffic = base.clone();
        traffic.traffic.total_up = 5;

        driver.stage(&result, LinkGroups::RESULT);
        driver.stage(&traffic, LinkGroups::TRAFFIC);
        assert_eq!(driver.staged_len(), 2, "one entry per (link, group)");

        assert_eq!(driver.flush().await.expect("flush"), 1);
        assert_eq!(driver.flush_count(), 1, "one transaction per window");

        let row = stored_link(&db, 1).await;
        assert_eq!(row.latency, Some(Latency::Fast { delay: 44 }));
        assert_eq!(row.speed_bps, Some(1_000_000));
        assert_eq!(row.traffic.total_up, 5);
    }

    /// `stage` never awaits a write: the flush task's transactions are the only
    /// writer, and the same `(link, group)` coalesces.
    #[tokio::test]
    async fn link_stage_never_awaits_a_write() {
        let (_db, driver) = seeded_links().await;
        let base = link_row(1);
        for delay in 0..500 {
            driver.stage(&with_latency(&base, delay), LinkGroups::RESULT);
        }
        assert_eq!(driver.flush_count(), 0, "no transaction without a flush");
        assert_eq!(driver.staged_len(), 1, "same (link, group) coalesces");
    }

    /// The read-through: a caller that must see a staged row BEFORE it commits
    /// reads it through `get`, with no await.
    #[tokio::test]
    async fn link_get_reads_a_staged_row_through() {
        let (_db, driver) = seeded_links().await;
        let row = with_latency(&link_row(1), 12);
        assert!(
            driver
                .get(&LinkSpec::key_of(&LinkRow {
                    link: row.clone(),
                    groups: LinkGroups::RESULT,
                }))
                .is_none(),
            "nothing staged yet"
        );

        driver.stage(&row, LinkGroups::RESULT);
        let staged = driver
            .get(&(row.protocol_id, row.endpoint_id, LinkGroups::RESULT))
            .expect("the staged RESULT row");
        assert_eq!(staged.link.latency, Some(Latency::Fast { delay: 12 }));
        assert!(
            driver
                .get(&(row.protocol_id, row.endpoint_id, LinkGroups::PURGE,))
                .is_none(),
            "one group does not make another visible"
        );
    }

    /// Poll a condition instead of sleeping a fixed span: these drive a REAL
    /// background task against a REAL database, so a fixed sleep is a bet on
    /// scheduling under full-suite load.
    async fn wait_for(
        driver: &WriteBehind<LinkSpec>,
        what: &str,
        mut done: impl FnMut(&WriteBehind<LinkSpec>) -> bool,
        timeout: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + timeout;
        while !done(driver) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out after {timeout:?} waiting for {what} (flushes={}, staged={})",
                driver.flush_count(),
                driver.staged_len(),
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The FLOOR path, for link rows. `flush_rows` drives both the size trigger
    /// and the floor, so the numbers put the floor strictly inside the row
    /// count while the size trigger is never reached: 128 -> floor 32, 64 rows
    /// -> exactly two floor-driven commits. The deadline (75 x 10 ms = 750 ms)
    /// is out of range for a 640 ms staging window, so it cannot be what fires.
    ///
    /// Every stage is a DISTINCT `endpoint_id`: the staging key is
    /// `(link, group)`, so staging the same link repeatedly coalesces into one
    /// entry and the floor could never be reached.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_link_trickle_coalesces_at_the_floor_not_every_tick() {
        const ROWS: usize = 64;
        const FLUSH_ROWS: usize = 128;
        let (db, _) = seeded_links().await;
        let interval = Duration::from_millis(10);
        let driver = WriteBehind::<LinkSpec>::new(Arc::clone(&db), FLUSH_ROWS, interval);
        let floor = driver.timer_flush_floor();
        assert_eq!(floor, FLUSH_ROWS / super::TIMER_FLOOR_DIVISOR);
        assert!(
            ROWS > floor && ROWS < FLUSH_ROWS,
            "the floor must sit strictly inside the row count, or this is not testing it",
        );
        let task = driver.spawn_flush_task();

        let base = link_row(1);
        for i in 0..ROWS {
            let mut link = with_latency(&base, i32::try_from(i).expect("small i"));
            link.endpoint_id = EndpointId::new(1_000 + i64::try_from(i).expect("small i"));
            driver.stage(&link, LinkGroups::RESULT);
            tokio::time::sleep(interval).await;
        }
        wait_for(
            &driver,
            "the staged rows to drain",
            |d| d.staged_len() == 0,
            Duration::from_secs(20),
        )
        .await;
        // 64 rows / floor 32 is 2 commits, plus at most one deadline flush for
        // the remainder. Ignoring the floor yields ~64, far outside this range.
        let commits = driver.flush_count();
        assert!(
            (1..=4).contains(&commits),
            "expected 1-4 floor-driven commits for {ROWS} rows at floor {floor}, got {commits}",
        );
        task.abort();
    }

    /// The DEADLINE path, which the floor case deliberately stays out of: a
    /// trickle that never reaches the floor must still be written, so a result
    /// is never stranded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_link_trickle_below_the_floor_is_still_written_by_the_deadline() {
        const ROWS: usize = 8;
        const FLUSH_ROWS: usize = 128;
        let (db, _) = seeded_links().await;
        let interval = Duration::from_millis(10);
        let driver = WriteBehind::<LinkSpec>::new(Arc::clone(&db), FLUSH_ROWS, interval);
        assert!(
            ROWS < driver.timer_flush_floor(),
            "this case needs rows UNDER the floor",
        );
        let task = driver.spawn_flush_task();

        let base = link_row(1);
        for i in 0..ROWS {
            let mut link = with_latency(&base, i32::try_from(i).expect("small i"));
            link.endpoint_id = EndpointId::new(2_000 + i64::try_from(i).expect("small i"));
            driver.stage(&link, LinkGroups::RESULT);
            tokio::time::sleep(interval).await;
        }
        wait_for(
            &driver,
            "the deadline to release a below-floor trickle",
            |d| d.flush_count() >= 1,
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(
            driver.staged_len(),
            0,
            "the deadline flush must drain, or a result is stranded",
        );
        task.abort();
    }

    /// The derived floor and deadline for the LINK policy, from the named
    /// constants the driver exports.
    #[tokio::test]
    async fn the_link_flush_policy_follows_the_named_constants() {
        let (db, _) = seeded_links().await;
        let driver = WriteBehind::<LinkSpec>::new(Arc::clone(&db), 512, Duration::from_millis(200));
        assert_eq!(driver.timer_flush_floor(), 512 / super::TIMER_FLOOR_DIVISOR);
        assert_eq!(
            driver.max_staged_age(),
            Duration::from_millis(200) * super::MAX_STAGED_AGE_TICKS
        );
        let small = WriteBehind::<LinkSpec>::new(Arc::clone(&db), 1, super::DEFAULT_FLUSH_INTERVAL);
        assert_eq!(
            small.timer_flush_floor(),
            1,
            "under the divisor floors to 1"
        );
    }
}
