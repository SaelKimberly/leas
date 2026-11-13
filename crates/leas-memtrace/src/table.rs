//! Symbol table, per-symbol counters and the instruction-pointer cache.
//!
//! The hot path reads a row out of a fixed slab and bumps atomics; the mutex is
//! only taken when a *new* module appears, which happens a few dozen times per
//! process at most.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

/// Row 0 collects allocations no row attributes; real symbols start at 1.
pub const UNTRACED: u32 = 0;

/// The header tag of an allocation no row accounts for — it was taken while
/// tracing was off, or from inside the tracer itself.
pub const NO_TAG: u32 = u32::MAX;

/// One row per distinct module — or per distinct function when
/// `LEAS_MEM_TRACE_ROWS=symbol` asks for it, which is what separates two
/// allocation sites inside one module. The slab is a fixed size so a counter
/// update is an index, never a grow or a lock; 16 384 rows cost 640 KiB of
/// virtual memory and a symbol-keyed run of a 40 MiB binary fits inside it.
const MAX_SYMBOLS: usize = 16_384;

/// 2^16 slots: sixteen times the plausible number of distinct allocating call
/// sites, so eviction is a non-event. (`SLOT_BITS` < 32 keeps the shift sane.)
const SLOT_BITS: u32 = 16;
const SLOTS: usize = 1 << SLOT_BITS;

/// Bits of a cache word below the frame address: the tag.
const TAG_BITS: u32 = 16;
const TAG_MASK: u64 = (1 << TAG_BITS) - 1;
/// A 16-bit tag cannot name `NO_TAG` (`u32::MAX`), so the cache spells
/// "resolved, not ours" with its own code.
const FOREIGN_CODE: u64 = TAG_MASK;
/// Frame addresses above this do not fit beside the tag (48-bit canonical
/// addresses are the widest this supports). A wider address bypasses the cache
/// — slower, never wrong.
const MAX_CACHED_IP: usize = (1 << (usize::BITS as usize - TAG_BITS as usize)) - 1;

/// One cache word: `ip << 16 | tag`, read and written atomically.
///
/// Two separate atomics would let a reader pair one caller's address with
/// another's tag; a single word cannot tear. Zero means empty — no real frame
/// address is zero.
pub struct Slot {
    word: AtomicU64,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            word: AtomicU64::new(0),
        }
    }

    fn encode(ip: usize, cached: Cached) -> u64 {
        let code = match cached {
            Cached::Foreign => FOREIGN_CODE,
            Cached::Row(id) => u64::from(id),
        };
        ((ip as u64) << TAG_BITS) | code
    }
}

/// What the cache knows about one frame address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cached {
    /// The frame belongs to a workspace module, with this row id.
    Row(u32),
    /// The frame was resolved and belongs to no workspace module.
    Foreign,
}

/// Bytes allocated and still live across every traced allocation.
pub static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
/// High-water mark of [`LIVE_BYTES`].
pub static PEAK_LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
pub static ALLOCS: AtomicUsize = AtomicUsize::new(0);
pub static DEALLOCS: AtomicUsize = AtomicUsize::new(0);
pub static CACHE_HITS: AtomicUsize = AtomicUsize::new(0);
pub static CACHE_RESOLVES: AtomicUsize = AtomicUsize::new(0);
pub static CACHE_EVICTIONS: AtomicUsize = AtomicUsize::new(0);
/// Frames the capture walked, summed over allocations. The mean is the
/// mechanism metric for the cache: a hit stops the walk at the first resolved
/// frame, so this should sit far below `MAX_FRAMES` per allocation.
pub static FRAMES_WALKED: AtomicUsize = AtomicUsize::new(0);
/// How many instruction-pointer resolutions found a module after the slab
/// filled up: their bytes are charged to `<untraced>` and the artifact reports
/// the count, because a sticky flag cannot tell one stray row from a run whose
/// attribution collapsed.
pub static OVERFLOWED: AtomicU64 = AtomicU64::new(0);

/// Allocations that entered the walk (i.e. were not filtered by `min_bytes`).
/// The frame-walk mean divides by this, never by the raw allocation count.
pub static ATTRIBUTED: AtomicUsize = AtomicUsize::new(0);

/// Per-symbol counters. All five are plain `Relaxed` atomics: the artifact only
/// needs a consistent-enough snapshot, never a transaction.
pub struct Stats {
    live_bytes: AtomicUsize,
    live_count: AtomicUsize,
    peak_live_bytes: AtomicUsize,
    total_bytes: AtomicUsize,
    total_count: AtomicUsize,
}

impl Stats {
    const fn new() -> Self {
        Self {
            live_bytes: AtomicUsize::new(0),
            live_count: AtomicUsize::new(0),
            peak_live_bytes: AtomicUsize::new(0),
            total_bytes: AtomicUsize::new(0),
            total_count: AtomicUsize::new(0),
        }
    }

    pub fn alloc(&self, bytes: usize) {
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.total_count.fetch_add(1, Ordering::Relaxed);
        let live = self.live_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        self.live_count.fetch_add(1, Ordering::Relaxed);
        self.peak_live_bytes.fetch_max(live, Ordering::Relaxed);
    }

    pub fn dealloc(&self, bytes: usize) {
        // Saturating: a mismatched size (an in-place `realloc`, a double-free
        // the allocator itself would abort on) must not wrap to a huge number.
        let _ = self
            .live_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                Some(live.saturating_sub(bytes))
            });
        let _ = self
            .live_count
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_sub(1))
            });
    }

    /// An in-place grow/shrink: the block moved, the allocation count did not.
    pub fn grow(&self, old: usize, new: usize) {
        if new > old {
            let delta = new - old;
            self.total_bytes.fetch_add(delta, Ordering::Relaxed);
            let live = self.live_bytes.fetch_add(delta, Ordering::Relaxed) + delta;
            self.peak_live_bytes.fetch_max(live, Ordering::Relaxed);
        } else {
            let delta = old - new;
            let _ = self
                .live_bytes
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                    Some(live.saturating_sub(delta))
                });
        }
    }

    pub fn row(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.live_bytes.load(Ordering::Relaxed),
            self.live_count.load(Ordering::Relaxed),
            self.peak_live_bytes.load(Ordering::Relaxed),
            self.total_bytes.load(Ordering::Relaxed),
            self.total_count.load(Ordering::Relaxed),
        )
    }
}

/// Names, `name → id` and the folded path per row.
///
/// Every name is owned here: the hot path carries a `u32`, so nothing needs a
/// `'static` string, and the registry dies with the process it measured.
#[derive(Default)]
pub struct Registry {
    /// `rows[id - 1]` — the name of every symbol row.
    rows: Vec<String>,
    ids: HashMap<String, u32>,
    /// Innermost-first module path per row, for the folded-stack artifact.
    folded: HashMap<u32, Vec<String>>,
}

impl Registry {
    /// The row for `name`, creating it. `None` once the slab is full.
    pub fn row(&mut self, name: &str) -> Option<u32> {
        if let Some(&id) = self.ids.get(name) {
            return Some(id);
        }
        if self.rows.len() + 1 >= MAX_SYMBOLS {
            return None;
        }
        let id = u32::try_from(self.rows.len() + 1).ok()?;
        self.rows.push(name.to_owned());
        self.ids.insert(name.to_owned(), id);
        Some(id)
    }

    pub fn name(&self, id: u32) -> Option<&str> {
        let index = usize::try_from(id).ok()?.checked_sub(1)?;
        self.rows.get(index).map(String::as_str)
    }

    pub fn set_folded(&mut self, id: u32, path: Vec<String>) {
        self.folded.insert(id, path);
    }

    pub const fn folded(&self) -> &HashMap<u32, Vec<String>> {
        &self.folded
    }
}

/// Everything a running tracer owns. Built once, then only read on the hot
/// path — every field a hot path touches is a slice index or a static.
pub struct State {
    pub stats: Box<[Stats]>,
    pub registry: Mutex<Registry>,
    cache: Box<[Slot]>,
    pub roots: &'static [&'static str],
    pub min_bytes: usize,
    /// Unit identity the artifacts echo (`rev`, features, dataset).
    pub metadata: &'static [(&'static str, &'static str)],
    /// `module` (default) or `symbol`: what a row's key is. Symbol rows are the
    /// finer grain — the same hot path, a different resolution key.
    pub rows: &'static str,
    pub started: Instant,
}

impl State {
    pub fn new(
        roots: &'static [&'static str],
        min_bytes: usize,
        metadata: &'static [(&'static str, &'static str)],
    ) -> Self {
        Self {
            stats: (0..=MAX_SYMBOLS).map(|_| Stats::new()).collect(),
            registry: Mutex::new(Registry::default()),
            cache: (0..SLOTS).map(|_| Slot::empty()).collect(),
            roots,
            min_bytes,
            metadata,
            rows: if std::env::var("LEAS_MEM_TRACE_ROWS").is_ok_and(|v| v == "symbol") {
                "symbol"
            } else {
                "module"
            },
            started: Instant::now(),
        }
    }

    /// The row counters for `tag`, if it names one.
    pub fn stats(&self, tag: u32) -> Option<&Stats> {
        self.stats.get(usize::try_from(tag).ok()?)
    }

    /// A multiplicative mix, not a modulus: call sites inside one function
    /// share a code page, and masking low bits would park them in the same
    /// handful of slots. One multiply, no hasher.
    const fn slot_index(ip: usize) -> usize {
        let mixed = ip.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (mixed >> (usize::BITS - SLOT_BITS)) & (SLOTS - 1)
    }

    pub fn cache_get(&self, ip: usize) -> Option<Cached> {
        let slot = self.cache.get(Self::slot_index(ip))?;
        let word = slot.word.load(Ordering::Relaxed);
        if word >> TAG_BITS != ip as u64 {
            return None;
        }
        if word & TAG_MASK == FOREIGN_CODE {
            Some(Cached::Foreign)
        } else {
            Some(Cached::Row(u32::try_from(word & TAG_MASK).ok()?))
        }
    }

    pub fn cache_put(&self, ip: usize, cached: Cached) {
        if ip > MAX_CACHED_IP {
            // Cannot be spelled beside the tag; re-resolve this address instead.
            return;
        }
        let Some(slot) = self.cache.get(Self::slot_index(ip)) else {
            return;
        };
        let word = Slot::encode(ip, cached);
        let previous = slot.word.swap(word, Ordering::Relaxed);
        let previous_ip = previous >> TAG_BITS;
        if previous != 0 && previous_ip != ip as u64 {
            CACHE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_track_live_peak_and_totals() {
        let stats = Stats::new();
        stats.alloc(100);
        stats.alloc(50);
        assert_eq!(stats.row(), (150, 2, 150, 150, 2));
        stats.dealloc(100);
        assert_eq!(stats.row(), (50, 1, 150, 150, 2));
        stats.dealloc(50);
        assert_eq!(stats.row(), (0, 0, 150, 150, 2));
        // The peak survives the drain: that is what the artifact reports.
        stats.alloc(10);
        assert_eq!(stats.row(), (10, 1, 150, 160, 3));
    }

    #[test]
    fn deallocating_more_than_live_saturates() {
        let stats = Stats::new();
        stats.alloc(10);
        stats.dealloc(90);
        let (live, count, _, _, _) = stats.row();
        assert_eq!((live, count), (0, 0));
    }

    #[test]
    fn registry_returns_one_row_per_name() {
        let mut registry = Registry::default();
        let first = registry.row("leas::ops::ping").expect("a row");
        let again = registry.row("leas::ops::ping").expect("the same row");
        assert_eq!(first, again);
        assert_eq!(registry.name(first), Some("leas::ops::ping"));
        assert_ne!(first, UNTRACED);
    }

    #[test]
    fn distinct_names_get_distinct_rows() {
        let mut registry = Registry::default();
        let first = registry.row("leas::ui::profiles").expect("a row");
        let second = registry.row("leas::ops::ping").expect("a row");
        assert_ne!(first, second);
        assert_eq!(registry.name(second), Some("leas::ops::ping"));
    }

    /// Different call sites must not collide into one slot; the mix is the only
    /// thing standing between a cache hit and a full re-resolve.
    #[test]
    fn slot_index_spreads_adjacent_call_sites() {
        let base = 0x5555_5555_0000_usize;
        let mut slots: Vec<usize> = (0..8).map(|i| State::slot_index(base + i * 4)).collect();
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), 8, "adjacent addresses collapsed into one slot");
    }

    #[test]
    fn cache_remembers_rows_and_foreign_frames() {
        let state = State::new(&["leas"], 0, &[]);
        let ip = 0x7f00_0000_1000_usize;
        assert_eq!(state.cache_get(ip), None);
        state.cache_put(ip, Cached::Row(7));
        assert_eq!(state.cache_get(ip), Some(Cached::Row(7)));
        state.cache_put(ip, Cached::Foreign);
        assert_eq!(state.cache_get(ip), Some(Cached::Foreign));
    }
}
