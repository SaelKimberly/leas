//! The process-wide allocator, owned by the binary.
//!
//! This used to be implicit: `turso`'s `mimalloc` feature installs a
//! `#[global_allocator]` from inside `leas-db`'s dependency tree, so the
//! choice could not be configured from our side, swapped for a profiling
//! allocator, or inspected. `leas-db` now requests turso without that feature
//! and the single `#[global_allocator]` lives here — the one place a different
//! allocator (a tracing allocator for a profile run, say) has to be put.
//!
//! Version: `mimalloc-safe` 0.1.70 with the `v3` feature (mimalloc 3.6.1, the
//! current 3.x). The older `mimalloc` 0.1.52 crate (3.3.2) was 2-4x slower on
//! the allocator lab's batch shape (`alloc/lab.rs`), and its `mi_collect(true)`
//! left abandoned blocking-thread heaps resident (41 MiB after 262 threads vs
//! 8 MiB here).
//!
//! Purging: do NOT override `purge_delay`. 3.6.x purges a page on its own free
//! path, so `purge_delay=0` turns every free into a purge — measured ~1.7-3x
//! slower on the burst. The default 1 s timer plus [`release_freed_heap`] at
//! each job boundary is the fast configuration, and the forced collect still
//! returns the pages the batch left behind.

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

unsafe extern "C" {
    /// mimalloc's `mi_collect(force)`: collect abandoned heaps and purge
    /// expired arena ranges.
    fn mi_collect(force: bool);
}

/// Return the allocator's freed-but-committed pages to the OS.
///
/// Call at a job boundary whose peak is far above the live set (a test batch,
/// an import): an idle session allocates too little to fire the purge path, so
/// the peak would otherwise stay in RSS until the process exits.
pub fn release_freed_heap() {
    // SAFETY: `mi_collect` takes no pointer arguments; it walks mimalloc's own
    // heap and arena metadata (thread-safe by design) and only decommits free
    // ranges.
    unsafe { mi_collect(true) };
}

#[cfg(all(test, feature = "perf-lab"))]
mod lab;
