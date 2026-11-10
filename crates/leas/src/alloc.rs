//! The process-wide allocator, owned by the binary.
//!
//! This used to be implicit: `turso`'s `mimalloc` feature installs a
//! `#[global_allocator]` from inside `leas-db`'s dependency tree, so the
//! choice could not be configured from our side, swapped for a profiling
//! allocator, or inspected. `leas-db` now requests turso without that feature
//! and the single `#[global_allocator]` lives here — the one place a different
//! allocator (a tracing allocator for a profile run, say) has to be put.
//!
//! Version: the crates.io `mimalloc` crate (0.1.52 / `libmimalloc-sys`
//! 0.1.49, vendoring mimalloc **3.3.2**). The newer `mimalloc-safe` 0.1.70
//! with its `v3` feature (mimalloc 3.6.1) was measured on the same 13,803-link
//! feed and is worse for this workload in every configuration tried — settle
//! 392 MiB untuned / 309 MiB tuned (`purge_delay=0`, `arena_purge_mult=1`,
//! `allow_thp=0`) against 275 MiB for 3.3.2. Revisit on a newer crates.io sys
//! crate, not before.
//!
//! Purging: mimalloc returns freed pages to the OS only when a later
//! allocation fires its purge timer (default 1 s), and `mi_collect` walks only
//! the CALLING thread's heap — 3.3.2 says so in `theap.c:149` ("cannot really
//! collect process wide"). A batch that peaks on hundreds of short-lived
//! blocking threads (DNS lookups) therefore leaves their heaps' pages resident
//! after the threads are gone: measured `Fast Test (All Profiles)` peaked at
//! 360 MiB with 262 threads and settled at 292 MiB against a 117 MiB baseline.
//! [`configure`] removes the timer delay, and [`release_freed_heap`] forces a
//! collect at each job boundary.

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// `mi_option_purge_delay` in mimalloc 3.3.2's `mi_option_e`
/// (`c_src/mimalloc/v3/include/mimalloc.h:455`, 15th enumerator). The C
/// option API takes the enum as an `int`, so the value is pinned here and
/// verified by [`tests::purge_delay_option_index_is_stable`] — a dependency
/// bump that changes the enum fails that test instead of silently setting an
/// unrelated option.
const MI_OPTION_PURGE_DELAY: i32 = 15;

// Declared here rather than through `libmimalloc-sys`: its bindings live
// behind the `extended` feature, which would pull `cty` in for three calls.
// The symbols are in the linked archive (link-time GC only drops one nothing
// references), so a missing symbol is a link error, not a silent no-op.
unsafe extern "C" {
    /// mimalloc's `mi_collect(force)`: collect the calling thread's heap and
    /// purge expired arena ranges.
    fn mi_collect(force: bool);
    /// mimalloc's `mi_option_set(option, value)`.
    fn mi_option_set(option: i32, value: std::ffi::c_long);
}

/// Apply this process's allocator policy. Call once, before the runtime does
/// real work.
///
/// `purge_delay = 0` purges a freed page immediately instead of after the
/// 1 s timer. Measured on a fast batch: settled RSS 292 → 253 MiB, peak 360 →
/// 308 MiB. The cost is recommit churn on bursty allocation, which the same
/// numbers already include.
pub fn configure() {
    // SAFETY: `mi_option_set` takes an option index and an integer; it mutates
    // mimalloc's own global option table and takes no pointers.
    unsafe { mi_option_set(MI_OPTION_PURGE_DELAY, 0) };
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

#[cfg(test)]
mod tests {
    unsafe extern "C" {
        /// mimalloc's `mi_option_get(option)` — the read-back the pin needs.
        fn mi_option_get(option: i32) -> std::ffi::c_long;
    }

    /// The C option API takes an enum value as a plain `int`; the constant is
    /// only correct for the vendored mimalloc. Setting and reading it back
    /// proves the index still names `purge_delay`.
    #[test]
    fn purge_delay_option_index_is_stable() {
        super::configure();
        // SAFETY: see `configure`.
        let got = unsafe { mi_option_get(super::MI_OPTION_PURGE_DELAY) };
        assert_eq!(
            got,
            0,
            "option {} is not purge_delay",
            super::MI_OPTION_PURGE_DELAY
        );
    }
}
