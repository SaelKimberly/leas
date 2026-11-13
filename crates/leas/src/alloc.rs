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
//!
//! Retention tuning ([`configure`]): 3.6's Linux defaults are shaped for
//! throughput, not footprint — `allow_thp=2` raises the minimal purge size to
//! 2 MiB, and the v3 page reclaimers are effectively unlimited. On this
//! workload the defaults cost ~45 MiB at idle and ~125 MiB after a feed-wide
//! batch against 3.3.2. The tuned set below restores parity (idle 93 vs 79 MB,
//! settle 183 vs 182 MB on the 13,803-link feed) while keeping 3.6.1's 2-4x
//! faster allocation. Windows needs none of it: v3's own commit reductions are
//! the reason the same build measured better there with default options.
//!
//! ## Feature switches
//!
//! - default (feature `mimalloc`): mimalloc, tuned by [`configure`].
//! - `std-alloc`: `System` instead. External profilers (heaptrack, valgrind,
//!   dhat) only observe individual allocations through the system allocator;
//!   mimalloc owns every block, so they see nothing.
//! - `mem-trace` (implies `std-alloc`): the workspace tracer
//!   (`leas-memtrace`) becomes the process allocator and writes per-module
//!   artifacts at each [`job_boundary`].
//!
//! Only one `#[global_allocator]` may exist per binary, which is why these are
//! mutually exclusive compile-time choices and not runtime switches.

/// Apply this process's allocator policy. Call once, before the runtime does
/// real work.
///
/// Measured on the 13,803-link feed (idle / Fast Test peak / settle):
/// defaults 124-127 / 371 / 307 MB, this set 93 / 284 / 183 MB, and the 3.3.2
/// baseline 78-79 / 196-299 / 182 MB.
///
/// A no-op when mimalloc is not the allocator.
#[allow(
    clippy::missing_const_for_fn,
    reason = "the mimalloc path calls FFI; only the `std-alloc` no-op body looks constant to clippy"
)]
pub fn configure() {
    #[cfg(all(feature = "mimalloc", not(feature = "std-alloc")))]
    mimalloc_alloc::configure();
}

/// Return the allocator's freed-but-committed pages to the OS.
///
/// Call at a job boundary whose peak is far above the live set (a test batch,
/// an import): an idle session allocates too little to fire the purge path, so
/// the peak would otherwise stay in RSS until the process exits.
///
/// A no-op when mimalloc is not the allocator.
#[allow(
    clippy::missing_const_for_fn,
    reason = "the mimalloc path calls FFI; only the `std-alloc` no-op body looks constant to clippy"
)]
pub fn release_freed_heap() {
    #[cfg(all(feature = "mimalloc", not(feature = "std-alloc")))]
    mimalloc_alloc::release_freed_heap();
}

/// Start the memory tracer, when `mem-trace` built it in.
///
/// Roots are crate-name prefixes; only frames inside them are attributed, and
/// every artifact prints the list. `LEAS_MEM_TRACE_MIN_BYTES` raises the
/// smallest allocation worth a stack walk (0 — the default — traces all).
pub fn start_tracing() {
    #[cfg(feature = "mem-trace")]
    {
        const ROOTS: &[&str] = &[
            "leas",
            "leas_core",
            "leas_config",
            "leas_db",
            "leas_dns",
            "leas_geoip",
            "leas_host_features",
            "leas_native",
            "leas_proto",
            "leas_route",
            "leas_tls",
        ];
        let min_bytes = std::env::var("LEAS_MEM_TRACE_MIN_BYTES")
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        if !leas_memtrace::start_with(ROOTS, min_bytes, &[("bin", "leas")]) {
            tracing::warn!(
                target: "tui::alloc",
                "a trace window is already running; keeping it"
            );
        }
        // Interval artifacts exist for the run that never reaches its exit
        // boundary (a SIGTERM, a crash); `0`/unset keeps the old behaviour.
        let interval = std::env::var("LEAS_MEM_TRACE_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        if interval > 0 {
            let max = std::env::var("LEAS_MEM_TRACE_INTERVAL_MAX")
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(8);
            let dir = std::env::var("LEAS_MEM_TRACE_DIR")
                .unwrap_or_else(|_| "target/mem-trace".to_owned());
            if let Err(error) = leas_memtrace::spawn_interval_writer(dir.into(), interval, max) {
                tracing::warn!(target: "tui::alloc", "interval artifacts unavailable: {error}");
            }
        }
    }
}

/// Close one unit of work: hand the allocator its freed pages back, and under
/// `mem-trace` write a labelled snapshot first.
///
/// The label is what makes the artifact readable later (`batch-ended`,
/// `import`); the trace directory is `LEAS_MEM_TRACE_DIR`, defaulting to
/// `target/mem-trace`.
pub fn job_boundary(label: &'static str) {
    #[cfg(feature = "mem-trace")]
    write_trace(label);
    #[cfg(not(feature = "mem-trace"))]
    let _ = label;
    release_freed_heap();
}

#[cfg(feature = "mem-trace")]
fn write_trace(label: &str) {
    if !leas_memtrace::is_started() {
        return;
    }
    let dir = std::env::var("LEAS_MEM_TRACE_DIR").unwrap_or_else(|_| "target/mem-trace".to_owned());
    if let Err(error) = leas_memtrace::write(std::path::Path::new(&dir), label) {
        tracing::warn!(target: "tui::alloc", "mem-trace artifact not written: {error}");
    }
}

/// The default build's allocator: mimalloc, tuned for footprint over the 3.6
/// Linux defaults (see the module docs).
#[cfg(all(feature = "mimalloc", not(feature = "std-alloc")))]
mod mimalloc_alloc {
    use mimalloc::MiMalloc;

    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;

    // Option indices from mimalloc 3.6.1's `mi_option_e`
    // (`c_src/mimalloc3/include/mimalloc.h`), 0-based. The C API takes the enum as
    // an `int`; [`tests::retention_options_index_are_stable`] reads every one back
    // so a dependency bump that renumbers the enum fails a test instead of
    // silently tuning an unrelated option.
    const MI_OPTION_GENERIC_COLLECT: i32 = 34;
    const MI_OPTION_PAGE_FULL_RETAIN: i32 = 36;
    const MI_OPTION_PAGE_MAX_RECLAIM: i32 = 41;
    const MI_OPTION_PAGE_CROSS_THREAD_MAX_RECLAIM: i32 = 42;
    const MI_OPTION_ALLOW_THP: i32 = 43;

    /// The tuned `(index, value)` set. Values are the measured optimum on the
    /// reference feed; `page_full_retain=0` alone is WORSE (181 MB idle) because
    /// each size class then commits a fresh page — it only pays with THP off.
    const RETENTION_OPTIONS: [(i32, std::ffi::c_long); 5] = [
        (MI_OPTION_ALLOW_THP, 0),
        (MI_OPTION_PAGE_FULL_RETAIN, 0),
        (MI_OPTION_PAGE_MAX_RECLAIM, 0),
        (MI_OPTION_PAGE_CROSS_THREAD_MAX_RECLAIM, 0),
        // Collect every 512 generic allocations instead of the default 10,000:
        // the app's steady state allocates in short bursts, so theaps otherwise
        // sit on pages between ticks.
        (MI_OPTION_GENERIC_COLLECT, 512),
    ];

    unsafe extern "C" {
        /// mimalloc's `mi_collect(force)`: collect abandoned heaps and purge
        /// expired arena ranges.
        fn mi_collect(force: bool);
        /// mimalloc's `mi_option_set(option, value)`.
        fn mi_option_set(option: i32, value: std::ffi::c_long);
    }

    pub(super) fn configure() {
        for (option, value) in RETENTION_OPTIONS {
            // SAFETY: `mi_option_set` takes an option index and an integer; it
            // mutates mimalloc's own option table and takes no pointers.
            unsafe { mi_option_set(option, value) };
        }
    }

    pub(super) fn release_freed_heap() {
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

        /// The C option API takes enum values as plain `int`s; they are only
        /// correct for the vendored mimalloc. Setting each and reading it back
        /// proves the indices still name the options [`super::configure`] tunes.
        #[test]
        fn retention_options_index_are_stable() {
            // Save and restore: the options are process-wide, so leaving the tuned
            // set behind would slow every other test in this binary (the generic
            // collect fires every 512 allocations).
            let saved: Vec<(i32, std::ffi::c_long)> = super::RETENTION_OPTIONS
                .iter()
                .map(|(option, _)| {
                    // SAFETY: `mi_option_get` takes an option index.
                    (*option, unsafe { mi_option_get(*option) })
                })
                .collect();
            super::configure();
            for (option, expected) in super::RETENTION_OPTIONS {
                // SAFETY: `mi_option_get` takes an option index.
                let got = unsafe { mi_option_get(option) };
                assert_eq!(
                    got, expected,
                    "option index {option} is not the expected option"
                );
            }
            for (option, value) in saved {
                // SAFETY: see `configure`.
                unsafe { super::mi_option_set(option, value) };
            }
        }
    }
}

/// The `mem-trace` allocator: per-module live/peak bytes and folded stacks,
/// written at [`job_boundary`] calls.
#[cfg(feature = "mem-trace")]
#[global_allocator]
static GLOBAL: leas_memtrace::TracingAllocator = leas_memtrace::TracingAllocator::new();

#[cfg(all(test, feature = "perf-lab"))]
mod lab;
