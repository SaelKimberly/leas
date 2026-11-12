//! A counting global allocator, so a benchmark can state how many allocations
//! and how many bytes a code path costs instead of asserting it.
//!
//! Counts are exact and deterministic, which is the point: a timing number on
//! a shared runner is a distribution, while an allocation count is a fact.
//! This is the one claim the gate is written against.
//!
//! The `leas` binary cannot host this — it installs mimalloc as the
//! process-wide allocator (`crates/leas/src/alloc.rs`) and a second
//! `#[global_allocator]` is a compile error — so it lives in this separate
//! crate, which never links that binary.

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Non-zero while a measurement is running. Counting is off otherwise, so the
/// harness's own bookkeeping never lands in a row.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
/// Allocations the allocator zero-filled. `vec![0u8; n]` goes through
/// `alloc_zeroed`, so this counts a memset the caller asked for and then had
/// to overwrite — invisible to the allocation count alone.
static ZEROED: AtomicUsize = AtomicUsize::new(0);

pub struct Counting;

#[inline]
fn tally(size: usize) {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size, Ordering::Relaxed);
    }
}

#[inline]
fn tally_zeroed(size: usize) {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        ZEROED.fetch_add(1, Ordering::Relaxed);
        tally(size);
    }
}

#[inline]
fn tally_realloc(new_size: usize, old_size: usize) {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        REALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size.saturating_sub(old_size), Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to `System` with the caller's `Layout`
// unchanged; the counters are plain atomics and never touch the pointer.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        tally(layout.size());
        // SAFETY: `layout` is the one this method was given.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        tally_zeroed(layout.size());
        // SAFETY: `layout` is the one this method was given.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        tally_realloc(new_size, layout.size());
        // SAFETY: `ptr`/`layout` arrive from the caller of `realloc` unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` arrive from the caller of `dealloc` unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// What a measured region cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// Distinct allocations.
    pub allocs: usize,
    /// `realloc` calls: a copy-and-grow rather than a fresh allocation.
    pub reallocs: usize,
    /// Bytes requested across allocations and grows.
    pub bytes: usize,
    /// Allocations the allocator zero-filled.
    pub zeroed: usize,
}

/// Counting is on while this guard lives. A panicking measured body unwinds
/// through it, so the next measurement is not told it was nested.
struct ActiveGuard;

impl ActiveGuard {
    fn enter() -> Self {
        assert!(
            ACTIVE.swap(1, Ordering::Relaxed) == 0,
            "allocation measurements cannot be nested"
        );
        ALLOCS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
        REALLOCS.store(0, Ordering::Relaxed);
        ZEROED.store(0, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.store(0, Ordering::Relaxed);
    }
}

/// Run one future to completion with counting on.
///
/// One future at a time: a nested call means two measurements share the
/// counters, so it is a hard error rather than a wrong number.
pub async fn measure_async<F: Future<Output = R>, R>(body: F) -> (R, Counts) {
    let _active = ActiveGuard::enter();
    let out = body.await;
    let counts = Counts {
        allocs: ALLOCS.load(Ordering::Relaxed),
        reallocs: REALLOCS.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
        zeroed: ZEROED.load(Ordering::Relaxed),
    };
    (out, counts)
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;

    /// The counters are process-global, so two tests measuring at once would
    /// see each other (and one would report a nested measurement). `cargo
    /// nextest` runs a process per test; `cargo test` runs them on threads,
    /// which is the runner this guard exists for. It is held across the
    /// measurement, so it is the async-aware mutex.
    static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

    #[tokio::test]
    async fn counts_one_zeroed_allocation_exactly() {
        let _serial = SERIAL.lock().await;
        let (buf, counts) = measure_async(async { vec![0u8; 16] }).await;
        assert_eq!(buf.len(), 16);
        assert_eq!(
            counts,
            Counts {
                allocs: 1,
                reallocs: 0,
                bytes: 16,
                zeroed: 1,
            }
        );
    }

    #[tokio::test]
    async fn counts_nothing_when_nothing_is_allocated() {
        let _serial = SERIAL.lock().await;
        let ((), counts) = measure_async(async {}).await;
        assert_eq!(
            counts,
            Counts {
                allocs: 0,
                reallocs: 0,
                bytes: 0,
                zeroed: 0,
            }
        );
    }

    /// A grow is counted apart from a fresh allocation: the header rows gate on
    /// `reallocs`, so the counter itself needs a test or a regression that
    /// stops tallying them would leave every row green.
    #[tokio::test]
    async fn counts_one_realloc_exactly() {
        let _serial = SERIAL.lock().await;
        let (buf, counts) = measure_async(async {
            let mut vec = Vec::with_capacity(1);
            vec.extend_from_slice(&[0u8; 8]);
            vec
        })
        .await;
        assert_eq!(buf.len(), 8);
        assert_eq!(counts.allocs, 1);
        assert_eq!(counts.reallocs, 1);
        assert!(counts.bytes >= 8);
        assert_eq!(counts.zeroed, 0);
    }

    /// Nesting is a hard error, and the guard must have cleared it on unwind so
    /// the next measurement is not told it was nested.
    #[tokio::test]
    #[should_panic(expected = "allocation measurements cannot be nested")]
    async fn nesting_is_refused() {
        let _serial = SERIAL.lock().await;
        let _ = measure_async(async {
            let _ = measure_async(async {}).await;
        })
        .await;
    }
}
