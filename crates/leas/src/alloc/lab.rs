//! Allocator cost lab: wall time and RSS of the batch allocation shape.
//!
//! Not a test: prints a table and asserts nothing. Run with
//! `cargo test -p leas --release --lib --features perf-lab -- --ignored --nocapture alloc_lab`
//! and `LEAS_ALLOC_PURGE_DELAY` = 1000 (the default), 0, or -1. The 0 and -1
//! rows exist to show the purge-policy cost, not because the app sets them.

use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

/// `mi_option_purge_delay` in mimalloc 3.x's `mi_option_e` (15th enumerator).
const MI_OPTION_PURGE_DELAY: i32 = 15;

unsafe extern "C" {
    fn mi_option_set(option: i32, value: std::ffi::c_long);
    fn mi_option_get(option: i32) -> std::ffi::c_long;
    fn mi_process_info(
        elapsed_msecs: *mut usize,
        user_msecs: *mut usize,
        system_msecs: *mut usize,
        current_rss: *mut usize,
        peak_rss: *mut usize,
        current_commit: *mut usize,
        peak_commit: *mut usize,
        page_faults: *mut usize,
    );
}

/// `(current_rss, peak_rss, current_commit, peak_commit)` in bytes.
fn rss() -> (usize, usize, usize, usize) {
    let (mut cur, mut peak, mut commit, mut peak_commit) = (0, 0, 0, 0);
    // SAFETY: each out-pointer names a live local `usize`; the unused ones are null.
    unsafe {
        mi_process_info(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut cur,
            &raw mut peak,
            &raw mut commit,
            &raw mut peak_commit,
            std::ptr::null_mut(),
        );
    }
    (cur, peak, commit, peak_commit)
}

const fn mib(bytes: usize) -> usize {
    bytes >> 20
}

const LINKS: usize = 13_803;

/// The feed-plan shape: a burst of short-lived strings plus many small maps.
fn phase_burst() {
    for _ in 0..20 {
        let mut links = Vec::with_capacity(LINKS);
        for i in 0..LINKS {
            links.push(format!(
                "vless://00000000-0000-0000-0000-00000000{i:04}@h:443"
            ));
        }
        let mut maps = Vec::with_capacity(512);
        for m in 0..512u64 {
            let mut map = HashMap::with_capacity(16);
            for k in 0..16u64 {
                map.insert(m * 16 + k, k);
            }
            maps.push(map);
        }
        black_box((links.len(), maps.len()));
    }
}

/// Many independent short-lived buffers, the per-host churn of a batch.
fn phase_threads() {
    let mut handles = Vec::with_capacity(8);
    for t in 0..8u64 {
        handles.push(std::thread::spawn(move || {
            let mut seed = t.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut live: Vec<Vec<u8>> = Vec::with_capacity(256);
            for _ in 0..100_000u64 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let len = 32 + usize::try_from(seed % 481).expect("481 fits in usize");
                live.push(vec![0u8; len]);
                if live.len() == 256 {
                    live.clear();
                }
            }
            black_box(live.len());
        }));
    }
    for handle in handles {
        handle.join().expect("lab thread panicked");
    }
}

/// One heap per blocking thread, the app's batch shape (262 threads).
fn phase_many_threads(n: usize) {
    let mut handles = Vec::with_capacity(n);
    for t in 0..n {
        handles.push(std::thread::spawn(move || {
            let mut seed = (t as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut live: Vec<Vec<u8>> = Vec::with_capacity(64);
            for _ in 0..1_000u64 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let len = 32 + usize::try_from(seed % 481).expect("481 fits in usize");
                live.push(vec![0u8; len]);
                if live.len() == 64 {
                    live.clear();
                }
            }
            black_box(live.len());
        }));
    }
    for handle in handles {
        handle.join().expect("lab thread panicked");
    }
}

#[test]
#[ignore = "perf lab: prints a table, asserts nothing"]
fn alloc_lab() {
    let delay: std::ffi::c_long = std::env::var("LEAS_ALLOC_PURGE_DELAY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    // SAFETY: `mi_option_set` takes an option index and an integer.
    unsafe { mi_option_set(MI_OPTION_PURGE_DELAY, delay) };

    let t = Instant::now();
    phase_burst();
    let burst = t.elapsed();
    let after = rss();

    let t = Instant::now();
    super::release_freed_heap();
    let collect = t.elapsed();
    let settled = rss();

    let t = Instant::now();
    phase_threads();
    let threads = t.elapsed();

    let t = Instant::now();
    phase_many_threads(262);
    let many = t.elapsed();
    let end = rss();
    let t = Instant::now();
    super::release_freed_heap();
    let end_collect = t.elapsed();
    let end_settle = rss();

    // SAFETY: `mi_option_get` takes an option index and returns an integer.
    let effective = unsafe { mi_option_get(MI_OPTION_PURGE_DELAY) };

    println!(
        "pd={effective} delay={delay:>4} burst={:>7.1}ms threads={:>7.1}ms many={:>7.1}ms \
         collect={:>6.2}ms endcollect={:>6.2}ms rss={}/{}MiB commit={}/{}MiB settled={}MiB \
         end={}MiB endsettle={}MiB",
        burst.as_secs_f64() * 1e3,
        threads.as_secs_f64() * 1e3,
        many.as_secs_f64() * 1e3,
        collect.as_secs_f64() * 1e3,
        end_collect.as_secs_f64() * 1e3,
        mib(after.0),
        mib(after.1),
        mib(after.2),
        mib(after.3),
        mib(settled.0),
        mib(end.0),
        mib(end_settle.0),
    );
}
