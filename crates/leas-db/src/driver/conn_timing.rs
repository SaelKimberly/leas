//! Completion-time split of a DB statement: pool checkout vs execution.
//!
//! The 2026-11-24 audit (§6) recorded two statements at 806 s / 812 s against a
//! 5 s busy ceiling and could not attribute them: a long write transaction,
//! a process-wide stall, and wall-clock inflation were all still open. Toasty's
//! `QueryLog` times the EXEC with a monotonic `Instant` but says nothing about
//! the checkout, and it owns that event — so the split is two small WARN lines
//! at the two boundaries we own, with the numbers IN THE MESSAGE because
//! `TuiLogLayer` drops structured fields from the persisted log.
//!
//! No heartbeat: `exec_sql_inner` holds a prepared statement/rows cursor and a
//! `&mut QueryLog` across async I/O, so a `select!`/spawned tick that drops it
//! is not cancellation-safe. A Database-scoped watcher is the shape if one is
//! ever needed, not a per-statement task.

// `DbMonitorLayer` folds EVERY `toasty::query` event as a query. A timing
// line at that target has no `duration_ms` field, so it would become a fake
// 0 ms sample and dilute `mean_ms`/`p50`/`p99` on the `d`-key dump. One
// shared const keeps the emitters and the regression test bound together.
pub const TARGET: &str = "leas_db";

use std::time::Duration;

/// A checkout longer than this is worth its own line. Below the 5 s busy
/// ceiling, so a pool waiting on the single-writer lock is visible before it
/// gives up.
pub const POOL_WAIT_WARN: Duration = Duration::from_millis(250);

/// Matches toasty's own `QueryLogConfig::default().slow_statement_threshold`.
/// The exec line therefore fires exactly when the existing `slow query` line
/// does — no new class of noise.
pub const EXEC_WARN: Duration = Duration::from_secs(1);

/// True when either boundary crossed its threshold. Fast statements produce
/// no line and no allocation.
pub fn is_slow(pool_wait: Duration, exec: Duration) -> bool {
    pool_wait >= POOL_WAIT_WARN || exec >= EXEC_WARN
}

/// The persisted message for one slow boundary. `stage` is a static label and
/// `ms` is a duration — no URL, config, or bind value can reach the log.
pub fn timing_message(stage: &str, ms: f64) -> String {
    match stage {
        "checkout" => format!("db timing: stage=checkout pool_wait_ms={ms:.1}"),
        _ => format!("db timing: stage=exec exec_ms={ms:.1}"),
    }
}

/// Emit one WARN iff the checkout was slow. Called from `Database::conn()`.
pub fn report_checkout(wait: Duration) {
    if is_slow(wait, Duration::ZERO) {
        tracing::warn!(
            target: TARGET,
            "{}",
            timing_message("checkout", wait.as_secs_f64() * 1e3)
        );
    }
}

/// Emit one WARN iff execution was slow. Called from `Connection::exec_sql`.
pub fn report_exec(exec: Duration) {
    if is_slow(Duration::ZERO, exec) {
        tracing::warn!(
            target: TARGET,
            "{}",
            timing_message("exec", exec.as_secs_f64() * 1e3)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_timing_target_is_not_the_query_target() {
        assert_ne!(TARGET, "toasty::query", "DbMonitorLayer would fold it");
    }

    #[test]
    fn fast_checkout_and_fast_exec_are_not_reported() {
        assert!(!is_slow(Duration::from_millis(1), Duration::from_millis(5)));
    }

    #[test]
    fn a_starved_checkout_is_reported_even_when_exec_is_fast() {
        assert!(is_slow(
            Duration::from_millis(260),
            Duration::from_millis(5)
        ));
    }

    #[test]
    fn a_slow_exec_is_reported_even_when_checkout_is_fast() {
        assert!(is_slow(
            Duration::from_millis(1),
            Duration::from_millis(1000)
        ));
    }

    #[test]
    fn the_exact_thresholds_are_the_boundaries() {
        assert!(!is_slow(
            Duration::from_millis(249),
            Duration::from_millis(999)
        ));
        assert!(is_slow(POOL_WAIT_WARN, Duration::ZERO));
        assert!(is_slow(Duration::ZERO, EXEC_WARN));
    }

    #[test]
    fn the_two_stages_have_distinct_labels() {
        assert_eq!(
            timing_message("checkout", 260.0),
            "db timing: stage=checkout pool_wait_ms=260.0"
        );
        assert_eq!(
            timing_message("exec", 812_000.0),
            "db timing: stage=exec exec_ms=812000.0"
        );
    }
}
