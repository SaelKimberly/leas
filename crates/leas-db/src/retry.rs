//! Retry helpers for `SQLite` write contention.
//!
//! toasty transactions that collide with a concurrent writer surface
//! `serialization failure: database is locked`. The enrichment pipeline and
//! the ping-buffer flush write from many spawned tasks at once, so a busy DB
//! is normal under load — retry with backoff instead of dropping the write.

use std::future::Future;
use std::time::Duration;

use crate::error::{DatabaseError, Result};

/// True when the error is `SQLite` write contention: toasty's
/// serialization-failure classification, or the raw "database is locked"
/// driver message.
#[must_use]
pub fn is_busy_error(err: &DatabaseError) -> bool {
    matches!(err, DatabaseError::Toasty(e) if e.is_serialization_failure())
        || err.to_string().contains("database is locked")
}

/// Run `op`, retrying up to `attempts` extra times when it fails with `SQLite`
/// write contention, with exponential backoff (20 ms doubling, 1.28 s cap) and
/// **full jitter**. Non-busy errors pass through immediately, unchanged.
///
/// # Why jitter
///
/// A fixed backoff is a **metastable** one: every writer that collides in the
/// same millisecond retries in the same millisecond, forever, so the database
/// never drains. The 2026-10-01 run measured this directly — ~1,000 concurrent
/// single-row writers, an un-jittered ladder, and **88 abandoned country
/// writes** in a 30 s burst.
///
/// The jitter source is a process-local xorshift seeded from the wall clock, so
/// no new dependency is introduced and no `rand` feature is pulled in. The
/// attempt count and the ~1.28 s ceiling are unchanged: the MVCC rollout plan
/// forbids *removing* retries, and this only spreads them.
#[must_use]
pub fn jittered_backoff(attempt: u32) -> Duration {
    let ceiling_ms = 20u64 << attempt.min(6);
    Duration::from_millis(pick_jitter(ceiling_ms))
}

/// A value in `0..=ceiling_ms`, unique per caller.
///
/// The draw MUST come from an **atomic read-modify-write**, not a relaxed load
/// followed by a store: the callers that collide are exactly the concurrent
/// ones, so a load/store race hands them all the SAME state and re-syncs them —
/// defeating the entire point. `fetch_add` returns the prior value, so every
/// caller draws from a distinct one.
fn pick_jitter(ceiling_ms: u64) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// Odd stride: successive prior values are never congruent modulo a power
    /// of two, so the low rungs still spread rather than stepping evenly.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let prior = NEXT.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let mixed = prior
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    mixed % ceiling_ms.saturating_add(1)
}

/// Total time ONE operation may spend retrying before it fails.
///
/// The attempt count alone does not bound the wait: each attempt carries the
/// driver's 5 s busy ceiling, so the 5–8 attempt ladders used across
/// `Database` could hold one caller 25–40 s — and every queued operation sits
/// behind it on the pool. The 2026-11-23/24 window measured 455 statements
/// ≥ 1 s and plan queries answering in 772 s while writers laddered. Failing
/// the OPERATION at a bounded time keeps the UI's read from queueing behind
/// it: 15 s is already three full busy ceilings, so only a pathologically
/// contended ladder is cut short. What a refusal costs depends on the caller:
/// the write-behind driver re-stages its window; the enrichment flush drops
/// that pass's resolutions, and the session's TTL gate (which reads the
/// session entry, not the persisted stamp) re-resolves the host when it
/// expires — the cost is a delay, never a lost row.
const BUSY_RETRY_BUDGET: Duration = Duration::from_secs(15);

/// Run `op`, retrying up to `attempts` extra times when it fails with `SQLite`
/// write contention, with exponential backoff and full jitter.
/// Non-busy errors pass through immediately, unchanged.
pub async fn retry_on_busy<T, F, Fut>(op: F, attempts: u32) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    retry_on_busy_within(op, attempts, BUSY_RETRY_BUDGET).await
}

/// [`retry_on_busy`] with an explicit total budget — the seam a test uses to
/// pin the bound without waiting for the shipped value.
pub async fn retry_on_busy_within<T, F, Fut>(
    mut op: F,
    attempts: u32,
    budget: Duration,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let started = tokio::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        match op().await {
            Err(err) if is_busy_error(&err) && attempt < attempts && started.elapsed() < budget => {
                tokio::time::sleep(jittered_backoff(attempt)).await;
                attempt += 1;
            }
            other => {
                // Publish the final retry count to the enclosing `Database`
                // method span (declared `fields(retries = Empty)`); a no-op
                // when the caller is not instrumented.
                tracing::Span::current().record("retries", u64::from(attempt));
                return other;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::error::DatabaseError;

    fn busy() -> DatabaseError {
        DatabaseError::Toasty(toasty::Error::serialization_failure("database is locked"))
    }

    /// The ladder stays inside its ceiling at every rung — jitter must not
    /// weaken the bound. Growth is asserted on the CEILINGS (below), not on
    /// individual draws.
    #[test]
    fn jittered_backoff_stays_within_its_ceiling() {
        for attempt in 0..8u32 {
            let ceiling = 20u64 << attempt.min(6);
            for _ in 0..64 {
                let ms = jittered_backoff(attempt).as_millis();
                let ms = u64::try_from(ms).expect("ms fits u64");
                assert!(
                    ms <= ceiling,
                    "attempt {attempt}: {ms}ms exceeded the {ceiling}ms ceiling",
                );
            }
        }
        // Under FULL jitter the CEILINGS grow, not the draws: attempt 3 draws
        // from 0..=160 and attempt 0 from 0..=20, so those ranges overlap and a
        // single draw from the larger one may legitimately fall below the
        // smaller. Asserting on draws would contradict the strategy — the
        // distinctness test above is what covers spreading.
    }

    /// The regression T4 exists to stop: a FIXED ladder makes every collided
    /// writer retry in lockstep, so the database never drains. Draws must spread.
    #[test]
    fn consecutive_conflicting_callers_draw_distinct_waits() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            seen.insert(jittered_backoff(4).as_millis());
        }
        assert!(
            seen.len() >= 16,
            "32 colliding writers should not share fewer than 16 distinct waits, got {}",
            seen.len(),
        );
    }

    #[tokio::test]
    async fn retries_serialization_failures_then_succeeds() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let result = retry_on_busy(
            move || {
                let c = c.clone();
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 3 { Err(busy()) } else { Ok(42u32) }
                }
            },
            5,
        )
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn gives_up_after_attempts() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let result = retry_on_busy(
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>(busy())
                }
            },
            2,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
    }

    /// The budget is what bounds the WAIT, not the attempt count: the old
    /// ladder would call this op `attempts + 1` times. Failing the operation
    /// at the budget is the point — the plan read queues behind it otherwise.
    #[tokio::test]
    async fn a_zero_budget_spends_no_retry() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let result = retry_on_busy_within(
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>(busy())
                }
            },
            5,
            Duration::ZERO,
        )
        .await;
        assert!(result.is_err(), "the busy error must surface, not vanish");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The shipped budget, with attempts that each burn the driver's 5 s
    /// busy ceiling: three attempts already fill 15 s, so the ladder stops
    /// there instead of exhausting its five rungs (the old code called the op
    /// six times). Paused time makes the 15 s instant, not a test wait.
    #[tokio::test(start_paused = true)]
    async fn the_shipped_budget_stops_a_slow_ladder_at_three_attempts() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let result = retry_on_busy(
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    Err::<(), _>(busy())
                }
            },
            5,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn does_not_retry_non_busy_errors() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let result = retry_on_busy(
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>(DatabaseError::Generic("boom".into()))
                }
            },
            5,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn classifies_busy_errors() {
        assert!(is_busy_error(&busy()));
        assert!(is_busy_error(&DatabaseError::Toasty(
            toasty::Error::from_args(format_args!(
                "transaction serialization failure: database is locked"
            ))
        )));
        assert!(!is_busy_error(&DatabaseError::Generic("boom".into())));
    }
}
