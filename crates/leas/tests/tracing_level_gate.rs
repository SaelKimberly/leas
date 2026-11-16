//! Guard for the process-wide TRACE cap.
//!
//! `turso_core` takes its traced VDBE loop — one explain `String` per opcode —
//! whenever `tracing::enabled!(TRACE)` answers true, so dropping the cap from
//! [`leas::logging::cap_trace`] silently restores a 2.5 M-allocation boot
//! (`docs/aegis/specs/2026-11-16-boot-allocation-burst-design.md`). This test
//! builds a stack shaped like the production one — a layer whose `EnvFilter`
//! asks for `trace` — and asserts the cap wins.
//!
//! It lives in `tests/` because installing a global subscriber is a
//! once-per-process operation.

use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

struct Noop;

impl<S: tracing::Subscriber> Layer<S> for Noop {}

#[test]
fn trace_is_disabled_across_the_process() {
    let stack = tracing_subscriber::registry().with(Noop.with_filter(
        tracing_subscriber::EnvFilter::new("trace,hickory_net::h2=error"),
    ));
    leas::logging::cap_trace(stack)
        .try_init()
        .expect("fresh process: the global subscriber is unset");

    assert!(
        !tracing::enabled!(target: "turso_core::vdbe", tracing::Level::TRACE),
        "TRACE must be off for a dependency that gates a costlier path on it"
    );
    assert!(
        !tracing::enabled!(target: "totally_bogus_target", tracing::Level::TRACE),
        "TRACE must be off process-wide, whatever the target or layer filter"
    );
    assert!(
        tracing::enabled!(tracing::Level::DEBUG),
        "the cap stops at DEBUG: the DB monitor's debug events must still flow"
    );
    assert!(
        tracing::enabled!(target: "totally_bogus_target", tracing::Level::INFO),
        "INFO must stay enabled"
    );
}
