//! Subscriber construction shared by the binary and its tests.
//!
//! A dependency can ask `tracing::enabled!` whether a level is on and then take
//! a costlier path when the answer is yes, so the *process-wide* answer is a
//! behaviour, not a logging detail. `turso_core` does exactly that: it runs its
//! traced VDBE interpreter loop when `TRACE` is enabled and formats one explain
//! `String` per opcode (`vdbe/mod.rs:2598`, `:4159`). Measured cost on a
//! 3 000-endpoint database: 2 545 487 allocations of a 2 574 862 boot, 91.6 MiB
//! churn (`docs/aegis/specs/2026-11-16-boot-allocation-burst-design.md`).
//!
//! Per-layer `EnvFilter` directives do not reach that question, so the cap is a
//! layer of its own: `cap_trace` appends an outermost [`LevelFilter::DEBUG`],
//! and `Layered::enabled` short-circuits on the outermost layer
//! (`tracing-subscriber/src/layer/layered.rs`), which is what makes
//! `enabled!(TRACE)` false everywhere.
//!
//! [`LevelFilter::DEBUG`]: tracing_subscriber::filter::LevelFilter::DEBUG

use tracing::Subscriber;
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt};

/// Appends the outermost level cap: `TRACE` is disabled for the whole process,
/// `DEBUG` and below keep flowing to every layer.
///
/// Call it last, on the fully composed stack, immediately before `try_init`.
pub fn cap_trace<S>(subscriber: S) -> impl Subscriber + Send + Sync + 'static
where
    S: Subscriber + Send + Sync + 'static,
{
    subscriber.with(LevelFilter::DEBUG)
}
