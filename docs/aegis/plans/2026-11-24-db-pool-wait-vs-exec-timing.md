# DB pool-wait vs exec timing — implementation plan (audit G9)

> **For agentic workers:** implement task-by-task; every step ends with a focused check.

**Goal:** make the next 800 s statement self-explaining: print checkout time separately from statement execution time, so the operator can tell a starved pool from a slow write — without a heartbeat, a spawned task, or a per-statement allocation.

**Architecture:** the two measurable boundaries are both ours. `Database::conn()` wraps the single `self.db.connection().await` (toasty's pool checkout); `Connection::exec_sql` wraps `exec_sql_inner` with toasty's `QueryLog`. One internal `driver::conn_timing` module owns the two thresholds and two WARN emitters. Each boundary emits its own line — `stage=checkout pool_wait_ms=…` and `stage=exec exec_ms=…` — with the number IN THE MESSAGE, because `TuiLogLayer` drops structured fields from the persisted heed store. The target is `leas_db`, NOT `toasty::query`: `DbMonitorLayer` folds every `toasty::query` event as a query, so a timing line there would become a fake 0 ms sample in the `d`-key dump. No change to toasty-core, no new line for fast statements, no shared state between the two boundaries.

**Tech Stack:** Rust 2024, `tracing`, `toasty` 0.11 / `toasty-core` 0.11, local vendored `leas-db::driver`, `cargo nextest run` (focused), workspace clippy (`-D warnings --all-targets --all-features`).

**Spec:** `docs/research/2026-11-24-log-and-failure-audit.md` §6 (G9 in §11): "Instrument before changing: log `pool_wait_ms` separately from `exec_ms`, and add a 5 s heartbeat line while a statement is in flight; that separates (1)/(2)/(3) in one run." The heartbeat half is deliberately NOT in scope (see Risks).

## Global Constraints

- `AGENTS.md`: every hand-written crate opts into `[lints] workspace = true`; "tests must discriminate a plausible consumer-visible bug"; comments explain WHY, not what; Conventional Commit subject.
- No full test suite. Focused: `cargo nextest run -p leas-db`, the `leas` `ops::events`/`ops::subscriptions` groups, workspace clippy, `cargo fmt --check`.
- User's uncommitted files stay untouched: `refresh.py`, `docs/research/INDEX.md`, `docs/research/2026-11-23-ferrox-comparison.md`, `docs/research/2026-11-24-tls-engine-enhance-vs-rewrite.md`.
- No new dependency, no new crate, no schema/DDL change, no `PRAGMA user_version` bump (observability only).
- Zero allocation per fast statement: one `Instant::now()` per checkout and one per exec are the entire added cost. `just hotpath` is not required — `leas-hotpath` does not link `leas-db`.
- TRACE is off process-wide (`logging.rs::cap_trace`); WARN is the only level that reaches the persisted log.
- Log leak rule: `TuiLogLayer` drops DEBUG/TRACE and all structured fields except a 5-entry allowlist. Both times therefore live in the event MESSAGE; no bind value, URL or config is ever rendered by the new code. `DbMonitorLayer` (`crates/leas/src/ops/db_monitor.rs:250,374`) filters on `toasty::query` only and would fold a stray timing event as a 0 ms query; hence target `leas_db`.

## Review Focus

1. A fast statement (`< 1 s` exec, `< 250 ms` checkout) emits NO new line and allocates nothing — a 190 708-probe batch must not turn into a log wall. Pinned by `fast_checkout_and_fast_exec_are_not_reported` and `the_exact_thresholds_are_the_boundaries`.
2. A slow checkout with a FAST exec is still reported — gating only on exec time would hide pool starvation, the §6 plan-latency suspect. Pinned by `a_starved_checkout_is_reported_even_when_exec_is_fast`.
3. A slow exec with a FAST checkout is reported independently, with a distinct label — the two numbers must not be conflated. Pinned by `a_slow_exec_is_reported_even_when_checkout_is_fast` and `the_two_stages_have_distinct_labels`.
4. Both numbers are in the persisted message, not only in structured fields. Pinned by the exact-string assertions in `the_two_stages_have_distinct_labels`.
5. No URL, config, or bind value reaches the new line; only `Duration`s and a static stage label. The formatter takes `(&str, f64)` only.

## File Structure

- `crates/leas-db/src/driver/conn_timing.rs` (new) — thresholds, the pure predicate, the message formatter, the two emitters, and their tests.
- `crates/leas-db/src/driver/mod.rs` — declares `pub(crate) mod conn_timing;` and calls `report_exec` from `exec_sql`.
- `crates/leas-db/src/database.rs` — `conn()` calls `report_checkout`.
- `docs/aegis/INDEX.md` — one row for this plan.
- `lib.rs` is NOT touched: the module is an internal detail of `driver`, reached from `database.rs` as `crate::driver::conn_timing`.

---

### Task 1: the timing helper (pure, tested)

**Files:**
- Create: `crates/leas-db/src/driver/conn_timing.rs`
- Modify: `crates/leas-db/src/driver/mod.rs` (one `pub(crate) mod conn_timing;` line)

**Interfaces:**
- Consumes: `std::time::Duration`, `tracing::warn!`.
- Produces:
  - `pub const POOL_WAIT_WARN: Duration` = 250 ms.
  - `pub const EXEC_WARN: Duration` = 1 s (matches `QueryLogConfig::default().slow_statement_threshold`).
  - `pub fn is_slow(pool_wait: Duration, exec: Duration) -> bool` — the pure predicate the emitters and tests share.
  - `pub fn timing_message(stage: &str, ms: f64) -> String` — exact persisted shape.
  - `pub fn report_checkout(wait: Duration)` and `pub fn report_exec(exec: Duration)` — one WARN each, only past their threshold.

**Steps:**

- [ ] Step 1: write the five failing tests FIRST (exact boundaries, distinct labels):

```rust
#[test]
fn fast_checkout_and_fast_exec_are_not_reported() {
    assert!(!is_slow(Duration::from_millis(1), Duration::from_millis(5)));
}

#[test]
fn a_starved_checkout_is_reported_even_when_exec_is_fast() {
    assert!(is_slow(Duration::from_millis(260), Duration::from_millis(5)));
}

#[test]
fn a_slow_exec_is_reported_even_when_checkout_is_fast() {
    assert!(is_slow(Duration::from_millis(1), Duration::from_millis(1000)));
}

#[test]
fn the_exact_thresholds_are_the_boundaries() {
    assert!(!is_slow(Duration::from_millis(249), Duration::from_millis(999)));
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
```

- [ ] Step 2: `cargo nextest run -p leas-db 'conn_timing'` → FAIL (module/functions missing). `is_slow` must be a plain `fn`, NOT `const fn`: `Duration` comparison is not a const operator (E0015).

- [ ] Step 3: implement the module. `report_checkout`/`report_exec` call `is_slow(wait, ZERO)` / `is_slow(ZERO, exec)` so the predicate is the single owner of the thresholds (and cannot drift into dead code). Numbers are `as_secs_f64() * 1e3` formatted with `{ms:.1}` inside the message.

- [ ] Step 4: `cargo nextest run -p leas-db 'conn_timing'` → 6 PASS.

### Task 2: time the checkout in `Database::conn()`

**Files:**
- Modify: `crates/leas-db/src/database.rs:689-696`

**Interfaces:**
- Consumes: `crate::driver::conn_timing::report_checkout`.
- Produces: no API change; `conn()` stays `async fn conn(&self) -> Result<toasty::Connection>`.

**Steps:**

- [ ] Step 1: start an `Instant` before `self.db.connection().await`, bind the RESULT, call `report_checkout(started.elapsed())` BEFORE `?` — a checkout that waited and then failed is the most pathological case and must still be reported. Keep the existing comment about the pool's create hook (it explains why the per-connection PRAGMAs are NOT re-issued here).

```rust
async fn conn(&self) -> Result<toasty::Connection> {
    let started = std::time::Instant::now();
    let conn = self.db.connection().await;
    crate::driver::conn_timing::report_checkout(started.elapsed());
    let conn = conn?;
    // ... existing comment ...
    Ok(conn)
}
```

- [ ] Step 2: `cargo check -p leas-db` → clean.

### Task 3: time the exec in `Connection::exec_sql`

**Files:**
- Modify: `crates/leas-db/src/driver/mod.rs:541-545`

**Interfaces:**
- Consumes: `conn_timing::report_exec`, `Instant` (already imported at `mod.rs:60`).
- Produces: no API change; `QueryLog::finish(&result)` stays on every path.

**Steps:**

- [ ] Step 1: capture `Instant::now()` after `QueryLog::sql` (so the new span matches the existing `duration_ms` exactly), call `report_exec(started.elapsed())` after `log.finish(&result)`, before returning `result`.

- [ ] Step 2: `cargo check -p leas-db` → clean.

### Task 4: verify at the boundaries, once

- [ ] Step 1: `cargo nextest run -p leas-db 'conn_timing'` → 6 PASS; `cargo nextest run -p leas-db` → 294 tests, 293 passed / 1 skipped.
- [ ] Step 2: `cargo nextest run -p leas 'ops::events' 'ops::subscriptions'` → unchanged, green.
- [ ] Step 3: `cargo fmt --check` → clean; `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings` → clean. The `-p leas-db -p leas` form is NOT authoritative here: without the workspace `--all-features` unification it trips the pre-existing `leas-native/src/transport/quic.rs:157` "very complex type" lint.
- [ ] Step 4: `docs/aegis/INDEX.md` — one row, marked executed.
- [ ] Step 5: one monitor regression test (`crates/leas/src/ops/db_monitor.rs::timing_events_are_not_folded_as_queries`) pins the target choice with the EXISTING `tracing_subscriber` dev-dep: emit both timing lines at `leas_db` and assert the dump keeps the real query and shows no 0 ms sample. No new dependency. The WARNs' own emission is not subscriber-tested (would need `tracing_test`); the pure predicate + exact message tests are the deterministic proof.

### Task 5: commit

- [ ] Step 1: `commit.draft()` / `take()` only our paths (`conn_timing.rs`, `driver/mod.rs`, `database.rs`, plan, INDEX row). NEVER stage `refresh.py` or the research docs.
- [ ] Step 2: subject `feat(db): split pool wait from exec time in slow-statement logs`. Body: the 806/812 s anomaly, the two boundaries, no heartbeat, no per-statement alloc.

## Verification (final, exact commands)

```
cargo nextest run -p leas-db 'conn_timing'
cargo nextest run -p leas-db
cargo nextest run -p leas 'ops::events' 'ops::subscriptions'
cargo fmt --check
cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings
```

No full suite (`just quality-gate` / bare `cargo nextest run`) — per the task instruction.

## Risks

- **No heartbeat.** The audit also asks for a 5 s in-flight heartbeat. That needs a Database-scoped watcher over shared state, NOT a `tokio::select!` around `exec_sql_inner`: that future owns a prepared statement/rows cursor and `QueryLog` is mutably borrowed into it, so dropping it on a tick is not cancellation-safe. A per-statement spawned task is the same bug plus an allocation per statement. Deferred deliberately; the completion-time split already separates "starved pool" from "slow exec" on the NEXT occurrence.
- **Wall vs monotonic.** `QueryLog` uses `std::time::Instant` (CLOCK_MONOTONIC), which rules out wall-clock adjustment inflation for the existing `duration_ms` and the new spans. It does NOT rule out a STOPPED process: SIGSTOP/VM pause still advances CLOCK_MONOTONIC, so suspend inflation remains open and is exactly what the deferred heartbeat would separate. The plan does not claim candidate (3) is closed.
- **Double line count.** At most two WARN lines per pathological statement (checkout + exec). The window's 455 slow statements would add ≤ 910 lines against 14 336; fast statements add ZERO.
- **Threshold choice.** 250 ms checkout is below the 5 s busy ceiling, so a pool waiting on the single-writer WAL lock is visible BEFORE it fails. 1 s exec matches toasty's own slow threshold, so the exec line fires exactly when the existing `slow query` line does — no new class of noise.
- **Persisted log.** `TuiLogLayer::on_event` drops DEBUG/TRACE and all structured fields except its 5-entry allowlist. Both new lines put their numbers in the MESSAGE, so they survive into the heed export the audit reads. No `db.params` (bind values, possibly `protocols.config`) is rendered.
- **G2 interaction.** `BUSY_RETRY_BUDGET` (15 s) already bounds a writer's total wait; this change does not alter retry behavior, only reports the checkout half.

## Retirement

If a future batch shows every slow statement is `stage=exec` with no checkout line, the contention theory (§6 candidate 1) is disproved and the next investigation moves to the statement/transaction itself, not the pool. If `stage=checkout` dominates, pool size / WAL single-writer is the target. Either way the 800 s anomaly stops being "unattributable". A true heartbeat is only worth building if BOTH halves are fast while the total is 800 s — which the completion-time split will show cannot be (the exec span includes the busy waits).

## Outcome

Implemented. `driver::conn_timing` owns the thresholds (250 ms / 1 s), the shared `is_slow` predicate, the exact message shape and the two WARN emitters; `Database::conn()` reports the checkout and `Connection::exec_sql` reports the exec, both with the ms in the persisted message. 6/6 `conn_timing` tests, 294 `leas-db` tests (1 skipped), `leas` `ops::events`/`ops::subscriptions` + `db_monitor::timing_events_are_not_folded_as_queries` green, `fmt --check` clean, workspace clippy green. No heartbeat, no task-local, no shared state, no schema change, no new dependency. Round 1 fixed: target `leas_db` (was `toasty::query`, which `DbMonitorLayer` would fold as a fake 0 ms query), checkout failures now reported before `?`, suspend-inflation claim corrected. Round 2 fixed: the target is now one shared `TARGET` const bound to both emitters and the monitor regression test, so a revert to `toasty::query` fails that test; the vacuous dump assertion was removed. Round 3 fixed: stale test counts and a comment direction word.
