# Plan: Details Panel, DB Aggregates, Tasks Pane — Implementation

| Field | Value |
|---|---|
| Date | 2026-10-23 |
| Spec | `docs/aegis/specs/2026-10-22-details-metrics-tasks-design.md` |
| Status | ready to execute |
| Owner | `crates/leas/src/ui/`, `crates/leas/src/state.rs`, `crates/leas/src/ops/scheduler.rs` (new), `crates/leas-db/src/profiles_query.rs` |
| Baseline | `cargo nextest run --workspace` green; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean |

## Goal

Land the spec end to end in three slices:

1. **Slice 1 — the scheduler** (no UI): one in-memory job queue, the only
   entry point for any job, one shared stop flag, terminal-event ownership.
2. **Slice 2 — the panel**: the aggregate read (`leas-db`), the cached counts,
   the rebuilt Details panel, Metrics absorbing the Actions Log.
3. **Slice 3 — the Tasks pane**: the third pane-2 tab, the `LineGauge` bar,
   the queue list, the keys, the status bar, the quit path.

Plus a defect fix folded into slice 1: the pane-2 scroll arm swallows
`Alt+↑`/`Alt+↓` (spec D26, verified live against the running binary).

## Architecture

- **Scheduler** (`crates/leas/src/ops/scheduler.rs`, new): owns the queue
  (`Vec<TaskSpec>`), the running task (`Option<RunningTask>`), and the paused
  flag. It is called by the UI (enqueue) and by the event loop (drain). It calls
  the existing spawn functions — which are retired from the UI.
- **Aggregate read** (`leas-db`): two conditional-aggregation statements over
  `endpoint_rank`, one per scope, both index-served. Cached in `AppState`.
- **Details panel** (`crates/leas/src/ui/details.rs`, new): two columns — facts
  (left) and aggregates (right) — that stack below ~100 cols.
- **Tasks pane** (`crates/leas/src/ui/tasks.rs`, new): the bar row + the queue
  list.

## Tech Stack

Rust 2024, ratatui 0.30.2, toasty, tokio. **No new dependency** — `tui-slider`
is rejected (spec D30).

## Baseline / Authority Refs

- Spec D1–D50; §14 for the redesign.
- `AGENTS.md` gates: `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace`.
- `docs/reference/database-manual-sql.md` §1/§6 — the two new statements need a recorded cause + a test that runs them.
- `docs/reference/ordering-law.md` §8.1 — no `USE SORTER` on any new statement.
- `crates/leas/src/ui/mod.rs:684-694` (the D26 defect), `:758-771` (the resize arm).
- `crates/leas/src/ui/mod.rs:1075-1085` (pane-2 dispatch), `:1311-1375` (shell).
- `crates/leas/src/ui/actions_log.rs` (to be deleted), `ui/metrics.rs`, `ui/profiles.rs`.
- `crates/leas-db/src/profiles_query.rs:440-518` (the predicate builders), `:100-124` (`PlanScope::predicate`), `:634-693` (the count).

## Compatibility Boundary

- **In scope**: pane-2 content, the aggregate read, the scheduler, the Tasks
  pane, the shell's log row, the status bar's progress line.
- **Out of scope**: the Profiles table's columns, the ping pipeline's probe
  logic, the enrichment pipeline, the write path, the ordering law.
- **Deleted**: `ui/actions_log.rs` (retired, not migrated — its content moves to
  Metrics, its log tail to the shell log row, its bars to the Tasks pane).
- **New raw SQL**: two statements, recorded in `database-manual-sql.md`.
- **No schema change**: no migration, no `SCHEMA_VERSION` bump.

## Change Necessity

Code is necessary: the Details panel is a new render, the aggregates are a new
DB read with a new cached owner, the scheduler is a new owner of job lifecycle,
and the Tasks pane is a new tab. Docs/config cannot express any of it. The
minimum boundary is the four owners above.

## TDD Route

| Field | Value |
|---|---|
| Mode | auto |
| Decision | **strict** for slice 1 (shared/core lifecycle + the D26 bugfix) and the aggregate read (contract + new raw SQL); **light** for the render-only slices 2–3 |
| Authority | repo test culture: `AGENTS.md` ("a test earns its place by discriminating a plausible consumer-visible bug") + the executed `2026-10-21-merged-test-pipeline` spec; the spec's acceptance A1–A22 |
| Test posture | failing-test-first for the scheduler's state transitions and the aggregate buckets; focused checks for the render slices |
| Reason | the scheduler's transitions (enqueue/drain/pause/skip/cancel) and the bucket partition are behaviour with consumer-visible failure modes; the renders are presentation |
| Verification | the full gate + the `tui-test` scenarios |

## Tasks

### Slice 1 — the scheduler (no UI)

**T1.1 — Task identity and the scheduler owner**
- Files: `crates/leas/src/types.rs` (or `ops/scheduler.rs`), `crates/leas/src/state.rs`
- Add `TaskKind` (Batch/RealBatch/FastBatch/FillExitIps/Compact/DnsRetry/Single), `TaskSpec { kind, scope, label, endpoint: Option<(i64, i64)> }`, and `RunningTask { spec, meters }`. Add `task_queue: VecDeque<TaskSpec>`, `running_task: Option<Arc<RunningTask>>`, `scheduler_paused: bool` to `AppState`.
- Verify: unit test that the fields round-trip.

**T1.2 — Enqueue + dedup**
- Files: `crates/leas/src/ops/scheduler.rs` (new)
- `enqueue(state, spec)`: ignore a duplicate identity (queued or running) with a log line; else push to the back and drain if idle.
- Verify: unit test — duplicate `(kind, scope)` → queue len 1; enqueue while running → ignored.

**T1.3 — Drain + terminal events + stale scope**
- Files: `crates/leas/src/ops/scheduler.rs`, `crates/leas/src/ops/events.rs`
- On `BatchEnded`/`CompactFinished`/`MaintenanceDone`: match the event to the running task's kind; a mismatch is a logged stray event and clears nothing. On a match: clear the meters, mark the outcome, and — if not paused — start the head. A head whose scope is empty is skipped with a log line.
- Verify: unit test — a stray event clears nothing; a stale-scope head is skipped and the next starts.

**T1.4 — One shared stop flag at each kind's safe boundary**
- Files: `crates/leas/src/ops/scheduler.rs`, `crates/leas/src/ops/ping.rs`, `crates/leas/src/ops/compact.rs`
- Batch checks at the dispatch boundary (`ping.rs:1378`, existing); fill between links; compact **between merges** (never inside a transaction); DNS retry between lookups. `s` sets the flag and pauses.
- Verify: unit test — a stop mid-compact leaves the merge loop between merges.

**T1.5 — Retire the direct spawn paths**
- Files: `crates/leas/src/ui/mod.rs:591-613`, `crates/leas/src/state.rs:1005-1015`
- The four `start_*_ping` wrappers enqueue instead of spawning. The four batch/compact spawns are called only by the scheduler.
- Verify: unit test — the UI's test keys enqueue, not start.

**T1.6 — D26: the ALT exclusion (defect fix)**
- Files: `crates/leas/src/ui/mod.rs:684-694`
- Add `&& !key.modifiers.contains(KeyModifiers::ALT)` to the pane-2 scroll arm (and the Details arm in slice 3).
- Verify: unit test — `Alt+Up` with pane 2 focused changes `pane2_height`, not the scroll offset.

### Slice 2 — the panel

**T2.1 — The aggregate read**
- Files: `crates/leas-db/src/profiles_query.rs`, `docs/reference/database-manual-sql.md`
- Two statements (global + view), the six bucket columns, `PlanScope::predicate`'s arms verbatim (D28). Record the cause + the inventory row.
- Verify: integration test that runs both statements — the partition sum, the view total matching `profiles_count_with`, the live-`alive` case.

**T2.2 — The cache + refresh triggers**
- Files: `crates/leas/src/state.rs`, `crates/leas/src/ui/mod.rs`
- A cached `AggregateCounts` + the scope key; refresh on filter/view/search/group change and on job events, **no timer** (D21).
- Verify: unit test — no refresh after N idle frames; refresh after a filter change.

**T2.3 — The Details panel**
- Files: `crates/leas/src/ui/details.rs` (new), `crates/leas/src/ui/mod.rs`
- Two columns (facts left, aggregates right), the `Server`/`Link` groups, the facts-column scroll offset, the cursor law, the `—` for a missing `endpoint_info` (no fill).
- Verify: unit test on `TestBackend` — two columns at 120 cols, stacked at 80; the cursor law under a filter; the `—` with no write.

**T2.4 — Metrics absorbs the Actions Log**
- Files: `crates/leas/src/ui/metrics.rs`
- Add the connection-status section; drop the duplicated traffic/log rows (D1).
- Verify: unit test — the section order and the dropped rows.

**T2.5 — Delete `ui/actions_log.rs`**
- Files: `crates/leas/src/ui/actions_log.rs`, `crates/leas/src/ui/mod.rs`
- Delete the module; move its tests to `metrics.rs`.
- Verify: the gate compiles; the moved tests pass.

### Slice 3 — the Tasks pane

**T3.1 — The third tab + heights**
- Files: `crates/leas/src/types.rs`, `crates/leas/src/state.rs:267-275`, `crates/leas/src/ui/mod.rs`
- `Pane2Tab::Tasks`; `pane2_rows()` gains a third arm (Tasks 10); the tab bar's third label.
- Verify: unit test — the tab cycles; the heights.

**T3.2 — The bar**
- Files: `crates/leas/src/ui/tasks.rs` (new)
- `LineGauge` with `filled_symbol("━")`/`unfilled_symbol("─")`, themed via `ThemeStyles::progress_fill`/`progress_bar`; the thumb at `floor(width * done/total)`; the label `<Task> <done>/<total> <ETA>`.
- Verify: unit test — the fill/thumb math.

**T3.3 — The queue list + keys**
- Files: `crates/leas/src/ui/tasks.rs`, `crates/leas/src/ui/mod.rs`
- The list (queued only, earliest first), the cursor + scroll, `d`/`s`/`r` scoped to the Tasks tab.
- Verify: unit test — the list has exactly the queued rows; `d` removes; `s` pauses; `r` resumes.

**T3.4 — Menu enqueue + busy predicate**
- Files: `crates/leas/src/ui/mod.rs:1519-1545`
- The menu's schedulable items enqueue; `Remove Bad Servers`/`Clear All Stats` are disabled while `running || queued || paused`.
- Verify: unit test — the items grey when busy.

**T3.5 — Status bar + quit**
- Files: `crates/leas/src/ui/status_bar.rs`, `crates/leas/src/ui/mod.rs:315-358`
- The status bar shows the running task's name + done/total; quitting cancels the running task and discards the queue, logging each queued task.
- Verify: unit test — the status line; the quit log lines.

**T3.6 — Docs**
- Files: `docs/guides/tui-manual.md`, `docs/aegis/INDEX.md`
- The Details/Metrics/Tasks sections, `F1`, the keybinding tables, the heights, the log row.
- Verify: the manual's keybinding table matches the code.

## Verification

Per task: the unit/integration test named in the task. Per slice: `cargo clippy --workspace --all-targets --all-features -- -D warnings` + `cargo nextest run --workspace`. At the end: the `tui-test` scenarios (`scenario-details-panel`, `scenario-tasks-pane`, updated `scenario-pane-shell`/`pane2-resize`/`scenario-tiny-80x14`).

## Risks

| Risk | Mitigation |
|---|---|
| The scheduler's terminal-event ownership changes the existing event handler's behaviour | the mismatch path is explicit (a logged stray event clears nothing); the existing interrupted-batch summary stays |
| The aggregate's `alive` arm differs between scopes | D7: the global is live, the view is the swept `band`; both labelled |
| The queue is in-memory | D34: matches today's `Arc<Meters>` model; quitting logs the tasks that never ran |
| `ui/actions_log.rs`'s tests move | the moved tests assert the Metrics surface, not the deleted file |
| The new raw SQL violates the sorter-free doctrine | both statements are index-served, no `GROUP BY`, no `ORDER BY`; the planner gate is checked |

## Retirement

- `ui/actions_log.rs` — deleted (T2.5).
- The four direct ping spawns — retired into the scheduler (T1.5).
- The pairwise spawn guards — retired (the scheduler is the only entry point).
- `Stop Testing` — retired (the scheduler's `s`/`r`).
- The gauge-over-border — retired (the Tasks pane's bar).
