# Boot allocation burst — Design Spec Brief

Date: 2026-11-16
Status: **implemented 2026-11-16 — W1 landed, W2 cancelled on measurement (T0: one execution per boot).**
Origin: `docs/research/2026-11-13-allocation-profile.md` §9 (re-audit), and the open P0 in
`plans/2026-11-13-memory-usage-improvements.md`
Evidence: `mem-audit/report.md` §9, `mem-audit/baseline/2026-11-16/`

---

## 1. Why this exists

A boot on a real-shaped database allocates **2 574 862** times, of which
**2 455 961 (95.4 %)** land in the inlined `leas::ui::run` body, **91.6 MiB** of
churn, against a peak live heap of **9.3 MiB**. The burst lasts ~5 s and ends
when the profile page lands; steady state afterwards is 57–386 allocations/s.
A fresh-one-endpoint control allocates **32 636** for the whole session, so the
mass is dataset-proportional.

The site is now named (Valgrind DHAT, full stacks, `std-alloc` build):

```
fmt::Formatter::pad_integral <- u32::fmt <- core::fmt::write <- format_inner
  <- turso_core::vdbe::explain::insn_to_str
  <- <Program>::trace_step <- dispatch_loop_traced
  <- <Statement>::_step <- <Rows>::next
  <- ProfilesQuery::Sql::exec_raw
  <- Database::profiles_aggregate          <- leas::ui::run::{closure#0}
```

`turso_core` gates its traced interpreter loop on `tracing::enabled!(TRACE)`
(`vdbe/mod.rs:2598`) and `trace_insn` then builds
`explain::insn_to_str(…, String::new(), …)` — one `String` per opcode
(`:4159`). The aggregate statement is issued from `state.refresh_aggregates`
(`state.rs:443`, two statements per call), reached through
`ui/mod.rs:320`. 2 545 487 of the process's 4 706 814 blocks are that one
program point.

What was tried and did not work (all rebuilt, verified, reverted; §9.3):

| Logs-tab filter | `ui::run` allocations |
|---|---:|
| `trace,hickory_net::h2=error` (current) | 2 455 961 |
| `…,turso_core=off` | 2 455 985 |
| `debug,hickory_net::h2=error` | 2 455 984 |
| `off` | 2 455 984 |

`try_init()` returns `Ok` (our subscriber is the installed one), yet an
instrumented probe measured `tracing::enabled!(target: "totally_bogus_target",
TRACE) == true` with every filter off, while an isolated crate with the same
construction reports `false`. **The reason our stack still reports TRACE
enabled is not established** — but the consequence is: no directive in a
per-layer `EnvFilter` can switch turso's traced loop off.

## 2. Scope

One change: make `tracing::enabled!(TRACE)` false process-wide, so turso takes
its untraced interpreter loop. One conditional follow-up: if the residual still
shows `profiles_aggregate` as a top allocation site, cut its executions.

**Out of scope, with reasons:** the idle-retention finding (reverted on
measurement, `plans/2026-11-13-memory-usage-improvements.md` §2.3b); the 76 MiB
of resident executable pages (no dominant symbol; needs `cargo bloat --crates`
first); the `ops::profiles` event reload (F6, needs its own design); every
render-path item (closed by `b0919ec`).

## 3. The shape

### W1 — cap TRACE at the subscriber root (primary)

`tracing::enabled!` consults the outermost layer(s) of the layered subscriber.
Append a `tracing_subscriber::filter::LevelFilter::DEBUG` as the **outermost**
layer of the stack in `main.rs` (last `.with(...)`): `Layered::enabled`
short-circuits on the outer layer (`layer/layered.rs:105`), so every TRACE
callsite in the process reports disabled, while per-layer `EnvFilter`s keep
delivering everything at DEBUG and below.

Then move the whole subscriber construction out of `main.rs` into
`crates/leas/src/logging.rs` (`pub fn subscriber_stack(...) -> impl Subscriber +
Send + Sync`) so an integration test can build it:

- `crates/leas/tests/tracing_level_gate.rs` installs that stack and asserts
  `!enabled!(TRACE)` and `enabled!(DEBUG)` for both `turso_core::vdbe` and a
  bogus target. This is the regression guard for the whole finding.

**If the layer does not take effect** — the leading explanation for the
anomaly in §1 is that per-layer filters (`Filtered`) are consulted at dispatch
time (`FilterState`) rather than by `Layered::enabled`, which is why the
`EnvFilter` directives changed nothing — then the guaranteed variant is the
compile-time cap `tracing/release_max_level_debug` on the workspace `tracing`
dependency: `enabled!(TRACE)` becomes a constant `false`, the traced loop's
formatting is dead code, and turso cannot reach it in any release build. Same
task list, one Cargo line instead of the layer, and T1 is gated on
`cfg!(not(debug_assertions))`.

What the Logs tab loses: **TRACE-level events only**. Our own logging is
`error`/`warn`/`info` (`log_trace`: 11/5/24 call sites); the workspace has ten
`tracing::trace!` sites, none user-facing (`leas-proto` host/port parsing,
`leas-db` driver, `leas-native` inbound). `#[instrument(target = "db_method")]`
spans are INFO and `toasty::query` events are DEBUG, so the DB monitor keeps
working. turso's per-opcode trace lines are the thing being removed.

**Drift from T2 (recorded):** the plan expected the whole construction — the
`registry()…try_init()` chain *and* the layers — to move into `logging.rs`. It
did not: `TuiLogLayer` + `LogVisitor` are ~350 lines whose doc comments carry
the persisted-message/session-detail split (`specs/2026-09-24-db-query-
monitoring-design.md` §10 non-goal 10 — a security boundary, not plumbing), and
the stderr layer's concrete type is built from env inside the chain. The seam
is therefore `cap_trace(stack)`: the chain stays in `main.rs`, wrapped once
immediately before `try_init`.

The consequence for the guard: the gate test cannot build the *production*
stack (the layer types are not nameable from `tests/`), so it asserts the cap's
effect on a stack whose layer filter asks for `trace` — the mechanism — and the
*wiring* is covered by `debug_assert!` on the installed subscriber in
`main.rs` (debug builds only). Accepted: a release-only wiring regression is
not observable by the test; it would show in any debug run of the app.

### W2 — conditional: cut aggregate executions

If the post-W1 measurement still shows `profiles_aggregate` in the top three
symbol rows, gate it: skip the refresh while the initial page load is in
flight and run it once when the load completes. The testable seam is a pure
predicate, not the DB:

```rust
fn should_refresh_aggregates(scope_changed: bool, dirty: bool, load_in_flight: bool) -> bool
```

`ui/mod.rs:320` keeps the call site; `state.aggregates` gains no field.

**Which of W1/W2 carries the win is decided by a count, not by preference.**
DHAT proves the stack but not the number of `profiles_aggregate` calls
(`state.rs:443` issues two statements per call, `live_alive=false` then `true`),
so T0 measures it in the same 25 s series. The matrix:

| executions during boot | reading | action |
|---|---|---|
| 1–5 | one aggregate over a many-opcode statement | W1 only; W2 is not worth code |
| 6–50 | the loop re-runs it while the load is in flight | W1 + W2 (coalescing), both measured |
| > 50 | it is re-issued per pass/endpoint | W2 first (query scheduling is the bug), W1 still caps the per-opcode cost |

## 4. Contract

- Public API: unchanged. `leas::logging` is crate-public (`pub` inside the
  binary crate only).
- Log delivery: DEBUG and below unchanged for every layer; TRACE no longer
  reaches any layer in any build. If a future debug need for TRACE appears, it
  is served by `LEAS_STDERR_LOG=1` plus a deliberate, measured exception — not
  by re-enabling it for the whole process.
- No new dependency; `tracing-subscriber` already exposes `LevelFilter` as a
  layer.

## 5. Decision required

**Does the Logs tab keep TRACE?** Recommended: no (W1 as written). TRACE in this
process is third-party per-opcode chatter; the cost is ~2.5 M allocations and
the bulk of a 5.7 G-instruction boot on every start. If TRACE must survive a
debugging session, the runtime layer can be bypassed by an env-gated branch at
construction, so the measurement travels with the flag. The compile-time
`release_max_level_debug` cap is the *fallback for effect* (§3), not an answer
to this decision: it cannot be flipped at runtime.

## 6. TDD route

`TDD Route`: mode `auto` → **strict** (behavior change in shared logging core,
plus a scheduling change in W2). Authority: this spec, task order below.

## 7. Tasks

| # | Task | Files | Minimum change | Verification |
|---|---|---|---|---|
| T0 | Count the executions (no product change) | scratch counter in `state.rs::refresh_aggregates` (`eprintln!` under an env flag), same 25 s series | print the call count at exit; remove before T2 | count recorded in `mem-audit/`; §3 matrix picks W1-only vs W1+W2 |
| T1 | RED: the gate test | `crates/leas/tests/tracing_level_gate.rs` | build the stack, assert `!enabled!(TRACE)`; fails today | `cargo nextest run -p leas --test tracing_level_gate` fails |
| T2 | Seam only — **drifted**, see note | `crates/leas/src/logging.rs`, `main.rs`, `lib.rs` | `cap_trace` takes the fully composed stack; `main.rs` keeps the `registry()…try_init()` chain and its `TuiLogLayer`/`LogVisitor` | `cargo nextest run -p leas`; `cargo clippy -p leas --all-targets` |
| T3 | GREEN: outermost `LevelFilter::DEBUG` | `logging.rs` | one `.with(LevelFilter::DEBUG)` as the last layer + a comment naming turso's gate | T1 passes |
| T3b | Fallback if T3 has no effect | `Cargo.toml` (workspace `tracing`) | `features = ["release_max_level_debug"]`; T1 gated on `cfg!(not(debug_assertions))` | T1 passes under `--release`; T4 as below |
| T4 | Measure | `mem-audit/` artifacts | `just memtrace-app`-style series, 3 000-endpoint sandbox, 25 s idle | total ≤ 120 000 allocations; `ui::run` ≤ 30 000; steady state ≤ 400/s |
| T5 | W2 decision point | — | re-read the post-W1 symbol table; if `profiles_aggregate` still top-3, do T6, else stop and record | symbol table in the artifact |
| T6 | W2: pure predicate + call site | `ui/mod.rs`, `state.rs` | `should_refresh_aggregates(...)` with a RED unit test first; skip while loading, refresh once after | predicate unit test + T4 re-measure |
| T7 | Docs | `AGENTS.md`, `docs/architecture/decisions.md` §30, the memory plan | one rule: TRACE is disabled process-wide because a dependency's fast-path gate cannot see per-layer filters; record the measurement | review |

## 8. Acceptance

Measured on the 3 000-endpoint sandbox (§9.2 of the research note), same
machine, `--features mem-trace`:

| metric | today | target |
|---|---:|---:|
| total allocations per boot | 2 574 862 | **≤ 120 000** |
| `leas::ui::run` bucket | 2 455 961 | ≤ 30 000 |
| churn in that bucket | 91.6 MiB | ≤ 12 MiB |
| peak live heap | 9.3 MiB | unchanged ±1 MiB |
| steady-state rate | 57–386/s | ≤ 400/s |

The targets are **predictions**, not measurements: with turso untraced the
bucket should collapse to the page-load rows (`load_profiles_rows` 27 495,
`build_display_rows` 18 677, `main` 7 950) plus geo. T0 decides whether W2 is written
at all (§3 matrix); if T4 lands between the target and today's number, T5
re-checks the post-W1 symbol table before the predicate ships.

Gates: `cargo nextest run`, `cargo clippy --workspace --exclude leas-oracles
--all-targets --all-features -- -D warnings`, `cargo fmt --check`.

## 9. Risks

- **The mechanism is unexplained.** We do not know why our stack reports TRACE
  enabled while an isolated identical construction does not; the leading
  hypothesis is the dispatch-time handling of per-layer filters, which would
  also bypass a plain `LevelFilter` layer. W1 tests the *effect*
  (`enabled!(TRACE)` false, allocation drop), so a wrong theory fails the test
  rather than shipping silently. If the layer variant fails, take the
  compile-time `release_max_level_debug` cap (§3) and re-run T4 — that path is
  not hypothesis-dependent. Triage if both fail: (a) the probe again under the
  new stack, (b) `tracing` interest rebuild, (c) upstream turso issue with the
  DHAT stack.
- **Lost TRACE forever in release and debug builds.** Accepted in §5; the
  `LEAS_STDERR_LOG` miror cannot restore it (it rides the same subscriber).
- **Logs-tab expectations.** Any test asserting a TRACE line from a dependency
  would have to change; none exists today (`cargo nextest run` is the check).
- **W2 can mask a slower query.** Deferring the aggregate hides executions
  rather than making the statement cheaper; if the post-W1 profile shows a
  large per-execution cost, the right follow-up is a covering query, not more
  deferral.

## 10. Outcome (measured)

Same sandbox, `--features mem-trace`, 25 s idle:

| metric | before | after | target |
|---|---:|---:|---:|
| total allocations per boot | 2 574 862 | **103 659** | ≤ 120 000 |
| `leas::ui::run` bucket | 2 455 961 | **2 934** | ≤ 30 000 |
| churn in that bucket | 91.6 MiB | **1.5 MiB** | ≤ 12 MiB |
| peak live heap | 9.3 MiB | 9.4 MiB | ±1 MiB |
| steady-state rate | 57–386/s | 13–117/s | ≤ 400/s |
| traced-boot CPU | 6.29 s | **0.50 s** | — |

T0 cancelled W2: `refresh_aggregates` runs **once** per boot
(`[audit] refresh_aggregates false`), so coalescing saves one statement, not
the matrix's 6–50 band. The 2.5 M was always the per-opcode `String`, not the
call count. Implementation note: the whole-stack extraction of T2 was not
needed — `cap_trace` takes the composed stack, `main.rs` calls it once, and a
`debug_assert!` on the installed subscriber covers the wiring in debug builds.

## 11. Rollback and retirement

Both changes are single commits: revert the `.with(LevelFilter::DEBUG)` line
(W1) and delete the predicate (W2). Nothing persists, no schema, no config
field. Retirement: the `tracing_level_gate` test is permanent — it is the guard
that stops a future layer edit from re-enabling TRACE process-wide.
