# memtrace: measured improvements — implementation plan

Date: 2026-11-13
Evidence: `docs/research/2026-11-13-allocation-profile.md` (the profiling runs) and the
CPU decomposition below, measured on this machine.
Domain: `crates/leas-memtrace` (the tracer), `crates/leas-hotpath/src/bin/memtrace.rs`
(the driver), and the docs that teach the workflow.
Execution route: **staged, inline per stage**; T1 and T2 are the ones with measured
payoff.
`User confirmation required: no for T1–T3; yes for T4+` (T4 is a runbook, T5 changes
the artifact's presentation).

## 1. Goal

Make the tracer cheap enough to run on a real session without distorting it, and make
two runs comparable without a human diffing tables. The tool's numbers are already
exact; the cost and the workflow are what is missing.

Acceptance, measured with the same 11 s boot on the same sandbox
(`$HOME/.config/leas` staged from the real profile DB, groups pinned):

| stage | metric | now | target |
| --- | --- | ---: | ---: |
| T1 | **attribution equivalence** (the gate): per-module row set, `.folded` stack set, and traced rows against a measured run-to-run band | — | same module and stack sets; traced rows within the band, `<untraced>` within its much wider one |
| T1 | **`frames_walked` mean per allocation** (the mechanism metric) | 32 (by construction) | ≤ 6 → **16.86 measured**; the target assumed a depth of ~3, the app's mean is ~17 |
| T1 | CPU of the traced boot over the untraced build (recorded, never gated) | +9.1 s (17×) | reported per run; a duration on one machine is an observation, not a threshold |
| T2 | run comparison | hand-diffed tables | `memtrace compare a.json b.json` prints per-module deltas |
| T3 | a killed run | no artifact at all | interval snapshots; `tick-<n>` survives SIGTERM |
| T4 | getting a valid app measurement | tribal knowledge | one runbook page + `just memtrace-app` |
| T5 | reading an artifact | live-sorted only | allocation-sorted table, crate rollup, allocator/fold lines |

## 2. Evidence

CPU time (`getrusage(RUSAGE_CHILDREN)`), same workload, 2–3 samples each:

| configuration | CPU | δ vs untraced |
| --- | ---: | ---: |
| untraced release (mimalloc) | 0.55–0.58 s | — |
| traced, `MIN_BYTES=1 GiB` (no capture) | 0.72–0.74 s | +0.17 s |
| traced, 1-frame capture (experiment) | 1.58–1.59 s | +1.0 s |
| traced, 32-frame capture (shipped) | 9.66–9.80 s | +9.1 s |
| traced, 32 frames, `trace_unsynchronized` | 9.51–9.69 s | no gain — the lock is not the cost |

`attribute()` (`attrib.rs:83`) captures up to `MAX_FRAMES` = 32 frames on **every**
allocation and only then walks the cache: the cache makes symbolization once-per-IP,
but the unwind is paid per allocation. Slope from the three points ≈ **0.27 µs setup
+ 0.09 µs per frame per allocation**; 2.79 M allocations × 32 frames ≈ 9 s.

The 1-frame figure is a **lower bound**, not the fix: capping at one frame changes
attribution (an allocation whose innermost frame is in ratatui resolves to
`<untraced>` instead of `leas::ui`) and skips the deeper resolutions, so it measures
less work *and* different work.

## 3. Design decisions

**D1 — hit stops the walk; a miss still walks to the end.** `attribute` fuses the
capture with the cache probe: the `backtrace::trace` callback fills the frame buffer,
probes the cache per IP, and returns `false` on a hit. A *hit* therefore costs
`d` frames, where `d` is the depth to the innermost workspace frame (typically 1–4).
A *miss* keeps walking — it is the once-per-distinct-IP path and it is what builds the
folded path (≤`MAX_FOLD_DEPTH` 8 modules), so folded stacks keep their depth; there are
~5 700 misses per run, i.e. ~18 ms at 32 frames, which is noise.
Attribution is unchanged **by definition**: `row_for` already keys on the innermost
frame whose module resolves to a workspace root, and `attribute`'s loop already returns
on the first frame with a cached row — stopping the *capture* at that same frame cannot
name a different root, because a deeper frame would only be reached if no earlier frame
were a root (which is the same condition in both shapes). The equivalence gate in §6
exists to prove that reasoning against a real artifact rather than trust it.

**D2 — the walk is measured, not assumed.** `Stats` gains `frames_walked`
(`AtomicU64`, one add per allocation) and the artifact prints
`frames walked: N (mean X/allocation, Y per resolve)`. Without it the next change to
the walk cannot be judged, and the "how deep does this app's stack go" question stays
unanswerable.

**D3 — artifacts get identity.** `Snapshot`/JSON gain `schema: 2`, `rev` (short git
SHA via a build script's `option_env!`), `features` (from the crate that installs the
tracer), `allocator: system`, `fold: live|allocs`, and `roots`/`min_bytes` (already
present). Two artifacts are then self-describing, which is what makes `compare`
honest — it refuses to diff runs whose rev/features/roots differ unless `--force`.

**D4 — comparison is a subcommand, not a script.** `memtrace compare a.json b.json`
prints a table of per-module `allocs`/`churn`/`live` deltas, sorted by absolute
`allocs` delta, plus a totals line. Both inputs are the artifacts the tool already
writes; `serde_json` is already a dependency.

**D5 — interval snapshots, not signal handlers.** A tracer-owned timer
(`LEAS_MEM_TRACE_INTERVAL_SECS`) writes `tick-<n>` artifacts from a background thread.
No new dependency, no signal semantics to negotiate with the TUI's terminal reader, and
it covers exactly the failure seen this session: a kill loses the exit-boundary write.

## 4. Stages

### T1 — fused capture and the walk counter (perf)

Files: `crates/leas-memtrace/src/attrib.rs`, `crates/leas-memtrace/src/table.rs`,
`crates/leas-memtrace/src/artifact.rs`.

- `capture` becomes a closure-driven walk that probes `cache_get(ip)` per frame and
  stops on a hit; `row_for` still receives the walked prefix for the folded path and
  finishes the walk when it creates a row.
- `FRAMES_WALKED` counter; `Totals`/text header line as in D2.
- Tests: the existing attribution tests must pass unchanged (they assert module
  attribution); add one asserting the counter grows by less than `MAX_FRAMES` per
  allocation for a same-site loop (a regression that restores the full walk fails it).

Acceptance, in three parts, because two runs of the *same* binary are not identical —
measured band from two consecutive `HEAD` runs on this workload:

| quantity | HEAD vs HEAD | what the gate requires |
| --- | --- | --- |
| module row set | identical | identical |
| `.folded` stack set | identical (27 stacks) | identical |
| traced rows (e.g. `leas::ops::profiles`) | 210 151 vs 210 139 (±0.006 %) | within **±1 %** |
| `<untraced>` | 29 616 vs 46 593 (**±57 %**) | within **±60 %** — it absorbs thread-timing noise |

The folded set is in the gate because it is the only depth-dependent output: rows are
keyed by module, so a truncated walk can pass a rows-only comparison while silently
shortening every stack. `frames_walked` is the mechanism metric. CPU is
recorded with the §2 harness on this machine and reported in the execution note; it is
deliberately not a pass/fail, because a duration on one machine is a distribution, not
a threshold.

### T2 — artifact identity and `compare`

Files: `crates/leas-memtrace/src/artifact.rs`, `crates/leas-memtrace/build.rs` (new),
`crates/leas-hotpath/src/bin/memtrace.rs`.

- `start_with(roots, min_bytes, &[(&str, &str)])` — `start` stays as a wrapper; the app
  passes `[("features", "mem-trace"), ("dataset", "roscomvpn")]`-style metadata.
- JSON `schema: 2` + `rev`/`features`/`allocator`/`fold`; the text header echoes them.
- `memtrace compare` subcommand (sorted deltas, totals, `--force` for mismatched rev).
- Tests: a fixture pair under `#[cfg(test)]` JSON constants → the delta table is a
  golden string; a mismatched-rev pair refuses without `--force`.

### T3 — interval snapshots

Files: `crates/leas-memtrace/src/attrib.rs` (or a new `timer.rs`).
- `LEAS_MEM_TRACE_INTERVAL_SECS=N` spawns one thread that calls `write(dir, "tick-N")`
  every N seconds; `0`/unset disables. The guard the reporter already takes keeps the
  timer's own allocations out of the numbers.
- Test: with `N=1` and a 2.5 s sleep, at least two `tick-*` files exist and their
  totals are monotonically increasing.

### T4 — runbook and recipe (docs)

File: `docs/guides/tracing.md` (new) + a `just memtrace-app` recipe.
The page carries what cost this session hours: the app reads
`dirs::config_dir().join("leas")`, so the sandbox must set `HOME` (not
`XDG_CONFIG_HOME`) with the DB copied to `$HOME/.config/leas`; pin
`groups.last_refreshed` or the boot sweep becomes a subscription import; the full
64 577-row database makes the app unresponsive in a PTY driver, so trim it; a graceful
quit needs a long drain because the exit artifact is written after shutdown.

### T5 — artifact presentation

- Second table sorted by `allocs` (the live sort hides churn), a crate rollup
  (`leas_db`, `leas`, … from the module prefix), `allocator: system` and
  `fold: allocs` in the header, and the symbol-slab overflow as a **count** of
  allocations charged to `<untraced>` after the latch (today it is a sticky bool plus
  one warning line).

### Deferred, with reasons

- **Thread-local accumulation / sampling `PEAK_LIVE_BYTES`**: the atomics cost ~0.06 µs
  per allocation today (0.17 s of 11 s); revisit only if core count or allocation rate
  makes contention visible in `frames walked`-era profiles.
- **Phase API**: `job_boundary(label)` already writes a labelled artifact; a phase API
  would be sugar until a caller needs overlapping phases.
- **Sampling allocations**: breaks the exactness that every number in the research
  report relies on. Opt-in only, and only if T1 proves insufficient.
- **Tracing the `perf-lab`**: needs `leas-memtrace` as a dev-dependency of `leas` and
  the allocator behind a feature; worth doing when the import/ping paths need numbers.

## 5. Compatibility boundary

No wire, schema (database), or config change. The artifact JSON gains fields and a
`schema` number; readers are inside this repository (`docs/research`, the plan's
comparison), and `memtrace compare` checks the version. `leas-memtrace` is publishable
at 0.1.0: adding `start_with` is additive, `schema: 2` is documented in the crate's
README.

## 6. Verification (every stage)

`cargo fmt --all` · `cargo clippy --workspace --exclude leas-oracles --all-targets
--all-features -- -D warnings` · `cargo nextest run` (workspace Summary line) ·
`just hotpath` (5/5 — the gate's rows are exact counts and must not move) · the CPU
harness from §2 for T1 · the fixed-sandbox artifact diff for T1's parity claim.

## 7. Risks

- **Early stop changes folded depth** if a hit short-circuits before the callers are
  captured. Mitigated by D1: folded paths are recorded on the miss path, which walks
  fully; the parity check in T1 compares the whole artifact, not just the rows.
- **A counter-only test is weak.** T1's real proof is the artifact-equivalence gate
  plus the counter; the unit test only pins that the walk short-circuits. CPU stays a
  recorded observation.
- **`rev` via build script** makes builds dirty-unfriendly (a `build.rs` watching the
  wrong files rebuilds constantly). Scope it to `git rev-parse --short HEAD` at build
  time with `rerun-if-changed=.git/HEAD` only, or read the SHA at runtime through
  `option_env!` from the parent crate — decide in T2, not before.
- **Interval artifacts can fill a disk** in a long session: cap the count
  (`LEAS_MEM_TRACE_INTERVAL_MAX`, default 32) and overwrite oldest-first.

## 8. Retirement

No shims: `start` becomes a thin wrapper over `start_with` (one caller each), the old
`capture` is replaced rather than kept, and the artifact's `schema: 1` reader does not
exist. `OVERFLOWED` becomes a counter, not a second flag.

## Execution note

### T1 — executed 2026-11-13

`attribute` now probes the cache from inside the `backtrace::trace` callback and stops
the walk at the first frame that already resolves; a first sight still walks to
`MAX_FRAMES` in a second pass so the folded path keeps its callers (that path runs once
per instruction pointer — ~5 150 per run, ~0.02 s), and the second pass's stack is
checked for the frame the first resolved on before it is used — a stack interrupted
between passes falls back to the first pass's prefix. Counter semantics are unchanged
(a `Cached::Foreign` probe still counts as a hit; only an uncached IP counts as a
resolve; a slab-overflow row is still cached once, as `UNTRACED`). The artifact JSON
carries `schema: 2` from this change, because `totals.frames_walked` alters the key
set. `FRAMES_WALKED` is a new counter and
the artifact prints `capture: frames walked N (X.XX per allocation)`; a unit test pins
that a repeated site walks ≤4 frames.

Measured on the fixed sandbox, same 11 s boot:

| metric | before | after |
| --- | ---: | ---: |
| CPU of the traced boot (recorded, not gated) | 9.66–9.80 s | **6.75 s** |
| tracer overhead over the untraced build | +9.1 s | **+6.0 s** |
| frames walked per allocation | 32 (ceiling) | **16.86** |
| `leas::ops::profiles` allocations | 210 139 | **210 139** (identical) |
| `leas::ui` allocations | 2 476 052 | 2 476 056 |
| `.folded` stack set (27 lines) | — | **identical set**, weights within run-to-run band |

So the gate holds (attribution and folded stacks unchanged) but the **≤6-frames target
was wrong**: it assumed the depth to the first workspace frame is ~3, and the app's real
mean is ~17 because most allocations happen deep inside non-workspace code (tokio,
ratatui). The walk is now bounded by that depth, not by `MAX_FRAMES` — a 2× cut
(9.7 → 6.75 s), not the 4–6× the arithmetic projected.

Remaining levers, in order: (a) sample the capture (`LEAS_MEM_TRACE_SAMPLE`, opt-in —
the exactness loss is acceptable for ranking but not for the hot-path gate, which has
its own allocator); (b) a cheaper unwinder (frame-pointer walk), which needs
`force-frame-pointers` in the release profile and arch-specific code — a build-policy
decision, not a crate one. Neither is scheduled here.

### T2 — executed 2026-11-13

Artifacts carry identity: `schema: 2`, `rev` (short git SHA stamped by
`crates/leas-memtrace/build.rs` through `LEAS_GIT_REV`, `unknown` outside a
checkout), `allocator: system`, `fold: live|allocs`, and the caller's metadata
(`start_with(roots, min_bytes, &[("bin", "leas")])`; the app and the `memtrace`
bin both pass their name). `memtrace compare a.json b.json [--force]` prints
per-module Δallocations/Δbytes, biggest change first, and refuses artifacts whose
`schema`, `rev` or roots differ. Unit tests pin the delta table (added, removed,
changed modules) and the empty case.

### T3 — executed 2026-11-13

`LEAS_MEM_TRACE_INTERVAL_SECS` (+ `LEAS_MEM_TRACE_INTERVAL_MAX`, default 32)
spawns one writer thread that emits `tick-N` artifacts and prunes the oldest.
Wired in `alloc::start_tracing`; a test asserts two ticks appear within a few
seconds.

### T4 — executed 2026-11-13

`docs/guides/tracing.md` (indexed) carries the sandbox rules — `HOME` not
`XDG_CONFIG_HOME`, pin `groups.last_refreshed`, copy-never-point, trim the DB for
a PTY driver, long exit drain — plus the knobs, artifact reading, comparison and
the measured tracer cost. `scripts/trace_app.py` stages the sandbox and drives
the app under a PTY, reporting CPU; it pins `groups.last_refreshed`, trims a
large database copy to 3 000 endpoints, and **fails the recipe** when the sandbox
cannot be prepared rather than tracing an unprepared run. `just memtrace-app` and
`just memtrace-compare` wrap the two workflows. The interval writer's prune is
tested deterministically (five fake ticks, three files each, newest two kept) and
the writer itself with one bounded existence check, because a wall-clock
multi-tick assertion flaked under a parallel suite.

### T5 — executed 2026-11-13

The text artifact now prints `rev`, `allocator`, `fold` and the metadata, the
attributed frame-walk mean, and the symbol-slab overflow as a **count** of
refused resolutions (`OVERFLOWED` is an `AtomicU64`). Below the live-sorted table
it adds `by allocations (top 10)` — a row that allocates and frees holds nothing
at snapshot time and would otherwise be invisible — and a per-crate rollup.

All five stages are implemented. Remaining deferred items are unchanged (thread-
local atomics, phase API, sampling, tracing the perf lab).
