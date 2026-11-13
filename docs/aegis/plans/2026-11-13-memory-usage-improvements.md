# Memory usage: measured improvements — implementation plan

Date: 2026-11-13
Evidence: `mem-audit/report.md` (runs B1–B5, smaps decompositions, claim ledger
C1–C13), artifacts under `mem-audit/baseline/`, driver `scripts/trace_app.py`.
Domain: `crates/leas` (`alloc.rs`, `ui/`, `ops/profiles.rs`),
`crates/leas-memtrace` (attribution output), `crates/leas-hotpath` (counts),
`scripts/`, docs.
Execution route: **staged, inline**; P0 gates P2–P4 (a measurement, not code).
`User confirmation required: yes for P1` — it changes runtime behaviour of the
shipped binary (an allocator call from the event loop) and is the only item whose
target is RSS rather than an allocation count.

## 1. Goal

Turn "the app uses a lot of memory" into two measured targets: **retained RSS
after the app goes idle**, and **allocations per boot/navigation**. The audit
found the live heap is 4–10 MiB while RSS is 102–116 MiB; the gap is allocator
retention and the binary image, not our data.

Acceptance (same sandbox, same 3 000-endpoint copy, `KEYS` script from
`mem-audit/report.md` §8):

| stage | metric | now | target |
| --- | --- | ---: | ---: |
| P0 | share of the 2.46 M `leas::ui` boot allocations attributed to a named function | 0 % (module rows only) | ≥ 80 % named |
| P1 | RSS 60 s after an idle burst (shipped mimalloc build) | 116 MiB, of which 63.5 MiB anon | anon ≥ 50 % lower; CPU of the collect reported, not gated |
| P2 | allocations per rendered frame (`row_heights` + filter `collect`) | ≥ 2 | 0 |
| P3 | allocations for one full display-row rebuild | ~14 per endpoint | ≤ 4 per endpoint |
| P4 | `leas::ops::profiles` allocations over 10 navigations | 403 211 (50 s run) | < 50 000 |
| P5 | `compact_str` majors in `cargo tree -d` | 2 (0.9.1, 0.10.0) | 1 |

## 2. P0 — attribute the UI cost before touching it (blocking)

**Finding it answers:** F1. 2.56 M allocations per boot, constant across 1 s and
12 s runs, with an *empty* database producing the same 2.46 M in `leas::ui` as a
3 000-endpoint one (B1 vs B2 vs B5). The tracer's `rows` say `leas::ui`; its
`.folded` says the hottest stack is `leas;leas::ops::profiles` (2 060 696). One
of those two aggregates is misleading, and the plan must not guess which.

**Scope of this plan's measurements (state it, don't assume it).** The audit
covered *boot and grid interaction* only. Import, subscription refresh, ping
batches and the live relay are **unmeasured**; the earlier research report names
them as the untraced paths. A ranking built on boot rows alone can target render
churn while a bigger cost sits in import/ping. P0 therefore covers those
workloads before P3/P4 are sized.

**Steps.**
1. `crates/leas-memtrace/src/artifact.rs`: emit `by_symbol` (top 32 by count and
   by bytes) next to `rows`. The table already keeps per-symbol atomics; the
   resolver already walks frames for the folded path — reuse it, do not add a
   capture.
2. `crates/leas-hotpath/src/bin/memtrace.rs`: print the new table in
   `render_text` and in the `compare` delta.
3. Run the attribution on **four** workloads, not one: (a) empty DB boot, (b)
   3 000-endpoint boot, (c) `memtrace connect <n>` and `record <n>`, (d) a
   subscription/import burst in the sandbox. Record the top 10 symbols per
   workload and their shares.

**Acceptance.** A named function (or an explicit "no workspace frame resolves,
the cost is in `<dep>` reached from X" verdict) covering ≥ 80 % of the 2.46 M,
written into this plan with the run's `rev`.
**Rollback.** None needed (artifact addition; schema stays 2 unless a field is
dropped — additive fields are fine).

## 2a. Re-ranked after P0 (decisions, with numbers)

The P0 runs moved three items. Nothing below is a promise; each carries the
measurement that decided it.

| item | measured | decision |
|---|---|---|
| P2 (per-frame `Vec`s) | 5 allocations, ~12 KiB per frame; the boot mass is 2.5 M | **closed as rejected** — below the noise floor (R11). Re-open only if a frame-rate change makes it visible. |
| P3 (`DisplayRowData` cells) | `build_display_rows` 18 617 allocations at n = 1 000 (2.0 % of boot), 41 614 in a 50 s interactive run (1.4 %); the rebuild is already cache-gated | **deferred**: the `CompactString` swap is the mechanism if the rebuild frequency rises; it cannot move a 2.5 M boot today. |
| P4 (patch rows by id) | `load_profiles_rows` 21 460 at boot, **428 834** when a search keystroke invalidates the page — interaction-bound, not boot-bound | **deferred with a measurement**: count reloads per keystroke first; the patch path touches the ordering law and is not justified by a number yet. |
| P5 (duplicate crates) | `compact_str` 0.9.1 via `ratatui-core`, `parking_lot` 0.12.5 via arboard/crossterm/hickory | **closed**: our copies are the direct ones; the bumps belong to upstreams; no memory effect. |

## 3. P1 — reclaim retained arena pages when the app goes idle (RSS)

**Finding:** F2. mimalloc holds 63.5 MiB anonymous for a 4–10 MiB live heap after
the boot burst, and nothing collects it once the app is idle. Upstream's issue
#1422 is the same shape and its maintainer added `mi_arenas_purge()`; our
vendored 3.6.1 header does not have it (`include/mimalloc.h:189,424` export
`mi_collect`/`mi_collect_reduce` only), so the available cheap primitive is
`mi_collect(false)` — already bound in `crates/leas/src/alloc.rs` and already
called at job boundaries (`release_freed_heap`).

**Steps.**
1. `crates/leas/src/alloc.rs`: add `pub fn purge_idle_heap()` — under
   `#[cfg(all(feature = "mimalloc", not(feature = "std-alloc")))]` call
   `mi_collect(false)`; otherwise a no-op with the same doc note as
   `release_freed_heap`.
2. Call site: the UI event loop (`crates/leas/src/ui/mod.rs`), where idle time is
   known — only when **all** hold: no input for ≥ 5 s, no active job
   (`job_scheduler` idle), no live connection, and ≥ 30 s since the last call.
   Rate limit explicitly; never call it per frame.
3. Measure with a scripted burst: `KEYS` drives a burst (tab through panes, open
   settings/menus), then the driver waits idle 60 s while sampling RSS. Compare
   the RSS curve with the call disabled and enabled, same binary otherwise.

**Acceptance.** Report, for both runs: RSS at burst end, at +60 s idle, CPU of
the run. Target: anonymous RSS ≥ 50 % lower 60 s after idle, elapsed CPU within
noise of the untraced baseline (0.67 s for the 40 s script). If the collect costs
more than ~50 ms when it runs, cut the rate further — it must never be visible as
a hitch.
**Risk.** `mi_collect(false)` is a full non-forced collect (abandoned heaps +
expired arena ranges): cheap when nothing is pending, but it is process-wide.
**Rollback.** One function call removed; no data or format change.

## 4. P2 — remove the two per-frame allocations (cheap, independent)

**Findings:** F3, F4 — **five** allocations, ~12 KiB, per frame. Small and
certain; explicitly **not** the 2.46 M.

- `ui/profiles.rs` `render_data_grid`: `widths: Vec<u16>` (per column),
  `order: Vec<usize>`, `columns: Vec<Column>`, and `heights: Vec<u16>` over
  **every** display row (the last is the 6 KiB one).
- `ui/widgets/data_table.rs`: `row_heights: Vec<u16>` over every row, per render.
- `ui/profiles.rs:465`: `state.filtered_profiles().collect::<Vec<_>>()` per render.

**Steps.** Keep a `row_heights: Vec<u16>` in `DataTableState` (`clear()` +
`extend`; capacity survives), and a `visible: Vec<&EndpointRow>`-shaped scratch
the render path can borrow (or make `render_data_grid` accept an iterator plus a
length, if the borrow checker allows it without a second pass).

**Acceptance.** Two runs of the same idle script, one with a redraw counter: the
allocation delta between consecutive frames drops by those five (bounded, not
zero — ratatui itself allocates); `heights`/`row_heights` become O(1)
allocations per frame. `just hotpath` unchanged (the widget is not on a measured
hot path today).
**Note.** Do not present this as the churn fix. It removes ~12 KiB/frame of
garbage; the 2.46 M is P0's to explain.

## 5. P3 — per-endpoint incremental rebuild, then inline cells

**Finding:** F5. `DisplayRowData` carries ~14 `String` fields per endpoint
(`ui/profiles.rs:144-200`); a cache miss rebuilds all rows for every differing
`endpoints_gen` or dirty bit. `ROWS_DIRTY_TRAFFIC`/`ROWS_DIRTY_TEST` are set by
event handlers (`ops/events.rs`, `ops/ping.rs`, `ops/enrich.rs`), so a busy feed
invalidates the whole grid.

**Steps (in this order, each measured).**
1. **Incremental patch:** keep the cache, add a `BTreeSet<EndpointId>` (or the
   dirty bits mapped to per-row ids) so a miss rebuilds only the changed rows;
   the `display_rows_cache.gen_id` full rebuild remains the fallback for a
   structural change (add/delete/reorder).
2. **Inline cells:** replace `String` with `CompactString` (already a workspace
   dependency, `Cargo.toml:102`) for cells whose measured p95 length ≤ 24 B. Do
   **not** change `DataTableRow` to require it — keep the field types internal to
   the row struct.
3. Re-measure `size_of::<DisplayRowData>()` and the rebuild allocation count.

**Acceptance.** One full rebuild: ≤ 4 allocations per endpoint (from ~14) with
unchanged rendering (the 7 TUI scenarios + `cargo nextest run`). Incremental
path: 10 navigations produce ≤ 2 × (changed rows) allocations, not 2 × (all
rows).
**Risk.** The cache-key logic is the trickiest part of the file (its comment
records a 160 ms/keypress incident); a wrong key renders stale cells. Every step
keeps the full-rebuild fallback and is covered by a test that flips each dirty
bit and asserts the affected row changed.

## 6. P4 — stop reloading every endpoint on an event

**Finding:** F6. `leas::ops::profiles` jumps from 30 201 (boot) to 403 211 (50 s
interactive) — `reload_profiles`/`reload_profiles_preserving_selection` re-read
all rows and rebuild the `EndpointRow` graph (`HashMap<ProtocolId, Protocol>` per
row) whenever a row-level fact changes.

**Steps.** Patch by id: the writers (`ops/ping.rs`, `ops/enrich.rs`,
`ops/events.rs`) already know the endpoint (and often the link) they touch; load
and replace that row instead of the whole vector. `endpoints_gen` still bumps for
structural changes only.

**Acceptance.** 10 navigations with a ping batch: `leas::ops::profiles` < 50 000
allocations, and `reload_profiles` call count drops (log line or counter). Ordering
law tests and the ping/enrich suites stay green.
**Rollback.** The reload path is retained; the patch path is additive.

## 7. P5 — dependency hygiene (no memory lever, do it once)

**Finding:** F8. `compact_str` 0.9.1 comes in through `ratatui-core 0.1.2`
(`cargo tree -i compact_str@0.9.1`), 0.10.0 is ours; `parking_lot` 0.12.5
(`arboard`, `crossterm`, `hickory-resolver`) beside our 0.13.0; `hashbrown`
0.14.5 transitive.

**Steps.** Check whether `opaline`/`ratatui` expose `CompactString` in their public
API (then a version alignment is a real constraint, not a choice). If they do,
align ours to 0.9.1 and re-run P3's checks; if not, record "two copies, no
interop" and leave it. `parking_lot` cannot be unified without upstream bumps —
record, do not fork.

**Acceptance.** `cargo tree -d | grep compact_str` shows one major, or the plan
records why not with the upstream version. Bumping `opaline`/`ratatui` is **out
of scope**: our copies are the direct ones, the duplicates come from those
upstreams, and the memory effect is code size only.

## 8. P6 — a soak harness that would have caught the 546 MB session

The audit measured 40–60 s runs; the user's symptom was a 22 h session at
546 MB. Add to `scripts/trace_app.py`: a `SOAK` mode (periodic `KEYS` chunks +
an RSS sample every 5 s written as CSV under `TRACE_DIR`), and a
`mem-audit/soak/` convention for keeping the curves. No threshold in CI — a curve
plus the burst/idle numbers P1 produces.

**Acceptance.** A 15-minute soak produces a flat-or-falling RSS curve after the
first minute on the sandbox dataset; P1's collect shows up as a step down, not a
sawtooth.

## 8a. P7 — image-size experiment (one variable, after P1–P4)

The shipped binary is 55.8 MiB with `.text` 40.3 MiB and 32.5 MiB of it resident
under the audit workload (~30 % of RSS). Whether that residency is *touch-driven*
is unknown, and no dependency swap addresses it (no symbol > 0.1 MiB).

**Steps.** Build with `[profile.release] lto = "thin"`, then `codegen-units = 1`
separately; record `.text` from `size -A` and RSS peak from the **same** 40 s
`KEYS` script. One profile change per run, no code change in the same commit. A
crate table, if wanted, comes from `cargo bloat --crates` — the `nm` parser in
`mem-audit/` is not trustworthy for v0-mangled names and is not used for claims.

**Acceptance.** `.text` and RSS side by side; adopt only if RSS drops ≥ 5 % with
no regression against the 0.67 s untraced CPU baseline. **Falsifier:** RSS that
does not follow `.text` means the pages are faulted for reasons other than code
size, and the item closes as "no lever".

**Result — closed, no lever.** `lto = "thin"` gives `.text` **40.9 MiB against
40.3 MiB** (larger, not smaller) and a settled RSS of **96 MiB against 93–96**
for the default profile, both with the idle reclaim on. The falsifier fired: the
image's residency is not a function of its size, so no profile change is
adopted.

## 9. Rejected, with numbers

Carried from `mem-audit/report.md` §5: `SmallVec`/`ArrayVec` for cells (redundant
with `CompactString`), `bumpalo` (no lifetime boundary for retained rows),
`thin-vec` (details pane is 4 225 allocs / 0.4 MiB), global allocator swap
(pending P1), `strip`/LTO (no dominant symbol; confounds the metric — promoted to
P7 as a measured profile experiment instead of a done-deal), `hashbrown` 0.17
(CPU-only).

## 10. Order and gates

P0 → P1 → P2 → P3 → P4 → P5/P6. Each step: one commit, before/after numbers in
the body, `cargo nextest run` + clippy `-D warnings` + `cargo fmt`, and the
tracer run recorded with its `rev` (the artifacts are comparable because
`memtrace compare` refuses a schema/rev mismatch — `docs/guides/tracing.md`).

## 11. Execution notes

(to be filled as stages land: the run `rev`, the numbers, and any deviation from
this plan — the same shape as `2026-11-13-memtrace-improvements.md`.)

**P0 landed (`af42893`).** `LEAS_MEM_TRACE_ROWS=symbol` keys rows by
`module::function` on the existing walk (no second capture), and the grain is in
the artifact header. Results: a fresh sandbox allocates 58 013 times; a 3 000-row
DB 2.56 M — the cost is **linear in endpoints at ~810 allocations each**, one-time
(6/12/25 s windows agree to ±30), terminal-size independent, 95.4 % under 64 B.
`build_display_rows` is 18 617 of it, `load_profiles_rows` 21 460; the rest
collapses into `leas::ui::run` — an **open question**, not a finding. What the
runs do establish: the mass is **not rendering** (a 24×80 and a 50×200 terminal
give the same count, and a search that filters the grid to zero rows still shows
1.96 M in `run`), and it is not the visible-row draw (`DataTable::render` loops
`while y < bottom`). An `#[inline(never)]` bisect was attempted and its result is
**void** — the patch briefly broke `ops/events.rs`, and the build that followed
was never verified to be a traced build, so the unchanged row count proves
nothing. `perf record` is unavailable here (0-byte capture: no permission).

**Next instrument, in order:** (1) emit the top site instruction pointers in the
artifact (`LEAS_MEM_TRACE_IPS=1`) and resolve them offline with
`addr2line -f -i -e target/release/leas …`, which *does* expand inline frames —
the tracer's `backtrace::resolve` does not; (2) re-run the `#[inline(never)]`
bisect with the artifact's `rev` and `rows` printed to prove the binary under
test. Until then no code change in `run` is justified.

**P1 landed.** `alloc::purge_idle_heap()` (the existing `mi_collect(false)`) is
called from the event loop after 5 s without **user** input (a key or a resize),
with no live connection, at most every 30 s (`LEAS_IDLE_PURGE=0` disables it for
an A/B, `LEAS_IDLE_PURGE_LOG=1` prints each collect). Two gating mistakes were
found by measuring, not by reading: keying the idle timer on `events_seen` (which
the draw block resets) froze it at startup, and gating on
`job_scheduler::is_busy` meant a feed that is still flowing — exactly the state
that grew the heap — never qualified. Measured on the shipped mimalloc build with
the same `SOAK` script: settled RSS **126 MiB with the reclaim off, 93–100 MiB
with it on** across four runs; peaks unchanged. The spread is *when* the first
collect lands (the app keeps redrawing while the boot's events stream), not
whether it reclaims. The remaining anonymous memory is the allocator's per-thread
heaps, which a process-wide collect does not return.

Audit-run facts worth keeping (2026-11-13, `rev 1eac71656619-dirty`, toolchain
1.99.1): `SOAK=1` curves reached 110 MiB (traced) and 108 MiB (mimalloc) at t=5 s
and were flat to the end — P1's acceptance is stated against exactly these two
curves. The `leas::ui` boot cost was measured at 2.46 M allocations on an empty
database, so *any* optimization aimed at rows must first explain that number
(P0). `scripts/trace_app.py` gained `KEYS`, `SOAK`, RSS sampling and smaps dumps
for this audit; the runbook documents them.
