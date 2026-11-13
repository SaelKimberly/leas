# Tracing allocations with `leas-memtrace`

The tracer answers "which module allocated this, and how much". It replaces the
process allocator, so it sees **this process only** — `xray-core`/`sing-box`
children are invisible by construction, and every artifact says so.

Two ways in:

| you want | command |
| --- | --- |
| a code path's cost, no app | `just memtrace [header\|connect\|geosite\|record\|all] [iterations]` |
| the app's real boot / session | `just memtrace-app [delay_secs]` |
| what changed between two runs | `just memtrace-compare a.json b.json [--force]` |

Artifacts land in `target/mem-trace/` (or `LEAS_MEM_TRACE_DIR`): `<label>-<pid>.json`,
`.txt`, `.folded`. The `.txt` is the readable table; `.folded` feeds flamegraph
tooling.

## Building

```sh
cargo build --release -p leas --features mem-trace
```

`mem-trace` implies `std-alloc`, so the traced binary runs on `System` instead of
mimalloc. **Allocation counts are allocator-independent; live/peak bytes are
not** — never compare a traced RSS with a release one.

## Knobs

| variable | meaning |
| --- | --- |
| `LEAS_MEM_TRACE_DIR` | artifact directory (default `target/mem-trace`) |
| `LEAS_MEM_TRACE_MIN_BYTES` | charge allocations below this to `<untraced>`; `0` traces everything, `64` is a sane default for long sessions |
| `KEYS` (driver) | scripted input for `scripts/trace_app.py`: `j:1,TAB:2,COMMA:2,ESC:1` — a chunk, then a pause; tokens `ESC`, `TAB`, `BTAB`, `ENTER`, `UP`/`DOWN`/`LEFT`/`RIGHT`, `COMMA`, `+` joins |
| `HOME_SRC` (driver) | source config directory to stage; point it at an empty directory for the no-profiles control run |
| `SOAK` (driver) | repeat `KEYS` until the delay expires and write an RSS CSV under `TRACE_DIR` (long-session curves) |
| `LOG` (driver) | keep the app's PTY output in `TRACE_DIR/app.log` (the only way to see app-level diagnostics under the driver) |
| `TRIM` (driver) | endpoints kept in the sandbox copy (default 3 000) — the knob behind the scaling runs |
| `LEAS_IDLE_PURGE` / `_LOG` | `0` disables the event loop's idle allocator collect; `_LOG=1` prints each one |
| `LEAS_MEM_TRACE_FOLD=allocs` | rank folded stacks by allocation count instead of live bytes (per-frame temporaries hold nothing at snapshot time) |
| `LEAS_MEM_TRACE_INTERVAL_SECS` | write `tick-N` artifacts every N seconds — the evidence a killed run leaves behind |
| `LEAS_MEM_TRACE_INTERVAL_MAX` | cap on retained ticks (default 32, oldest pruned first) |

## Sandbox rules (the app)

`scripts/trace_app.py` stages these; they are the traps that cost this project
hours:

1. **`HOME`, not `XDG_CONFIG_HOME`.** The app resolves
   `dirs::config_dir().join("leas")`. Pointing `XDG_CONFIG_HOME` at a scratch
   directory makes it read `$XDG_CONFIG_HOME/leas`, find nothing, create a fresh
   database and download its own 10.9 MB `geosite.dat`. The "boot profile" then
   describes a first install.
2. **Pin `groups.last_refreshed`.** Ten due subscriptions turn a boot
   measurement into an import benchmark.
3. **Copy, never point at the real directory.** The app writes (write-behind
   flushes, rank updates, checkpoints).
4. **Trim the database for a TUI driver.** A 64 577-row profile database keeps
   the app busy enough that a scripted `q` is not always read; a 3 000-row copy
   booted reliably. `trace_app.py` does this automatically (and fails the recipe
   rather than tracing an unprepared sandbox — a run on the wrong database is
   worse than none).
5. **Give the exit a long drain.** The exit artifact is written after the event
   loop returns and the runtime shuts down; a 10 s drain killed runs before the
   write and produced nothing. `trace_app.py` waits up to 90 s.

The driver also samples `VmRSS`/`VmHWM` and keeps the last `/proc/<pid>/smaps` as
`rss-<pid>.smaps`: an artifact's `peak_live_bytes` is the heap the tracer saw, not what
the OOM killer sees, and the two differ by the resident binary image and allocator
retention (see `mem-audit/report.md`).

## Reading an artifact

Header lines state scope, duration, `rev`, `allocator`, `fold` mode, roots,
`min_bytes`, cache counters, total frames walked and the symbol-slab overflow
count. Two tables follow: rows sorted by **live bytes** (what is held now), then
`by allocations` (what churns — a row that allocates and frees holds nothing and
would otherwise be invisible), and a per-crate rollup.

Attribution is by **module path**, charged to the innermost frame that resolves
to a traced root (`roots` in the app: every `leas*` crate). So work inside a
dependency called from workspace code is charged to that workspace caller —
`leas::ui`'s row is mostly ratatui widget work, not our strings. `<untraced>`
counts only stacks with **no** workspace frame, plus allocations under
`min_bytes`.

## Comparing runs

```sh
just memtrace-compare target/mem-trace/a.json target/mem-trace/b.json
```

Prints per-module Δallocations/Δbytes, biggest change first, and refuses to diff
artifacts whose `schema`, `rev` or `roots` differ (`--force` overrides). Two runs
of the same binary are **not** identical: measured run-to-run band on a fixed
workload is ±0.006 % on a traced row and ±57 % on `<untraced>` (thread timing),
so treat small deltas on `<untraced>` as noise.

## Cost

The tracer's own overhead on an 11 s boot, measured with `trace_app.py`:

| build | CPU |
| --- | ---: |
| untraced (mimalloc) | 0.55 s |
| traced, sub-`min_bytes` filtered | 0.72 s |
| traced, full capture | 6.8 s |

The remainder is the stack walk (`capture: frames walked … per attributed
allocation` in the header — ~17 on the app). A run that is CPU-bound pays for
it; an idle UI does not.
