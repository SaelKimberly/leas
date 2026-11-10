# Memory reduction — design

**Date:** 2026-11-10
**Status:** approved direction (user: floor and peak), implementation in
`docs/aegis/plans/2026-11-10-memory-reduction.md`.

## Goal

Cut both ends of the resident-set curve measured on a 13,803-link reference
feed: the idle floor (122–136 MB) and the test-batch peak/settle (374/275 MB
with mimalloc 3.3.2; 360/292 MB with stats instrumentation).

## Evidence (measured, release build)

| measurement | value |
|---|---|
| idle floor: `huge` bin (mmdb in a heap `Vec`) | 53.3 MB peak (48.4 MB is the mmdb) |
| idle floor: `pages` touched / live small objects | 69.9 MB / 6.2 MB |
| idle floor: arena committed | 115.8 MB |
| `Fast Test (All)` | 1,475–4,928 sockets, peaks 315–539 MB |
| threads during that batch | 23 → 262, all tokio blocking-pool threads |
| — cause | `tcp_ping` dials the hostname → `getaddrinfo` on `spawn_blocking` |
| allocator peaks in that batch | `binned` 169.4 MB, `huge` 119.6 MB, committed 613.7 MB |
| after the batch (threads back to 23) | RSS stays 275–292 MB |
| `mi_collect` reach (mimalloc 3.3.2, `theap.c:149`) | caller's thread heap + arena purge only |
| mimalloc 3.6.1 A/B, same feed | peak 396 / settle 392 (untuned), 347 / 309 (pd=0, mult=1, thp=0) |
| settled RSS across repeated batches | +59 MB per batch before D11 |
| mimalloc 3.3.2 A/B, same feed | peak 374 / settle 275 (default); 358 / 264 with `purge_delay=0` |

## Decisions

**D1 — Allocator stays mimalloc 3.3.2, owned by `leas`.** The 3.6.1 upgrade
(`mimalloc-safe` + `v3`) was measured on the identical feed and is worse for
this workload in every configuration tested (settle 392 untuned, 309 tuned vs
275). `[global_allocator]` remains in `crates/leas/src/alloc.rs`, `leas-db`
keeps turso's `mimalloc` feature off. Revisit when a newer crates.io sys crate
appears or the workload changes.

**D2 — `purge_delay=0` at startup.** mimalloc returns free pages only when a
later allocation fires the timer; eager purge measured 374→358 MB peak and
275→264 MB settled on the pristine feed (an earlier, differently-warmed copy
showed 360→308 / 292→253). Small but consistent, and it removes the timer from
the reclaim path. Set
programmatically through `mi_option_set(mi_option_purge_delay, 0)`; a unit test
pins the enum index (15 in the 3.3.2 header) so a dependency bump cannot
silently retarget the option.

**D3 — Keep the job-end reclaim** (`mi_collect(true)`), which purges arena
ranges process-wide; the thread-local limit is documented, not worked around.

**D4 — mmap the mmdb.** `maxminddb`'s `mmap` feature (off by default) with
`Reader<Mmap>`: 48.4 MB moves from anonymous heap to a file mapping the kernel
can evict and share. The update path already replaces the artifact by
temp-file + rename, so the mapping is never truncated under the reader; a
replaced file is reopened through the existing heal path.

**D5 — One concurrency limit.** The fast-only probe takes the
`real_ping_concurrency` permit (spec D14's "one limit", which the code did not
honor: `ping.rs:1854`). This bounds sockets, in-flight tasks and the whole
batch peak to the same value the real phase already uses.

**D6 — Dial the resolved address.** A batch already resolves every endpoint
(`DnsResolveRequest`); the fast probe now dials that address and retries once
by hostname on connect failure. `Fast` is a transport span, so DNS is excluded
by design; the fallback keeps a stale cached address from becoming a hard
`[fast]` marker that retires the real half. This removes the 240-thread
blocking-pool explosion.

**D7 — Bound the blocking pool.** The runtime is built with
`max_blocking_threads(64)`: `getaddrinfo`, `tokio::fs` and the log reader all
run there, and each thread gets its own mimalloc heap. `worker_threads` keeps
tokio's default (still env-overridable through `TOKIO_WORKER_THREADS`).

**D8 — One fast-probe manager.** `EngineProbeRunner` holds a single
`FastPingManager`; building a registry of boxed adapters per link was pure
churn on a 13 k-link run.

**D9 — A database open failure never deletes data.** The recovery branch in
`Database::open_with_concurrent_writes` wiped the file on ANY open error, which
destroyed a live user database when a second instance opened it (2026-11-10
incident, recovered from `/proc/<pid>/fd`). The wipe remains only for the
explicit `IncompatibleSchema` verdict (AGENTS decision 4); a lock/IO/parse
failure propagates and names the path.

**D11 — The batch handle is a `Weak`.** `BatchShared` owns the `OnceLock`
that publishes it (`state.batch`), and the slot held an `Arc` back to the same
object — a reference cycle, so every finished batch's per-link maps, per-
protocol config cache and counters stayed resident for the process's life.
Measured before the fix: settled RSS rose +59 MB per repeated feed-wide batch.
The slot now holds `Weak`; a regression test asserts the shared state is dropped
when the batch ends.

**D10 — Explicitly out of scope.** Log-cache byte caps, `CompactString`
interning of log targets, and per-thread `mi_collect` scheduling: measured at a
few MB each and not worth the surface until the big three (mmdb, batch peak,
blocking pool) are proven.

## Acceptance (measured after implementation)

- Idle RSS on the reference feed: **79 MB** (target ≤ 90; from 122–136). ✅
- `Fast Test (All)`: peak **196–299 MB** across runs (target ≤ 180 — MISSED on
  the upper runs; the early plan/enrichment phase sets it), settle **182 MB**
  (from 264–275; target "idle + 30" missed by the log/enrichment caches that
  the run fills). In-flight sockets **≤ ~120 steady, 345 transient** (from
  2,421) — bounded by `real_ping_concurrency`. ✅
- A failed open leaves the file untouched (test
  `a_failed_open_leaves_the_file_untouched`). ✅
- Workspace clippy, `cargo nextest run -p leas -p leas-db -p leas-geoip`
  (681/681), fmt, hakari green. ✅

Remaining gap (recorded, not claimed): the post-batch 182 MB settle is the log
cache (10 k lines the run fills) plus the batch's arena high-water; the peak's
plan/enrichment half is the next target if a lower ceiling is wanted.

## Risks

- Eager purge costs recommit churn on allocation-heavy bursts (measured; the
  peak dropped too, so net wins).
- mmap makes the reader dependent on the artifact's inode stability — safe
  because the only writer renames.
- The D5 cap changes `Fast Test` wall-clock on large feeds (bounded by
  `results ≈ cap / timeout`).
