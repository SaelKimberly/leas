# Memory reduction — implementation plan

**Date:** 2026-11-10
**Spec:** `docs/aegis/specs/2026-11-10-memory-reduction-design.md` (D1–D10)
**Status:** executed — T1–T9 landed. Verification: workspace clippy clean,
fmt clean, hakari unchanged, `cargo nextest run -p leas -p leas-db -p leas-geoip`
681/681. Measured on a pristine 13,803-link feed: idle 122→79 MB; Fast Test
(All) peak 374→196–299 MB (run variance), settle 264–275→182 MB, in-flight
sockets 2,421→≤~120 steady. The spec's peak ≤180 MB target is MISSED on the
higher runs; the remaining gap and its next lever are recorded there.

## Goal

Idle floor ≤ 90 MB and `Fast Test (All)` peak ≤ 180 MB / settle ≤ idle + 30 MB
on the 13,803-link reference feed, with no behavior change to single-probe
paths and no data-loss path on database open.

## Architecture

- `crates/leas/src/alloc.rs` owns the single `#[global_allocator]` (mimalloc
  3.6.1) with the default purge policy; `leas-db` keeps turso's `mimalloc`
  feature off.
- `leas-geoip` reads the mmdb through a file mapping (`Reader<Mmap>`).
- `ops/ping.rs`: the fast-only half takes a `real_ping_concurrency` permit;
  the fast probe dials the plan's resolved address with one hostname fallback;
  one `FastPingManager` per runner.
- `main.rs` builds the tokio runtime explicitly to bound the blocking pool.
- `leas-db`: an open failure propagates instead of deleting the database.

## Tasks

**T1 — allocator ownership and purge policy.**
`mimalloc-safe` 0.1.70 + `v3` (mimalloc 3.6.1) direct dependency (turso feature
off, done), `alloc.rs` declares the global allocator, `release_freed_heap()`
keeps `mi_collect(true)`. No `purge_delay` override: on 3.x the job-end collect
already settles the heap and eager purge costs ~1.7–3x on the burst (spec D2).
Verify: `cargo nextest run -p leas alloc`, `nm` shows `mi_collect`.

> Superseded 2026-11-10: the original T1 pinned `mimalloc` 0.1.52 (3.3.2) and
> set `purge_delay=0`; the allocator lab showed 3.6.1 at default purge is
> 2–4x faster on the same shape, so the pin and the override changed. The
> option-index unit test is gone with the override.

**T2 — mmap the GeoLite database.**
Enable `maxminddb`'s `mmap` feature, switch `GeoIp::reader` to
`Reader<Mmap>`, open with `Reader::open_mmap` under a SAFETY note (the only
writer writes a temp file and renames). Verify: geoip tests (fake artifact
path) plus a runtime smaps check that the mmdb is file-backed.

**T3 — one concurrency limit for the fast half.**
Acquire the permit in `dispatch_fast_link` (fast-only batches), sized by
`real_ping_concurrency`, and move it into the spawned chain. Taking it inside
the chain still spawned one future per link (13.8 k); taking it at dispatch
stops the walk at the limit, so the queued futures never exist. Fast-only
batches dispatch no real halves, so no deadlock.
Verify: a batch test asserting at most `real_concurrency` fast probes are in
flight (instrumented runner), plus the bundle test count unchanged.

**T4 — dial the resolved address.**
`fast_probe` dials the plan's first resolved IP when the endpoint is DNS;
on failure it retries once by hostname. The dedup key uses the same address.
Verify: a probe test where the resolver returns a loopback and the name does
not resolve, asserting the fast probe still succeeds; a second test asserts
the name fallback when the address is dead.

**T5 — bounded blocking pool.**
Replace `#[tokio::main]` with an explicit
`Builder::new_multi_thread().enable_all().max_blocking_threads(64)` runtime.
Verify: a batch run shows ≤ 64 blocking threads (thread count sampled), tests
green.

**T6 — one fast-probe manager.**
`EngineProbeRunner` holds `FastPingManager`; `fast()` reuses it.
Verify: `ops::ping` tests green; the flow lab still compiles.

**T7 — database open must not delete data.**
Remove the wipe-on-open-failure branch; propagate the error with the path.
Keep the `IncompatibleSchema` wipe. The test uses an unopenable file
(`a_failed_open_leaves_the_file_untouched`): a second-open lock race is not
deterministic, while the failure path and the preservation are the same.

**T7a — release the batch's shared state.**
`BatchShared.batch_slot` held `Arc<Self>` inside the object it publishes:
a reference cycle that kept the whole batch (per-link maps, per-protocol config
cache) alive per run. Switch it to `Weak` and pin it with
`a_finished_batch_releases_its_shared_state`.
Verify: the new test, plus repeated-batch RSS stays flat instead of +59 MB.

**T8 — verification matrix (pristine feed snapshot).**
Restore `data.db` before each run; measure idle RSS, fast-batch peak/settle,
socket peak, thread peak; compare against the spec's acceptance numbers.

**T9 — documentation.**
Update the spec/plan status, `ops/ping.rs`'s D14 comment (the fast half now
takes a permit), and the `d` dump note if the numbers it prints change.

## Verification commands

```
cargo fmt --all --check
cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings
cargo nextest run -p leas -p leas-db
cargo hakari generate --diff
```

Measurement: `ptyfast` / `ptyidle` harness on a copied feed, restoring
`data.db` per run.
