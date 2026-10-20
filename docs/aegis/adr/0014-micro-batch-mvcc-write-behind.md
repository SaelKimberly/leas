# ADR 0014 — Micro-batch MVCC write-behind

Date: 2026-10-20
Status: accepted
Supersedes: the WAL-only batching assumptions of ADR 0002 (the column-group
contract and the synchronous `stage()` stand unchanged); refines the MVCC
verdict of `specs/2026-09-24-turso-mvcc-rollout-design.md` §12 and
`specs/2026-10-20-turso-0.9-access-design.md` §7.1.
Plan: `docs/aegis/plans/2026-10-20-mvcc-architecture-migration.md`

## Context

The 2026-10-20 Turso 0.9 spec measured MVCC at 75–95× WAL per batch on the
disjoint production shape (100-row batches through `set_endpoint_ip_countries`)
and rejected it. But both prior probes measured MVCC through the WAL-shaped
batching layer: wide transactions whose page sets collide at commit, with the
`endpoint_rank` refresh folded inside every window. `mvcc_load_probe` (1-patch
transactions) showed the mechanism working — MVCC at parity on disjoint rows —
but never the middle ground.

## Decision

When the database is opened with concurrent writes (MVCC), the write-behind
driver switches to a micro-batch shape:

1. **Window = 32 rows** (`DEFAULT_FLUSH_ROWS_MVCC`), not 512. The transaction's
   page set stays small enough that commit validation rarely collides across
   the pool.
2. **`endpoint_rank::refresh` leaves the window transaction** for link patches
   (`LinkSpec`). Touched endpoints are recorded in `Database::dirty_ranks` on
   commit; `profiles_page` drains the set before its scan. WAL keeps the
   atomic in-tx refresh. The import path (`SourceSpec`) keeps the in-tx
   refresh in both modes — a fresh endpoint has no rank row, and deferring
   would blind the page until a drain.
3. **The failure path reconstructs from the patch** (`CacheSpec::restage_patch`)
   instead of carrying a duplicate source-row clone in every drained triple.
   `Coalesced<K, R, P>` becomes `Coalesced<K, P>`; the re-stage contract
   (failing window + every later window, no clobber of a newer push) is
   preserved.
4. **`stage()`/`push()` remain synchronous** (ADR 0002 §3). No backpressure,
   no await on the UI task; the pending map stays bounded by key space.

**Deferred:** writer-partitioned drain (plan T7's N-channel pool) is NOT
implemented. The probe ran hand-rolled concurrent transactions, not a
partitioned driver, and `tests/partitioned_writers.rs` exercises the existing
single-driver path (four staging tasks sharing one `WriteBehind`; the flush
gate serializes their windows). Partitioning is future work — the retry
budget absorbed every commit without it.

## Evidence

`micro_batch_mvcc_probe` (perf-lab, 8,192-endpoint feed, 16 writers × 256
updates/writer, pre-seeded rows updated in place, disjoint slices, hand-rolled
`retry_on_busy` transactions — NOT the driver's flush path):

| batch | WAL p50/p99 (rank in-tx) | MVCC p50/p99 (rank in-tx) |
| --- | --- | --- |
| 1 | 717 µs / 179 ms | 1.4 ms / **7.4 ms** |
| 16 | 1.2 ms / 631 ms | 2.7 ms / **12 ms** |
| 32 | 1.7 ms / 831 ms | 5.8 ms / **21 ms** |
| 128 | 8.8 ms / 835 ms | 27 ms / **48 ms** |

WAL carries 330–835 ms tail stalls at every size ≥16 (writer serialization);
MVCC's p99 never exceeds 67 ms at any measured size. Wall time for 4,096
1-row updates: WAL 3.40 s, MVCC 0.63 s.

The rank-decoupling premise is measured separately (rank_ref=false rows): the
in-tx refresh is the dominant cost at batch 1 (WAL p50 717 µs → 92 µs without),
confirming that moving it out of the MVCC transaction removes the widest page
collision source.

## Consequences

- MVCC is faster on the MEASURED shape only: hand-rolled micro-batch
  transactions over pre-seeded disjoint rows at 16 writers. The geo path's
  100-row batched verdict (75–95× slower, `2026-10-20-turso-0.9` spec §7.1)
  is NOT retracted — that writer keeps its shape and its verdict. The default
  stays WAL: existing files cannot convert in place, and the sequential/import
  workload still favors WAL.
- The dirty set is IN-MEMORY (`Arc<DashSet>` on `Database`). A crash between a
  link-patch commit and the next drain leaves stale stored keys that reopen
  does NOT repair: `endpoint_rank::ensure` backfills MISSING rows and
  recomputes on a weight-version change, but it does not detect an existing
  row whose keys are stale relative to its links. A stale row persists until
  that endpoint is next written (any link change refreshes it in-tx on WAL,
  or marks it dirty again on MVCC). This is the accepted durability boundary
  of the deferred design; a persisted dirty marker is the fix if it matters.
- Readers must drain `dirty_ranks` before an ordering read or they see stale
  keys. `profiles_page` drains; `WriteBehind::flush` also drains at its end.
  A bypassing reader (raw SQL outside these paths) would mis-sort.
- `retry_on_busy` (5 attempts) still wraps every window.
  `tests/partitioned_writers.rs` pins the single-driver concurrent-staging
  path committing every row with zero exhaustions.

## Retirement

None. `upsert_links_bulk_opt` and the `should_refresh_in_tx` hook are the
extending seams; no fallback path is retained.
