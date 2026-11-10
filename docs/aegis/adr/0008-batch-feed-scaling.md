# 0008 — Batch-feed scaling: id-ordered walk, per-protocol loads, throttled page refetch

Date: 2026-09-18
Status: accepted — decision 1 SUPERSEDED 2026-10-01 by the static config weight (see "Superseded decision 1" below)
Related: decisions 15 (batch pipeline), 16 (tiers + labels), 21 (SQL page + materialized keys),
22 (write-behind RESULT group); ADR 0003 (stored ordering keys), 0005 (address table)
Spec: `docs/aegis/specs/2026-09-17-batch-ping-pipeline-design.md` (the pipeline this amends)
Evidence: `crates/xray-tui/src/ops/ping/flow_cost.rs` (ignored perf lab — see "Evidence" below)

## Context

A `Fast + Real Ping` run over a whole feed makes every per-link step visible: at 100k links a
step that costs microseconds per link is seconds of serial work, and a step that runs on the
UI task competes with probe dispatch. Measurement (7,486-endpoint / 9,090-link reference
feed, medians over the warm samples of each section) located four such steps, plus one
structural query cost the tab pays on every result-driven refetch:

| site | measured before |
| --- | --- |
| feed walk, `PageSort::Address` (hardcoded twice in `PlanWalk`) | 11.9 ms/page × 38 = ~450 ms |
| `real_probe`, `load_protocol_with_config` per LINK | 55–121 µs → 0.5–1.1 s over 9k links |
| `SpeedTestResult` handler → page refetch, per RESULT | 22–25 ms per UI tick (tick = 16 ms) |
| `LinkWriter::stage`, `pending.len()` per stage call | 1.06 µs of stage's 1.12 µs |
| `dispatch_page`, `Arc::new(endpoint.clone())` + map insert per LINK | ~1.9 µs/link |

## Decision

1. **The feed walk orders by `endpoint_id`** — a new `PageSort::Id`. The walk's requirement is
   an order no write can move while the batch runs; ids satisfy it exactly as host text did,
   and they are 3.2× cheaper (11.9 → 3.9 ms per page raw, 12.1 → 3.0 ms in the walk, both
   through the app's own driver). Nothing displays this order.

   **SUPERSEDED 2026-10-01** (spec
   `docs/aegis/specs/2026-10-01-static-config-weight-design`). The walk now orders by the
   decision-16 law (`PageSort::Test`), so the most reliable links are probed first. The
   requirement this decision met — an order no write can move — is deliberately given up:
   the new order is the weight/metric ranking the batch itself rewrites. It is restored by
   other means instead: `PlanScope::All` now reads its whole id set ONCE before the first
   probe and serves it in page-sized chunks, the same freeze the scoped walks already used
   for exactly this reason. The 3.2× cost advantage of the id order is the price paid; the
   title's "id-ordered walk" no longer describes decision 1.
2. **Real probes load each `ProtocolId` once per batch** (`BatchShared::protocols`,
   `DashMap<ProtocolId, Arc<LoadedProtocol>>`). A `Protocol` row is shared by every endpoint
   carrying the same config (identity ignores host/port: 6,283 rows for 9,090 links on the
   reference feed), and a load failure is deliberately NOT cached, so a transient read error
   cannot poison the protocol for the rest of the run.
3. **A result-driven page refetch is per-VISIBLE-row and throttled during a batch.** The row
   is already patched in memory by the handler; the refetch exists to re-place it in the
   ordered window, which is a statement about a row the window can show. Off-page results (a
   feed-wide run's ~98%) request nothing; on-page results request at most one refetch per
   `RESULT_RELOAD_THROTTLE` (500 ms) while `batch_progress` is set. `BatchEnded` clears the
   stamp and requests one final refetch, so the window always settles on the exact final
   order. A single manual ping keeps its immediate refetch.
4. **The write-behind flush trigger reads a counter, not the map.** `LinkWriter` keeps an
   `AtomicU64` in step with `pending` through two helpers (`put`/`take`), because
   `DashMap::len()` walks every shard on every call (1.03–1.08 µs of stage's 1.12 µs).
   `staged_len()` is unchanged as an API; the counter is pinned against the map by
   `staged_counter_matches_the_map_through_every_transition`.
5. **`PlanLink` shares its endpoint as `Arc<Endpoint>`** and `dispatch_page` inserts per
   ENDPOINT (`entry().or_insert_with`), so a plan page allocates one endpoint clone for a row
   rather than one per link. `PlanLink` shrinks 472 → 336 bytes, and `fast_probe` borrows the
   address instead of cloning it.

## Alternatives considered

1. **Throttle the page refetch only.** Rejected as the sole fix: it leaves the walk's 450 ms
   of plan latency and hides a structural query problem (the tab's default sort) behind a
   rate limit.
2. **An index on `endpoints(host, port)`.** Rejected by measurement: the planner keeps the
   rank-driven plan plus a temp B-tree sort (19.5 ms with the index present, unchanged), and
   forcing the index is slower (13.2 ms vs 11.9 ms).
3. **`rank_host`/`rank_port` columns in `endpoint_rank` + a covering index** (mirroring
   `endpoint_rank_test`), which is what would make the tab's default `Address` sort
   index-driven. Not taken: it needs schema tag 13, and a tag bump WIPES the database
   (decision 4). Left open below.
4. **`Arc<str>` or a prehashed `(u64, u16)` key for the fast-probe dedup map.** Rejected by
   measurement: 42 ns → 37 ns for the refcount bump, and the prehashed variant is *slower*
   (58 ns) because hashing the host bytes costs more than the clone saves.
5. **`CompactString` for `Endpoint.host`.** Deferred, not rejected: 94% of hosts fit the
   24-byte inline form (avg 15.1 over 7,486 endpoints), but the site it would fix is one
   26 ns clone per link (~2.6 ms per 100k links) and the type ripples through the toasty
   model, the DB builders and every UI call site.
6. **A counting `#[global_allocator]` for the lab.** Impossible in this crate: `turso`
   installs one via its default `mimalloc` feature and a second is a compile error; tracing
   the test binary with `valgrind --tool=dhat` dies with SIGILL at startup under that
   allocator. Allocation figures are therefore derived from the code path and backed by A/B
   timing of the allocation-free variant.
   **Superseded 2026-11-10:** `leas-db` no longer requests turso's `mimalloc` feature and the
   single `#[global_allocator]` now lives in `crates/leas/src/alloc.rs`, so a counting or
   tracing allocator is installable by replacing that one static.

## Consequences

- No schema change, no tag bump, no migration.
- Observable behavior change: while a batch runs, the Profiles window re-sorts at most twice a
  second instead of once per tick, and always once at the batch's end. A manual single ping is
  unchanged.
- Batch results for rows outside the loaded page no longer trigger any UI work; the batch
  still stages them (`emit_result` → `stage_result`), so persistence is unaffected.
- `LinkWriter::staged_len()` must stay exact for the flush trigger to fire; the counter is the
  only mutable-number source and the test above pins every transition (stage, coalesce, drain,
  failed-window re-stage in both its Occupied and Vacant arms).
- Still open, with measurements: (a) the tab's default `Address` sort costs 19–20 ms per page
  fetch against 0.37–0.77 ms for the materialized sorts, so a user-sorted Address tab pays it
  on every refetch — fixing it needs `rank_host` (schema tag 13, a data wipe); (b)
  `endpoint_rank::refresh` is ~22 µs per endpoint (~half of `apply_link_patches`'s per-window
  cost) and does two SELECTs plus one multi-row INSERT per window; (c) the lab's in-memory
  end-to-end batch shows an intermittent, exactly ~3.09 s stall that did not reproduce in
  isolation (`finish_batch` alone measured 36 ms, a cold `db.connection()` 153 µs) — the only
  multi-second bounds on that path are `finish_batch`'s 2 s connection and 2 s checkpoint
  timeouts.

## Evidence

Run the lab (ignored by default, no network, no core binaries):

```text
cargo test -p xray-tui --release --lib -- --ignored --nocapture flow_cost
XRAY_TUI_MEASURE_DB=<copy of data.db> cargo test …   # the real-feed rows
```

Every row is the median of its samples (`Acc`), because the first sample of a section pays
page-cache, statement compilation and pool setup that steady state never pays. After this
change: `stage` 1,120 → 54 ns, `stage_result` 1,128 → 80 ns, walk 12.1 → 3.0 ms/page,
`PlanLink` 472 → 336 B, and `run_batch` (stub probes, 2,000 links) 55–70 µs/link.


## Note — 2026-09-22: the untestability counter is one counter

Spec: `2026-09-22-native-testability-improvement-design.md` (T7).

`counters.untestable` counted only the plan-time kind gate, while a config-level capability
refusal incremented `real_failed`/`real_fail[Config]` — one fact booked twice, which is why a
run line could read `untestable=0 … config=173` where the 173 were the persisted untestable
markers. `emit_result` now routes both to `untestable`, off a single shared predicate
(`is_untestable_text`, which `is_untestable_marker` delegates to).

The run line's other counters are unchanged, and the batch's `summary_line` remains the only
record a run writes.
