# Plan: Migration to True MVCC Architecture

- **Spec / Basis:** `docs/aegis/specs/2026-09-24-turso-mvcc-rollout-design.md`, `docs/aegis/specs/2026-10-20-turso-0.9-access-design.md` (A/B evidence and tail latency diagnosis), ADR 0002 (`docs/aegis/adr/0002-write-behind-link-writer.md`), ADR 0012 (`docs/aegis/adr/0012-owned-turso-driver-and-migrations.md`).
- **Goal:** Redesign database write workflows from WAL-tailored macro-batching (512-row windows, 10.7 s timer floors, unbounded `DashMap` heaps, wide multi-table transactions) to an MVCC-first architecture: bounded micro-batches (16–32 rows), key-partitioned concurrency, out-of-band derived rank refresh, and bounded channel backpressure. Eliminate RAM bloat from `Coalesced<K, R, P>` triples while resolving MVCC page-conflict tail latencies.
- **Baseline refs:** `docs/reference/database.md`, `crates/leas-db/src/write_behind.rs`, `crates/leas-db/src/database.rs`, `crates/leas-db/src/endpoint_rank.rs`, `crates/leas/src/ops/ping.rs`, `crates/leas/src/ops/stream_import.rs`, `crates/leas/src/ops/enrich.rs`.
- **Compatibility:** Database file format remains unchanged (`read_version=255` for MVCC, `read_version=2` for WAL; Turso 0.9.0-pre.1 file format oracle confirmed bidirectional compatibility). Existing WAL files continue using WAL. MVCC remains explicit via `XRAY_TUI_TURSO_CONCURRENT_WRITES=1` until this migration meets the acceptance throughput gate. Public `Database` API remains backward compatible.

**Aegis Visibility:** A durable plan is required because the migration modifies cross-module persistence boundaries across `leas-db` and `leas`, replaces core concurrency structures in `WriteBehind<S>`, changes derived state refresh guarantees for `endpoint_rank`, and alters the database contention/durability contract.

**Requirement Ready Check:**
- Approved Source: User request for architectural migration to true MVCC; grounded by existing empirical findings in `specs/2026-10-20-turso-0.9-access-design.md` and `database.rs::mvcc_load_probe`.
- Scope: `crates/leas-db` (`write_behind.rs`, `database.rs`, `endpoint_rank.rs`) and `crates/leas/src/ops/` (`ping.rs`, `enrich.rs`, `stream_import.rs`).
- Acceptance Evidence:
  1. Elimination of unbounded heap growth in `WriteBehind` (replaced with bounded queue + backpressure).
  2. Micro-batch MVCC throughput exceeds WAL on disjoint multi-writer workloads with 0 retry exhaustions.
  3. Tail latency on concurrent writes under MVCC drops from 2.6–13.5 s down to sub-100 ms.
  4. All workspace tests (2499+) pass; zero clippy warnings.

**Change Necessity:**
Configuration or documentation cannot change concurrency semantics or heap usage. The current `WriteBehind<S>` implementation is hardcoded to 512-row windows and unbounded `DashMap` storage, and in-transaction rank refreshes inherently force cross-table B-tree page clashes under MVCC. Minimum code boundary = `crates/leas-db/src/write_behind.rs`, `crates/leas-db/src/endpoint_rank.rs`, `crates/leas-db/src/database.rs`, and writer integration call sites in `crates/leas/src/ops/`.

**Ripple Signal Triage:**
- Canonical Owner: `crates/leas-db` owns database concurrency and schema writes; `crates/leas` is the downstream producer.
- Downstream Consumers: UI ping event loops, batch ping pipeline, geo resolver drain, subscription stream import.
- Contract / Source of Truth: Staged rows in `WriteBehind` must remain readable or drain before readers scan the database; `endpoint_rank` must maintain correct ordering without holding transaction locks during link writes.
- Expanded Verification: Must run existing perf-lab probes (`mvcc_load_probe`, `geo_batched_fanin_probe`) plus a new micro-batch probe to prove before/after performance.

**TDD Route:** auto → **strict** (persistence, concurrency, cross-module data flow, and error-recovery behavior). RED tests for bounded queue backpressure, partitioned worker routing, and decoupled rank maintenance before implementation.

---

## Tasks

### Phase 1: Perf-Lab Baseline, Micro-Batching Harness & Decision Gate

- **T1 — New Perf-Lab Harness: `micro_batch_mvcc_probe` (DECISION GATE)** (`crates/leas-db/src/database.rs` tests or `tests/turso_planner.rs`):
  - **Purpose:** Benchmark fine-grained and micro-batched concurrent writes (batch sizes: 1, 8, 16, 32, 64, 128, 512) across 16 and 32 Tokio writers, under both WAL and MVCC on a realistic disjoint feed.
  - **Measurement Metrics:** Wall time, p50/p95/p99 latency, conflict count, retry exhaustions, and checkpoint stalls.
  - **Decision Gate:** Proceed to Phase 2 **only if** micro-batch MVCC (16–32 rows) demonstrates a decisive win over WAL on the disjoint production shape (lower median latency, p99 < 100 ms, zero retry exhaustion). If MVCC remains 75–95× slower or continues exhibiting multi-second tail latency due to Turso core dirty-key checkpoint thrashing, **STOP HERE**, record the negative empirical finding, and keep WAL as the default.
  - **Verification:** `cargo test -p leas-db --release --features perf-lab -- --ignored micro_batch_mvcc_probe --nocapture`.

### Phase 2: Decouple Derived Rank Refresh from Link Transactions

- **T2 — RED Test for Out-of-Band Rank Dirtying** (`crates/leas-db/src/endpoint_rank.rs`):
  - Add test asserting that `apply_link_patches_tx` can execute purely on `profile_stats` without invoking `endpoint_rank::refresh`, marking touched `EndpointId`s in an in-memory dirty set.
  - Assert that a subsequent `drain_dirty_ranks(&mut tx)` correctly synchronizes `endpoint_rank` before page loads.
  - Run → FAIL.
- **T3 — Decouple `endpoint_rank` Maintenance from Transaction Bodies** (`crates/leas-db/src/endpoint_rank.rs`, `crates/leas-db/src/database.rs`, `crates/leas-db/src/write_behind.rs`):
  - Update `CacheSpec::refresh`: make in-transaction refresh optional or no-op for link patches under MVCC mode.
  - Implement atomic dirty set (`Arc<DashSet<EndpointId>>` or bitset) tracking endpoints needing rank recomputation.
  - Hook dirty set drain into `profiles_page` / `load_page_projection` pre-scan hooks, ensuring readers observe truthful ordering while writers never pay B-tree page collision penalties.
  - Run T2 → PASS. Verify `cargo nextest -p leas-db`.

### Phase 3: Bounded Memory & Elimination of `Coalesced` Source Triples

- **T4 — Invariant Guard: `stage()` Stays Synchronous and Non-Blocking** (`crates/leas-db/tests/write_behind_bounds.rs`):
  - Guard the ADR 0002 §3 contract: `WriteBehind::stage` MUST NOT await, block on I/O, or acquire locks that yield to the Tokio executor. UI event loop (`poll_core_events`) and sync disconnect paths call `stage()` synchronously.
  - Verify that memory bounds are enforced via:
    1. Key-space deduplication in `DashMap` (natural ceiling bounded by link count: repeated pushes to an existing key overwrite in place).
    2. Async-only backpressure in background producers (`stream_import::push`), which can yield if `pending.len() > HIGH_WATERMARK`.
  - Run → PASS.
- **T5 — Eliminate `Coalesced<K, R, P>` Source-Row Retention & Enable Micro-Batches** (`crates/leas-db/src/write_behind.rs`):
  - In `WriteBehind::flush`, eliminate the `Coalesced<K, R, P>` triple where the full source row `R` was cloned and held in heap alongside patch `P` solely for re-staging on rollback.
  - Implement in-worker retry: if a micro-batch write fails or encounters busy contention, retry the borrowed patch slice directly in the flush worker rather than cloning rows back into `pending`.
  - Add configurable `flush_rows` floor: support micro-batching down to 16–32 rows under MVCC (vs 512 for WAL).
  - Run T4 & all existing `write_behind.rs` tests → PASS.
### Phase 4: Hash-Partitioned Concurrency & Secondary Index Contention Management

- **T6 — RED Test for Partitioned Writer Throughput & Retry Absorption** (`crates/leas-db/tests/partitioned_writers.rs`):
  - Assert that multiple worker tasks partitioned by `endpoint_id % PARTITIONS` can execute concurrent `BEGIN CONCURRENT ... COMMIT` micro-batches (16–32 rows).
  - Because `profile_stats` carries `index_profile_stats_by_last_seen_at` (a timestamp index where current timestamps cluster on the same rightmost B-tree leaf pages), conflicts *can* occur at the index leaf page even when PKs are disjoint.
  - Assert that with jittered backoff (1–5 ms), all concurrent transactions successfully commit within the 5-attempt budget with **zero retry exhaustions** (`retry_exhausted == 0`).
  - Run → FAIL.
- **T7 — Implement Partitioned Concurrent Drain with Index Coarsening** (`crates/leas-db/src/write_behind.rs`, `crates/leas-db/src/database.rs`):
  - Support an $N$-channel worker pool ($N = 4$ or $8$) inside `WriteBehind` when `db.uses_concurrent_writes()` is true, routing staged keys by `hash(key) % N`. This isolates primary key B-tree leaves and per-endpoint indexes across partitions.
  - Mitigate `index_profile_stats_by_last_seen_at` leaf contention: update `last_seen_at` only when older than a coarse threshold (e.g. 60 s staleness), or ensure RESULT patches leave `last_seen_at` untouched (adhering strictly to `LinkGroups::RESULT` vs `SOURCE` disjoint column writes).
  - Wrap partition commits in standard bounded optimistic retry with randomized jitter.
  - Run T6 → PASS.
### Phase 5: Pipeline Cutover & Observability

- **T8 — Downstream Writers Cutover** (`crates/leas/src/ops/ping.rs`, `crates/leas/src/ops/enrich.rs`, `crates/leas/src/ops/stream_import.rs`):
  - Wire the micro-batch and partitioned drain configuration into `AppState::link_stage`, `GEO_DRIVER`, and `stream_import`.
  - Ensure graceful shutdown (`flush()` drains all partitions with full barrier synchronization).
- **T9 — Full Workspace Verification & Benchmarking**:
  - Run `micro_batch_mvcc_probe` on synthetic 20k and 74k feeds.
  - Verify that under MVCC, tail latency drops below 100 ms and disjoint batch throughput matches or exceeds WAL.
  - Run `cargo nextest run --workspace`.
  - Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
  - Run `cargo fmt --check`.

### Phase 6: Documentation, ADR & Governance

- **T10 — Documentation & ADR**:
  - Update `docs/reference/database.md`: document the true MVCC micro-batching architecture, the partitioned drain model, and decoupled rank maintenance.
  - Draft ADR 0014: "True MVCC Architecture: Bounded Micro-Batching and Partitioned Writes" superseding the WAL-only batching assumptions in ADR 0002.
  - Update `docs/aegis/INDEX.md` with this plan and resulting ADR.

---

## Verification & Acceptance Gates

1. **Compilation & Quality Gate:**
   - `cargo check --workspace --all-targets` (0 errors)
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings` (clean)
   - `cargo fmt --check` (clean)
   - `cargo nextest run --workspace` (all 2499+ pass)
2. **Empirical MVCC Gate:**
   - Run `micro_batch_mvcc_probe`: MVCC at 16–32 rows per batch must demonstrate zero `retry_exhausted` errors across 32 writers.
   - P99 latency under MVCC fan-in must not exceed 100 ms (eradicating the 2.6–13.5 s tail seen in 0.9.0-pre.1 under 100-row batches).
   - Peak memory consumption of `WriteBehind` during a 50k-link feed ingestion must drop by $\ge 70\%$ due to removal of source row caching.

## Risks & Retirement

- **Risk: Checkpoint stalls in Turso core.** If Turso 0.9.0-pre.1 engine still pauses during background dirty-key collection regardless of micro-batching, tune `wal_autocheckpoint` and report upstream.
- **Risk: Out-of-band rank drift.** If rank recalculation is deferred, a page query reading immediately after a ping transition might read an order based on stale latency if the dirty set is not flushed before the query. Mitigation: `profiles_page` explicitly drains the dirty rank set before issuing the covering index scan.
- **Retirement:** Retires `Coalesced<K, R, P>` source row retention, deletes `TIMER_FLOOR_DIVISOR = 4` staleness delay under MVCC, and retires unbounded `DashMap` storage.

**Execution Route:** `inline` (sequential architectural phases requiring tight coordination across driver, models, and UI event loops).
**User confirmation required:** no — bounded planning within authorized technical scope.
