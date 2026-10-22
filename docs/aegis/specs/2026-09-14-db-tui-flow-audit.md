# DB ↔ TUI flow audit

Date: 2026-09-14
Status: research complete; implementation not started (see §6 plan)
Method: 6 read-only scout surveys over disjoint slices (query call sites, schema/indexes,
write paths, read/hydration, startup/import/housekeeping, memory), cross-checked against
measurements taken directly on a fresh tag-8 database (7,672 endpoints / 15,344 links and a
2,000-endpoint fixture). Every claim below is either measured here or carries a `path:line`
and is marked *needs probe* when it does not.

## 1. Measurements (this pass, not inherited)

| Path | Cost | Note |
| --- | --- | --- |
| one page load, as shipped | **12 statements, ~600 binds** | 6 PRAGMA + 6 data (S4) |
| `load_page_rows(200 ids)` | **488 ms** | the page's dominant term |
| page query (`profiles_page`, incl. count) | 9.6–14.3 ms | index-driven, ADR 0003 |
| `in_list(200 ids)` matching **nothing** | 80 ms | pure statement cost, zero rows |
| same rows with ids **inlined** in SQL text | 9.7 ms | 17× cheaper than binds |
| **one raw statement, endpoints ⋈ links, ids inlined** | **29 ms** | the hydration floor |
| typed `in_query(projected subquery)`, same rows | **1111 ms** | DEAD END — turso re-runs it per outer row |
| `profile_link_order(200)` (second read of the same links) | 22 ms | duplicate work, cheap |
| in-memory link sort (the Rust order) | 0.12 ms / 400 links | — |
| `db.connection()` acquisition (2 PRAGMAs) | 0.08 ms | 6/page ≈ 0.5 ms: **not hot** |

## 2. The four flows, as they stand

1. **Page reload** (`reload_profiles` → `load_profiles_rows`, `ops/profiles.rs:118`):
   `clear_expired_errors` (no-op unless an error TTL is set) → `profiles_page`
   (COUNT over `endpoint_rank` + the index-scan page) → `load_page_rows`
   (`Endpoints::in_list(200)` + `ProfileStats::in_list(200)` + `Protocol::in_list(N)` +
   in-memory join + sort + `profile_link_order(N)` + re-sort + reindex).
2. **Batch tick** (`ui/mod.rs:167`): a dirty tick runs `profiles_count`, then **up to two
   full page loads** plus `profiles_anchor` (`reload_profiles_preserving_selection`,
   `ops/profiles.rs:222`).
3. **Batch gate** (`ops/scheduler.rs:413` `fresh()`): every `schedule`/`complete`/`cancel`/
   `sweep` does `read_link` → a connection (2 PRAGMAs) + one SELECT. Two transitions per
   link ⇒ **~60k reads per 30k-link batch**.
4. **Import** (`state.rs:360` `persist_parsed`): 6 statements + 6 PRAGMAs + one transaction
   per endpoint, on the UI task — while `upsert_*_bulk` (used by `stream_import`) exists.
   Measured: 848 µs/endpoint, 1.76 ms/link.

## 3. Findings

### Tier 0 — correctness (not performance)

| # | Finding | Evidence | Status |
| --- | --- | --- | --- |
| C1 | Four writers change ordering-law inputs without refreshing `endpoint_rank`: `update_last_used` (it also writes `last_seen_at`), `restore_endpoint`, `clear_all_stats`, `set_manual_override`. The page drives from the stored keys, so those writes are invisible (stale order, wrong Active/Stale window) until an unrelated refresh. | `database.rs:759, 1040, 1020, 877` | **FIXED this pass** (refresh per path; `backfill_all` for the wholesale reset) |
| C2 | `purge_expired` has **no production caller**: staleness retention never reclaims rows; the table only grows. | grep: only doc comments reference it | open |
| C3 | The Logs tab polls `read_newer_than(limit 100)` every 100 ms; a burst > 100 entries between polls is silently skipped (the cursor advances past them). | `ui/logs.rs` poll + `log_heed.rs` | *needs probe* |
| C4 | `EndpointId`'s non-zero invariant is not enforced by the schema; a zero id would alias the rank row. | `models_toasty.rs:187` | open |

### Tier 1 — hot paths

| # | Finding | Evidence | Expected |
| --- | --- | --- | --- |
| H1 | **Hydration**: three `in_list` statements dominate a page load (488 ms of ~500 ms). One raw statement over `endpoints ⋈ profile_stats` with ids inlined costs **29 ms**; the remaining unknown is decoding models from it (spike). | measured above | −460 ms/page |
| H2 | **Gate reads**: `read_link` always hits the database + a connection, even when the writer has the row staged; 2 transitions per link ⇒ ~60k reads/batch. | `link_writer.rs:98`, `scheduler.rs:413` | −30…60 s/batch |
| H3 | **`apply_link_patches`** does one SELECT **and** one UPDATE per patched row (~1024 statements per 512-row window) plus the post-commit key write. | `database.rs:637` | −0.5 s/window |
| H4 | **`add_server.rs:424` `get_endpoint` per keystroke** in the edit form: a full row hydration (~7 statements, 2 connections) to read one enum already present on the loaded row. | `ui/add_server.rs:416-426` | per-keystroke latency |
| H5 | **Double page load per dirty tick** + a COUNT that only changes with the dataset. | `ops/profiles.rs:222-258`, `ui/mod.rs:167` | −50% of tick cost |
| H6 | **Import on the UI task** via the single-row loop (`state.rs:360`) instead of the existing bulk path. | `state.rs:360`, `stream_import.rs:300` | minutes → seconds |
| H7 | `remove_failed_servers` runs N sequential `delete_endpoint` transactions (connection + transaction each). | `ops/ping.rs:400` | *needs probe* |
| H8 | `reorder_routing_rules` issues one autocommit UPDATE per rule, on the UI task, no transaction. | `ui/settings.rs:956` | *needs probe* |

### Tier 2 — structure (pre-alpha: free to change)

| # | Finding | Evidence | Expected |
| --- | --- | --- | --- |
| S1 | **Scheduler task state is persisted** (`task_id`, `task_queue` per link) although the gate is runtime-only and the writer's pending map is authoritative (ADR 0002). Dropping the two columns + the TASK group removes a whole write family, the `Vec` rewrite per transition, and OCC churn. | `models_toasty.rs:240`, `database.rs:1064` | −1 column group, −60k writes/batch |
| S2 | **Timestamps are 30-char ISO-8601 TEXT** (every jiff field) — larger indexes, string compares, a fixed-width invariant enforced only by convention (`sql_ts`). Epoch nanos/i64 is strictly better. | `models_toasty.rs`, `profiles_query.rs:115` | index size, compare cost |
| S3 | **`Protocol.config` (JSON) redeclares transport + security**, which are also separate columns; and the page hydrates full `Protocol` models for data it displays as three fields. A projection query (`Query::select` exists) plus a lighter page row would cut decode cost and remove a sync risk. | `models_toasty.rs:219` | decode cost, one source of truth |
| S4 | `ProfileStats.cred_hash` is derivable (`id ^ sig`); `Endpoint.resolved_as` (JSON) duplicates the child-endpoint rows created by `upsert_resolved_ip_children`. Pick one owner per fact. | `models_toasty.rs:220`, `database.rs:817` | storage, sync risk |
| S5 | Missing indexes on predicates that actually run: `endpoints.parent_id` (DNS/enrich lookups), `profile_stats.last_seen_at` (purge), `profile_stats.error` (failed-ids + sweep). | `database.rs:365, 908`, `profiles_query.rs:399` | scan → seek |
| S6 | TUI duplicates DB state: `endpoint_info` re-derives `resolved_as`, display rows are cloned per frame, `page_total` is cached. | `state.rs:172`, `ui/profiles.rs:596` | memory, drift |

### Tier 2b — memory & allocation

| # | Finding | Evidence | Expected |
| --- | --- | --- | --- |
| M1 | The whole page's `Vec<DisplayRowData>` is **deep-cloned on every draw**, even on a cache hit. | `ui/profiles.rs:596` | per-frame allocation |
| M2 | `endpoint_info` is **unbounded**: it accumulates one entry per endpoint *ever displayed*, approaching feed size at 40k. | `state.rs:172` | memory growth |
| M3 | The write-behind pending map stores a **full `ProfileStats` clone per column group** per staged link. | `ops/link_writer.rs:79` | batch memory |
| M4 | Each `EndpointRow` clones its links' `Protocol` models (with the config `Deferred`), and the country LRU clones `String`s per lookup. | `models_toasty.rs`, `state.rs` | per-page memory |
| M5 | Rings are properly bounded (`log_cache` 10k, `native_activity` 2k) — no finding; recorded as the counter-example. | `ops/events.rs` | — |

All memory numbers need an RSS probe; none of these is currently measured.

### Tier 3 — retirement (dead surface)

`profiles_ids`, `profiles_link_pairs`, `profiles_failed_ids`, `profiles_enrich_seed_ids`,
`profiles_count`, `get_endpoint_by_protocol_id`, `endpoints_by_parent` and `purge_expired`
have **no production caller** (S1/Q1). Each is code that must be read, tested and kept
consistent — the cheapest wins in this audit are deletions.

## 4. Proposed target shape

1. **One statement per page** in the raw module: a projection returning exactly the columns
   the list shows (endpoint + link + the 3 protocol display fields), ids inlined, decoded
   into a purpose-built page row rather than the full models. Connect-time needs the full
   `Protocol` (config included) for ONE protocol and already re-reads it
   (`load_protocol_with_config`).
2. **The gate reads from memory**: the writer serves `read_link` from its pending map +
   a read-through cache; the DB is touched only for rows it has never seen.
3. **Task state stops being a column**: the scheduler gate is runtime state; persisting it
   buys the startup orphan sweep and costs a write family.
4. **Timestamps and enums as integers**; one owner per fact (`cred_hash`, `resolved_as`);
   indexes on the predicates that run.
5. **Delete the dead query surface** (Tier 3).

## 5. Open spikes (each is a bounded probe, not a rewrite)

- **P1**: decoding a page row (endpoint + links + light protocol) from the raw projection —
  the only unknown between 488 ms and ~30 ms.
- **P2**: `read_link` call counts and cost during a real batch (instrument the gate).
- **P3**: log-poll burst gap (C3) — is it reachable at the shipped rates?
- **P4**: `purge_expired` intent — wire it, or delete the retention settings with it.
- **P5**: RSS + allocation counts for M1–M4 (tui-test harness or a `/proc` sample during scroll).

## 6. Plan (ordered by value ÷ risk)

| Phase | Work | Gate |
| --- | --- | --- |
| **0** | C1 (done), C2 decision, P3/P4 spikes | — |
| **1** | H1 + H5 + H4 + H3: page load to one statement, one load per tick, no per-keystroke hydration, batched patch window | H1 parity tests (page order, panel order, anchor) must stay green |
| **2** | H2 + S1: gate in memory, drop persisted task state | batch throughput measured before/after |
| **3** | H6 + H7 + H8: import through the bulk path, batched deletes/reorders | import wall-clock |
| **4** | S2 + S3 + S4 + S5 + Tier 3: schema and surface cleanup | one wipe (tag 9), then the full suite |

Each phase is independently shippable; phases 1–3 need no schema change, phase 4 does.

## 7. Delivered — phase 1 (page load), measured

Probe: fresh DB seeded through the bulk paths with 7,656 endpoints × 2 links
(15,312 links), in-memory turso, page size 200. `probe_page_cost.rs`, deleted after
this record (the numbers are reproducible from the seed it used).

| Operation | Before | After |
| --- | --- | --- |
| `load_page_rows` (typed hydration, 200 rows) | 1,027 ms | — (kept as the parity oracle) |
| `load_page_projection` (one statement, 200 rows) | — | **49.6 ms** |
| `profiles_page` (count + ordered ids) | (in the 12-statement load) | 13.2 ms |
| `profiles_count` alone | — | 7.5 ms |
| `profiles_anchor` | 65 ms (earlier probe) | 49.4 ms |
| **page load end to end** | **~1,040 ms** | **63 ms** (16.5×) |

Decisions this changed:

- **1.4 (count caching) dropped**: the count is 7.5 ms of the 63 ms load (12%). Reusing it
  needs a dataset-generation counter that every mutation site must remember to bump, and a
  missed site shows a wrong footer total — a correctness risk for a tenth of a load. The scan
  stays.
- **1.5 (anchor-then-load) narrowed**: anchoring FIRST costs 49 ms on every tick to avoid a
  second load that only the (rare) "selected row left the page" case pays. The common path
  therefore stays one load, and the re-anchor path now uses `load_profiles_page_only` so the
  error-TTL sweep — which writes — runs once per reload instead of twice.
- **1.3 turned out to be a correctness fix, not a cleanup**: the retired SQL link order put a
  measured success above a failure on a DNS-unresolved endpoint, while the law (decision 16,
  tier 5) sinks every link of such an endpoint. `page_projection_matches_the_orm_rows` pins
  the law's order for that pair (protocols 99 before 13 on a fresh failure beat a live
  measurement).

  > **Superseded 2026-10-22 (ADR 0003 amendment, `STAB_VERSION` 2 → 3):** the "tier 5 sinks
  > every link" clause is **no longer the law**. A MEASURED link keeps its measurement's band:
  > the probe dials the DNS name and the OS resolves it, without persisting the resolution, so
  > a DNS endpoint the probe reached has an empty address set AND a measurement — and the old
  > reading put a working server below the failures. The retirement of the SQL link order still
  > stands (one implementation, `RankLink::key`); only the tier-5 claim is corrected.

## 8. Delivered — phases 2 and 3

**Phase 2 (gate, writes, import, retention)**

> **Superseded 2026-09-16 (ADR 0002 amendment 4):** the per-row `UPDATE` and the `VALUES`-CTE
> existence probe described in the first bullet are both **retired**. Both link writers now emit one
> multi-row `INSERT … VALUES (…),(…) ON CONFLICT(protocol_id, endpoint_id) DO UPDATE …` per (400-row
> statement chunk, `ON CONFLICT` action) — the action bucketed by the patch's column groups with
> `contains`, `DO NOTHING` when a patch carries none — so the probe's predicate shape and
> `SQLITE_MAX_EXPR_DEPTH` no longer constrain this path. Measured 29.0 → 10.0 ms per 512-patch window
> and 360 → 44.3 ms per 2 000 imported links. The bullets below are the record of what phase 2
> delivered at the time; `docs/database-manual-sql.md` is the current authority for the shapes.

- The gate's persistence seam (`SchedulerDb`) is gone from the batch's hot path: it reads the
  caller's snapshot and its own staged state, so a transition costs a map lookup. The writer's
  drain now coalesces one patch per link (three column groups → one write), and
  `apply_link_patches` writes each existing row with ONE literal `UPDATE` covering only the
  groups — no SELECT per row, no bound parameters (turso charges ~0.8 ms each). The
  existence probe runs once per 400-row chunk, as one `VALUES`-CTE join on the composite key. Its
  shape is load-bearing: the first version chained `(protocol_id = .. AND endpoint_id = ..) OR …`,
  which is left-deep and exceeds `SQLITE_MAX_EXPR_DEPTH` from ~99 pairs, so every flush window
  wider than that failed its whole transaction and persisted nothing (fixed 2026-09-14; ADR 0002
  §amendment 2 has the measurements). Turso has no `UPDATE ... FROM (VALUES ...)`, so
  the per-row statements stay per-row.
- `persist_parsed` builds the batch and writes it in one transaction through the bulk upserts
  (the shape `stream_import` already used), instead of N autocommit upserts on the UI task.
- `remove_failed_servers` deletes through one `delete_endpoints` transaction; the typed
  per-endpoint delete is now that same function with a one-element slice. Routing-rule reorder
  is one transaction.
- Retention is wired: a 10-minute task (main.rs, same cadence as the log TTL) purges endpoints
  whose newest link aged past the retention window and reports `CoreEvent::RetentionPurged`, so
  the page re-reads. `purge_expired` had no caller before this.

**Phase 3 (schema, one wipe at tag 9)**

- Task state is runtime-only: `profile_stats.task_id`/`task_queue` are gone, `TaskScheduler`
  owns `HashMap<(ProtocolId, EndpointId), LinkTasks>`, `update_scheduler_state` and
  `sweep_orphans` are deleted, and `SchedulerDb` (trait + 3 impls + its mock) is deleted — the
  gate no longer has a database handle at all, which is why orphan ids are now
  unrepresentable rather than reconciled. Batch start calls `scheduler.reset()`.
- Timestamps are epoch SECONDS integers (9 columns): `sql_ts` (the fixed-width RFC3339 binder)
  and `parse_nanos` are deleted, the rank keys (`rank_seen`/`rank_display_seen`/
  `rank_newest_seen`) and `RankLink` compare seconds, `PageRequest` thresholds are seconds, and
  `to_epoch`/`from_epoch`/`now_epoch` are the only conversion points. `#[auto]` came off the
  four timestamp fields on purpose: on an integer column toasty's auto strategy is
  `Increment`, not "now", so the writers stamp them.
- `protocols.cred_hash` and `endpoints.parent_id` are gone, with the child-endpoint machinery
  (`endpoints_by_parent`, `upsert_resolved_ip_children`): `resolved_as` + `resolved_at` are the
  single owner of a DNS endpoint's resolutions.
- Index: `profile_stats.last_seen_at` (retention cutoff + staleness windows). `error`
  deliberately is not indexed — it is an embed, and `#[index]` has no `IndexableField` for one;
  the TTL sweep's scan is ~7 ms on a reload.
- Dead query surface deleted: `profiles_ids`, `profiles_link_pairs`, `profiles_failed_ids`,
  `profiles_enrich_seed_ids`, the public `profiles_count` wrapper, and `LinkWriter::read` /
  `overlay_pending` (the write-behind writer has no reader left).
- `SCHEMA_VERSION` 8 → 9: a v8 file is WIPED and rebuilt (the destructive test pins it).

Verification: `cargo nextest run --workspace` 1914/1914, `cargo clippy --workspace
--all-targets` 0 warnings, `cargo fmt --check` clean. The projection parity test, the 7-sort ×
2-direction ordering golden, the anchor golden and the paging golden all pass on the rebuilt
schema.
