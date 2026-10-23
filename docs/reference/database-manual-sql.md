# Hand-written SQL and DDL in the DB layer — why, where, and the rules

This file is the authority for every place `crates/leas-db` does **not** go
through toasty, and for the reason each exception exists. If you are adding a
query and wondering whether it may be raw SQL, the answer is: read this list
first, and prefer the typed path unless your case matches one of the causes
below. Every entry here is either (a) a capability `toasty` **0.11** does not
have, or (b) a measured cost difference on this engine. Entries re-verified
against the vendored `toasty-0.11.0` source are marked as such inline — currently
**C1 and C2 only**; C3–C6 are unverified against 0.11 and are NOT carried forward
on trust. See §7.

Related records: `docs/reference/database.md` (schema, flows, query map),
`docs/aegis/adr/0001-raw-sql-profiles-page-query.md` (the page query),
`docs/aegis/adr/0002-write-behind-link-writer.md` (the link writers),
`docs/aegis/adr/0003-stored-profile-ordering-keys.md` (the rank keys),
`docs/aegis/specs/2026-09-16-db-claim-verification.md` (the measurements behind
the engine facts cited here).

> **Baseline note.** `AGENTS.md` decisions 4 and 21 describe raw SQL as
> "confined to PRAGMAs, plus `profiles_query.rs`". That was already narrower than
> the code when it was written, and the 2026-09-16 write-path change added one
> more site. The exception list below is the accurate one; the decision text was
> corrected to point here rather than restate the list.

## 1. The rule

- **Typed path first.** Single-row reads and writes of a model (endpoints,
  protocols, links, groups, endpoint↔group links, routing rules, DNS settings,
  route probes) go through the typed API — `Model::filter…`, `upsert_by_*`,
  `toasty::create!/update!` — so the enum/JSON/timestamp encodings and the
  `CHECK` constraints stay the ORM's business.
- **Raw SQL needs a cause from §2.** "It is easier to write" is not one. Neither
  is "it is faster" without a number in the table below.
- **Never a second owner of a fact.** A hand-written statement may only write
  columns its own group/owner owns, and may not create a second spelling of a
  stored fact (this is why the `(family, addr)` split in §5 was rejected).
- **Inlined literals, not binds, on bulk statements.** The engine charges
  ~0.8 ms per *bound* parameter (200 ids = 174 ms against 9.7 ms for the same
  statement with literals, `endpoint_rank.rs`). Ids and keys that come from our
  own rows are rendered as literals; user text still goes through `sql_lit`
  (quotes doubled) or a bind.
- **Every raw statement must be exercised by a test.** There is no single drift
  guard: the statement-vs-schema test (`tests/profiles_query.rs`
  `every_statement_runs_against_a_pushed_schema`) executes only the
  **`profiles_query.rs`** paths (`profiles_page` for every sort/view,
  `profiles_anchor`, `load_page_projection`). The other sites are pinned
  indirectly, by the behavior tests that call them (§3, last column) — and a
  **new** raw statement is covered by neither until a test actually runs it. That
  is checklist item 5 in §6.

## 2. The causes

| Cause | Consequence |
| --- | --- |
| **C1. No upsert / conflict clause.** `toasty` 0.11 **does** have a multi-row insert — `stmt::CreateMany` (`stmt/create_many.rs`, `lib.rs:124`) — but it builds a BARE `INSERT INTO … VALUES (…), (…)` from `item.into_insert()` and carries **no** `on_conflict` / `or replace` / upsert semantics (`grep -rl "on_conflict\|OnConflict" toasty-0.11.0/src/stmt` finds nothing). `upsert_by_*` **does** exist but is macro-generated and single-row: `toasty-macros-0.11.0/src/model/expand/upsert.rs:60-82` emits `upsert_by_{field}` + `{Model}UpsertBy{suffix}`/`…OrIgnore` (documented at `toasty-macros-0.11.0/src/lib.rs:52`), and the statement it builds is documented as "A typed **single-row** upsert statement" (`toasty-0.11.0/src/stmt/upsert.rs:5`). So it is absent from the hand-written `toasty-0.11.0/src/` by construction, not missing. The blocker is therefore the conflict clause, not the row count: an idempotent re-import needs `ON CONFLICT … DO UPDATE`, which a bare multi-row insert cannot express. *(Re-verified 2026-10-01; the previous "no multi-row insert" wording was true of 0.10 and false of 0.11.)* **The link-writer upserts are NOT thereby retired**: they also rest on C6 (10.0 ms/512-patch vs 29.0 ms measured) and on per-column-group `ON CONFLICT … DO UPDATE SET col = CASE …` bucketing (RESULT/TRAFFIC/PURGE), which the typed `upsert` cannot express — the engine compares ONE `UpsertAction` per statement (`toasty-0.11.0/src/engine/lower.rs:1226`, `engine/upsert.rs:61`), so there is no per-group action to set. Migrating them is a separate task with its own measurement.* | Bulk paths are hand-built multi-row statements. |
| **C2. `#[index]` is per-field and single-column.** *(Re-verified against `toasty-macros-0.11.0/src/lib.rs:224` / `:1155` — still "Creates a non-unique index on the field / the field's flattened column", no composite, mixed-direction, partial or expression form.)* No composite, mixed-direction, partial, or expression index. | Indexes toasty cannot express are raw `CREATE INDEX IF NOT EXISTS` at open. |
| **C3. No per-connection hook.** The driver creates pooled connections itself. | Every per-connection PRAGMA is re-issued in `Database::conn()`. |
| **C4. No raw connection access.** `Db::driver()` yields `&dyn Driver`, not the turso connection. | UDFs, `turso::core`, statement-cache control, `set_query_timeout`, `interrupt`, and experimental driver flags beyond the `experimental_*` setters are unreachable. |
| **C5. Engine shape.** No `UPDATE … FROM (VALUES …)` (parse error); unknown PRAGMAs are silently ignored; `array_agg` needs an experimental flag and returns text; `BIGINT`/`BOOLEAN` are illegal in a STRICT table; expression indexes are not used for `LIKE`. | Some statements cannot be expressed at all; some "obvious" tuning is a no-op. |
| **C6. Measured cost.** Binding, per-row statements, and ORM-round-trips cost more than one hand-built statement on this engine. | The numbers in §3 are the justification. |
| **C7. No aggregate projection.** Toasty's typed builders are per-model row reads — `all`, `filter`, `order_by`, `limit`, `first` — with no `COUNT`/`SUM`/`GROUP BY` constructor and no expression projection. A derived partition over stored columns (`SUM(CASE WHEN rank_bin = 12 …)`) is unreachable from the typed path. | Bucket/aggregate reads over a materialized table are raw SQL; the typed path can only re-read every row and count in Rust, which is the O(feed) cost the page query exists to avoid. |

## 3. The inventory (every site, with its cause and its number)

| Site | What it does | Cause | What the typed path costs | Pinned by |
| --- | --- | --- | --- | --- |
| `profiles_query.rs` (whole file) | The Profiles page: count + ordered ids + one-statement hydration, ids inlined; `profiles_walk_page` is the same ordered-id SELECT with NO count (the batch's plan walk asks for the feed-wide total once instead of once per page, which was `O(feed²/200)`); the plan-scope predicate (`rank_tier IN (…)`, bound, shared by the page, the walk and the count, so a scoped batch and its footer cannot drift) | C2 (covering-index ordering), C4 (the id-inlined projection runs on the raw `Database::direct` connection, whose uncached `prepare` dodges the driver's unbounded per-text statement cache — see the dated section below), C6 | 488 ms per page typed (`in_list`, ~600 binds) vs 49.6 ms inlined (ADR 0001); a `ROW_NUMBER()` window sort is 1757 ms vs 8.6 ms index-driven (ADR 0003); the scope predicate is an index range on the same covering index, so it costs no extra storage | `every_statement_runs_against_a_pushed_schema` — the only site with a direct statement-vs-schema guard — plus `walk_pages_match_the_page_ids_and_count_once` for the count-free variant and `plan_scopes_select_by_materialized_tier` for the scope |
| `profiles_query.rs` `profiles_aggregate` | The Details panel's bucket counts: one `SELECT COUNT(*)` plus six `SUM(CASE WHEN …)` arms over `endpoint_rank`, per scope. The `alive` arm is `rank_newest_seen >= ?` (live, the global group) or `band = 0` (swept, the view group); the four partition arms are `PlanScope::predicate` verbatim, so a proven endpoint carrying bin 12 counts once. | C7 (no aggregate constructor), C6 | The typed path cannot express it: `SUM(CASE …)` over `rank_bin`/`rank_stab`/`rank_proven` is not a model read. The statement is index-served — `endpoint_rank_key_v2` carries `rank_bin`/`rank_stab`/`rank_proven`, `endpoint_rank_band_window` carries `rank_newest_seen` — and groups/sorts nothing | `aggregate_buckets_partition_the_total`, `aggregate_view_total_matches_the_page_count`, `aggregate_alive_is_live_for_the_global_scope` (integration) |
| `database.rs` `LINK_UPSERT_PREFIX` + `link_values_sql` + `exec_link_upsert` | `apply_link_patches` and `upsert_links_bulk`: one multi-row `INSERT … VALUES (…),(…) ON CONFLICT(protocol_id, endpoint_id) DO UPDATE …` per (400-row chunk, group action — three groups, so eight bucket shapes) | C1, C4 (the inlined-literal writer runs through `Operation::RawSql`, which the crate's OWN driver fork routes to the UNCACHED `prepare` — the published driver would cache a compiled program per window, forever; see the 2026-10-08 section), C5 (`UPDATE … FROM (VALUES …)` is a parse error) | 29.0 ms → 10.0 ms per 512-patch window; 360 ms → 44.3 ms per 2,000 imported links (ADR 0002 amendment 4) | `apply_link_patches_writes_patched_groups_for_every_row`, `…isolates_column_groups`, `…survives_a_stale_snapshot_without_clobbering`, `…applies_a_window_wider_than_one_statement_chunk`, `…upserts_absent_and_near_miss_pairs_exactly`, `link_patch_inserts_a_missing_row_and_refreshes_its_key`; the import path by `subscription_upsert_flow_assembles_group_rows`; the RAW path by `raw_link_window_writes_like_the_pooled_path` |
| `driver/` (the crate's own `toasty-driver-turso` fork) | `Connection::exec` routes `Operation::RawSql` to the UNCACHED `prepare`; `Insert`/`QuerySql` keep `prepare_cached` | C4 (the published driver's `prepare_cached` map is unbounded and keyed by text; an inlined-literal statement is a new text every call) | Replaces the retired `sql_exec.rs` `SqlConn`/`RawConn` seam: the SQL text is unchanged, only the executor routing is. The fork is vendored from toasty `main` (turso 0.8) | `contention_is_retryable_and_real_errors_are_not` (contention still reaches `retry_on_busy`), `file_db_link_window_writes_the_staged_values` (the pooled write path, on a real file db) |
| `database.rs` `link_patch_conflict_sql` | The per-action `DO UPDATE SET` list — the column-group disjointness, in SQL, for FOUR groups (RESULT / PURGE / TRAFFIC / STAB) | C1 (the action is per-statement, so the groups must be bucketed) | n/a — this *is* the group contract; `contains`-decided, so an unknown bit cannot drop a group. `purge_reason` is its own group because this action writes a FIXED column set from each patch's snapshot, so riding RESULT would let a phase-1 fast half rewrite a verdict it never classified (ADR 0006); `stab_mask`/`stab_len` get their own bit for the same shape — a fast-only RESULT snapshot never sampled the ring (spec 2026-10-09-stab-bin-design) | `apply_link_patches_isolates_column_groups` (seeds a verdict, then proves a stale RESULT-only patch leaves it intact while a PURGE-only patch moves it and nothing else), `link_patches_leave_columns_outside_their_groups_alone`, `subscription_upsert_flow_assembles_group_rows` |
| `database.rs` PRAGMAs (`user_version`, `journal_mode=WAL`, `busy_timeout`, `synchronous=NORMAL`, `foreign_keys=ON`) | Connection and durability settings, per connection | C3 | `busy_timeout`/`synchronous` never reach pool-created connections if set once at open — that was the "database is locked" storm | Every `Database::open`/`in_memory` call; the tag semantics by `open_wipes_a_file_with_a_mismatched_schema_tag`, `fresh_open_creates_schema_and_sets_user_version_tag`, `open_reopen_preserves_data` |
| `database.rs` (`sql_lit`, `error_kind_str`, `purge_reason_str`) | Literal escaping and the `CHECK`-constrained storage spellings (the `purge_reason` spellings are toasty's own, verified by a column-shape probe) | C1 (a hand-built statement has no encoder) | A wrong spelling is rejected by the column `CHECK` or the test that runs it, never silently stored | Any test that round-trips an error through the writers — `apply_link_patches_writes_patched_groups_for_every_row`, `page_projection_matches_the_orm_rows` |
| `schema/ddl.rs` (moved from `endpoint_rank.rs::ensure_in`, 2026-10-08) | `CREATE INDEX IF NOT EXISTS endpoint_rank_key_v2` (covering, mixed-direction, `rank_proven` TRAILING) + `DROP INDEX IF EXISTS endpoint_rank_key` + `endpoint_rank_band_window` | C2 | toasty's `#[index]` cannot express either; 1757 ms → 8.6 ms is the covering index. `rank_proven` trails so every scope filters inline; the name change is what makes an existing file pick the new column list up (`IF NOT EXISTS` makes an in-place edit a silent no-op) | Applied by the migration runner on every `Database::open`/`in_memory`; the index's *effect* by `page_order_matches_the_rust_oracle_for_every_sort` |
| `endpoint_rank.rs` `write` | Bulk `INSERT OR REPLACE … VALUES` per 400 rows, then one `UPDATE … SET band …` per chunk | C1 | Per-row `upsert_by_endpoint_id` is ~1.2 ms per statement: a 400-endpoint window took ~470 ms and a 7.7k-endpoint import ~8 s; the bulk form is ~10× cheaper | `link_writes_keep_the_stored_keys_current`, `a_result_patch_that_inserts_a_link_still_moves_the_key`, `purging_endpoints_drops_their_keys` |
| `endpoint_rank.rs` `refresh` / `load_raw_endpoints` / `backfill` / `repair` / `prune` | Id-inlined reads (`WHERE endpoint_id IN (…)`) and the raw facts behind the rank law | C6 | Binding costs ~0.8 ms per id | `resolving_a_dns_host_moves_its_stored_key`, `purging_endpoints_drops_their_keys`, `load_page_rows_preserves_page_and_link_order`, `seed_ranks` (integration) |
| `merge.rs` `overwrite_link_fields` / `merge_memberships` | The Smart Endpoints Compact's collision writes: one `UPDATE profile_stats SET <measured fields…> WHERE protocol_id = ? AND endpoint_id = ?` (deliberately NOT `purge_reason` — the survivor's verdict is its own) and one `UPDATE endpoint_groups SET last_seen_at = MAX(…)` per collided membership | The typed `update()` builder is a partial-column setter (so no C1 here) but cannot express the column SELF-references the rule needs — `last_seen_at = MAX(last_seen_at, ?)` and `last_used_at = MAX(COALESCE(last_used_at, 0), ?)` — nor the conditional per-column mix of copied/skipped fields in one statement; same expression class as the `reband` statements above | n/a — maintenance-path, one statement per merge; the literals reuse `sql_lit`/`error_kind_str` | `merge_keeps_survivor_purge_verdict_over_absorbed_measured_link`, `merge_moves_group_membership_and_resolves_collision` (integration) |
| `schema/ddl.rs` (moved from `endpoint_ip.rs::ensure`, 2026-10-08) | `CREATE INDEX IF NOT EXISTS endpoint_ip_by_key(ip_key, endpoint_id)` | C2 | The sort wants a two-column index; `#[index]` is single-column | Applied by the migration runner on every `Database::open`/`in_memory`; the index's *effect* by `page_order_matches_the_rust_oracle_for_every_sort` (`PageSort::Ip`) |
| `endpoint_ip.rs` `load` | One id-inlined statement for a page's address sets, key-ordered | C6 | Same 0.8 ms per bound id | `page_rows_assemble_links_and_protocols` (through `load_endpoint_rows`), `large_page_loads_via_batched_in_list` |
| `endpoint_ip.rs` `load_resolved` | The same id-inlined statement plus the `country` column (`load` maps it back to addresses) | C6 | Same 0.8 ms per bound id; one read serves both the page oracle and the enrichment seed | `page_rows_assemble_links_and_protocols`, `large_page_loads_via_batched_in_list`, `stored_country_reaches_the_ui_without_the_mmdb` |
| `endpoint_ip.rs` `countries_of` | Id-inlined `SELECT … WHERE country IS NOT NULL` for the endpoint being rewritten | C6 | It runs once per resolution inside `replace`, and re-reading one endpoint's 1–3 rows is cheaper than re-walking the mmdb | `stored_country_survives_re_resolution` |
| `endpoint_ip.rs` `replace` | Delete-then-insert the whole set, deduped by key (typed delete + typed create per row — the mix that is fine because the set is 1–3 rows and TTL-gated), plus one `countries_of` read to carry the surviving addresses' countries | — | The writes stay typed on purpose (the model for "small set, typed is fine"); only the country read is raw, for the id-inlining reason above | `resolving_a_dns_host_moves_its_stored_key`, `stored_country_survives_re_resolution` |
| `schema/ddl.rs` (moved from `endpoint_rank.rs::ensure_in`, 2026-10-08) — `band` + `rank_weight` columns, with `backfill_bands` still in `endpoint_rank.rs` | `ALTER TABLE endpoint_rank ADD COLUMN band` / `… rank_weight BLOB NOT NULL DEFAULT …` / `… rank_stab INTEGER NOT NULL DEFAULT 4` / `… rank_proven INTEGER NOT NULL DEFAULT 0`, the `ALTER TABLE profile_stats ADD COLUMN stab_mask/stab_len`, the stability seed (`UPDATE profile_stats SET stab_mask=1, stab_len=1 WHERE latency_real_delay IS NOT NULL` — schema 19 renamed the predicate's column, since the `latency` discriminator is gone; it is now gated on a one-way `app_meta` stamp, `stability_seeded_v2`, written in the SAME transaction as the seed, plus a `DELETE FROM rank_weight_meta` so the rank keys recompute — all applied by the runner, which TOLERATES the duplicate-column error since this engine has no `ALTER … IF NOT EXISTS`), the `endpoint_rank_band_window` index, and `backfill_bands` (one-time `band IS NULL` fill) | C1/C2/C5 | A raw column on a DERIVED, rebuildable table avoids a toasty-model change → no `user_version` tag bump → **no file wipe** of a large enriched feed; `#[index]` cannot express the composite | `backfill_bands_fills_null_band_rows_on_reopen` (the NULL fill, via reopen), `active_and_stale_windows` (band membership through the page) |
| `endpoint_rank.rs` `write` (band follow-up) | Per chunk after the `INSERT OR REPLACE`, one `UPDATE … SET band = CASE WHEN rank_newest_seen >= ? …` — REPLACE nulls the raw column, so it is re-set each write | C1 | n/a — it maintains the raw column the toasty model cannot carry; band is the ttl membership from the just-written `rank_newest_seen` | `active_and_stale_windows`, the page-order parity tests |
| `endpoint_rank.rs` `reband_expired` / `reband_all` | Directional demote `UPDATE … SET band=1 WHERE band=0 AND rank_newest_seen < ?` (retention tick) and the full-recompute `CASE` (startup) | C1/C6 | Membership is a stored `band`, maintained as `now` crosses the threshold; the directional form seeks only the drifted rows via `(band, rank_newest_seen)`, continuity-independent across downtime | `reband_sweep_demotes_rows_that_drifted_during_downtime` (demote), `reband_all_promotes_rows_the_default_backfill_demoted` (promote) |
| `database.rs` `purge_expired` | `SELECT e.id FROM endpoints e WHERE NOT EXISTS (SELECT 1 FROM profile_stats p WHERE p.endpoint_id = e.id AND p.last_seen_at >= ?)` — all-links staleness, replacing toasty's `.all()` quantifier | C6 | toasty's `.all()` compiled to a whole-`endpoints` projection (145 ms); this is indexed on `profile_stats.last_seen_at`. Deliberately NOT the live-only `band` — a fresh-but-purged link must keep its endpoint (ADR 0006, view-band spec §3.5) | `purge_expired_matches_all_links_semantics` |
| `export.rs` direct reader | Whole-feed export count + one-row-at-a-time projection, with WAL `BEGIN DEFERRED` / MVCC `BEGIN CONCURRENT`, joined `protocols.config`, and deterministic protocol/transport/security/address ordering | C4/C6: Toasty 0.11 public query/raw SQL returns `Vec`; Turso driver drains physical `Rows` before Toasty sees them, so typed/page APIs cannot provide the required bounded row stream. Direct read is file-only and separate from Toasty writes | Public Toasty `.exec` buffers values; no page API preserves physical row streaming. One direct row is decoded and dropped per iteration; feed-wide row/config vectors are forbidden | `export::tests::alive_uses_canonical_link_tier_and_dns_resolution`, `export::tests::resolved_emits_each_dns_address_and_one_ip_literal`; RSS/file-reader smoke in T6 |

## 4. Toasty blockers, with the exact failures

1. **Bulk upsert** — no `insert_many`/`on_conflict` (absent from
   `toasty-0.11.0/src/stmt/` — `CreateMany` exists there but has no conflict
   clause, see C1); single-item `upsert_by_*(…)` only. Cost of the missing
   upsert semantics: the hand-built statement above, plus the manual `CHECK`
   spellings. **Re-verified 2026-10-01 against the vendored 0.11.0 source.**
2. **Composite/mixed-direction/partial/expression indexes** — `#[index]`
   documents "creates a non-unique index on the field". Cost: three raw DDL
   statements at open, invisible to toasty's schema (guarded by every
   `Database::open`/`in_memory` call in the suite executing the DDL).
3. **Per-connection settings** — the driver owns connection creation.
4. **Connection access** — `Db::driver() -> &dyn Driver` exposes no turso
   connection, so `register_external_scalar_function`, `set_query_timeout` and
   `interrupt` are still out of reach from the APP's side (RAW SQL is not:
   `toasty::sql::query/statement` is the supported channel and is what every
   site above uses).
   **The `prepare_cached` control and `experimental_mvcc_passive_checkpoint` used
   to be on this list and no longer are — the crate owns its driver.** The fork
   in `crates/leas-db/src/driver/` routes `Operation::RawSql` through the
   UNCACHED `prepare` and `Insert`/`QuerySql` through `prepare_cached`
   (ADR 0012), so the unbounded per-text cache the published driver accumulated
   (measured ~116–310 KiB per distinct text) cannot grow on the inlined-literal
   path; and `file_driver` enables the MVCC passive-checkpoint flag. The
   `Database::direct` raw connection STAYS for the page's execution-layer bypass,
   which is a read win unrelated to the cache.
5. **Schema management** — `push_schema` still emits `CREATE TABLE` with no
   `IF NOT EXISTS`, but it is no longer guarded by a wipe tag: `crate::schema`
   is the migration runner (ADR 0012). `PRAGMA user_version` is a CURSOR seeded
   at `SCHEMA_VERSION` (18); a current file is a no-op, a fresh file applies the
   seed, a supported older version applies the pending steps, and only an
   UNKNOWN cursor is `IncompatibleSchema` (which `open` answers with the
   pre-alpha wipe). Hand-written DDL lives in `schema/ddl.rs`, not scattered
   through `ensure*`. See decision 4 in AGENTS.md.
6. **No STRICT tables, generated columns, or materialized views** — see §5.
7. **No caller-supplied driver** — `Database::open` builds `Turso::file(path)`
   internally, so an experiment with a driver flag (`.concurrent_writes()`, any
   `experimental_*`) cannot reuse `open`: a probe has to rebuild the driver *and*
   the `toasty::models!(…)` list itself. A `#[cfg(test)]`/example hook taking a
   driver would remove that duplication. Still true AFTER the driver fork: the
   fork changed who owns the driver, not `open`'s signature.

## 5. Rejected manual paths (so they are not re-proposed)

| Proposal | Verdict | Why |
| --- | --- | --- |
| Enable MVCC **as the default** (`Turso::concurrent_writes()`) | rejected | The original reasons were: a measured reader tax (p50 56.5 → 85.9 µs, p95 66.8 → 97.0 µs) and a **checkpoint gap** (`PRAGMA wal_checkpoint(PASSIVE)` failed with "PASSIVE checkpoint requires experimental_mvcc_passive_checkpoint"). The checkpoint half is now FIXED, though the ORIGINAL mechanism recorded here was wrong: MVCC already auto-checkpoints on the commit path at a ~4.12 MB logical-log threshold, so the log was never unbounded; `file_driver` setting that flag changes the auto-checkpoint's MODE from blocking `Truncate` to `Passive` and lets `ping.rs`'s batch-end checkpoint run under MVCC at all. What still makes it an opt-in, per ADR 0012 D-D — three costs, all still live: **(a) it needs the Turso project's own `tursodb` rather than stock `sqlite3` (which answers `file is not a database`), and there is no VERIFIED convert-back — a documented `tursodb .dump | sqlite3` path turned out to be a data-loss trap (no `user_version` in the dump → the app wipes the reimported file) and not reproducible; (c) MVCC is SINGLE-PROCESS (the engine rejects multiprocess access), so a second instance is a hard failure; (b) real-feed throughput is unresolved and mixed by path.** It also adds a `<db>-log` file the wipe paths do not delete |
| Hand-create tables as STRICT | rejected (for now) | STRICT gives **no storage and no speed change** (4,000 rows: 83 pages / 339,968 bytes in both schemas; a full-surface scan 2.72 ms heap vs 2.76 ms STRICT) and its only unlocks are validation and custom types. Its type vocabulary is also **flag-dependent**: without the custom-types flag `BIGINT` and `BOOLEAN` are `Parse error: unknown datatype` in a STRICT table (those are what toasty's DDL emits), and they become legal only with `experimental_custom_types(true)`. So adopting STRICT means hand-owning the **entire** schema DDL *and* turning on an experimental engine flag, for validation alone. (Typed toasty access on a hand-created STRICT table does work: verified create + read.) Revisit only if type validation becomes a requirement |
| Custom types (`CREATE TYPE … BASE blob OPERATOR '<'`) for the address column | rejected | Reachable only with `experimental_custom_types(true)`; the packed-BLOB column already orders and indexes correctly (byte order IS address order) and needs no experimental flag. The operator would buy expressiveness, not speed, and duplicate an existing fact |
| Split `endpoint_ip.ip_key` into `(family, addr)` | rejected | Requires the experimental custom-types flag for `array_agg` (which the driver then returns as TEXT — `String("{\"X'040A0001'\",…}")`, not `Value::List` of blobs, so the cheap decode is unreachable); the split is not cheaper (`group_concat(hex(addr))` 806 µs vs the shipped 724 µs per 200-row page); and it makes `PageSort::Ip` worse (the correct `(family, addr)` term needs two correlated subqueries: 16.49 ms vs 9.97 ms packed; the single-subquery variant cannot produce a pair) |
| One-blob wire via `unhex(string_agg(hex(x), ''))` (the flag-free rewrite of the idea above — `test_array_agg_result_deserialize_to_ips`) | rejected — **correct but not faster** | Not gated (`string_agg`/`hex`/`unhex`/`FILTER` all work with the custom-types flag OFF), and its decoded output is **identical** to the shipped carrier (277 == 277 addresses on a resolved page). But it is the same cost within noise (statement 747–836 µs shipped vs 758–776 µs one-blob; decode 4.7 µs vs 4.6–7.4 µs) while the shipped text parse it would remove costs 8–14 µs per page, i.e. ≤0.4 %. Adopting it would also not fix the mixed-family trap below. If it is ever wanted, the decoder must WALK the packed key (family byte then 4/16 octets), never slice a fixed width |
| Slicing one concatenated blob by a fixed address width | rejected — **incorrect** | On a `(endpoint_id, family, addr)` table the `chunks::<4>()` decode returned **367** addresses where the packed key holds 277: one width cannot describe a mixed IPv4/IPv6 set, so the decoder silently invents addresses. Two `FILTER`ed aggregates (per family) would be required, which is more engine work than the comma list |
| `ANALYZE`, `likely()`/`unlikely()`, `wal_autocheckpoint`, `max_wal_size`, `mmap_size`, `cache_size` tuning | rejected | Measured neutral or non-existent; unknown PRAGMAs are silently ignored, so the tuning would be invisible rather than effective (details in the verification spec §2) |

## 6. Adding a manual path — checklist

1. Name the cause from §2. If none applies, use the typed API.
2. Prefer inlined integer literals for our own ids/keys; `sql_lit` for text.
3. Keep the write inside the transaction that owns the fact, and never write a
   column group another owner writes.
4. Make it idempotent if it runs at open (`IF NOT EXISTS`, `INSERT OR REPLACE`).
5. **Make a test actually run the new statement.** No guard is automatic: the
   statement-vs-schema test covers only `profiles_query.rs`. For a link-writer
   statement that means an `apply_link_patches_*` / `subscription_upsert…` test
   (or a new one) that executes it against the pushed schema; for
   `endpoint_rank`/`endpoint_ip` statements, a test on the path that calls them
   (`link_writes_keep_the_stored_keys_current`,
   `page_rows_assemble_links_and_protocols`, …). A raw statement added without
   such a test is verified by nothing.
6. Record the measurement (probe → this file's table or the relevant ADR). A raw
   statement without a number is a guess, and the next reader will "simplify" it.

## 7. Re-verify a blocker against the vendored source before relabelling it

The causes in §2 are pinned to a **toasty version**, and a version bump can retire
them silently. Nothing detects that: the blocker is prose, so a `0.10 → 0.11`
find-replace looks like a correction while actually *asserting* every absence still
holds.

This is not hypothetical — it happened on 2026-10-01. Blindly relabelling toasty
0.10 → 0.11 would have kept C1's "no multi-row `insert().values([…])`" as fact,
when `toasty-0.11.0/src/stmt/create_many.rs` now provides exactly that
(`CreateMany`, announced at `lib.rs:124`). Re-reading the source showed C1 is
now **half retired**: the multi-row insert exists, the *conflict clause* does not
(`grep -rl "on_conflict\|OnConflict" …/toasty-0.11.0/src/stmt` → nothing). C1 was
requalified to name the capability that is actually missing, which is the one that
still forces the hand-built statement.

So:

1. Cite the vendored path **with its version** (`toasty-0.11.0/src/…`), never a
   bare version number — a stale path is worse than a stale number because it
   reads like a citation that was checked.
2. Before changing a blocker, **grep the vendored source for the missing symbol**
   and read what is there. A capability that APPEARED is a **retirement trigger,
   not a retirement**: record that the trigger fired and what now carries the
   site, then treat the migration as its own task with its own measurement. A
   requalified blocker is a documentation change; rewriting the SQL that depends
   on it is a code change, and it does not ride along on a doc edit.
3. Distinguish "renamed" from "re-verified" in the text, and only claim what was
   checked. **C1 and C2 were re-verified against `toasty-0.11.0` on 2026-10-01;
   C3, C4, C5 and C6 have NOT been and carry no such marker.** C4/C6 were spot
   confirmed incidentally while checking C1 (`Load::Output` for `List<M>` is
   still `Vec<M::Output>`), but their prose is otherwise unverified against 0.11 —
   so a future bump must re-check them rather than trusting the absence of a
   date. A rule that claims more coverage than the table delivers is the same
   defect it was written to catch.

## Weight columns and indexes (2026-10-01)

| Site | Cause | Why raw |
| --- | --- | --- |
| `ALTER TABLE endpoint_rank ADD COLUMN rank_weight BLOB NOT NULL DEFAULT x'0000000000000000'` (`schema/ddl.rs`; the runner tolerates the duplicate-column error) | The weight must be materialized where SQL can `ORDER BY` it. Declaring it on the toasty model would change the pushed schema, and the only lever for that is the schema cursor — where decision 4 would make an unexplained bump a wipe. The raw-column precedent (`band`) is the non-destructive path. | The model has no seat for a raw column, so the write path carries a `RankRow` instead. `NOT NULL DEFAULT` is required, not stylistic: `profiles_anchor` binds each ordering term's value back and the engine refuses to type a NULL there, so a NULL weight makes the anchor query ERROR. |
| `CREATE INDEX IF NOT EXISTS endpoint_rank_key (band, rank_bin, rank_weight DESC, rank_domain, rank_sub_domain, rank_addr, endpoint_id)` | Serves the `PageSort::Test` ORDER BY as an index scan (Active Test page **1.52 ms at 50k scale**; 8.6 ms at 7,672 endpoints) instead of a filesort. | toasty's `#[index]` is single-column and cannot express a mixed-direction composite. **A new name is mandatory**: `IF NOT EXISTS` makes an edited column list a silent no-op on every existing database, so the old index would keep serving the new ORDER BY. |
| `CREATE TABLE IF NOT EXISTS rank_weight_meta (id INTEGER PRIMARY KEY CHECK (id = 0), weight_version INTEGER NOT NULL)` | The weight tables are compiled into the binary, so an app upgrade silently invalidates every stored weight. | A one-row stamp is the smallest thing that can say "these numbers came from a different build". A mismatch recomputes every rank key at open — the only trigger that can replace the all-zero default that `ADD COLUMN` materializes for pre-existing rows. |
| `INSERT … SELECT`-free weight backfill (`backfill_all` reads `Protocol::all()`) | SQL cannot call the Rust `weight_of`. Duplicating the four tables as a SQL `CASE` expression would create a second owner of the law — exactly the drift ADR 0003 exists to prevent. | The weight is derived from `transport_type`/`security_type`/`security_sni`/`security_fp`, four small scalar columns the protocol row already stores. |
| `refresh`'s `LEFT JOIN protocols pr ON pr.id = ps.protocol_id` | The link row carries no protocol, so the weight cannot be derived from `profile_stats` alone. | Four discriminator columns (`transport_type`, `security_type`, `security_sni`, `security_fp` — `proto_kind` is deliberately not a weight dimension) cost one indexed lookup per link inside a statement the refresh path already issues; the deferred `config` JSON stays unloaded. They are parsed with `TransportType::from_db_label`, NOT `FromStr`: toasty's embed writes `http_upgrade`/`x_http` where the wire form says `httpupgrade`/`xhttp`, and the wrong parser silently persists a zero weight for 314 of ~21k real protocol rows. |

## Purge candidate scan moved out of the write transaction (2026-10-02)

| Site | Cause | Why raw |
| --- | --- | --- |
| `purge_expired_once`'s candidate `SELECT e.id FROM endpoints e WHERE NOT EXISTS (…)` split into an **outside-transaction** scan plus an in-transaction **re-check** over the candidate ids only (`database.rs:1440+`) | The scan used to run INSIDE the write transaction, which turned a read-only full-table walk into a write-lock hold. The 2026-10-01 run measured that statement at **3,098 ms** on 74,014 endpoints — a three-second lock on the single database handle, from a statement that only reads. Every concurrent writer (import chunks, the enrichment geo flush, the link-writer window) queued behind it, and that queue is where the `snapshot is stale` aborts came from. | Unchanged as raw: toasty's `.all()` quantifier compiles to a whole-table projection (145 ms). What changed is **placement, not the statement**: the scan is now a plain read on `conn`, and the write transaction opens only for the re-check and the cascade. The re-check is what closes the race the split introduces — an endpoint that gained a link between the two statements must not be deleted with a live link — and it is bounded by the candidate set, so it is an index seek rather than a scan. Ids are inlined as literals in the re-check, the convention every other raw statement here uses (~0.8 ms per bound id). |

**Measured effect:** the write transaction is now bounded by the DELETE count, not by the scan. `purge_expired`'s cost moves to a plain read that blocks no writer.

## Import upserts: two of three families moved to multi-row (2026-10-02)

| Site | Cause | Measured |
| --- | --- | --- |
| `upsert_endpoints_bulk` — one multi-row `INSERT … VALUES (…),(…) ON CONFLICT("id") DO UPDATE` per 400 rows, replacing one typed upsert per row | The typed builder cannot batch. The 2026-10-01 run issued **105,147 statements** for this family alone. | ~263 statements for the same rows. `AGENTS.md` decision 22 already carried the finding ("the import path's per-row typed upserts 360 ms per 2,000 links against 44.3 ms"); the fix had never been applied to this path. |
| `upsert_endpoint_group_links_bulk` — same shape on `("endpoint_id","group_id")` | The largest single family: **204,592 statements**, half the import's total, because a 500-URL batch touches one endpoint once per protocol and each was its own statement. | ~511 statements. |

**db-rewamp D10: the endpoints writer now writes `domain`/`sub_domain`, not `host`/`host_type`.**
The `HostType::as_db_label()` round-trip this section used to require is gone with the columns: the
stored TEXT is the psl2 split itself — `domain` (eTLD+1) plus `sub_domain` (the labels left of it),
both empty for an IP-literal or exotic host — so a mistyped split, not a mistyped enum label, is the
failure mode. `multi_row_import_writers_round_trip_through_a_real_database` reads the `domain` column
back **as text** rather than through the typed loader (which would hide the error) and asserts the
split's expected value per host kind; `multi_row_endpoint_upsert_replaces_and_preserves` proves the
upsert replaces `domain`/`port` and leaves `manual_protocol_override` and `resolved_at` alone — the
import does not own them. An IP-literal endpoint's address is written to `endpoint_ip` alongside its
row (`state::persist_parsed`, `SourceSpec::write_window`), pinned by
`streaming_import_splits_and_persists_in_batches` — the literal has no other home once `host` is
dropped.

### `upsert_protocols_bulk` is DELIBERATELY NOT converted

99,728 statements, the remaining quarter. It needs three enum labels (`proto_kind`,
`transport_type`, `security_type` — the feed stores `shadowsocks2022`, `http_upgrade`, `x_http`,
which are **not** `as_str()`/`FromStr` spellings; see the same trap documented in
`proto_spec/kinds.rs`) **and** the storage encoding of the `transport.data` / `security.data`
JSON columns, which has not been verified here. Writing raw SQL against `protocols.config` without
that would risk a row the connect path cannot read — a worse failure than a slow import. **Blocker:
a writer-side `as_db_label` for `TransportType`/`SecurityType`/`ProtocolKind`, each with a
DB round-trip test**, and the confirmed encoding of the two JSON blob columns. This entry is the
record of that deferral, not an omission.

## Enrichment country writes: one owner, one transaction per drain (2026-10-02)

The resolution task no longer writes. It **stages** `(endpoint, address, country)` into the
process-global `leas_db::WriteBehind<CountrySpec>` driver and returns without awaiting; the
driver task started from `ui::run` writes the window with `set_endpoint_ip_countries_once` on the
transaction IT opened — **one transaction**, no nested connection.

**Why a cross-host buffer and not per-host batching.** `spawn_dns_resolve_host` already loops its
`waiters`, so "collect the per-host rows and call `set_endpoint_ip_countries` once" only collapses
transactions when a host has more than one waiter — and the 2026-10-01 run says it almost never
does: **933 lookups, 1,577 deferred HALVES (≈788 distinct links), 790 per-address invocations**, so
`waiters.len() ≈ 1`. Per-host batching would have been very nearly a no-op.

**What the damage actually was.** The per-address writer's isolated cost is **108 µs**; production
p99 was **1,051 ms** — a ~9,700× multiplier produced by *concurrent* single-row write transactions,
not by cheap writes. So the transaction count is the thing to reduce, and only accumulation across
hosts reduces it.

**A failed flush RE-STAGES.** The old loop `break`ed on the first error and abandoned the host's
remaining waiters — the source of the run's **88 `country persist failed` aborts**. The driver
re-stages the failing window AND every later one, and a re-stage never clobbers a newer push for the
same endpoint, so it cannot grow without bound.

**Durability window:** the driver's tick is `GEO_DRAIN_INTERVAL = 5 s` and its window is
`GEO_FLUSH_AT = 256` rows. A bare tick commits only once the row floor (`flush_rows / 4`, i.e. 64)
is staged — that is what buys transaction size, per the `TIMER_FLOOR_DIVISOR` table — with the
staleness DEADLINE as the net for a trickle too slow to reach it. The deadline is **pinned at
`GEO_MAX_STAGED_AGE = 15 s`** through `WriteBehind::new_with_deadline`, not left at the driver's
`75`-tick default, which at a 5 s tick would have been 375 s: sixty-odd times the hard ceiling the
hand-rolled loop had. Results are delayed, not lost: `spawn_geo_drain` takes one final `flush()`
when `shutdown_token` is set, and the page seed persists its own rows. This is the same trade the link writer's
`max_staged_age` makes, and it is recorded here for the same reason.

## RowCache write-behind: the same statements, a caller-owned transaction (2026-10-05)

**No new raw SQL.** The RowCache migration replaced three bespoke writers (`LinkWriter`,
`GeoQueue`, the per-chunk import commits) with the generic `WriteBehind<Spec>` driver
(`crates/leas-db/src/write_behind.rs`, added in this change). It added **zero** statements to
this inventory: `write_behind.rs` contains no production SQL at all — only test fixtures
(`fake_state`) and an assertion statement. Every site below is a **move**, recorded here so a
reader diffing the file does not mistake a relocated statement for a new exception.

| Site | Change | Why |
| --- | --- | --- |
| `database.rs` `apply_link_patches_tx` | **MOVED.** The upsert loop was extracted out of `apply_link_patches_once` and now takes `(&mut impl toasty::Executor, &[LinkPatch], now)` instead of opening and committing its own transaction. The SQL text, the eight group buckets, and `LINK_STATEMENT_ROWS = 400` are unchanged; so is the wrapper's post-commit `endpoint_rank::refresh` on a second connection. | `LinkSpec` must run the write inside the transaction the DRIVER opened, so the retry and the commit belong to one owner. The wrapper `apply_link_patches_once` keeps its old signature and still calls it, so **nothing moved out of a transaction**. The one deliberate behaviour change is the driver's: `LinkSpec::refresh` calls `endpoint_rank::refresh` on the transaction it is about to commit, making the rank keys atomic with the write that invalidated them instead of a post-commit repair whose failure was only logged. |
| `database.rs` `set_endpoint_ip_countries_once` (`pub`) | **MOVED.** The per-row loop that was inlined in `set_endpoint_ip_countries`'s retry closure became a free `pub async fn` over `&mut impl Executor`. The statement is still `endpoint_ip::set_country` per row; no statement was rewritten. | `CountrySpec` opens its own transaction. A call that opened a *second* connection inside the driver's tx would deadlock on itself, and a second `retry_on_busy` inside the driver's retry would double the retry budget. |
| `upsert_endpoints_bulk`, `upsert_endpoint_group_links_bulk`, `upsert_protocols_bulk`, `upsert_links_bulk` | **UNCHANGED**, but their callers moved: `stream_import` now hands whole batches to `WriteBehind<SourceSpec>`, which commits once per window instead of once per chunk. | Same statements, fewer commits around them. |

**The transaction count is the thing that changed, so it is the thing to measure.** §3's numbers
are per-statement costs and are unaffected; what the migration removes is the *number of
transactions* around them. The measurement lives in
`crates/leas/src/ops/ping/flow_cost.rs` (`flow_cost_contention`, the ADR-0008 perf lab), in
the AFTER-NUMBERS block inside that function: the **driver-backed trickle row** is the direct
evidence (32 commits for 4,028 arrivals, 125.9 rows/flush, against the ~8 a bare size trigger
gives and 1,167 pre-driver).

**Its mixed import+geo fan-in arm is currently unusable and proves nothing.** Every import
transaction in that arm fails deterministically — `upsert_protocols_bulk` rejects a `Protocol`
whose deferred `config` was not loaded, because the lab builds its slice from `load_page_rows`
and `fcf2a5f` ("no toasty .include() on the profiles read path") stopped issuing `.include()`
there. `fcf2a5f` is an ancestor of this migration's base, the diff touches no `upsert_*_bulk`,
and `ArmFailures` correctly DISCARDs both import rows, so **the arm emits no row at all** — read
the geo arms and the trickle row instead, and do not read a before/after into a number that was
never recorded.

**No `db_method` span on the tx-scoped pair; one on the flush instead.** `apply_link_patches_tx`
and `set_endpoint_ip_countries_once` deliberately carry no
`#[tracing::instrument(target = "db_method")]` while their public wrappers do. A span is an
attribution, and `DbMonitor` attributes a write to the span that produced it — the driver flushes
from a background task, so a short inner span on a tx-scoped callee would win the attribution over
the wrapper's longer one and make the write look cheaper and shorter than the transaction it is
actually inside.

So the span sits one level UP, on `WriteBehind::flush` itself, named `write_behind_flush`: it is
the span that owns the transaction the driver opened, and it is what carries the write-behind
statements and the `retries` count. Without it the tx-scoped callees' deliberate silence left every
write-behind `toasty::query` event with no enclosing `db_method` span, so they all landed in the
`unattributed` bucket and the public `apply_link_patches` / `set_endpoint_ip_countries` rows read
zero in production even though those methods were being called.

## The driver's statement cache is unbounded — hydrate on the raw connection (2026-10-08)

**Symptom.** A long session (imports + tests + a feed-wide batch) reached ~1.5 GB RSS on a
13 MB database. Reproduced headlessly against a copy of a real feed (11,585 endpoints):
400 page hydrations with fresh ids grew RSS **+123,580 KiB, linear** (~309 KiB/call); the
same page twice over grew nothing (text-keyed, saturates); `profiles_page` (bound `?N`)
stayed flat.

**Cause (C4, measured).** `turso_sdk_kit/src/rsapi.rs` —
`TursoConnection.cached_statements: HashMap<String, Arc<CachedStatement>>`: no capacity, no
eviction. `prepare_cached` inserts one entry per SQL **text**, each holding a compiled
`Arc<turso_core::PreparedProgram>`. The PUBLISHED `toasty-driver-turso-0.11.0/src/lib.rs:1254`
routed **every** statement through it (`exec_sql_inner`). An inlined-literal statement is a
new text on every call, so the page hydration (ids inlined for the C6 perf win) compiled and
retained a program per page — forever. An A/B on identical unique texts: toasty `exec`
**+34,884 KiB / 300 calls** (~116 KiB/call) against the raw `turso::Connection::query`
**+0 KiB**.

**Fix (2026-10-08 — supersedes the earlier `Database::direct`-as-escape-hatch account).** The
crate now OWNS its driver (`crates/leas-db/src/driver/`, ADR 0012), and the fix is at the
boundary the leak lives on: `Connection::exec` routes `Operation::RawSql` — the hand-built,
literal-inlined statements that `toasty::sql::query`/`statement` produce — through the
UNCACHED `prepare`, and keeps `prepare_cached` for the engine-generated `Insert`/`QuerySql`
(stable text, compile-once). No LRU, no counter, no second connection. The old `sql_exec.rs`
`SqlConn` seam and `Database::write_conn` are RETIRED; `Database::direct` STAYS only because
it serves the page's execution-layer bypass (a read win, unrelated to the cache) and its
`exec_raw` reads still decode with the fork's `from_turso_infer`. A file db takes the raw
path; an in-memory db keeps the toasty path, which is the oracle the raw path is pinned to
(`page_projection_raw_matches_toasty`).

**Measured after:** the same 400 fresh-id hydrations plateau at **+8 MB** (was +123 MB), and
the routing itself is pinned by `tests/cache_routing.rs` (0 KiB uncached vs 59,336 KiB when
the routing is flipped to `Cached`).

**The write side, same owner (2026-10-08).** The leak is not read-only. `WriteBehind<LinkSpec>`
(and the same `apply_link_patches_tx` / `exec_link_upsert` / `upsert_endpoints_bulk` /
`upsert_endpoint_group_links_bulk` / `endpoint_rank::write` bodies) INLINE their literals, so a
flush window's SQL text varies on every call. Measured on a file db, 20-link slice, 200
windows: an IDENTICAL stamp **saturates at +1,752 KiB**, a varying stamp **grows +26,088 KiB
linear** — and at 200 links the pre-fix linear growth was **+188,684 KiB**. The typed writers
(`upsert_protocols_bulk`, `endpoint_ip::set_country`) bind their values, so their text is
stable and they do NOT leak.

**Fix — the crate owns its driver (2026-10-08).** Rather than dodge the cache from a SECOND
connection, the crate now VENDORS a local-only fork of `toasty-driver-turso`
(`crates/leas-db/src/driver/`, from toasty `main` at its `turso = "0.8"` bump) and fixes the
cache at its boundary: `Connection::exec` routes `Operation::RawSql` — the hand-built,
literal-inlined statements — through the UNCACHED `prepare`, and `Insert`/`QuerySql` (stable,
engine-generated text) through `prepare_cached`. That is the same boundary the leak lives on, so
no LRU, counter, or flush threshold is needed. The old `sql_exec.rs` `SqlConn`/`RawConn` seam,
`CacheSpec::RAW`, `write_window_raw`/`refresh_raw`, the manual `BEGIN`/`COMMIT`, and
`Database::write_conn` are RETIRED; the bulk writers run on the POOLED driver and keep their
literal-inlining win. (`Database::direct` stays — it serves the page's execution-layer bypass, a
~80x read win unrelated to the cache.)

**Busy classification is load-bearing.** `export::turso_error` flattens every turso error to
`DatabaseError::Generic`, which `is_busy_error` rejects — so an MVCC commit conflict or a WAL wait
would be a PERMANENT failure that re-stages the window instead of retrying, the one class
`retry_on_busy` exists for. The fork's `driver::error::classify_turso_error` keeps
`Busy`/`BusySnapshot`/`"conflict"` retryable (a toasty serialization failure), pinned by
`contention_is_retryable_and_real_errors_are_not`.

**Measured after:** the write-side leak is fixed AT THE SOURCE (the `RawSql` arm no longer
touches the per-text cache), so no raw-connection workaround remains. The write path is pinned by
`file_db_link_window_writes_the_staged_values` (a real file db) plus the existing write-behind
suite.

**Resolved by the driver fork (2026-10-08).** `SourceSpec::write_window` used to mix the raw
families with the TYPED `upsert_protocols_bulk` in one transaction across two sessions. That
split is GONE: every helper now takes `&mut impl toasty::Executor`, so the whole window — raw
families and the typed protocols writer alike — runs on ONE pooled transaction, and the
inlined-literal statements are served by the fork's uncached `RawSql` route. No raw protocols
INSERT or two-tx split is needed.
