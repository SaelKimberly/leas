# Hand-written SQL and DDL in the DB layer

This file answers one question: which statements in `crates/leas-db` bypass
toasty, and why is each one allowed to. It gives the rule, the capability gaps
that force an exception, one row per live site with its cause, measurement and
pinning test, the toasty failures that justify the gaps, the manual paths already
rejected, the checklist for adding a site, and the procedure for re-checking a
blocker after a toasty bump. It does not own the schema, the flows, or the query
map: those live in [`database.md`](database.md). Derived-state law lives in
[`ordering-law.md`](ordering-law.md).

Related records: [`database.md`](database.md) (tables, indexes, flows, query
map), [`../aegis/adr/0001-raw-sql-profiles-page-query.md`](../aegis/adr/0001-raw-sql-profiles-page-query.md)
(the page query), [`../aegis/adr/0002-write-behind-link-writer.md`](../aegis/adr/0002-write-behind-link-writer.md)
(the link writers), [`../aegis/adr/0003-stored-profile-ordering-keys.md`](../aegis/adr/0003-stored-profile-ordering-keys.md)
(the rank keys), [`../aegis/adr/0012-owned-turso-driver-and-migrations.md`](../aegis/adr/0012-owned-turso-driver-and-migrations.md)
(the driver fork and the migration cursor),
[`../aegis/specs/2026-09-16-db-claim-verification.md`](../aegis/specs/2026-09-16-db-claim-verification.md)
(the measurements behind the engine facts cited here).

## 1. The rule

- **Typed path first.** Single-row reads and writes of a model (endpoints,
  protocols, links, groups, endpoint to group links, routing rules, DNS
  settings, route probes) go through the typed API (`Model::filter...`,
  `upsert_by_*`, `toasty::create!/update!`), so enum, JSON and timestamp
  encodings and the `CHECK` constraints stay the ORM's business.
- **Raw SQL needs a cause from §2.** "It is easier to write" is not one.
  Neither is "it is faster" without a number in §3.
- **Never a second owner of a fact.** A hand-written statement may only write
  columns its own group owns, and may not create a second spelling of a stored
  fact (the reason the `(family, addr)` split in §5 was rejected).
- **Inlined literals, not binds, on bulk statements.** The engine charges
  ~0.8 ms per *bound* parameter (200 ids = 174 ms against 9.7 ms for the same
  statement with literals). Ids and keys produced by this database are rendered
  as literals; user text goes through `sql_lit` (quotes doubled) or a bind.
- **Every raw statement must be exercised by a test.** There is no single drift
  guard. `tests/profiles_query.rs`
  `every_statement_runs_against_a_pushed_schema` executes only the
  `profiles_query.rs` builders. Every other site is pinned indirectly by the
  behaviour test named in §3, and a new statement is covered by neither until a
  test runs it (checklist item 5 in §6).

`write_behind.rs` contains no production SQL. Its only statements are test
fixtures (`fake_state`) and an assertion, so the write-behind driver is a
transaction and retry owner, not an exception.

Statements that moved without being rewritten are recorded in §3's note on
moved statements, not as new rows. Sites that no longer exist are in §8.

## 2. The causes

| Cause | Consequence |
| --- | --- |
| **C1. No upsert or conflict clause.** `toasty` 0.11 **does** have a multi-row insert, `stmt::CreateMany` (`stmt/create_many.rs`, `lib.rs:124`), but it builds a bare `INSERT INTO ... VALUES (...), (...)` from `item.into_insert()` and carries **no** `on_conflict`, `or replace` or upsert semantics (`grep -rl "on_conflict\|OnConflict" toasty-0.11.0/src/stmt` finds nothing). `upsert_by_*` exists but is macro-generated and single-row: `toasty-macros-0.11.0/src/model/expand/upsert.rs:60-82` emits `upsert_by_{field}` plus `{Model}UpsertBy{suffix}` and `...OrIgnore` (documented at `toasty-macros-0.11.0/src/lib.rs:52`), and the statement it builds is documented as "A typed **single-row** upsert statement" (`toasty-0.11.0/src/stmt/upsert.rs:5`). The multi-row *conflict* clause is the missing capability. | Multi-row upserts are hand-built. |
| **C2. `#[index]` is per-field and single-column.** Re-verified against `toasty-macros-0.11.0/src/lib.rs:224` and `:1155`: "Creates a non-unique index on the field / the field's flattened column", with no composite, mixed-direction, partial or expression form. | Indexes toasty cannot express are raw `CREATE INDEX IF NOT EXISTS`, applied at open by the migration runner. |
| **C3. No per-connection hook.** The driver creates pooled connections itself. | `Database::conn()` re-issues the per-connection settings it can (`busy_timeout`, `synchronous`); `journal_mode` and `foreign_keys` are set once at open. |
| **C4. No raw connection access.** `Db::driver()` yields `&dyn Driver`, not the turso connection. | UDFs, `turso::core`, statement-cache control, `set_query_timeout`, `interrupt`, and experimental driver flags beyond the `experimental_*` setters are unreachable through the trait. Raw SQL itself is reachable: `toasty::sql::query/statement` is the supported channel and is what every site below uses. |
| **C5. Engine shape.** No `UPDATE ... FROM (VALUES ...)` (parse error); unknown PRAGMAs are silently ignored; `array_agg` needs an experimental flag and returns text; `BIGINT` and `BOOLEAN` are illegal in a STRICT table; expression indexes are not used for `LIKE`. | Some statements cannot be expressed at all; some "obvious" tuning is a no-op. |
| **C6. Measured cost.** Binding, per-row statements and ORM round-trips cost more than one hand-built statement on this engine. | The numbers in §3 are the justification. |
| **C7. No projection over aggregate expressions.** The typed builders are per-model row reads (`all`, `filter`, `order_by`, `limit`, `first`) plus `count()`; there is no `SUM`, conditional aggregate, `GROUP BY`, or expression projection. A partition such as `SUM(CASE WHEN rank_bin = 12 ...)` over stored columns is unreachable from the typed path. | Bucket and anchor reads are raw SQL. The typed path can only re-read every row and aggregate in Rust, which is the O(feed) cost the page query exists to avoid. |
| **C8. Derived state outside the model.** `endpoint_rank`'s `band`, `rank_alive` and `rank_weight` columns sit on a derived table and are recomputed on every write; `rank_weight_meta` is a one-row stamp. Declaring them on a model would give a second owner of a derived fact. | Raw `ALTER TABLE ADD COLUMN` and `CREATE TABLE ... IF NOT EXISTS` in `schema/ddl.rs`. Not a toasty gap; a design choice. |
| **C9. One-way data migration.** Copying a column, clearing it, renaming it and dropping the discriminator in one gated step cannot be expressed through the typed layer, and the statements are not idempotent. | Statements live in the migration step list (`schema/steps.rs`), gated by the `PRAGMA user_version` cursor in `schema/mod.rs`. |
| **C10. Expressions the typed update builder cannot render.** There is no column self-reference, no `MAX`/`COALESCE` self-comparison, and no per-column conditional mix of copied and skipped fields. | Maintenance writes that must keep the larger of two timestamps are raw `UPDATE` statements. |

C1 and C2 were re-verified against `toasty-0.11.0` on 2026-10-01. C3 to C7 are
unverified against 0.11 and carry no re-verification date; see §7. C8 to C10 are design causes, not toasty gaps, and do not move with a toasty version.

## 3. The inventory

One row per site. The `Site` column names the file and the items that hold the
statement, all paths relative to `crates/leas-db/`. Measurements are quoted from
the run that produced them, with its date; "no number recorded" means exactly
that, not "fast".

| Site | Cause | Measurement | Pinned by |
| --- | --- | --- | --- |
| `src/schema/ddl.rs` `ENDPOINT_IP_BY_KEY`: `CREATE INDEX IF NOT EXISTS endpoint_ip_by_key ON endpoint_ip (ip_key, endpoint_id)` | C2 | No standalone number recorded. The index is what makes `PageSort::Ip` a two-column key order instead of a sort. | `page_order_matches_the_rust_oracle_for_every_sort` (`PageSort::Ip`); applied by the runner on every `Database::open` and `in_memory` |
| `src/schema/ddl.rs` `ENDPOINT_RANK_KEY_V2` and `ENDPOINT_RANK_KEY_DROP`: covering index `(band, rank_bin, rank_stab, rank_weight DESC, rank_domain, rank_sub_domain, rank_addr, endpoint_id, rank_proven)`, plus `DROP INDEX IF EXISTS endpoint_rank_key` | C2 | Page fetch 1757 ms to 8.6 ms for the default Test sort (ADR 0003, 7,672 endpoints); Active Test page 1.52 ms at 50k scale, 8.6 ms at 7,672 endpoints (2026-10-01). A new name is mandatory: `IF NOT EXISTS` makes an edited column list a silent no-op on an existing file. `rank_proven` trails so every scope filters inline on the same index. | `page_order_matches_the_rust_oracle_for_every_sort`, `the_test_order_has_an_index_that_includes_the_weight` |
| `src/schema/ddl.rs` `ENDPOINT_RANK_BAND_WINDOW`: `CREATE INDEX IF NOT EXISTS endpoint_rank_band_window ON endpoint_rank(band, rank_newest_seen)` | C2 | No number recorded. The directional sweep seeks `band < 2 AND rank_newest_seen < ?` through this index, so an arbitrary downtime gap is corrected in one range scan. | `reband_sweep_demotes_rows_that_drifted_during_downtime` |
| `src/schema/ddl.rs` `RANK_WEIGHT_META`: `CREATE TABLE IF NOT EXISTS rank_weight_meta (id INTEGER PRIMARY KEY CHECK (id = 0), weight_version INTEGER NOT NULL)` | C8 | A mismatch between the stored version and `KEY_INPUTS_VERSION` recomputes every rank key at open. The stamp is the only trigger that can replace the all-zero default that `ADD COLUMN` materializes for pre-existing rows. | `a_stale_weight_version_is_recomputed_at_open` |
| `src/schema/ddl.rs` `ENDPOINT_RANK_ADD_COLUMNS` (`band`, `rank_weight BLOB NOT NULL DEFAULT x'0000000000000000'`, `rank_stab`, `rank_proven`, `rank_alive`) and `STAB_ADD_COLUMNS` (`profile_stats.stab_mask`, `stab_len`) | C8 for the rank columns; the stab columns are typed model fields whose ALTER only backfills tables created before the fields were declared | `ALTER TABLE ADD COLUMN` is not idempotent on this engine. The runner attempts it on every open and tolerates exactly one error string, "duplicate column". `rank_weight` must be `NOT NULL DEFAULT`: `profiles_anchor` binds each ordering term's value back and the engine refuses to type a NULL there, so a NULL weight makes the anchor query error. | `fresh_open_creates_tables_and_raw_ddl`, `reopen_tolerates_duplicate_column_on_already_migrated_file`, `every_rank_row_carries_a_non_null_weight`, `anchoring_works_on_a_row_carrying_only_the_weight_default` |
| `src/schema/ddl.rs` `V19_LATENCY_RESHAPE`, applied by `src/schema/steps.rs` `STEPS` | C9 | Schema 19. Order is load-bearing: add `latency_fast_delay`, copy a `'fast'` row's delay into it, clear that delay from `latency_delay`, rename `latency_delay` to `latency_real_delay`, then drop `latency`. `RENAME COLUMN` and `DROP COLUMN` fail with "no such column" on a second application, so the steps and the cursor advance in one `TransactionMode::Immediate` transaction. | `a_v18_database_migrates_and_keeps_its_numbers`, `reopening_a_migrated_file_does_not_re_run_the_non_idempotent_step`, `the_migrated_table_has_no_latency_discriminator` |
| `src/schema/mod.rs` `cursor`, `migrate`, `ensure_raw_ddl`, `seed_stability_once`: `PRAGMA user_version` read and stamp, `app_meta` stamp upsert, `UPDATE profile_stats SET stab_mask = 1, stab_len = 1 WHERE latency_real_delay IS NOT NULL`, `DELETE FROM rank_weight_meta` | C4 (the cursor is below the typed layer) and C9 (the seed and its one-way stamp must share a transaction) | Schema constant is 19 (`database.rs:SCHEMA_VERSION`). The seed runs at most once per database; the stamp key is `stability_seeded_v2` (renamed from the v1 key because the old predicate named the `latency` discriminator that migration 19 drops). The `DELETE FROM rank_weight_meta` is best-effort: a very old file may lack the table, and the rank `ensure` recreates it. | `the_stability_seed_runs_once_and_is_stamped`, `the_stab_seed_marks_real_latency_links_as_proven`, `a_seed_lost_to_a_crash_is_rerun_on_the_next_open`, `unknown_cursor_is_recreated_not_migrated` |
| `src/database.rs` `open_with_concurrent_writes`, `in_memory`, `conn`, `configure_journal_mode`, `open_direct_conn`: `PRAGMA journal_mode`, `busy_timeout=5000`, `synchronous=NORMAL`, `foreign_keys=ON` | C3 | Default `synchronous=FULL` costs ~4.2 ms per commit on this engine; a 30k-link ping batch issues ~90k commits and froze the UI task awaiting them (2026-09-11 investigation). `busy_timeout` is what turns instant "database is locked" failures into queuing (the 850-line dump class). `conn()` re-issues `busy_timeout` and `synchronous` only; `journal_mode` and `foreign_keys` are set at open. | `fresh_open_creates_schema_and_sets_user_version_tag`, `open_reopen_preserves_data`, `open_wipes_a_file_with_a_mismatched_schema_tag` |
| `src/database.rs` `sql_lit`, `sql_opt_lit`, `sql_opt_num`, `error_kind_str`, `purge_reason_str`, `blob_lit` | C1 (a hand-built statement has no encoder) | `purge_reason` spellings are toasty's own `snake_case` rendering, verified by the column-shape probe of 2026-09-17. A wrong spelling is rejected by the column `CHECK`, never stored. `blob_lit` writes `ports` as the JSON text the typed upsert writes. | `multi_row_import_writers_round_trip_through_a_real_database`, `apply_link_patches_writes_patched_groups_for_every_row` |
| `src/database.rs` `LINK_UPSERT_PREFIX`, `link_values_sql`, `exec_link_upsert` (used by `apply_link_patches_tx` and `upsert_links_bulk`): one multi-row `INSERT INTO profile_stats ... ON CONFLICT(protocol_id, endpoint_id) DO UPDATE` per 400-row chunk | C1, C4 (the `RawSql` route is uncached), C5 (`UPDATE ... FROM (VALUES ...)` is a parse error) | 512-patch window 29.0 ms to 10.0 ms including the rank refresh (ADR 0002). Chunk width is free: 400, 1,000 and 2,000 rows per statement measured 11.1, 10.6 and 10.6 ms (2026-09-16). Bound parameters cost ~0.8 ms each, so every value is inlined. | `apply_link_patches_writes_patched_groups_for_every_row`, `apply_link_patches_applies_a_window_wider_than_one_statement_chunk`, `link_writes_keep_the_stored_keys_current` |
| `src/database.rs` `link_patch_conflict_sql` and the bucket loop in `apply_link_patches_tx`: the per-action `DO UPDATE SET` list | C1 (the action is per statement, so patches are bucketed by action) | Four groups (RESULT, PURGE, TRAFFIC, STAB), so sixteen 4-bit buckets; the empty bucket is `DO NOTHING` (a patch with no group only creates a missing row). `contains` decides the columns, so an unknown bit cannot drop a group. `purge_reason` is its own group because the action writes a FIXED column set from each patch's snapshot: riding RESULT would let a phase-1 fast half rewrite a verdict it never classified (ADR 0006). `stab_mask` and `stab_len` have their own bit for the same shape, because a fast-only RESULT snapshot never sampled the ring. | `apply_link_patches_isolates_column_groups`, `link_patches_leave_columns_outside_their_groups_alone`, `apply_link_patches_upserts_absent_and_near_miss_pairs_exactly` |
| `src/database.rs` `LINK_SOURCE_CONFLICT_SQL` and `upsert_links_bulk`: SOURCE columns only on conflict (`last_seen_at`, `updated_at`) | C1 | Per-row typed upserts destroyed freshly measured latencies when an import refresh ran beside a Fast+Real batch (2026-09-15). The conflict action is deliberately narrow so RESULT, PURGE and TRAFFIC columns keep their owners. | `multi_row_import_writers_round_trip_through_a_real_database`, `link_writes_keep_the_stored_keys_current`, `a_result_patch_that_inserts_a_link_still_moves_the_key` |
| `src/database.rs` `upsert_endpoints_bulk`: one multi-row `INSERT INTO endpoints ... ON CONFLICT(id) DO UPDATE` per 400 rows | C1 | The 2026-10-01 import issued 105,147 statements for this family; chunked at 400 it issues ~263 for the same rows (2026-10-02). The update list excludes `manual_protocol_override` and `resolved_at`, which the import does not own. | `multi_row_import_writers_round_trip_through_a_real_database`, `multi_row_endpoint_upsert_replaces_and_preserves` |
| `src/database.rs` `upsert_endpoint_group_links_bulk`: one multi-row `INSERT INTO endpoint_groups ... ON CONFLICT(endpoint_id, group_id) DO UPDATE` per 400 rows | C1 | The single largest import family: 204,592 statements, half the total, because a 500-URL batch touches one endpoint once per protocol. Chunked at 400 it issues ~511 (2026-10-02). | `multi_row_import_writers_round_trip_through_a_real_database`, `streaming_import_splits_and_persists_in_batches` |
| `src/database.rs` `upsert_protocols_bulk`: **typed, one `Protocol::upsert_by_id` per row**. Listed because the deferral is deliberate, not an omission | C1 is NOT used here | 99,728 statements, the remaining quarter of the import (2026-10-01). Conversion is blocked on a writer-side `as_db_label` for `TransportType`, `SecurityType` and `ProtocolKind` (the feed stores `shadowsocks2022`, `http_upgrade`, `x_http`, which are not the `as_str()`/`FromStr` spellings) plus the confirmed storage encoding of the `transport.data` and `security.data` JSON columns. Raw SQL without both would risk a row the connect path cannot read. | `multi_row_import_writers_round_trip_through_a_real_database` (round-trips the typed writer). No test asserts the deferred-config guard |
| `src/database.rs` `purge_expired_once`: candidate `SELECT e.id FROM endpoints e WHERE NOT EXISTS (...)` outside the write transaction, plus an id-inlined re-check inside it | C6 (toasty's `.all()` quantifier compiles to a whole-table projection) | The scan measured 3,098 ms on 74,014 endpoints (2026-10-01), and it ran INSIDE the write transaction, so every other writer queued behind a three-second lock hold on the single database handle. The typed `.all()` form costs 145 ms but cannot express the all-links quantifier without a full projection. The predicate is all-links staleness, deliberately not the live-only `band`: a fresh-but-purged link must keep its endpoint (ADR 0006). | `purge_expired_matches_all_links_semantics` |
| `src/endpoint_rank.rs` `ensure_in`, `stamp_weight_version`, `backfill_bands`: `SELECT weight_version FROM rank_weight_meta`, `INSERT ... ON CONFLICT(id) DO UPDATE`, `SELECT COUNT(*) FROM endpoint_rank`, `UPDATE ... SET band = CASE ... WHERE band IS NULL` | C1, C8 | The band backfill is the one-time cost for rows that predate the column (`repair_missing` fills only absent rows). The version check must sit on the populated branch: `ADD COLUMN ... NOT NULL DEFAULT` materializes the worst weight, so there are no NULLs to find. | `a_stale_weight_version_is_recomputed_at_open`, `link_writes_keep_the_stored_keys_current` |
| `src/endpoint_rank.rs` `write`: `INSERT OR REPLACE INTO endpoint_rank (...) VALUES (...)` per 400 rows, then one `UPDATE ... SET band = CASE ... WHERE endpoint_id IN (...)` per chunk | C1, C8 | Per-row `upsert_by_endpoint_id` costs ~1.2 ms per statement: a 400-endpoint window took ~470 ms and a 7.7k-endpoint import ~8 s. The bulk form is ~10x cheaper (no separate number recorded). The follow-up `UPDATE` exists because `INSERT OR REPLACE` nulls the raw `band` column; `rank_weight` is Rust-computed and rides the VALUES tuple. | `link_writes_keep_the_stored_keys_current`, `a_result_patch_that_inserts_a_link_still_moves_the_key`, `purging_endpoints_drops_their_keys` |
| `src/endpoint_rank.rs` `reband_expired` and `reband_all`: directional demote `UPDATE ... SET band = 2 WHERE band < 2 AND rank_newest_seen < ?`, and the full-recompute `CASE` | C1, C6 | Membership is a stored `band` maintained as `now` crosses the threshold. The directional form seeks only the drifted rows through `(band, rank_newest_seen)`, so an arbitrary downtime gap is corrected in one range scan. Full recompute runs at startup because a configured TTL larger than the default must promote rows the default demoted. | `reband_sweep_demotes_rows_that_drifted_during_downtime`, `reband_all_promotes_rows_the_default_backfill_demoted` |
| `src/endpoint_rank.rs` `refresh`, `load_raw_endpoints`, `repair_missing`, `first_ip_keys`, `resolved_endpoint_ids`: id-inlined reads plus the `LEFT JOIN protocols` weight read (`backfill_all` reuses the two id reads and typed loads) | C6 | Binding costs ~0.8 ms per id, so ids are inlined. The join carries four discriminator columns (`transport_type`, `security_type`, `security_sni`, `security_fp`; `proto_kind` is deliberately not a weight dimension) at one indexed lookup per link, and leaves the deferred `config` JSON unloaded. `transport_type` is parsed with `TransportType::from_db_label`, not `FromStr`, because toasty's embed writes `http_upgrade` and `x_http` where the wire form says `httpupgrade` and `xhttp`; the wrong parser silently persists a zero weight for 314 of ~21k real protocol rows. A link whose protocol row is absent (LEFT join) sorts as worst. | `resolving_a_dns_host_moves_its_stored_key`, `purging_endpoints_drops_their_keys`, `load_page_rows_preserves_page_and_link_order` |
| `src/endpoint_ip.rs` `insert_literals_bulk`: multi-row `INSERT INTO endpoint_ip (endpoint_id, ip_key) VALUES ... ON CONFLICT DO NOTHING` per 400 rows | C1 | Replaces the import path's reuse of the resolution writer for IP literals, which cost 3 statements each over ~56k IP-literal endpoints (db-rewamp D10). `DO NOTHING` is exact: an existing row means the same literal was imported before, and its `country` must survive. | `streaming_import_splits_and_persists_in_batches` |
| `src/endpoint_ip.rs` `set_countries_bulk` (reached from `database.rs` `set_endpoint_ip_countries_once`, the `CountrySpec` write): multi-row `INSERT INTO endpoint_ip (endpoint_id, ip_key, country) VALUES ... ON CONFLICT DO UPDATE SET country = excluded.country` per 400 rows | C1, C6 | One statement removes the TOCTOU that two writers could hit under MVCC: the resulting `Constraint` is not a busy error, so `retry_on_busy` never retried it. The per-address writer it replaced cost 108 µs in isolation against a production p99 of 1,051 ms (2026-10-01): a ~9,700x multiplier produced by concurrent single-row transactions. The 2026-10-01 run recorded 933 lookups, 1,577 deferred halves (~788 distinct links) and 790 per-address invocations, so per-host batching would have been a no-op (`waiters.len()` ~ 1). The run also recorded 88 `country persist failed` aborts, which the write-behind driver's re-stage path removes. | `set_countries_bulk_keeps_the_last_value_for_a_duplicate_row`, `stored_country_survives_re_resolution` |
| `src/endpoint_ip.rs` `load_resolved` (used by `load`), `countries_of`, `delete_for`: id-inlined `SELECT endpoint_id, ip_key, country FROM endpoint_ip WHERE endpoint_id IN (...)` and `DELETE ... WHERE endpoint_id IN (...)` | C6 | Same ~0.8 ms per bound id. `countries_of` runs once per resolution inside `replace`; re-reading one endpoint's 1 to 3 rows is cheaper than re-walking the mmdb. `delete_for` runs in the same transaction that removes the endpoint rows. | `page_rows_assemble_links_and_protocols`, `large_page_loads_via_batched_in_list`, `stored_country_reaches_the_ui_without_the_mmdb` |
| `src/endpoint_ip.rs` `replace`: typed `EndpointIp` delete plus typed create per key, with one raw `countries_of` read | C6 for the read; the writes are typed on purpose | The write half is the model for "small set, typed is fine": the set is 1 to 3 rows and TTL-gated. The raw half carries the surviving addresses' countries so a re-resolution does not throw away a stored lookup. | `resolving_a_dns_host_moves_its_stored_key`, `stored_country_survives_re_resolution` |
| `src/merge.rs` `overwrite_link_fields`: one `UPDATE profile_stats SET <measured fields> WHERE protocol_id = ? AND endpoint_id = ?` | C10: the typed `update()` builder cannot express the column self-references the rule needs (`last_seen_at = MAX(last_seen_at, ?)`, `last_used_at = MAX(COALESCE(last_used_at, 0), ?)`) nor the conditional per-column mix of copied and skipped fields in one statement | No number recorded; maintenance path, one statement per collision. `purge_reason` and the traffic counters are deliberately absent from the SET list: the survivor's verdict and counters are its own. | `merge_keeps_survivor_purge_verdict_over_absorbed_measured_link`, `merge_dns_survivor_absorbs_ip_literal_and_takes_better_evidence` |
| `src/merge.rs` `merge_memberships`: `UPDATE endpoint_groups SET last_seen_at = ? WHERE endpoint_id = ? AND group_id = ?` | C10: the fresher confirmation wins, and the survivor's display order stays | No number recorded. | `merge_moves_group_membership_and_resolves_collision` |
| `src/merge.rs` `merge_links`: `UPDATE profile_stats SET last_used_at = ? WHERE protocol_id = ? AND endpoint_id = ?` after the moved links are bulk-upserted | C1 | The bulk upsert's VALUES tuple writes `last_used_at` as literal `NULL` and its SOURCE conflict action never restores it; the column's owner (`update_last_used`) cannot run inside this transaction. | `merge_dns_survivor_absorbs_ip_literal_and_takes_better_evidence` |
| `src/profiles_query.rs` `profiles_count_with` and `page_ids_direct` (`profiles_page`), `profiles_walk_page`: `SELECT COUNT(*)` plus the ordered id `SELECT` built by `base_select`/`order_by` (the page's id list carries no binds; hydration is the site that inlines ids) | C2 (ordering through the covering index), C4 (the direct connection's uncached `prepare` avoids the per-text statement cache), C6 | Page path 488 ms typed against 49.6 ms inlined for 200 rows; the same ADR 0001 comparison measured 1,027 ms to 49.6 ms. The walk asks for the feed-wide total once instead of once per page, which was `O(feed²/200)` (92 `COUNT(*)` calls for one 18,334-endpoint batch, 2026-09-17). `profiles_walk_page` has **no production caller since 2026-10-01** (the batch walk freezes its id set up front); it stays as the streaming baseline for `ops/ping/flow_cost.rs`. The plan-scope predicate (`PlanScope::predicate`) is shared by page, walk and count so a scoped batch and its footer cannot drift. | `every_statement_runs_against_a_pushed_schema`, `page_order_matches_the_rust_oracle_for_every_sort`, `count_narrows_with_search_and_group_filters`, `walk_pages_match_the_page_ids_and_count_once`, `paging_visits_every_endpoint_exactly_once`, `the_direct_page_matches_the_toasty_page` |
| `src/profiles_query.rs` `profiles_anchor`: one key `SELECT` through the ordering expressions, then a lexicographic `SELECT COUNT(*)` over the same terms and directions | C2, C7 | No number recorded. Exact for every sort and direction because it reuses `order_terms`, with each earlier term compared for equality and the current one strictly before. | `anchor_and_page_agree_after_a_weight_change`, `anchor_returns_each_rows_position_for_every_sort_and_direction`, `anchoring_works_on_a_row_carrying_only_the_weight_default` |
| `src/profiles_query.rs` `load_page_projection`: one statement over `PAGE_PROJECTION`, ids inlined, `group_concat(hex(ip_key), ',')` for the address set | C6 (binding), C4 (uncached `prepare` on the direct connection), C7 (the aggregate expression) | One inlined-id statement returns the same 200 rows in 29 ms; the typed path's three IN-list hydration reads were ~480 ms of the 488 ms page cost (ADR 0001). A 200-row page carries ~600 binds. The correlated address aggregate costs +3.3 to +4.6 ms on an unresolved page and +6.1 ms fully resolved, against 389 ms for a correlated derived table with its own `ORDER BY`; the address aggregate figures are from the 2026-09-15 address-storage spec. The deferred JSON carriers are omitted so no JSON is decoded. | `page_projection_matches_the_orm_rows`, `page_projection_raw_matches_toasty`, `page_projection_keeps_the_requested_order_and_skips_empty_pages` |
| `src/profiles_query.rs` `profiles_aggregate` (`aggregate_sql`): one `SELECT COUNT(*)` plus seven `SUM(CASE WHEN ...)` arms over `endpoint_rank`, per scope | C7, C6 | `alive` is `rank_newest_seen >= ? AND rank_alive = 1` for the global scope (live, because the swept `band` can lag) or `band = 0` for a view; `active` is the same with `rank_alive = 0` or `band = 1`. Three partition arms are the crate's own `PlanScope::predicate` strings verbatim (Successful, New, Failed), plus a `rank_stab <= 2` reliability arm and an `other` remainder, so a proven endpoint carrying bin 12 counts once. The statement is index-served: `endpoint_rank_key_v2` carries `rank_bin`, `rank_stab` and `rank_proven`, and `endpoint_rank_band_window` carries `rank_newest_seen`. It groups and sorts nothing. | `aggregate_buckets_partition_the_total`, `aggregate_alive_and_active_are_distinct_bands`, `aggregate_alive_is_live_for_the_global_scope`, `aggregate_view_total_matches_the_page_count`, `the_direct_aggregate_matches_the_toasty_aggregate` |
| `src/export.rs` `open_export_reader`, `projection_sql`, `query_count`: dedicated turso connection, `PRAGMA journal_mode`, `BEGIN DEFERRED` (WAL) or `BEGIN CONCURRENT` (MVCC), one count statement, one ordered projection streamed row by row | C4 (the trait exposes no raw connection), C6 (toasty's public query and raw SQL return `Vec`; the driver drains physical `Rows` before toasty sees them, so no bounded row stream is reachable) | No number recorded. The reader is file-only and separate from toasty writes; it holds the process export gate, decodes one physical row at a time, and never materializes a feed-wide row or config vector. Ordering is deterministic (protocol kind, transport, security, address rank, key, host, port, ids). | `export::tests::alive_uses_canonical_link_tier_and_dns_resolution`, `export::tests::resolved_emits_each_dns_address_and_one_ip_literal` |
| `src/driver/mod.rs` `Connection::exec`: `Operation::RawSql` routed to `Prepare::Uncached`, `Insert` and `QuerySql` kept on `Prepare::Cached` | C4 (the cache policy belongs to the driver boundary) | The leak: `turso_sdk_kit/src/rsapi.rs` `TursoConnection.cached_statements` has no capacity and no eviction. Reproduced on a copy of a real feed (11,585 endpoints): 400 page hydrations with fresh ids grew RSS +123,580 KiB, linear, ~309 KiB per call; the same page twice grew nothing; `profiles_page` (bound `?N`) stayed flat. A/B on identical unique texts: toasty `exec` +34,884 KiB over 300 calls (~116 KiB per call) against +0 for raw `turso::Connection::query`. Fix measured after: the same 400 hydrations plateau at +8 MB. Write side, 20-link slice, 200 windows: an identical stamp saturates at +1,752 KiB, a varying stamp grew +26,088 KiB linear, and at 200 links the pre-fix growth was +188,684 KiB. | `tests/cache_routing.rs` (0 KiB uncached against 59,336 KiB with the routing flipped to `Cached`), `file_db_link_window_writes_the_staged_values`, `contention_is_retryable_and_real_errors_are_not` |
| `src/driver/mod.rs` `applied_migrations`, `apply_migration`: `CREATE_MIGRATIONS_TABLE`, `SELECT id FROM __toasty_migrations ORDER BY applied_at`, parameterized `INSERT INTO __toasty_migrations` | C4 (the migration trait sits at the driver boundary, one layer below the typed API) | No number recorded. The migration batch is applied as one atomic transactional batch. The crate's own runner (`schema::migrate`) does not call this path, so nothing in this repository pins it. | none |

### Notes on the table

- **Moved statements.** The RowCache change (2026-10-05) added **zero**
  statements. It moved `apply_link_patches_tx` out of
  `apply_link_patches_once` and `set_endpoint_ip_countries_once` out of the
  per-address retry closure, so both run on the transaction the write-behind
  driver opened. The SQL text and the 400-row chunk size did not change.
  `apply_link_patches_once` keeps its public signature and still owns the
  post-commit `endpoint_rank::refresh`; the driver's `LinkSpec::refresh` does the
  same on the driver's transaction.
- **Span placement.** `apply_link_patches_tx` and
  `set_endpoint_ip_countries_once` deliberately carry no
  `#[tracing::instrument(target = "db_method")]`. `DbMonitor` attributes a write
  to the span that produced it, and the driver flushes from a background task, so
  a short inner span would win attribution over the wrapper's longer one. The
  span sits on `WriteBehind::flush` as `write_behind_flush`, which carries the
  write-behind statements and the retry count.
- **Transaction count, not statement cost.** The 2026-10-05 change reduced the
  number of transactions around unchanged statements. Measured in
  `crates/leas/src/ops/ping/flow_cost.rs` (`flow_cost_contention`, ADR 0008 perf
  lab): the driver-backed trickle row records 32 commits for 4,028 arrivals at
  125.9 rows per flush, against the ~8 a bare size trigger gives and 1,167 before
  the driver.
- **The lab's mixed import and geo arm proves nothing.** Every import
  transaction in that arm fails deterministically: `upsert_protocols_bulk`
  rejects a `Protocol` whose deferred `config` was not loaded, because the lab
  builds its slice from `load_page_rows` and `fcf2a5f` ("no toasty `.include()`
  on the profiles read path") stopped issuing `.include()` there. `fcf2a5f`
  predates the write-behind change, the diff touches no `upsert_*_bulk`, and
  `ArmFailures` discards both import rows, so the arm emits no row at all. Read
  the geo arms and the trickle row instead.
- **Geo durability window.** `GEO_DRAIN_INTERVAL` is 5 s, `GEO_FLUSH_AT` is 256
  rows, and a bare tick commits only once the row floor (64, i.e.
  `flush_rows / TIMER_FLOOR_DIVISOR`) is staged. The staleness deadline is
  pinned at `GEO_MAX_STAGED_AGE` (15 s) through `WriteBehind::new_with_deadline`,
  not left at the driver's 75-tick default, which at a 5 s tick would be 375 s.
  Results are delayed, not lost: `spawn_geo_drain` takes one final `flush()` when
  the shutdown token is set, and the page seed persists its own rows.

## 4. Toasty blockers, with the exact failures

1. **Bulk upsert.** No multi-row insert WITH a conflict clause: `CreateMany`
   exists in `toasty-0.11.0/src/stmt/` but carries none (see C1), and
   `upsert_by_*` is single-row only. Cost of the
   missing semantics: the hand-built statement in §3, plus the manual `CHECK`
   spellings. **Re-verified 2026-10-01 against the vendored 0.11.0 source.**
2. **Composite, mixed-direction, partial and expression indexes.** `#[index]`
   documents "creates a non-unique index on the field". Cost: raw DDL at open,
   invisible to toasty's schema, guarded by every `Database::open` and
   `in_memory` call in the suite executing the DDL.
3. **Per-connection settings.** The driver owns connection creation.
4. **Connection access.** `Db::driver() -> &dyn Driver` exposes no turso
   connection, so `register_external_scalar_function`, `set_query_timeout` and
   `interrupt` are out of reach from the app's side. Raw SQL is not:
   `toasty::sql::query/statement` is the supported channel and is what every site
   in §3 uses. The `prepare_cached` control and
   `experimental_mvcc_passive_checkpoint` used to be on this list and no longer
   are, because the crate owns its driver: `crates/leas-db/src/driver/` routes
   `Operation::RawSql` through the UNCACHED `prepare` and `Insert`/`QuerySql`
   through `prepare_cached` (ADR 0012), and `file_driver` enables the MVCC
   passive-checkpoint flag. The `Database::direct` raw connection stays for the
   page's execution-layer bypass, a read win unrelated to the cache.
5. **Schema management.** `push_schema` still emits `CREATE TABLE` with no
   `IF NOT EXISTS`, but it is no longer guarded by a wipe tag: `crate::schema` is
   the migration runner (ADR 0012). `PRAGMA user_version` is a cursor seeded at
   `SCHEMA_VERSION` (19); a current file is a no-op, a fresh file applies the
   seed, a supported older version applies the pending steps, and a cursor that
   names a pre-migration or foreign schema is `IncompatibleSchema`, which `open`
   answers with the pre-alpha wipe. A cursor of 0 over foreign tables is also
   `IncompatibleSchema(0)`: `push_schema` fails on a table it did not create, and
   that failure is reported as the named verdict. Hand-written DDL lives in
   `schema/ddl.rs`, not scattered through `ensure*` functions.
6. **No STRICT tables, generated columns or materialized views.** See §5.
7. **No caller-supplied driver.** `Database::open` builds `Turso::file(path)`
   internally, so an experiment with a driver flag (`.concurrent_writes()`, any
   `experimental_*`) cannot reuse `open`: a probe has to rebuild the driver and
   the `toasty::models!(...)` list itself. A `#[cfg(test)]` or example hook taking
   a driver would remove that duplication. Still true after the driver fork: the
   fork changed who owns the driver, not `open`'s signature.

## 5. Rejected manual paths (so they are not re-proposed)

| Proposal | Verdict | Why |
| --- | --- | --- |
| Enable MVCC **as the default** (`Turso::concurrent_writes()`) | rejected | The original reasons were a measured reader tax (p50 56.5 to 85.9 µs, p95 66.8 to 97.0 µs) and a checkpoint gap (`PRAGMA wal_checkpoint(PASSIVE)` failed with "PASSIVE checkpoint requires experimental_mvcc_passive_checkpoint"). The checkpoint half is fixed, though the original mechanism recorded here was wrong: MVCC already auto-checkpoints on the commit path at a ~4.12 MB logical-log threshold, so the log was never unbounded. `file_driver` setting that flag changes the auto-checkpoint's mode from blocking `Truncate` to `Passive` and lets `ping.rs`'s batch-end checkpoint run under MVCC at all. What keeps MVCC an opt-in (ADR 0012 D-D) is the reader tax and the remaining costs recorded there. |
| Hand-create tables as STRICT | rejected (for now) | STRICT gives **no storage and no speed change** (4,000 rows: 83 pages and 339,968 bytes in both schemas; a full-surface scan 2.72 ms heap against 2.76 ms STRICT), and its only unlocks are validation and custom types. Its type vocabulary is flag-dependent: without the custom-types flag, `BIGINT` and `BOOLEAN` are `Parse error: unknown datatype` in a STRICT table (those are what toasty's DDL emits), and they become legal only with `experimental_custom_types(true)`. Adopting STRICT means hand-owning the entire schema DDL and turning on an experimental engine flag, for validation alone. Typed toasty access on a hand-created STRICT table does work (create and read verified). Revisit only if type validation becomes a requirement. |
| Custom types (`CREATE TYPE ... BASE blob OPERATOR '<'`) for the address column | rejected | Reachable only with `experimental_custom_types(true)`; the packed BLOB column already orders and indexes correctly (byte order is address order) and needs no experimental flag. The operator buys expressiveness, not speed, and would duplicate an existing fact. |
| Split `endpoint_ip.ip_key` into `(family, addr)` | rejected | Requires the experimental custom-types flag for `array_agg`, which the driver then returns as TEXT (`String("{\"X'040A0001'\",...}")`, not `Value::List` of blobs), so the cheap decode is unreachable. The split is not cheaper: `group_concat(hex(addr))` 806 µs against the shipped 724 µs per 200-row page. It also makes `PageSort::Ip` worse: the correct `(family, addr)` term needs two correlated subqueries, 16.49 ms against 9.97 ms packed, and the single-subquery variant cannot produce a pair. |
| One-blob wire via `unhex(string_agg(hex(x), ''))` (`test_array_agg_result_deserialize_to_ips`) | rejected: **correct but not faster** | Not gated (`string_agg`, `hex`, `unhex` and `FILTER` all work with the custom-types flag off), and its decoded output is identical to the shipped carrier (277 == 277 addresses on a resolved page). It is the same cost within noise (statement 747 to 836 µs shipped against 758 to 776 µs one-blob; decode 4.7 µs against 4.6 to 7.4 µs), while the shipped text parse it would remove costs 8 to 14 µs per page, at most 0.4 %. It would not fix the mixed-family trap below. If it is ever wanted, the decoder must walk the packed key (family byte, then 4 or 16 octets), never slice a fixed width. |
| Slicing one concatenated blob by a fixed address width | rejected: **incorrect** | On a `(endpoint_id, family, addr)` table, the `chunks::<4>()` decode returned 367 addresses where the packed key holds 277: one width cannot describe a mixed IPv4/IPv6 set, so the decoder silently invents addresses. Two `FILTER`ed aggregates, one per family, would be required, which is more engine work than the comma list. |
| `ANALYZE`, `likely()`/`unlikely()`, `wal_autocheckpoint`, `max_wal_size`, `mmap_size`, `cache_size` tuning | rejected | Measured neutral or non-existent; unknown PRAGMAs are silently ignored, so the tuning would be invisible rather than effective (details in the verification spec §2). |

## 6. Adding a manual path: checklist

1. Name the cause from §2. If none applies, use the typed API.
2. Prefer inlined integer literals for ids and keys produced by this database;
   use `sql_lit` for text.
3. Keep the write inside the transaction that owns the fact, and never write a
   column group another owner writes.
4. Make it idempotent if it runs at open (`IF NOT EXISTS`, `INSERT OR REPLACE`).
   If it cannot be idempotent, put it in `schema/steps.rs` so the cursor gates
   it, and never in `ensure_raw_ddl`.
5. **Make a test actually run the new statement.** No guard is automatic: the
   statement-versus-schema test covers only `profiles_query.rs`. A link-writer
   statement needs an `apply_link_patches_*` test (or a new one) that executes it
   against the pushed schema; an `endpoint_rank` or `endpoint_ip` statement needs
   a test on the path that calls it.
6. Record the measurement in §3 or in the relevant ADR, with its date. A raw
   statement without a number is a guess, and the next reader will "simplify" it.

## 7. Re-verify a blocker against the vendored source before relabelling it

The causes in §2 are pinned to a toasty version, and a version bump can retire
one silently. Nothing detects that: the blocker is prose, so a `0.10` to `0.11`
find-replace looks like a correction while asserting every absence still holds.

This happened on 2026-10-01. Blindly relabelling 0.10 to 0.11 would have kept
C1's "no multi-row `insert().values([...])`" as fact, when
`toasty-0.11.0/src/stmt/create_many.rs` provides exactly that (`CreateMany`,
announced at `lib.rs:124`). Re-reading the source showed C1 was half retired: the
multi-row insert exists, the conflict clause does not
(`grep -rl "on_conflict\|OnConflict" .../toasty-0.11.0/src/stmt` returns
nothing). C1 was requalified to name the capability actually missing.

1. Cite the vendored path with its version (`toasty-0.11.0/src/...`), never a
   bare version number. A stale path is worse than a stale number because it
   reads like a citation that was checked.
2. Before changing a blocker, grep the vendored source for the missing symbol
   and read what is there. A capability that appeared is a retirement trigger,
   not a retirement: record that the trigger fired and what now carries the site,
   then treat the migration as its own task with its own measurement. A
   requalified blocker is a documentation change; rewriting the SQL that depends
   on it is a code change, and it does not ride along on a doc edit.
3. Distinguish "renamed" from "re-verified" in the text, and claim only what was
   checked. C1 and C2 were re-verified against `toasty-0.11.0` on 2026-10-01; C3
   to C7 have not been and carry no such marker. C8 to C10 are design causes,
   so a toasty bump does not invalidate them. C4 and C6 were spot-confirmed
   incidentally while checking C1 (`Load::Output` for `List<M>` is still
   `Vec<M::Output>`), but their prose is otherwise unverified against 0.11, so a
   future bump must re-check them rather than trust the absence of a date.

## 8. Retired sites

| Retired site | Retired on | Replaced by, or why not to revive it |
| --- | --- | --- |
| `sql_exec.rs` `SqlConn`/`RawConn`, `CacheSpec::RAW`, `Database::write_conn`, `write_window_raw`, `refresh_raw`, the manual `BEGIN`/`COMMIT` around them | 2026-10-08 | The driver fork's uncached `RawSql` route (`driver/mod.rs`). The SQL text is unchanged; only the executor routing is. Reintroducing a second connection would re-create the transaction split the fork removed. |
| `Database::direct` used as the statement-cache escape hatch | 2026-10-08 | The connection stays, but only as the page's execution-layer bypass (a read win). The leak it used to dodge is fixed at the driver boundary; do not route new bulk SQL through it for cache reasons. |
| `endpoint_rank_key` (v1 column list without `rank_stab`) | 2026-10-09 | `endpoint_rank_key_v2`, with `rank_stab` in the order and `rank_proven` trailing. The old index is dropped by `ENDPOINT_RANK_KEY_DROP`. |
| The DDL inside `endpoint_rank.rs::ensure_in` | 2026-10-08 | `schema/ddl.rs`, run by the migration runner before `ensure_in`. `ensure_in` now owns DATA only. |
| The per-address country writer inside `set_endpoint_ip_countries` (one transaction per address, then one `endpoint_ip::set_country` per row) | 2026-10-02 | First replaced by the write-behind driver, which commits once per drain instead of once per address; the per-row statement inside it is now `endpoint_ip::set_countries_bulk`, one multi-row upsert per 400 rows. The measurements in §3 are the evidence for batching, not a reason to return. |
| `profiles_walk_page` as a production path | 2026-10-01 | The batch walk freezes its id set up front (`PlanWalk::next_page`). The method stays as the streaming baseline for `ops/ping/flow_cost.rs`; do not add a UI caller. |
| Separate statements for `endpoint_ip` import (delete then insert per endpoint) | db-rewamp D10 | `endpoint_ip::insert_literals_bulk`, with `DO NOTHING` so a stored country survives a re-import. |
