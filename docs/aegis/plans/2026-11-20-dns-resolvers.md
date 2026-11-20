# 2026-11-20 — DNS resolvers: sources, latency test, top-N pool

Status: `implemented 2026-11-20` — gate green: fmt, workspace clippy `-D warnings`, 2 905 tests passed / 12 skipped, live DoH + DNSCrypt lookups
(`specs/2026-11-20-dns-resolvers-design.md`; grilling answers top-N / manual
re-test / top-N only / no quota / `www.google.com`; uniqueness by exact stamp).
Owners: `leas-dns` (parse, fetch, measure, live swap), `leas-db` (tables,
migration 23, queries), `leas` (ops, job, state, UI).
TDD route: `auto` → **strict** (schema migration, persistence, pool contract,
resolver swap); UI render checks are light.

## Baseline

- `crates/leas-dns/src/lib.rs` — one hard-coded URL, one file cache, `ResolverList`,
  `DnsResolver` with `OnceCell`; consumers `ops/enrich.rs:609`,
  `leas-route/src/dns_adapter.rs`.
- `crates/leas-db/src/schema/{steps.rs,ddl.rs,mod.rs}` — cursor 22, steps own
  DDL; `push_schema` runs only on a fresh file (`database.rs:374`).
- `crates/leas/src/types.rs:170` `Pane1Tab`; `ui/mod.rs:1580` dispatch, `:1916`
  tab bar; `ui/sources.rs` group table + `AppMode::GroupForm`;
  `ops/job_scheduler.rs` `TaskKind`; `ui/tasks.rs:133` `batch_progress` meters.

## Tasks

### T1 — `leas-dns` surface (strict)

- `Candidate { stamp, protocol, host, port, kind }`; `Kind::Hickory(NameServerConfig)`
  | `Kind::DnsCrypt(DnsCryptServer)`.
- `parse_stamps(&str) -> Vec<Candidate>`: existing policy gate, dedupe by stamp.
- `fetch_source(url) -> anyhow::Result<String>` (10 s, 8 MiB cap).
- `measure(&[Candidate], domain, timeout, concurrency) -> Vec<TestOutcome>`.
- `DnsResolver { ArcSwapOption<Resolver<..>>, OnceLock<system> }` with
  `new()`, `set_candidates(&[Candidate])`, `lookup_ip`.
- Delete: `ResolverList`, `parse_dnscrypt_lines`, cache read/write/download/
  `get_dns_servers*`, `DNSCRYPT_*` constants; keep `STAMP_IPV4` fixtures.
- Add `arc-swap` (direct, single crate); `cargo hakari generate`.
- RED: `parse_stamps_dedupes_and_applies_policy`, `measure_times_out_a_stalled_server`,
  `set_candidates_swaps_the_pool`; then GREEN. Live rows updated to the new API.

### T2 — DB (strict)

- Models `DnsSource`, `DnsResolver`, `DnsSourceResolver`; `DnsSetting` gains
  `resolver_pool_size`, `resolver_test_domain`.
- `SCHEMA_VERSION` 23; `V23_DNS_SOURCES` statements in `ddl.rs`; step 23.
- `Database`: `seed_dns_source_if_empty`, `list/upsert/delete_dns_source`,
  `refresh_source_links(&self, source_id, &[(stamp, proto, host, port, skipped)])`,
  `list_dns_resolvers`, `set_dns_resolver_enabled`, `dns_pool(limit)`,
  `apply_dns_test_results(&[TestOutcome])`.
- RED: `a_v22_cursor_gets_the_dns_step`, `one_stamp_in_two_sources_is_one_row`,
  `refresh_preserves_a_measurement`, `duplicate_source_url_is_refused`,
  `dns_pool_orders_by_latency_and_limits`, `deleting_a_source_keeps_a_shared_resolver`.

### T3 — app ops + job (strict for the pool contract)

- `ops/dns.rs`: `ensure_sources`, `refresh_source(s)`, `run_test`, `rebuild`
  (pool → `set_candidates`), `boot` (seed + stale refresh in background).
- `state.rs`: `DnsResolver::new()`, `dns_sources`, `dns_resolvers` session rows;
  call `dns::boot` after settings load; `ops/settings.rs` saves the two fields
  then rebuilds.
- `job_scheduler`: `TaskKind::DnsTest`, dispatch → `dns::run_test`, empty-scope arm.
- RED: `dns_test_is_one_queued_job`; `settings_save_rebuilds_the_pool` (or a
  focused ops test).

### T4 — UI (light)

- `Pane1Tab::Dns` (ALL/next/prev/tab bar/dispatch); `ui/dns.rs` table + keys
  (`t` test, `Space` toggle, `s` re-apply, `g/G`).
- Sources `Kind` column, `a` kind picker, `AppMode::GroupForm` gains
  `kind: SourceKind`; DNS form labels; hints.
- Render test: tab order and the empty-state hint.

### T5 — docs + gate

- `docs/architecture/architecture.md` (pool owner), `decisions.md` #18
  amendment, `docs/reference/database.md` (tables + indexes), glossary,
  `tui-manual.md`.
- `cargo fmt --check`, workspace clippy `-D warnings`, `cargo nextest run`,
  `cargo hakari generate --diff` empty.

## Verification

Focused: `cargo nextest run -p leas-dns`, `-p leas-db`, `-p leas`.
Full: `cargo nextest run`. Live: test the built-in list, apply the pool,
resolve `www.google.com`.

## Risks

One probe is noisy (second probe deferred); a DNSCrypt-only top-N breaks under
transport-specific DPI (protocol column + `Space`); a poisoned test domain
fails every resolver (setting is the escape).

## Execution notes (2026-11-20)

- **T1** landed as designed. `DnsResolver` holds an `ArcSwapOption` plus a
  `OnceLock` for the OS fallback; `measure` chunks with `join_all` rather than
  a `buffered` stream — the stream adapter made the future non-uniform across
  lifetimes and the spawned task saw "FnOnce is not general enough".
- **T1** also added `DnsResolver::is_configured` (the UI's empty state) and
  `candidate_from_stamp` public (the app rebuilds from stored stamps).
- **T2** landed with one corrected draft assumption: a test fixture (and a
  half-applied open) can carry the new tables while still stamped older, so the
  step's `CREATE TABLE`s are `IF NOT EXISTS`, and the two `dns_settings` columns
  moved into `ddl::V23_DNS_ADD_COLUMNS` under `ensure_raw_ddl`'s
  duplicate-column tolerance (the `STAB_ADD_COLUMNS` rule). The three indexes
  stay in `ddl::V23_DNS_INDEXES` because `push_schema` does not emit a composite
  or non-key unique index; `apply_steps` now also calls `ensure_raw_ddl` so both
  provenance paths converge.
- **T2** added `dns_resolvers` tests (`tests/dns_resolvers.rs`) and a SQL
  artifact test (`tests/migration_v23.rs`).
- **T3** landed: `ops::dns` owns seed/reload/rebuild/refresh/test; `TaskKind::DnsTest`
  and `TerminalEvent::DnsTestDone`; progress reuses `BatchMeters.main`.
- **T4** landed with two simplifications: `a` adds a subscription and `A` adds a
  DNS source (no modal picker), and the DNS tab drops the per-row Sources
  column (the link table is a uniqueness device; showing it would add a query).
- **T5**: architecture, decisions #18, database, glossary, tui-manual and the
  crate README updated.
