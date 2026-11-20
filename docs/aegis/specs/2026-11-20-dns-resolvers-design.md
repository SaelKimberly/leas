# Design: DNS resolvers — user sources, latency test, top-N pool

**Status**: implemented 2026-11-20 (plan `2026-11-20-dns-resolvers.md`); gate
green. Grilling answered the five policy questions (top-N, manual re-test,
top-N only, no transport quota, `www.google.com` default).

## Goal

Make the resolver set the user's, not a hard-coded download: many `sdns://`
sources, a measured latency per resolver against one stable name, and a pool of
the N fastest that the existing hickory resolver actually uses. Add a pane-1
`DNS` tab (between `Profiles` and `Sources`) that shows the resolvers and their
measurements, and give the `Sources` tab a second kind for DNS sources.

## Grounding — what exists today

| Fact | Site |
|---|---|
| One hard-coded source (`public-resolvers.md`), one file cache, 7-day age | `crates/leas-dns/src/lib.rs:20-24`, `:180-300` |
| Every parsed stamp becomes a name server; `RoundRobin`, 500 ms/attempt | `lib.rs:28-33`, `:340-370` |
| Resolver built once per process (`OnceCell`), no rebuild | `lib.rs:324-327` |
| Lookups: profile-host enrich (5 s queue + 8 s lookup) and the routing engine | `ops/enrich.rs:51-75`, `:609`; `leas-route/src/dns_adapter.rs` |
| Policy: `NO_LOGS\|NO_FILTER`, IPv4 transport, no private/loopback, no plain DNS | `lib.rs:60-160`; `dnscrypt.rs:87-92` |
| Sources tab = proxy subscription `groups` only | `ui/sources.rs`; `types.rs:170` |
| Job queue: one task at a time, `TaskKind`, progress via `batch_progress` | `ops/job_scheduler.rs`; `ui/tasks.rs:133` |
| Schema cursor 22; migrations are `Step`s; `push_schema` only on a fresh file | `schema/mod.rs`, `schema/steps.rs`, `database.rs:374-395` |

A dead resolver in today's pool costs up to 500 ms per rotation step, and the
user cannot see or exclude it. That is the defect this design removes.

## Decisions

- **D1 — A candidate is one stamp.** `leas-dns` gains
  `Candidate { stamp: String, protocol, host, port, kind }`, where `kind` is
  either a hickory `NameServerConfig` (DoH/DoT/DoQ) or a `DnsCryptServer`.
  `parse_stamps(text) -> Vec<Candidate>` replaces `parse_dnscrypt_lines`;
  dedupe is by the exact stamp string (two stamps for one endpoint differ by
  key/path and are distinct resolvers). The existing policy gate is unchanged
  and applies to every candidate: a plain, anonymized-relay, private-address or
  non-`NO_LOGS|NO_FILTER` stamp is dropped and counted as skipped.
- **D2 — The DB is the only persisted resolver truth.** The single-file cache
  (`dsncrypt.resolvers.txt`, 7-day rule) is deleted. `leas-dns` keeps the HTTP
  client and exposes `fetch_source(url) -> String` (10 s, 8 MiB cap); `leas`
  owns refresh, persistence and policy. `DnsResolver` no longer downloads: it
  starts empty and the app installs candidates.
- **D3 — Sources are rows, unique by URL.** New `dns_sources` table; the
  built-in URL becomes a seeded row (`builtin:public-resolvers`, enabled)
  inserted by `ops::dns::ensure_sources` when the table is empty — the
  routing-preset seed pattern, not a migration (a fresh file never runs steps).
  `url` is `NOT NULL UNIQUE` after canonicalisation (`url::Url::to_string()`:
  scheme/host case and default ports collapse), so the same list cannot be added
  twice under two names; the form refuses the second add and names the owner.
- **D4 — A resolver is unique by stamp; sources link to it.** `dns_resolvers`
  is keyed by the exact stamp (the wire identity: key + address + path), so a
  stamp listed by three sources is one row, tested once and stored once.
  Ownership is a separate `dns_source_resolvers(source_id, stamp)` table:
  a refresh inserts links (`OR IGNORE`), deletes the links it no longer lists,
  and then deletes only resolvers with no remaining link. Consequences:
  - `INSERT … ON CONFLICT(stamp) DO NOTHING` — a refresh never rewrites
    `latency_ms`, `status`, `checked_at` or `enabled`, so **re-import does not
    erase a test result and does not force a retest**.
  - Removing one source keeps a resolver another source still lists, and
    deleting the last link removes the row.
  - `parse_stamps` dedupes within one text as well, so one run never measures
    the same stamp twice.
  - A stamp whose parsed protocol/host/port disagrees with the stored row (a
    parser policy change) updates those three columns only — the measurement
    stands until the next test.
- **D5 — Selection is a query, not a stored rank.**
  `db.dns_pool(limit)`: `enabled AND status='ok' AND latency_ms IS NOT NULL
  ORDER BY latency_ms, stamp LIMIT pool_size`. `pool_size` (default 10) and
  `test_domain` (default `www.google.com`) live in `dns_settings` beside
  `cache_ttl_secs`.
- **D6 — Manual re-test only.** No test at boot. A source refresh at boot runs
  only when a source has no rows or its rows are older than 7 days (today's
  cache rule), in the background; the tab renders result age and marks >24 h as
  stale.
- **D7 — Top-N only.** No standby set, no full-list tail. When the pool is
  exhausted the lookup fails as today. (Q3 answer.)
- **D8 — Pure latency ranking.** No per-transport quota: the fastest wins even
  if all ten are DNSCrypt. The tab shows the protocol so the user can exclude a
  transport by disabling rows. (Q4 answer.)
- **D9 — Measurement is one probe per candidate.** `leas-dns::measure` builds a
  one-server resolver per candidate and times a `lookup_ip` of `test_domain`:
  single attempt, 2 s timeout, 32 in flight. Latency = wall time to a non-empty
  answer; a failure stores `status='error'` + the error class, latency NULL.
  DNSCrypt's certificate fetch is inside the measured time — the cold cost is
  what the user's first lookup pays.
- **D10 — The test is a job.** `TaskKind::DnsTest`, enqueued by the `DNS` tab's
  `t`, run by `ops::dns::run_test` through `job_scheduler` (one at a time,
  cancellable by the existing stop flag). Progress uses the existing
  `batch_progress` slot (`main.done/total/rate_milli`); the Tasks pane is
  unchanged.
- **D11 — The resolver is rebuilt live, through `ArcSwapOption`.** `DnsResolver`
  replaces `OnceCell<Resolver>` with
  `arc_swap::ArcSwapOption<Resolver<DnsCryptProvider>>`; `set_candidates(&[Candidate])`
  builds the resolver and `store`s it (sync — `Resolver::build` does no I/O).
  `lookup_ip` calls `load_full()` — one atomic load, an `Arc` handed back with no
  guard lifetime to respect, so an in-flight lookup finishes on the old pool and
  every holder (including `DnsSinkAdapter`'s `Arc<DnsResolver>`) sees the new one
  with no adapter change. Chosen over `RwLock` because the read side is the
  lookup path and the write side is rare: no lock, no await-under-lock rule to
  remember, no poisoning. `arc-swap` 1.9.5 is already in `Cargo.lock`
  (transitive); it becomes a direct `leas-dns` dependency, single-crate, so no
  workspace entry. Rebuild after: test completion, source refresh/delete,
  `Space` toggle, settings save. No `ok` rows → all enabled rows (today's
  behaviour); none at all → `system_conf`, held in a separate `OnceLock` so the
  read path never writes.
- **D12 — Sources tab gains a kind.** `dns_sources` rows render beside `groups`
  with a `Kind` column (`proxy`/`dns`). **Implemented as two keys, not a
  modal picker** (execution note 2026-11-20): `a` adds a subscription, `A` adds
  a DNS source — the picker would have been a third overlay for one bit. The
  DNS form reuses `AppMode::GroupForm` with a `kind` field (name, URL, user
  agent, interval), so one renderer serves both. `e`/`d`/`u` dispatch by kind;
  the tab keeps one selection over the union.
- **D13 — DNS tab.** `Pane1Tab::Dns` between `Profiles` and `Sources`, label
  `DNS`. Columns: Protocol, Endpoint, Latency, Status, Checked. (The draft's
  Sources column is dropped in execution: the link table is a uniqueness
  device, and a per-row source name would add a third query to every reload
  for a fact the Sources tab already shows.) Keys:
  `t` test all, `Space` enable/disable, `s` re-apply the pool, `↑↓`/`g`/`G` as
  every table. Empty state names the next action (`u` in Sources refreshes a
  source; `t` tests).
- **D14 — Schema 22 → 23.** One `Step` (`V23_DNS_SOURCES`) creates the three
  tables with `IF NOT EXISTS` (a fixture or a half-applied open may already
  carry them); the two `dns_settings` columns and the indexes are idempotent raw
  DDL in `ensure_raw_ddl` (`V23_DNS_ADD_COLUMNS` with the duplicate-column
  tolerance, `V23_DNS_INDEXES`), and `migrate` runs `ensure_raw_ddl` after a
  migration as well as on a current/fresh file. `push_schema` creates the tables
  on a fresh file from the toasty models. No data rewrite.

## Data model

```sql
CREATE TABLE dns_sources (
  "id" TEXT PRIMARY KEY, "name" TEXT, "url" TEXT NOT NULL,
  "enabled" BOOLEAN NOT NULL, "user_agent" TEXT, "sort_order" INTEGER,
  "last_refreshed" INTEGER, "status" TEXT, "error_message" TEXT,
  "refresh_interval" INTEGER
);
CREATE UNIQUE INDEX dns_sources_url ON dns_sources ("url");
CREATE TABLE dns_resolvers (
  "stamp" TEXT PRIMARY KEY,
  "protocol" TEXT NOT NULL, "host" TEXT NOT NULL, "port" INTEGER NOT NULL,
  "latency_ms" INTEGER, "status" TEXT NOT NULL, "error" TEXT,
  "checked_at" INTEGER, "enabled" BOOLEAN NOT NULL
);
CREATE INDEX dns_resolvers_pool ON dns_resolvers ("enabled", "status", "latency_ms");
CREATE TABLE dns_source_resolvers (
  "source_id" TEXT NOT NULL, "stamp" TEXT NOT NULL,
  PRIMARY KEY ("source_id", "stamp")
);
CREATE INDEX dns_source_resolvers_stamp ON dns_source_resolvers ("stamp");
ALTER TABLE dns_settings ADD COLUMN "resolver_pool_size" INTEGER;
ALTER TABLE dns_settings ADD COLUMN "resolver_test_domain" TEXT;
```

The two uniqueness rules are structural, not app-side: `dns_sources.url` is
`UNIQUE`, and a resolver exists once per stamp. The link table carries no
measurement, so deleting and re-adding a source never touches a test result.

`status` reuses the group status values (`ok`/`error`/`never`) plus
`unchecked` for a freshly listed resolver.

## Flows

1. **Boot.** Construct `DnsResolver` (empty) → `ensure_sources` seeds the
   built-in row when the table is empty → background refresh for sources with no
   rows or >7 days old → `set_candidates(pool or all enabled)`.
2. **Refresh a source.** `fetch_source` → `parse_stamps` (deduped) → one
   transaction: `INSERT … ON CONFLICT(stamp) DO NOTHING` per candidate,
   `INSERT OR IGNORE` its links, delete this source's links that vanished,
   delete resolvers with no link left, stamp `last_refreshed`/`status` (`error`
   + message on failure, links and rows kept) → rebuild. Measurement columns are
   never written here, so a refresh costs no retest.
3. **Test.** Snapshot the candidate rows → `measure` → chunked upserts
   (32 outcomes per write) → rebuild → log the count of `ok`/`error`/skipped.
4. **Lookup.** Read the pool from the DB at rebuild time only; the hot path is
   unchanged (`RwLock` read, Arc clone, `lookup_ip`).

## Failure modes

| Case | Behaviour |
|---|---|
| Source URL unreachable | Source `status=error`, existing rows kept, no rebuild |
| Source URL already present (canonical) | Add/edit refused; the owning source is named |
| Stamp already listed by another source | One row, one test; the refresh adds a link only |
| Refresh of an unchanged source | No measurement column written; no retest needed |
| Last link to a resolver removed | Row deleted; an in-flight test result for it is dropped |
| A candidate times out | `status=error`, `error` = class, latency NULL; listed last |
| Every candidate fails | Pool empty → all enabled rows; lookups fail as today; tab says so |
| Test cancelled | Partial results persisted; the pool rebuilds from what landed |
| Stamp no longer parses after a policy change | Skipped at rebuild with a log line; row stays visible |
| DB busy during the test | Chunked upserts retry via the existing busy path |

## Non-goals

Anonymized DNSCrypt relays (`0x81`), ODoH, plain-DNS stamps, per-domain DNS
policy, a local DNS server for other devices, auto-test at boot, historical
latency charts, DNSveil's safe-search/blocked-content scanning.

## Delivery slices

1. **S1 — `leas-dns` surface**: `Candidate`, `parse_stamps`, `fetch_source`,
   `measure`, `set_candidates`; delete the file cache and `get_dns_servers`;
   unit tests for parse/dedupe/policy/measure.
2. **S2 — DB**: models, v23 step, `dns_pool`/`refresh_source_links`/
   `apply_dns_test_results`/`list_dns_resolvers`/`set_dns_resolver_enabled`,
   migration + query tests.
3. **S3 — app ops + job**: `ops::dns` (seed, refresh, run_test), `TaskKind::DnsTest`
   dispatch, rebuild wiring in `state.rs` and `ops/settings.rs`.
4. **S4 — UI**: `Pane1Tab::Dns` + render/keys, Sources `Kind` column + picker +
   DNS form, hints; render tests.
5. **S5 — docs + gate**: architecture, decisions #18 amendment, database,
   glossary, `tui-manual`; fmt/clippy/nextest.

## Acceptance

- A1 Fresh DB seeds `builtin:public-resolvers`; before any test the resolver
  behaves as today (all enabled candidates).
- A2 Adding a second source lists its resolvers; a stamp in both is one row,
  tested once, and survives deleting either source. Adding the same URL twice
  (including a case/trailing-slash variant) is refused.
- A2b Refreshing a source that did not change writes no measurement column:
  latency, status, checked time and `enabled` are byte-identical before and
  after.
- A3 `t` enqueues exactly one `DnsTest`; the Tasks bar shows `done/total`; stop
  cancels; results persist with latency and checked time.
- A4 After a test, the pool is the top-N enabled+ok by latency; `s` swaps the
  resolver without a restart, and a lookup reaches only pool members (hermetic:
  two candidates, one fake server, assert which receives the query).
- A5 `Space` disables a resolver and it leaves the pool on rebuild.
- A6 A source carrying a private-address, plain or non-policy stamp contributes
  zero candidates and reports the skipped count.
- A7 A v22 DB opens at 23 with both tables and both columns; a v22 DB with no
  DNS rows behaves as today.
- A8 Workspace clippy `-D warnings`, fmt, and the full suite green.

## Verification

Unit: parse/dedupe/policy, pool selection order and limit, `set_candidates`
swap, measure timeout classification, source-kind dispatch, tab render.
Live: test the built-in list, inspect the tab, resolve `www.google.com` through
the selected pool. Migration: open a v22 fixture and assert the cursor.

## Risks

- **One probe is noisy.** A cold-connect outlier can keep a good resolver out of
  the top ten. Mitigation deferred: a second probe with the minimum, if the live
  run shows it matters.
- **Cross-transport bias** (D8, accepted): a DNSCrypt-only pool breaks if DPI
  starts blocking DNSCrypt. The protocol column and `Space` are the escape.
- **Stale pools** (D6, accepted): age is visible, never auto-fixed.
- **Test domain**: `www.google.com` may be poisoned on some paths, which marks
  every resolver failed — the setting is the escape, and the empty state names
  it.
