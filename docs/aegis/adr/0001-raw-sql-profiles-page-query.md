# ADR 0001 — Raw SQL for the Profiles page query

Date: 2026-09-11
Status: accepted — amended 2026-09-14 (the projection, and ids as literals; see the amendment at the end)
Supersedes: nothing (amends `AGENTS.md` decision 4's "zero raw SQL" rule)
Spec: `docs/aegis/specs/2026-09-11-profiles-page-query-design.md`

## Context

The Profiles tab loaded every row of the typed schema (7,672 endpoints, 9,048
links, 6,111 protocols on the reference feed) with three full-table scans and an
in-memory join, then filtered, sorted, counted, and paginated in Rust. Measured
costs: 33 ms of SQL, ~23k model structs materialized per reload, a ~150 ms
display rebuild per frame, and ~160 ms per keypress (the display-row cache keyed
on the selection).

Making the tab a page required ordering and aggregation the typed API cannot
express: toasty 0.10 has `count()` only — no `GROUP BY`, `MIN`/`MAX`, or
`HAVING` (upstream issue #421, open). The tab's ordering is also not a column
comparison: it is a tier/latency/recency tuple over each endpoint's links, plus
per-endpoint display-link selection.

## Decision

Add ONE bounded raw-SQL owner, `crates/xray-tui-db/src/profiles_query.rs`, and
make the tab a SQL page.

- The page query uses a `ROW_NUMBER() OVER (PARTITION BY endpoint_id ORDER BY
  …)` window to pick each endpoint's representative link, a `CASE` expression
  as the decision-16 weight, `EXISTS` predicates for the view/search/group
  filters, and `LIMIT`/`OFFSET`.
- Rules for the module: parameterised `?N` binds only (no interpolated user
  text), read-only, decodes only ids and ordering keys (model hydration stays on
  the typed `load_page_rows` path), and every statement is executed against a
  pushed schema by a drift test.
- The ordering is expressed once (`WEIGHT_TEMPLATE`) and pinned against the Rust
  oracle for all 7 sorts × both directions.
- Paging is `LIMIT`/`OFFSET`, measured flat (8.3–9.3 ms at offsets 0 → 7,472).

## Alternatives rejected

1. **Stored `dynamic_weight` column + endpoint rollups.** The weight is a pure
   function of existing columns, so storing it adds a second owner of the
   ordering law that every mutator must maintain (`clear_expired_errors` already
   bypasses `upsert_link`), plus a schema bump — which is a data wipe, since the
   tag scheme has no migrations (decision 4).
2. **Keyset cursors.** They cannot avoid the sort without an index on a stored
   endpoint weight, i.e. alternative 1. Named escalation if per-page cost ever
   outgrows the measured numbers.
3. **Wait for toasty #421 and keep the in-memory load.** Leaves the freeze.
4. **Link-centric (star) rows for the tab.** Removes the rollup problem but
   discards the endpoint row model (decision 14) that groups one server's
   protocols.

## Consequences

- Positive: page-bounded memory and per-frame work (~1 ms rebuild for 200 rows,
  13.5 ms per selection move), SQL-side ordering/filtering/counting, and the
  whole-feed read paths retired (`load_tab_rows`, `get_active_endpoints*`,
  `get_stale_*`).
- Negative: the schema's column names now appear in two places (the models and
  this module). Mitigated by the drift test and by keeping the module read-only
  and id-only.
- Behaviour change: `SortColumn::Core` left the sort cycle (it resolves through
  runtime `protocol_core_overrides`), and the display-link sorts now use the
  spec's rule (manual override → best measured link → column sentinel) rather
  than `active_link()`'s untested-link fallback, pinned by the parity test.
- Compatibility: no schema or data-format change; existing databases open
  unchanged (the pragma work added `synchronous=NORMAL`, which is a durability
  trade, not a format change).

## Retirement trigger

Delete `profiles_query.rs` and express the page query with the typed API once
toasty #421 (or an equivalent) provides aggregation and window functions. The
module's API (`PageRequest`/`PageMeta`/`profiles_page`/`load_page_rows`) is
shaped so the TUI does not change when that happens.

## Amendment — 2026-09-14: the projection, and ids as literals

Two of the rules above no longer describe the module. Both changes come from the
DB↔TUI flow audit (`docs/aegis/specs/2026-09-14-db-tui-flow-audit.md`, H1) and
are in force:

1. **Hydration moved into this module** — `Database::load_page_projection`
   returns `Vec<EndpointRow>` from ONE statement (endpoints ⋈ links LEFT JOIN
   protocols), so "model hydration stays on the typed `load_page_rows` path" is
   no longer true. `load_page_rows` survives as the typed REFERENCE
   implementation that `tests/profiles_query.rs::page_projection_matches_the_orm_rows`
   pins the projection against; it has no production caller.
   The decoded set is bounded on purpose: the display columns only, with the
   three deferred JSON carriers (`transport_data`, `security_data`, `config`)
   left unloaded — no page consumer reads them, and decoding them was ~0.5 s of
   the typed path's cost. Reading one is a bug, not a fallback: the connect path
   re-reads its protocol through `load_protocol_with_config`.

2. **Ids are interpolated as integer literals, not bound** — turso charges
   ~0.8 ms per BOUND parameter, so binding a 200-id page (~600 parameters across
   the three hydration reads) cost ~480 ms of the 488 ms the typed path spent.
   The safety argument replaces the bind-only rule rather than weakening it: the
   interpolated values are `i64` from typed `EndpointId` newtypes, never text and
   never user input; every other predicate (thresholds, search, group) still
   binds. Measured 1,027 ms → 49.6 ms for the same 200 rows, 63 ms including the
   page's ids and count, on a 7,656-endpoint / 15,312-link feed.

Also retired in the same pass: `profile_link_order` / `order_links`. The SQL
link order disagreed with the decision-16 law for a DNS-unresolved endpoint (a
live measurement sorted above a fresh failure; the law sinks every link of such
an endpoint to tier 5), so the comparator is the single implementation again and
`load_page_rows` no longer re-orders links. `profiles_ids`,
`profiles_link_pairs`, `profiles_failed_ids`, `profiles_enrich_seed_ids` and the
public `profiles_count` wrapper were callerless and are gone; the page's total
comes back with the page.

## Amendment — 2026-10-22: the DNS band no longer sinks a measured link

The amendment above records that "the law sinks every link of such an endpoint
to tier 5". That is **no longer the law** (see ADR 0003's 2026-10-22
amendment): a MEASURED link keeps its measurement's band, because the probe
dials the DNS name and the OS resolves it without persisting the resolution.
A working server sorted below the failures; it does not any more.

The retirement of `profile_link_order`/`order_links` still stands — one
implementation of the link order, `RankLink::key` — and the guard
(`load_page_rows_preserves_page_and_link_order`) still pins the pair. Only
the tier-5 claim is corrected.
