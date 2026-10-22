# ADR 0003 — Materialized per-endpoint ordering keys

Date: 2026-09-14
Status: accepted — amended 2026-09-14 (seconds, one link order, one group set; see the amendment at the end)
Supersedes: ADR 0001 §paging (the SQL window core), decision 21 §paging
Spec: `docs/aegis/specs/2026-09-14-profiles-stored-sort-key-design.md`

## Context

The 2026-09-11 page query made the tab a SQL page but derived each endpoint's
position on every fetch: a `ROW_NUMBER() OVER (PARTITION BY endpoint_id ORDER
BY <weight>)` window over every link, plus correlated subqueries for the
display-link sorts, plus a second full evaluation of the same window for the
count. Measured on the reference feed (7,672 endpoints / 9,048 links):

| Query | Cost |
| --- | --- |
| page fetch (count + page) | 1757 ms |
| …of which the count | 860 ms |
| …of which the window core | ~800 ms |
| ordering the same rows by the same expression WITHOUT the window | 114 ms |
| `in_list` hydration (3 statements, 200 ids each) | ~450 ms |

Every page-boundary move in the TUI blocked the UI task for ~2.2 s. Two engine
facts drove the design: turso re-evaluates the whole window per page (there is
no index it could use), and it parses ~0.8 ms per bind parameter (200 ids =
174 ms; the same statement with inline literals = 9.7 ms).

## Decision

Store each endpoint's ordering keys in a side table and read the page through
an index.

- Table `endpoint_rank(endpoint_id PRIMARY KEY, rank_dns, rank_tier,
  rank_latency, rank_seen, rank_protocol, rank_display_seen, rank_speed,
  rank_traffic, rank_config, rank_newest_seen)` with two indexes: the Test
  order (the scroll path) and the view window.
- A first-class `toasty` model (`models_toasty::EndpointRank`, table
  `endpoint_rank`), so `push_schema` creates it with the rest of the schema.
  This project is pre-alpha, so the table arrived with **schema tag 8** — the
  tag bump WIPES the database (decision 4), which is the accepted way to add a
  table here; the keys rebuild from the re-imported feed. (The first cut
  created the table additively with raw DDL to avoid the wipe; the model is the
  better shape and the wipe was authorised.)
- Two statements stay raw, both performance-critical and inexpressible in the
  ORM: the covering index (`#[index]` is single-column and cannot express a
  composite whose last-but-one term is DESC) and the `refresh`/`repair_missing`
  reads of `endpoints`/`profile_stats`, which inline their integer ids because
  the engine charges ~0.8 ms per bound parameter. Rows are written with the
  typed `upsert_by_endpoint_id`; writes are per-row inside the caller's
  transaction, matching the existing `upsert_*_bulk` pattern.
- **The keys are computed in Rust**, by the same function that is the
  ordering law (`endpoint_rank::RankLink::key`, which
  `EndpointRow::link_test_key` now delegates to). SQL stores the numbers and
  reads them back; it never re-derives the law. One authority for the page
  order, the panel order, and the parity golden.
- The page source is the rank table; the view windows read
  `rank_newest_seen` ("some link is in the band" ⟺ "the newest link is"),
  which keeps the predicate off `profile_stats` — an `EXISTS` there forced the
  planner into a full sort.
- **Maintenance**: every write path that can change a link refreshes the
  endpoints it touched — `Database::upsert_link` (per-row),
  `upsert_links_bulk` (inside the caller's transaction),
  `apply_link_patches` (after commit), and the error-TTL sweep. A bypassed
  writer self-heals: `repair_missing` runs at open and via
  `Database::repair_endpoint_ranks`.

## Alternatives rejected

1. **Keep the window** — 800 ms per fetch is the price of re-deriving a value
   that changes only when a link changes.
2. **A stored, indexed column on `endpoints`** (the shape the spec first
   named): the tuple does not fit one integer (protocol ids are full-range
   hashes) and a `toasty` column needs `push_schema` → a tag bump → a wipe.
   A side table is additive.
3. **Keys computed in SQL** (the prototype's `INSERT … SELECT` over the
   window): puts a second implementation of the decision-16 law in SQL, where
   it can drift from the oracle the panel uses.
4. **Keyset cursors**: still need an index on a stored key — this, minus the
   ability to filter.
5. **In-memory ordered list**: reintroduces the per-frame rebuild T3 removed,
   and does not survive a restart.

## Consequences

- Page fetch: **1757 ms → 8.6 ms** for the default Test sort at any offset
  (`EXPLAIN` shows `SCAN endpoint_rank USING COVERING INDEX`).
  LastSeen/Speed/Traffic/ConfigType ≈ 39 ms (ordered column not indexed);
  Address/Port ≈ 166 ms (sorts the joined rows). The anchor query ≈ 65 ms.
- One-time cost per database: the backfill (typed reads of every endpoint and
  link, then the key writes) + index build, at the first open; the table
  persists afterwards.
- Measured after the model switch (7,672 endpoints / 15,344 links, synthetic):
  page query 9.6–14.3 ms at offsets 0/2400/7400 (unchanged — the covering index
  still serves it), hydration ~470 ms; a full import through `upsert_links_bulk`
  now costs ~39 s (endpoints 6.7 s, links + key maintenance 32.5 s), of which
  the key write is ~0.7 ms/row; one flush window's key refresh (400 endpoints)
  is ~300 ms, of which the reads are ~80 ms and the write ~280 ms — decomposed
  per 400 rows: 136 ms for the statement alone, +60 ms for the covering index,
  +87 ms for the window index. The batch writer stays ahead at observed result
  rates; the write cost is what the derived-state cache buys.
- A patch window refreshes a key only when it could have changed it:
  `LinkGroups::KEY_AFFECTING` (RESULT | TRAFFIC) skips the scheduler's TASK-only
  transitions, which carry `task_id`/`task_queue` — columns no rank field
  derives from. Measured on 400 patches: TASK-only 450 ms, RESULT 792 ms, so
  the skip is worth ~340 ms per scheduler window, and those windows are the
  bulk of a batch.
- **Membership now depends on the rank row.** The page drives from the rank
  table, so a write path that changed links without refreshing would hide its
  endpoint. The freshness test pins the three write paths, the parity and
  paging tests pin coverage, and the open-time repair heals a bypassed writer.
  A NULL/missing row is therefore a bug signal, not a normal state.
- Sub-second recency now participates in the tiebreak: the law compares epoch
  nanoseconds (matching the stored `last_seen_at` text the SQL used), where the
  old Rust oracle truncated to seconds.
- Hydration (~450 ms, the `in_list` parameter cost) is unchanged and now the
  dominant term of a page fetch. The fix is a raw read with the endpoint ids
  inlined (integers from the database, never user text — the same rule the rank
  table already uses), which contradicts ADR 0001's "parameterised binds only":
  amend that ADR before implementing, or accept the term.
- **`profile_link_order` is NOT redundant and must not be retired as duplicate
  work.** The SQL link order uses `weight(ps)` with no DNS collapse, while
  `EndpointRow::sort_links_by_test_priority(dns_unresolved)` forces tier 5 for
  every link of an unresolved endpoint — so the two orders differ for those
  endpoints, and `load_page_rows_preserves_page_and_link_order` is the guard.
  Retiring either side is a deliberate law decision, not free work.

## Amendment — 2026-09-14: seconds, one link order, one group set

Three consequences above are no longer true; the stored-keys decision itself is
unchanged and still in force (the covering index serves the page at 8–14 ms).

1. **The recency tiebreak is seconds, not nanoseconds** — the "Sub-second
   recency now participates" bullet is reversed. `profile_stats.last_seen_at` is
   an epoch-second INTEGER (tag 9; see ADR 0001's amendment for the schema
   pass), `RankLink::seen_secs` reads it directly, and `compute_rank` orders by
   `-seen_secs`. Second precision is also the law's original granularity: two
   links seen inside one second tie and the protocol id breaks it. The
   `last_seen_at` TEXT parse (`parse_nanos`) and the nanos unit went with it.
2. **The TASK-only skip is gone with the TASK group** — `LinkGroups` now has
   RESULT and TRAFFIC only (`task_id`/`task_queue` were dropped: task state is
   runtime-only), and both remaining groups can move a key, so every patch
   refreshes its endpoint's keys. `KEY_AFFECTING` was deleted with the skip it
   expressed; the measured 450 ms/792 ms split no longer applies.
3. **`profile_link_order` WAS retired** — this ADR said "must not be retired as
   duplicate work", and that was right about the disagreement: the SQL weight
   let a live measurement sort above a fresh failure on a DNS-unresolved
   endpoint, where the law sinks every link to tier 5. The law won. The panel
   order is `RankLink::key` (via `EndpointRow::sort_links_by_test_priority`),
   `load_page_rows` no longer re-orders links, and
   `page_projection_matches_the_orm_rows` pins the divergent pair (protocols 99
   then 13). The guard test's premise — that two orders exist — is what changed,
   not the law.

The hydration bullet was also acted on rather than accepted: the page is a
one-statement raw read with the ids interpolated as integer literals
(`load_page_projection`, 1,027 ms → 49.6 ms), and ADR 0001 was amended for it.

## Amendment — 2026-09-18: a marker-carrying link contributes no displayable delay

Decision 16's law was implemented TWICE, for two different purposes, and the two
disagreed about a link that carries both a measurement and a failure marker —
which is exactly the shape `apply_test_result` persists (it keeps `latency` when
it writes an error) and `stage_result` re-creates (it overlays the batch's fast
latency onto every patch, failures included).

- **The ordering key** reads `error_kind` first: tier 3/4, `rank_latency =
  i32::MAX`. Unchanged, and still the law.
- **The single-row Test cell** read `active_link()` →
  `select_best_measured_link`, which is error-BLIND, and then let the delay win
  over the marker. So a real failure kept rendering its fast latency while the
  row sorted into an error band: numeric cells interleaved with a band the user
  could not see, and — worse — a full fast+real batch left every failed real
  probe looking like a working fast one.

**The cell now selects the same link the key does.** The Test cell renders the
endpoint's REPRESENTATIVE link — the argmin of `RankLink::key`, the very link
`compute_rank` stores `rank_tier` from — and that link's own failure marker
outranks its own stored delay. Precedence: `[name]` > untestable > purge >
marker > delay > blank.

Selecting by `active_link()` → `select_best_measured_link` was the deeper defect,
not the precedence alone: that rule is error-BLIND (it takes the lowest-delay
MEASURED link), so for `A = fast-ok 12 + real-err` (tier 3) beside
`B = fast-ok 20 + real pending` (tier 1) it picks A and a precedence-only fix
would render `[real]` on a row whose `rank_tier` is 1 — a marker cell inside the
measurement band. With the representative link the cell's content IS the row's
tier band: tier 0/1 → that link's delay (identical to `rank_latency`), tier 2 →
blank, tiers 3/4 → the marker, tier 5 → `[name]`, tier 6 → the purge label
(reachable only when every link is purged, because tier 6 sits below every live
band — which is what the purge label's own comment always claimed).

**Corrected 2026-10-22:** tier 5 → `[name]` is the UNMEASURED case only. A
measured link keeps its measurement's band, so it never renders `[name]` — the
probe dialled the name and the OS resolved it, so the empty address set is not
evidence that the name fails. The tier-5 marker also renders as `[ n/a]`
rather than `[real]` when the engine could not serve the row (no probe ran at
all).

Deliberate behaviour change: the cell no longer follows
`selected_protocol`/`manual_protocol_override`. The ordering law's tier ignores
the override, and a cell that honoured it could not report the endpoint's band.
The override still wins for `active_link()`, which drives the row's exit IP,
country, speed and traffic, and for the sub-table's first position.

`select_best_measured_link` and `display_link_index` stay two functions for two
purposes (the display link vs the tier). What changed is the cell's link
selection and content rule, both of which are now functions of the tier the
ordering law already computes.

Also recorded here because it is the same class of defect on the ordering side:
the cell's `[name]` and the tier-5 band read DIFFERENT resolution sources (the
in-memory `endpoint_info` cache vs the row's persisted `endpoint_ip` addresses).
The cell now reads `endpoint_rank::dns_unresolved(row)` — the row — so the label
and the band are one fact.

## Amendment — 2026-10-09: stability joins the keys; membership becomes its own column

Spec: `docs/aegis/specs/2026-10-09-stab-bin-design.md`.

### The keys gain a term

```text
link key:     (bin, stab_bin, ¬weight, -seen, protocol_id)
endpoint key: (band, bin, stab_bin, ¬weight, domain, sub_domain, addr, endpoint_id)
```

`stab_bin` (`0..7`, `4` neutral) is a link's recent REAL-probe success rate from
a ring of its last 16 real outcomes. It sits **before** the static weight: the
order is measurement class, then reliability, then stack prior. The 2026-10-01
amendment's "the weight outranks latency inside a bin" is narrowed to "the weight
orders links that share both the bin and the stability" — a deliberate reversal,
since four coarse weight bands would otherwise leave `stab_bin` almost never
consulted.

### Membership is a separate fact

`rank_bin` stays the representative link's LAST outcome, so it cannot express
"this endpoint has worked" — a just-failed proven link loses representation to an
untested sibling (bin 12 < 13), which was exactly the churn that motivated the
feature. The new `endpoint_rank.rank_proven` (any live unpurged link's ring holds
a success, on a resolved endpoint) is therefore what the `Successful` scope
selects:

| scope | predicate |
| --- | --- |
| Successful | `rank_proven = 1` |
| New | `rank_proven = 0 AND rank_bin = 12` |
| Failed | `rank_proven = 0 AND rank_bin IN (13, 14, 15)` |
| SuccessfulAndNew | `rank_proven = 1 OR rank_bin = 12` |

`PlanScope::bins()` (a `rank_bin` list) is retired for `PlanScope::predicate()`.

### One index, new name

`endpoint_rank_key_v2(band, rank_bin, rank_stab, rank_weight DESC, rank_domain,
rank_sub_domain, rank_addr, endpoint_id, rank_proven)` replaces
`endpoint_rank_key`, which the same DDL list drops. `rank_proven` rides LAST as a
covering column: placing it between `band` and the ORDER BY terms would filesort
Active and All; trailing, every scope filters **inline** on an index scan, which
is the doctrine this ADR already relied on and why no scope needs a second index.

### Storage

`profile_stats.stab_mask`/`stab_len` and `endpoint_rank.rank_stab`/`rank_proven`
are **typed model fields** — `push_schema` runs only at cursor 0, so declaring
them costs no schema-cursor bump and no wipe. `ALTER TABLE` entries in
`schema/ddl.rs` cover databases that already exist. `rank_weight_meta`'s stamp
becomes `KEY_INPUTS_VERSION` (weight tables + stability thresholds), so a
threshold edit recomputes every stored key exactly as a weight-cell edit does.

A **day-one seed** gives every link with `latency = 'real'` a one-sample success
ring: `apply_test_result` keeps `latency` when it later writes an error, so
without the seed every pre-upgrade success would read `rank_proven = 0` and fall
out of all four scoped menus.

### Consequences

- `RankLink::key` gains one term; `compute_rank` still one `.min()`, and now
  also derives `stab` (the representative's) and `proven` (the endpoint's OR).
- `LinkGroups` gains a fourth bit `STAB`; `merge_group`'s catch-all `else` is
  replaced by explicit arms, and `link_patch_conflict_sql`/the patch bucketing
  widen from 8 to 16 column-set combinations.
- **Remove Bad Servers is not gated by stability** — the user can still delete
  the pool this feature curates, deliberately.

## Amendment — 2026-10-22: a MEASURED link is never in the DNS band

The "tier 5 collapses every link of an unresolved endpoint" reading above (in
the Consequences bullet, the `profile_link_order` bullet, and the
`dns_unresolved_endpoint` doc) is **no longer the law**.

The probe dials the DNS *name* and lets the OS resolve it, **without persisting
the resolution** — so a DNS endpoint the probe reached has an **empty address
set AND a measurement**. The old law read the empty address set as "the name
does not resolve" and filed such a link in the DNS band, which sits BELOW every
real-error band: a working server sorted below the failures. The ordering law,
inverted. The 2026-10-22 report saw it on the live corpus.

The correction: the DNS band needs **positive evidence** of "unresolved". A
**measured** link keeps its measurement's band; the band is for the links that
were never measured. The same correction applies to `rank_proven` (a measured
DNS endpoint is proven like an IP-literal one), because the flag's premise —
"the host cannot be dialled" — is false for an endpoint the probe reached.

`STAB_VERSION` 2 → 3: the band law is an input to the stored keys, so every
stored `rank_bin` re-derives on the first open. The amendment to ADR 0001
below and to `docs/reference/ordering-law.md` §6 carry the same correction.
