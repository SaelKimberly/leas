# 019 — The feed search scans the whole rank table — the footer count on every keystroke, the page too when fewer than 200 rows match

- **Location**: `crates/leas-db/src/profiles_query.rs:513-548` (the search
  predicate in `base_from_where`), `:762-799` (`page_ids_direct` — count, then
  page), `crates/leas-db/src/schema/ddl.rs:49-51`
  (`endpoint_rank_key_v2`, the only index that carries `rank_domain`)
- **Severity**: medium
- **Status**: theory (plan + timings measured)

## Hypothesis

The D6 comment on the search predicate states the contract: prefix matching is
"a byte RANGE (`>= term AND < term||U+10FFFF`) rather than `LIKE '%term%'`, so a
keystroke is an index seek, not a full scan". The predicate is a **scan
filter**, not a seek, for two independent reasons:

1. **No index leads with the search column.** `rank_domain`/`rank_sub_domain`
   sit at positions 5 and 6 of `endpoint_rank_key_v2(band, rank_bin, rank_stab,
   rank_weight DESC, rank_domain, rank_sub_domain, rank_addr, endpoint_id,
   rank_proven)`. A B-tree range on a non-leading column needs every preceding
   column equality-constrained, and neither view supplies that: the tab opens on
   `PurgatoryView::Active` (its `#[default]`, `models_toasty.rs:1019-1023`;
   `AppState` initialises it at `state.rs:831`), which binds `band < 2` — a
   RANGE on the leading column — and the `All` view binds nothing (`1 = 1`). So
   the ordering index can only be scanned end to end with the predicate
   evaluated per row — which is exactly what the plan says.
2. **The port arm cannot be indexed at all, and it is OR-ed with the others.**
   `CAST(e.port AS TEXT) LIKE '%…%'` has a leading wildcard; inside the same
   `OR` as the two range arms it also *prevents* them from being served by an
   index even after one is added (measured below).

The page request then runs the predicate **twice**: `page_ids_direct` issues the
footer `COUNT(*)` with the identical `WHERE`, then the page itself. The count has
no LIMIT, so it is always a full scan of the rank table. The page keeps the index
order and stops at `LIMIT 200`, so it degrades to a full scan exactly when fewer
than 200 rows match — the tail of the typeahead, which is the common case once
the user stops narrowing and finds nothing. Both statements join `endpoints` per
scanned row.

At the reference feed (74k endpoints) the crate's own lab measured a no-search
page read at ~1 ms; the scan below is that value times the table size.

## Evidence

The predicate, `profiles_query.rs:529-546`:

```rust
let term = search.to_lowercase();
let escaped = escape_like(&term);
let port_pat = sql.bind(format!("%{escaped}%"));
let mut clauses = vec![format!("CAST(e.port AS TEXT) LIKE {port_pat} ESCAPE '\\'")];
if let Some((lo, hi)) = ip_range_bounds(&term) {
    …
} else {
    … clauses.push(format!("(k.rank_domain >= {l} AND k.rank_domain < {h})"));
    … clauses.push(format!("(k.rank_sub_domain >= {l2} AND k.rank_sub_domain < {h2})"));
}
sql.push(&format!(" AND ({})", clauses.join(" OR ")));
```

Measured with `~/.turso/tursodb` 0.6.1 on a synthetic store (50,000 endpoints ×
1 rank row, the exact DDL of `endpoint_rank` plus `endpoint_rank_key_v2` and
`endpoint_rank_band_window`), the page statement built by `base_select` +
`order_by(Test)` with a term that matches nothing (the tail of the typeahead,
the worst case):

```text
EXPLAIN QUERY PLAN
  SELECT k.endpoint_id FROM endpoint_rank k JOIN endpoints e ON e.id = k.endpoint_id
   WHERE 1 = 1 AND (CAST(e.port AS TEXT) LIKE '%zzz%' ESCAPE '\'
                 OR (k.rank_domain >= 'zzz' AND k.rank_domain < 'zzz'||x'F48FBFBF')
                 OR (k.rank_sub_domain >= 'zzz' AND k.rank_sub_domain < 'zzz'||x'F48FBFBF'))
   ORDER BY k.band, k.rank_bin, k.rank_stab, k.rank_weight DESC, k.rank_domain,
            k.rank_sub_domain, k.rank_addr, k.endpoint_id LIMIT 200 OFFSET 0

|--SCAN endpoint_rank AS k USING COVERING INDEX endpoint_rank_key_v2
`--SEARCH e USING INTEGER PRIMARY KEY (rowid=?)
```

| variant | wall | plan |
| --- | --- | --- |
| page, no search | **0.5 µs** | `SCAN … USING COVERING INDEX` + LIMIT stop |
| page, port arm only | **10 ms** | scan + per-row join |
| page, all three arms | **40 ms** | scan + per-row join |
| `COUNT(*)` with all three arms (the footer, same keystroke) | **15 ms** | scan + per-row join |

Adding the two indexes the predicate needs — `endpoint_rank(rank_domain)` and
`endpoint_rank(rank_sub_domain)` — while REMOVING the port arm turns the whole
thing into an index lookup:

```text
|--MULTI-INDEX OR k (ix_rank_domain, ix_rank_sub_domain)
`--USE SORTER FOR ORDER BY
```

**53 µs** for the same no-match term: ~750× faster. With the port arm left in
the `OR`, the plan does not change at all (still `SCAN … COVERING INDEX`, still
35 ms) — the unindexable arm poisons the whole disjunction.

The app pins turso `=0.9.0-pre.5` (`crates/leas-db/Cargo.toml:34`) and the probe
above ran on the 0.6.1 shell, so the exact `MULTI-INDEX OR` / sorter wording is
indicative. The two structural facts are not planner-dependent: a range on a
non-leading index column cannot seek, and a leading-wildcard `LIKE` can never be
index-served. The shape must be re-confirmed through the pinned engine with the
repo's own gate, `arm_plan_sweep` in
`crates/leas-db/tests/turso09_lab.rs:684` — the lab that exists to catch exactly
this, and whose 13 listed statements do **not** include the search page.

## Reproducer

```bash
~/.turso/tursodb /tmp/probe.db \
  "EXPLAIN QUERY PLAN SELECT k.endpoint_id FROM endpoint_rank k \
     JOIN endpoints e ON e.id = k.endpoint_id WHERE 1 = 1 \
     AND (CAST(e.port AS TEXT) LIKE '%zzz%' ESCAPE '\\' \
       OR (k.rank_domain >= 'zzz' AND k.rank_domain < 'zzz'||x'F48FBFBF') \
       OR (k.rank_sub_domain >= 'zzz' AND k.rank_sub_domain < 'zzz'||x'F48FBFBF')) \
     ORDER BY k.band, k.rank_bin, k.rank_stab, k.rank_weight DESC, k.rank_domain, \
              k.rank_sub_domain, k.rank_addr, k.endpoint_id LIMIT 200 OFFSET 0"
```

Run against a 50k-row `endpoint_rank` built with `ddl.rs`'s statements; the
plan and the timings in the table above are its output.

## Fix sketch

1. Add the two prefix indexes as raw DDL, next to `ENDPOINT_IP_BY_KEY`
   (`ddl.rs:32`): `CREATE INDEX IF NOT EXISTS endpoint_rank_domain ON
   endpoint_rank(rank_domain)` and the same on `rank_sub_domain`. Idempotent,
   applied by `ensure_raw_ddl` on every open — the established way to add an
   index without a cursor bump (`V18_AFTER_ALTERS` is the precedent).
2. Take the port arm out of the `OR`. Either drop it (the D6 contract already
   gave up substring matching for hostnames; the port's `%…%` is the odd one
   out), or resolve it first — `SELECT id FROM endpoints WHERE CAST(port AS
   TEXT) LIKE ?`, then bind the small id set as `k.endpoint_id IN (…)`, an OR of
   PK equalities the planner can seek.
3. Accept the sorter: with the index in play the ORDER BY sorts the FILTERED
   set, which for a real keystroke is tens of rows. The 53 µs above already
   includes it. A broad prefix (`h`) sorts more; that is the honest trade
   against scanning 74k rows to keep the order free.

The footer count gets the same predicate, so it improves for free; nothing else
in `page_ids_direct` needs to change.

## Related

- **018** — same failure class in the same crate: a query priced by a table
  instead of by the rows it needs. Independent paths (merge vs page read).
- **006** (mux-pool) — unrelated, but the same lesson: a shared gate sized for
  the whole population instead of the caller's slice.
