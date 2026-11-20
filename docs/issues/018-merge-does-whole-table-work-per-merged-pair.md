# 018 — A merge reads the whole protocol table and rescans it for orphans, once per merged pair

- **Location**: `crates/leas-db/src/merge.rs:174` (`protocol_weights` inside
  `merge_in`), `crates/leas-db/src/merge.rs:486` (`purge_orphan_protocols` in
  `delete_absorbed`), `crates/leas-db/src/endpoint_rank.rs:1088-1096`
  (`Protocol::all()`), `crates/leas-db/src/database.rs:2215-2224` (the anti-join)
- **Severity**: medium
- **Status**: theory (both halves measured in-repo)

## Hypothesis

`merge_endpoints` merges exactly one `(survivor, absorbed)` pair per
transaction — and inside that transaction it does two pieces of work whose cost
is the size of the WHOLE protocol table:

1. `protocol_weights(&mut *tx)` = `Protocol::all().exec(conn)`, decoding every
   protocol row to build a map that the merge then queries with at most a
   handful of keys (only the protocol ids of the two endpoints' links, which
   `merge_in` has already loaded).
2. `purge_orphan_protocols` = `DELETE FROM protocols WHERE NOT EXISTS (SELECT 1
   FROM profile_stats p WHERE p.protocol_id = protocols.id)`, a full-table
   anti-join, run once per pair.

The compact pass drives `merge_endpoints` in a loop, one pair per transaction
(`crates/leas/src/ops/compact.rs:334`, inside `for c in &plan.components { for
absorbed in &c.absorbed {`), so a pass of M merges pays M whole-table reads and
M whole-table deletes. The crate knows this shape is wrong twice over:

- `endpoint_rank::refresh` right after the merge deliberately joins the five
  discriminator columns into the links statement instead of loading protocols —
  "a separate load would re-scan the whole protocols table on every flush
  window. The deferred `config` JSON is NOT touched" (`endpoint_rank.rs:1149-1152`).
- `delete_endpoints` was already refactored for the same reason: "The
  per-endpoint path … scans for orphan protocols and prunes rank keys per
  endpoint; a bulk delete … did all of that N times"
  (`database.rs:1918-1921`). The merge path is that pre-refactor shape.

The repo's own study already recommends the batch half of this — "**Consider
running the orphan purge once per compact pass**, not once per merged endpoint:
the statement is 23 ms now, but 171 merges still pay 171 of them inside their
own transactions" (`docs/research/2026-11-16-turso-0.9-delta.md:205-207`,
`§6` item 3). It was never implemented, and the `protocol_weights` read is not
mentioned there at all.

## Evidence

The per-merge transaction, `merge.rs:168-192`:

```rust
let weights = crate::endpoint_rank::protocol_weights(&mut *tx).await?;
let weight_of = |pid: i64| -> ConfigWeight { … };
let report = merge_links(tx, survivor, absorbed, &links, &weight_of).await?;
…
delete_absorbed(tx, absorbed).await?;
crate::endpoint_rank::refresh(&mut *tx, &[survivor]).await?;
```

`links` — the only input `weight_of` is ever called with — was loaded a few
lines above:

```rust
let links: Vec<ProfileStats> = ProfileStats::filter(toasty::stmt::in_list(
    ProfileStats::fields().endpoint_id(),
    ids.clone(),
)).exec(&mut *tx).await?;
```

So the exact key set is already in hand: `links.iter().map(|l| l.protocol_id)`,
at most two endpoints' worth.

Measured costs, all recorded in this repo rather than estimated:

| Work | Cost | Source |
| --- | --- | --- |
| `Protocol::all()` (typed, whole table) | **~0.47 s at 6,111 protocols** | `database.rs:1226-1229`, the page-load measurement that retired the same read |
| orphan anti-join + DELETE, 74k protocols | **23 ms + 29 ms** in autocommit; **31.0 ms** inside the merge transaction | `docs/research/2026-11-16-turso-0.9-delta.md:225`, `:237-240` |
| compact pass | 171 merges in the recorded dump | same doc, `§6` item 3 |

So one merge on the reference feed pays ~0.5 s of protocol work to move a
handful of links, and a 171-merge compact pays ~85 s of it inside its own
transaction queue. That number is the same order as the 556 s compact pass the
anti-join rewrite was originally chasing (`database.rs:2210-2214`).

## Reproducer

Shape only — the cost is already tabulated above, and re-deriving it needs a
74k-protocol build of the lab. What the fix must preserve is the exactness of
the restricted form: after deleting one endpoint's links, the protocols that can
have become orphaned are exactly the ones those links referenced.

```sql
-- today: O(all protocols)
DELETE FROM protocols WHERE NOT EXISTS
  (SELECT 1 FROM profile_stats p WHERE p.protocol_id = protocols.id);

-- restricted: O(the pair's links), a PK lookup per candidate
DELETE FROM protocols WHERE id IN (7, 9, 11) AND NOT EXISTS
  (SELECT 1 FROM profile_stats p WHERE p.protocol_id = protocols.id);
```

Probed with `~/.turso/tursodb` 0.6.1 on a synthetic 50k-row table (the app pins
turso `=0.9.0-pre.5`, so treat the plan shape as indicative, the predicate
arithmetic as exact):

```text
EXPLAIN QUERY PLAN DELETE FROM protocols WHERE id IN (7,9,11) AND NOT EXISTS (…)
`--SEARCH protocols USING INTEGER PRIMARY KEY (rowid=?)

EXPLAIN QUERY PLAN DELETE FROM protocols WHERE NOT EXISTS (…)
`--SCAN protocols
```

## Fix sketch

Two edits, both inside `merge_in`, no schema change:

1. Restrict the weights read to the pair's protocols:
   `Protocol::filter(in_list(Protocol::fields().id(), pair_protocol_ids))`.
   Better still, fold the five discriminator columns into the existing links
   statement the way `endpoint_rank::refresh` does and compute the weight with
   `weight_from_discriminators` — one statement, no `Protocol` decode at all.
2. Give `purge_orphan_protocols` a `&[ProtocolId]` parameter (the ids of the
   links `delete_absorbed` just deleted) and add `AND id IN (…)`. Keep the
   no-argument form for the wholesale callers (`delete_endpoints_once`,
   `purge_expired_once`) where one statement for the batch is already correct.

The batch alternative — move the purge out of `delete_absorbed` into the
compact loop, once after all merges — is what the study recommends, but it
leaves orphans visible to a concurrent reader between merges and needs an
error path for a failed pass. The restricted form keeps the transaction atomic
and is strictly cheaper per merge, so it is the one to take. If both are done,
the pass-level one subsumes the per-pair call and the per-pair one can go.

## Related

- **019** — the other per-keystroke full scan in the same crate; same failure
  class (a query whose cost is a table, not a row set), different path.
- **020** — same file family, maintenance-risk rather than cost.
