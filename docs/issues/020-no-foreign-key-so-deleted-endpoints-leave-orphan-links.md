# 020 — No foreign key exists, so a link staged while its endpoint is deleted lands as a permanent orphan row

- **Location**: `crates/leas-db/src/write_behind.rs:271-289` (`discard_where`
  and the rationale it states), `crates/leas/src/ops/compact.rs:209-217` (the
  only delete path that guards), `crates/leas/src/ops/profiles.rs:938-946` and
  `crates/leas/src/ops/ping.rs:612-625` (user-triggered deletes, unguarded),
  `crates/leas/src/main.rs:594-630` (the 10-minute retention purge, unguarded),
  `crates/leas-db/src/driver/mod.rs:445-452` (`foreign_keys = ON`)
- **Severity**: medium
- **Status**: theory (mechanism proven by the schema; three of four delete paths
  are unguarded)

## Hypothesis

The link write-behind's delete guard is justified by a foreign-key error that
cannot happen, because **the schema declares no foreign keys at all**:

- `docs/reference/database.md`, entity map: "References | none: toasty emits no
  SQL `REFERENCES`, so the arrows in the entity map are ownership, not
  constraints".
- The two `profile_stats` rebuild statements in `ddl.rs` build the table from
  the model's own column list and carry no `FOREIGN KEY` clause (`ddl.rs:187`,
  `:206`); no statement in `crates/leas-db` contains `REFERENCES`.
- `PRAGMA foreign_key_list` was already measured empty on the real schema:
  "FK ON vs OFF, 200k child upserts: 347 vs 358 ms (noise). `PRAGMA
  foreign_key_list` empty (no `REFERENCES`)"
  (`docs/aegis/specs/2026-10-06-db-rewamp-design.md:378`, §9.5).
- `driver/mod.rs:450` still applies `PRAGMA foreign_keys = ON` to every pooled
  connection, and `pooled_connection_carries_the_driver_pragmas`
  (`tests/turso09_lab.rs:1286`, assertion at `:1308`) asserts it — so the pragma
  is enforced and there is nothing for it to enforce.

`discard_where`'s doc (`write_behind.rs:271-275`) says the guard exists because
"the write would hit a live-FK error and the failure path would re-stage it,
retrying forever". With no FK, the real consequence of a missed guard is the
opposite of a loud failure: an **orphan `profile_stats` row** — a link whose
`endpoint_id` has no `endpoints` row — inserted silently and never removed.
`purge_orphan_protocols` prunes only `protocols`, `endpoint_rank::prune` only
rank keys; nothing collects orphan links. Each one permanently inflates
`distinct_exit_ips` (`COUNT(DISTINCT latency_ip)` over the whole table,
`database.rs:2105-2108`) and keeps its protocol row alive, so every merge pass
keeps evaluating a dead config.

**Only one of the four delete paths guards.** The compact pass flushes and then
discards (`compact.rs:213-214`). The other three do not:

| path | trigger | guard |
| --- | --- | --- |
| compact merge → `merge_endpoints` | user starts maintenance | `flush` + `discard_where` (`compact.rs:213-214`) |
| `ops/profiles.rs:938-946` → `delete_endpoint` | user deletes a profile | none |
| `ops/ping.rs:612-625` → `delete_endpoints` | user presses "remove failed servers" | none |
| `main.rs:618` → `purge_expired` | every 10 minutes | none |

The "remove failed servers" path is the sharpest: it deletes exactly the
endpoints whose links carry a persisted failure marker (`is_removable_failure`),
and that marker is written by the probe result that `ops/events.rs:875-877`
stages through this same write-behind (`writer.stage(link, groups)`). The user is
invited to press the key because the failures just appeared, so the staged
patches and the delete are correlated rather than merely adjacent. The other two
paths catch a session's final traffic delta (`ops/connect.rs:228-229`) and a
`Real Test (Purgatory)` re-probe of an aged row (ADR 0006 D8).

The guard's other half is also point-in-time: `discard_where` removes what is
already in `pending`, and any push landing after it (before the DELETE commits)
is unprotected even in the compact path.

Impact is bounded — an orphan is invisible to the UI (the page drives from
`endpoint_rank`, which is pruned) and costs a dictionary row, a metrics count
and a permanently-live protocol — but it is permanent, silent, and reachable
from a common user action, which is why this is medium rather than low.

## Evidence

`write_behind.rs:276-289` — the sweep is a one-shot pass over `pending`:

```rust
pub fn discard_where<F: Fn(&S::Key) -> bool>(&self, pred: F) -> usize {
    let keys: Vec<S::Key> = self.pending.iter().map(|entry| *entry.key()).collect();
    let mut dropped = 0usize;
    for key in keys {
        if pred(&key) && self.take(&key).is_some() { dropped += 1; }
    }
    dropped
}
```

`compact.rs:213-215` — the only delete path that calls it:

```rust
link_stage.flush().await?;
link_stage.discard_where(|k| absorbed_ids.contains(&k.1.get()));
crate::ops::enrich::discard_country_for(absorbed_ids);
```

`main.rs:596-630` — the purge task: `reband_expired()`, then `purge_expired(cutoff)`,
`Ok(count)` reported to the UI, nothing else. Its cascade
(`database.rs:1877-1900`) deletes `endpoint_groups` (`:1878`), `profile_stats`
(`:1885`), the orphan protocols (`:1892`), `endpoint_ip` (`:1893`), `endpoints`
(`:1894`) and the rank rows (`:1900`) for the candidate set — a different
connection and transaction from the write-behind's flush.

So the orphan needs: (a) a staged patch for an endpoint a delete path removes,
(b) that DELETE to commit before the next flush drains the patch. On the purge
path the window is one flush interval (200 ms) per 10-minute tick; on the
"remove failed servers" path it is one flush interval per keypress, and the
patches there are exactly the ones the press is about.

## Reproducer

Schema-level, cheap to re-run on any real database:

```sql
PRAGMA foreign_key_list(profile_stats);   -- expected: empty (no FK to enforce)
PRAGMA foreign_key_list(endpoint_ip);     -- empty
```

Then the write itself, against any opened `Database`:

```sql
-- these both succeed today; with a real FK the first would raise
INSERT INTO profile_stats (protocol_id, endpoint_id, last_seen_at, stab_mask,
  stab_len, traffic_today_up, traffic_today_down, traffic_total_up,
  traffic_total_down, created_at, updated_at, version)
VALUES (1, 999999, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);
SELECT COUNT(*) FROM profile_stats ps
  WHERE NOT EXISTS (SELECT 1 FROM endpoints e WHERE e.id = ps.endpoint_id);
```

I verified the absence of `REFERENCES` textually (`rg REFERENCES crates/leas-db`
finds none; `docs/reference/database.md` states "none") and did not run the
insert against a real feed — the claim is the schema's, not a measurement.

## Fix sketch

Three options, cheapest first:

1. **Declare the constraint.** Add `REFERENCES endpoints(id) ON DELETE CASCADE`
   to `profile_stats.endpoint_id` and `protocol_id`, and the same on
   `endpoint_ip`/`endpoint_groups`. This is DDL, so it is a `steps` entry plus a
   `SCHEMA_VERSION` bump (the cursor psychology in `schema/steps.rs`), and it
   converts the whole class — orphans from a purge race, from a merge race, from
   a bug — into the FK error `discard_where` already believes in. Cost: a table
   rebuild of `profile_stats` (the v21/v22 procedure already exists) on the
   largest table.
2. **A collecting sweep.** One `DELETE FROM profile_stats WHERE NOT EXISTS
   (SELECT 1 FROM endpoints e WHERE e.id = profile_stats.endpoint_id)` at the
   end of `purge_expired_once`, inside its transaction. O(all links) on a 74k
   feed — 50 ms — and only on a pass that actually deleted something.
3. **Make the guard real on every path.** `flush_and_drain` before the delete,
   `discard_where` after — the compact recipe — in `delete_endpoints`,
   `delete_endpoint`'s caller and the purge loop. Cheapest, but it must be added
   to three call sites that today do not stage links at all, and it only narrows
   the window: a push landing after the sweep is still uncovered, so the race
   survives in a smaller form.

Option 1 is the honest fix: the write-behind's retry-forever reasoning, and the
`foreign_keys = ON` pragma, both assume a constraint that does not exist. Option
2 is the one-line stopgap if a rebuild is too much for a maintenance PR.

## Related

- **018** — the other owner of `profile_stats` row lifetimes in the merge path;
  its `discard_where` guard is this issue's only working instance.
- **017** (routing-engine) — same shape of defect one layer up: a guarantee the
  code assumes (a compiled condition constrains) that the implementation does
  not provide.
