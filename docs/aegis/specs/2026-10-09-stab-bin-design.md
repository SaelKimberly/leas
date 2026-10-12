# `stab_bin` — link stability in the ordering law

Date: 2026-10-09
Status: IMPLEMENTED 2026-10-09 (plan `docs/aegis/plans/2026-10-09-stab-bin.md`). The §13 open items are resolved: the boundaries shipped as the table in §5.1, `KEY_INPUTS_VERSION` is a new constant folded with `WEIGHT_VERSION`, and the DB+law landed before the UI.
Supersedes/extends: `docs/ordering_law.md` §1–§6, §8, §9
Related: decisions 4 (schema cursor), 11 (identity), 15 (batch pipeline),
16 (binned law + weight), 21 (SQL page), 22 (write-behind);
ADRs 0002 (write-behind groups), 0003 (stored ordering keys),
0006 (purge), 0010 (band), 0011 (rewamp/identity)
Touches: `crates/xray-tui-db` (`endpoint_rank`, `profiles_query`,
`write_behind`, `database`, `schema/ddl`), `crates/xray-tui/src/ops`
(`ping`, `events`), `crates/xray-tui/src/ui/profiles.rs`,
`docs/ordering_law.md`, `docs/database.md`, `docs/database-manual-sql.md`,
`AGENTS.md` decision 16, ADR 0003

Source draft: `STAB_BIN.md`. This spec replaces that draft's §1–§7 where they
conflict; each reversal is listed in §2.

## 1. Problem

`rank_bin` is the **last outcome** of the endpoint's representative link. One
failed real probe therefore removes a link from `PlanScope::Successful`
(`rank_bin IN (0..=5)`), and a later success puts it back. For a feed where
~1% of endpoints are alive, that churn is wrong twice:

- an intermittently-working server leaves the working pool on every bad night;
- a server that failed first and succeeded later re-enters indistinguishable
  from one that has never failed.

Neither Active `band` (a TTL window, ADR 0010) nor purge (a permanent verdict,
ADR 0006) answers the question "has this link worked, repeatedly?". That is a
third, orthogonal fact: **recent reliability**.

## 2. Decisions taken in the interview (2026-10-09)

| # | decision | rejected alternative and why |
| --- | --- | --- |
| D1 | **Sample** = a real outcome that ran, **plus** a hard-fast retirement **only when `real_phase`** (F1+W2) | fast-only: a routine Fast Ping pass would fill rings with failures, demoting proven links with no real evidence (F2) |
| D2 | Retirement sample is keyed on the **retirement decision**, never on `hard_fast.contains(key)` | the quic-plugin arm `retract_fast_marker`s and *does* get real-probed; a sample there would demote a working link |
| D3 | Window is a **ring of the last N outcomes** (`u64` mask + len) | two counters cannot evict one outcome; tumbling counters sawtooth `stab_bin` at every wrap (W3) |
| D4 | Ring lives on `profile_stats` (**typed** `stab_mask`/`stab_len` fields), own `LinkGroups::STAB` bit (S1) | folding into `RESULT` recreates the clobber shape PURGE was split out to prevent; an append-only probe log is unbounded |
| D5 | `proven` = **any `1` still in the ring** (P1) | a durable bit cleared only on purge keeps dead links in Successful for the whole purge TTL |
| D6 | Endpoint membership is a **separate stored fact** (`rank_proven` on `endpoint_rank`), OR over live unpurged links' rings | option A (representative only) fails: a just-failed proven link loses representation to an untested sibling (bin 12 < 13); option C (`¬proven` first in the link key) makes a failure the row's displayed measurement |
| D7 | Successful/New/Failed partition on **`rank_proven` first**, then bin (R1) | bin-only labels a proven endpoint with an untested sibling as "New" |
| D8 | Key order `(meas_bin, stab_bin, ¬weight, …)` (O1) | stability after weight is decorative — the four weight bands differ too often to reach it |
| D9 | `rank_proven` is materialized on `endpoint_rank`; Successful is a **second predicate family**, not a `rank_bin` list | the link key alone cannot deliver membership (§5.2) |
| D10 | Neutral warm-up = `STAB_NEUTRAL = 4` | 3 sinks anything under 60%; 5 lets a 3-of-4-failing link outrank an untested one |
| D11 | `STAB_WINDOW = 16`, `STAB_WARMUP = 4` | 8 drops out of Successful on a bad week; 32 overlaps purge's job |
| D12 | UI = panel sub-row `successes/attempts`; **no** main-row glyph | the Test cell is "the endpoint's measurement tier"; folding stability in merges two concerns |
| D13 | Remove Bad Servers is **not** gated by stability (§8) | product promise (requirement 3) is about the Successful pool and batch scopes, not about a user-issued deletion |

## 3. What changed from the draft (`STAB_BIN.md`)

| draft | verdict | reason |
| --- | --- | --- |
| §1 "attempts + successes counters" | **replaced** | cannot express a sliding window (D3) |
| §1 "only real probes increment" | **narrowed** | the hard-fast retirement in a real-capable batch takes a sample (D1); quic retract does not (D2) |
| §3 "Successful = proven" | **completed** | needs `rank_proven`; a proven endpoint can carry `rank_bin = 12` (§5.2) |
| §3 "last measurement may be failure while the link remains Successful" | **reachable only with D9** | the endpoint key's `bin` term still sinks a failed link |
| §4 index "…`rank_bin, rank_stab`, …" with `rank_proven` | **replaced** | a non-leading `rank_proven` between `band` and `rank_bin` filesorts Active and All; one index with `rank_proven` trailing (§6.3) |
| §7 "bump schema tag per project wipe rules" | **retired** | the tag is now a **cursor** (`schema/mod.rs`): `18 → 19` reports a compatible file as `IncompatibleSchema` and **deletes the feed**. Raw columns only (§6.1) |

## 4. Requirement

R1. A real failure on a proven link leaves the endpoint in Successful; the row
still shows the failure (`[real]`/`[fast]`, or the stale delay it keeps).

R2. A real success after failures enters/stays Successful, with `stab_bin`
reflecting the ratio — unstable until `N_min` successes.

R3. Never-probed and warm-up links get neutral (`4`), not best and not worst.

R4. Only samples (D1) move the counters. A fast success never does. A fast-only
batch never does.

R5. Every page plan (Active / Purgatory / All / the four scoped walks) is an
index seek or an index scan **with no sorter**.

R6. The ratio is visible per link without depending on order alone.

R7. An existing tag-18 database upgrades in place: no wipe, no re-import.

## 5. The law

### 5.1 Ring, counters, `stab_bin`

Per **link** (`profile_stats`):

- `stab_mask` — `u64` ring of the last `STAB_WINDOW` outcomes, `1` = success,
  `0` = failure. Bit 0 is the OLDEST of the live window.
- `stab_len` — `0..=16` (number of live samples).

Append (partial fill and full window are different operations):

```rust
// len < STAB_WINDOW: the new sample is the newest — every existing bit stays
// at its own index, so bit i still means "the i-th oldest live sample"
mask |= u64::from(ok) << len;
len += 1;

// len == STAB_WINDOW: evict the oldest and push the new one in at the top
mask = (mask >> 1) | (u64::from(ok) << (STAB_WINDOW - 1));
```

**Invariant (pin with a test):** bits `[len, 64)` are always zero, so
`mask.count_ones()` is the success count of the live window at every length —
a partial window is as correct as a full one. Bit index 0 is the oldest live
sample throughout.

```rust
// ONE function; `compute_rank` and the panel read it, SQL never re-derives it
pub const fn stab_bin(mask: u64, len: u8) -> u8 {
    if len < STAB_WARMUP { return STAB_NEUTRAL; }        // 4
    let successes = mask.count_ones();
    match (successes * 100) / u32::from(len) {
        95.. => 0, 85..=94 => 1, 75..=84 => 2, 60..=74 => 3,
        45..=59 => 4, 30..=44 => 5, 15..=29 => 6, _ => 7,
    }
}
pub const STAB_WINDOW: u8 = 16;
pub const STAB_WARMUP: u8 = 4;
pub const STAB_NEUTRAL: u8 = 4;
```

`STAB_NEUTRAL` has **three uses** and they must stay the same value: the
warm-up/empty return, the `rank_stab` column DEFAULT, and the panel's "no data"
rendering.

### 5.2 Keys

```text
link key:     (meas_bin, stab_bin, u64::MAX - weight, -seen_secs, protocol_id)
endpoint key: (band, meas_bin, stab_bin, u64::MAX - weight,
               rank_domain, rank_sub_domain, rank_addr, endpoint_id)
```

`RankLink::key` gains one term; `compute_rank` still takes one `.min()`.

Deliberate ordering consequence, to be written into `ordering_law.md` §3.1:
the law is now **three layers** — measurement class, then reliability, then
stack prior. Weight no longer outranks latency *or* stability inside a bin; it
orders links that share both. The 900 ms-REALITY-vs-40 ms-TCP example still
holds only when the two also share `stab_bin`.

### 5.3 `proven` and the scopes (D7)

Per **endpoint**, materialized on `endpoint_rank`:

```text
rank_proven = 1  ⟺  ∃ link with (purge_reason IS NULL) ∧ (ring has a 1)
```

| scope | predicate |
| --- | --- |
| Successful | `rank_proven = 1` |
| New | `rank_proven = 0 AND rank_bin = 12` |
| Failed | `rank_proven = 0 AND rank_bin IN (13, 14, 15)` |
| SuccessfulAndNew | `rank_proven = 1 OR rank_bin = 12` |

A proven endpoint **can** carry `rank_bin = 12` or `13`: the representative is
the endpoint's minimum link key, and a sibling that was never probed (bin 12)
outranks a failed one (13). That is exactly the churn R1 must survive, and it
is why membership is a separate column rather than a bin list.

**Invariant (pin with a test):** `rank_bin ∈ 0..=5 ⇒ rank_proven = 1`, because
`latency = Real` is only ever written by a real success and the seed of §6.2
gives every such link a `1` in its ring.

**Known gap, documented not silently carried:** bins 6..11 (fast success, no
real success) match no scope, and bin 16 (purged) matches none by design.
Pre-existing; inherited by R1.

## 6. Storage, schema, invalidation

### 6.1 Columns (no cursor bump)

`SCHEMA_VERSION` stays **18**. The tolerated `ALTER` loop in
`ensure_raw_ddl` (`schema/mod.rs:47-61`) covers every existing file, and
`push_schema` runs only at cursor `0` — so a **declared model field costs no
bump and no wipe**. A cursor bump would report every existing file as
`IncompatibleSchema` and delete it — unacceptable, because the feature's premise
is retained probe history.

The stale rationale at `endpoint_rank.rs:384` and in `ddl.rs` ("adding a model
field would need `push_schema` and therefore a tag bump") predates the
migration runner. Both comments are corrected as part of this change.

**Typed, not raw** — `profile_stats` and `endpoint_rank` are both typed models,
and every reader already goes through the typed path:

| column | where | why typed |
| --- | --- | --- |
| `stab_mask: i64` | `ProfileStats` (`#[column("stab_mask")]`) | `decode_projected_link` builds a `ProfileStats` from the page projection, so a non-model column has **no** home in `EndpointRow`; `backfill_all`'s `ProfileStats::all()` would miss it too |
| `stab_len: i64` | `ProfileStats` | same |
| `rank_stab: i64` | `EndpointRank` (`#[column("rank_stab")]`) | `EndpointRank` is itself a typed model — `rank_bin`/`rank_domain`/`rank_addr`/`rank_newest_seen` are all declared with `#[column]` |
| `rank_proven: i64` | `EndpointRank` | same |

`rank_weight` remains the ONE raw column: it has no model field, which is why
it is written through `RANK_COLUMNS` and carries the `NOT NULL DEFAULT` note.
`rank_stab`/`rank_proven` do not copy that shape.

The ALTER list stays as the editor for databases that already exist (a declared
field changes nothing about an already-created table), and the duplicate-column
error is tolerated exactly as today.

```sql
-- ddl.rs, new const STAB_ADD_COLUMNS (profile_stats; tolerated duplicate-column loop)
ALTER TABLE profile_stats ADD COLUMN stab_mask INTEGER NOT NULL DEFAULT 0
ALTER TABLE profile_stats ADD COLUMN stab_len  INTEGER NOT NULL DEFAULT 0

-- ddl.rs, ENDPOINT_RANK_ADD_COLUMNS (append)
ALTER TABLE endpoint_rank ADD COLUMN rank_stab   INTEGER NOT NULL DEFAULT 4
ALTER TABLE endpoint_rank ADD COLUMN rank_proven INTEGER NOT NULL DEFAULT 0
```

`rank_stab`'s default is `STAB_NEUTRAL` (4), not 0: a default of 0 would be
"best" for a row the law has not derived. `NOT NULL DEFAULT` still matters for
existing rows *even though* the column is typed: the model's `CREATE TABLE` is
never re-run on them.

`RANK_COLUMNS`/the `VALUES` tuple still list both `endpoint_rank` columns —
`INSERT OR REPLACE` resets any column missing from the list to its DEFAULT,
which for `rank_proven` is 0 (silently dropping the endpoint out of Successful,
with no error). That requirement is about the *statement*, not about
typed-vs-raw.

### 6.2 Day-one seed — required, and the one non-obvious step

`latency = Real` is evidence a real success happened, but `apply_test_result`
(`events.rs:161-172`) **keeps latency when it writes an error**. So after the
ALTER every previously-successful link has `latency = Real` *and* an empty
ring: `rank_proven = 0`, and under D7 those endpoints match **no** scope. The
whole pre-upgrade Successful set would vanish from every scoped menu.

Therefore, on the run where the stab ALTER actually added the column:

```sql
-- `latency` is the embed's discriminator column (TEXT 'real'/'fast'/'', the
-- same column `refresh` matches on); `latency_delay` is the shared value.
UPDATE profile_stats SET stab_mask = 1, stab_len = 1 WHERE latency = 'real'
```

before `backfill_all`. A seeded link gets `attempts = 1 < STAB_WARMUP` →
neutral `stab_bin` (correct: we know it worked, we have no reliability
estimate) and `proven = 1` (correct, and it restores the §5.3 invariant).

Gate: **a durable stamp**, written in the same transaction as the seed
(`app_meta['stability_seeded']`), and the seed re-run whenever the stamp is
absent. Do **not** gate it on "the ALTER just added the column": a process
killed between the ALTER and the UPDATE would leave every pre-upgrade success
with an empty ring, and every later open would see `duplicate column`, skip the
seed, and strand those endpoints outside all four scopes until each was
re-probed — weeks on a large feed. The stamp closes that window; the seed and
its stamp are all-or-nothing.

Do **not** key the seed on `rank_bin ∈ 0..=5`: that misses a
succeeded-then-failed link, the exact case the feature exists for. And a
never-yet-probed database stamps too (a fresh file, and a first run with no real
links): the backfill is a MIGRATION concern, and a link that earns a real
latency later gets its ring from the probe that measured it.

Cold start is otherwise correct by construction: empty ring → `len = 0` →
neutral `stab_bin`, `rank_proven = 0` until samples arrive.

### 6.3 Index

**One** index, new name (an in-place column-list change under `IF NOT EXISTS`
is a silent no-op — `ddl.rs` says so):

```sql
-- the Test order for EVERY view. `rank_proven` is a TRAILING covering column,
-- never placed between `band` and the order terms: the ORDER BY is
-- `band, rank_bin, rank_stab, rank_weight DESC, …`, so an unconstrained
-- `rank_proven` in that run would filesort Active and All.
CREATE INDEX IF NOT EXISTS endpoint_rank_key_v2 ON endpoint_rank(
  band, rank_bin, rank_stab, rank_weight DESC,
  rank_domain, rank_sub_domain, rank_addr, endpoint_id, rank_proven)
```

`endpoint_rank_key` (the v18 name) is **dropped** in the same DDL list once the
new name exists. `order_terms(PageSort::Test)` gains the `rank_stab` term
directly after `rank_bin`, matching the index order term for term.

**Why no second index for the Successful scope.** `ordering_law.md` §5's
doctrine is that a scoped predicate rides the main covering index with the
predicate inline, and R5 asks only for *no sorter*. With `rank_proven` as a
trailing covering column:

| scope | plan |
| --- | --- |
| Successful | `band = ?` seek (or scan) + inline `rank_proven = 1` |
| New / Failed | `band = ?` + inline `rank_bin IN (…)` |
| SuccessfulAndNew | `band = ?` + inline `rank_proven = 1 OR rank_bin = 12` |
| All / Purgatory | covering scan / seek |

Every one is the index order, so no sorter. The LIMIT stops the scan at 200
rows; a scope with few matches walks more of its band range, which is an index
scan, not a sort. An extra index would cost a write on every rank refresh at
74k rows for a seek the trailing column already provides.

**Escalation, measured not assumed:** if a real-feed measurement shows a
Successful page scanning an unacceptably wide band range, add
`endpoint_rank_proven(band, rank_proven, rank_bin, rank_stab, rank_weight DESC,
…)` then — with the number recorded in `docs/ordering_law.md` §8, like every
other index decision in that file.

### 6.4 Invalidation (the input-version stamp)

`rank_stab` derives from compiled thresholds, so a threshold edit invalidates
every stored value exactly as a weight-cell edit does. **Reuse
`rank_weight_meta`**: rename its meaning in place to "version of the
key-derivation INPUTS" (`WEIGHT_VERSION` + the stab constants; one bumped
constant `KEY_INPUTS_VERSION`, or fold both into the same value). No second
meta table, no second staleness path.

`ensure_in`'s populated branch already recomputes all keys on a mismatch; that
path now also covers `rank_stab`/`rank_proven`. The `IS NULL` heal is
deliberately **not** used: `NOT NULL DEFAULT` materializes every row, so an
`IS NULL` probe finds nothing (the weight spec records this exact trap).

## 7. Write path

### 7.1 Producers

| event | samples? | group staged |
| --- | --- | --- |
| real probe result (success or failure) | yes | `STAB` (+ `RESULT`, + `PURGE` when a verdict moves) |
| hard-fast retirement, `real_phase == true` (§7.2) | yes, failure | `STAB` (+ `RESULT` for the `[fast]` marker) |
| hard-fast retirement, fast-only batch | no | `RESULT` only |
| quic-plugin `retract_fast_marker` | no | `RESULT` only |
| fast success | no | `RESULT` only |
| dedup-sibling retire, stop-retire, queue-full, `UNTESTABLE_PREFIX` refusal | no | — |

### 7.2 Where the retirement sample is written

`after_fast_settle` (`ping.rs:1878-1917`):

```rust
if self.hard_fast.lock().contains(&key) {
    if self.is_quic_plugin_link(link).await {
        self.retract_fast_marker(link);        // no sample
    } else {
        self.counters.unreachable.fetch_add(1, Ordering::Relaxed);
        if self.real_phase { self.sample_stability(link, false); }  // NEW
        return;
    }
}
```

The sample goes **with the verdict, not with the class** — the same rule the
`[fast]` marker already follows.

### 7.3 Ring append is not a snapshot value

`stage` takes a whole `ProfileStats` row, but a **ring append is a
read-modify-write over staged state**, and the write-behind drain is a *remove*,
not a copy. Two indusers of a lost sample exist today: a single ping staging
from the page-loaded row while a batch sample is pending, and the retirement
sample whose snapshot is the plan-time row.

Rule: the producer reads the current mask/len through
`WriteBehind::<LinkSpec>::get(&(protocol_id, endpoint_id, LinkGroups::STAB))`
(read-through over the pending map, `write_behind.rs:389`), appends, then
stages; it falls back to the loaded/plan row only when nothing is staged.
`get` + `push` is not atomic — the scheduler's one-mutex gate serializes a
link's transitions today, and the single-ping path must carry a regression test.

### 7.4 Link groups

`LinkGroups` gains `STAB = 0b1000` (`TRAFFIC` stays `0b100`). Consequences,
all required:

- `merge_group` (`write_behind.rs:797-812`) gets an **explicit arm per group**;
  the catch-all `else { base.traffic = … }` is deleted, because a fourth bit
  currently falls into it and would write TRAFFIC columns from a `STAB`
  snapshot — the silent clobber the PURGE split exists to prevent.
- `link_patch_conflict_sql` (`database.rs:675`) takes four booleans and adds
  `stab_mask = excluded.stab_mask`, `stab_len = excluded.stab_len` in the STAB
  branch (16 buckets).
- `LinkSpec::coalesce`'s per-flag loop and `restage_entries` include `STAB`.
- The staged link's mask/len are written by the multi-row upsert's column list
  **and** the `INSERT VALUES` tuple. They are typed fields on
  `ProfileStats`, so the write path names the columns explicitly (the same
  statement shape, not a new mechanism).

### 7.5 `endpoint_rank` write path

- `RankLink` gains `stab: u8` and `proven: bool`; `compute_rank` writes them
  into the typed `EndpointRank` fields (`rank.stab` from the minimum-keyed
  link, `rank.proven` ORed over live unpurged links). `RankRow` keeps only its
  existing fields — its one non-model field is `weight`.
- `RANK_COLUMNS` and the `VALUES` tuple gain `rank_stab`, `rank_proven`.
  Omitting them lets `INSERT OR REPLACE` reset them to the DEFAULT on every
  refresh — `rank_proven` to 0, which silently drops the endpoint out of
  Successful with no error.
- `refresh`'s link statement (`endpoint_rank.rs:867`) already reads raw
  `ps.*`; it gains `ps.stab_mask`, `ps.stab_len`.
- `backfill_all` (`:749`) loads typed `ProfileStats::all()`; because both
  fields are typed, that load already carries them — no projection change is
  needed there (raw columns would have forced one).
- `clear_all_stats` (`database.rs:1766`) zeroes `stab_mask`/`stab_len`
  alongside traffic/latency/error/speed, before its `backfill_all`.

## 8. Product surfaces

- Panel sub-row (per link): a `Stab` column rendering `successes/attempts`
  (`12/16`), or `—` when `len = 0`. Numeric, not a glyph: it must be checkable
  against the ordering.
- Main row: **no** stability glyph, no stability-only color. Order already
  reflects the representative's `rank_stab`; the Test cell keeps its meaning.
- Page projection gains `stab_mask`, `stab_len` per link
  (`PAGE_PROJECTION`'s `profile_stats` block, 23 → 25 columns; the positional
  decoder moves in lockstep).
- **Remove Bad Servers is NOT gated by stability.** `is_removable_failure`
  (`ping.rs:96`) still keys on an error marker, proven or not: the user can
  delete the pool this feature curates, deliberately, and the panel shows the
  ratio so the deletion is informed. `docs/ordering_law.md` §6 states this.
  (Not changed: the feature is about batch scopes and the Successful pool, not
  about a destructive user action.)

## 9. Verification

| check | what it pins |
| --- | --- |
| `stab_bin` thresholds | the 8 boundaries + warm-up/empty → 4, as a pure table test |
| ring arithmetic | append/evict at `len` 0, 15, 16; oldest-out; `count_ones` == successes |
| law parity (extended) | SQL `PageSort::Test` order == `load_page_rows` in-memory order over a fixture carrying differing `stab_mask`/`len` |
| scope partition | the four predicates are disjoint where claimed and cover the R1 space; `rank_bin ∈ 0..=5 ⇒ rank_proven = 1` |
| seed | a fixture of links with `latency = Real`, some carrying an error, seeded → all `rank_proven = 1`, all `stab_bin = 4`, and the Successful scope is non-empty |
| retirement sample | a hard-fast failure in a `real_phase` batch appends exactly one `0`; in a fast-only batch appends none; a quic-plugin retract appends none |
| ring append through the map | a single-ping append while a batch sample is staged does not lose either (the `get`+`push` path) |
| group disjointness | a `STAB`-only patch does not write traffic/latency/error columns; a `TRAFFIC`-only patch does not write mask/len |
| index shape | the DDL carries `rank_stab` between `rank_bin` and `rank_weight DESC`, and `rank_proven` trailing; a new name, so an existing database cannot keep the old index |
| planner gate (turso, `tests/turso_planner.rs`) | Active / Purgatory / All / Successful-scoped plans are seek or covering scan, `USE SORTER` absent |
| upgraded-database anchor | `profiles_anchor` on a database whose `rank_stab`/`rank_proven` came from the DEFAULT (both directions, three offsets) does not error |
| clear-all | `clear_all_stats` leaves `stab_len = 0` everywhere |
| version rebuild | a bumped input version recomputes `rank_stab`/`rank_proven` at open; a matching one does not |
| page projection | 25 columns decode in `PAGE_PROJECTION` order (drift test); `stab_mask`/`stab_len` populate the decoded `ProfileStats` |

## 10. Acceptance

1. Real failure on a proven link: the endpoint remains in `Successful`; its
   `stab_bin` worsens by one sample; the row's Test cell shows the failure
   marker.
2. Real success after failures: the endpoint is in `Successful`; `stab_bin`
   reflects the ratio (neutral while `len < 4`).
3. Never-probed and warm-up links: `stab_bin = 4`, `rank_proven = 0`.
4. A fast-only batch changes no `stab_mask`/`stab_len`/`stab_bin`.
5. Page EXPLAIN for Active / Purgatory / All / all four scoped walks uses an
   index with no sorter.
6. A tag-18 database opens with no wipe; its previously-successful endpoints
   are still in `Successful` after the seed.
7. Panel shows `successes/attempts` per link; the main row is unchanged.
8. Authority docs state the shipped law: two keys with `stab_bin`; three-layer
   ordering; Successful = proven, not last-ok-only; the index and its trailing `rank_proven`; the
   constants.

## 11. Non-goals

- Merging `endpoint_rank` into `endpoints`; `WITHOUT ROWID`; FK cascade.
- Counting fast successes as stability successes.
- Replacing purge or the Active band with stability.
- A durable `proven` bit / an eviction threshold richer than "no `1` left".
- Any user-tunable threshold, and any visible stability score outside the panel.
- Gating Remove Bad Servers on stability.

## 12. Authority docs that move in the same change

- `docs/ordering_law.md` — §1.1/§1.2 keys, §2 (add `stab_bin`), §3.1
  (three-layer rule; delete "weight outranks latency"), §5 (one index, predicate inline), §6
  (proven scopes + the Remove Bad Servers note), §8 (measurements), §9 (retired
  names).
- `docs/database.md` — the `endpoint_rank` entity block, the
  `profile_stats` column list, both index rows, the query map.
- `docs/database-manual-sql.md` — the four added columns (cause + the
  tolerated-ALTER mechanism), the new `endpoint_rank_key_v2` index and the
  dropped v18 name, the seed statement, and the `RANK_COLUMNS`/conflict-SQL
  entries.
- `AGENTS.md` decision 16 — the key text, the bins/bands paragraph, the
  Successful scope sentence.
- ADR 0003 — a superseding amendment (the key gains a term; `rank_proven`
  carries membership; one index replaces one). ADR 0006 — the purge
  interaction.
- `docs/aegis/INDEX.md` — register this spec and the amendment.

## 13. Open items (resolved on implementation, 2026-10-09)

- **Boundaries** — shipped as the §5.1 table; one function, monotonic, pinned by
  `stab_bin_maps_every_boundary_to_its_bin` and
  `stab_bin_is_monotonic_in_successes_at_every_length`.
- **`KEY_INPUTS_VERSION`** — a new constant (`weight::WEIGHT_VERSION * 100 +
  STAB_VERSION`), so one stamp covers both input families. `rank_weight_meta` is
  reused rather than a second table.
- **Phasing** — DB + law first, UI second, as the plan's task order.

Two things the implementation settled that the spec left open, recorded here
rather than silently:

- The **producer split** (§7.1's table says which events sample, not who stages
  them): the batch stages the sample for its own links and the events handler
  only for single pings, because the handler holds the loaded page and a batch's
  rows are off-page there. Sampling in both would count each batch probe twice.
- An **untestable refusal** is excluded by its own prefix, so the capability gate
  cannot accrue attempts for a row no probe ever touched.
