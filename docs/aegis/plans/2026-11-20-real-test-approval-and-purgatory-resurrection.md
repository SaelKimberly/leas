# 2026-11-20 — Real Test as approval, and a Purgatory resurrection sweep

Status: `implemented 2026-11-20` (design approved in session 2026-11-20: clock owner = widen
`last_seen_at`; entry point = new menu item; sweep population = aged **and** purged)
Owners: `leas-db` (patch groups, band), `leas` (result mapping, plan walk, menu)
Surface: ADR 0006 decisions 7 and 8 (amendment required), `docs/reference/database.md` §`profile_stats`

## Problem

Purgatory is one range over the newest **live** link's `last_seen_at`
(`profiles_query.rs:610`, bound `now − purgatory.ttl_days` = 7 d). `last_seen_at` has exactly two
writers today: the import/refresh upsert (`database.rs:869`, `LINK_SOURCE_CONFLICT_SQL`) and
`Database::update_last_used` on a real dial (`database.rs:1564`). **No probe writes it**, and it
belongs to no `LinkGroups` bit, so a test physically cannot refresh it.

Consequences, both confirmed in the tree:

1. A config whose last real probe succeeded this morning, and which the feed no longer re-lists
   (or which was imported once and never re-fetched), falls from band 1 to band 2 on day 8 and its
   Test column stops claiming anything — a success is not an approval.
2. A purged link is invisible to every batch: the plan walk loads the page with
   `load_page_projection(&ids, false)` (`ping.rs:1666`), so the only way to re-prove a Purgatory row
   is to select it by hand while the Purgatory/All view is loaded. There is no bulk resurrection.

`purge_expired` (retention, 30 d) keys on the same column (`database.rs:1824`), so today a working
config is deleted 30 days after the feed stopped mentioning it, regardless of passing probes.

## Decisions (user-owned, answered)

- **D-A — Clock owner: widen `last_seen_at`.** A data-carrying success (Real Test, Speed Test)
  stamps it. No schema change, no new ordering key: `rank_newest_seen`, `band` and the retention
  cutoff all derive from the column already. Accepted cost: `last_seen_at` now means "the source
  listed it **or** we proved it works", so a config dropped from its feed but still passing tests
  stays Active.
- **D-B — Entry point: a new `Real Test (Purgatory)` menu item.** The feed sweep's purge skip
  (ADR 0006 D8) stays intact; only this explicit action re-proves band-2 links.
- **D-C — Population: band 2 in full** — the aged-but-healthy link (verdict NULL) and the
  permanently purged one (`purge_reason` set). A verdict is a guess; a passing probe is proof.
- **D-D — Ordering: reuse `FEED_SORT`.** No second ordering law. (The interview sketched
  "newest `last_seen` first"; dropped — retention protection comes from D-A, and a bespoke sort
  would be a new ordering law for one menu item.)
- **Non-goal: no automatic keep-alive.** Nothing schedules probes today; the 7-day TTL keeps its
  meaning ("not confirmed live and recent") and still expires configs nobody tests. Adding a timer
  is a separate decision.

## Design delta

### 1. `LinkGroups::SEEN` (`crates/leas-db/src/database.rs`)

- New bit `0b10000`; `ALL = 0b11111`; `link_patch_conflict_sql` grows one SET line under it:
  `last_seen_at = MAX(excluded.last_seen_at, profile_stats.last_seen_at)` — monotone, same
  convention as `merge.rs`. `Vec::with_capacity(16)` → `17`.
- Why a group and not RESULT: the fixed-column-set rule (ADR 0002). A fast half stages its own
  patch from a plan-time snapshot; riding RESULT would let it rewrite the stamp it never measured.
- The import writer keeps its unconditional `last_seen_at = excluded.last_seen_at` (its snapshot is
  a fresh parse, so it only moves forward).

### 2. `apply_test_result` stamps the approval (`crates/leas/src/ops/events.rs:149`)

- On the success tail, under the existing `config_evidence` predicate
  (`RealPing | SpeedTest`) — one predicate, no second rule:
  `row.last_seen_at = leas_db::models::now_epoch();` and union `LinkGroups::SEEN` into the returned
  groups (both success returns: plain, and the verdict-cleared one).
- Failure path, `Cancelled`, and the merged probe's transport-stage failure: untouched. A `TcpPing`
  / `UdpTest` success still proves nothing (ADR 0006 D8).
- Both call sites (`ping.rs::stage_result`, `events.rs` UI half, `speed_test.rs:389`) already forward
  the returned groups, so no caller changes.

### 3. Plan source (`crates/leas/src/ops/ping.rs`)

- `PlanSource::Purgatory`; in `PlanWalk::next_page` it builds
  `PageRequest { view: Purgatory, active_threshold: now − purgatory_ttl_secs, … }` and loads the page
  with `load_page_projection(&ids, true)` — the one flag difference from the feed arm.
- `start_batch_then_real_ping_purgatory()` = `start_batch(state, PlanSource::Purgatory, true, dedup)`,
  dedup flag as in `start_batch_then_real_ping`.
- The frozen id list still makes the walk stable while resurrected rows leave band 2 mid-run.

### 4. Scheduler + menu (`crates/leas/src/ops/job_scheduler.rs`, `crates/leas/src/ui/mod.rs`)

- `TaskKind::RealTestPurgatory` (its own kind, like `MultiRealTest`: it is a distinct spawn path and
  its dedup identity must not collide with `Real Test (All Profiles)`), `dispatch` arm,
  `scope_is_empty` arm using `view = Purgatory` so a queue head with nothing left is skipped.
- One menu row after `Real Test (Failed)`; one handler arm. No enable/disable logic beyond the
  existing scheduler gates.

### 5. Docs

- ADR 0006: dated amendment — D8 now reads "a **feed-wide** sweep never plans a purged link; the
  explicit `Real Test (Purgatory)` action does", and D7's clock gains "or a data-carrying success".
- `docs/reference/database.md:300` (`last_seen_at` meaning) and `:461` ("the column-group split
  already keeps `last_seen_at` out of the RESULT patch" → now `SEEN`).
- `docs/INDEX.md` / `docs/aegis/INDEX.md` row for this plan.

## Acceptance criteria

1. Aged, healthy link (verdict NULL, `last_seen` 8 d old, band 2): a Real Test success leaves
   `purge_reason` NULL, `last_seen_at ≈ now`, and the next page load reports band < 2.
2. Purged link reached by `Real Test (Purgatory)`: success clears the verdict **and** re-bands it;
   a failure leaves the verdict and the band alone.
3. `Fast Test` and `UDP Test` successes do not move `last_seen_at`; `Speed Test` success does.
4. `Real Test (All Profiles)` still plans zero purged links (guard on ADR 0006 D8).
5. `purge_expired(cutoff)` does not delete an endpoint whose newest link was just stamped by a test.
6. A `SEEN` patch cannot move a stored `last_seen_at` backwards (MAX).

## Verification

- `cargo nextest run -p leas-db apply_link_patches_isolates_column_groups`
- `cargo nextest run -p leas-db purgatory` / the band integration rows in `crates/leas-db/tests/integration.rs:472`
- `cargo nextest run -p leas apply_test_result` and the new plan/menu rows
- `just quality-gate code`
- Manual: Purgatory view populated, menu item runs, rows leave the tab as they pass.

## Risks

- `last_seen_at` now advances on test activity, so the recency tiebreak and the refresh-age labels
  move with it. Intended, but it changes ordering visibly after a big sweep.
- Two writers on one column: the import's unconditional SET and the patch's MAX. Both monotone; the
  only loss shape would be an import parse-time stamp older than a test stamp, which MAX prevents.
- A Purgatory sweep re-probes links the classifier judged dead — the real phase is the long pole
  (~2.6 probes/s). Sized by the band, not by the menu.
- Band/retention now depend on probe cadence: a user who never tests still loses configs at 7/30 d.

## Executed 2026-11-20

Landed as designed (`LinkGroups::SEEN`, the stamp in `apply_test_result`, `PlanSource::Purgatory`,
`TaskKind::RealTestPurgatory`, the menu row, the ADR amendment, `database.rs`/`tui-manual.md`).

One defect the plan did not foresee, found by the new isolation test:
`apply_link_patches_tx` bucketed patches over a hand-copied **four-bit** presence vector, so a patch
carrying only `SEEN` matched bucket 0 and its `DO NOTHING` action dropped it — the stamp would have
looked written and never reached the file. The loop now bounds on `LinkGroups::ALL.0` and compares
`groups` to the bucket directly, so a sixth group cannot repeat it.

A second, larger instance of the same shape was found in review and fixed: `WriteBehind`'s `stage`,
`coalesce`, `restage_patch` and `merge_group` each enumerated the four old groups, so a `SEEN` patch
was discarded before the writer saw it and the feature was inert end to end — `last_seen_at` never
moved, `band` never changed, and both of the tests above still passed because they stop at
`apply_link_patches`. One `GROUP_FLAGS` list now feeds every fold, `merge_group` has its explicit
`SEEN` arm, `the_fold_list_covers_every_group_bit` guards the list, and
`link_flush_writes_the_seen_stamp_and_no_other_column` is the driver-level seam test.

Tests: `apply_link_patches_isolates_column_groups` (the newer stamp lands first, so only a monotone
write can hold it; no other group written), `a_data_carrying_success_stamps_the_approval` (real +
speed stamp; fast and failure do not), `the_purgatory_walk_plans_both_band_two_populations` (aged and
purged planned by the new source; the feed sweep still skips the purged link),
`link_flush_writes_the_seen_stamp_and_no_other_column` (the driver, not just the SQL) and
`the_fold_list_covers_every_group_bit`.
