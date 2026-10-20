# Design: Stability Keeps a Stable Server Alive

- **Date:** 2026-10-20
- **Status:** approved (grilling interview, same day)
- **Owners:** `crates/leas-db/src/endpoint_rank.rs` (the law), `crates/leas/src/ui/profiles.rs` (the column)
- **Amends:** `2026-10-09-stab-bin-design.md`, `2026-10-06-db-rewamp-design.md` (D11 link key), `docs/reference/ordering-law.md`

## 1. Problem

The ordering law sorts the representative link by `(delay_bin, stab_bin, …)`.
A link whose **latest real probe failed** is forced into the `real-err` band
(bin 13), which dominates `stab_bin` entirely. A server with a 16/16
stability ring and one recent failed real ping lands below every working
server — below a 1/16 server at 500 ms. Stability orders *inside* a bin but
never protects position. The user's intent when introducing stability was:
**stable servers stay on top even when the most recent real ping failed.**

Membership is NOT the problem: `rank_proven` (≥1 success in the 16-sample
ring) already tolerates transient failures, and purge is verdict-only by
design (`2026-09-17-purge-reason-design.md` §6/§7 — timeouts never purge).
This spec changes POSITION, not membership.

## 2. Root cause (code facts)

| fact | site |
|---|---|
| `RankLink::bin` maps `ProfileErr::Real \| Name → 13`, dominating stab | `endpoint_rank.rs` `bin()` |
| link key is `(bin, stab, ¬weight, -seen, protocol_id)` — bin first | `RankLink::key` |
| representative = min-key link | `compute_rank` |
| failed real probe keeps `latency` (last good delay) and sets `error.kind` | `ops/events.rs` `apply_test_result` |
| ring: per-link `stab_mask`/`stab_len`, newest sample is bit `len-1` | `endpoint_rank.rs` ring |

Because `latency` survives a failure, the "last good delay" needed for the
new law is already in the data; no new column, no schema change.

## 3. Decisions

### D1 — Membership unchanged
`Successful` = endpoint `rank_proven`; purge stays evidence-verdict-only.
No change.

### D2 — Link bin: error no longer dominates a known-good delay
New `bin()` law (per link):

| condition | bin |
|---|---|
| purged | 16 |
| endpoint DNS-unresolved | 15 |
| `ProfileErr::Fast` | 14 — UNCHANGED, all cases (the fast-error arm does not move to the new law: a fast failure never samples the ring, so "demote via stab" cannot express it; today's behavior is kept in full) |
| real-err (`Real`/`Name`), `!link.proven` — no real success anywhere in this link's ring window (never-succeeded, short all-failure ring, full-dead 0/16) | 13 |
| real-err, `link.proven`, latency is `Real` | real delay bin 0-5 — the approved last-good-real-delay rule |
| real-err, `link.proven`, latency is `Fast` | fast delay bin 6-11 (user re-approval Q7, 2026-10-20) |
| real-err, `link.proven`, no latency | 13 |
| no error | unchanged (real 0-5, fast 6-11, untested 12) |

Rationale: a recent failure is a stab-ring event (a `0` is appended), not a
band change. The err bands remain for links with nothing to fall back on.

**Per-link, not endpoint-level:** the bin-13 gate reads THIS link's ring via
its own `proven` (`stab_successes(mask, len) > 0`), never the stored endpoint
`rank_proven`, and it is NOT gated on a full window. A full-window-only gate
orphans a link with a fast-only latency and a short all-failure ring
(proven=0, bin 6-11 → no view matches); the `!proven` gate sends every
real-err link without a real success in its window to 13, which the Failed
filter (`bin ∈ 13,14,15`) always catches.

**Q7 re-approval (data limitation):** a fast success overwrites `latency`, so
a link's last-good REAL delay is unrecoverable once a later fast test
succeeded. For a proven real-err link whose stored latency is `Fast`, the
approved choice is the stored-latency bin (6-11), not a new persisted
real-delay field and not a forced 13.

### D3 — Representative: live-first
`compute_rank` picks the representative (min-key link) among links with
`!purged && latest_ok == Some(true)`; if no link qualifies, min-key over all
links (today's rule, where purged lose via bin 16 anyway).

**Purged links are excluded from the live subset on purpose:** a purged
link's ring is frozen at purge time, so its newest bit can still be 1 —
selecting on the bit alone could pick the purged link (bin 16) over a
non-purged failing sibling (bin 13) and drop the endpoint into Purgatory
despite a live sibling.

`RankLink` gains a `latest_ok: Option<bool>` field, derived ONCE in
`RankLink::new` from the new `stab_latest_ok(mask, len)` helper (`None` when
`len == 0`, else the newest ring bit `bit len-1`). The module invariant — the
law is implemented once in `RankLink`, and the panel order, stored keys, and
parity golden cannot drift apart — is preserved: representative selection and
the display-link rule both read the same derived field, neither re-derives
from raw masks.

Rationale: without this, a ghost link (old 40 ms real success, now failing)
out-keys a live slower sibling — key `(0, 7)` beats `(2, 0)` — and the
endpoint row would display the dead link's Test/Stab while the working
sibling is hidden.

### D4 — Display link: production paths own it; the retired helper goes
**Amendment (execution finding):** `endpoint_rank::display_link_index` had NO
production caller — the UI's Test/Stab link is
`EndpointRow::representative_link_index` (the D3 live-first law, shared via
`representative_index`), and `active_link` (`select_best_measured_link` +
manual override) owns the connect/marker/exit-IP link. Decision:

- `display_link_index` is DELETED (dead duplicate of the law).
- The main grid's Test and Stab cells both follow the REPRESENTATIVE link —
  one link, one rule, no drift between the two columns or against the stored
  page order.
- `select_best_measured_link`/`active_link` are UNCHANGED (connection choice;
  its purge gate already mirrors the law's eligibility). Wiring live-first
  into the connect target is NOT in this spec's scope.
- Pin precedence is unaffected: `active_link` checks the manual override
  first (existing behavior, tested in `models_toasty`).

### D5 — Main-grid "Stab" column after "Test"
The §7 grid gains an 11th logical column `(10, "Stab", 7)` after `Test`.

- Value: the REPRESENTATIVE link's ring (the same link the Test cell shows)
  as `n/window` (`12/16`), `—` when the link has no samples — the collapsed
  row reuses `stability_ratio`.
- Color: ≥80% success → `--success`; ≥50% → `--warning`; <50% → `--error`;
  `—` → muted. Same span-styling pattern as the Test column's latency
  thresholds.
- Drop order: after `Exit` (narrow terminals drop Exit, Out, White, then
  Stab before Address shrinks). `PROFILES_SORT_COLUMN` stays 7 — the Stab
  column is inserted after Test, so Test's logical id is unchanged.
- The panel sub-table already shows per-link stab; unchanged.

### D6 — Version bump, one rebuild
`STAB_VERSION: u32 = 2` → `KEY_INPUTS_VERSION` folds it → the first open
after this ships rebuilds `rank_weight`/`rank_stab`/`rank_proven` once
(existing mechanism, `rank_weight_meta` stamp). No new stored column: the
endpoint key terms are unchanged, only their derivation.

## 4. What does NOT change

- Ring semantics: `STAB_WINDOW`/`STAB_WARMUP`/`STAB_NEUTRAL`, append rules,
  real-only sampling.
- `stab_bin` thresholds and its `0..=7` coarsening.
- Purge policy (`ops/purge.rs`), `Remove Bad Servers` gating.
- Endpoint key term order (`band, bin, stab, ¬weight, domain, sub_domain,
  addr, id`) and the SQL `ORDER BY` / covering index — the columns mean the
  same things; only the numbers change.
- Membership/view filters (`rank_proven = 1`, `New` = 12, `Failed` =
  13/14/15) — with D2's per-link `!proven` gate, every real-err link with no
  real success in its ring lands in bin 13, so the Failed filter keeps
  catching it. No orphan partition.

## 5. Failure modes checked

| scenario | outcome |
|---|---|
| 16/16 stable, latest real ping failed | bin from stored latency, stab demotes within the bin — stays near top |
| link dies completely (0/16) | `!proven` → bin 13 → Failed view |
| short all-failure ring (e.g. 3 real fails, fast-only latency) | `!proven` → bin 13 → Failed view; no proven=0/bin 6-11 orphan |
| real success in ring, then fast success overwrote latency, then real fails | proven → stored-latency bin 6-11 (Q7) |
| ghost fast link + live slow sibling | live sibling represents and displays |
| purged link with fresh-looking frozen ring | excluded from live subset; loses via bin 16 |
| single-link failing server | keeps last-good values, sorts by its stab |
| fast-only link, fast ping fails | bin 14 unchanged — fast-error arm does not move |
| warm-up link (len < 4) | neutral stab 4, unaffected by this spec |

## 6. Tests

- `endpoint_rank.rs` unit table (`#[rstest]`): every D2 row — real-err
  `!proven` (never-succeeded / short ring / full-dead), real-err proven with
  `Real` latency, proven with `Fast` latency (Q7), proven without latency;
  fast-err unchanged (14 with and without latency); purged; DNS-unresolved.
- `stab_latest_ok`: empty ring `None`, newest-bit semantics below/at window.
- `compute_rank`: ghost vs live sibling — live sibling represents; all-dead
  endpoint falls back to min-key; purged link never enters the live subset.
- `display_link_index`: override first (even against live siblings), then
  live-first, then best measured; purged eligibility gate intact.
- Old-law pins to REWRITE deliberately (they assert the behavior this spec
  retires): `crates/leas-db/src/models_toasty.rs:1047`
  `fresh_failure_dominates_stored_success`, `models_toasty.rs:958`
  `select_best_measured_link_error_with_latency_still_measured`, the parity
  golden, and `profiles_query` expectations pinning `rank_bin = 13` for
  real-err-with-latency rows.
- `profiles.rs`: Stab column header/value/color rows; Test column position
  unchanged; drop-order test covers the new column.

## 7. Docs to sync at implementation time

- `docs/reference/ordering-law.md` — §2 link key, §2.1 stab bin, new §"the
  last-good-delay bin (2026-10-20)".
- `docs/aegis/INDEX.md` — this spec's row.
- `docs/guides/tui-manual.md` — profiles grid gains the Stab column.
