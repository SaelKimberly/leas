# 0006 — Purge evidence is persisted per link; Purgatory is "not confirmed live and recent"

Date: `2026-09-17`
Status: `accepted`
Supersedes: nothing
Related: `specs/2026-09-17-purge-reason-design.md`,
`plans/2026-09-17-purge-reason.md`, ADR 0002 (column groups), ADR 0003 (stored
ordering keys), decision 4 (the schema tag), decision 16 (the ordering law),
decision 20 (the native real probe).

## Context

A real probe can return evidence that a config can **never** work again: a
REALITY endpoint answering with a real certificate, a certificate the
configured SNI cannot match, a port answering cleartext, a proxy whose own
upgrade handshake answers `404`, a CDN answering `530` because the origin is
gone. Before this decision that evidence was discarded into
`profile_stats.error`, a marker the `error_ttl_hours` sweep deletes, so a
permanently dead config sat in the Active view forever, competing for attention
with configs that work. On the reference corpus 1,687 links of 56,140 carried
such evidence at the time of the design (739 links over 362 endpoints on the
snapshot taken mid-re-run — the number moves with every probe run).

## Decision

1. **The unit of purge is the LINK** (`protocol_id`, `endpoint_id`), not the
   endpoint: an endpoint with several protocols keeps its working ones.
2. **A new `profile_stats.purge_reason` column** holds the verdict —
   `PurgeReason`, seven fieldless variants, one nullable `TEXT` column with a
   `CHECK` list (schema tag 11 → 12, a WIPE under decision 4).
3. **The verdict is written by its own column group** (`LinkGroups::PURGE`,
   `0b010`). Not riding RESULT: `link_patch_conflict_sql` writes a FIXED column
   set from each patch's *snapshot*, so riding RESULT would let a phase-1 fast
   half — whose snapshot is the plan-time row — rewrite a verdict it never
   classified. That is exactly the clobber shape ADR 0002's groups exist to
   prevent, and the classifier becomes structurally the only producer.
4. **The evidence is typed where it failed, never parsed from the message.**
   `TlsError` splits name-mismatch/expiry/cleartext; `NativeError` gains those
   three plus `TransportRejected { detail, status }` at the five sites that
   render the peer's own HTTP status; `NativeError::evidence()` is one
   exhaustive match. The probe's TARGET leg (the probe URL's own TLS) reports
   plain `Tls` and carries no evidence — a target certificate says nothing
   about the config, and `target_leg_tls_failure_carries_no_evidence` pins it.
5. **The taxonomy is one function in the TUI crate** (`ops::purge::reason_for`):
   521/522/526/530 → `OriginUnreachable`; 301/302/400/403/404/405/409/410 →
   `TransportRejected`; the three TLS causes, `ConfigDefect` and REALITY
   fallback map one-to-one. Deliberately NOT purging: every timeout, dial/DNS
   failure, TLS alert, framing failure, `412`/`429`/`500`/`502`/`503`/`520`/`525`,
   and `not testable by the native engine` (a capability gap, not a verdict —
   the subprocess core may serve it).
6. **The ordering law gains one band**: `RankLink.purged` → tier 6, below every
   live band, so a purged link never represents the endpoint while a live link
   exists (`display_link_index`'s gate covers the `manual_protocol_override`
   branch, which the display rank alone could not); `compute_rank`'s
   `newest_seen` becomes the **live-only** maximum.
7. **Purgatory is one range**: `rank_newest_seen < now - ttl_days`, which
   covers the aged band AND endpoints with no live link (they report
   `NO_SEEN`). No `OR`, no second predicate column, no new index.
8. **A verdict is cleared by a data-carrying success only** — a real ping or a
   speed test. A TCP/UDP handshake cannot clear it, a feed-wide sweep never
   plans a purged link (phase 2 is the long pole at 2.6 results/s), and the
   selected-endpoint entry points keep them so a Purgatory row stays testable
   by hand. The `error_ttl_hours` sweep never touches it; `purge_expired` still
   deletes the profile once its newest link of any kind ages past
   `purgatory.retention_days`.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Encode the reason as an `error_text` prefix (the `UNTESTABLE_PREFIX` pattern) | The `error_ttl_hours` sweep deletes `error_text`, so a "permanent" verdict would vanish; the page predicate and the rank law would have to parse a string, which `docs/database-manual-sql.md` §1 forbids ("never a second owner of a fact") |
| Purge the whole endpoint on any verdict | Destroys the case the feature exists for: one endpoint, several protocols, only one real |
| Ride `LinkGroups::RESULT` (one less group bit) | See decision 3 — a silent clobber, currently only *incidentally* safe because plan/page snapshots happen to be fresh |
| A second predicate column (`rank_live`) plus an `OR` | Would defeat the window index and duplicate a fact the live-only `newest_seen` already carries |
| An `EXISTS (SELECT 1 FROM profile_stats WHERE purge_reason IS NOT NULL)` correlation in the page predicate | The correlated-subquery shape ADR 0001/0003 removed: the page would stop being a single index scan |
| Purge from the fast phase's hard failures (timeout/refused/no-route) | A transient network condition, not a statement by the server; 31,020 links carried one on the reference run |
| Purge `not testable by the native engine` | It is a statement about THIS engine, not about the config — the subprocess core can serve those rows |
| A migration for the new column (additive `ALTER TABLE`) | **Superseded by ADR 0012 D-C (2026-10-08):** the project DOES have migration machinery now — `PRAGMA user_version` is a cursor, a supported older version applies the pending steps, and only an unknown cursor wipes. This row's original reason ("the project has no migration machinery… decision 4") no longer holds; the row is kept for the record because the alternative it rejected (an ad-hoc `ALTER` outside the cursor) is still wrong. The `purge_reason` column itself still ships as a schema-tag bump, because the *CHECK list* it needed is a table rebuild (decision 2) — that part of the row stands. |

## Consequences

- **A schema bump wipes the database.** Accepted: the verdicts are re-derived
  by the next Real run, and the reference classification was extracted to
  `/tmp/xray-tui-tag11-backup/purge-classification.csv` before the bump.
- The Active view sheds dead configs automatically, and the tab's Test column
  says *why* for the rows that remain visible in Purgatory.
- A wrong verdict costs one manual real test to undo; a too-timid taxonomy
  costs one function's edit (`reason_for`) with no schema change.
- The three retirements this implies: `PurgatoryView::Stale`,
  `PageRequest.stale_threshold`, and the never-read `PurgatoryConfig.enabled`.
- ADR 0002's group contract is now three groups wide, and
  `apply_link_patches_isolates_column_groups` pins the new one.


## Note — 2026-09-22: two refinements inside `reason_for`, no taxonomy change

Spec: `2026-09-22-native-testability-improvement-design.md` (T5).

This ADR's premise — "a taxonomy revision costs one function, not a schema change" — held
exactly: both refinements landed inside `reason_for(FailureEvidence)`, with **no new
`PurgeReason` variant** (the column is a `TEXT CHECK` over 7 variants, so a new one is a
schema-tag bump, and a bump makes `Database::open` delete the file).

1. A malformed REALITY config (missing/!32-byte `pbk`, malformed `short_id`) now raises
   `NativeError::Config` instead of `Reality`, so it maps to `ConfigDefect` → `config_invalid`
   rather than `RealityFallback`. A verdict about the peer when the peer was never reached is
   the misclassification this ADR's typed-evidence rule exists to prevent.
2. `reason_for` takes the link's `fp` and returns `None` when it is an approximation: the probe
   dialled a shape the link did not ask for, so its failure is evidence about a config that was
   never tried. The predicate is shared with the row label and with `security::wrap` — but their
   INPUTS differ: `security::wrap` (the dial) resolves `opts.fp` off the CONFIG, while the label
   and `reason_for` read the `security_fp` COLUMN. The column is written from that same `tls.fp`
   at parse time (`state::security_embed`), so the two agree only because of that projection, and
   `the_security_fp_column_agrees_with_the_config_field` is the guard on it.

## Note — 2026-09-22: the class names the STAGE, not the wrapper

Spec: `2026-09-22-native-testability-improvement-design.md` (T6).

`FailureEvidence` did not change. What changed is the CLASS a failure is counted under: a tunnel
that ends under a later phase is now `NativeError::TunnelClosed` → `ProbeClass::Protocol`, not
`Tls` (which is what the engine's `TlsError::Io` wrap produced). `evidence()` is `None` for it,
exactly as for `Tls`, so this refines reporting without touching what a failure proves.

## Amendment — 2026-10-21: an auth rejection earns NO purge verdict

Spec: `2026-10-21-merged-test-pipeline-design.md` (D9). ADR: `0014`.

The merged probe records a new fact: **the Auth flag** — a quad-state success flag (`ok` /
`failed` / `n-a` / `unknown`) saying whether the server ACCEPTED this config. Its `failed` state is
defined as *positive* rejection evidence, which is the shape decision 4's typed-evidence rule
describes. So the question this ADR must answer is: does that observation earn a purge verdict?

**It does not.** An auth rejection is recorded as the Auth flag plus a `[real]` marker, and the row
**stays in Active**. No `FailureEvidence` arm and no `PurgeReason` variant are added.

Three reasons, in the order they matter:

1. **The signal is not unambiguously positive.** For hysteria2 it is (an explicit non-233 h3
   status), and even there a non-233 may be the server's **masquerade** page answering a
   non-hysteria request — a hijacked IP, not a wrong credential. For VLESS/VMess, "the connection
   ended before the ack" is indistinguishable from a crash or a middlebox kill. sing-box writes the
   VLESS response header **lazily** (only before the first application-data write), so an unobserved
   ack is not a rejection at all — which is why the flag's `failed` state requires positive
   evidence and an unobserved ack is `unknown`.
2. **A false positive DELETES a working profile.** "Remove Bad Servers" deletes the row. A config
   that worked yesterday and whose server restarted badly today would be gone, and no later run
   would have proved it good.
3. **The column is CHECK-frozen.** `PurgeReason` is "one nullable TEXT column and one CHECK list"
   (decision 2), so a new variant forces a `profile_stats` table rebuild — the largest table in the
   schema — for a signal that is not yet trustworthy.

Decision 8 is unaffected and still governs: a verdict is cleared by a data-carrying success only.
The merged pipeline does not change that — a transport handshake (the Fast Test, and stage 1 of
the merged probe) still cannot clear a verdict, and the Fast Test still earns none.

**Revisit condition.** Measure the Auth-flag distribution per server family once the merged probe
lands. If `failed` is observed on rows that later succeed, the flag is unsound and must be
dropped. If it is observed overwhelmingly on never-succeeding rows, a typed
`FailureEvidence::AuthRejected` plus a `PurgeReason` variant becomes worth the rebuild. Until then
the flag is a diagnostic, not a verdict.
