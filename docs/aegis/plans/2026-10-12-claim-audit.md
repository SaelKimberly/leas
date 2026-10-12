# Claim audit — implementation plan

- **Status:** draft — awaiting execution
- **Date:** 2026-10-12
- **Parent:** `docs/aegis/specs/2026-10-12-docs-and-identity-revamp-design.md` (Phase 4, D2 phase 2)
- **Route:** inline (`executing-plans`); one topic per task/commit.
- **TDD Route:** mode `off`; decision `skipped` (documentation only). Verification = claim-by-claim check against code/ADRs at HEAD.

## Goal

Every surviving `docs/{architecture,guides,reference}/` page states only what the code does at HEAD. Where a claim is stale: fix it in place, or — if the claim documents a retired design — move it to `history/`. `docs/aegis/**` is frozen and out of scope.

## Scope

In: `docs/architecture/*`, `docs/guides/*`, `docs/reference/*`, `docs/history/roadmap.md` (slim). Out: `docs/aegis/**`, `docs/research/*` (evidence, not authority), the local-only files.

## Acceptance (per task)

A claim is *verified* when it is checked against the cited code symbol / ADR / schema at HEAD; the task is done when no unverifiable or contradicted claim remains in the page and every path it cites resolves.

## Tasks (one topic each)

| # | Page(s) | Known audit leads |
|---|---|---|
| T4.1 | `architecture/architecture.md` | `ping_sessions` block + fast-ping queue claim just fixed; re-read whole page for other retired-design prose; confirm the `SpeedTestResult`/`PlanScope`/`rank_tier` wording matches the binned law |
| T4.2 | `architecture/decisions.md` | Confirm each decision maps to current code; confirm "11 tables" and cursor 18 |
| T4.3 | `architecture/native-core-integration.md` | Marked *superseded in part* (ADR 0004, `ops/connect.rs`) — decide inline fix vs `history/` |
| T4.4 | `reference/database.md` | Table/index/flow claims vs `models_toasty.rs` + `schema/`; the `user_version` cursor text |
| T4.5 | `reference/database-manual-sql.md` | C3–C6 marked "unverified against toasty 0.11" — verify or annotate |
| T4.6 | `reference/ordering-law.md` | Law text vs `endpoint_rank.rs` / `weight.rs` / `profiles_query.rs` |
| T4.7 | `reference/crypto-dependencies.md` | Each site + advisory trigger vs the manifests |
| T4.8 | `reference/protocols.md` | Dated 2026-07-08; `PlaceholderConfig` stub rows are now typed configs — re-verify the coverage matrix and per-protocol fields |
| T4.9 | `reference/clash.md` | Upstream mihomo/quirktiva version drift |
| T4.10 | `reference/native-core.md` | Capability tables + tier counts vs `capability.rs` / e2e |
| T4.11 | `reference/tls-fingerprint-roster.md` | Roster count + JA4 claims vs the generated roster |
| T4.12 | `reference/glossary.md` | Term definitions vs current types |
| T4.13 | `guides/tui-manual.md` | Test-column + backend-intro just fixed; audit remaining column/key claims |
| T4.14 | `history/roadmap.md` | **Slim to history**: keep measurements, drop superseded phase detail (carried from the revamp plan T2.2) |

## Verification

Per task: the page's claims are checked against the named code; any cited path resolves (`git ls-files`); the page carries no claim contradicting HEAD. A final pass re-runs the citation check over `docs/{architecture,guides,reference}/`.

## Risks

- Docs-only, so no runtime risk; the residual risk is an *unverified* claim that looks verified — mitigate by citing the exact symbol/ADR for each audited claim in the task's commit message.
