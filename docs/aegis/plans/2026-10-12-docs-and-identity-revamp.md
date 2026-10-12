# Documentation & Identity Revamp — Implementation Plan

- **Status:** draft — awaiting author review before execution
- **Date:** 2026-10-12
- **Approved basis:** `docs/aegis/specs/2026-10-12-docs-and-identity-revamp-design.md` (approved 2026-10-12; decisions D1–D13, §11 resolved)
- **Route:** inline execution (`executing-plans`); Phase 1 (mechanical) MAY be delegated within the phase, Phase 2 is inline (judgment).

## Goal

Deliver a `leas`-identified repository with a kind-first documentation wiki (each folder carrying an `INDEX.md`), under a synthesize-then-delete history policy, and make the workspace publishable to crates.io. `docs/aegis/**` stays frozen.

## Aegis Visibility

A durable plan is warranted because the change is a public-contract surface (crate/binary/env/config-dir names become crates.io-visible) plus a repo-wide destructive migration (53 files hard-deleted) — both need one reviewed ordering before any edit.

## Requirement Ready Check

- Source: the approved Design Spec (§2 acceptance, §6 rename, §7 map, §8 history, §9 publishing).
- Scope/non-goals: §2. Acceptance: §2 criteria 1–7. Decision-changing gaps: none (D1–D13 all resolved).

## Baseline / Authority Refs

`AGENTS.md` (rewritten this plan), `docs/aegis/BASELINE-GOVERNANCE.md` §1, `docs/aegis/INDEX.md`, `docs/aegis/baseline/2026-09-11-initial-baseline.md` (do not edit), the Design Spec.

## Compatibility Boundary

- **Breaking, accepted (pre-alpha):** binary name, crate names, `XRAY_TUI_*`→`LEAS_*` env vars, `~/.config/xray-tui`→`~/.config/leas`, tracing target, User-Agent. No config-file migration is provided (documented as a deliberate break).
- **Preserved:** `docs/aegis/**` byte-identical; `thirdparty/**` untouched; local-only ad-hoc files untouched on disk.
- **Pinned by frozen citations:** nothing is *moved* that a frozen aegis doc cites (D13).

## TDD Route

- Mode: `off` (no explicit TDD request). Decision: **skipped**.
- Compensating verification: the rename is proven by a zero-hit identifier grep + `cargo build --release` + `cargo nextest run --workspace` + `just quality-gate`; the doc restructure by the citation + completeness checks. No new behaviour is introduced.

## Change Necessity

Code change is required (crate/package/env/config-dir identifiers are code, not docs). Doc/structure change is required (the wiki + deletes). Minimum boundary: identifier strings + file moves/renames + deletions; no logic change.

## Ripple Signal Triage

Fires (distribution/release + public contract + retirement): crate names become published artifacts; `docs/superpowers/**` retirement; `AGENTS.md` loses the product-baseline role. Canonical owners: `Cargo.toml` files (naming), `docs/aegis/BASELINE-GOVERNANCE.md` §1 + new baseline (product baseline), `docs/INDEX.md` (wiki hub). Verified by §2 acceptance.

## Plan Pressure Test

Owner/contract/retirement fit OK; no higher-level simplification outstanding; verification scope is exact (greps + cargo + citation check); tasks are executable. Proceed.

---

## Tasks

### Phase 0 — Guardrails

**T0.1 — Unlink `CLAUDE.md`.**
- Files: `CLAUDE.md` (symlink).
- Change: delete the symlink (`CLAUDE.md`→`AGENTS.md`). Do not create a replacement; `CLAUDE.md` is user-authored (D10).
- Verify: `CLAUDE.md` absent; `AGENTS.md` intact.

**T0.2 — Repositioning baseline + registry.**
- Files: ADD `docs/aegis/baseline/2026-10-12-leas-repositioning.md`; EDIT `docs/aegis/INDEX.md`.
- Change: new baseline records the repositioned north star + the identity change (D6); add rows for the Design Spec and this plan.
- Verify: `docs/aegis/INDEX.md` lists both new artifacts; the 2026-09-11 baseline is unchanged.

**T0.3 — `BASELINE-GOVERNANCE.md` §1 realignment (user review required).**
- Files: `docs/aegis/BASELINE-GOVERNANCE.md`.
- Change: §1's Product/Requirement Baseline currently names `AGENTS.md`; re-point it to the new baseline + `docs/INDEX.md`. **Requires explicit user review** (the file says it is never auto-updated).
- Verify: user approval recorded; no other § changed.

### Phase 1 — Rename to `leas`

**T1.1 — Crate directories, package names, workspace deps, hakari.**
- Files: `crates/xray-tui*` → `crates/leas*` (12 dirs); every `Cargo.toml`; root `Cargo.toml` `[workspace.dependencies]`; `.config/hakari.toml` (`hakari-package`).
- Change: `git mv` dirs; rename `name = "leas*"`; update path deps and workspace-dotted entries; `leas-hakari` keeps `publish = false`; then run `cargo hakari generate` so the hack manifest's `name`/description are regenerated (the `hakari-check` `generate --diff` gate would otherwise flag it).
- Verify: `cargo metadata` resolves; `cargo build` compiles the workspace skeleton.

**T1.2 — Rust module paths.**
- Files: 137 `.rs` files containing `xray_tui_*`.
- Change: `xray_tui_*` → `leas_*` in `use`/paths.
- Verify: `grep -rIl 'xray_tui' crates --include=*.rs` → 0.

**T1.3 — Runtime identifiers.**
- Files: ~30 `XRAY_TUI_*` sites (`.cargo/config.toml`, benches, tests, `.rs`, justfile, docs), the 5 `join("xray-tui")` sites, tracing targets, `updater.rs`/`probe.rs` User-Agent.
- Change: `XRAY_TUI_*`→`LEAS_*`; `join("leas")`; tracing target `leas`; UA `leas`/`leas/probe`.
- Verify: `grep -rIl 'XRAY_TUI'` → 0 (in scope); binary is named `leas`.

**T1.4 — Docs prose (in-scope only).**
- Files: root `*.md` + `docs/**` **minus** `docs/aegis/**` and the local-only set.
- Change: identifier strings `xray-tui`→`leas`, `xray-tui-*`→`leas-*`.
- Verify: `grep -rIl 'xray-tui' --exclude-dir=aegis` → 0 outside exclusions.

**T1.5 — Frozen-exclusion guard + full verification.**
- Change: none (verification).
- Verify: `grep -rIl -e xray-tui -e xray_tui -e XRAY_TUI` over the codemod scope = 0 outside `docs/aegis/**`, `docs/superpowers/**`, `thirdparty/**`, local-only; `cargo build --release`; `cargo nextest run --workspace`; `just quality-gate` (or its pre-existing-red delta noted).

### Phase 2 — Documentation restructure

**T2.1 — Skeleton + hubs.**
- ADD `docs/INDEX.md` + one `INDEX.md` per folder (`architecture/`, `guides/`, `reference/`, `history/`, `research/`).
- Verify: every folder has an `INDEX.md` listing its files.

**T2.2 — Move root topic docs** (lowercase-hyphen, D11): `ARCHITECTURE.md`→`architecture/architecture.md`; `NATIVE_CORE.md`→`reference/native-core.md`; `docs/native-core-integration.md`→`architecture/native-core-integration.md`; `ROADMAP.md`→`history/roadmap.md`; `TUI_MANUAL.md`→`guides/tui-manual.md`.
- Fix in passing: `architecture.md` drop `ping_sessions`/`subscriptions`; `tui-manual.md` fix stale test-column + "dual-backend" intro; `roadmap.md` slim to history.
- Verify: `git mv` history preserved; no broken internal links.

**T2.3 — Move `docs/*`** to `reference/` (database, database-manual-sql, ordering-law, crypto-dependencies, protocols, clash, tls-fingerprint-roster), `research/` (amiabot-roster-report, dry-normalization-plan), `history/` (routing-engine-decision). **Review note:** `review-by-expert-1/2` are local-only (D13) — not moved, not referenced.
- Verify: map match.

**T2.4 — Dissolve the duplicates (D4).**
- DELETE `docs/agents-reference.md`; fold durable content → `architecture/decisions.md`.
- DELETE `CONTEXT.md`; glossary → `reference/glossary.md`, decisions → `architecture/decisions.md`.
- Rewrite `AGENTS.md` to drop the `docs/agents-reference.md` pointer and any local-only reference (`STAB_BIN.md`).
- Verify: no dangling pointers; `AGENTS.md` is context-only.

**T2.5 — History synthesis + delete (D12).**
- ADD `history/superpowers.md` (lineage note: each pre-Aegis design + its aegis successor).
- DELETE `docs/superpowers/**` (53 files) after synthesis.
- Verify: `git ls-files docs/superpowers` empty; the synthesis names every deleted design.

**T2.6 — Anonymize local-only citations (D13).**
- Files: editable docs citing `.git/info/exclude` paths — `docs/database-manual-sql.md` (dump-*), `ROADMAP.md`/`history/roadmap.md` (Expert/PDF/dump), `AGENTS.md`.
- Change: keep the measurement/fact, drop the filename (e.g. "measured 145 ms" not "(145 ms, dump-3.log)").
- Verify: `grep -rn 'dump-[0-9]\|Expert [0-9]\|Database Performance Lab\|review-by-expert\|STAB_BIN\|coding-agent-transcript'` over editable docs → 0; `docs/aegis/**` untouched.

**T2.7 — README front door (D9).**
- Rewrite root `README.md` = `# leas` + ≤2 sentences + one link to `docs/INDEX.md`.

**T2.8 — Citation + completeness check.**
- Verify: every path cited by a surviving doc resolves; `git ls-files '*.md'` all appear in the map (§2 criterion 6).

### Phase 3 — Publishability

**T3.1 — LICENSE.** ADD MIT `LICENSE`; keep `license = "MIT"`.
**T3.2 — READMEs.** ADD per-crate `README.md` (`# leas-<x>` + ≤2 sentences) + `readme.workspace = true`; ADD `docs/guides/publishing.md`.
**T3.3 — Metadata.** `[workspace.package]`: `repository`, `authors`, `homepage`. Per crate: `description` (required), `keywords`, `categories`.
**T3.4 — Proof.** `cargo hakari remove-deps` → `cargo package -p <leaf>` (×5: leas-proto/-tls/-dns/-geoip/-host-features) → `cargo hakari manage-deps`. Record the topological `cargo hakari publish` order in `docs/guides/publishing.md`.

### Phase 4 — Claim audit (separate plan)

Per-topic verification of surviving `reference/`/`architecture/` pages against code (D2 phase 2). Own plan, one topic per task.

---

## Verification (frozen-command summary)

1. `grep -rIl -e 'xray-tui' -e 'xray_tui' -e 'XRAY_TUI'` → 0 outside `docs/aegis/**`, `docs/superpowers/**`, `thirdparty/**`, local-only paths.
2. `cargo build --release`; `cargo nextest run --workspace`; `just quality-gate`.
3. Every folder has `INDEX.md`; `git ls-files '*.md'` all mapped.
4. No editable doc cites a `.git/info/exclude` path.
5. `cargo package` green for the five leaves; publish order documented.

## Retirement

- `docs/superpowers/**` — deleted (D12), after synthesis.
- `docs/agents-reference.md`, `CONTEXT.md` — dissolved (D4).
- Old identifiers (`xray_tui*`, `XRAY_TUI_*`, `~/.config/xray-tui`) — fully retired in one rename commit; no aliases kept.

## Risks

Partial rename into a frozen tree (guarded by the grep); broken citations across the move (guarded by T2.8); non-leaf publish proof impossible offline (staged publish / local registry); crates.io squatting on the 12 free names (publish promptly).

## Execution route

`inline` via `executing-plans`. Phase 0 + T1.1–T1.5 must land as one atomic rename before Phase 2 begins (rename-before-restructure, D6).
