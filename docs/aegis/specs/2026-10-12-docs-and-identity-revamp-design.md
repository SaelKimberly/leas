# Documentation & Identity Revamp — Design Spec

- **Status:** draft — awaiting user review
- **Date:** 2026-10-12
- **Scope:** repository-wide (documentation structure + crate identity)
- **Authority affected:** `AGENTS.md`, `docs/aegis/BASELINE-GOVERNANCE.md` §1, `docs/aegis/INDEX.md`
- **Frozen by decision:** `docs/aegis/**` (structure and content), `thirdparty/**`

## 1. Summary

Two coupled changes, delivered in phases:

- **A — Identity:** reposition the project and rename it `xray-tui` → **`leas`** (Irish *ray/shine*), enabling a crates.io publication. The old north star ("feature parity with v2rayN") is replaced by "compatibility with the mainstream server backends, with a first-class TUI".
- **B — Documentation:** replace the three overlapping generations of docs (pre-Aegis `docs/superpowers/**`, current root topic docs, `docs/*.md`) with one kind-first wiki, each folder carrying an `INDEX.md`. Superseded material is **synthesized into brief history notes, then deleted** (lossless-by-construction floor, §8).

`docs/aegis/**` is the Aegis workspace and is **frozen**: not restructured, not renamed, not rewritten. The repositioning **adds** a new baseline; it never edits `docs/aegis/baseline/2026-09-11-initial-baseline.md`.

## 2. Goal / Non-goals / Acceptance

**Goal.** A maintainable, wiki-like documentation tree with one canonical home per fact; a consistent `leas` identity across crates, runtime surfaces, and prose; and a repository that is actually publishable to crates.io.

**Non-goals.**
- No behaviour change to the proxy/TUI code beyond the mechanical rename.
- No restructuring *inside* `docs/aegis/**`, `thirdparty/**`, or the pre-Aegis history verbatim archive.
- No new product features.

**Acceptance.**
1. `grep -rIl -e 'xray-tui' -e 'xray_tui' -e 'XRAY_TUI'` over the codemod scope (§6) returns **zero** hits outside the frozen/history exclusions.
2. `cargo build --release` and `cargo nextest run --workspace` pass after the rename; `just quality-gate` green (or its pre-existing-red delta explicitly noted).
3. Every folder in the target tree has an `INDEX.md`; `docs/INDEX.md` is the hub.
4. No surviving doc cites a path that no longer exists (the "citations are contracts" check, §7).
5. Publishability (§9): the five leaf crates package offline; the full set publishes in topological order; every publishable crate has `description`; `LICENSE` + per-crate `README.md` exist.
6. **Completeness:** every tracked `*.md` (`git ls-files '*.md'` — 139 files) and every tracked top-level doc appears in the §7 map or is explicitly frozen.
7. **No local-only references (D13):** no editable doc cites a `.git/info/exclude` path; frozen `docs/aegis` is exempt.

## 3. Locked decisions (from the design interview)

| # | Decision |
|---|---|
| D1 | Taxonomy axis is **artifact kind**: `architecture/ · guides/ · reference/ · history/ · research/`. |
| D2 | **Two-phase**: Phase 1 = structure + rename + page-level triage; Phase 2 = per-topic claim audit. |
| D3 | History policy A: **synthesize then delete**, with the floor rule (§8). |
| D4 | **One canonical "how it works" layer**; `CONTEXT.md` and `docs/agents-reference.md` are dissolved, not kept as a second copy. |
| D5 | **Citations are contracts**: an artifact cited by a survivor keeps a resolvable path; frozen `docs/aegis` citations stay live. |
| D6 | Identity = **full rename to `leas`** (crates, binary, module paths, `LEAS_*` env vars, `~/.config/leas`, tracing target, User-Agent); **rename before restructure**. |
| D7 | Workspace-hack stays `publish = false`; releases use **`cargo hakari publish -p <crate>`** (methods B/C rejected). |
| D8 | Publishability is **in scope** this pass (LICENSE, README, per-crate metadata). |
| D9 | **README rule A**: every `README.md` = header + ≤2 sentences; root adds one link to `docs/INDEX.md`; the front door is `docs/INDEX.md`. |
| D10 | `CLAUDE.md` = user-authored only; `AGENTS.md` = auto-detected context. No symlink, no duplication. |
| D11 | File naming = **lowercase-hyphen** (`native-core.md`); existing `SCREAMING_CASE.md` names are renamed. |
| D12 | `docs/superpowers/**` is **hard-deleted** after synthesis into `history/superpowers.md`. |
| D13 | **Local-only ad-hoc files are anonymous**: no editable doc references a git-excluded path; existing citations are removed/anonymized (the fact stays, the filename goes). Frozen `docs/aegis` is exempt. |

## 4. Approved positioning (north star)

> **leas** — a feature-rich terminal client for modern VPN and proxy protocols. Top priority: **compatibility with the mainstream server backends** (Xray-core, sing-box) across every protocol they support, delivered with a first-class TUI experience.

`v2rayN` is demoted from "parity target" to one *reference implementation* among several (with mihomo, v2rayNG).

## 5. Current-state inventory (evidence)

Three generations, mutually overlapping; sources: `agent://RootDocsScout`, `agent://DocsTopicScout`, `agent://SuperpowersScout`. The scouts' `target_bucket` values are **advisory input only** — the locked decisions (D1–D10) and the §7 map govern; where a scout bucket disagrees with a locked decision (e.g. a scout proposing `CONTEXT.md` → `architecture` or `README.md` → `delete`), the locked decision wins.

- **Root topic docs** (`CONTEXT.md` 50 KB, `ARCHITECTURE.md` 54 KB, `NATIVE_CORE.md` 85 KB, `ROADMAP.md` 86 KB, `TUI_MANUAL.md` 43 KB, `STAB_BIN.md` 7 KB) — current except `ROADMAP.md` (history), `STAB_BIN.md` (superseded by `docs/aegis/specs/2026-10-09-stab-bin-design.md`), `TUI_MANUAL.md` (stale test-column + "dual-backend" intro), `ARCHITECTURE.md` (stale `ping_sessions` table).
- **`docs/*.md`** — living authority (`database.md`, `database-manual-sql.md`, `ordering_law.md`, `crypto-dependencies.md`, `tls-fingerprint-roster.md`, `clash.md`) vs aged (`native-core-integration.md`, `protocols.md`) vs ad-hoc evidence (`Expert 1–4.md`, `review-by-expert-1/2.md`, `Database Performance Lab.pdf`, `amiabot-roster-report.md`, `dry_normalization_plan.md`, `routing-engine-decision.md`).
- **`docs/superpowers/**`** — 53 tracked files, pre-Aegis (2026-07-09 → 2026-09-11); every file superseded by an aegis successor.
- **`docs/agents-reference.md`** (142 KB) — the corpus extracted from `AGENTS.md` on 2026-10-12; a duplicate, to be dissolved (D4).

**Non-documentation, already ignored (do not migrate):** `.superpowers/` (627 files/27 MB), `.codegraph/`, `.benchmarks/`, `.worktrees/`, `.omp/`, `.zed/`, `*.zip`, `*.tar.gz` — and the root `Xray-linux-64.zip` / `sing-box-*.tar.gz` (local e2e core binaries, **not** repo junk).

**Tracked fixtures (do not delete):** `large.yaml`, `tests/fixtures/*.txt`.

**Local-only files (excluded via `.git/info/exclude` — NOT repo content; the git restructure does not cover them):** `coding-agent-transcript.md`, `STAB_BIN.md`, `dump-1..4.log`, `docs/Expert 1–4.md`, `docs/review-by-expert-1/2.md`, `docs/Database Performance Lab.pdf`. Per **D13** these are **anonymous ad-hoc files**: no editable doc may reference them, and existing citations in editable docs are removed/anonymized (the measurement/fact stays, the filename goes). They are left in place (not moved) and are expected to be deleted once their task is done. Frozen `docs/aegis` keeps its references (it cannot be edited). `refresh.py` **is** tracked (a thirdparty-clone setup script).

## 6. Rename plan (`xray-tui` → `leas`)

**Scope (the codemod set).**

| Surface | Count | Transform |
|---|---|---|
| Crate dirs + package names | 12 | `crates/xray-tui*` → `crates/leas*`; `name = "leas*"` |
| Rust module paths | 137 / 309 `.rs` files | `xray_tui_*` → `leas_*` (`use`, `Cargo.toml` workspace-dotted deps) |
| Workspace deps | root `Cargo.toml`, `.config/hakari.toml` | `xray-tui-hakari`→`leas-hakari`; path entries |
| Env vars | ~30 `XRAY_TUI_*` → `LEAS_*` | `.cargo/config.toml`, benches, tests, docs, justfile |
| Config dir | 5 sites (`join("xray-tui")`) | → `join("leas")` (`~/.config/leas`) |
| Tracing target | `xray_tui*` | → `leas*` |
| User-Agent | `updater.rs` (`"xray-tui"`), `probe.rs` (`"xray-tui/probe"`) | → `leas` / `leas/probe` |
| Binary name | 1 | → `leas` |
| Build/config | `justfile`, `deny.toml`, `.cargo/config.toml`, `criterion.toml` | identifier strings |
| Docs prose | root `*.md` + `docs/**` minus exclusions | identifier strings |

**Frozen exclusions (MUST NOT be rewritten):** `docs/aegis/**`; the pre-Aegis lineage at its **pre-move** path `docs/superpowers/**` (the rename runs before the restructure, so at codemod time `docs/history/superpowers/**` does not yet exist — exclude **both** spellings); `thirdparty/**`; and every gitignored/local path (`.superpowers/**`, `.codegraph/**`, `.benchmarks/**`, `.worktrees/**`, `.omp/**`, `*.zip`, `*.tar.gz`).

**Order:** rename **before** the documentation restructure (code, then prose), so the restructure never re-edits a moved tree.

**Verification:** the D6 acceptance grep returns zero outside the exclusions; `cargo build --release`; `cargo nextest run --workspace`; `just quality-gate`.

**`leas*` availability:** all 12 candidate names confirmed free on crates.io (2026-10-12, `cargo info` per name: `leas`, `leas-core`, `-db`, `-proto`, `-config`, `-dns`, `-geoip`, `-host-features`, `-native`, `-tls`, `-route`, `-hakari`). Names are unreserved — publish promptly or accept the squatting risk.

## 7. Target taxonomy and migration map

**Shape** (file names lowercase-hyphen — D11; existing `SCREAMING_CASE.md` names are renamed):

```
docs/
  INDEX.md                       # wiki hub
  architecture/  INDEX.md · architecture.md · decisions.md · native-core-integration.md
  guides/        INDEX.md · getting-started.md · tui-manual.md · publishing.md
  reference/     INDEX.md · glossary.md · database.md · database-manual-sql.md · ordering-law.md ·
                 crypto-dependencies.md · protocols.md · clash.md · native-core.md · tls-fingerprint-roster.md
  history/       INDEX.md · roadmap.md · stab-bin.md · coding-agent-transcript.md ·
                 routing-engine-decision.md · superpowers/  (or a synthesis note, §8)
  research/      INDEX.md · expert-reviews/ (expert-1..4.md, review-by-expert-1/2.md,
                 database-performance-lab.pdf) · amiabot-roster-report.md · dry-normalization-plan.md
  aegis/         FROZEN — unchanged
```

Every `INDEX.md` lists the files/subfolders it contains with a one-line description.

**Local-only ad-hoc files (D13) — NOT moved and NOT referenced by any editable doc:** `docs/Expert 1.md`…`Expert 4.md`, `docs/Database Performance Lab.pdf`, `docs/review-by-expert-1/2.md`, `dump-1..4.log`, `STAB_BIN.md`, `coding-agent-transcript.md`. Citations to them in editable docs (`docs/database-manual-sql.md`, `ROADMAP.md`, `AGENTS.md`) are removed/anonymized; frozen `docs/aegis` is exempt. (D5's frozen-citation concern does not require moving them — aegis is historical and they are outside git.)

**Migration map.**

| Source | Target | Action |
|---|---|---|
| `README.md` (0 B) | `README.md` | Rewrite — D9 front door |
| `AGENTS.md` | root | Keep; rewrite to drop the `docs/agents-reference.md` pointer and any local-only reference (`STAB_BIN.md`) (D4/D10/D13) |
| `CLAUDE.md` (symlink) | `CLAUDE.md` (root) | **Unlink**; user-authored file, not created by agents |
| `CONTEXT.md` | (dissolved) | **Delete**; glossary → `reference/glossary.md`, durable decisions → `architecture/decisions.md` (D4) |
| `ARCHITECTURE.md` | `architecture/architecture.md` | Move; drop stale `ping_sessions`/`subscriptions` |
| `NATIVE_CORE.md` | `reference/native-core.md` | Move |
| `docs/native-core-integration.md` | `architecture/native-core-integration.md` | Move; banner "superseded in part by ADR 0004 / `ops/connect.rs`" |
| `ROADMAP.md` | `history/roadmap.md` | Slim to history (keep measurements; drop superseded phase detail) |
| `STAB_BIN.md`, `coding-agent-transcript.md` | — | **Local-only ad-hoc (D13)** — not moved, not referenced by any editable doc |
| `docs/routing-engine-decision.md` | `history/routing-engine-decision.md` | Move |
| `TUI_MANUAL.md` | `guides/tui-manual.md` | Move; fix stale test-column + intro |
| `docs/database.md` | `reference/database.md` | Move |
| `docs/database-manual-sql.md` | `reference/database-manual-sql.md` | Move |
| `docs/ordering_law.md` | `reference/ordering-law.md` | Move |
| `docs/crypto-dependencies.md` | `reference/crypto-dependencies.md` | Move |
| `docs/protocols.md` | `reference/protocols.md` | Move; Phase-2 audit (stale stub rows) |
| `docs/clash.md` | `reference/clash.md` | Move |
| `docs/tls-fingerprint-roster.md` | `reference/tls-fingerprint-roster.md` | Move |
| `docs/amiabot-roster-report.md` | `research/amiabot-roster-report.md` | Move |
| `docs/dry_normalization_plan.md` | `research/dry-normalization-plan.md` | Move |
| `docs/Expert 1–4.md`, `docs/review-by-expert-1/2.md`, `docs/Database Performance Lab.pdf` | — | **Local-only ad-hoc (D13)** — not moved, not referenced by any editable doc |
| `docs/agents-reference.md` | — | **Delete**, fold durable content → `architecture/decisions.md` + topic docs (D4) |
| `docs/superpowers/**` | `history/superpowers.md` (synthesis) | Synthesize, then **hard-delete** the 53 files (D12/§8) |
| `docs/aegis/**` | unchanged | **Frozen** |
| `dump-1..4.log` | — | **Local-only ad-hoc (D13)** — not moved; `database-manual-sql.md`'s citations anonymized |
| `refresh.py` | `scripts/refresh.py` (proposed) | Tracked thirdparty-clone helper; not documentation — out of doc scope |
| `.benchmarks/baseline-memory.md` | keep in place | Tracked **despite** the `.benchmarks/` gitignore (force-added); benchmark baseline memory, not wiki content |
| `crates/xray-tui-native/benches/baseline.md` | keep in place | Benchmark baseline, co-located with `benches/`; not wiki content |

## 8. History policy (synthesize, then delete)

For every superseded artifact:

1. If its claims are **still true and covered** by a surviving `reference/`/`architecture/` doc, or **already captured** by an `docs/aegis/adr/` entry → **fold a one-line pointer into the relevant `history/` note, then delete**.
2. Otherwise → **fold the durable outcome into a `history/` note first**, then delete.
3. Never delete a file whose path is cited by a survivor or by frozen `docs/aegis` without first re-pointing the citation or keeping a stub (§7 "citations are contracts").

**`docs/superpowers/**` (53 tracked files, all superseded) is the largest application: synthesize into `history/superpowers.md` (a lineage note naming each design and its aegis successor), then **hard-delete** the files (D12). The raw record remains in git history.

**`history/` verbatim exception:** none (D12 — hard-delete).

## 9. Publishing plan

**Metadata (all 11 publishable crates; `leas-hakari` stays `publish = false`).**
- Add `LICENSE` (MIT) at root; keep `license = "MIT"` inheritance.
- `[workspace.package]`: add `repository`, `authors`, `homepage`; keep `readme = "README.md"`.
- Per crate: `description` (required by crates.io), `keywords`, `categories`, `readme.workspace = true` (none opt in today).
- De-space `[package] name` collisions: none expected.

**Release procedure (D7).** Topological order, each via `cargo hakari publish -p <crate>`:

`leas-proto` → `leas-tls` → `leas-dns` → `leas-geoip` → `leas-host-features` → `leas-route` → `leas-db` → `leas-core` → `leas-config` → `leas-native` → `leas`.

**Acceptance (offline first).**
- `cargo hakari remove-deps` → `cargo package -p <crate>` → `cargo hakari manage-deps` for the five leaves (`leas-proto`, `-tls`, `-dns`, `-geoip`, `-host-features`).
- Non-leaf crates are provable only after their siblings are on the registry → full proof = the staged `cargo hakari publish` order, or a local-registry dry-run.

**`docs/guides/publishing.md`** records this procedure.

## 10. Phasing

- **Phase 0 — Guardrails.** Unlink `CLAUDE.md`; add the new aegis baseline (`docs/aegis/baseline/2026-10-12-leas-repositioning.md`) + this spec's registry entry; note the `BASELINE-GOVERNANCE.md` §1 update (explicit user review).
- **Phase 1 — Rename to `leas`.** Codemod + verification (§6). One atomic change.
- **Phase 2 — Documentation restructure.** Build the taxonomy, write the `INDEX.md` files, execute the migration map and the history policy. Delete `docs/agents-reference.md`, `CONTEXT.md`'s duplicate content.
- **Phase 3 — Publishability.** LICENSE, READMEs, metadata, offline proof.
- **Phase 4 — Claim audit.** Per-topic verification of surviving `reference/`/`architecture/` pages against code (D2 phase 2).

## 11. Open decisions (need confirmation)

All resolved (user, 2026-10-12):
1. File naming = **lowercase-hyphen** (D11).
2. `docs/superpowers/**` = **hard-delete** after synthesis (D12).
3. Local-only ad-hoc files = **anonymous** (D13) — not referenced, not pinned.
4. Root README's single link = `docs/INDEX.md` (D9).

## 12. Risks / rollback

- **Partial rename** (search/replace leaking into frozen aegis/history) → guarded by the acceptance grep; the codemod lists exclusions explicitly.
- **Broken citations** across the move → the "citations are contracts" check is a gate.
- **crates.io squatting** on the 12 free names before release.
- **Non-leaf crate proof** is impossible offline → staged publish / local registry.
- **Phase 4 unbounded** → scope per topic, one PR per topic.
- **Rollback:** the rename is one commit, the restructure is per-folder commits; both revert cleanly from git.

## 13. ADR signals

- **Owner/contract:** `AGENTS.md` ceases to be the product-requirement baseline; a new `docs/aegis/baseline/` snapshot + a framing spec assume that role (updates `BASELINE-GOVERNANCE.md` §1 — user review required).
- **Public contract:** crate names, binary name, env-var names, config-dir path become the published surface (an external contract once on crates.io).
- **Compatibility boundary:** `~/.config/xray-tui` is not migrated to `~/.config/leas` (pre-alpha; documented as a deliberate break, not a migration).
- **Retirement:** `docs/superpowers/**` retirement schedule is §8.

## 14. Sources

Inventory produced 2026-10-12 by read-only scouts: `agent://RootDocsScout`, `agent://DocsTopicScout`, `agent://SuperpowersScout`. Registry: `docs/aegis/INDEX.md`. Constitution: `docs/aegis/BASELINE-GOVERNANCE.md`.
