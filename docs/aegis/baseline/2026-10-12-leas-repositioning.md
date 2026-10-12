# leas Repositioning Baseline

Date: `2026-10-12`
Status: `repositioning snapshot` — **adds to, and does not replace, `2026-09-11-initial-baseline.md`**

## 1. Purpose

Record the project repositioning and identity change decided on 2026-10-12 so later
`Baseline Role Alignment` checks read the new product framing, not the superseded one.
The 2026-09-11 snapshot remains the historical record of the pre-repositioning state and
**MUST NOT be edited** (falsifying it would destroy the evidence this workspace exists to keep).

This snapshot is evidence, not authority. The authoritative requirement surface after the
change is `docs/INDEX.md` + the pages under `docs/{architecture,guides,reference}/`, plus
accepted ADRs. `docs/aegis/**` itself is frozen.

## 2. Repositioning (product)

- **Was:** "Rust TUI client for Xray-core and Sing-box; feature parity with v2rayN for every
  protocol either backend supports."
- **Now:** **leas** — a feature-rich terminal client for modern VPN and proxy protocols. Top
  priority: **compatibility with the mainstream server backends** (Xray-core, sing-box) across
  every protocol they support, delivered with a first-class TUI experience.
- `v2rayN` is demoted from the parity target to one *reference implementation* among several
  (with mihomo, v2rayNG). Protocol/URL-format fidelity to those implementations remains a
  requirement; feature-for-feature UI parity is no longer the goal.
- Unchanged: the protocol set, and the single operator managing large subscription feeds
  (10k+ endpoints) from a terminal.

## 3. Identity change (breaking, accepted — pre-alpha)

- Project and crates renamed `xray-tui*` → **`leas*`** (12 crates; binary `leas`).
- Runtime surfaces renamed: env vars `XRAY_TUI_*` → `LEAS_*`; config dir
  `~/.config/xray-tui` → `~/.config/leas`; tracing target `leas`; User-Agent `leas`.
- **No migration is provided** for the config directory. This is a deliberate break, not an
  omission (the project is pre-alpha and its on-disk format already changes by wipe).
- Distribution: the workspace becomes publishable to crates.io. The workspace-hack
  (`leas-hakari`) stays `publish = false`; releases use `cargo hakari publish -p <crate>`.
  All 12 `leas*` names were confirmed free on crates.io on 2026-10-12.

## 4. Authority surfaces after the change

| Surface | Role |
| --- | --- |
| `AGENTS.md` | Auto-detected project context (commands, structure, conventions) **only**; it ceases to be the product-requirement baseline |
| `docs/INDEX.md` | Wiki hub; folders `architecture/ · guides/ · reference/ · history/ · research/`, each with its own `INDEX.md` |
| `docs/aegis/**` | Unchanged (frozen) |
| this file | Product / Requirement baseline for the repositioned project |
| `docs/aegis/BASELINE-GOVERNANCE.md` §1 | To be re-pointed from `AGENTS.md` to the above (**requires explicit user review** — that file is never auto-updated) |

## 5. Non-negotiables carried forward

The 2026-09-11 §4.2 (product) and §5.2 (architecture) non-negotiables remain in force unchanged;
in particular: one backend process per session; identity excludes host/port and credentials never
move `sig`; persisted `core_type` stays `{Xray, SingBox}` with the native core runtime-only; the
schema cursor (not a wipe tag) owns migrations; secret key material is wiped.

## 6. Compatibility boundary

- The identifier break in §3 is the only external compatibility break introduced here.
- `docs/aegis/**` stays byte-identical; local-only ad-hoc files (git-excluded) are not moved and
  must not be referenced by editable docs.
- Git history retains the pre-rename naming; the rename is one revertible commit.

## 7. Alignment use

Read this snapshot before product-scope, identity, distribution, or acceptance changes. A change
that alters behaviour *and* the boundary carrying it reports `scope: both`. This snapshot does not
grant completion authority.
