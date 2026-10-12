# Baseline Governance

## 1. Baseline Roles

- **Product / Requirement Baseline**: `docs/aegis/baseline/2026-10-12-leas-repositioning.md`
  (project identity, north star, scope), `docs/INDEX.md` and the pages under
  `docs/{architecture,guides,reference}/`, `docs/guides/tui-manual.md` (screens, keys,
  workflows), `docs/reference/native-core.md` (native core and TLS engine scope and
  verification tiers), `docs/reference/protocols.md`, approved specs under
  `docs/aegis/specs/`.
- **Architecture / Runtime Boundary Baseline**: `docs/architecture/decisions.md` (durable
  design decisions), `docs/architecture/architecture.md` (crate graph and owners),
  `docs/architecture/native-core-integration.md`,
  `docs/history/routing-engine-decision.md`, ADRs under `docs/aegis/adr/`.

## 2. Design Defect

A confirmed error, gap, contradiction, or wrong abstraction IN the relevant
requirement, design, or baseline.

- Fix the defective requirement/design/baseline first.
- Then align implementation to the corrected baseline.
- Do NOT patch implementation around a defective baseline.

## 3. Implementation Drift

Implementation, plan, review, or documentation has deviated from a confirmed,
correct, unchanged requirement or architecture baseline.

- Return to baseline via the simplest stable path.
- Do NOT "update baseline to match drift" without explicit review.

## 4. Compatibility Aliases

- Architecture Defect = architecture-scoped Design Defect.
- Architecture Drift = architecture-scoped Implementation Drift.
- New findings report Design Defect / Implementation Drift plus
  `scope: requirements | architecture | both`.

## 5. Baseline Check Protocol

Before non-trivial changes:

1. Read the latest Product / Requirement Baseline candidate.
2. Read the latest Architecture / Runtime Boundary Baseline candidate.
3. Compare current work against requirement acceptance and architecture owner /
   contract boundaries.
4. Check for new anti-patterns not recorded in the known list.
5. Report `aligned | Design Defect | Implementation Drift | missing-authority |
   needs-clarification` with `scope`.

## 6. Architecture Review — 7 Dimensions

After each non-trivial change:

1. **Ownership integrity** — every component has exactly one canonical owner.
2. **Module boundaries** — no unauthorized cross-module coupling.
3. **Contract changes** — all API/signature/behavior contract changes documented.
4. **Cascade proliferation** — no new cascading dependency chains.
5. **Dependency direction** — dependencies flow toward stability.
6. **Retirement completeness** — old owners/fallbacks/paths removed or scheduled.
7. **Entropy flow** — net complexity decreased or stayed; no unjustified new entities.

## 7. Hard Boundaries

- `BASELINE-GOVERNANCE.md` is the constitution for this project's Aegis workspace.
- Baseline snapshots in `baseline/` are evidence, not authority.
- ADRs in `adr/` record decisions; they do not replace baseline governance.
- This file is NEVER auto-updated — changes require explicit user review.
