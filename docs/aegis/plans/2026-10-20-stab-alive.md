# Plan: Stability Keeps a Stable Server Alive

- **Spec:** `docs/aegis/specs/2026-10-20-stab-alive-design.md` (approved 2026-10-20)
- **Goal:** a stable server stays near the top when its latest real ping failed; main grid gains a colored `Stab` column after `Test`.
- **Baseline refs:** `docs/reference/ordering-law.md`, specs `2026-10-09-stab-bin-design`, `2026-10-06-db-rewamp` D11, `2026-09-15-pane…` (§7 grid), `2026-09-17-purge-reason-design`.
- **Compatibility:** no schema change; stored key columns keep meaning, values re-derive via `STAB_VERSION 2` → one rebuild on open. No API/contract change outside leas-db leas cross-crate use of existing pub fns.

**TDD Route:** auto → **strict** (behavior change in the shared ordering law; consumer-visible ordering). RED first for the bin law + representative selection, then implementation.
**Change Necessity:** docs/config-only cannot reorder rows — the law lives in `endpoint_rank.rs`; minimum boundary = `RankLink`/`compute_rank`/`display_link_index` + `profiles.rs` grid.
**Ripple:** shared/core ordering law read by page query, panel, parity golden, goldens regenerate; purged/Fast arms deliberately unchanged.

**Coordination:** a sibling agent works on leas-db (`2026-10-20-turso-0.9-access` spec, untracked). Re-read `git status` + target files before each leas-db edit; no shared-file edits without a fresh read.

## Tasks

- **T1 — RED tests** (`crates/leas-db/src/endpoint_rank.rs` tests): rstest bin-law table for every D2 row; `stab_latest_ok` (empty `None`, newest bit below/at window); `compute_rank` ghost-vs-live rep + purged-live-exclusion; `display_link_index` override-first/live-first. Run → fail.
- **T2 — Law** (`endpoint_rank.rs`): add `stab_latest_ok(mask, len)`, `RankLink.latest_ok` in `new()`; rewrite `bin()` per D2 (real-err `!proven` → 13; proven → stored-latency bin; `Fast`/unchanged arms pinned); live-first representative in `compute_rank`; display precedence override → live-first → best measured; `STAB_VERSION = 2`. Run T1 → green.
- **T3 — Old pins** (leas-db): rewrite `models_toasty.rs:958 select_best_measured_link_error_with_latency_still_measured`, `:1047 fresh_failure_dominates_stored_success`; regenerate parity golden; fix `profiles_query` tests pinning real-err + latency → bin 13. Verify: `cargo nextest run -p leas-db`.
- **T4 — Grid column** (`crates/leas/src/ui/profiles.rs`): logical `(10, "Stab", 7)` after Test; value = display link's `stability_ratio`; color ≥80% `--success` / ≥50% `--warning` / <50% `--error` / `—` muted (same span pattern as Test thresholds); drop order Exit→Out→White→Stab; `PROFILES_SORT_COLUMN` still 7; render tests updated + new Stab rows.
- **T5 — Docs** (`docs/reference/ordering-law.md` link-key/stab sections + new dated subsection; `docs/guides/tui-manual.md` grid; `docs/aegis/INDEX.md` plan row).
- **T6 — Gate:** `cargo nextest run --workspace`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo fmt`. Fix fallout.
- **T7 — Smoke:** `cargo run` against workspace DB, verify a stable-but-recently-failed server sits near top with colored Stab cell. Report evidence.

**Retirement:** old err-band behavior in tests only; no fallback/compat path retained.
**Execution route:** inline (shared crate with sibling agent; sequencing safer than parallel subagents).
