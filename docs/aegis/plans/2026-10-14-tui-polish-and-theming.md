# TUI Polish & Theming — Implementation Plan

| Field | Value |
|---|---|
| Date | 2026-10-14 |
| Spec | `docs/aegis/specs/2026-10-14-tui-polish-and-theming-design.md` |
| Status | **executed through P2 (D1–D5); P3–P5 remain.** Verification, all re-run after the contrast fix: `cargo check -p leas --all-targets` exit=0, `cargo clippy --workspace --all-targets --all-features -- -D warnings` exit=0, `cargo nextest run --workspace` **2386/2386 passed, 11 skipped** (Summary line captured), all 6 tui-test scenarios re-run green (0 errored steps) |
| Owner | `crates/leas/src/ui/` + `crates/leas-config` |

## Goal

Ship the five themes of the spec — a single theme source (opaline 0.4.2), state-derived hints, a
per-frame size read, density fixes in the table/tree/panels, and corrected docs — with all seven
existing `tui-test` scenarios re-run green as the acceptance gate.

## Architecture / Tech Stack

Rust 2024 workspace, ratatui 0.30 + crossterm 0.29. `ratatui-themes` 0.3 and `ratatui-cheese` 0.7 are
replaced by `opaline` 0.4.2 (features `builtin-themes`, `ratatui`, `gradients`, `global-state`,
`discovery`). No new crates beyond opaline; `just` recipes unchanged.

## Baseline / Authority Refs

- `docs/guides/tui/INDEX.md` + the 7 scenario documents and transcripts (regression suite and evidence)
- `docs/aegis/specs/2026-10-14-tui-polish-and-theming-design.md` (§5 design, §6 verification)
- `AGENTS.md` — gate commands, test conventions (`rstest` tables, tests beside code), DB rules (untouched here)

## Compatibility Boundary

- **Config**: `theme_name` keeps kebab-case slugs; `gui.theme` is removed. A config carrying only
  `theme_name` loads unchanged. An unknown slug must error at load, not fall back.
- **Behaviour**: no protocol, DB, schema or persistence change. `SCHEMA_VERSION` is not touched.
- **Public API**: `AppState::current_palette()` is private to the crate; no external consumer.
- **Fixtures**: `docs/guides/tui/fixtures/config.json` and `config-light.json` keep `dracula` /
  `catppuccin-latte`; the light fixture additionally pins the canvas env vars.

## TDD Route

| Field | Value |
|---|---|
| Mode | `auto` |
| Decision | `strict` for P1 (theme contract, shared core, 108 consumers) and P2 (behaviour: hints/state); `light` for P3–P5 (layout/docs) |
| Authority | risk signals — contract, shared core, consumer-visible behaviour (P1/P2); local, single-owner presentation changes (P3–P5) |
| Test posture | P1/P2 get failing tests first: `AppState`-level unit tests for the hint table and the token mapping, plus scenario assertions re-run as the acceptance gate. P3–P5 get the minimum change plus the scenario re-run as regression |
| Reason | the theme swap changes a contract 108 call sites consume; the hint owner changes consumer-visible text on every screen |
| Verification | `cargo nextest run --workspace` + all 7 scenarios + the grep gates (A9, A10) |

## Requirement Ready Check

- Spec approved by the user (this request authorises the plan).
- Acceptance criteria A1–A10 are machine-checkable via the scenario suite or grep.
- P0's unknown (opaline's exact API) is explicitly gated, not assumed.
- No DB/schema/permission surface; no new owner crate.

## Change Necessity

Each task changes code because a scenario proved the current behaviour is wrong (spec §4). The two
structural tasks — P1 (delete the bridge) and P2 (one hint owner) — remove duplicate ownership rather
than adding a layer.

## Ripple Signal Triage

| Signal | Where | Handling |
|---|---|---|
| 108 `ThemeStyles::` consumers | 11 UI files | one mapping table + one mechanical sweep in P1 |
| 11 `ThemeName::` uses in tests | `ui/profiles.rs`, others | updated with the sweep; `palette_from_name` deleted |
| `gui.theme` dead field | `leas-config`, `settings.rs` | removed in P1 with the config; a config carrying it still parses (unknown keys are ignored) unless strict — verify in P0 |
| Hint text asserted by scenarios | 4 scenario docs | updated in the same task that changes the owner; transcripts re-recorded |
| `actions_compact` read in 4 places | `ui/mod.rs`, `state.rs` | replaced by a per-frame local; `F1` keeps toggling panel height only |

## Plan Pressure Test

- **Does P1 block P2–P4?** Only P2's styling of new hint text wants tokens. P2's *owner* (a pure
  function over `AppState`) can land first; sequencing P1 → P2 is chosen so the new hints are written
  with tokens from the start. If P0 reveals opaline friction, P2 can be reversed out independently.
- **Can P3 land without P1?** Yes — the size read and column priority are token-agnostic.
- **Smallest useful slice?** P0 + P2 fixes the four state-truthiness majors (including the blank
  `Esc` screen) with no dependency change.
- **What if the user wants only the theme swap?** P0 + P1 alone, and the remaining majors stay open —
  record it in the plan's status rather than silently deferring.

## Tasks

### P0 — opaline spike (gate)

1. `cargo add opaline@0.4.2 --features builtin-themes,ratatui,gradients,global-state,discovery` in a
   throwaway branch; `cargo check` (MSRV 1.98 ≥ 1.85 ✓).
2. Verify in a scratch test, one line each: `load_by_name("dracula")`, `load_by_name("catppuccin-latte")`,
   `theme.style("…")`, `theme.color("…")`, `theme.span(…)`, `list_available_themes()`,
   `register_default_token()`, and the ratatui `From` conversions the design needs.
3. Verify an unknown slug errors (no silent fallback) and that `crossterm`/`owo-colors` adapters are
   unnecessary for this app.
4. Record the confirmed API in the spec's §10 and pin the version. **Exit criterion: every API the
   design cites is either confirmed working or the design is amended before P1.**

### P1 — theme foundation (strict) — **executed**

**Corrected API facts** (the README was wrong on three of four):

| Spec claim | Reality (read from the vendored crate) |
|---|---|
| `load_by_name` errors on an unknown slug | returns `Option<Theme>` → `ui/theme::load` maps `None` to an error |
| ratatui adapter returns `Style` | `From<OpalineStyle> for Style` (a conversion, applied via `.into()`) |
| `global-state` is a useful feature | a process-wide singleton that duplicates `AppState` — **feature left off** |
| `widgets` renders egui | a **Ratatui** `ThemeSelector` — the manual's picker is in reach; feature enabled, not yet used |

Also: `OpalineStyle` has `with_fg`/`with_bg` (chaining) but no `with_bold`; modifiers are fields set via
the `Stylize` trait it implements. `ratatui-cheese` survives **only** as a widget toolkit (Tree/List/
Input/Select) and takes its own `Palette` — `ui/theme::widget_palette` is the single adapter, so a
widget can never introduce a colour the theme does not define.

Land: `AppState.theme: Theme` (one owner, `config.theme_name` now a kebab slug),
`ui/theme.rs` rewritten as the mapping table + app-role registration, `ui/palette_bridge.rs` **deleted**,
`current_palette()` gone, `gui.theme` removed, 108 call sites swept, all 33 hardcoded `Color::*` sites
tokenized (the deliberate `Color::Reset` notch in `panel_row_selected` kept — opaline has no Reset), and
`ThemeStyles::table_header` finally called.

### P2 — state truthfulness (strict) — **executed**

`build_hints` is now the one owner: a modal returns `[y] Confirm  [n/Esc] Cancel`; a filtered-empty list
renders `No match for "ams"` instead of `No profiles — press 'a' to add one`; a zero-row list drops
Expand/Variant; the Settings tree names `[Tab] Next tab`. Verified live by re-running
`profiles-menus-states`, which greps both new strings out of the transcript.

Not yet done in P2: `Esc` from the Settings tree still leaves the tab on Settings with an empty body
(`ui/settings.rs:385`), and `q` still edits an editable field.

### P1 — theme foundation (strict) — original"

**RED.** Tests first:
- `AppState` loads a theme from `theme_name` and an unknown slug returns an error (unit).
- The 16 helper names resolve to an opaline token/style and every token exists in both fixture themes
  (unit, table-driven with `#[rstest]` over `dracula`/`catppuccin-latte`).
- A style read proves the table header carries fg+bg+bold under both themes (this is A3; it fails
  today because `ThemeStyles::table_header` is never called).

**GREEN.**
1. Add `AppState.theme: Theme`; load once from `config.theme_name`; delete `current_palette()`.
2. Rewrite `ui/theme.rs` as the mapping table (16 helper names → opaline style names) plus the app token
   registration (`app.error/warning/success/hint/muted/badge`, `table.header/row.selected/row.alt`,
   `dialog.fill/dialog.text`, `statusbar.hint`, `log.level.*`).
3. Delete `ui/palette_bridge.rs`; sweep the 108 call sites mechanically.
4. Replace the 33 hardcoded `Color::*` sites with tokens (spec §4 table); keep the deliberate
   `Color::Reset` notch.
5. Remove `gui.theme` from `leas-config` and any settings read of it.
6. Call the previously-unused `table_header` style so A3 passes.

**REFACTOR.** `grep` gates A9/A10; `clippy -D warnings`; the colour scenario gains the both-theme
assertions (A1–A3) and is re-recorded.

### P2 — state truthfulness (strict)

**RED.** Unit table over states → expected hint vectors: List-with-rows, List-empty, filtered-empty,
Confirm modal, Settings tree, Settings form, Add/Edit form. Each fails today where the app currently
shows the tab's constant set. Plus a test that `Esc` from the Settings tree returns to the Profiles tab
(A5) and that `q` in an editable field does not quit (T4).

**GREEN.**
1. Add `hints_for(&AppState)` in one module; `status_bar::render` consumes only it.
2. Distinguish empty states: "No profiles — press 'a' to add one" only when the store is empty; a
   filtered-empty list shows `No match for "<q>"` and hints `Esc`; zero rows drop Expand/Variant hints.
3. `Esc` at the Settings tree returns to the Profiles tab (`ui/settings.rs:385`).
4. `q` is a no-op in editable fields; document it in the manual.
5. Modal hint set (`[y] Confirm  [n/Esc] Cancel`).

**REFACTOR.** Re-run `profiles-menus-states`, `settings-forms`, `live-resize`; re-record transcripts;
update the manual's key tables.

### P3 — per-frame size and width (light)

1. Compute `compact`/`panel_rows` from `frame.area().height` each frame; delete the `<20` overlay branch
   and `F1`'s content-area takeover; `F1` toggles height only and the hint row says so.
2. Column drop priority (`Country` → `Outbound` → `Feat`, keep `Test`); ellipsize clipped cells.
3. Build the hint row right-to-left from `Quit`.
4. Regression: `narrow-80x24`, `tiny-80x14`, `live-resize` (A6, A7); record that a live shrink to 19
   rows now keeps the table.

### P4 — density (light)

1. Profiles: right-align the `#` header; panel header row + one empty glyph; inset the panel by one cell.
2. Batch import: lead each row with the parsed `#name`.
3. Settings: label or drop the tree count; select the first leaf on pane open; focus the first field on
   open; dirty marker on a changed form.
4. Menus/help: full-width separators; help popup sized to its widest row; modals keep the tab row.
5. Regression: `profiles-import-and-table`, `settings-forms`, `profiles-menus-states`.

### P5 — docs and fixture hardening (light)

1. `docs/guides/tui-manual.md`: token-based theme section, the 20-node tree, the corrected key tables
   (Settings `Tab`, `q`), the Statistics empty-state wording, the overlay title.
2. Fixtures: both configs assert `NO_COLOR` is dropped from the launch; `light-canvas-shots.py` and
   `check-theme-pixels.py` stay in `fixtures/` and are referenced from the colour scenario.
3. Every colour remark in a scenario doc carries a `shot()` path and a read (already the convention;
   make it explicit in the fixture so a future run cannot skip it).
4. Re-run all 7 scenarios; record the final verdicts in `INDEX.md`.

## Verification Summary

| Gate | Command / check | Criterion |
|---|---|---|
| Lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| Tests | `cargo nextest run --workspace` | green (incl. the new hint/token tables) |
| Suite | 7 scenarios via `run_scenario` | all green; A1–A7 asserted inside them |
| Colour | `get_cell_style` on both themes | header styled ✓; dialog tokenised ✓; hint contrast raised 1.23:1 → light **4.64:1** / dark **4.53:1** via a contrast-derived registered token — A1 **met** |
| Gates | `grep -rn "Color::(Rgb|Gray|Black|White|Cyan|Yellow)" crates/leas/src/ui/` | only `ui/theme.rs` |
| Gates | `grep -rn "gui.theme" crates/` | none |
| Teardown | `list_sessions` → none; `pgrep -a leas` → none; `rescue_files` → `[]` | clean |

## Risks

- **P0 blocks P1.** If opaline's API differs from the README in a way that breaks the mapping, amend
  the spec before writing code — the plan says stop, not improvise.
- **Large mechanical diff in P1.** Review it as one rename-shaped diff; `clippy` catches drift.
- **Scenario churn.** P2/P3 change on-screen text the scenarios assert; transcripts are re-recorded
  beside the originals, not overwritten.
- **Light-theme regressions.** A1 is asserted for both themes in the same run.

## Retirement Track

| Retired | Replaced by | When |
|---|---|---|
| `ui/palette_bridge.rs`, `current_palette()`, `ThemeName` in `AppState` | `AppState.theme` + `ui/theme.rs` mapping | P1 |
| `gui.theme` config field | `theme_name` | P1 |
| `ratatui-themes`, `ratatui-cheese` workspace deps | `opaline` | P1 |
| the `<20` overlay branch and `F1`'s content-area takeover | per-frame compact bar | P3 |
| per-tab hint constants | `hints_for(&AppState)` | P2 |
| "No profiles — press 'a'" for every empty screen | state-specific empty messages | P2 |
| the manual's hex-based theme table | token documentation | P5 |

## Sources

- `docs/aegis/specs/2026-10-14-tui-polish-and-theming-design.md`
- `docs/guides/tui/` (7 scenarios, 2 reviews, fixtures)
- `crates/leas/src/ui/`, `crates/leas/src/state.rs`, `crates/leas-config/src/app_config.rs`
- opaline 0.4.2 README / docs.rs; `AGENTS.md`
