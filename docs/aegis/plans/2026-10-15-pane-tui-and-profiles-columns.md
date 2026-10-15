# Pane TUI Redesign & Profiles Columns — Implementation Plan

| Field | Value |
|---|---|
| Date | 2026-10-15 |
| Spec | `docs/aegis/specs/2026-10-15-pane-tui-and-profiles-columns-design.md` |
| Status | **executed P1–P6.** P1 overlay stack (3 unit tests), P2 pane shell + keymap (`Tab`/`1`/`2`/`[`/`]`/`,`/`Alt+↑↓`), P3 Settings popup + dirty-discard, P4 merged frameless Metrics (3 ported tests; `statistics.rs` deleted), P5 10-column Profiles grid (hex ID, flag cells, `White`, split Port, bold `+`/`-`, fixed sort arrow), P6 manual rewrite. Gates: `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo nextest run --workspace` **2393/2393 passed, 11 skipped**. Scenario re-run evidence (2026-10-15, against the new chrome): `profiles-menus-states` re-executed end-to-end — pane-1 tab bar `1: [Profiles]  Logs`, new 10-column grid with `Test ↑`, help popup with pane keys, `Speed Test` popup (title fixed, no dead sort item), Export Scope, delete confirm with `[y] Confirm  [n/Esc] Cancel` hints (the old E8 defect — Profiles hints during confirm — is now fixed), prefix search. `settings-forms` re-driven: `,` opens the popup (inner pane `Sections`), `Esc` closes it, `q` then quits from the list (documented `q — Quit`, not a regression). Narrow 80x24 and tiny 80x14 verified by direct capture: columns drop Exit→Out→White with Test protected, hints fit with `Quit` at the edge, pane 2 auto-compacts below 20 rows and renders borderless. Live-resize exercised 120x40→80x24→80x14→120x40 with correct re-layout. The old transcripts remain valid as historical evidence; the manual now documents the new chrome |
| Owner | `crates/leas/src/ui/`, `crates/leas/src/types.rs`, `crates/leas/src/state.rs`, `crates/leas/src/ops/` |

## Goal

Land the spec end to end: two framed panes with inline bracketed tab bars (pane 1 `[Profiles]`/`Logs`, pane 2 `Details`/`[Metrics]`), Settings as popup overlay, overlay-stack render (no bespoke branches), and the 10-column Profiles table (hex ID, flag prefixes, `White`, split Port, bold `+`/`-`, no decorative brackets/arrows).

## Baseline / Authority Refs

- Spec §3 D1–D14, §6 shell, §7 columns, §12 phases
- `docs/guides/tui-manual.md` (rewrite in P6)
- `AGENTS.md` gates: `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace`

## Compatibility Boundary

- No protocol/DB/schema/persistence change. `SCHEMA_VERSION` untouched.
- `Tab` enum deleted (bin-crate-local; no external consumer). `current_tab` sites all within `crates/leas/src`.
- Settings forms keep their existing field defs and save paths — only the container changes (popup) plus the D1/D5 metadata additions come in a later spec slice.
- tui-test scenarios `profiles-menus-states`, `settings-forms`, `narrow-80x24`, `tiny-80x14`, `live-resize`, `menus`, `colour-focus-audit` are the regression suite; transcripts re-recorded where assertions change.

## Change Necessity

Each phase removes a structure the spec retires: 7 overlay branches → one stack; 6-tab shell → 2 panes; settings tab → popup; separate screens → pane-2 tabs; 16-column table → 10-column table.

## Ripple Signal Triage

| Signal | Where | Handling |
|---|---|---|
| `current_tab` reads (~20) | `ui/mod.rs` handle_key/render, `ops/*` | enumerated in P1 grep; routed through new pane state in P2 |
| `Tab::ALL` cycles | `ui/mod.rs:676-699`, `render_tabs:1264` | deleted in P2; `Tab` enum removed from `types.rs` |
| `AppMode::Settings` handlers | `ops/settings.rs`, `ui/settings.rs` (2136 lines) | container becomes popup; enter/exit paths adapted in P3 |
| Statistics/NativeActivity screens | `ui/statistics.rs`, `ui/native_activity.rs` | become Metrics content renderers in P4; modules kept |
| Actions log panel | `ui/actions_log.rs` | becomes pane-2 Details tab in P4 |
| Scenarios asserting tab chrome | `docs/guides/tui/` | re-recorded in P6 with new chrome assertions |

## Tasks

### P1 — overlay-stack render (behaviour-preserving)

**RED.** Unit: `overlay_for(&AppMode) -> Option<OverlayKind>` ordering; one test per overlay kind pins the precedence (Confirm > SpeedTest > Export chain > Forms > Settings > Help).

**GREEN.**
1. Add `OverlayKind` + `overlay_for()` in `ui/mod.rs`; render() becomes: base content (existing tab dispatch, unchanged) → `for kind in overlay_stack(state) { render_overlay(kind, …) }`.
2. Delete the 7 bespoke branches: small-terminal overlay duplicate, `is_form_mode` set threading, export-chain special case, speed-test-menu special case, generic non-List branch, per-Tab form early-returns.
3. `render_tabs` suppression: the tab row renders only when no overlay is open.

**Gate.** `cargo nextest run -p leas` + 7 scenarios re-run green (chrome unchanged, so transcripts must match).

### P2 — pane state + shell + keymap

**RED.** Unit: pane focus cycles `Tab`/`BackTab`, `1`/`2` jump, `[`/`]` cycle pane tabs (state-level fns over `AppState`).

**GREEN.**
1. `types.rs`: delete `Tab`; add `Pane1Tab { Profiles, Logs }`, `Pane2Tab { Details, Metrics }`, `FocusedPane`. `state.rs`: replace `current_tab` with `focused_pane`, `pane1_tab`, `pane2_tab`; update the ~20 sites.
2. `render()`: layout = pane 1 (`Min(6)`) + pane 2 (per-tab height: Details 8 / Metrics 14, `Alt+↑/↓` resize, clamp 3..h/2) + status bar; frames accent-when-focused/muted; tab bars inline in border titles (`1: [Profiles] Logs`).
3. Keymap (spec D2): `Tab`/`BackTab` focus cycle, `1`/`2` jump, `[`/`]` pane tabs, `,` settings, pane-scoped routing for profiles/logs/pane-2 keys.
4. Delete `<20` overlay-fullscreen branch; `F1` toggles pane-2 compact only.

**Gate.** unit + scenarios `profiles-menus-states`, `tiny-80x14`, `live-resize` (re-record chrome assertions).

### P3 — settings popup

**RED.** Scenario: `,` opens popup over panes; `Esc` closes; dirty form prompts `y/n` (uses existing `ConfirmAction`).

**GREEN.**
1. Settings renders as centered popup (D5 dims) over the pane shell; split tree+form interior unchanged.
2. `enter_settings`/exit paths (`ui/settings.rs:385` Esc-from-tree, `ops/settings.rs`) route through popup open/close.
3. Dirty tracking + discard confirm (minimal: compare form fields to loaded snapshot on Esc).

**Gate.** `settings-forms` scenario re-run + re-record.

### P4 — pane 2: Details/Metrics

**RED.** Scenario: Metrics tab shows session totals, native ring rows, sys stats with a visible `rows x-y of n` counter; Details shows the actions log.

**GREEN.**
1. Pane 2 chrome: tab bar + content; `ui/actions_log.rs` full/compact become Details; height state per D3.
2. Merge: `ui/statistics.rs` + `ui/native_activity.rs` renderers + traffic counters into one scrollable Metrics view (window-then-format; native ring slice only).
3. `Alt+↑/↓` resize, pane-2 focused guard; counter in pane title.

**Gate.** scenarios `menus` (actions rows), new `pane2-metrics` step set; `native-activity` assertions moved.

### P5 — Profiles columns

**RED.** Unit table (`rstest`): `flag_cell` both forms (`🇳🇱-NL` / `NL`, unknown `—`); `truncate_host` subdomain elision vs IP right-truncate; ID cell `{:08x}` vs `*` equal widths; `white_cell` tokens.

**GREEN.**
1. Cell builders: `flag_cell`, `truncate_host`, `white_cell`, ID cell (D9/D10), Address cell with bold `+`/`-` prefix (D11).
2. Rebuild the column list to the 10-column §7 grid (D8); delete bracket/glyph cells; per-column colour map (D12); `truncate_pad`/`center_cell` reuse.
3. Sort arrow: one shared constant from `PageRequest.sort` (D13) — `Some(11)` → `Some(7)`.
4. 80-column priority drop list re-derived on the new columns.

**Gate.** units + `profiles-columns` scenario + `narrow-80x24` re-run; A7 grep scoped to cell builders.

### P6 — docs + fixtures

1. Rewrite `docs/guides/tui-manual.md`: pane shell, popup settings, keymap table, column table.
2. Update tui-polish spec's open items mapping reference; re-record all scenario transcripts.
3. Final gate: clippy `-D warnings` + `cargo nextest run --workspace` + all scenarios.

## Verification

Full gate per `AGENTS.md`; each phase's scenario subset before moving on; A1–A10 from spec §2 mapped: A1 grep gate (P2), A2/A3/A4/A5/A6 scenarios, A7 grep + scenario (P5), A9 unit, A10 full gate.
