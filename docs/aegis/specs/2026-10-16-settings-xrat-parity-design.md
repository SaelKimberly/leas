# Settings Form — xrat Parity Reskin — Design Spec

| Field | Value |
|---|---|
| Date | 2026-10-16 |
| Status | approved — implementing |
| Kind | spec |
| Supersedes | — (extends `2026-10-15-pane-tui-and-profiles-columns-design.md`, which landed the Settings *popup*; this spec redraws what the popup contains) |
| Inputs | user directive (2026-10-16: "improve TUI settings form, to look exactly like it was implemented in thirdparty/xrat"); reference read: `thirdparty/xrat/crates/xrat-app/src/tui/view/modals/settings.rs` (552 lines, the whole modal renderer), `xrat-app/src/tui/theme.rs` (style helpers), `xrat-app/src/tui/keymap/view.rs:15` (`','` opens Settings), `xrat-app/src/tui/view/modals/tests.rs` (exact expected strings); live-reference attempts failed (see §7); current-state reads: `crates/leas/src/ui/settings.rs` (2150 lines), `crates/leas/src/ui/mod.rs:1180-1210` (popup geometry), `crates/leas/src/ops/settings.rs:16-29`, `crates/leas/src/types.rs` (`SettingsMode`), `crates/leas/src/ui/status_bar.rs` (`fit_hints`) |

## 1. Summary

The Settings popup keeps its geometry (already byte-identical to the reference: `clamp(w-4,50,110) × clamp(h-2,20,40)`) and its identity (leas sections, leas persistence). What changes is everything drawn *inside* it: the reference's four-band layout

```
┌ Settings * ─────────────────────────────────────────────┐
│ ┌ Search ─────────────────────────────────────────────┐ │   row 0 (3): search / edit bar
│ │ Press / to filter settings                          │ │
│ └─────────────────────────────────────────────────────┘ │
│ ┌ Sections · 3/9 ─────────┐ ┌ Values · 4/23 ──────────┐ │   row 1 (Min 7): 30 / 70 split
│ │ ▾ Core                  │ │ › * Log Level    warning │ │
│ └─────────────────────────┘ └─────────────────────────┘ │
│ ┌ Help · Core ────────────────────────────────────────┐ │   row 2 (10): field help
│ │ Type      Select                                    │ │
│ └─────────────────────────────────────────────────────┘ │
│ Discard unsaved changes?  y / n                          │   row 3 (0-2): status
└─────────────────────────── [Tab] Focus  [Enter] Save ───┘   footer: hints IN the border
```

replaces today's two-titled-panes-and-nothing-else surface. Zero persistence change: Enter still validates and saves the open section; the popup still guards unsaved edits with `y/n`; no schema, no config key, no protocol.

## 2. Goal / Non-goals / Acceptance

**Goal.** The settings surface reads like the reference: one screen bar telling you what you are editing, a section list and a value list that each say where you are (`3/9`), a help box that explains the field under the cursor, per-field `*`/`·` provenance, and key hints attached to the modal instead of the app.

**Non-goals.** No change to what any setting *does*, to `SettingsSection`, to field keys, or to the save/validate path. No session-wide `Ctrl+S` save (the reference saves a whole config file; leas saves per section on Enter — see D6). No new dependency. The `RoutingRules`/`GroupList`/`GroupForm`/`UpdateForm` right-pane contents keep their current rows; only the chrome around them is reskinned.

**Acceptance.**

| # | Criterion | Proved by |
|---|---|---|
| A1 | Popup draws all four bands (search bar, split, help, status) and the footer hint line in the modal's bottom border, at 120x40 and at the 50x20 minimum | tui-test scenario `settings-xrat-parity` |
| A2 | `Sections · n/N` and `Values · i/n` counters match the selected row / total rows | scenario + unit test on the counter helper |
| A3 | The focused value row renders `›` + provenance marker + label + value; the marker is `*` when the field differs from the form snapshot and `·` otherwise | scenario (`*` after an edit) + unit test |
| A4 | Bools render `✓`/`✗`, empty text fields render `—` (muted), selects keep `< option >` | unit test on the value formatter |
| A5 | `/` focuses the search bar (accent border, `Filter` title when a query is present); typing filters the section list and the value rows; `Enter` applies, `Esc` cancels, `Ctrl+U` clears | scenario |
| A6 | Help box names the field under the cursor with `Field`/`Type`/`Accepts`/`Current` rows and a `Keys` legend; with no field focused it explains the pane | scenario |
| A7 | Status row shows the first validation error (failure colour), the filter-miss line (warning) or the save notice (success). The discard prompt stays the app-level `Confirm` overlay it already was — the reference shows it in its status line only because it has no confirm overlay | scenario + re-run of `settings-forms` |
| A8 | Footer hints track focus (tree / form / routing list / routing form / group list / group form / update form) and never overflow the border width at 80 cols | scenario at 80x24 + unit test on the hint fitter |
| A9 | Existing settings behaviour unchanged: `,` opens, `Esc` closes, dirty `Esc` prompts, focus moves with `Tab`/`Ctrl+W`, `Enter` saves a valid section | the `settings-xrat-parity` scenario (E1-E8) — the 2026-10-14 `settings-forms` transcript predates the reskin and is superseded **for the popup surface** only; its own non-surface notes stay historical |
| A10 | Full gate green: `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace` | verification step |
| A11 | Popup cells report the **app** background (`bg=default` under the harness), not a modal fill; no cell in any modal reports `#808080` | `get_cell_style` on the settings popup, the sections rows and the help overlay (transcript) |
| A12 | Every `theme.color("…")` / `theme.style("…")` string in the workspace resolves against opaline's contract | token audit (0 unknown sites; `bg.surface` was the only one) |

## 3. Locked decisions

| ID | Decision | Why |
|---|---|---|
| D1 | Geometry stays `clamp(w-4,50,110) × clamp(h-2,20,40)`; inner bands `Length(3) / Min(7) / Length(10) / Length(0..2)`; outer block gains `Padding::horizontal(1)` | Verbatim from the reference; already equal for the popup rect, so no reconciliation risk |
| D2 | Sections pane is a **flat row list** (group headers + indented children with `▾`/`▸`, selected row `›` accent-bold), 30 % width; not the cheese tree | The reference's left pane is a flat list of rows; the cheese tree cannot render the `›` + counter chrome without fighting its own styles, and the pane's data is 5 groups / 15 leaves — a list is the boring fit |
| D3 | Section/row counters (`n/N`, `i/n`) count **visible rows after filtering**, 1-based, clamped to `len` | The reference's counters; clamped so an empty filter result cannot print `1/0` |
| D4 | Row prefix is `›` for the selected row, two spaces otherwise; provenance marker is `*` (differs from the form snapshot) or `·` (matches); the reference's `+` (explicit override) is **not** ported — leas has no config-source concept | `*`/`·` both derive from data leas really has (`settings_form_snapshot`); inventing `+` would print a claim we cannot back |
| D5 | Values: `✓`/`✗` bools, `—` for empty text, `< option >` for selects, numbers/floats verbatim | Reference bool glyphs; `—` matches the Profiles table's empty-cell token (one empty-cell convention in the app) |
| D6 | **Per-section Enter still saves.** No `Ctrl+S`, no global dirty session | The reference persists a whole `config.toml`; leas persists section-scoped via `ops/settings.rs`. A session-wide save is a persistence-contract change, out of scope for a reskin |
| D7 | Search (`/`) filters the **section list and the value rows of the open section** with a case-insensitive substring match; the open section is never filtered out of the list unchanged — if the query matches nothing anywhere, the status row says so | Bounded scope: a global field index would need the field defs of every section resolved into one list (they are per-section `&'static` tables) — the visible win (find a field in the section you are in) does not justify that refactor |
| D8 | Search state lives in the `SettingsMode::Split` variant (`search: SettingsSearch { query, active }`, `notice: Option<String>`); cleared on every `enter_settings` | In-memory only, mirrors the reference's modal-local state, and re-entering settings must not resume a stale filter |
| D9 | Footer hints are drawn as the outer block's `title_bottom`, right-aligned in the hint style, fitted by dropping from the left; while the popup is open the app-level status bar renders **no** hint set (mode prefix only) | Reference behaviour; the global bar is the shell's, the modal owns its own keys, and the same key list must not be printed twice |
| D12 | The popup rect is additionally clamped to the live area, and the help band yields its rows before the sections/values split does | Below the reference's 20-row minimum the verbatim formula produced a frame clipped out of its own border; the reference has no small-terminal story here |
| D13 | **Modals have no background of their own.** The popup fills only its borders' text style; the app canvas, the popup and every other modal sit on the same background, and `Clear` wipes the pane content underneath | The reference's `theme::clear()` paints every modal **and the whole app** with one `palette.background`, so a modal is never a different colour than the app (confirmed in `xrat-app/src/tui/theme.rs:253-267` + `view/render.rs:5`). Reported as the popup reading as an unreadable slab: the old fill used `bg.surface`, which is **not an opaline token** — `Theme::color` falls back to `OpalineColor::FALLBACK`, neutral grey `#808080` (`opaline-0.4.2/src/theme.rs:53-59`, `color.rs:26-31`), which `get_cell_style` then reported as the popup's `bg=808080`. The `app.dialog` role now carries text colour only, so the confirmation, help, export, logs-target and add-server modals follow the same rule |
| D14 | Every theme token string is audited against opaline's 28-token contract plus the app's registered roles; an unknown token is a defect, not a style choice | `Theme::color` cannot fail — it substitutes grey. A silent fallback is how the defect above survived the previous review |
| D10 | Help box rows are `Field`, `Type`, `Accepts`, `Current`, `Keys` — no fabricated `Description`/`Default`/`Example` rows | The reference reads those from typed config metadata leas does not carry; printing a default we do not know would be a lie |
| D11 | Theme styles come from `ThemeStyles` (opaline roles): accent = `accent.primary`, muted = `hint`, secondary = `footer_label`, status = `error`/`success`, modal surface = `bg.surface` | Existing app vocabulary; the reference's `accent/chrome/secondary/muted/success/failure` map 1:1 onto these roles |

## 4. Layout spec

Inside the modal (`Padding::horizontal(1)` applied by the outer block):

| Band | Height | Contents |
|---|---|---|
| 0 | 3 | Input bar. Idle: title ` Search `, body muted `Press / to filter settings`. Filtering: title ` Filter `, body `<query>█` accent. Editing a field: title ` Edit <label> · <type> `, body `<value>█` accent. Border accent while filtering or editing, muted otherwise |
| 1 | Min 7 | 30/70 split. Left ` Sections · n/N `: group rows `▾ <Group>` (secondary bold; `▸` when its children are hidden by the filter) and child rows `    <leaf>`; selected row `› ` + accent bold. Right ` Values · i/n `: `›`/space + marker + space + padded label + value; selected row accent bold. Empty: ` Select a section ` / ` No settings match the filter. ` |
| 2 | 10 | Help box ` Help · <section> `. Rows `Field`, `Type`, `Accepts`, `Current`, `Keys` (label secondary bold, value chrome). With no field focused: one muted line naming the pane's keys |
| 3 | 0-2 | 0 when clean and no message; 2 for the discard prompt; 1 for an error or notice |

Label column width: `clamp(right_width - 14, 12, 24)` (reference formula) — the value column then has ≥ 6 cells at the 50-col minimum.

## 5. Keymap deltas

| Key | Scope | Action |
|---|---|---|
| `/` | Split, any focus, not filtering | Focus the search bar (`search.active = true`) |
| printable | search active | Append to `search.query` |
| `Backspace` | search active | Pop the query |
| `Ctrl+U` | search active | Clear the query |
| `Enter` | search active | Apply (keep the query, return focus to the pane it came from) |
| `Esc` | search active | Cancel (clear the query, return focus) |

Everything else is unchanged (D6).

## 6. Verification

- **Unit:** counter clamp (`counter_label(0, 0)`), value formatter (`✓`/`✗`/`—`/`< opt >`), provenance marker (`*` vs `·` from a snapshot diff), filter predicate (section and field label), hint fitting at 80/50 cols.
- **tui-test:** new scenario `settings-xrat-parity` (open → assert four bands + footer → `/` filter → assert filtered rows → `Esc` → edit a field → assert `*` → `Esc` → `y` → assert closed); re-run `settings-forms` for A9.
- **Gates:** workspace clippy `-D warnings`, `cargo nextest run --workspace`, `cargo fmt`.

## 7. Reference-liveness note (why this spec reads source, not screenshots)

Four launch paths were tried against the installed `xrat 0.29.0` (tui-test buffer mode, a `script(1)` pty, a hand-rolled `pty.openpty` + `setsid` + `TIOCSCTTY` harness under `strace`, and the same harness with a sandbox `HOME`). The app dies in every one with `error: application I/O failed` after `AppContext` is ready and after raw mode succeeds; the strace shows the failure is **not** the terminal (`TIOCGWINSZ` returns 0 in the harness) and not the config (`mkdir $HOME/.config/xrat` → `EEXIST`, then 23 migrations found). Under `script(1)` with a fifo on stdin the app did stay alive ≥ 4 s, but the capture never reached a frame the harness could read back. Root cause not established under the sandbox' available `HOME` (`xray`/`sing-box` cores live under `/home/user/.config/xray-tui/bin`, and the reference logs `optional engine probe failed … engine="sing-box" error=application I/O failed` immediately before dying).

Consequence: the reference's appearance is taken from its **renderer source** (`view/modals/settings.rs`, read in full) plus its render tests, which assert the exact strings this spec ports (`Sections ·`, `Values ·`, `^S save`, `Esc close`, `› <section>`). Colour mapping is taken from `theme.rs` style helpers, whose semantics are three lines each. This is recorded so nobody re-litigates the "we should have screenshotted it" question: the source *is* the specification here, and the leas side is verified live with tui-test, where the app does render.
