# Settings Form — xrat Parity Reskin — Implementation Plan

| Field | Value |
|---|---|
| Date | 2026-10-16 |
| Status | in progress |
| Kind | plan |
| Spec | `docs/aegis/specs/2026-10-16-settings-xrat-parity-design.md` |
| Route | inline, owner-local (one module + its types); TDD light — pure helpers get unit tests, layout is proved live |
| Gates | `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo nextest run --workspace`; `cargo fmt`; tui-test `settings-xrat-parity` + re-run `settings-forms` |

## Slices

### P1 — state and types
- `types.rs`: `SettingsMode::Split` gains `search: SettingsSearch` and `notice: Option<String>`; new `SettingsSearch { query: String, active: bool }` (`Default` = empty/inactive); `Clone` impl updated.
- `state.rs`: helpers `settings_search_mut()`, `settings_is_filtering()`, `settings_notice_mut()`.
- `ops/settings.rs`: `enter_settings` seeds `search: SettingsSearch::default()`, `notice: None`.
- **Exit:** `cargo check -p leas` clean; no behaviour change yet.

### P2 — pure helpers + unit tests
- `ui/settings.rs`: `counter_label(selected_idx, total) -> String` (1-based, clamped, `n/N`), `settings_value_display(field_type, value) -> String` (`✓`/`✗`/`—`/`< opt >`), `provenance_marker(snapshot_value: Option<&str>, current: &str) -> char` (`*`/`·`), `section_matches_filter(name, query)`, `hint_line(hints, width) -> Line` (right-aligned, drops from the left until it fits).
- **Exit:** unit tests green (`cargo nextest run -p leas settings::`).

### P3 — popup chrome
- `ui/mod.rs` Settings arm: `Padding::horizontal(1)` on the outer block, `title_bottom(settings::footer_hints(state))`, keep `Clear` + `bg.surface`.
- `ui/settings.rs::render`: replace the two-pane pass with the four-band layout (search bar / split / help / status) per spec §4; sections pane becomes the flat row list (D2) with counters (D3).
- **Exit:** live capture at 120x40 shows all four bands; nothing regressed in the section/field interaction.

### P4 — value rows, markers, help box
- Value rows per D4/D5; label column `clamp(width-14, 12, 24)`; selected row `› ` + accent bold.
- Help box per D10 for `SplitRightPane::Form` (and `GroupForm`, which renders a form); for other panes, a one-line muted key explanation.
- Status row per A7.
- **Exit:** scenario asserts `*` after editing a field, `—` for an empty field, `✓` for a true bool, and the help rows.

### P5 — search
- Key routing before the focus dispatch: `/` enters search; while active, printable/Backspace/`Ctrl+U`/`Enter`/`Esc` are consumed by the bar; `Esc` cancels, `Enter` applies (spec §5).
- Filtering applies to the section list (group hidden when no child matches) and to the value rows (D7).
- Search bar rendering (accent border + `Filter`/`Search` titles).
- **Exit:** scenario filters by a field name and by a section name; empty result shows the status line message.

### P5b — modal surface (added after the D13 report)
- The popup's `bg.surface` fill was an opaline **unknown token** → fallback grey `#808080`. Removed: the popup and every modal now share the app background, as the reference does (`app.dialog` role keeps text colour only).
- Popup rect clamped to the live area; help band yields rows first; pane counters drop below 18 columns (a clipped `2/` reads as a broken number); `Tab` moves focus to the Values pane instead of silently closing the popup; `Tab` from an empty Values pane returns to Sections (its own hint promised it).
- **Exit:** `get_cell_style` shows `bg=default` inside the popup, the help overlay, and the pane; the token audit reports 0 unknown sites.

### P6 — docs + verification
- `docs/guides/tui-manual.md`: Settings popup section rewritten (bands, markers, `/`, counters, footer hints).
- `docs/aegis/INDEX.md`: spec + plan rows.
- tui-test scenario `settings-xrat-parity` recorded under `docs/guides/tui/fixtures/` conventions; re-run `settings-forms`.
- Full gate; commit.

## Risks

| Risk | Mitigation |
|---|---|
| The 50x20 minimum clips the help box or the footer hints | P3 verifies live at the minimum size; hint fitting drops from the left (Quit survives) |
| Search filtering can hide the section you are editing | D7: the filter never removes the open section's own rows silently — an empty result states it in the status row |
| Adding bands steals rows from the section list at 24-row terminals | Band heights are fixed (`3/10`) and the split is `Min(7)`; the section list scrolls to keep the selection visible |
| `SettingsMode::Split` is matched in several places; the new fields break those matches | All construction sites go through `enter_settings`; `..`-patterns stay pattern-compatible |
