# TUI Polish & Theming — Design Spec

| Field | Value |
|---|---|
| Date | 2026-10-14 |
| Status | proposed |
| Kind | spec |
| Supersedes | — |
| Inputs | `docs/guides/tui/INDEX.md` (7 scenarios, 36 polish rows, 7 review findings, 4 doc-drift items) |
| Decision authority | repo conventions in `AGENTS.md`; scenario evidence in `docs/guides/tui/` |

## 1. Summary

The seven `tui-test` walkthroughs produced 36 evidence-backed defects (10 major, 17 minor, 9 nit) plus
4 documentation-drift items. They cluster into five root causes, not thirty-six:

| Theme | Rows | Root cause (one owner each) |
|---|---|---|
| T1 state truthfulness | 7 (4 major) | the hint bar and the empty states are per-tab constants; nothing recomputes them from `AppState` |
| T2 small-terminal layout | 12 (4 major) | `actions_compact` is decided once from the *startup* size (`ui/mod.rs:78`); no width-aware column or hint selection |
| T3 theming | 8 (1 major) | the palette bridge maps 10 colours to 11 roles, an unused style helper exists, and 33 sites hardcode `Color::*` |
| T4 data density | 9 (1 major) | table/panel/tree cells are rendered without headers, alignment or one empty-value glyph |
| T5 docs | 4 | `docs/guides/tui-manual.md` predates the tree UI, the theme table and the current hint sets |

The user has chosen the fix for T3's foundation: replace `ratatui-themes` 0.3 (+ the
`ratatui-cheese` bridge) with **opaline 0.4.2**, a token-based theme engine whose 28 semantic tokens,
14 contract-tested styles, `register_default_token()` app-level derivation and ratatui/crossterm
adapters cover both the missing plumbing and the hardcoded chrome. This spec fixes all five themes;
the plan sequences them.

## 2. Goal / Non-goals / Acceptance

**Goal.** Every screen states what it is and what to press; the small-terminal paths keep the tab's
content; all colour comes from one theme source that works on light and dark themes; the manual
describes the app that ships.

**Non-goals.** No new screens, no protocol/DB behaviour, no rewrite of `ui/widgets/data_table.rs`, no
theme editor UI beyond selecting from the builtin list, no change to the Logs tab's data source.

**Acceptance (each is machine-checked by a scenario).**

| # | Criterion | Proved by |
|---|---|---|
| A1 | Under a light theme the status-bar hint row's contrast rises from the measured 1.23:1 to ≥4.5:1 on every screen that shows it — **met**: the hint role is *derived* (`derive_readable` in `ui/theme.rs`) — the theme's `text.muted` darkened against `bg.selection` until it clears 4.5:1, because no Latte token reaches that on the selection strip (`text.primary` tops out at 4.39). Measured live: light **4.64:1** (`#4b4c5c` on `#bcc0cc`), dark **4.53:1** (`#b4b6bf` on `#44475a`). It stays a registered token, so a user TOML can override it | `colour-focus-audit` (new `style()` assertions on `bg`/`fg` for both themes) |
| A2 | A confirm dialog's fill and text follow the theme; only the border stays semantic red | `colour-focus-audit` E12 + `profiles-menus-states` |
| A3 | The table header carries a style under every theme (glyph and padding alike) | `colour-focus-audit` E3 |
| A4 | The hint row matches the state: a modal shows `y/N`, a filtered-empty list says so, a zero-row list offers no Expand | `profiles-menus-states` E6/E8/E9, `settings-forms` |
| A5 | `Esc` out of Settings returns to the Profiles tab; no screen renders an empty content area | `settings-forms` E10 |
| A6 | A live shrink below 20 rows keeps the table and uses the compact bar; `F1` never takes the content area | `live-resize` E4/E5, `tiny-80x14` E4 |
| A7 | At 80 columns `Test` survives, clipped cells carry an ellipsis, and the hint row keeps `Quit` | `narrow-80x24` E2/E3/E4 |
| A8 | All 7 existing scenarios re-run green, plus `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo nextest run --workspace` | verification step |
| A9 | No `Color::Rgb/Gray/...` literal survives in `crates/leas/src/ui/` outside `ui/theme.rs` | `grep` gate in the plan |
| A10 | `gui.theme` is gone; `theme_name` is the only theme input | `grep` gate |

## 3. Locked decisions

| ID | Decision | Why |
|---|---|---|
| D1 | Theme source is **opaline 0.4.2**, features `builtin-themes`, `ratatui`, `gradients`, `global-state`, `discovery`. `widgets` deferred until its render target is verified | token model + adapters cover T3 end to end; 39 themes; `register_default_token()` is the mechanism for the app's semantic roles |
| D2 | One owner for theme identity: `AppState.theme` (opaline `Theme`). Retire `gui.theme: Option<String>` (`crates/leas-config/src/app_config.rs:140`), which is currently a dead second input | two fields, one used (`state.rs:507` reads `theme_name`) — an entropy the swap must not carry forward |
| D3 | `palette_bridge.rs` and the 16 `ThemeStyles::*` helpers (108 call sites) migrate to opaline in one sweep. No adapter shim, no `Palette` type | the bridge is the reason the mapping is partial and the reason a light theme breaks |
| D4 | App semantic roles become **registered tokens**: error, warning, success, hint, muted, badge, `table.header`, `table.row.selected`, `table.row.alt`, `dialog.fill`, `dialog.text`, `statusbar.hint` | makes T3's remaining colour work declarative and theme-testable |
| D5 | One hint owner: `hints_for(&AppState) -> Vec<(key, label)>`, rendered by `status_bar::render`. Empty states distinguish *no data* from *no match* | T1's four majors are all this function missing |
| D6 | `actions_compact` and the panel height are recomputed per frame from `frame.area().height`; the `<20` overlay branch is deleted, not patched | collapses T2's four majors (fresh-launch compact, resize overlay, `F1` overlay, 8-row panel at 80x24) |
| D7 | Column drop is priority-based and clipped cells are ellipsized; the hint row drops from the left, `Quit` last | T2's two 80-column majors |
| D8 | The manual's "Visual Theme" section documents tokens, not hex; the 4 drift items are corrected | T5 |
| D9 | Fixtures guard against the monochrome trap: the light/dark configs assert `NO_COLOR` is dropped, and every colour claim in a scenario carries `shot()` | the earlier pass nearly reported "the app emits no colour" as an app defect |

## 4. Current-state inventory (evidence)

**Colour ownership today.** 108 `ThemeStyles::*` uses across 11 files, 19 `current_palette()` calls,
11 `ThemeName::` uses in tests, and 33 hardcoded `Color::*` sites:

| File | Sites | What |
|---|---|---|
| `ui/mod.rs` | 9 | confirm popup `Color::Red`/`Rgb(40,20,20)` (46,52-53); popup fill `Rgb(30,30,40)` (1188,1258); speed-test/help popups (1175,1238,1241-1242,1312) |
| `ui/status_bar.rs` | 3 | testing chip `Black`/`Yellow` (83-84); hint text `Color::Gray` (148) — the light-theme bug |
| `ui/logs.rs` | 9 | level colours `Cyan`/`Yellow`/`Gray` (52,91,93,95,97); popup fills (560,588,601) |
| `ui/export.rs` | 6 | popup fill + list styles (207-253) |
| `ui/statistics.rs` | 4 | placeholder styles (68-77) |
| `ui/theme.rs`, `ui/profiles.rs` | 2 | `Color::Reset` (deliberate), a test-only `Rgb` (2162) |

**Dead code and duplicate owners.** `ThemeStyles::table_header` is defined (`ui/theme.rs:26`) and never
called — the table header is the unstyled row A3 targets. `gui.theme` is a second theme input that
nothing reads.

**The bridge.** `palette_bridge::from_theme_palette` maps `ratatui_themes::ThemePalette` (10 colours) to
`ratatui_cheese::theme::Palette` (11 roles) — `faint` duplicates `muted`, `border` duplicates
`secondary`. opaline's 28 tokens remove the need for that mapping entirely.

**Findings by theme** (full text and verbatim evidence in `docs/guides/tui/`):

- **T1** — `menus` P6 (hints unchanged under Confirm; `q` cancels), P7 (filter-empty claims "No
  profiles"), P8 (hints for zero rows); `settings` P2 (tree hint omits Tab-leaves), P8 (`Esc` → blank
  content area); `live-resize` P2; `tiny` P4.
- **T2** — `narrow` P1 (80 cols drops `Test`/`Outbound`/`Country`, cell cut mid-token), P2 (hint row
  truncated), P3 (8-row panel at 80x24), P4/P5 (nits); `tiny` P1 (compact-bar clipping), P2 (6 of 7
  rows, no cue), P3 (`F1` takes the content area); `live-resize` P1 (shrink hides the table).
- **T3** — `colour` P3 (hardcoded grey hints, ≈1.2:1 on light), P2 (dialog chrome), P1 (unstyled
  header), P4/P5 (nits); `menus` P2 (log line leaks `DurationOrSecs(5s)`).
- **T4** — `import` P1–P4 (`#` alignment, raw URLs in batch list, unlabelled sub-table, panel border vs
  scrollbar); `settings` P1/P3/P4/P5/P7 (tree count, empty pane, row pitch, discard without dirty
  marker, focus invisible until Tab), P6 (`q` types into a field); `menus` P1/P3/P4/P5 (duplicated
  status lines, help popup clipping, 5-cell separators, modal blanks the tab row).
- **T5** — D1–D4 of the text review: flat 14-item menu vs the 20-node tree, `q — Quit` on the Settings
  tab, the Statistics empty-state wording, and the overlay title (`Server Tools` vs "Speed Test").

## 5. Design

### 5.1 Theme foundation (T3, D1–D4)

```
config.theme_name ──► opaline::load_by_name(slug) ──► Theme
                                                   ├── theme.color("token")      (28 core + app tokens)
                                                   ├── theme.style("name")      (14 core + app styles)
                                                   └── theme.span/style → ratatui Style
```

- `AppState.theme: Theme` replaces `theme_name: ThemeName` + `current_palette()`.
- `ui/palette_bridge.rs` is deleted; `ui/theme.rs` keeps a thin mapping table from the 16 helper names
  to opaline token/style names, so the 108 call sites change shape once
  (`ThemeStyles::hint(palette)` → `state.theme().style("app.hint")`) rather than being rewritten one by
  one semantically.
- App tokens registered once at load: `app.error/warning/success/hint/muted/badge`,
  `table.header/row.selected/row.alt`, `dialog.fill/dialog.text`, `statusbar.hint`, `log.level.*`.
- The 33 hardcoded sites become token lookups; `Color::Reset` survives only where the code documents a
  deliberate notch (`ui/theme.rs:75`).
- Theme slugs stay kebab-case. Both fixtures' names (`dracula`, `catppuccin-latte`) exist in opaline's
  builtin list, so no config migration is needed — but the load path must fail loudly on an unknown
  slug rather than silently falling back (the earlier pass showed a silent fallback cost a run).

### 5.2 State truthfulness (T1, D5)

`hints_for(&AppState) -> Vec<(&'static str, &'static str)>` in one module, consulted by
`status_bar::render`:

| State | Hints |
|---|---|
| List, rows present | `[↑↓] Select  [→] Expand  [Enter] Activate  [Tab] Next  [?] Help  [q] Quit` |
| List, zero rows | `[a] Add  [Ctrl+V] Import  [Tab] Next  [?] Help  [q] Quit` |
| Search focused, no match | `No match for "<q>"  [Esc] Clear  [q] Quit` |
| Any confirm modal | `[y] Confirm  [n/Esc] Cancel` |
| Settings tree | `[↑↓] Navigate  [Enter] Open  [←→] Collapse  [Tab] Next tab  [Esc] Close` |
| Settings form | `[Tab] Next field  [Enter] Save  [Esc] Back` |
| Panel overlay open (if ever) | `[F1] Close panel  [q] Quit` |

`q` is a no-op inside editable fields (T4 `settings` P6) and quits everywhere else — one meaning, one
owner. `Esc` from the Settings tree returns to the Profiles tab (`ui/settings.rs:385`).

### 5.3 Small-terminal layout (T2, D6–D7)

Per frame: `let compact = frame.area().height < 30; let panel_rows = if compact { 1 } else { 8 };`
The `<20` overlay branch (`ui/mod.rs:964-969`) and `F1`'s ability to take the content area are removed;
`F1` toggles the panel's height only, and the hint row says so while it is open.

At 80 columns: the table drops columns in a fixed priority order (`Country`, `Outbound`, `Feat`) and
keeps `Test`; every clipped cell ends in `…`; the hint row is built right-to-left from `Quit` so the
quit affordance survives every width.

### 5.4 Data density (T4)

- Profiles table: right-align the `#` header in its slot; add a header row to the expandable panel and
  one empty-value glyph (`—`); inset the panel one cell so its border stops colliding with the
  scrollbar.
- Batch import: each row leads with the parsed `#name`, then `host:port`.
- Settings: label the tree's trailing count (`2 sections`) or drop it; select the first leaf when the
  pane opens so `Enter` opens instead of collapsing; focus the first field on open and mark a form
  dirty.
- Menus/help: separators span the menu's inner width; the help popup sizes to its widest row; modals
  keep the tab bar's row.

### 5.5 Documentation (T5, D8)

`docs/guides/tui-manual.md`: replace the "Visual Theme" table with the token list, restate the Settings
screen as the 5-group/20-node tree, fix the Settings key table (`Tab` cycles tabs; `q` is not a quit
key there), the Statistics empty-state wording, and the overlay title.

## 6. Verification

| Criterion | Mechanism |
|---|---|
| A1–A3 | `colour-focus-audit` gains `style()` assertions for both themes; contrast computed from the returned hexes; a `shot()` beside each colour remark, read before the claim is written |
| A4–A5 | `profiles-menus-states` and `settings-forms` gain assertions for the new hint sets and the Esc path |
| A6–A7 | `live-resize` asserts the table survives 80x19; `tiny-80x14` asserts `F1` keeps the content; `narrow-80x24` asserts `Test` survives and `Quit` is present |
| A8 | all 7 scenarios re-run + `cargo clippy --workspace --all-targets --all-features -- -D warnings` + `cargo nextest run --workspace` |
| A9, A10 | `grep -rn "Color::\(Rgb\|Gray\|Black\|White\|Cyan\|Yellow\)" crates/leas/src/ui/` → only `ui/theme.rs`; `grep -rn "gui.theme\|\"theme\"" crates/leas-config/src/` → gone |

The scenarios are the regression suite: any change to the hint owner, the panel height or the token
names must re-run them, and the transcripts are the evidence.

## 7. ADR signals

- **ADR candidate 1:** opaline replaces `ratatui-themes`/`ratatui-cheese` as the theme source, and the
  app's semantic roles are registered tokens rather than a palette bridge.
- **ADR candidate 2:** screen state (hints, empty states) is derived per frame from `AppState` in one
  owner, not stored per tab.
- **ADR candidate 3:** terminal size is read per frame for layout decisions; nothing about the layout
  is fixed at startup.

## 8. Risks / rollback

| Risk | Mitigation |
|---|---|
| opaline's API is only known from its README (no vendored copy yet) | P0 spike vendors the crate and verifies every call the design uses before any migration task starts; the plan's first task is that spike |
| 108 `ThemeStyles::` call sites make a large mechanical diff | one mapping table + one sweep, reviewed as a single "rename" diff; `clippy -D warnings` catches signature drift |
| theme slugs change meaning across the swap | both fixture slugs exist in opaline; unknown slugs must fail loudly (asserted in the spike) |
| a token name chosen here has no opaline equivalent | `register_default_token()` accepts app-level tokens, so TOML themes can override them; the spike confirms the registration API |
| light-theme fixes regress the dark theme | both themes are fixtures; A1 is asserted for both |
| scenario transcripts predate the change and stop passing | expected: the plan includes re-running all 7 and recording new transcripts beside the old ones |

Rollback: the swap is one dependency plus one mapping table; reverting the crate and the table restores
the previous look without touching behaviour. The hint owner and the per-frame size read are independent
and can land separately.

## 9. Phasing

| Phase | Content | Standalone value |
|---|---|---|
| P0 | opaline spike: vendor, verify API, pin version, fail-loud slug loading | unblocks P1 |
| P1 | theme foundation: `AppState.theme`, delete the bridge, token registration, colour sweep (D1–D4) | fixes the light-theme major |
| P2 | hint/state truthfulness (D5) | fixes 4 majors, incl. the blank Esc screen |
| P3 | per-frame size + width-aware columns/hints (D6–D7) | fixes 4 majors |
| P4 | data density (§5.4) | 9 rows |
| P5 | manual + fixture hardening (D8–D9) | drift + the monochrome trap |

## 10. Evidence-dependent items (not open decisions)

- opaline 0.4.2 exists and ships Dracula + Catppuccin Latte (verified against its README/crates.io
  listing); whether `widgets` renders ratatui is unverified → deferred, not assumed.
- The 33 hardcoded sites and the 108 call sites are counted from this checkout; a prior branch may
  differ.
- `#`-header alignment, panel-border collision and the viewport count were measured under tui-test
  1.0.1's column-exact rendering, so the coordinates are stable.

## 11. Corrections found while executing P0 (opaline 0.4.2, read from the vendored source)

| # | Assumption in this spec | Verified behaviour | Consequence |
|---|---|---|---|
| 1 | an unknown slug fails loudly at load | `load_by_name` returns `Option<Theme>` | `ui/theme::load` maps `None` to a typed error; the fail-loud property is kept, by hand |
| 2 | the ratatui adapter returns `ratatui::style::Style` | it provides `From<OpalineStyle> for Style` (and `From<OpalineColor> for Color`) | helpers end in `.into()`; `OpalineStyle` itself has `with_fg`/`with_bg` and `Stylize` but **no** `with_bold`, so bold is set through the trait |
| 3 | `global-state` is a useful feature to enable | a process-wide `current()`/`set_theme()` singleton | **left off** — it would be a second theme owner, the exact duplication D2 removes |
| 4 | `widgets` renders egui (so the picker was deferred) | `widgets` is a **Ratatui** `ThemeSelector` + `ThemeSelectorState` | the theme picker the manual already promises is in reach; feature enabled, wiring is new work |
| 5 | `ratatui-cheese` can be dropped with the bridge | cheese is also the widget toolkit (`Tree`, `List`, `Input`, `Select`) and takes its own `Palette` | kept as a widget dep; `ui/theme::widget_palette` is the single adapter, and it is the only place cheese's palette shape appears |

`Theme::color(token)` / `Theme::style(name)` are two namespaces (28 contract tokens, 14 contract
styles), and `register_default_token`/`register_default_style` fill gaps only, so a user TOML can
override any app role. Both fixture slugs (`dracula`, `catppuccin-latte`) exist as builtins, so no
config migration was needed.

## 12. Sources

- `docs/guides/tui/INDEX.md` and the 7 scenario documents + transcripts (the findings corpus)
- `docs/guides/tui/2026-10-14-132534-review-tui-polish.md`, `2026-10-14-144700-review-colour-resize.md`
- `crates/leas/src/ui/{theme.rs,palette_bridge.rs,mod.rs,status_bar.rs,settings.rs,profiles.rs,logs.rs,export.rs,statistics.rs}`
- `crates/leas/src/state.rs:507`, `crates/leas-config/src/app_config.rs:32,140`
- opaline README / docs.rs 0.4.2 (token model, features, API sketch)
- `AGENTS.md` (gate: `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace`)
