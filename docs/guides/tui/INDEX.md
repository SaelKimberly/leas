# TUI scenario index

One row per scenario document (the `*-transcript.md` files are its evidence, not scenarios). Built with the
`tui-test` skill's index recipe, with the transcript files excluded and each run's verdict added.

- [narrow-80x24](2026-10-14-132534-scenario-narrow-80x24.md) — leas at 80x24 (table columns, status-bar hints) and at 80x19, where the <20-row layout switches to the compact one-line actions bar instead of the 8-row panel · verdict 5 PASS / 3 PARTIAL / 2 FAIL
- [profiles-import-and-table](2026-10-14-132534-scenario-profiles-import-and-table.md) — leas Profiles tab from the empty state through a clipboard batch import (8 share URLs → 7 endpoints) to the populated table and an expanded multi-variant endpoint · verdict 10 PASS / 0 PARTIAL / 0 FAIL
- [profiles-menus-states](2026-10-14-132534-scenario-profiles-menus-states.md) — leas Profiles tab overlays and modal states — help, speed-test menu, export scope, delete confirmation, and the prefix-search filter including its filtered-empty state · verdict 6 PASS / 4 PARTIAL / 0 FAIL
- [settings-forms](2026-10-14-132534-scenario-settings-forms.md) — leas Settings tab — the 20-node section tree, opening a section into the right pane, field focus and the cursor, and what q does inside a settings form · verdict 8 PASS / 1 PARTIAL / 1 FAIL
- [tiny-80x14](2026-10-14-132534-scenario-tiny-80x14.md) — leas at 80x14 — the compact one-line actions bar the <20-row layout selects, a table viewport that clips one endpoint, and F1's overlay that replaces the content area · verdict 4 PASS / 1 PARTIAL / 0 FAIL
- [colour-focus-audit](2026-10-14-144700-scenario-colour-focus-audit.md) — leas colour and focus audit with get_cell_style/screenshot — the Dracula palette as actually emitted (tabs, selection, failure marker, chrome), the hardcoded popup/status colours that ignore the theme, and the same cells under a light theme · verdict 9 PASS / 1 PARTIAL / 3 FAIL
- [live-resize](2026-10-14-144700-scenario-live-resize.md) — leas driven through live resizes with the resize tool — 120x40 to 80x24 to 80x19 (the overlay branch a fresh small launch never reaches) back to 120x40, checking the layout and any residue · verdict 7 PASS / 0 PARTIAL / 0 FAIL

## Related

- [Aesthetics and UX review](2026-10-14-132534-review-tui-polish.md) — all findings from the five original runs (text-only pass), severity-ranked.
- [Aesthetics and UX review — colour, focus and resize](2026-10-14-144700-review-colour-resize.md) — findings from the two new runs using `get_cell_style`/`screenshot`/`resize`, including the colour pass that supersedes the earlier "not covered" section.
- [Ad-hoc probe evidence](2026-10-14-132534-review-evidence-adhoc.md) — probe reports the earlier review cites.
- `artifacts/` — PNG screenshots taken by the `screenshot` step, cited by the colour and resize scenarios. The `colour-light-canvas-*` pair is re-rendered on a light canvas (`MCP_TUI_TEST_BG=eff1f5`) so a light theme is witnessed faithfully.
- `fixtures/` — synthetic app config (`config.json`, `config-light.json`), the import URL list, the seeded store, and `light-canvas-shots.py` (re-renders the light-theme pair on a light canvas, which is what the contrast finding is read from) and `check-theme-pixels.py` (proves which theme a screenshot shows by sampling pixels).
