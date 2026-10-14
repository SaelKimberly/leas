# leas TUI — aesthetics and UX review

| Field | Value |
|---|---|
| Run at | 2026-10-14 13:25:34 +0500 |
| App under test | leas 0.1.0, debug binary `/home/user/oss/xray-tui/target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Harness | mcp-tui-test 0.3.0 (`/home/user/oss/mcp-tui-test` checkout, driven in-process — the `tui-test` MCP mount dropped mid-session), Python 3.14.7, pyte 0.8.2 |
| Method | five scenario walkthroughs (`docs/guides/tui/INDEX.md`), each with a pre-registered expectation table and a verbatim transcript beside it |
| Fixture | `docs/guides/tui/fixtures/` — synthetic config + 7 endpoints, no real credentials |
| Evidence | one transcript per scenario, plus [ad-hoc probe evidence](2026-10-14-132534-review-evidence-adhoc.md) for four statements the scenarios do not cover; every claim below cites `scenario#Pn` or `scenario` E-id + step |

Screens walked: Profiles (empty state, batch import, populated table, expanded endpoint, sort/view
footer), the four Profiles overlays (help, Server Tools, export scope, delete confirmation), the
prefix-search filter and its filtered-empty state, Settings (tree, section form, focus, back-out) and
the small-terminal layouts at 80x24, 80x19 and 80x14.

## Verdict

| Severity | Count | Where |
|---|---|---|
| blocker | 0 | — |
| major | 7 | menus#P6, menus#P7, settings#P6, settings#P8, narrow#P1, narrow#P2, tiny#P3 |
| minor | 15 | import#P2–P4, menus#P1–P3, menus#P5, settings#P1–P3, settings#P5, settings#P7, narrow#P3, tiny#P1, tiny#P2 |
| nit | 7 | import#P1, menus#P4, menus#P8, settings#P4, narrow#P4, narrow#P5, tiny#P4 |

33 of 45 scenario expectations PASSed; 9 were PARTIAL and 3 FAILed. Nine of the twelve were wrong
row/content predictions in my own expectation tables (popup and layout rows move with the terminal
size); the other three were wrong predictions *about the app* that turned out to be findings —
settings#E10 (blank screen after `Esc`) and narrow#E8/E10 (the `<20`-row layout compacts instead of
overlaying). Every one is recorded in its scenario's *Corrections* rather than patched over.

## Findings, ranked

Each row: what the user sees → why it matters → what to change. The scenarios hold the verbatim
screens; `step N` points into the matching transcript.

### Fix first — behaviour that contradicts what the screen says

1. **`d`'s confirmation keeps the Profiles hint bar (menus#P6, major).** With `╭ Confirm ─…╮` up
   (step 23), row 39 still reads `[→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next
   [?] Help  [q/Ctrl+C] Quit` (step 24) — while only `y`/`n`/`Esc` do anything and `q` *cancels the
   dialog*. The same overlay serves `Quit?`, `Clear all stats?` and the group confirmations, so the fix
   is one state-aware hint set (`ui/status_bar.rs` is the renderer; the confirmation lives in
   `ui/mod.rs`/`ui/profiles.rs`).
2. **A filter that matches nothing claims the store is empty (menus#P7, major).** `/ams` (a *prefix*
   search — `nl` matches, `ams` does not) renders ` No profiles — press 'a' to add one` under
   ` View: Active [P]  / ams▉`, with the table box and header gone (steps 27–29). A user cannot tell
   "no data" from "filtered to nothing", and the offered action (`a`) is the wrong one. Distinguish the
   two states, keep the header, and hint `Esc`.
3. **`Esc` out of Settings leaves a blank window (settings#P8, major).** `Esc` at the tree level sets
   the mode back to `List` but leaves the tab on Settings, which has no List-mode body: rows 1–30 are
   empty (step 26), leaving the tab bar, the actions panel and a status bar whose only useful hint is
   `q`. `ui/settings.rs:385` is the two-line cause; either return to the Profiles tab or give the
   Settings tab a body.
4. **`q` types a character into a config value (settings#P6, major).** In a focused form field,
   `send("Z")`, `send("q")` produced `│ Sing-Box Path           : > Zq │` (step 20) with the app still
   running (step 21); in the tree `q` is ignored (probe14). `q` quits on every other screen, so the
   reflex silently edits proxy configuration, and `Esc` then discards it without a dirty marker.
   `docs/guides/tui-manual.md` still documents `q / Ctrl+C — Quit application` for this tab.
5. **`F1` below 20 rows replaces the working screen with the log panel (tiny#P3, major).** At 80x14,
   `F1` makes the content area entirely ` ⚙ Actions Log  ////…` / `○ Disconnected` / `🖥 …` / `⏱ …` /
   `📊 …` / `📋 Core: …` (step 9) while the tab bar still says `Profiles`; the hint row never mentions
   `F1` closing it, and the toggle is documented as a panel toggle. Cap or overlay the panel instead of
   handing it the content area (`ui/mod.rs:964-977`).
6. **80 columns silently drops the verdict columns (narrow#P1, major).** The header stops at
   `Protocol Info` and the last visible cell is cut inside a token — `vless/tcp/reali█│` (step 5) — so
   `Test` (delay / `[name]` failure marker), `Outbound` and `Country` are gone with no cue. Keep `Test`
   at every width and drop `Feat`/`Country`/`Outbound` first (`ui/widgets/data_table.rs` width strategy).
7. **The hint bar loses its tail — including quit — at 80 columns (narrow#P2, major).** Row 23/18 reads
   ` Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next` and stops
   mid-token (steps 7, 19); `[?] Help` and `[q/Ctrl+C] Quit` are the casualties. Anchor the right-hand
   hints, or drop from the left by priority.

### Then — density, chrome and readability

8. **The always-on 8-row Actions Log panel restates the status bar (menus#P1, narrow#P3, minor).** At
   120x40 it costs 8 of 40 rows for one log line plus `○ Disconnected`, `⏱ TCP: … RP: … SPD: …`,
   `📊 ⬆ … ⬇ … 💾 …` (menus step 3) — and ` Disconnected` is repeated on row 39. At 80x24 it is 8 of 24
   (narrow step 7). The app already ships the better default: below 20 rows it collapses to
   `○ vless 203.0.113.77:443 [xray] | <last log line>` (tiny steps 3–4). Raise that threshold
   (`ui/mod.rs:78`) or persist the `F1` choice.
9. **The endpoint detail panel is a wall of unlabelled cells (import#P3, minor).** Nine columns with no
   header, and "no value" written `-` in three of them and `—` in three others (step 23). Add a header
   row and one empty glyph (`ui/profiles.rs`).
10. **The batch-import list hides the only human field (import#P2, minor).** Every row is a
    head-truncated share URL (`…security=rea…`, step 10), so the `#name` the user recognises is off the
    end. Lead with the parsed name.
11. **The help overlay clips its own instructions (menus#P3, minor).** `Set as active server / Activa`
    (step 6) — the popup is a fixed 52 columns while the longest row needs more. Size it to content.
12. **The panel's last-log line leaks Rust internals and is cut mid-word (menus#P2, minor).**
    `📋 Core: [info] startup: version=0.1.0 page=7 rows tcp-timeout=DurationOrSecs(5s) real-timeout=…
    real-r` (step 3). Ellipsize, and keep `Debug`-formatted values out of user-facing text.
13. **`Enter` on a Settings category collapses it; the pane opens empty (settings#P3, minor).** The first
    keystroke in Settings does nothing useful and the 81×28 right pane says only `Select a section`
    (steps 4, 23). Select the first leaf on entry.
14. **Export modal blanks the tab bar's row (menus#P5, minor).** `Line 0` is empty while the dialog is up
    (step 18), so the top of the screen looks torn and the content shifts. Keep or reclaim the row.
15. **The expanded panel's border collides with the scrollbar column (import#P4, minor).**
    `╭───…───╮█│` / `╰───…───╯█│` (steps 24–25). Inset the panel one cell.
16. **A form edit is discarded without a dirty marker (settings#P5, minor).** `Esc` from a changed field
    returns to the tree with no confirmation and nothing to say the value was dropped (steps 20, 23).
17. **Focus is invisible until the first `Tab` (settings#P7, minor).** The cursor is parked at
    (39, 120) — the bottom-right corner — on entry (step 15), and every field wears the same `> `
    prefix, so nothing indicates the edit target until `Tab` puts the caret inside a value (step 17).
18. **The table clips a row without saying so (tiny#P2, minor).** At 80x14 six data rows are drawn while
    the footer claims `rows 1-7 of 7` (step 3); `End` proves the seventh is reachable (step 7). Report
    the visible range.

### Polish — small, mechanical

19. `#` header is left-aligned over a right-aligned numeric column (`#` at col 4, values ending at col 9)
    — import#P1.
20. Server Tools separators are `─────` inside a 38-cell menu, and `Stop Testing` is disabled by dimming
    only — menus#P4.
21. The hint bar advertises `[→] Expand  [↑↓] Variant  [Ctrl+Enter] Connect` in states where they cannot
    apply (filtered-empty, menus#P8).
22. Settings field rows are pitched two rows apart, one field per blank-row pair, leaving 60% of the pane
    empty — settings#P4.
23. The Settings tree's trailing integer (`│▾ Core                           2│`) is an unlabelled child count
    — settings#P1.
24. The Settings tree's hint row omits that `Tab` leaves the screen (help overlay and manual both say it)
    — settings#P2.
25. `////` banner chrome (Statistics, Native Activity, Actions) sits beside box-drawing panels on other
    tabs — narrow#P5.
26. The compact bar's connection glyph has no label (`○ vless …`) where the full panel writes
    `○ Disconnected` — tiny#P4.
27. At 80 columns the Settings tree shrinks to 24 cells and the child count crowds the label — narrow#P4.
28. The compact bar clips its log message mid-token — tiny#P1.

## Documentation drift (`docs/guides/tui-manual.md`)

| # | Manual says | App does | Evidence |
|---|---|---|---|
| D1 | Settings is "a menu of 14 sections" in a fixed order, with a separator after the first five | a two-level tree of 20 nodes in five collapsible groups, no separator | settings steps 5–6 |
| D2 | Settings tab: `q / Ctrl+C — Quit application` | `Ctrl+C` quits; `q` is typed into a focused field, and ignored in the tree | settings step 20; probe14 in the [ad-hoc evidence](2026-10-14-132534-review-evidence-adhoc.md) |
| D3 | Statistics empty state: `No data — connect to a server` | `Not connected — select a profile and press Ctrl+Enter to connect` | probe8 in the [ad-hoc evidence](2026-10-14-132534-review-evidence-adhoc.md) |
| D4 | the overlay is titled after the speed test (`Speed Test`) | the popup title is `Server Tools`, while the status bar says `Server Tools` and the hint says speed test | menus step 11; `ui/mod.rs` `render_speed_test_menu` |

## Verified good

- **First run**: empty state names the key that fixes it (` No profiles — press 'a' to add one`), the
  batch import counts before it acts (` 8 valid, 0 invalid — Enter to import, Esc to cancel`), and 8
  share URLs become 7 endpoints because grouping is `host:port` (import E1–E6).
- **Keyboard-only**: every state in this review — overlays, modals, forms, filters, tabs, the expanded
  panel — is reachable with `Esc`/`Enter`/arrows/`Tab` alone; no mouse is needed.
- **Non-colour cues** where they matter most: the menu/scope selection marker is `►`, the active
  protocol variant is `●` vs `○`, the sort column is in the header (`Test ↑`), modal popups are
  bordered and titled (import E9/E10, menus E4).
- **Destructive actions**: the delete dialog names its object and defaults to `N` in its own text
  (` Delete "203.0.113.77:443"? (y/N) `) — menus E7 and its *Corrections*.
- **Small terminals**: below 20 rows the app keeps the table and collapses the panel to one line
  (tiny step 3), and at 80 columns every column left of `Protocol Info` survives with correct
  box-drawing (narrow steps 9–10).
- **Focus and navigation on the Settings form**: `Tab` moves focus and the caret lands inside the
  focused field's value (`row 4, column 67`), the breadcrumb tracks the path (` Settings > Core `), and
  `Esc` backs out one level cleanly (settings E4–E9).

## What this pass did not cover

- **Colour and ANSI.** Buffer-mode reads are text-only, so the `dracula` palette, contrast, colour-only
  semantics and the selection highlight were not evaluated. Several findings (settings#P7's focus cue,
  menus#P4's disabled row) would be softened or sharpened by that view. **Superseded:** the companion
  [colour, focus and resize review](2026-10-14-144700-review-colour-resize.md) covers colour with
  `get_cell_style`/`screenshot` and finds three colour findings (a major light-theme contrast bug, a
  theme-independent dialog, an unstyled table header).
- **Resize mid-session** (no resize step in the harness vocabulary — the overlay branch of the small
  layout is only reachable via `F1` in a headless run), **the mouse** (scroll-wheel handling exists in
  `ui::handle_mouse` but no scenario drives it), **network flows** (speed test, subscription update,
  export, connect) and **the Logs / Statistics / Native Activity content** beyond their empty states.
  **Superseded in part:** tui-test 1.0.1's `resize` tool drives SIGWINCH mid-session, and
  [`live-resize`](2026-10-14-144700-scenario-live-resize.md) shows a session that starts tall and then
  shrinks below 20 rows hides the profile table entirely — a major finding no launch-only pass could
  reach.

## Reproduce

```bash
cd /home/user/oss/xray-tui
R=/home/user/.cache/leas-tui; mkdir -p $R
# the fixture is per-scenario scratch; each scenario's "Environment and fixtures" repeats its own block
for L in profiles-menus settings-forms narrow-80x24 tiny-80x14; do
  rm -rf $R/$L && mkdir -p $R/$L/config/leas
  cp docs/guides/tui/fixtures/config.json docs/guides/tui/fixtures/seeded/data.db $R/$L/config/leas/
done
# the import scenario needs its clipboard prerequisite (see its own section) and an empty store
rm -rf $R/profiles-core && mkdir -p $R/profiles-core/config/leas
cp docs/guides/tui/fixtures/config.json $R/profiles-core/config/leas/
```

Runner (in-process `run_scenario`, plus the pyte guard described in import#*Tooling friction*):
`~/.cache/leas-tui/run.py`, invoked as
`uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py doc <scenario.md> <label>`.

Fixture inventory: `fixtures/config.json` (app config; `check_on_startup` off), `fixtures/import-urls.txt`
(8 synthetic share URLs), `fixtures/seeded/data.db` (7 endpoints / 8 protocols, produced by the
`profiles-import-and-table` run). The seeded store is regenerated by re-running that scenario against an
empty store — do that after any schema change rather than reusing the committed file.

Teardown of this pass: every scenario ended with `session closed` (the harness closes what it
launched), `rescue_files: []`, `pgrep -af target/debug/leas` empty, no `*.save` files under the scratch
root, and the clipboard restored to its pre-run content. The `tui-test` MCP mount was down for the whole
pass (all runs went through the in-process entry point), so a mounted `list_sessions` was not available
as a cross-check.

> **Added afterwards (2026-10-14, second pass):** this environment exports `NO_COLOR=1`, and crossterm
> 0.29 honours it by suppressing *all* colour emission. Every run of this pass therefore executed a
> monochrome copy of the app — harmless for its text findings, but it means nothing here describes the
> app's colours. The companion
> [colour review](2026-10-14-144700-review-colour-resize.md) reruns the same surfaces with
> `env -u NO_COLOR` and covers them.
