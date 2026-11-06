# TUI scenario index

Reference for the scenario records under this directory: what each one proves, how the harness behaves,
and how to replay a document. It answers "which scenario covers this surface" and "how do I run it
again". It does not review the app; findings live in each scenario's verdict and in the two review
documents.

A scenario document is a dated evidence record: expectations were written before the run, observations
are tool results, and a wrong expectation stays in the file with its correction. A `*-transcript.md` file
is that scenario's raw capture, not a scenario.

## Harness rules

The harness is `mcp-tui-test`, driven through the MCP tools or through `run_scenario`. Five rules cover
every document here.

**`assert_text` is literal, `expect` is a regex.** `assert_text` maps to `assert_contains`, which does a
plain substring search over the captured screen (`if text in model.text`). `expect` maps to `expect_text`,
which calls `re.compile(pattern)` and searches each screen line, falling back to the ANSI-stripped raw
buffer. So `assert_text("2: [Details]  Metrics  Tasks")` matches the literal brackets, while
`expect("2: [Details]")` reads `[Details]` as a character class and cannot match it. Use `assert_text` for
text that contains regex metacharacters, `expect` for synchronization (it waits, with a timeout).

**One key per call.** The harness accepts several keys in one call (`key("down", "down")`), but a list
over-delivers: the 2026-10-16 run measured `send_special_keys([down]*6)` moving eight rows, while a single
call moves exactly one. Every document here sends one key per call, so one transcript step equals one
keystroke. `send` sends text, `key` sends named special keys (`up`, `down`, `enter`, `escape`, `f1`).
`Esc` must go through the named-key tool: a raw `\u001b` is swallowed and the press becomes the following
`Enter`, which reads as a cancelled action that did not cancel.

**Fixtures are synthetic and copied per run.** Fixture root: `docs/guides/tui/fixtures/`.

| File | Used for |
|---|---|
| `config.json` | app config, default theme (`dracula`) |
| `config-light.json` | the light-theme launch; copy it to `config.json` in the fixture home, never under its own name |
| `seeded/data.db` | 7 synthetic endpoints, pre-populated store. It ages out of the Active view after the 7-day TTL, so aggregate numbers can read `0` |
| `import-urls.txt` | 8 synthetic share URLs for the clipboard import; no real credentials |

Each scenario document builds its own `XDG_CONFIG_HOME` under `/home/user/.cache/leas-tui/<label>`,
containing `config/leas/` with the config and, when the scenario needs data, `data.db`. Deleting that
directory and re-running replays the scenario from its starting state; a scenario that starts empty
(`profiles-import-and-table`) lets the app create `data.db` itself, which keeps it idempotent.

**The clipboard is a prerequisite for the import scenario.** `Ctrl+V` is the app's only entry into the
batch-import screen, and a scenario has no clipboard step. Before running
[profiles-import-and-table](2026-10-14-132534-scenario-profiles-import-and-table.md), put
`docs/guides/tui/fixtures/import-urls.txt` on the clipboard, either with the `set_clipboard` MCP tool
(content = that file) or with `xclip -selection clipboard < docs/guides/tui/fixtures/import-urls.txt`.
No other scenario reads the clipboard.

**Colour needs two environment fixes.** This host exports `NO_COLOR=1`, and crossterm 0.29 suppresses all
colour emission when it is set, so any colour read comes back `default` and every screenshot note reads
`no colour`. Launch with `env -u NO_COLOR`. The harness pins `TERM` and `LC_ALL` but not `NO_COLOR`, and
`launch_tui(env=…)` merges over the inherited environment, so it cannot unset a variable. A screenshot's
canvas is the terminal's background, because the app paints none of its own: for a light theme, set
`MCP_TUI_TEST_BG` / `MCP_TUI_TEST_FG` to the theme's own base and text before rendering, or the PNG is
unfaithful in exactly the way that hides a contrast defect.

## Reproduce

A document replays through `run_scenario`, keyed by the document's own `name:`, which must equal the
filename label and the session id:

```python
run_scenario(script=open("docs/guides/tui/2026-10-14-144700-scenario-live-resize.md").read(),
             session_id="live-resize", dry_run=True)   # lint first
run_scenario(script=..., session_id="live-resize")     # then execute
```

Lint errors abort before anything launches; warnings (a `\n` sent to a buffer-mode app, a missing
`close()`) are advisory. On this host the same document is replayed with a small wrapper:

```bash
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-144700-scenario-live-resize.md live-resize
```

`run.py` is a scratch wrapper in `~/.cache/leas-tui/`, not a committed file; the MCP `run_scenario` tool
is the durable route. Run from the repository root: documents launch `target/debug/leas` relatively.
Build the binary first; the records name the md5 of the build that produced them, and a different build
can change cell widths (an emoji fallback, a theme constant), so compare against the recorded md5 before
trusting a diff.

Harness versions differ across the collection: 0.3.0 for the 2026-10-14 13:25 and 2026-10-23 runs, 1.0.1
for the 2026-10-14 14:47 runs, and an unversioned buffer-mode run for 2026-10-16. `get_cell_style`,
`screenshot` and `resize` only exist from 1.0.1 onward, so the earlier runs are text-only by construction.

## Catalogue

| Date | Scenario | What it proves | Verdict |
|---|---|---|---|
| 2026-10-14 | [narrow-80x24](2026-10-14-132534-scenario-narrow-80x24.md) | leas at 80x24 (table columns, status-bar hints) and at 80x19, where the under-20-row layout switches to the compact one-line actions bar instead of the 8-row panel | 5 PASS / 3 PARTIAL / 2 FAIL |
| 2026-10-14 | [profiles-import-and-table](2026-10-14-132534-scenario-profiles-import-and-table.md) | the Profiles tab from the empty state through a clipboard batch import (8 share URLs to 7 endpoints) to the populated table and an expanded multi-variant endpoint | 10 PASS / 0 PARTIAL / 0 FAIL |
| 2026-10-14 | [profiles-menus-states](2026-10-14-132534-scenario-profiles-menus-states.md) | Profiles overlays and modal states: help, speed-test menu, export scope, delete confirmation, and the prefix-search filter including its filtered-empty state | 6 PASS / 4 PARTIAL / 0 FAIL |
| 2026-10-14 | [settings-forms](2026-10-14-132534-scenario-settings-forms.md) | the Settings tab before the reskin: the 20-node section tree, opening a section into the right pane, field focus and the cursor, and what `q` does inside a form | 8 PASS / 1 PARTIAL / 1 FAIL |
| 2026-10-14 | [tiny-80x14](2026-10-14-132534-scenario-tiny-80x14.md) | leas at 80x14: the compact one-line actions bar the under-20-row layout selects, a table viewport that clips one endpoint, and F1's overlay replacing the content area | 4 PASS / 1 PARTIAL / 0 FAIL |
| 2026-10-14 14:47 | [colour-focus-audit](2026-10-14-144700-scenario-colour-focus-audit.md) | the palette actually emitted (tabs, selection, failure marker, chrome) under the dark theme and under Catppuccin Latte, and the cells that ignored the theme | 9 PASS / 1 PARTIAL / 3 FAIL |
| 2026-10-14 14:47 | [live-resize](2026-10-14-144700-scenario-live-resize.md) | live resizes 120x40 → 80x24 → 80x19 (the overlay branch a fresh small launch never reaches) → 120x40, checking the layout and any residue | 7 PASS / 0 PARTIAL / 0 FAIL |
| 2026-10-16 09:30 | [settings-xrat-parity](2026-10-16-093000-scenario-settings-xrat-parity.md) | the Settings popup after the reskin: four bands, `Sections · n/N` and `Values · i/n`, the `/` filter lifecycle, `*`/`·` provenance after an edit, the help box following the cursor, hints in the modal border, the shared (no-fill) modal background, the never-empty Values pane, wrapping selectors, and 80x24 / 54x24 | 18 PASS / 0 PARTIAL / 0 FAIL |
| 2026-10-23 | [details-panel](2026-10-23-scenario-details-panel.md) | pane 2's Details tab: the `Server` and `Link` groups, the aggregate column's partition block and orthogonal block, the facts column's own scroll offset, the compact bar `F1` produces, and the column stack below 100 columns | pass on both runs (120x40 and 80x24) |
| 2026-10-23 | [tasks-pane](2026-10-23-scenario-tasks-pane.md) | pane 2's Tasks tab: the idle bar, two feed-wide tasks enqueued from the Speed Test menu (one running, one queued), and `d` emptying the queue | pass (120x40) |

The 2026-10-16 record supersedes `settings-forms` for the Settings surface only: the section tree became
a flat list that loads its pane on move, the empty right pane is gone, and `Enter` on a selector advances
it (save is `Ctrl+S`). `settings-forms` keeps the field-focus, save and `q` observations.

## Supporting material

- [Aesthetics and UX review](2026-10-14-132534-review-tui-polish.md): all findings from the five text-only
  runs, severity-ranked.
- [Colour, focus and resize review](2026-10-14-144700-review-colour-resize.md): findings from the two runs
  that used `get_cell_style`, `screenshot` and `resize`.
- [Ad-hoc probe evidence](2026-10-14-132534-review-evidence-adhoc.md): probe reports the text-only review
  cites.
- `artifacts/`: PNG screenshots written by the `screenshot` step, cited by the colour and resize records.
  The `colour-light-canvas-*` pair is re-rendered on a light canvas (`MCP_TUI_TEST_BG=eff1f5`) so a light
  theme is witnessed faithfully.
- `fixtures/`: the synthetic config (`config.json`, `config-light.json`), the import URL list, the seeded
  store, `light-canvas-shots.py` (re-renders the light-theme pair on a light canvas, which is what the
  contrast finding is read from) and `check-theme-pixels.py` (proves which theme a screenshot shows by
  sampling pixels).
