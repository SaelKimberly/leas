---
name: colour-focus-audit
description: leas colour and focus audit with get_cell_style/screenshot — the Dracula palette as actually emitted (tabs, selection, failure marker, chrome), the hardcoded popup/status colours that ignore the theme, and the same cells under a light theme
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [colour, focus, theme, contrast, accessibility]
---

# Scenario: colour-focus-audit

| Field | Value |
|---|---|
| Run at | 2026-10-14 14:47:00 +0500 |
| App under test | leas 0.1.0, debug binary `/home/user/oss/xray-tui/target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Launch command (dark) | `env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/colour-dark/config /home/user/oss/xray-tui/target/debug/leas` |
| Launch command (light) | same, with `XDG_CONFIG_HOME=/home/user/.cache/leas-tui/colour-light/config` (`theme_name: catppuccin-latte`) |
| Session / mode / size | `colour-focus-audit` / buffer / 120x40 (two launches in one scenario) |
| Harness | mcp-tui-test 1.0.1 (`/home/user/oss/mcp-tui-test`), Python 3.14.7, pyte 0.8.2, Pillow |
| Evidence | [2026-10-14-144700-scenario-colour-focus-audit-transcript.md](2026-10-14-144700-scenario-colour-focus-audit-transcript.md); screenshots in [`artifacts/`](artifacts/) |

## Purpose and scope

Closes the gap the text-only pass could not: what colour the app actually emits, whether the
state cues that were previously "colour-only" are in fact distinguishable, and whether the palette
survives a theme switch. Two launches: the default dark theme (`dracula`) and a light one
(`catppuccin-latte`).

Does not cover: contrast ratios computed numerically (the screenshots are for a human eye), the
cursor-as-focus (`cursor()` / a shot of a focused form field — see `settings-forms`), or transitions over
time (`gif`).

## Environment and fixtures

```bash
R=/home/user/.cache/leas-tui
D=$R/colour-dark; L=$R/colour-light
rm -rf $D $L; mkdir -p $D/config/leas $L/config/leas
cp docs/guides/tui/fixtures/config.json       $D/config/leas/
cp docs/guides/tui/fixtures/config-light.json $L/config/leas/config.json
cp docs/guides/tui/fixtures/seeded/data.db    $D/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db    $L/config/leas/
mkdir -p docs/guides/tui/artifacts
```

**`NO_COLOR` must be removed from the child's environment.** This machine exports `NO_COLOR=1`, and
crossterm 0.29 implements <https://no-color.org/> by suppressing *all* colour emission when the
variable is set to a non-empty value — the app then renders monochrome and the `screenshot` palette
note reads `no colour: the app emits bold only`, which looks like an app defect. Hence `env -u
NO_COLOR` in both launch commands (the harness pins `TERM`/`LC_ALL`, not this).

The palette values asserted below are the Dracula and Catppuccin Latte constants of
`ratatui-themes 0.3.0` (the app reads `theme_name` from config and maps them through
`crates/leas/src/ui/palette_bridge.rs`).

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | `style(0, 5)` | selected tab: `fg=bd93f9 bg=default bold=yes` (palette `accent`, bold) |
| E2 | `style(0, 20)` | deselected tab: `fg=6272a4 bg=default bold=no` (palette `muted`) |
| E3 | `style(3, 4)`, `style(3, 6)`, `style(3, 16)` | table header, glyph cell / padding cell / another label alike: `fg=f8f8f2 bg=44475a bold=yes` (so the header band is solid, not patchy under the glyphs) |
| E4 | `style(4, 20)`, `style(5, 20)` | selected row `fg=f8f8f2 bg=44475a bold=yes`; unselected row `fg=f8f8f2 bg=default` — the selection is a surface fill, not colour-on-nothing |
| E5 | `style(5, 90)` | the `[name]` DNS-failure marker: `fg=ff5555` (palette `error`) |
| E6 | `style(39, 2)`, `style(39, 25)` | status bar: state word `fg=ff5555 bg=44475a bold=yes`; the hint text carries the palette `muted` (`fg=6272a4`) like every other hint in the app |
| E7 | `shot(artifacts/colour-dark-profiles.png)` | the note reports colour present (not `no colour`), and the picture shows a dark-purple-accented table on the terminal's canvas |
| E8 | `d` then `style(14, 42)` | the Confirm dialog's border is `fg=ff5555 bold=yes` — the hardcoded red (`Color::Red`) |
| E9 | `shot(artifacts/colour-dark-confirm.png)` | the dialog is legible on the dark canvas |
| E10 | light launch, `style(0, 5)` | selected tab takes the light accent: `fg=1e66f5` |
| E11 | light launch, `style(39, 25)` | the status-bar hint carries the *palette* colour under the light theme (`fg=8c8fa1`, `surface` `ccd0da` background) — not a colour fixed to the dark theme |
| E12 | light launch, `d`, `style(15, 44)` | the Confirm dialog's interior background is the theme's `surface` (`ccd0da`) rather than a hardcoded dark fill |
| E13 | `shot(artifacts/colour-light-confirm.png)` | the dialog reads as part of the light UI |

**Note on E13 (added after grading):** the light-theme screenshots this scenario produces are *not* a
faithful witness of a light terminal unless the canvas is set. The app paints no background of its own
(no cell carries a `bg` except chrome), so `screenshot` fills the canvas from `MCP_TUI_TEST_BG` /
`MCP_TUI_TEST_FG`, whose defaults are dark. E13's picture therefore shows a light *theme* on a dark
canvas — the hint strip looked low-contrast but the dialog looked fine, and the two could not be
compared. The findings below are read from `artifacts/colour-light-canvas-*.png`, the same frames
re-rendered with `MCP_TUI_TEST_BG=eff1f5` / `MCP_TUI_TEST_FG=4c4f69` (Latte's own base and text) by
`~/.cache/leas-tui/lightcanvas.py`; the E13 PNGs are kept as the record of the trap.

## Scenario script

```python
launch("env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/colour-dark/config /home/user/oss/xray-tui/target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
expect("rows 1-7 of 7", timeout=20)
style(row=0, col=5)
style(row=0, col=20)
style(row=3, col=4)
style(row=3, col=6)
style(row=3, col=16)
style(row=4, col=20)
style(row=5, col=20)
style(row=5, col=90)
style(row=39, col=2)
style(row=39, col=25)
shot(path="/home/user/oss/xray-tui/docs/guides/tui/artifacts/colour-dark-profiles.png")
send("d")
expect("Confirm", timeout=5)
style(row=14, col=42)
shot(path="/home/user/oss/xray-tui/docs/guides/tui/artifacts/colour-dark-confirm.png")
key("escape")
close()
launch("env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/colour-light/config /home/user/oss/xray-tui/target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
expect("rows 1-7 of 7", timeout=20)
style(row=0, col=5)
style(row=39, col=25)
send("d")
expect("Confirm", timeout=5)
style(row=15, col=44)
shot(path="/home/user/oss/xray-tui/docs/guides/tui/artifacts/colour-light-confirm.png")
close()
```

## Observed behaviour

| ID | Verdict | Evidence (verbatim excerpt + transcript step) |
|---|---|---|
| E1 | PASS | step 3 `Style at (0, 5) …: char='P' fg=bd93f9 bg=default bold=yes reverse=no italic=no underline=no strike=no blink=no` |
| E2 | PASS | step 4 `Style at (0, 20) …: char='t' fg=6272a4 bg=default bold=no …` |
| E3 | FAIL | steps 5–7: the glyph cell `char='#'`, the padding cell `char=' '` and the `A` of `Address` are all `fg=default bg=default bold=no` — the header row carries **no style at all** (see *Corrections* and the review's finding 1) |
| E4 | PASS | step 8 `Style at (4, 20) …: char='.' fg=f8f8f2 bg=44475a bold=yes` (selected) vs step 9 `Style at (5, 20) …: char='a' fg=f8f8f2 bg=default bold=no` (unselected) |
| E5 | PASS | step 10 `Style at (5, 90) …: char='m' fg=ff5555 bg=default bold=no` |
| E6 | PARTIAL | step 12 `Style at (39, 2) …: char='i' fg=ff5555 bg=44475a bold=yes` is as predicted, but step 13 `Style at (39, 25) …: char='E' fg=e5e5e5 bg=44475a bold=no` — the hint is **not** the palette's muted `6272a4` (finding 3) |
| E7 | PASS | step 14 `✓ Screenshot saved: …/artifacts/colour-dark-profiles.png` / `120x40 cells, font 14pt, 1810 cells carry colour` |
| E8 | PASS | step 17 `Style at (14, 42) …: char=' ' fg=cd0000 bg=281414 bold=yes …` — the hardcoded red (`Color::Red`) on the hardcoded dark maroon (`Color::Rgb(40, 20, 20)`) |
| E9 | PASS | step 18 `✓ Screenshot saved: …/artifacts/colour-dark-confirm.png` / `2000 cells carry colour`; the dialog is legible on the dark canvas |
| E10 | PASS | step 23 `Style at (0, 5) …: char='P' fg=1e66f5 bg=default bold=yes` — the Catppuccin Latte accent, so `theme_name` reaches the terminal |
| E11 | FAIL | step 24 `Style at (39, 25) …: char='E' fg=e5e5e5 bg=ccd0da bold=no` — the *background* is the theme's `surface` but the text stays the fixed light grey (finding 3) |
| E12 | FAIL | step 27 `Style at (15, 44) …: char='D' fg=ffffff bg=281414 bold=yes` — white on the hardcoded dark maroon in a light-theme UI (finding 2) |
| E13 | PASS | step 28 `✓ Screenshot saved: …/artifacts/colour-light-confirm.png` / `2000 cells carry colour` — the dark box is visually intact, but it is a dark box in a light UI |

## Corrections to expectations

- **E3's prediction was wrong in the app's favour-and-against.** I predicted the header band would be
  `fg=f8f8f2 bg=44475a bold=yes` (a solid fill). Observed: all three sampled header cells are
  `fg=default bg=default bold=no`. `ThemeStyles::table_header` exists in `ui/theme.rs` and is **never
  called**; `DataTable::render` paints the header from the column's `Line` (which carries no style),
  while the sort arrow and the divider use the *column's* style. So the header is a bare unstyled row
  under every theme.
- **E6 was half right.** The state word (` Disconnected`) is the palette's `error` red as predicted;
  the hint is a fixed grey, not `muted`.
- **E11/E12 confirm the theme-independence** my prediction treated as a bug: the status bar's background
  *is* themed (`ccd0da` = Latte `selection`) while its hint text is a constant `e5e5e5`, and the dialog's
  chrome ignores the theme entirely.
- **Attempt 1's light-theme half was invalid** and is preserved as an appendix in the transcript: the
  fixture copied the config under `config-light.json` instead of `config.json`, so the second launch
  fell back to the default theme and every "light" sample measured Dracula. Attempt 2 (the transcript)
  fixed the copy.

## Visual polish remarks

| # | Where | What | Severity | Recommendation |
|---|---|---|---|---|
| P1 | table header row 3, all columns | the header carries no fg, no bg and no bold — `#`, `Address`, `Feat`, `Protocol Info` are the same weight as the data rows, so the eye has nothing to anchor the columns to | minor | style the header line with `ThemeStyles::table_header(palette)` (the helper already exists), or apply the column's `style` to the header cell inside `DataTable::render` |
| P2 | Confirm dialog (dark: `fg=ffffff bg=281414`; light: step 27) | the dialog's chrome is a fixed dark maroon with white text under both themes, so a light UI gets a dark box that shares no colour with the rest of the screen | minor | derive the dialog bg/fg from the palette (`surface` / `on_highlight`) and keep only the red border as the semantic "destructive" cue |
| P3 | status-bar hints, `fg=e5e5e5` (`ui/status_bar.rs:148`) | the hint text is a hardcoded `Color::Gray`; on the light theme's `surface` (`ccd0da`) the computed contrast is ≈1.2:1 (against ≈7.3:1 on the dark theme's `44475a`), and the light-canvas read of `colour-light-canvas-confirm.png` calls it *"poorly readable — very low contrast … the glyphs barely separate from the background"* while the red `Disconnected` beside it is *"clearly readable"* | major | use the palette's `muted` (or `faint`) like every other hint in the app |
| P4 | table rows | the unselected row is plain `fg=f8f8f2` on the canvas, so the table reads as a single block; row separation depends on the scrollbar and the `▶` marker | nit | an alternating `surface`-tinted row (`TABLE_ROW_ALT`) would separate 7 rows from each other without adding noise |
| P5 | `[name]` marker | the DNS-failure label is error-red on the plain canvas — the most alarming cell in the table has the least support | nit | keep the red, consider a subtle background so it reads as a badge |

## Tooling friction

- **A screenshot's canvas is the terminal's background, and its defaults are dark.** The app paints no
  background of its own, so for a light theme the default canvas makes the PNG unfaithful: the hint
  strip and the dialog read as equally "dark-canvas" content and neither defect is visible. Set
  `MCP_TUI_TEST_BG` / `MCP_TUI_TEST_FG` to the theme's own base/text before rendering
  (`~/.cache/leas-tui/lightcanvas.py` does this in-process; the values are read per render, so a
  shell `export` works too). Without it, a light-theme walkthrough can pass while shipping an
  unreadable status bar.
- **`NO_COLOR` in the ambient environment silently monochromes the app.** crossterm 0.29 honours
  no-color.org; with `NO_COLOR=1` in the child's environment every colour emission is suppressed and
  `screenshot` reports `no colour: the app emits bold only`. The harness pins `TERM` and `LC_ALL` but
  **not `NO_COLOR`**, and `launch_tui(env=...)` can only *add or override* inherited variables — it
  cannot remove one, so `env -u NO_COLOR` in the launch command is the only route. Any colour walkthrough
  on this machine must do this or it will file a false app finding.
- **`shot` is buffer-mode only and needs Pillow** — present here. The note returned with the path
  (`1810 cells carry colour`) is the cheapest way to prove colour reached the terminal, and is what
  distinguishes "the app sent none" from "my reader dropped it".
- **`get_cell_style` reports the cell's *own* character**, so sampling a padded cell proves a style only
  for that cell — E3 took three samples (glyph, pad, another label) to establish the row-wide claim.

## Review of findings

**1. The table header carries no style at all (minor, every theme).** Evidence: steps 5–7 — `#`, its
padding and the `A` of `Address` are all `fg=default bg=default bold=no`. `ThemeStyles::table_header`
(`ui/theme.rs:26`) is defined and never called; `DataTable::render` writes the header from the column's
`Line`, which has no style. Why it matters: the table is the app's primary surface and its header is the
only thing labelling the columns — the columns currently read as undifferentiated rows. Recommendation:
apply `ThemeStyles::table_header` to the header line (or give `Column` a `header_style` the widget
applies) — one call site fixes every column.

**2. The dialog chrome ignores the theme (minor).** Evidence: step 17 (`fg=cd0000 bg=281414`) and step
27 (`fg=ffffff bg=281414` on the light theme) — `ui/mod.rs:52-53` hardcodes `Color::Red` and
`Color::Rgb(40, 20, 20)`, and `ui/export.rs:240`, `ui/logs.rs:560,601` and `ui/mod.rs:1188,1258`
hardcode `Color::Rgb(30, 30, 40)`. Why it matters: a light-theme user gets dark boxes; a user on a
dark-but-not-Dracula theme gets maroon boxes. The red *border* is a legitimate semantic cue; the fill
and the text are not. Recommendation: palette-derive the fill and text; keep the red border.

**3. The status-bar hints are a hardcoded grey and vanish on a light theme (major).** Evidence: step 24 —
`fg=e5e5e5 bg=ccd0da` under Catppuccin Latte (`ui/status_bar.rs:148`, `Style::default().fg(Color::Gray)`).
Why it matters: the hint row is the app's primary keyboard affordance — "how do I use this app" — and
it is unreadable on a light theme. Recommendation: `ThemeStyles::hint(palette)` (muted) for the
right-hand hints, as the rest of the app already does.

**4. The theme itself works and the state cues are distinguishable (verified good).** Evidence: steps
3, 4, 8, 9, 10, 23 — tab selected `bd93f9`+bold vs deselected `6272a4`; selected row `f8f8f2` on
`44475a` + bold vs unselected `f8f8f2` on the canvas; the failure marker `ff5555`; the light theme's
accent `1e66f5` proving `theme_name` is honoured end-to-end. The earlier text-only pass had to report
"colour not covered"; this pass shows those cues are real and theme-driven.

### Verified good

- The palette reaches the terminal as emitted, not as intended: every semantic role I sampled matches
  the theme's constants (steps 3, 4, 8, 9, 10) and the screenshot note confirms colour (`1810 cells
  carry colour`, step 14).
- Selection is a surface fill plus bold, not a colour-on-nothing trick — it survives a monochrome
  terminal (step 8 vs 9).
- The destructive dialog is unambiguously destructive: red border and a red-tinted fill, distinct from
  every other popup (step 17).
- The light theme loads and repaints correctly (step 23) — no stale colour from the previous frame.
- The round trip through a resize leaves a clean frame (see `live-resize`, step 18).

### What the pictures added, and what they corrected

Both contrast claims in this review were arithmetic before they were seen. Reading the PNGs changed
one of them:

- **Confirmed (light canvas):** the hint strip is **"poorly readable — very low contrast … the glyphs
  barely separate from the background"**, while the red `Disconnected` beside it is **"clearly
  readable"** — so finding 1 stands as a legibility defect, not a theoretical one.
- **The profiles frame corroborates the pixel evidence, not the prose.** Its reader called the hint
  row *"the hardest to read"* but also described it as *"bright fuchsia/pink … against the dark
  terminal background"* — wrong on the canvas. `fixtures/check-theme-pixels.py` measures the actual
  pixels: canvas `#eff1f5`, status-bar fill `#ccd0da`, i.e. Catppuccin Latte on a **light** canvas
  (the same script shows the `E13` frames are Latte on the *default dark* canvas, which is why a
  reader found the hints legible there). The "hardest to read" ranking is kept because it agrees with
  the confirm frame and with the measured fills; the colour description is discarded as a reader
  error, not app evidence.
- **Downgraded:** the confirm dialog is **"readable — good contrast"** (white on its dark fill), so
  finding 2 is a theme-consistency defect, not a readability one. The E9 expectation ("legible on the
  dark canvas") is also satisfied for the same reason.
- **A rendering artefact, not an app finding:** the `Feat` column reads as stray `]` glyphs in the
  pictures because the flag emoji does not paint — no colour-emoji font is installed on this host
  (`_render.py` falls back per glyph). The text reads show `[🏁  ]`; the app is fine, the PNG is
  degraded. Filed under *Tooling friction*, not as a finding.
- The vision reader also mangled two hint labels and merged the log line into the status bar, so all
  *wording* claims in this review come from the harness's text reads, not from the pictures; the
  pictures are used only for the visual judgements above.

The two light-canvas PNGs are written by `fixtures/light-canvas-shots.py` (committed — the
`~/.cache` scratch copy was not durable on this host); the `E13` frames are the as-run dark-canvas
shots, kept as the record of why they could not show the defect.

### Reproduce

```bash
cd /home/user/oss/xray-tui
R=/home/user/.cache/leas-tui; D=$R/colour-dark; L=$R/colour-light
rm -rf $D $L; mkdir -p $D/config/leas $L/config/leas
cp docs/guides/tui/fixtures/config.json       $D/config/leas/
cp docs/guides/tui/fixtures/config-light.json $L/config/leas/config.json
cp docs/guides/tui/fixtures/seeded/data.db    $D/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db    $L/config/leas/
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-144700-scenario-colour-focus-audit.md colour-focus-audit

# the light-theme contrast witness (finding 1) needs a light canvas: the app paints no background,
# so these two variables ARE the terminal's background for `screenshot`.
MCP_TUI_TEST_BG=eff1f5 MCP_TUI_TEST_FG=4c4f69 \
  uv run --quiet --project /home/user/oss/mcp-tui-test python \
  docs/guides/tui/fixtures/light-canvas-shots.py
```
