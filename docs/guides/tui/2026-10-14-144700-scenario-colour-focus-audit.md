---
name: colour-focus-audit
description: leas colour and focus audit with get_cell_style/screenshot, the Dracula palette as actually emitted (tabs, selection, failure marker, chrome), the hardcoded popup/status colours that ignore the theme, and the same cells under a light theme
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [colour, focus, theme, contrast, accessibility]
---

# Scenario: colour-focus-audit (2026-10-14)

Records the colour the app actually emitted on 2026-10-14: whether the state cues that were previously
"colour-only" are distinguishable, whether the palette survives a theme switch, and which cells ignore
the theme. Two launches, the default dark theme (`dracula`) and a light one (`catppuccin-latte`). It does
not cover contrast ratios as the app computes them, the cursor-as-focus, or transitions over time.

## Purpose and scope

The text-only pass could not judge colour: buffer reads carry none, so "the selection highlight", "the
focus indicator" and "the theme" were unverifiable. This pass closes that gap with `get_cell_style` (a
cell's fg/bg and attributes as assertable text), `screenshot` (a PNG of the same cell grid, plus a count
of cells carrying colour) and a light-theme launch.

Out of scope: contrast ratios computed from the app's own palette (the screenshots are for a human eye),
the cursor-as-focus (`cursor()` or a shot of a focused form field, see `settings-forms`), and transitions
over time (`gif`).

## Environment and fixtures

| Field | Value |
|---|---|
| Run at | 2026-10-14 14:47:00 +0500 |
| App under test | leas 0.1.0, debug binary `target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Launch command (dark) | `env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/colour-dark/config target/debug/leas` |
| Launch command (light) | same, with `XDG_CONFIG_HOME=/home/user/.cache/leas-tui/colour-light/config` and `theme_name: catppuccin-latte` |
| Session / mode / size | `colour-focus-audit` / buffer / 120x40 (two launches in one scenario) |
| Harness | mcp-tui-test 1.0.1, Python 3.14.7, pyte 0.8.2, Pillow |
| Evidence | [colour-focus-audit transcript](2026-10-14-144700-scenario-colour-focus-audit-transcript.md); screenshots in [`artifacts/`](artifacts/) |

Commands run from the repository root.

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

The light fixture must land as `config.json`, not under the source file's name: attempt 1 copied it as
`config-light.json`, the launch found no config and fell back to `dracula`, and every "light" sample
measured the dark palette. The transcript keeps that failed attempt as an appendix.

**`NO_COLOR` must be removed from the child's environment.** This machine exports `NO_COLOR=1`, and
crossterm 0.29 implements <https://no-color.org/> by suppressing all colour emission when the variable is
set to a non-empty value: the app then renders monochrome and the `screenshot` palette note reads
`no colour: the app emits bold only`, which looks like an app defect. Hence `env -u NO_COLOR` in both
launch commands; the harness pins `TERM` and `LC_ALL`, not this variable, and `launch_tui(env=…)` can
only add or override inherited values, never unset one.

The palette values asserted below are the Dracula and Catppuccin Latte constants. The theme crate on
this build is `opaline 0.4.2` (`crates/leas/Cargo.toml:82`, `builtin-themes` feature); the app reads
`theme_name` from config and loads it through `crate::ui::theme::load` (`crates/leas/src/ui/theme.rs`).

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | `style(0, 5)` | selected tab: `fg=bd93f9 bg=default bold=yes` (palette `accent`, bold) |
| E2 | `style(0, 20)` | deselected tab: `fg=6272a4 bg=default bold=no` (palette `muted`) |
| E3 | `style(3, 4)`, `style(3, 6)`, `style(3, 16)` | table header, glyph cell / padding cell / another label alike: `fg=f8f8f2 bg=44475a bold=yes` (so the header band is solid, not patchy under the glyphs) |
| E4 | `style(4, 20)`, `style(5, 20)` | selected row `fg=f8f8f2 bg=44475a bold=yes`; unselected row `fg=f8f8f2 bg=default`, the selection is a surface fill, not colour-on-nothing |
| E5 | `style(5, 90)` | the `[name]` DNS-failure marker: `fg=ff5555` (palette `error`) |
| E6 | `style(39, 2)`, `style(39, 25)` | status bar: state word `fg=ff5555 bg=44475a bold=yes`; the hint text carries the palette `muted` (`fg=6272a4`) like every other hint in the app |
| E7 | `shot(artifacts/colour-dark-profiles.png)` | the note reports colour present (not `no colour`), and the picture shows a dark-purple-accented table on the terminal's canvas |
| E8 | `d` then `style(14, 42)` | the Confirm dialog's border is `fg=ff5555 bold=yes` (`Color::Red` at run time) |
| E9 | `shot(artifacts/colour-dark-confirm.png)` | the dialog is legible on the dark canvas |
| E10 | light launch, `style(0, 5)` | selected tab takes the light accent: `fg=1e66f5` |
| E11 | light launch, `style(39, 25)` | the status-bar hint carries the *palette* colour under the light theme (`fg=8c8fa1`, `surface` `ccd0da` background), not a colour fixed to the dark theme |
| E12 | light launch, `d`, `style(15, 44)` | the Confirm dialog's interior background is the theme's `surface` (`ccd0da`) rather than a hardcoded dark fill |
| E13 | `shot(artifacts/colour-light-confirm.png)` | the dialog reads as part of the light UI |

Note on E13, added after grading: the light-theme screenshots are not a faithful witness of a light
terminal unless the canvas is set. The app paints no background of its own (no cell carries a `bg` except
chrome), so `screenshot` fills the canvas from `MCP_TUI_TEST_BG` / `MCP_TUI_TEST_FG`, whose defaults are
dark. E13's picture therefore shows a light *theme* on a dark canvas: the hint strip looked low-contrast
but the dialog looked fine, and the two could not be compared. The findings below are read from
`artifacts/colour-light-canvas-*.png`, the same frames re-rendered with `MCP_TUI_TEST_BG=eff1f5` /
`MCP_TUI_TEST_FG=4c4f69` (Latte's own base and text); the E13 PNGs are kept as the record of the trap.

## Scenario script

```python
launch("env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/colour-dark/config target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
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
shot(path="docs/guides/tui/artifacts/colour-dark-profiles.png")
send("d")
expect("Confirm", timeout=5)
style(row=14, col=42)
shot(path="docs/guides/tui/artifacts/colour-dark-confirm.png")
key("escape")
close()
launch("env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/colour-light/config target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
expect("rows 1-7 of 7", timeout=20)
style(row=0, col=5)
style(row=39, col=25)
send("d")
expect("Confirm", timeout=5)
style(row=15, col=44)
shot(path="docs/guides/tui/artifacts/colour-light-confirm.png")
close()
```

## Observed behaviour

Step numbers are the transcript's (attempt 2, the valid run):

| ID | Verdict | Evidence (verbatim excerpt + transcript step) |
|---|---|---|
| E1 | PASS | step 3 `Style at (0, 5) …: char='P' fg=bd93f9 bg=default bold=yes reverse=no italic=no underline=no strike=no` |
| E2 | PASS | step 4 `Style at (0, 20) …: char='t' fg=6272a4 bg=default bold=no …` |
| E3 | FAIL | steps 5–7: the glyph cell `char='#'`, the padding cell `char=' '` and the `A` of `Address` are all `fg=default bg=default`, the header row carries no style at all |
| E4 | PASS | step 8 `Style at (4, 20) …: char='.' fg=f8f8f2 bg=44475a bold=yes` (selected) vs step 9 `Style at (5, 20) …: char='a' fg=f8f8f2 bg=default bold=no` (unselected) |
| E5 | PASS | step 10 `Style at (5, 90) …: char='m' fg=ff5555 bg=default bold=no` |
| E6 | PARTIAL | step 11 `Style at (39, 2) …: char='i' fg=ff5555 bg=44475a bold=yes` is as predicted, but step 12 `Style at (39, 25) …: char='E' fg=e5e5e5 bg=44475a bold=no`: the hint is not the palette's muted `6272a4` (finding 3) |
| E7 | PASS | step 13 `✓ Screenshot saved: …/artifacts/colour-dark-profiles.png` / `120x40 cells, font 14pt, 1722 cells carry colour` (attempt 1, before the light fixture was fixed, reported `1810 cells carry colour`) |
| E8 | PASS | step 16 `Style at (14, 42) …: char=' ' fg=cd0000 bg=281414 bold=yes …`: the red of `Color::Red` on a hardcoded dark maroon (`Color::Rgb(40, 20, 20)`) |
| E9 | PASS | step 17 `✓ Screenshot saved: …/artifacts/colour-dark-confirm.png` / `1912 cells carry colour`; the dialog is legible on the dark canvas (attempt 1 reported `2000 cells carry colour`) |
| E10 | PASS | step 22 `Style at (0, 5) …: char='P' fg=1e66f5 bg=default bold=yes`: the Catppuccin Latte accent, so `theme_name` reaches the terminal |
| E11 | FAIL | step 23 `Style at (39, 25) …: char='E' fg=e5e5e5 bg=ccd0da bold=no`: the background is the theme's `surface` but the text stays the fixed light grey (finding 3) |
| E12 | FAIL | step 26 `Style at (15, 44) …: char='D' fg=ffffff bg=281414 bold=yes`: white on the hardcoded dark maroon in a light-theme UI (finding 2) |
| E13 | PASS | step 27 `✓ Screenshot saved: …/artifacts/colour-light-confirm.png` / `2000 cells carry colour`: the dark box is visually intact, but it is a dark box in a light UI |

Corrections to the expectations:

- **E3's prediction was wrong.** I predicted the header band would be `fg=f8f8f2 bg=44475a bold=yes` (a
  solid fill). Observed: all three sampled header cells are `fg=default bg=default`. At run time
  `ThemeStyles::table_header` existed and was never called; `DataTable::render` painted the header from
  the column's `Line` (which carries no style), while the sort arrow and the divider used the column's
  style. So the header was a bare unstyled row under every theme.
- **E6 was half right.** The state word (` Disconnected`) is the palette's `error` red as predicted; the
  hint is a fixed grey, not `muted`.
- **E11/E12 confirm theme-independence.** The status bar's background *is* themed (`ccd0da`, Latte's
  selection) while its hint text is a constant `e5e5e5`, and the dialog's chrome ignored the theme
  entirely.
- **Attempt 1's light-theme half was invalid** and is preserved as an appendix in the transcript: the
  fixture copied the config under `config-light.json` instead of `config.json`, so the second launch fell
  back to the default theme and every "light" sample measured Dracula. Attempt 2 fixed the copy.

Tooling friction from this run:

- **A screenshot's canvas is the terminal's background, and its defaults are dark.** The app paints no
  background of its own, so for a light theme the default canvas makes the PNG unfaithful: the hint strip
  and the dialog read as equally "dark-canvas" content and neither defect is visible. Set
  `MCP_TUI_TEST_BG` / `MCP_TUI_TEST_FG` to the theme's own base/text before rendering. Without it, a
  light-theme walkthrough can pass while shipping an unreadable status bar.
- **`NO_COLOR` in the ambient environment silently monochromes the app** (see *Environment and
  fixtures*). Any colour walkthrough on this machine must unset it or it will file a false app finding.
- **`shot` is buffer-mode only and needs Pillow**, present here. The count returned with the path (`1722
  cells carry colour`) is the cheapest way to prove colour reached the terminal, and distinguishes "the
  app sent none" from "my reader dropped it".
- **`get_cell_style` reports the cell's *own* character**, so sampling a padded cell proves a style only
  for that cell; E3 took three samples (glyph, pad, another label) to establish the row-wide claim.

## Verdict

9 PASS, 1 PARTIAL, 3 FAIL.

**Finding 1 (minor at run time, every theme): the table header carried no style at all.** Evidence:
steps 5–7, `#`, its padding and the `A` of `Address` are all `fg=default bg=default bold=no`. Why it
matters: the table is the app's primary surface and its header is the only thing labelling the columns,
so the columns read as undifferentiated rows. Fix: apply `ThemeStyles::table_header` to the header line,
one call site for every column. Closed in the current source: the helper lives at
`crates/leas/src/ui/theme.rs:164` and is called by the profiles table
(`crates/leas/src/ui/profiles.rs:1487,1556`) and the sniffer (`crates/leas/src/ui/sniffer.rs:199`).

**Finding 2 (minor): the dialog chrome ignored the theme.** Evidence: step 16 (`fg=cd0000 bg=281414`) and
step 26 (`fg=ffffff bg=281414` on the light theme). At run time `crates/leas/src/ui/mod.rs` hardcoded
`Color::Red` and `Color::Rgb(40, 20, 20)` (lines 52-53), with `Color::Rgb(30, 30, 40)` in
`ui/export.rs:240`, `ui/logs.rs` (560, 601) and `ui/mod.rs` (1188, 1258). Why it matters: a light-theme
user gets dark boxes, and a user on a dark-but-not-Dracula theme gets maroon ones; the red *border* is a
legitimate semantic cue, the fill and the text are not.
Fix: palette-derive the fill and text, keep the red border. Closed in the current source:
`render_confirmation_overlay` now takes the theme and styles the popup with `ThemeStyles::dialog(theme)`
and an `ThemeStyles::error(theme)` border (`crates/leas/src/ui/mod.rs:39-63`).

**Finding 3 (major, fixed at run time but not yet to AA then): the status-bar hints were a hardcoded
grey.** Evidence: step 12 `fg=e5e5e5 bg=44475a` on the dark theme, step 24 `fg=e5e5e5 bg=ccd0da` under
Catppuccin Latte, from `Style::default().fg(Color::Gray)` in `ui/status_bar.rs`. The computed WCAG ratio
of the light pair is 1.23:1, against about 7.3:1 on the dark theme, below every legibility threshold.
Why it matters: the hint row is the app's primary keyboard affordance. Fix: `ThemeStyles::hint(palette)`
(muted) for the right-hand hints, as the rest of the app already did. Closed in the current source: the
status bar uses `ThemeStyles::status_bar_hint(theme)` (`crates/leas/src/ui/status_bar.rs:181`), a
registered `app.statusbar_hint` token whose foreground `derive_readable` darkens until it clears its
contrast target (`crates/leas/src/ui/theme.rs:44-70`; the comment there records Latte's `text.muted` at
2.72:1 on the selection background, with no Latte token reaching 4.5:1).

**Finding 4 (verified good): the theme worked end to end.** Evidence: steps 3, 4, 8, 9, 10, 22, the tab
selected `bd93f9` plus bold versus deselected `6272a4`, the selected row `f8f8f2` on `44475a` plus bold
versus unselected on the canvas, the failure marker `ff5555`, and the light theme's accent `1e66f5`
proving `theme_name` is honoured. The earlier text-only pass had to report "colour not covered"; this
pass shows those cues are real and theme-driven. The selection is a surface fill plus bold, so it
survives a monochrome terminal.

Visual polish remarks recorded at run time:

| # | Where | What | Severity | Recommendation |
|---|---|---|---|---|
| P1 | table header row 3, all columns | no fg, no bg and no bold: `#`, `Address`, `Feat`, `Protocol Info` carry the same weight as the data rows, so the eye has nothing to anchor the columns to | minor | style the header line with `ThemeStyles::table_header(palette)` (the helper already exists), or apply the column's `style` to the header cell inside `DataTable::render` |
| P2 | Confirm dialog (dark `fg=ffffff bg=281414`; light step 26) | fixed dark maroon with white text under both themes, so a light UI gets a dark box that shares no colour with the rest of the screen | minor | derive the dialog bg/fg from the palette (`surface` / `on_highlight`) and keep only the red border as the semantic destructive cue |
| P3 | status-bar hints, `fg=e5e5e5` | hardcoded `Color::Gray`; on the light theme's `surface` (`ccd0da`) the computed contrast is about 1.2:1 (against about 7.3:1 on the dark theme's `44475a`), and the light-canvas read calls it "poorly readable — very low contrast … the glyphs barely separate from the background" while the red `Disconnected` beside it is "clearly readable" | major | use the palette's `muted` (or `faint`) like every other hint in the app |
| P4 | table rows | the unselected row is plain `fg=f8f8f2` on the canvas, so 7 rows read as one block; separation depends on the scrollbar and the `▶` marker | nit | an alternating `surface`-tinted row (`TABLE_ROW_ALT`) would separate them without adding noise |
| P5 | `[name]` marker | the DNS-failure label is error-red on the plain canvas, the most alarming cell in the table with the least support | nit | keep the red, consider a subtle background so it reads as a badge |

The pictures, read on a *correct* canvas, confirmed one contrast claim and downgraded the other:
`artifacts/colour-light-canvas-confirm.png` rates the hint text `"poorly readable — very low contrast …
the glyphs barely separate from the background"` while the red `Disconnected` beside it is `"clearly
readable"` (finding 3 is a real legibility defect), and rates the confirm dialog itself `"readable —
good contrast"` (finding 2 is a consistency defect, not a readability one; the original wording implied
otherwise). A second reader called the hint row "the hardest to read" but described the canvas as dark,
which contradicted the first read: `fixtures/check-theme-pixels.py` measures
`artifacts/colour-light-canvas-profiles.png` as canvas `#eff1f5` with a `#ccd0da` status fill (Latte on a
light canvas) and the E13 frames as Latte on the default dark canvas, which is why a reader found the
hints legible there. The ranking is kept as corroborating evidence; the reader's colour description is
discarded. The `Feat` column's stray `]` glyphs in the pictures are a missing colour-emoji font on this
host, not an app bug; the text reads show `[🏁  ]`.

Reproduce:

```bash
R=/home/user/.cache/leas-tui; D=$R/colour-dark; L=$R/colour-light
rm -rf $D $L; mkdir -p $D/config/leas $L/config/leas
cp docs/guides/tui/fixtures/config.json       $D/config/leas/
cp docs/guides/tui/fixtures/config-light.json $L/config/leas/config.json
cp docs/guides/tui/fixtures/seeded/data.db    $D/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db    $L/config/leas/
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-144700-scenario-colour-focus-audit.md colour-focus-audit

# the light-theme contrast witness (finding 3) needs a light canvas: the app paints no background,
# so these two variables ARE the terminal's background for `screenshot`.
MCP_TUI_TEST_BG=eff1f5 MCP_TUI_TEST_FG=4c4f69 \
  uv run --quiet --project /home/user/oss/mcp-tui-test python \
  docs/guides/tui/fixtures/light-canvas-shots.py
```
