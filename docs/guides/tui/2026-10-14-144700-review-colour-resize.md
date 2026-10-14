# leas TUI review — colour, focus and resize

Companion to the [text-only review](2026-10-14-132534-review-tui-polish.md). This pass exists because
that one had to declare colour out of scope: buffer reads carry no colour, so "the selection
highlight", "the focus indicator" and "the theme" were unverifiable. tui-test 1.0.1 added
`get_cell_style` (a cell's fg/bg and text attributes as assertable text), `screenshot` (a PNG of the
same cell grid, plus a note saying how many cells carry colour) and `resize` (SIGWINCH mid-session),
and all three are used here.

| Field | Value |
|---|---|
| Run at | 2026-10-14 14:47:00 +0500 |
| App under test | leas 0.1.0, debug binary `/home/user/oss/xray-tui/target/debug/leas` (md5 `13e132f2f7abb5e376ce477504709b93`) |
| Harness | mcp-tui-test 1.0.1 (`/home/user/oss/mcp-tui-test`), Python 3.14.7, pyte 0.8.2, Pillow |
| Scenarios | [`colour-focus-audit`](2026-10-14-144700-scenario-colour-focus-audit.md), [`live-resize`](2026-10-14-144700-scenario-live-resize.md) |
| Screenshots | [`artifacts/`](artifacts/) — `colour-dark-profiles.png`, `colour-dark-confirm.png`, `resize-back-120x40.png`, plus the light-theme pair `colour-light-canvas-profiles.png` / `colour-light-canvas-confirm.png` re-rendered on a light canvas (`MCP_TUI_TEST_BG=eff1f5`), which is what the contrast finding is read from. `colour-light-confirm.png` is the same frame on the default dark canvas and is kept as the record of why it could not show the bug |
| Evidence | one transcript per scenario (the colour transcript also keeps the invalid first attempt) |

Screens covered: the Profiles tab under the default dark theme and under a light one (Catppuccin
Latte), the delete-confirmation dialog in both, and the layout through 120x40 → 80x24 → 80x19 → 120x40.

## Headline: colour was never broken — my own environment hid it

The first sample of this pass returned `fg=default bg=default` on every cell and the screenshot note
read `no colour: the app emits bold only`. That is **not** an app property: the host exports
`NO_COLOR=1`, and crossterm 0.29 implements <https://no-color.org/> by suppressing all colour emission
when that variable is set, so the app rendered monochrome and *every* style read came back `default`.
With `env -u NO_COLOR` the palette appears exactly as intended.

This is a trap for any colour walkthrough on this machine, and the harness pins `TERM`/`LC_ALL` but not
`NO_COLOR` (and `launch_tui(env=…)` can only add or override, never unset). Every colour scenario in this
collection must drop it; see *Tooling friction*.

## Findings, ranked

### Fix first — colour that only works on one theme

**1. The status-bar hints are a hardcoded grey and are unreadable on a light theme (major — fixed, but not yet to AA).**
`colour-focus-audit` step 24: `Style at (39, 25) … char='E' fg=e5e5e5 bg=ccd0da bold=no` — the
background *is* the theme's `surface` (`ccd0da`, Catppuccin Latte) but the text is the constant
`Color::Gray` from `ui/status_bar.rs:148`. The computed WCAG ratio of that pair is **1.23:1**, against
≈7.3:1 on the dark theme — below every legibility threshold.

The picture confirms it, but only when the canvas is right. The app paints no background of its own
(every cell is `bg=default`), so a screenshot's canvas *is* the terminal's; the default dark canvas
hid the bug, and `artifacts/colour-light-canvas-confirm.png` was re-rendered with
`MCP_TUI_TEST_BG=eff1f5`/`MCP_TUI_TEST_FG=4c4f69` (Latte's own base/text) to reproduce a light
terminal. Read there: **"Hint text … Poorly readable — very low contrast … the glyphs barely separate
from the background"**, while the red `Disconnected` two words away is **"Clearly readable"**, and the
dialog is **"Readable"**. The row that teaches the app's keyboard model disappears on a light theme.
Recommendation: `ThemeStyles::hint(palette)` (muted) for the right-hand hints — the helper exists and
every other hint in the app already uses it.

**2. The confirmation dialog ignores the theme (minor).** `colour-focus-audit` steps 17 and 27:
`fg=cd0000 bg=281414` (dark) and `fg=ffffff bg=281414` (light) — `ui/mod.rs:52-53` hardcodes
`Color::Red` and `Color::Rgb(40, 20, 20)`; `ui/mod.rs:1188,1258`, `ui/export.rs:240` and
`ui/logs.rs:560,601` hardcode `Color::Rgb(30, 30, 40)`. A light-theme user gets a dark maroon box that
shares no colour with anything else on screen — visible in `artifacts/colour-light-canvas-confirm.png`,
where the vision read describes it as a **"solid black background with bright white/light text"**
inside an otherwise light UI. It is *readable* (the same read rates it "Readable — good contrast"), so
this is a consistency defect, not a legibility one. The red border is a legitimate semantic cue for
"destructive"; the fill and text are not. Recommendation: palette-derive them.

### Then — structure and reachability

**3. The table header carries no style at all (minor, every theme).** `colour-focus-audit` steps 5–7:
the `#` glyph, its padding and the `A` of `Address` are all `fg=default bg=default bold=no`.
`ThemeStyles::table_header` is defined in `ui/theme.rs:26` and **never called**; `DataTable::render`
paints the header from the column's `Line`, which carries no style. So the app's primary surface has a
header row that is visually indistinguishable from its data rows. One-line fix at the column
construction in `ui/profiles.rs:1006-1020`.

**4. A mid-session shrink to 19 rows replaces the profile table with the log panel (major).**
`live-resize` steps 9–12: after `resize("80x19")` the content area is entirely
` ⚙ Actions Log  ///…` / `○ Disconnected` / `🖥 vless 203.0.113.77:443 [xray]` / `⏱ TCP: …` / `📊 …` /
`📋  Core: [info] Whitelist loaded`, with **no `Address` and no `┌ Profiles ─` anywhere** — while row 0
still says `Profiles`. This state is unreachable from a fresh small launch (`tiny-80x14` compacts
correctly): `ui/mod.rs:78` decides `actions_compact` once from the *startup* size, so a session that
started tall and then shrank takes the overlay branch. Fix: make that decision follow the current size.

**5. The hint set does not follow the view (major, shared root cause with the text pass).**
`live-resize` step 12 keeps advertising `[→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect` while
the panel is showing; `profiles-menus-states` step 24 does the same under the delete confirmation, and
`q` there cancels the dialog instead of quitting. One state-aware hint set fixes all three.

### Polish

**6. The unselected rows are undifferentiated (nit).** `colour-focus-audit` step 9: the unselected row
is `fg=f8f8f2 bg=default` on the canvas, so 7 rows read as one block; separation depends on the
scrollbar and the `▶` marker. An alternating `surface` tint (the `TABLE_ROW_ALT` role the manual
documents) would separate them without adding noise.

**7. The `[name]` failure marker has no support (nit).** `colour-focus-audit` step 10:
`fg=ff5555 bg=default` — the most alarming cell in the table is red text on the plain canvas. A subtle
background would read as a badge.

## Verified good

- **The theme works end to end, and I nearly mis-reported it.** With `NO_COLOR` removed, every semantic
  role matches the theme's own constants: selected tab `bd93f9`+bold vs deselected `6272a4`
  (`colour-focus-audit` steps 3–4), selected row `f8f8f2` on `44475a` + bold vs unselected `f8f8f2` on
  the canvas (steps 8–9), the failure marker `ff5555` (step 10), the state word `ff5555` on `44475a`
  bold (step 12), and the light theme's accent `1e66f5` (step 23) proving `theme_name` is honoured.
- **The selection is a surface fill plus bold**, not colour-on-nothing — it survives a monochrome
  terminal, which is what the text-only pass could not establish.
- **The destructive dialog is unambiguous and readable**: a red border and a red-tinted fill, distinct
  from every other popup, and the vision read of `artifacts/colour-light-canvas-confirm.png` rates it
  **"readable — good contrast"** on both canvases.
- **Resize is handled properly**: the 80x24 shape reached by a live resize is row-for-row identical to a
  fresh launch at that size, and the return to 120x40 restores the full table, the panel and the full
  hint row with a clean frame — no torn box-drawing, no ghost columns, and the loaded page survives
  (`rows 1-7 of 7` throughout).

## How the pictures were read, and one they corrected

Both contrast claims started as hex arithmetic. Reading the PNGs — on a *correct* canvas, which took a
re-render, since the app paints no background and the harness default is dark — confirmed one and
downgraded the other:

- `artifacts/colour-light-canvas-confirm.png`: hint text **"poorly readable — very low contrast"**,
  `Disconnected` **"clearly readable"** → finding 1 is a real legibility defect.
- Same file: the confirm dialog **"readable — good contrast"** → finding 2 is a consistency defect, not
  a readability one (the original wording implied otherwise).
- A second reader described the hint row in `colour-light-canvas-profiles.png` as *"the hardest to
  read"* but called the canvas dark, which contradicted the first read. The pixels settle it —
  `fixtures/check-theme-pixels.py` measures that file's canvas as `#eff1f5` with a `#ccd0da` status fill
  (Latte on a light canvas), and the `E13` frames as Latte on the default dark canvas, which is exactly
  why a reader found the hints legible there. The ranking is corroborating evidence; the reader's colour
  description was wrong.
- The `Feat` column's stray `]` glyphs in the pictures are a missing colour-emoji font on this host, not
  an app bug; the text reads show `[🏁  ]`. Tooling friction, not a finding.

## What changed in the harness, and what it bought

| Capability | What it settled |
|---|---|
| `get_cell_style` | the "colour-only cues" gap in the text-only review; the light-theme contrast bug (#1), the unstyled header (#3), and the palette's actual values |
| `screenshot` | proof that colour reached the terminal (`1810 cells carry colour`), the picture for the light-theme contrast judgement, and the clean-frame check after resize |
| `resize` | the `<20`-row overlay branch (#4) — a state no fresh launch can produce, because the app reads the size once at startup |
| dead-child detection, column-exact rows, the pyte crash fix | the text pass's two biggest friction items (random `IndexError`, emoji column drift) are gone |

## Reproduce

```bash
cd /home/user/oss/xray-tui
R=/home/user/.cache/leas-tui; D=$R/colour-dark; L=$R/colour-light; Z=$R/resize
rm -rf $D $L $Z; mkdir -p $D/config/leas $L/config/leas $Z/config/leas
cp docs/guides/tui/fixtures/config.json       $D/config/leas/
cp docs/guides/tui/fixtures/config-light.json $L/config/leas/config.json
cp docs/guides/tui/fixtures/config.json       $Z/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db    $D/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db    $L/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db    $Z/config/leas/
for s in colour-focus-audit live-resize; do
  uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
    doc docs/guides/tui/2026-10-14-144700-scenario-$s.md $s
done
```
