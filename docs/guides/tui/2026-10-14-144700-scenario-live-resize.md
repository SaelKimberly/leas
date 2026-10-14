---
name: live-resize
description: leas driven through live resizes with the resize tool — 120x40 to 80x24 to 80x19 (the overlay branch a fresh small launch never reaches) back to 120x40, checking the layout and any residue
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [responsiveness, resize, overlay, anomalies]
---

# Scenario: live-resize

| Field | Value |
|---|---|
| Run at | 2026-10-14 14:47:00 +0500 |
| App under test | leas 0.1.0, debug binary `/home/user/oss/xray-tui/target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Launch command | `env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/resize/config /home/user/oss/xray-tui/target/debug/leas` |
| Session / mode / size | `live-resize` / buffer / 120x40 → 80x24 → 80x19 → 120x40 (one launch, three resizes) |
| Harness | mcp-tui-test 1.0.1 (`/home/user/oss/mcp-tui-test`), Python 3.14.7, pyte 0.8.2, Pillow |
| Evidence | [2026-10-14-144700-scenario-live-resize-transcript.md](2026-10-14-144700-scenario-live-resize-transcript.md); screenshots in [`artifacts/`](artifacts/) |

## Purpose and scope

`dimensions` only applies at launch, so the layout branch a *shrink* takes (a session that started
tall, then lost rows) was unreachable in the earlier pass — `tiny-80x14` and `narrow-80x24` both
launched at the small size and observed the app *compacting*. This drives SIGWINCH mid-session
instead, and checks the round trip for torn or ghosted cells.

Does not cover: resize while connected (no core is running), or the terminal's own reflow.

## Environment and fixtures

```bash
R=/home/user/.cache/leas-tui/resize
rm -rf $R && mkdir -p $R/config/leas
cp docs/guides/tui/fixtures/config.json    $R/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db $R/config/leas/
```

`env -u NO_COLOR` is required for the same reason as in `colour-focus-audit` (this host exports
`NO_COLOR=1`, and crossterm honours it). Rows/columns asserted below were measured at 120x40 and
80x24 in the earlier pass; a resize should reproduce those layouts without a relaunch.

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | launch + `expect` | 120x40 baseline: footer ` Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`, status bar at row 39 |
| E2 | `resize("80x24")` | the app re-lays out with no relaunch: row 3 header stops at `Protocol Info`, the table footer moves to row 14 (`rows 1-7 of 7`), the 8-row panel to 15–22, the status bar to 23 |
| E3 | `line(23)` | the truncated 80-column hint row: ` Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next` |
| E4 | `resize("80x19")` | the shrink crosses the 20-row threshold with `actions_compact` still false, so the overlay branch takes the content area: row 1 becomes ` ⚙ Actions Log  ////…` and the profile table disappears from the screen |
| E5 | `capture` at 80x19 | no table anywhere (`Address` absent, the `┌ Profiles ─` box absent) while the tab bar still says `Profiles` — the app shows its log panel instead of its list |
| E6 | `resize("120x40")` | the table and the 8-row panel come back; row 3 is the full-width header again and row 30 the breadcrumb (` Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`) |
| E7 | `shot(artifacts/resize-back-120x40.png)` | the round trip leaves no torn frame, stray box characters or half-painted rows |

## Scenario script

```python
launch("env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/resize/config /home/user/oss/xray-tui/target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
expect("rows 1-7 of 7", timeout=20)
line(row=3)
resize("80x24")
stable()
line(row=3)
line(row=14)
line(row=23)
resize("80x19")
stable()
line(row=1)
capture(preserve_format=True)
resize("120x40")
stable()
line(row=3)
line(row=30)
line(row=39)
shot(path="/home/user/oss/xray-tui/docs/guides/tui/artifacts/resize-back-120x40.png")
close()
```

## Observed behaviour

| ID | Verdict | Evidence (verbatim excerpt + transcript step) |
|---|---|---|
| E1 | PASS | step 2 `✓ Found expected text: 'rows 1-7 of 7'`; step 4 `Line 3 …: │   #           Address                             Feat    Protocol Info              Test ↑  Outbound        Country█│` (the 120-column header) |
| E2 | PASS | steps 6–8 after `resize("80x24")`: `Line 3 …: │   #           Address                             Feat    Protocol Info     █│`, `Line 14 …:  Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`, `Line 23 …:  Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next` — the layout moved to the 80x24 shape with no relaunch |
| E3 | PASS | step 8 — the hint row is truncated at column 80, exactly as on a fresh 80x24 launch (`narrow-80x24` step 7) |
| E4 | PASS | step 11 `Line 1 (session: live-resize):  ⚙ Actions Log  ////////////////////////////////////////////////////////////////` — the content area is the log panel |
| E5 | PASS | step 12's capture: the whole content area is the actions panel (` ⚙ Actions Log  ///…`, `○ Disconnected`, `🖥 …`, `⏱ …`, `📊 …`, `📋  Core: [info] Whitelist loaded`), `┌ Profiles ─` and `Address` are absent, and row 0 still reads ` ○   Profiles    Settings …` |
| E6 | PASS | steps 15–17 after `resize("120x40")`: `Line 3 …` is the full-width header again, `Line 30 …:  Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`, `Line 39 …` the full hint row with `[?] Help  [q/Ctrl+C] Quit` |
| E7 | PASS | step 18 `✓ Screenshot saved: …/artifacts/resize-back-120x40.png` / `120x40 cells, font 14pt, 1722 cells carry colour` — the frame is clean: no torn box-drawing, no half-painted rows, no residue from the 80x19 pass |

## Corrections to expectations

None — all seven held on the first clean run.

## Visual polish remarks

| # | Where | What | Severity | Recommendation |
|---|---|---|---|---|
| P1 | 80x19, whole content area | the shrink replaces the profile table with the Actions Log panel while the tab bar still says `Profiles` — the app's primary view disappears and nothing on screen says so or offers a way back | major | make the small-height path choose the compact bar (the `<20` launch path already does) instead of the overlay, or cap the panel height and keep the tab's content above it |
| P2 | 80x19, status bar | the hint row keeps advertising `[→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect` while the panel is showing, so every hint on screen is wrong | major | swap the hint set with the view (the `Confirm`-dialog finding in `profiles-menus-states` #P6 is the same root cause) |
| P3 | 80x24, row 23 | the hint row is cut at column 80 and `[?] Help`/`[q/Ctrl+C] Quit` are the casualties — unchanged from a fresh small launch, so the resize path adds nothing new here | minor (already reported) | see `narrow-80x24` #P2 |
| P4 | 120x40 → 80x24 → 120x40 | the round trip repaints correctly: the 80x24 layout's column cut (`Protocol Info     █│`) does not leave ghost columns behind when the screen grows again | nit (positive) | nothing to do |

## Tooling friction

- **`resize` needs a settled frame**: a `stable()` after each resize is required (each read straight
  after the resize caught the pre-SIGWINCH frame once during recon).
- **`resize` changes only the session's pty and screen** — it does not relaunch the app, which is exactly
  the point, but it means `actions_compact` keeps the value it took at launch (`ui/mod.rs:78` sets it
  once from the startup size). That is what makes the 80x19 overlay reachable here and unreachable on a
  fresh small launch.

## Review of findings

**1. A mid-session shrink to 19 rows hides the profile table (major).** Evidence: steps 9–12 — after
`resize("80x19")` the content area is ` ⚙ Actions Log  ///…` with `🖥 vless 203.0.113.77:443 [xray]`,
`⏱ TCP: …`, `📊 …`, `📋  Core: …` and **no `Address` and no `┌ Profiles ─` anywhere**, while row 0
still reads `Profiles`. Why it matters: the one layout a user is most likely to trigger accidentally
(dragging a window smaller, or a smaller split pane) removes the app's reason to exist, and the hint
row still promises `[→] Expand`. Note the launch-time path handles this correctly — `tiny-80x14`
compacts the panel to one line and keeps the table — so the fix is to make the two paths agree:
`ui/mod.rs:78`'s one-shot `actions_compact` decision should follow the current size, not the startup
size.

**2. The hint set does not follow the view (major, shared root cause).** Evidence: step 12's status bar
with the panel showing: ` Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab]
Next  [?] Help  [q/Ctrl+C] Quit`. Every hint is wrong for the state on screen. Same class as
`profiles-menus-states` #P6 (hints unchanged under the delete confirmation).

**3. Resize itself is handled well (verified good).** Evidence: steps 6–8, 15–18 — the 80x24 shape
reproduces the fresh-launch layout exactly (same rows for header, footer and status bar), the 80x19
overlay is deterministic, and the return to 120x40 restores the full table, the panel and the full hint
row with a clean frame (1722 cells carrying colour, no ghosts).

### Verified good

- `resize` drives a real re-layout: the same row arithmetic as a fresh launch at each size (steps 6–8,
  15–17), so the responsive paths are testable headlessly for the first time.
- No torn frames, no residual box-drawing, no half-painted rows across two resizes (step 18's
  screenshot).
- The selection and the loaded page survive the round trip (`rows 1-7 of 7` before and after), so the
  resize path does not reload or re-sort the data.

### Reproduce

```bash
cd /home/user/oss/xray-tui
R=/home/user/.cache/leas-tui/resize
rm -rf $R && mkdir -p $R/config/leas
cp docs/guides/tui/fixtures/config.json    $R/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db $R/config/leas/
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-144700-scenario-live-resize.md live-resize
```
