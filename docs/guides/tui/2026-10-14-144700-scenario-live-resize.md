---
name: live-resize
description: leas driven through live resizes with the resize tool, 120x40 to 80x24 to 80x19 (the overlay branch a fresh small launch never reaches) back to 120x40, checking the layout and any residue
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [responsiveness, resize, overlay, anomalies]
---

# Scenario: live-resize (2026-10-14)

Records what leas does when the terminal shrinks and grows mid-session: the layout at each size, the
state a shrink below 20 rows produces, and whether the round trip leaves residue. It does not cover
resize while a core is connected, or the terminal's own reflow.

## Purpose and scope

`dimensions` only applies at launch, so the layout branch a *shrink* takes (a session that started
tall, then lost rows) was unreachable in the earlier pass: `tiny-80x14` and `narrow-80x24` both
launched at the small size and observed the app *compacting*. This drives SIGWINCH mid-session instead,
and checks the round trip for torn or ghosted cells.

Out of scope: resize while connected (no core is running), and the terminal's own reflow.

## Environment and fixtures

| Field | Value |
|---|---|
| Run at | 2026-10-14 14:47:00 +0500 |
| App under test | leas 0.1.0, debug binary `target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Launch command | `env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/resize/config target/debug/leas` |
| Session / mode / size | `live-resize` / buffer / 120x40 → 80x24 → 80x19 → 120x40 (one launch, three resizes) |
| Harness | mcp-tui-test 1.0.1, Python 3.14.7, pyte 0.8.2, Pillow |
| Evidence | [live-resize transcript](2026-10-14-144700-scenario-live-resize-transcript.md); screenshots in [`artifacts/`](artifacts/) |

Commands run from the repository root.

```bash
R=/home/user/.cache/leas-tui/resize
rm -rf $R && mkdir -p $R/config/leas
cp docs/guides/tui/fixtures/config.json    $R/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db $R/config/leas/
```

`env -u NO_COLOR` is required for the same reason as in
[colour-focus-audit](2026-10-14-144700-scenario-colour-focus-audit.md): this host exports `NO_COLOR=1`,
and crossterm honours it. Rows and columns asserted below were measured at 120x40 and 80x24 in the
earlier pass; a resize should reproduce those layouts without a relaunch.

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | launch + `expect` | 120x40 baseline: footer ` Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`, status bar at row 39 |
| E2 | `resize("80x24")` | the app re-lays out with no relaunch: row 3 header stops at `Protocol Info`, the table footer moves to row 14 (`rows 1-7 of 7`), the 8-row panel to 15–22, the status bar to 23 |
| E3 | `line(23)` | the truncated 80-column hint row: ` Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next` |
| E4 | `resize("80x19")` | the shrink crosses the 20-row threshold with `actions_compact` still false, so the overlay branch takes the content area: row 1 becomes ` ⚙ Actions Log  ////…` and the profile table disappears from the screen |
| E5 | `capture` at 80x19 | no table anywhere (`Address` absent, the `┌ Profiles ─` box absent) while the tab bar still says `Profiles`, the app shows its log panel instead of its list |
| E6 | `resize("120x40")` | the table and the 8-row panel come back; row 3 is the full-width header again and row 30 the breadcrumb (` Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`) |
| E7 | `shot(artifacts/resize-back-120x40.png)` | the round trip leaves no torn frame, stray box characters or half-painted rows |

## Scenario script

```python
launch("env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/resize/config target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
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
shot(path="docs/guides/tui/artifacts/resize-back-120x40.png")
close()
```

## Observed behaviour

| ID | Verdict | Evidence (verbatim excerpt + transcript step) |
|---|---|---|
| E1 | PASS | step 2 `✓ Found expected text: 'rows 1-7 of 7'`; step 3 `Line 3 …: │   #           Address                             Feat    Protocol Info              Test ↑  Outbound        Country█│` (the 120-column header) |
| E2 | PASS | steps 6–8 after `resize("80x24")`: `Line 3 …: │   #           Address                             Feat    Protocol Info     █│`, `Line 14 …:  Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`, `Line 23 …:  Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next` — the layout moved to the 80x24 shape with no relaunch |
| E3 | PASS | step 8, the hint row is truncated at column 80, exactly as on a fresh 80x24 launch (`narrow-80x24` step 7) |
| E4 | PASS | step 11 `Line 1 (session: live-resize):  ⚙ Actions Log  ////////////////////////////////////////////////////////////////`, the content area is the log panel |
| E5 | PASS | step 12's capture: the whole content area is the actions panel (` ⚙ Actions Log  ///…`, `○ Disconnected`, `🖥 …`, `⏱ …`, `📊 …`, `📋  Core: [info] Whitelist loaded`), `┌ Profiles ─` and `Address` are absent, and row 0 still reads ` ○   Profiles    Settings …` |
| E6 | PASS | steps 15–17 after `resize("120x40")`: `Line 3 …` is the full-width header again, `Line 30 …:  Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`, `Line 39 …` the full hint row with `[?] Help  [q/Ctrl+C] Quit` |
| E7 | PASS | step 18 `✓ Screenshot saved: …/artifacts/resize-back-120x40.png` / `120x40 cells, font 14pt, 1722 cells carry colour`, the frame is clean: no torn box-drawing, no half-painted rows, no residue from the 80x19 pass |

All seven expectations held on the first clean run, so there are no corrections to the expectation
table. The step numbers above are the transcript's own.

## Verdict

7 PASS, 0 PARTIAL, 0 FAIL.

**Finding 1 (major, at run time): a mid-session shrink to 19 rows hides the profile table.** Evidence:
steps 9–12, after `resize("80x19")` the content area is ` ⚙ Actions Log  ///…` with
`🖥 vless 203.0.113.77:443 [xray]`, `⏱ TCP: …`, `📊 …`, `📋  Core: …` and no `Address` and no
`┌ Profiles ─` anywhere, while row 0 still reads `Profiles`. The launch-time path handles this
correctly: `tiny-80x14` compacts the panel to one line and keeps the table. Fix: make the
`actions_compact` decision follow the current size, not the startup size.

**Finding 2 (major, at run time, shared root cause): the hint set does not follow the view.** Evidence:
step 12's status bar with the panel showing: ` Disconnected [→] Expand  [↑↓] Variant
[Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit`. Every hint is wrong for the state
on screen. Same class as `profiles-menus-states` #P6 (hints unchanged under the delete confirmation).
Fix: one state-aware hint set.

Both findings are still open in the current source, with a partial mitigation: `actions_compact` is
still decided once at startup (`ui/mod.rs:78` at run time, `crates/leas/src/ui/mod.rs:140` now, inside
`run`), so the 80x19 shrink can still take the overlay branch, but `Esc` now closes that overlay when
the terminal is below 20 rows (`crates/leas/src/ui/mod.rs:1381-1382`). Verified good at run time:
`resize` drives a real re-layout (the same row arithmetic as a fresh launch at each size), no torn
frames or residual box-drawing across two resizes (step 18's screenshot), and the selection and the
loaded page survive the round trip (`rows 1-7 of 7` before and after), so the resize path does not
reload or re-sort the data.

Harness notes:

- `resize` needs a settled frame: `stable()` after each resize is required (each read straight after the
  resize caught the pre-SIGWINCH frame once during recon).
- `resize` changes only the session's pty and screen. It does not relaunch the app, which is the point,
  and it means the `actions_compact` value taken at launch persists at run time. That is what made the
  80x19 overlay reachable here and unreachable on a fresh small launch.

Reproduce:

```bash
R=/home/user/.cache/leas-tui/resize
rm -rf $R && mkdir -p $R/config/leas
cp docs/guides/tui/fixtures/config.json    $R/config/leas/
cp docs/guides/tui/fixtures/seeded/data.db $R/config/leas/
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-144700-scenario-live-resize.md live-resize
```
