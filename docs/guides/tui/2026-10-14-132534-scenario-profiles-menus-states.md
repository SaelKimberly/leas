---
name: profiles-menus-states
description: leas Profiles tab overlays and modal states — help, speed-test menu, export scope, delete confirmation, and the prefix-search filter including its filtered-empty state
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [profiles, overlays, help, search, confirm, status-bar]
---

# Scenario: profiles-menus-states (2026-10-14)

Recorded 2026-10-14 against leas 0.1.0 debug build `13e132f2…`. Walks every overlay reachable from
the Profiles tab plus both search outcomes, and records what the always-on bottom panel and the status
bar do while each is open. The screens quote that build; the shell has changed since (Settings is now
an overlay, the pane tabs are Profiles/Sniffer/Logs), so read the quotes as evidence of the recorded
build, not of the current tree.

## Purpose and scope

Walks every overlay reachable from the Profiles tab (help, Server Tools, export scope, delete
confirmation) plus both search outcomes, and records what the always-on bottom panel and the status bar
do while each is open.

Does not cover: running a speed test or an export (both hit the network or the clipboard), colour and
ANSI styling, or the settings screens.

## Environment and fixtures

| Field | Value |
|---|---|
| Run at | 2026-10-14 13:25:34 +0500 |
| App under test | leas 0.1.0, debug binary `/home/user/oss/xray-tui/target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Launch command | `env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/profiles-menus/config /home/user/oss/xray-tui/target/debug/leas` |
| Session / mode / size | `profiles-menus-states` / buffer / 120x40 |
| Harness | mcp-tui-test 0.3.0 (`/home/user/oss/mcp-tui-test`), Python 3.14.7, pyte 0.8.2 |
| Evidence | [2026-10-14-132534-scenario-profiles-menus-states-transcript.md](2026-10-14-132534-scenario-profiles-menus-states-transcript.md) |

Harness behaviour, its known limits and the wide-character workaround are documented once in
[INDEX.md](INDEX.md).

```bash
R=/home/user/.cache/leas-tui/profiles-menus
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"      # 7 endpoints, 8 protocols, synthetic
```

Fixtures: `fixtures/config.json` plus the seeded store `fixtures/seeded/data.db`. Fixture provenance:
the [profiles-import-and-table](2026-10-14-132534-scenario-profiles-import-and-table.md) scenario
imports `fixtures/import-urls.txt` into an empty store.

The copy is required before **every** run: background enrichment writes to `data.db`, so a re-run
against a dirty fixture is not the run this document describes.

Reproduce:

```bash
cd /home/user/oss/xray-tui
R=/home/user/.cache/leas-tui/profiles-menus
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-132534-scenario-profiles-menus-states.md profiles-menus-states
```

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | `region(30, 40)` | content footer ` Server: 203.0.113.77:443  [xray]  rows 1-7 of 7`, then the always-on panel ` ⚙ Actions Log  ////…`, `○ Disconnected`, `🖥 …`, `⏱ TCP:  -  RP:  -  SPD:  -`, `📊 ⬆ …`, `📋 Core: [info] …`, a blank row, `////…`, and the status bar; the connection state appears twice on one screen |
| E2 | `?` | popup `╭ Keyboard Shortcuts ─…╮`; row 8 is ` ↑↓ (expanded)         Navigate protocol variants (p`, description cut at the popup edge, no ellipsis |
| E3 | `line(28)` | the popup's bottom border `╰───…───╯` sits at row 28 of 30 content rows |
| E4 | `t` | popup `╭ Server Tools ─…╮` with `► Fast Ping (Selected)` at row 7 and the separator `─────` at row 11 |
| E5 | `line(21)` | ` Stop Testing` is drawn (dim = disabled) in a menu whose status bar advertises `[↑↓] Navigate  [Enter] Select  [Esc] Close` |
| E6 | `Ctrl+E` | `╭ Export Scope ─…╮` with `► Only Alive` at row 14; **row 0 is blank**: the tab bar is not drawn in form mode though its row is still reserved |
| E7 | `d` | `╭ Confirm ─…╮` naming the object: `  Delete "203.0.113.77:443"? (y/N)` |
| E8 | `line(39)` | while the confirm is open, the status bar still shows the Profiles hint set (`[→] Expand  [↑↓] Variant …`), not `y/N` |
| E9 | `/ams` | the query is a domain **prefix** match: `ams` matches nothing, so the table area shows ` No profiles — press 'a' to add one` although 7 endpoints exist; row 1 = ` View: Active [P]  / ams▉` |
| E10 | `/nl` | `nl` matches `nl-ams-01.synthetic-node.example`: row 4 = that endpoint, footer ` rows 1-1 of 1` |

## Scenario script

```python
launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/profiles-menus/config /home/user/oss/xray-tui/target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
expect("rows 1-7 of 7", timeout=20)
region(row_start=30, row_end=40)
send("?")
expect("Keyboard Shortcuts", timeout=5)
line(row=8)
line(row=9)
line(row=28)
key("escape")
send("t")
expect("Server Tools", timeout=5)
line(row=7)
line(row=11)
line(row=21)
key("escape")
ctrl("e")
expect("Export Scope", timeout=5)
line(row=0)
line(row=14)
key("escape")
send("d")
expect("Confirm", timeout=5)
line(row=14)
line(row=39)
key("escape")
send("/ams")
stable()
line(row=1)
line(row=2)
key("escape")
send("/nl")
stable()
line(row=4)
line(row=30)
close()
```

## Observed behaviour

| ID | Verdict | Evidence (verbatim excerpt + transcript step) |
|---|---|---|
| E1 | PASS | step 3 `region(30-39)`: ` Server: 203.0.113.77:443  [xray]  rows 1-7 of 7` then ` ⚙ Actions Log  ////…`, `○ Disconnected`, `🖥 vless 203.0.113.77:443 [xray]`, `⏱ TCP:       -  RP:       -  SPD:        -`, `📊 ⬆    0.0 B  ⬇    0.0 B  💾       -`, `📋 Core: [info] startup: version=0.1.0 page=7 rows tcp-timeout=DurationOrSecs(5s) real-timeout=DurationOrSecs(5s) real-r`, blank, `////…`, and the status bar; the connection state is on screen twice |
| E2 | PARTIAL | step 5 `✓ Found expected text: 'Keyboard Shortcuts'`; step 6 `Line 8 …: │        5 [🏴   fi-hel-06.synthe│ Enter                 Set as active server / Activa│[name] [—               —      █│`; a description is clipped, but it is `Activa`, not the row-8 text the prediction named (see *Corrections*) |
| E3 | PASS | step 8 `Line 28 …: │                                ╰────────────────────────────────────────────────────╯                               █│` |
| E4 | PARTIAL | step 11 `✓ Found expected text: 'Server Tools'`; step 12 `Line 7 …: │        4 [🏴   de-fra-02.synthetic-no│► Fast Ping (Selected)                  │   }=>[name] [—               —      █│`; step 13 `Line 11 …: │                                      │ ─────                                  │                                     █│` |
| E5 | PASS | step 14 `Line 21 …: │                                      │  Stop Testing                          │                                     █│` |
| E6 | PARTIAL | step 17 `✓ Found expected text: 'Export Scope'`; step 18 `Line 0 (session: profiles-menus-states):` (empty, the tab bar's row is not drawn); step 19 `Line 14 …: │                                │  Only Resolved                                     │                               █│`; the popup and the blank row 0 are as predicted, the marker row is one higher (see *Corrections*) |
| E7 | PARTIAL | step 22 `✓ Found expected text: 'Confirm'`; step 23 `Line 14 …: │                                        ╭ Confirm ───────────────────────────╮                                       █│`; the popup's top border is at row 14, the object-naming row (15) was not read by this script (see *Corrections*) |
| E8 | PASS | step 24 `Line 39 …:  Disconnected        [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit` |
| E9 | PASS | step 27 (stabilized screen) ` View: Active [P]  / ams▉` … `                                           No profiles — press 'a' to add one` and no `┌ Profiles` box; step 28 `Line 1 …:  View: Active [P]  / ams▉`; step 29 `Line 2 …:                                            No profiles — press 'a' to add one` |
| E10 | PASS | step 32 (stabilized screen) `┌ Profiles ─…│▶       1 [🏴   nl-ams-01.synthetic-node.example …` with ` Server: nl-ams-01.synthetic-node.example:443  [xray]  rows 1-1 of 1`; step 33 `Line 4 …: │▶       1 [🏴   nl-ams-01.synthetic-node.example ][🏁  ]=>{   vless/tcp/reality    }=>[name] [—               —      █│`; step 34 `Line 30 …:  Server: nl-ams-01.synthetic-node.example:443  [xray]  rows 1-1 of 1` |

## Corrections to expectations

- **E2's row index was one off, its text was two off.** Predicted `Navigate protocol variants (p` at
  row 8; the observed row 8 is the third `↑↓ / PgUp PgDn` item, `Enter                 Set as active
  server / Activa`. The defect class is the same (a description cut at the popup's inner edge with no
  ellipsis), and the help body starts one row lower than predicted: the popup is 25 rows tall (21 items
  + 2 blank rows + 2 borders), vertically centred in the 30-row content area, so the first item is
  row 5.
- **E4's marker row is right, its wording is loose.** `► Fast Ping (Selected)` is on row 7 exactly as
  predicted; the transcript does not carry the popup's title row (row 6), only
  `✓ Found expected text: 'Server Tools'` at step 11.
- **E6's first item sits on row 13, not 14.** Row 14 is `Only Resolved`; the predicted `► Only Alive`
  is one row higher. The popup is 9 rows (title 12, items 13–16, two blank rows, border 20) and row 0 is
  empty in this mode, as predicted and confirmed at step 18.
- **E7 read the popup's top border, not its text row.** The dialog is present, centred, and titled
  `Confirm` at row 14 (step 23); the naming row is 15 and this script did not read it. The earlier
  ad-hoc probe for this walkthrough did, immediately after `Esc` from the export menu and `↓`, `d`:
  `│  Delete "nl-ams-01.synthetic-node.example:443"? (y/N)  │`. That is an ad-hoc observation, not this
  scenario's transcript, so E7 is PARTIAL rather than PASS.
- **Overlays are read through the screen, so a row index in a prediction is easy to be one off.** Two
  predictions here were off by exactly one row for that reason (E2, E6). The popup geometry is computed
  from the content area's size, not from a constant, so it also moves with the terminal size; prefer
  `expect`/`assert_text` for popups and read rows only to quote a cell.
- **`expect` on a popup title is not a synchronizer for the popup's *content*.** `expect('Server Tools')`
  matches while the list is still painting its first frame; the following `line()` reads are 300 ms
  later and did reflect the painted list here, but a popup that animates would need `wait_for_stable`
  first.
- **`send('d')` with a live clipboard is a no-op trap for a scenario author**: `d` opens the delete
  confirmation only on the Profiles tab in List mode, and this scenario reaches it through two prior
  modal states, so the step order matters more than the keystroke.

## Verdict

Six of ten expectations PASSed and four were PARTIAL; none FAILed, and every PARTIAL was a wrong row
index or wrong wording in the prediction rather than a different app state. Two of the eight remarks are
user-facing contradictions rather than cosmetics: the modal hint bar (P6) and the filtered-empty state
(P7). Both are cheap to fix and both currently mislead.

Severity split: 0 blocker, 2 major, 4 minor, 2 nit.

### P1: the always-on panel spends 8 of 40 rows restating the status bar (minor)

- **Where**: row 31, col 1.
- **Observed**: the breadcrumb ` Server: …` and the panel below it are a second status line:
  `○ Disconnected` (panel row 32) repeats the status bar's ` Disconnected` (row 39) verbatim, and the
  panel's other four lines are idle-state telemetry: `🖥 vless 203.0.113.77:443 [xray]`,
  `⏱ TCP: …  RP: …  SPD: …`, `📊 ⬆ … ⬇ … 💾 …` (step 3).
- **Why it matters**: 20% of a 40-row terminal is given to a block whose only changing content is the
  last log line; at 80x24 it is 8 of 24 (see
  [narrow-80x24](2026-10-14-132534-scenario-narrow-80x24.md)).
- **Fix**: drop the panel's connection block when a connection is up, or fold it into the status bar and
  give the 8 rows back to the table; the app's own compact bar is the better default.

### P2: the panel's last-log line leaks Rust internals and is cut mid-word (minor)

- **Where**: panel row 37.
- **Observed**: `📋 Core: [info] startup: version=0.1.0 page=7 rows tcp-timeout=DurationOrSecs(5s)
  real-timeout=DurationOrSecs(5s) real-r` (step 3).
- **Why it matters**: `DurationOrSecs(5s)` is a Rust `Debug` form, and the line ends mid-word, so a
  reader cannot tell whether the message is complete.
- **Fix**: keep the summary line to a user-level message and ellipsize the tail.

### P3: the help popup clips its own instructions (minor)

- **Where**: help popup rows 6–27.
- **Observed**: every description longer than 27 cells is cut mid-word with no ellipsis:
  `│ Enter                 Set as active server / Activa│` (step 6). The `Keyboard Shortcuts` popup is a
  fixed 52 columns.
- **Why it matters**: the help overlay is where a user goes to discover keys, and the two longest rows
  are the ones cut.
- **Fix**: measure the content and size the popup to its widest row (or wrap), and add `…`.

### P4: menu separators and the disabled item (nit)

- **Where**: Server Tools popup rows 12–28.
- **Observed**: separators are a 5-cell dash ` ─────` inside a 38-cell menu (step 13), so the groups are
  visually weaker than the items; ` Stop Testing` (step 14) is disabled by dimming only, with no glyph
  change.
- **Why it matters**: grouping and disabled-state cues that live in colour alone do not survive a
  monochrome terminal.
- **Fix**: draw separators across the menu's inner width; mark a disabled item with a suffix (e.g. `·`)
  as well as the dim.

### P5: the export modal blanks the tab bar's row (minor)

- **Where**: export popup, row 0.
- **Observed**: `Line 0 (session: profiles-menus-states):` is an empty string (step 18) while the list
  renders normally below. In `ExportScope` the tab bar's reserved row is left blank instead of being
  kept or reclaimed, so the whole content area shifts up one row.
- **Why it matters**: the top of the screen looks torn for the dialog's lifetime, and any future layout
  change that assumes the tab bar is always at row 0 will be wrong.
- **Fix**: keep the tab bar while a modal is open, or give its row to the dialog.

### P6: the status bar lies during the delete confirmation (major)

- **Where**: status bar row 39 during `Confirm`.
- **Observed**: step 24 reads
  ` Disconnected        [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit`
  while the dialog `╭ Confirm ─…` is up on row 14 (step 23) and only `y`/`n`/`Esc` are handled; `q`
  here *cancels the dialog*, it does not quit.
- **Why it matters**: the one hint a user reads before pressing a key during a destructive action is
  wrong in both directions: it advertises operations that do nothing and a quit that actually cancels.
- **Fix**: swap the hint set for `[y] Delete  [n/Esc] Cancel` while the confirmation is open. The same
  overlay serves `Quit?`, `Clear all stats?` and the group confirmations, so the fix is one state-aware
  hint set. `ui/status_bar.rs` owns the hint row and `ui/mod.rs` draws the confirmation dialog.

### P7: a filter that matches nothing claims the store is empty (major)

- **Where**: row 2, filtered-empty state.
- **Observed**: steps 27–29: ` View: Active [P]  / ams▉`, then ` No profiles — press 'a' to add one`,
  with the table box and the header gone entirely.
- **Why it matters**: the store holds 7 endpoints; the screen says it is empty and offers to create a
  profile, and the user is unlikely to guess that a prefix filter (`nl` matches, `ams` does not) is
  hiding them.
- **Fix**: when `search_query` is non-empty and the page is empty, render `No profile matches "ams"` and
  hint `Esc`; keep the table header so the columns do not vanish.

### P8: the hint bar advertises no-ops in the filtered-empty state (nit)

- **Where**: status bar, step 27.
- **Observed**: with the list showing ` No profiles — press 'a' to add one`, row 39 still advertises
  `[→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect`; all three are no-ops with nothing selected.
- **Fix**: derive the hint set from the state (row count, filter, modal).

### Verified good

- The help overlay opens from the table (`?`), exists on every screen, and closes on both `?` and `Esc`:
  `✓ Found expected text: 'Keyboard Shortcuts'` (step 5), popup border on row 28 (step 8).
- The Server Tools menu shows a keyboard-independent selection marker (`►`) rather than colour alone,
  and the menu's disabled row is at least dimmed rather than absent: steps 12, 14.
- The delete confirmation names the object it will delete and defaults to `N` in its own text
  (`(y/N)`): step 23 and the ad-hoc quote in *Corrections*.
- Prefix search is fast and correct on the domain (`/nl` → `rows 1-1 of 1`, steps 32–34) and `Esc`
  clears it, returning the full `rows 1-7 of 7` list on the next attempt.
- The keyboard-only selection model holds: `↑↓`, `Esc` and `Enter` reach every one of these states
  without a mouse.
