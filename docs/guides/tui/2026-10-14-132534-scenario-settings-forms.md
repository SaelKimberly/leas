---
name: settings-forms
description: leas Settings tab — the 20-node section tree, opening a section into the right pane, field focus and the cursor, and what q does inside a settings form
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [settings, tree, form, focus, keyboard]
---

# Scenario: settings-forms (2026-10-14)

Recorded 2026-10-14 against leas 0.1.0 debug build `13e132f2…`. Covers the Settings entry state,
opening a section, field focus, what a printable key does inside a form, and the two `Esc` levels back
out. The screens quote that build. The Settings surface has since been rebuilt as a popup overlay with a
flat section list that loads its pane on move (see
[settings-xrat-parity](2026-10-16-093000-scenario-settings-xrat-parity.md)), so read the quotes as
evidence of the recorded build, not of the current tree.

## Purpose and scope

Covers the Settings entry state (tree + empty right pane), opening `Core Settings`, how field focus is
signalled, what a printable key does inside a form, and the two `Esc` levels back out.

Does not cover: saving a form (the fixture's config is not the user's), the Routing Rules or
Subscriptions sub-screens, or colour.

## Environment and fixtures

| Field | Value |
|---|---|
| Run at | 2026-10-14 13:25:34 +0500 |
| App under test | leas 0.1.0, debug binary `/home/user/oss/xray-tui/target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Launch command | `env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-forms/config /home/user/oss/xray-tui/target/debug/leas` |
| Session / mode / size | `settings-forms` / buffer / 120x40 |
| Harness | mcp-tui-test 0.3.0 (`/home/user/oss/mcp-tui-test`), Python 3.14.7, pyte 0.8.2 |
| Evidence | [2026-10-14-132534-scenario-settings-forms-transcript.md](2026-10-14-132534-scenario-settings-forms-transcript.md) |

Harness behaviour, its known limits and the wide-character workaround are documented once in
[INDEX.md](INDEX.md).

```bash
R=/home/user/.cache/leas-tui/settings-forms
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"
```

Fixtures: `fixtures/config.json` plus the seeded store `fixtures/seeded/data.db`. Copy before every run
(see [profiles-menus-states](2026-10-14-132534-scenario-profiles-menus-states.md) for why). The typed
`Z`/`q` reached a config field, so a re-run without the reset starts from `Q`/`Zq` in `Sing-Box Path`;
the assertion below pins only the *last* keystroke's effect.

Reproduce:

```bash
cd /home/user/oss/xray-tui
R=/home/user/.cache/leas-tui/settings-forms
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-132534-scenario-settings-forms.md settings-forms
```

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | `Tab` from Profiles | tab bar highlights Settings; `┌ Settings ────────…┐` (34 cols) beside `┌ Select a section ─…┐`; the right pane is empty until a section is opened |
| E2 | `line(2)`, `line(4)` | tree rows `│▾ Core                           2│` and `│    Core Settings                 │`; the trailing number is the child count, unlabelled |
| E3 | `line(39)` | status bar ` Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close`; no quit hint |
| E4 | `Enter` on the tree | the right pane title becomes `┌ Core Settings ─…┐` with fields `Xray Path               : > (empty)`, `Log Level               : > < warning >`, `Skip Cert Verify        : > [ ]` |
| E5 | `cursor()` after opening | cursor parked at row 39, column 120 (bottom-right of the screen); no field is focused yet |
| E6 | `cursor()` after `Tab` | cursor inside a field value: row 4, column 67 |
| E7 | `send("Z")` then `send("q")` | row 4 shows `Sing-Box Path           : > Zq`; printable keys edit the focused field, and the app does not quit |
| E8 | `assert_text` | `Core Settings` still on screen after `q` (the session is alive) |
| E9 | `Esc` | back to the tree: right pane title `┌ Select a section ─…┐`, breadcrumb ` Settings `, hint row back to `[↑↓] Navigate  [←→] Collapse …` |
| E10 | `Esc` again | back on the Profiles tab with its table and ` View: Active [P] …` row |

## Scenario script

```python
launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-forms/config /home/user/oss/xray-tui/target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
expect("rows 1-7 of 7", timeout=20)
key("tab")
expect("Select a section", timeout=5)
line(row=2)
line(row=4)
line(row=39)
key("down")
key("enter")
expect("Core Settings", timeout=5)
line(row=2)
line(row=6)
line(row=8)
line(row=39)
cursor()
key("tab")
cursor()
send("Z")
send("q")
line(row=4)
assert_text("Core Settings")
key("escape")
line(row=1)
line(row=39)
key("escape")
line(row=1)
close()
```

## Observed behaviour

| ID | Verdict | Evidence (verbatim excerpt + transcript step) |
|---|---|---|
| E1 | PASS | step 4 `✓ Found expected text: 'Select a section'`; step 23 `Line 1 …: ┌ Settings ────────────────────────┐ ┌ Select a section ───────────────────────────────────────────────────────────────┐` |
| E2 | PARTIAL | step 5 `Line 2 …: │▾ Core                           2│ │                                                                                 │` (count confirmed); step 6 `Line 4 …: │    Protocol Core                 │`; the second tree row is on row 3, not row 4 (see *Corrections*) |
| E3 | PASS | step 7 `Line 39 …:  Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close` |
| E4 | PASS | step 11 `Line 2 …: │▾ Core                           2│ │Xray Path               : > (empty)                                              │`; step 12 `Line 6 …: │    Inbound                       │ │Log Level               : > < warning >                                          │`; step 13 `Line 8 …: │    TUN                           │ │Skip Cert Verify        : > [ ]                                                  │` |
| E5 | PASS | step 15 `Cursor position (session: settings-forms): row 39, column 120` |
| E6 | PASS | step 17 `Cursor position (session: settings-forms): row 4, column 67` |
| E7 | PASS | step 20 `Line 4 …: │    Protocol Core                 │ │Sing-Box Path           : > Zq                                                   │` |
| E8 | PASS | step 21 `✓ Assertion passed: Found 'Core Settings' in output` |
| E9 | PASS | step 23 `Line 1 …: ┌ Settings ────────────────────────┐ ┌ Select a section ───────────────────────────────────────────────────────────────┐`; step 24 `Line 39 …:  Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close` |
| E10 | FAIL | step 26 `Line 1 (session: settings-forms):` (empty); `Esc` at the tree level does **not** return to the Profiles table (see *Corrections*) |

## Corrections to expectations

- **E2: the tree's second leaf is on row 3, not row 4.** Step 5 shows `│▾ Core 2│` on row 2 and step 6
  shows `│    Protocol Core │` on row 4, so `Core Settings` occupies row 3. The tree is
  `▾ Core` / `Core Settings` / `Protocol Core` / `▾ Connection` / …, one node per row, no blank rows; the
  child-count claim (trailing `2` on the category row) is confirmed.
- **E10 is wrong about the app, and the expectation is the wrong part.** `Esc` in the Settings tree sets
  the app mode back to `List` but leaves the tab on `Settings` (the two-line cause is in
  `ui/settings.rs`), and the Settings tab has no List-mode body: step 26 returns an empty row 1 and the
  tab bar, the actions panel and the status bar are the only content left. An ad-hoc capture taken while
  preparing this document shows the full state, the whole content area blank between the tab bar and the
  panel, status bar
  ` Disconnected                                                                                           [q/Ctrl+C] Quit`.
  It is flagged as an ad-hoc observation because it is not in this scenario's transcript (probe12,
  collected in the [ad-hoc evidence](2026-10-14-132534-review-evidence-adhoc.md)). The state is a dead
  end: the only keys that lead anywhere are `Tab`/`Shift+Tab` and `q`.
- **Cursor state is the only focus witness, and only the buffer exposes it.** `get_cursor_position` is a
  single-cell read and was reliable here (`row 39, column 120` then `row 4, column 67`), but nothing in a
  text capture distinguishes a focused field from an unfocused one, because the `> ` prefix is on every
  field.
- **A printable key sent to a text form edits the fixture's config.** `send("Z")`/`send("q")` here wrote
  into `Sing-Box Path`, so this scenario mutates its own fixture and depends on the copy-before-run reset
  even more than the others.
- **`Esc` semantics differ per level and are not discoverable from the screen** (form → tree, tree →
  blank Settings tab). E10 was written on the assumption that the second `Esc` leaves the tab; a
  `Tab`-less way back to the profile list does not exist, which is itself the finding.

## Verdict

Eight of ten expectations PASSed, one was PARTIAL and one FAILed; the failure is a real app state, not a
prediction error. The form itself is in good shape: labels, value controls, `Enter` to save, `Esc` to
back out, a breadcrumb and a complete hint row. The findings are about *what the screen omits*, and two
of them are contradictions between the UI or the manual and the behaviour.

Severity split: 0 blocker, 2 major, 5 minor, 1 nit.

### P1: the Settings tree's trailing integer is an unlabelled child count (minor)

- **Where**: tree rows 2–21.
- **Observed**: 20 nodes in 5 groups, each category row carrying an unlabelled trailing integer
  (`│▾ Core                           2│`) that is the *child count* but reads as an ordinal. The group
  order is Core, Connection, Routing, GUI, Advanced.
- **Why it matters**: the manual's flat 1–14 numbering does not match the UI at all.
- **Fix**: label the count (`2 items`) or drop it, and reorder groups by frequency of use (the manual's
  order).

### P2: the tree's hint row omits that `Tab` leaves the screen (minor)

- **Where**: row 39 after `Tab`.
- **Observed**: `[↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close`. Both the
  help overlay (`Tab / Shift+Tab  Cycle tabs`) and `docs/guides/tui-manual.md` say `Tab` cycles tabs; the
  hint row is the only surface that does not.
- **Why it matters**: `Tab` is a "next field" reflex for anyone who used the form level one keystroke
  earlier, and here it silently switches tabs.
- **Fix**: add `[Tab] Next tab` to the tree's hint row (the wording already exists in the help overlay).

### P3: the right pane opens empty and `Enter` on a category collapses it (minor)

- **Where**: right pane, entry state.
- **Observed**: entering Settings leaves an 81×28 pane titled `Select a section` completely empty (28
  blank rows, steps 4/23), with the tree's first node (a *category*) selected, so the first `Enter`
  (steps 8–9, ad-hoc witness) toggles `Core`'s disclosure triangle instead of opening anything.
- **Why it matters**: a 60-cell-wide pane that says nothing is the first thing a user sees in Settings,
  and the natural first keystroke does nothing useful.
- **Fix**: auto-select the first leaf (`Core Settings`) when the pane opens, or render a short index of
  sections in the empty pane.

### P4: field pitch (nit)

- **Where**: form, rows 2–10.
- **Observed**: fields are separated by whole blank rows (`Xray Path` row 2, `Sing-Box Path` row 4,
  `Log Level` row 6 …), so five fields occupy nine rows and the pane is 60% empty below them.
- **Fix**: halve the row pitch, or put the field's help text where the blank row is.

### P5: a form edit is discarded without a dirty marker (minor)

- **Where**: closing the form.
- **Observed**: `Esc` **discards** the edited field with no save/discard confirmation and no dirty
  marker; `Sing-Box Path : > Zq` returns to `Select a section` with nothing on screen to say the edit was
  dropped.
- **Fix**: mark the form dirty, or confirm discard when a field changed.

### P6: `q` types a character into a config value (major)

- **Where**: row 39 in the form.
- **Observed**: step 20 `│ Sing-Box Path           : > Zq │` after `send("Z")`, `send("q")` (steps
  18–19), with the session alive (step 21). The form's hint row is complete
  (`[Tab/Shift+Tab] Focus  [Enter] Save  [Ctrl+W] Focus Tree  [Esc] Back`) but omits quit, while `q` in
  a focused text field types `q` into the config value and `q` in the tree does nothing (probe14: session
  alive, `Select a section` still on screen, [evidence](2026-10-14-132534-review-evidence-adhoc.md)).
- **Why it matters**: `q` is the quit key everywhere else in this app, and every user has that muscle
  memory; in a settings form it silently appends a character to a proxy configuration value, and `Esc`
  then discards it (P5) with no marker that anything changed. The manual's Settings-Tab table still says
  `q / Ctrl+C — Quit application`.
- **Fix**: fix the manual's Settings-Tab key table, and make `q` a no-op in editable fields (or require
  `Ctrl+Q`) so quit keeps one meaning.

### P7: focus is invisible until the first `Tab` (minor)

- **Where**: form entry.
- **Observed**: the cursor is parked at (39, 120), the screen's bottom-right corner, until the first
  `Tab` (step 15), so nothing on screen indicates the edit target; the value controls also all wear the
  same `> ` prefix (`> (empty)`, `> < warning >`, `> [ ]`), which is decoration rather than focus.
- **Fix**: focus the first field on open and draw the caret there, or use `>` for the focused field only.

### P8: `Esc` at the tree level leaves a blank Settings tab (major)

- **Where**: whole content area after the second `Esc`.
- **Observed**: step 26 `Line 1 (session: settings-forms):` is empty. `Esc` closes the split but leaves
  the tab on Settings, whose List-mode body is empty: rows 1–30 render nothing and the only remaining
  chrome is the tab bar, the actions panel and ` Disconnected … [q/Ctrl+C] Quit` (the full state is the
  ad-hoc capture quoted in *Corrections*).
- **Why it matters**: the tree's own hint says `[Esc] Close`, and what it closes is the split view while
  staying on the Settings tab; the tab then renders nothing at all, so the screen is a dead end whose
  only exit is `Tab` or `q`.
- **Fix**: return to the Profiles tab on `Esc`, or give the Settings tab a List-mode body (the manual
  describes a section menu).

### Verified good

- Labels and value controls are unambiguous and consistent: `Xray Path  : > (empty)`,
  `Log Level  : > < warning >`, `Skip Cert Verify  : > [ ]` (steps 11–13); text, select and boolean each
  have a distinct shape.
- Focus is reachable and the caret lands *inside* the focused field: `row 4, column 67` after one `Tab`
  (step 17), and the edit lands on the same field (`> Zq`, step 20). The tree↔form focus switch
  (`Ctrl+W`) and the breadcrumb (` Settings > Core `, step 14) communicate where you are.
- Opening a section is a real two-pane layout at 120 columns with a title, not a modal that hides the
  tree: steps 11–14.
- `Esc` from the form is a clean, single-level back-out: the tree returns with
  `┌ Select a section ─…┐` and the hint row reverts (steps 23–24).
- The app keeps running through `q` and every read stays consistent (step 21), so the scenario's own
  liveness assumption held.
