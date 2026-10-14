---
name: settings-forms
description: leas Settings tab — the 20-node section tree, opening a section into the right pane, field focus and the cursor, and what q does inside a settings form
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [settings, tree, form, focus, keyboard]
---

# Scenario: settings-forms

| Field | Value |
|---|---|
| Run at | 2026-10-14 13:25:34 +0500 |
| App under test | leas 0.1.0, debug binary `/home/user/oss/xray-tui/target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Launch command | `env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-forms/config /home/user/oss/xray-tui/target/debug/leas` |
| Session / mode / size | `settings-forms` / buffer / 120x40 |
| Harness | mcp-tui-test 0.3.0 (`/home/user/oss/mcp-tui-test`), Python 3.14.7, pyte 0.8.2 |
| Evidence | [2026-10-14-132534-scenario-settings-forms-transcript.md](2026-10-14-132534-scenario-settings-forms-transcript.md) |

## Purpose and scope

Covers the Settings entry state (tree + empty right pane), opening `Core Settings`, how field focus is
signalled, what a printable key does inside a form, and the two `Esc` levels back out.

Does not cover: saving a form (the fixture's config is not the user's), the Routing Rules /
Subscriptions sub-screens, or colour.

## Environment and fixtures

```bash
R=/home/user/.cache/leas-tui/settings-forms
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"
```

Copy before every run (see `profiles-menus-states` for why). The typed `Z`/`q` reached a config field,
so a re-run without the reset starts from `Q`/`Zq` in `Sing-Box Path`; the assertion below pins only
the *last* keystroke's effect.

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | `Tab` from Profiles | tab bar highlights Settings; `┌ Settings ────────…┐` (34 cols) beside `┌ Select a section ─…┐` — the right pane is empty until a section is opened |
| E2 | `line(2)`, `line(4)` | tree rows `│▾ Core                           2│` and `│    Core Settings                 │` — the trailing number is the child count, unlabelled |
| E3 | `line(39)` | status bar ` Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close` — no quit hint |
| E4 | `Enter` on the tree | the right pane title becomes `┌ Core Settings ─…┐` with fields `Xray Path               : > (empty)`, `Log Level               : > < warning >`, `Skip Cert Verify        : > [ ]` |
| E5 | `cursor()` after opening | cursor parked at row 39, column 120 (bottom-right of the screen) — no field is focused yet |
| E6 | `cursor()` after `Tab` | cursor inside a field value: row 4, column 67 |
| E7 | `send("Z")` then `send("q")` | row 4 shows `Sing-Box Path           : > Zq` — printable keys edit the focused field; the app does not quit |
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
| E2 | PARTIAL | step 5 `Line 2 …: │▾ Core                           2│ │                                                                                 │` (count confirmed); step 6 `Line 4 …: │    Protocol Core                 │` — the second tree row is on row 3, not row 4 (see *Corrections*) |
| E3 | PASS | step 7 `Line 39 …:  Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close` |
| E4 | PASS | step 11 `Line 2 …: │▾ Core                           2│ │Xray Path               : > (empty)                                              │`; step 12 `Line 6 …: │    Inbound                       │ │Log Level               : > < warning >                                          │`; step 13 `Line 8 …: │    TUN                           │ │Skip Cert Verify        : > [ ]                                                  │` |
| E5 | PASS | step 15 `Cursor position (session: settings-forms): row 39, column 120` |
| E6 | PASS | step 17 `Cursor position (session: settings-forms): row 4, column 67` |
| E7 | PASS | step 20 `Line 4 …: │    Protocol Core                 │ │Sing-Box Path           : > Zq                                                   │` |
| E8 | PASS | step 21 `✓ Assertion passed: Found 'Core Settings' in output` |
| E9 | PASS | step 23 `Line 1 …: ┌ Settings ────────────────────────┐ ┌ Select a section ───────────────────────────────────────────────────────────────┐`; step 24 `Line 39 …:  Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close` |
| E10 | FAIL | step 26 `Line 1 (session: settings-forms):` (empty) — `Esc` at the tree level does **not** return to the Profiles table (see *Corrections*) |

## Corrections to expectations

- **E2: the tree's second leaf is on row 3, not row 4.** Step 5 shows `│▾ Core 2│` on row 2 and step 6
  shows `│    Protocol Core │` on row 4, so `Core Settings` occupies row 3. The tree is
  `▾ Core` / `Core Settings` / `Protocol Core` / `▾ Connection` / …, one node per row, no blank rows —
  the child-count claim (trailing `2` on the category row) is confirmed.
- **E10 is wrong about the app, and the doc's expectation is the wrong part.** `Esc` in the Settings
  tree sets the app mode back to `List` but leaves the tab on `Settings` (`ui/settings.rs:385-388`),
  and the Settings tab has no List-mode body: step 26 returns an empty row 1 and the tab bar, the
  actions panel and the status bar are the only content left. An ad-hoc capture taken while preparing
  this document shows the full state — the whole content area blank between the tab bar and the panel,
  status bar ` Disconnected                                                                                           [q/Ctrl+C] Quit`
  — flagged as an ad-hoc observation because it is not in this scenario's transcript (probe12, collected in
  the [ad-hoc evidence](2026-10-14-132534-review-evidence-adhoc.md)). The state is a
  dead end: the only keys that lead anywhere are `Tab`/`Shift+Tab` and `q`.

## Visual polish remarks

| # | Where | What | Severity | Recommendation |
|---|---|---|---|---|
| P1 | tree rows 2–21 | 20 nodes in 5 groups, each category row carrying an unlabelled trailing integer (`│▾ Core                           2│`) that is the *child count* but reads as an ordinal; the group order is Core, Connection, Routing, GUI, Advanced (the manual's flat 1–14 numbering does not match the UI at all) | minor | label the count (`2 items`) or drop it, and reorder groups by frequency of use (the manual's order) |
| P2 | row 39 after `Tab` | the Settings tree's hint row does not mention that `Tab` leaves the screen and cycles tabs: `[↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close`. Both the help overlay (`Tab / Shift+Tab  Cycle tabs`) and `docs/guides/tui-manual.md` say it; the hint row is the only surface that does not | minor | add `[Tab] Next tab` to the tree's hint row |
| P3 | right pane, entry state | entering Settings leaves an 81×28 pane titled `Select a section` completely empty, with the tree's first node (a *category*) selected, so `Enter` collapses `Core` instead of opening anything | minor | auto-select the first leaf (`Core Settings`) when the pane opens, or render a short index of sections in the empty pane |
| P4 | form, rows 2–10 | fields are separated by whole blank rows (`Xray Path` row 2, `Sing-Box Path` row 4, `Log Level` row 6 …), so five fields occupy nine rows and the pane is 60% empty below them | nit | halve the row pitch (or add the field's help text where the blank row is) |
| P5 | closing the form | `Esc` **discards** the edited field with no save/discard confirmation and no dirty marker; `Sing-Box Path : > Zq` returns to `Select a section` with nothing on screen to say the edit was dropped | minor | mark the form dirty, or confirm discard when a field changed |
| P6 | row 39 in the form | the form's hint row is complete (`[Tab/Shift+Tab] Focus  [Enter] Save  [Ctrl+W] Focus Tree  [Esc] Back`) but omits quit, while `q` in a focused text field **types `q`** into the config value (E7) and `q` in the tree does nothing (ad-hoc probe `probe14`: session alive, `Select a section` still on screen — [evidence](2026-10-14-132534-review-evidence-adhoc.md)) — the manual's Settings-Tab table says `q / Ctrl+C — Quit application` | major | fix the manual's Settings-Tab key table, and make `q` a no-op in editable fields (or require `Ctrl+Q`) so quit keeps one meaning |
| P7 | form entry | the cursor is parked at (39, 120) — the screen's bottom-right corner — until the first `Tab`, so nothing on screen indicates the edit target; the value controls also all wear the same `> ` prefix (`> (empty)`, `> < warning >`, `> [ ]`), which is decoration rather than focus | minor | focus the first field on open and draw the caret there, or use `>` for the focused field only |
| P8 | whole content area after the second `Esc` | `Esc` at the tree level closes the split but leaves the tab on Settings, whose List-mode body is empty: rows 1–30 render nothing and the only remaining chrome is the tab bar, the actions panel and ` Disconnected … [q/Ctrl+C] Quit` (step 26; the full state is in the ad-hoc capture quoted in *Corrections*) | major | return to the Profiles tab on `Esc`, or give the Settings tab a List-mode body (the manual describes a section menu) |

## Tooling friction

Same harness limits as `profiles-import-and-table` (pyte wide-char crash patched in the runner; buffer
reads are text-only; no liveness check). Additional ones:

- **Cursor state is the only focus witness, and only the buffer exposes it.** `get_cursor_position`
  is a single-cell read and was reliable here (`row 39, column 120` then `row 4, column 67`), but
  nothing in a text capture distinguishes a focused field from an unfocused one — the `> ` prefix is on
  every field. Any focus/contrast review of this screen needs a colour-capable witness (stream mode
  with ANSI) that this pass could not use.
- **A printable key sent to a text form edits the fixture's config.** `send("Z")`/`send("q")` here
  wrote into `Sing-Box Path`, so this scenario mutates its own fixture and depends on the
  copy-before-run reset even more than the others (noted in *Environment and fixtures*).
- **`Esc` semantics differ per level and are not discoverable from the screen** (form → tree, tree →
  blank Settings tab). The scenario's E10 was written on the assumption that the second `Esc` leaves
  the tab; a `Tab`-less way back to the profile list does not exist, which is itself the finding.

## Review of findings

The form itself is in good shape — labels, value controls, `Enter` to save, `Esc` to back out, a
breadcrumb and a complete hint row. The findings are about *what the screen omits*, and two of them
are contradictions between the UI/manual and the behaviour.

**1. `Esc` from the Settings tree leaves a blank screen (major).** Evidence: step 26 —
`Line 1 (session: settings-forms):` (empty). Why it matters: the tree's own hint says `[Esc] Close`, and
what it closes is the split view while staying on the Settings tab; the tab then renders nothing at
all, so the screen is a dead end whose only exit is `Tab` or `q`. Recommendation: `Esc` should return
to the Profiles tab (or the Settings tab in List mode should render a menu, as `docs/guides/tui-manual.md`
describes).

**2. `q` types into a config field instead of quitting (major).** Evidence: step 20 —
`│ Sing-Box Path           : > Zq │` after `send("Z")`, `send("q")` (steps 18–19), with the session alive
(step 21). The manual's Settings table lists `q / Ctrl+C — Quit application`. Why it matters: `q` is the
quit key everywhere else in this app, and every user has that muscle memory; in a settings form it
silently appends a character to a proxy configuration value, and `Esc` then discards it (P5) with no
marker that anything changed. Recommendation: make `q` a no-op in text fields (or require `Ctrl+Q`),
and fix the manual.

**3. `Tab` leaves the Settings screen and the hint row doesn't say so (minor).** Evidence: step 7 —
` Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form
[Esc] Close`; `ui/settings.rs:429` comments the handler as "Handle Tab/BackTab to exit Settings mode and
cycle tabs". The help overlay (`Tab / Shift+Tab  Cycle tabs`) and the manual's Settings-Tab table both
document it correctly — only the hint row, the surface the user is looking at, omits it. Why it
matters: `Tab` is a "next field" reflex for anyone who has used the form level one keystroke earlier,
and here it silently switches tabs. Recommendation: add `[Tab] Next tab` to the tree's hint row (the
wording already exists in the help overlay).

**4. The right pane opens empty and `Enter` on a category collapses it (minor).** Evidence: step 4/23 —
`┌ Select a section ─…┐` with 28 blank rows; the first `Enter` (steps 8–9, ad-hoc witness) toggles
`Core`'s disclosure triangle instead of opening a section. Why it matters: a 60-cell-wide pane that
says nothing is the first thing a user sees in Settings, and the natural first keystroke does nothing
useful. Recommendation: select the first leaf on entry (and render a short section index in the pane).

**5. Field pitch and the unlabelled child count (minor/nit).** Evidence: rows 2/4/6/8/10 (step 11–13)
and `│▾ Core                           2│` (step 5). Why it matters: half the pane is empty while the
information density is one field per two rows, and `Core   2` is ambiguous. Recommendation: tighter
rows, labelled counts.

**6. Documentation drift on this screen (docs).** Two claims in `docs/guides/tui-manual.md` no longer
match the app, both witnessed here:

- The manual describes Settings as "a settings panel with a menu of 14 sections" in a fixed order with
  a separator after the first five. The app renders a two-level tree of 20 nodes in five collapsible
  groups (Core, Connection, Routing, GUI, Advanced) with no separator line — `│▾ Core 2│`,
  `│    Core Settings │`, `│    Protocol Core │` (steps 5–6).
- The manual's Settings-Tab key table lists `q / Ctrl+C — Quit application`. On this screen `Ctrl+C`
  quits and `q` does not: in a form it is typed into the focused field (step 20) and in the tree it is
  ignored (ad-hoc probe `probe14`: the session is alive and `Select a section` is still on screen after
  `q`).

### Verified good

- Labels and value controls are unambiguous and consistent: `Xray Path  : > (empty)`,
  `Log Level  : > < warning >`, `Skip Cert Verify  : > [ ]` (steps 11–13) — text / select / boolean
  each have a distinct shape.
- Focus is reachable and the caret lands *inside* the focused field: `row 4, column 67` after one
  `Tab` (step 17), and the edit lands on the same field (`> Zq`, step 20). The tree↔form focus switch
  (`Ctrl+W`) and the breadcrumb (` Settings > Core `, step 14) communicate where you are.
- Opening a section is a real two-pane layout at 120 columns with a title, not a modal that hides the
  tree — steps 11–14.
- `Esc` from the form is a clean, single-level back-out: the tree returns with
  `┌ Select a section ─…┐` and the hint row reverts (steps 23–24).
- The app keeps running through `q` and every read stays consistent (step 21), so the scenario's own
  liveness assumption held.

### Reproduce

```bash
cd /home/user/oss/xray-tui
R=/home/user/.cache/leas-tui/settings-forms
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-132534-scenario-settings-forms.md settings-forms
```
