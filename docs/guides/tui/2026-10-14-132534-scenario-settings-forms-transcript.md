# Transcript: settings-forms (2026-10-14)

Verbatim report of one `run_scenario` call on 2026-10-14. The expectations, the script and the findings
live in [the scenario document](2026-10-14-132534-scenario-settings-forms.md); this file holds only what
the harness returned.

## Purpose and scope

Records the harness report for session `settings-forms`, unchanged: every step, its status, its duration,
and every screen, line or cursor position it read. Use it to check a quote in the scenario document or
the review; it contains no analysis of its own.

## Environment and fixtures

| Field | Value |
|---|---|
| Produced by | `run_scenario(script=2026-10-14-132534-scenario-settings-forms.md, session_id=settings-forms)` |
| Date | 2026-10-14 |
| Harness | mcp-tui-test 0.3.0, executed in-process from the `/home/user/oss/mcp-tui-test` checkout, Python 3.14.7, pyte 0.8.2 |
| Session / mode / size | `settings-forms` / buffer / 120x40 |
| App under test | leas 0.1.0 debug build `13e132f2…`, `/home/user/oss/xray-tui/target/debug/leas` |
| Fixture | `fixtures/config.json` plus `fixtures/seeded/data.db`, copied to `/home/user/.cache/leas-tui/settings-forms` |

The runner patches pyte's `Screen.display` before the call; nothing else is changed. Harness limits and
that patch are documented once in [INDEX.md](INDEX.md).

## Expected behaviour (written before the run)

Ten expectations, E1–E10, in the scenario document's *Expected behaviour* table.

## Scenario script

The 27-step script is in [the scenario document](2026-10-14-132534-scenario-settings-forms.md).

## Observed behaviour

```text
Scenario document: settings-forms — leas Settings tab — the 20-node section tree, opening a section into the right pane, field focus and the cursor, and what q does inside a settings form

Scenario executed — session 'settings-forms' (launched)
============================================================
[ 1] launch(launch_tui) — ok (582 ms)
✓ Launched TUI application (session: settings-forms)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-forms/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 120x40
Mode: buffer

[ 2] expect(expect_text) — ok (306 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] key(send_special_keys) — ok (654 ms)
✓ Sent 1 special key(s) to session settings-forms

[ 4] expect(expect_text) — ok (303 ms)
✓ Found expected text: 'Select a section'

[ 5] line(get_line) — ok (302 ms)
Line 2 (session: settings-forms): │▾ Core                           2│ │                                                                                 │

[ 6] line(get_line) — ok (302 ms)
Line 4 (session: settings-forms): │    Protocol Core                 │ │                                                                                 │

[ 7] line(get_line) — ok (301 ms)
Line 39 (session: settings-forms):  Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close

[ 8] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session settings-forms

[ 9] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session settings-forms

[10] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Core Settings'

[11] line(get_line) — ok (302 ms)
Line 2 (session: settings-forms): │▾ Core                           2│ │Xray Path               : > (empty)                                              │

[12] line(get_line) — ok (302 ms)
Line 6 (session: settings-forms): │    Inbound                       │ │Log Level               : > < warning >                                          │

[13] line(get_line) — ok (302 ms)
Line 8 (session: settings-forms): │    TUN                           │ │Skip Cert Verify        : > [ ]                                                  │

[14] line(get_line) — ok (302 ms)
Line 39 (session: settings-forms):  Settings > Core Disconnected                      [Tab/Shift+Tab] Focus  [Enter] Save  [Ctrl+W] Focus Tree  [Esc] Back

[15] cursor(get_cursor_position) — ok (302 ms)
Cursor position (session: settings-forms): row 39, column 120

[16] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session settings-forms

[17] cursor(get_cursor_position) — ok (302 ms)
Cursor position (session: settings-forms): row 4, column 67

[18] send(send_keys) — ok (652 ms)
✓ Sent keys to session settings-forms

[19] send(send_keys) — ok (651 ms)
✓ Sent keys to session settings-forms

[20] line(get_line) — ok (301 ms)
Line 4 (session: settings-forms): │    Protocol Core                 │ │Sing-Box Path           : > Zq                                                   │

[21] assert_text(assert_contains) — ok (302 ms)
✓ Assertion passed: Found 'Core Settings' in output

[22] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session settings-forms

[23] line(get_line) — ok (302 ms)
Line 1 (session: settings-forms): ┌ Settings ────────────────────────┐ ┌ Select a section ───────────────────────────────────────────────────────────────┐

[24] line(get_line) — ok (302 ms)
Line 39 (session: settings-forms):  Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close

[25] key(send_special_keys) — ok (652 ms)
✓ Sent 1 special key(s) to session settings-forms

[26] line(get_line) — ok (301 ms)
Line 1 (session: settings-forms):

[27] close(close_session) — ok (101 ms)
✓ Closed session: settings-forms

------------------------------------------------------------
steps: 27 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
```

## Corrections to expectations

None: a transcript reports what happened. The two wrong predictions (E2's row index, E10's
return-to-Profiles assumption) are corrected in
[the scenario document](2026-10-14-132534-scenario-settings-forms.md).

## Verdict

27 steps, 0 errored, session closed; `ok: True`, `rescue_files: []`.
