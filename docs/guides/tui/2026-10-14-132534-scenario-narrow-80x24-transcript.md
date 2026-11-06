# Transcript: narrow-80x24 (2026-10-14)

Verbatim report of one `run_scenario` call on 2026-10-14. The expectations, the script and the
findings live in [the scenario document](2026-10-14-132534-scenario-narrow-80x24.md); this file holds
only what the harness returned.

## Purpose and scope

Records the harness report for session `narrow-80x24`, unchanged: every step, its status, its
duration, and every screen or line it read. Use it to check a quote in the scenario document or the
review; it contains no analysis of its own.

## Environment and fixtures

| Field | Value |
|---|---|
| Produced by | `run_scenario(script=2026-10-14-132534-scenario-narrow-80x24.md, session_id=narrow-80x24)` |
| Date | 2026-10-14 |
| Harness | mcp-tui-test 0.3.0, executed in-process from the `/home/user/oss/mcp-tui-test` checkout, Python 3.14.7, pyte 0.8.2 |
| Session / mode / size | `narrow-80x24` / buffer / 80x24, then 80x19 after a relaunch |
| App under test | leas 0.1.0 debug build `13e132f2…`, `/home/user/oss/xray-tui/target/debug/leas` |
| Fixture | `fixtures/config.json` plus `fixtures/seeded/data.db`, copied to `/home/user/.cache/leas-tui/narrow-80x24` |

The runner patches pyte's `Screen.display` before the call; nothing else is changed. Harness limits and
that patch are documented once in [INDEX.md](INDEX.md).

## Expected behaviour (written before the run)

Ten expectations, E1–E10, in the scenario document's *Expected behaviour* table.

## Scenario script

The 20-step script is in [the scenario document](2026-10-14-132534-scenario-narrow-80x24.md).

## Observed behaviour

```text
Scenario document: narrow-80x24 — leas at 80x24 (table columns, status-bar hints) and at 80x19, where the <20-row layout swaps the content area for the Actions Log panel

Scenario executed — session 'narrow-80x24' (launched)
============================================================
[ 1] launch(launch_tui) — ok (584 ms)
✓ Launched TUI application (session: narrow-80x24)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/narrow-80x24/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 80x24
Mode: buffer

[ 2] expect(expect_text) — ok (302 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] line(get_line) — ok (301 ms)
Line 0 (session: narrow-80x24):  ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions

[ 4] line(get_line) — ok (301 ms)
Line 3 (session: narrow-80x24): │   #           Address                             Feat    Protocol Info     █│

[ 5] line(get_line) — ok (301 ms)
Line 4 (session: narrow-80x24): │        1 [🏴   203.0.113.77:443                 ][    ]=>{   vless/tcp/reali█│

[ 6] line(get_line) — ok (301 ms)
Line 21 (session: narrow-80x24):

[ 7] region(get_screen_region) — ok (301 ms)
Screen region (session: narrow-80x24, rows 13-23, cols 0-79):
============================================================
└──────────────────────────────────────────────────────────────────────────────┘
 Server: 203.0.113.77:443  [xray]  rows 1-7 of 7
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////
○ Disconnected
🖥 vless 203.0.113.77:443 [xray]
⏱ TCP:       -  RP:       -  SPD:        -
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -
📋 Core: [info] startup: version=0.1.0 page=7 rows tcp-timeout=DurationOrSecs(5s

////////////////////////////////////////////////////////////////////////////////
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next
============================================================

[ 8] key(send_special_keys) — ok (652 ms)
✓ Sent 1 special key(s) to session narrow-80x24

[ 9] line(get_line) — ok (301 ms)
Line 1 (session: narrow-80x24): ┌ Settings ────────────┐ ┌ Select a section ───────────────────────────────────┐

[10] line(get_line) — ok (301 ms)
Line 2 (session: narrow-80x24): │▾ Core               2│ │                                                     │

[11] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session narrow-80x24

[12] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session narrow-80x24

[13] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session narrow-80x24

[14] line(get_line) — ok (301 ms)
Line 1 (session: narrow-80x24):  Native Activity  //////////////////////////////////////////////////////////////

[15] close(close_session) — ok (101 ms)
✓ Closed session: narrow-80x24

[16] launch(launch_tui) — ok (586 ms)
✓ Launched TUI application (session: narrow-80x24)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/narrow-80x24/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 80x19
Mode: buffer

[17] line(get_line) — ok (302 ms)
Line 0 (session: narrow-80x24):  ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions

[18] region(get_screen_region) — ok (301 ms)
Screen region (session: narrow-80x24, rows 0-9, cols 0-79):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions
 View: Active [P]   /  (press / to search)
┌ Profiles ────────────────────────────────────────────────────────────────────┐
│   #           Address                             Feat    Protocol Info     █│
│        1 [🏴   203.0.113.77:443                 ][    ]=>{   vless/tcp/reali█│
│▶       2 [🏴   nl-ams-01.synthetic-node.example ][🏁  ]=>{   vless/tcp/reali█│
│        3 [🏴   sg-sin-03.synthetic-node.example ][🏁  ]=>{     trojan/tcp/tl█│
│        4 [🏴   de-fra-02.synthetic-node.example ][🏁  ]=>{      vmess/ws/tls█│
│        5 [🏴   fi-hel-06.synthetic-node.example ][🏁  ]=>{     tuic/quic/tls█│
│        6 [🏴   jp-tyo-05.this-is-a-deliberately ][🏁  ]=>{     vless/tcp/non█│
============================================================

[19] line(get_line) — ok (301 ms)
Line 18 (session: narrow-80x24):  Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next

[20] choice(choice) — ok (602 ms)
matched: 'table still drawn at 19 rows'

CHOICE → matched: 'table still drawn at 19 rows'
  matched   'table still drawn at 19 rows' assert_text(assert_contains) 301 ms
  no match  'content area replaced by the Actions Log at 19 rows' assert_text(assert_contains) 301 ms

------------------------------------------------------------
steps: 20 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
choice: ok ['table still drawn at 19 rows']
```

## Corrections to expectations

None: a transcript reports what happened, and the two wrong predictions (E4/E5's row indices, E8/E10's
compact-versus-overlay call) are corrected in
[the scenario document](2026-10-14-132534-scenario-narrow-80x24.md).

## Verdict

20 steps, 0 errored, session closed; `ok: True`, `rescue_files: []`. The `choice` step matched
`'table still drawn at 19 rows'` and matched nothing for the overlay label.
