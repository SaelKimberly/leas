# Transcript — profiles-menus-states

Verbatim report returned by `run_scenario(script=2026-10-14-132534-scenario-profiles-menus-states.md, session_id=profiles-menus-states)`
on 2026-10-14, executed in-process from the `/home/user/oss/mcp-tui-test` v0.3.0 checkout (Python 3.14.7, pyte 0.8.2).
The runner patches pyte's `Screen.display` before the call (see the scenario document's *Tooling friction*); nothing else is changed.

```text
Scenario document: profiles-menus-states — leas Profiles tab overlays and modal states — help, speed-test menu, export scope, delete confirmation, and the prefix-search filter including its filtered-empty state

Scenario executed — session 'profiles-menus-states' (launched)
============================================================
[ 1] launch(launch_tui) — ok (589 ms)
✓ Launched TUI application (session: profiles-menus-states)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/profiles-menus/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 120x40
Mode: buffer

[ 2] expect(expect_text) — ok (304 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] region(get_screen_region) — ok (301 ms)
Screen region (session: profiles-menus-states, rows 30-39, cols 0-119):
============================================================
 Server: 203.0.113.77:443  [xray]  rows 1-7 of 7
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////////////////////////////////////////////
○ Disconnected
🖥 vless 203.0.113.77:443 [xray]
⏱ TCP:       -  RP:       -  SPD:        -
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -
📋 Core: [info] startup: version=0.1.0 page=7 rows tcp-timeout=DurationOrSecs(5s) real-timeout=DurationOrSecs(5s) real-r

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 Disconnected        [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit
============================================================

[ 4] send(send_keys) — ok (653 ms)
✓ Sent keys to session profiles-menus-states

[ 5] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Keyboard Shortcuts'

[ 6] line(get_line) — ok (301 ms)
Line 8 (session: profiles-menus-states): │        5 [🏴   fi-hel-06.synthe│ Enter                 Set as active server / Activa│[name] [—               —      █│

[ 7] line(get_line) — ok (301 ms)
Line 9 (session: profiles-menus-states): │        6 [🏴   jp-tyo-05.this-i│ Ctrl+Enter            Connect to selected server   │[name] [—               —      █│

[ 8] line(get_line) — ok (301 ms)
Line 28 (session: profiles-menus-states): │                                ╰────────────────────────────────────────────────────╯                               █│

[ 9] key(send_special_keys) — ok (652 ms)
✓ Sent 1 special key(s) to session profiles-menus-states

[10] send(send_keys) — ok (651 ms)
✓ Sent keys to session profiles-menus-states

[11] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Server Tools'

[12] line(get_line) — ok (302 ms)
Line 7 (session: profiles-menus-states): │        4 [🏴   de-fra-02.synthetic-no│► Fast Ping (Selected)                  │   }=>[name] [—               —      █│

[13] line(get_line) — ok (301 ms)
Line 11 (session: profiles-menus-states): │                                      │ ─────                                  │                                     █│

[14] line(get_line) — ok (302 ms)
Line 21 (session: profiles-menus-states): │                                      │  Stop Testing                          │                                     █│

[15] key(send_special_keys) — ok (652 ms)
✓ Sent 1 special key(s) to session profiles-menus-states

[16] ctrl(send_ctrl) — ok (652 ms)
✓ Sent Ctrl+E to session profiles-menus-states

[17] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Export Scope'

[18] line(get_line) — ok (301 ms)
Line 0 (session: profiles-menus-states):

[19] line(get_line) — ok (301 ms)
Line 14 (session: profiles-menus-states): │                                │  Only Resolved                                     │                               █│

[20] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session profiles-menus-states

[21] send(send_keys) — ok (651 ms)
✓ Sent keys to session profiles-menus-states

[22] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Confirm'

[23] line(get_line) — ok (301 ms)
Line 14 (session: profiles-menus-states): │                                        ╭ Confirm ───────────────────────────╮                                       █│

[24] line(get_line) — ok (301 ms)
Line 39 (session: profiles-menus-states):  Disconnected        [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit

[25] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session profiles-menus-states

[26] send(send_keys) — ok (653 ms)
✓ Sent keys to session profiles-menus-states

[27] stable(wait_for_stable) — ok (1506 ms)
Screen stabilized (session: profiles-menus-states):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions
 View: Active [P]  / ams▉
                                           No profiles — press 'a' to add one



























 Server: (none selected)
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////////////////////////////////////////////
○ Disconnected
🖥 - []
⏱ TCP:       -  RP:       -  SPD:        -
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -
📋 Core: [info] Whitelist loaded

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 Disconnected        [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit
============================================================

[28] line(get_line) — ok (301 ms)
Line 1 (session: profiles-menus-states):  View: Active [P]  / ams▉

[29] line(get_line) — ok (301 ms)
Line 2 (session: profiles-menus-states):                                            No profiles — press 'a' to add one

[30] key(send_special_keys) — ok (653 ms)
✓ Sent 1 special key(s) to session profiles-menus-states

[31] send(send_keys) — ok (651 ms)
✓ Sent keys to session profiles-menus-states

[32] stable(wait_for_stable) — ok (1506 ms)
Screen stabilized (session: profiles-menus-states):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions
 View: Active [P]  / nl▉
┌ Profiles ────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│   #           Address                             Feat    Protocol Info              Test ↑  Outbound        Country█│
│▶       1 [🏴   nl-ams-01.synthetic-node.example ][🏁  ]=>{   vless/tcp/reality    }=>[name] [—               —      █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
│                                                                                                                     █│
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 Server: nl-ams-01.synthetic-node.example:443  [xray]  rows 1-1 of 1
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////////////////////////////////////////////
○ Disconnected
🖥 vless nl-ams-01.synthetic-node.example:443 [xray]
⏱ TCP:       -  RP:       -  SPD:        -
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -
📋 Core: [info] Whitelist loaded

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 Disconnected        [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit
============================================================

[33] line(get_line) — ok (301 ms)
Line 4 (session: profiles-menus-states): │▶       1 [🏴   nl-ams-01.synthetic-node.example ][🏁  ]=>{   vless/tcp/reality    }=>[name] [—               —      █│

[34] line(get_line) — ok (301 ms)
Line 30 (session: profiles-menus-states):  Server: nl-ams-01.synthetic-node.example:443  [xray]  rows 1-1 of 1

[35] close(close_session) — ok (100 ms)
✓ Closed session: profiles-menus-states

------------------------------------------------------------
steps: 35 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
```
