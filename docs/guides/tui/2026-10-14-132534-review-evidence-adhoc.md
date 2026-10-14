# Ad-hoc probe evidence — 2026-10-14 walkthrough

Four probe runs taken while preparing the five scenario documents, quoted by the review and by
`settings-forms` / `narrow-80x24`. They are **not** scenario transcripts: a probe is a bare step block
(`run_scenario(ad_hoc=…)`) written to answer one question, with no header and no pre-registered
expectation table, so it is weaker evidence than a transcript — used here only for statements the
scenarios do not cover.

All four ran on 2026-10-14 from the same checkout as the scenarios (leas 0.1.0 debug `13e132f2…`,
mcp-tui-test 0.3.0, Python 3.14.7, pyte 0.8.2, runner `~/.cache/leas-tui/run.py`). Reports are verbatim.

| Probe | Question | Cited by |
|---|---|---|
| `probe8` | what the 80x24 layout looks like, and the Statistics empty-state wording | review D3, `narrow-80x24` *Corrections* (E4/E5) |
| `probe12` | what `Esc` at the Settings tree leaves on screen | `settings-forms` *Corrections* (E10) / P8 |
| `probe13` | the full layout at 80x19, 80x18 and 80x14 | `narrow-80x24` *Corrections* (E8/E10), `tiny-80x14` scope |
| `probe14` | whether `q` quits from the Settings tree | `settings-forms` P6, review D2 |

## probe8 — 80x24 across tabs (80x24, seeded fixture)

```text
1:1: warning: W_NO_CLOSE: the script never calls close()
    launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/narrow-80x24/config /home/user/oss/xray-tui/target/debug/leas", mode="buffer", dimensions="80x24", timeout=40)
    ^
    hint: run_scenario() closes a session it launched, but keeps an attached session alive

Scenario executed — session 'probe8' (launched)
============================================================
[ 1] launch(launch_tui) — ok (581 ms)
✓ Launched TUI application (session: probe8)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/narrow-80x24/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 80x24
Mode: buffer

[ 2] expect(expect_text) — ok (305 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] capture(capture_screen) — ok (301 ms)
Screen output (session: probe8, mode: buffer):
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
│        7 [🏴   us-nyc-04.synthetic-node.example ][🏁  ]=>{      ss/tcp/none █│
│                                                                             █│
│                                                                             █│
└──────────────────────────────────────────────────────────────────────────────┘
 Server: 203.0.113.77:443  [xray]  rows 1-7 of 7                                
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////
○ Disconnected                                                                  
🖥 vless 203.0.113.77:443 [xray]                                                 
⏱ TCP:       -  RP:       -  SPD:        -                                      
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -                                           
📋 Core: [info] Whitelist loaded                                                
                                                                                
////////////////////////////////////////////////////////////////////////////////
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[ 4] key(send_special_keys) — ok (652 ms)
✓ Sent 1 special key(s) to session probe8

[ 5] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session probe8

[ 6] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session probe8

[ 7] capture(capture_screen) — ok (301 ms)
Screen output (session: probe8, mode: buffer):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions   
 Statistics  ///////////////////////////////////////////////////////////////////
        Not connected — select a profile and press Ctrl+Enter to connect        
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
////////////////////////////////////////////////////////////////////////////////
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////
○ Disconnected                                                                  
🖥 vless 203.0.113.77:443 [xray]                                                 
⏱ TCP:       -  RP:       -  SPD:        -                                      
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -                                           
📋 Core: [info] Whitelist loaded                                                
                                                                                
////////////////////////////////////////////////////////////////////////////////
 Disconnected                                                   [q/Ctrl+C] Quit 
============================================================

[ 8] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session probe8

[ 9] capture(capture_screen) — ok (301 ms)
Screen output (session: probe8, mode: buffer):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions   
 Native Activity  //////////////////////////////////////////////////////////////
    No native session — connect with the native core to see live connections    
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
////////////////////////////////////////////////////////////////////////////////
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////
○ Disconnected                                                                  
🖥 vless 203.0.113.77:443 [xray]                                                 
⏱ TCP:       -  RP:       -  SPD:        -                                      
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -                                           
📋 Core: [info] Whitelist loaded                                                
                                                                                
////////////////////////////////////////////////////////////////////////////////
 Disconnected                       [F1] Actions Log  [?] Help  [q/Ctrl+C] Quit 
============================================================

------------------------------------------------------------
steps: 9 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
```

## probe12 — `Tab`, then `Esc` at the Settings tree (120x40, seeded fixture)

```text
1:1: warning: W_NO_CLOSE: the script never calls close()
    launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-forms/config /home/user/oss/xray-tui/target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
    ^
    hint: run_scenario() closes a session it launched, but keeps an attached session alive

Scenario executed — session 'probe12' (launched)
============================================================
[ 1] launch(launch_tui) — ok (582 ms)
✓ Launched TUI application (session: probe12)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-forms/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 120x40
Mode: buffer

[ 2] expect(expect_text) — ok (307 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] key(send_special_keys) — ok (653 ms)
✓ Sent 1 special key(s) to session probe12

[ 4] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Select a section'

[ 5] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session probe12

[ 6] capture(capture_screen) — ok (301 ms)
Screen output (session: probe12, mode: buffer):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions






























 ⚙ Actions Log  ////////////////////////////////////////////////////////////////////////////////////////////////////////
○ Disconnected
🖥 vless 203.0.113.77:443 [xray]
⏱ TCP:       -  RP:       -  SPD:        -
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -
📋 Core: [info] Whitelist loaded

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 Disconnected                                                                                           [q/Ctrl+C] Quit
============================================================

[ 7] line(get_line) — ok (301 ms)
Line 39 (session: probe12):  Disconnected                                                                                           [q/Ctrl+C] Quit

------------------------------------------------------------
steps: 7 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
```

## probe13 — 80x19, 80x18 and 80x14 (seeded fixture)

```text
Scenario executed — session 'probe13' (launched)
============================================================
[ 1] launch(launch_tui) — ok (588 ms)
✓ Launched TUI application (session: probe13)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/narrow-80x24/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 80x19
Mode: buffer

[ 2] expect(expect_text) — ok (305 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] capture(capture_screen) — ok (301 ms)
Screen output (session: probe13, mode: buffer):
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
│        7 [🏴   us-nyc-04.synthetic-node.example ][🏁  ]=>{      ss/tcp/none █│
│                                                                             █│
│                                                                             █│
│                                                                             █│
│                                                                             █│
└──────────────────────────────────────────────────────────────────────────────┘
 Server: 203.0.113.77:443  [xray]  rows 1-7 of 7                                
○ vless 203.0.113.77:443 [xray] | Whitelist loaded                              
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[ 4] close(close_session) — ok (100 ms)
✓ Closed session: probe13

[ 5] launch(launch_tui) — ok (594 ms)
✓ Launched TUI application (session: probe13)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/narrow-80x24/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 80x18
Mode: buffer

[ 6] expect(expect_text) — ok (302 ms)
✓ Found expected text: 'Address'

[ 7] capture(capture_screen) — ok (301 ms)
Screen output (session: probe13, mode: buffer):
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
│        7 [🏴   us-nyc-04.synthetic-node.example ][🏁  ]=>{      ss/tcp/none █│
│                                                                             █│
│                                                                             █│
│                                                                             █│
└──────────────────────────────────────────────────────────────────────────────┘
 Server: 203.0.113.77:443  [xray]  rows 1-7 of 7                                
○ vless 203.0.113.77:443 [xray] | Whitelist loaded                              
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[ 8] close(close_session) — ok (100 ms)
✓ Closed session: probe13

[ 9] launch(launch_tui) — ok (582 ms)
✓ Launched TUI application (session: probe13)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/narrow-80x24/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 80x14
Mode: buffer

[10] capture(capture_screen) — ok (302 ms)
Screen output (session: probe13, mode: buffer):
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
│        6 [🏴   jp-tyo-05.this-is-a-deliberately ][🏁  ]=>{     vless/tcp/non │
└──────────────────────────────────────────────────────────────────────────────┘
 Server: 203.0.113.77:443  [xray]  rows 1-7 of 7                                
○ vless 203.0.113.77:443 [xray] | Whitelist loaded                              
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[11] close(close_session) — ok (100 ms)
✓ Closed session: probe13

------------------------------------------------------------
steps: 11 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
```

## probe14 — `q` in the Settings tree (120x40, seeded fixture)

```text
Scenario executed — session 'probe14' (launched)
============================================================
[ 1] launch(launch_tui) — ok (581 ms)
✓ Launched TUI application (session: probe14)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-forms/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 120x40
Mode: buffer

[ 2] expect(expect_text) — ok (307 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] key(send_special_keys) — ok (654 ms)
✓ Sent 1 special key(s) to session probe14

[ 4] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Select a section'

[ 5] send(send_keys) — ok (651 ms)
✓ Sent keys to session probe14

[ 6] sessions(list_sessions) — ok (0 ms)
Active sessions:
  probe14 — buffer (PID 20723, 120x40, up 2s) — "(no capture)"

[ 7] assert_text(assert_contains) — ok (301 ms)
✓ Assertion passed: Found 'Select a section' in output

[ 8] line(get_line) — ok (301 ms)
Line 39 (session: probe14):  Settings Disconnected             [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Esc] Close

[ 9] close(close_session) — ok (100 ms)
✓ Closed session: probe14

------------------------------------------------------------
steps: 9 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
```
