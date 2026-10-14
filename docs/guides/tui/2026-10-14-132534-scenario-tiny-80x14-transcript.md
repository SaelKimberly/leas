# Transcript — tiny-80x14

Verbatim report returned by `run_scenario(script=2026-10-14-132534-scenario-tiny-80x14.md, session_id=tiny-80x14)`
on 2026-10-14, executed in-process from the `/home/user/oss/mcp-tui-test` v0.3.0 checkout (Python 3.14.7, pyte 0.8.2).
The runner patches pyte's `Screen.display` before the call (see the scenario document's *Tooling friction*); nothing else is changed.

```text
Scenario document: tiny-80x14 — leas at 80x14 — the compact one-line actions bar the <20-row layout selects, a table viewport that clips one endpoint, and F1's overlay that replaces the content area

Scenario executed — session 'tiny-80x14' (launched)
============================================================
[ 1] launch(launch_tui) — ok (582 ms)
✓ Launched TUI application (session: tiny-80x14)
Command: env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/tiny-80x14/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 80x14
Mode: buffer

[ 2] expect(expect_text) — ok (305 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] capture(capture_screen) — ok (301 ms)
Screen output (session: tiny-80x14, mode: buffer):
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
○ vless 203.0.113.77:443 [xray] | startup: version=0.1.0 page=7 rows tcp-timeout
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[ 4] line(get_line) — ok (301 ms)
Line 12 (session: tiny-80x14): ○ vless 203.0.113.77:443 [xray] | startup: version=0.1.0 page=7 rows tcp-timeout

[ 5] line(get_line) — ok (301 ms)
Line 13 (session: tiny-80x14):  Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next

[ 6] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session tiny-80x14

[ 7] capture(capture_screen) — ok (301 ms)
Screen output (session: tiny-80x14, mode: buffer):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions   
 View: Active [P]   /  (press / to search)                                      
┌ Profiles ────────────────────────────────────────────────────────────────────┐
│   #           Address                             Feat    Protocol Info      │
│▶       2 [🏴   nl-ams-01.synthetic-node.example ][🏁  ]=>{   vless/tcp/reali█│
│        3 [🏴   sg-sin-03.synthetic-node.example ][🏁  ]=>{     trojan/tcp/tl█│
│        4 [🏴   de-fra-02.synthetic-node.example ][🏁  ]=>{      vmess/ws/tls█│
│        5 [🏴   fi-hel-06.synthetic-node.example ][🏁  ]=>{     tuic/quic/tls█│
│        6 [🏴   jp-tyo-05.this-is-a-deliberately ][🏁  ]=>{     vless/tcp/non█│
│        7 [🏴   us-nyc-04.synthetic-node.example ][🏁  ]=>{      ss/tcp/none █│
└──────────────────────────────────────────────────────────────────────────────┘
 Server: us-nyc-04.synthetic-node.example:8388  [xray]  rows 1-7 of 7           
○ ss us-nyc-04.synthetic-node.example:8388 [xray] | startup: version=0.1.0 page=
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[ 8] key(send_special_keys) — ok (652 ms)
✓ Sent 1 special key(s) to session tiny-80x14

[ 9] capture(capture_screen) — ok (301 ms)
Screen output (session: tiny-80x14, mode: buffer):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions   
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////
○ Disconnected                                                                  
🖥 ss us-nyc-04.synthetic-node.example:8388 [xray]                               
⏱ TCP:       -  RP:       -  SPD:        -                                      
📊 ⬆    0.0 B  ⬇    0.0 B  💾       -                                           
📋 Core: [info] startup: version=0.1.0 page=7 rows tcp-timeout=DurationOrSecs(5s
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
////////////////////////////////////////////////////////////////////////////////
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[10] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session tiny-80x14

[11] capture(capture_screen) — ok (301 ms)
Screen output (session: tiny-80x14, mode: buffer):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions   
 View: Active [P]   /  (press / to search)                                      
┌ Profiles ────────────────────────────────────────────────────────────────────┐
│   #           Address                             Feat    Protocol Info      │
│▶       2 [🏴   nl-ams-01.synthetic-node.example ][🏁  ]=>{   vless/tcp/reali█│
│        3 [🏴   sg-sin-03.synthetic-node.example ][🏁  ]=>{     trojan/tcp/tl█│
│        4 [🏴   de-fra-02.synthetic-node.example ][🏁  ]=>{      vmess/ws/tls█│
│        5 [🏴   fi-hel-06.synthetic-node.example ][🏁  ]=>{     tuic/quic/tls█│
│        6 [🏴   jp-tyo-05.this-is-a-deliberately ][🏁  ]=>{     vless/tcp/non█│
│        7 [🏴   us-nyc-04.synthetic-node.example ][🏁  ]=>{      ss/tcp/none █│
└──────────────────────────────────────────────────────────────────────────────┘
 Server: us-nyc-04.synthetic-node.example:8388  [xray]  rows 1-7 of 7           
○ ss us-nyc-04.synthetic-node.example:8388 [xray] | Whitelist loaded            
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[12] close(close_session) — ok (100 ms)
✓ Closed session: tiny-80x14

------------------------------------------------------------
steps: 12 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
```
