# Transcript — live-resize

Verbatim report returned by `run_scenario(script=2026-10-14-144700-scenario-live-resize.md, session_id=live-resize)`
on 2026-10-14, executed in-process from the `/home/user/oss/mcp-tui-test` v1.0.1 checkout (Python 3.14.7, pyte 0.8.2, Pillow).
The runner no longer patches anything: 1.0.0 fixed the wide-char crash upstream and renders the cell grid itself.

```text
Scenario document: live-resize — leas driven through live resizes with the resize tool — 120x40 to 80x24 to 80x19 (the overlay branch a fresh small launch never reaches) back to 120x40, checking the layout and any residue

Scenario executed — session 'live-resize' (launched)
============================================================
[ 1] launch(launch_tui) — ok (582 ms)
✓ Launched TUI application (session: live-resize)
Command: env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/resize/config /home/user/oss/xray-tui/target/debug/leas
Dimensions: 120x40
Mode: buffer

[ 2] expect(expect_text) — ok (304 ms)
✓ Found expected text: 'rows 1-7 of 7'

[ 3] line(get_line) — ok (301 ms)
Line 3 (session: live-resize): │   #           Address                             Feat    Protocol Info              Test ↑  Outbound        Country█│

[ 4] resize(resize) — ok (602 ms)
✓ Resized session live-resize to 80x24

[ 5] stable(wait_for_stable) — ok (1503 ms)
Screen stabilized (session: live-resize):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions
 View: Active [P]   /  (press / to search)
┌ Profiles ────────────────────────────────────────────────────────────────────┐
│   #           Address                             Feat    Protocol Info     █│
│        1 [🏴    203.0.113.77:443                 ][    ]=>{   vless/tcp/reali█│
│▶       2 [🏴    nl-ams-01.synthetic-node.example ][🏁   ]=>{   vless/tcp/reali█│
│        3 [🏴    sg-sin-03.synthetic-node.example ][🏁   ]=>{     trojan/tcp/tl█│
│        4 [🏴    de-fra-02.synthetic-node.example ][🏁   ]=>{      vmess/ws/tls█│
│        5 [🏴    fi-hel-06.synthetic-node.example ][🏁   ]=>{     tuic/quic/tls█│
│        6 [🏴    jp-tyo-05.this-is-a-deliberately ][🏁   ]=>{     vless/tcp/non█│
│        7 [🏴    us-nyc-04.synthetic-node.example ][🏁   ]=>{      ss/tcp/none █│
│                                                                             █│
│                                                                             █│
└──────────────────────────────────────────────────────────────────────────────┘
 Server: 203.0.113.77:443  [xray]  rows 1-7 of 7
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////
○ Disconnected
🖥 vless 203.0.113.77:443 [xray]
⏱ TCP:       -  RP:       -  SPD:        -
📊  ⬆    0.0 B  ⬇    0.0 B  💾        -
📋  Core: [info] startup: version=0.1.0 page=7 rows tcp-timeout=DurationOrSecs(5s

////////////////////////////////////////////////////////////////////////////////
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next
============================================================

[ 6] line(get_line) — ok (301 ms)
Line 3 (session: live-resize): │   #           Address                             Feat    Protocol Info     █│

[ 7] line(get_line) — ok (301 ms)
Line 14 (session: live-resize):  Server: 203.0.113.77:443  [xray]  rows 1-7 of 7

[ 8] line(get_line) — ok (301 ms)
Line 23 (session: live-resize):  Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next

[ 9] resize(resize) — ok (601 ms)
✓ Resized session live-resize to 80x19

[10] stable(wait_for_stable) — ok (1503 ms)
Screen stabilized (session: live-resize):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////
○ Disconnected
🖥 vless 203.0.113.77:443 [xray]
⏱ TCP:       -  RP:       -  SPD:        -
📊  ⬆    0.0 B  ⬇    0.0 B  💾        -
📋  Core: [info] Whitelist loaded










////////////////////////////////////////////////////////////////////////////////
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next
============================================================

[11] line(get_line) — ok (300 ms)
Line 1 (session: live-resize):  ⚙ Actions Log  ////////////////////////////////////////////////////////////////

[12] capture(capture_screen) — ok (301 ms)
Screen output (session: live-resize, mode: buffer):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions   
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////
○ Disconnected                                                                  
🖥 vless 203.0.113.77:443 [xray]                                                 
⏱ TCP:       -  RP:       -  SPD:        -                                      
📊  ⬆    0.0 B  ⬇    0.0 B  💾        -                                           
📋  Core: [info] Whitelist loaded                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
////////////////////////////////////////////////////////////////////////////////
 Disconnected [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next 
============================================================

[13] resize(resize) — ok (603 ms)
✓ Resized session live-resize to 120x40

[14] stable(wait_for_stable) — ok (1503 ms)
Screen stabilized (session: live-resize):
============================================================
 ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions
 View: Active [P]   /  (press / to search)
┌ Profiles ────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│   #           Address                             Feat    Protocol Info              Test ↑  Outbound        Country█│
│        1 [🏴    203.0.113.77:443                 ][    ]=>{   vless/tcp/reality    }=>       [—               —      █│
│▶       2 [🏴    nl-ams-01.synthetic-node.example ][🏁   ]=>{   vless/tcp/reality    }=>[name] [—               —      █│
│        3 [🏴    sg-sin-03.synthetic-node.example ][🏁   ]=>{     trojan/tcp/tls     }=>[name] [—               —      █│
│        4 [🏴    de-fra-02.synthetic-node.example ][🏁   ]=>{      vmess/ws/tls      }=>[name] [—               —      █│
│        5 [🏴    fi-hel-06.synthetic-node.example ][🏁   ]=>{     tuic/quic/tls      }=>[name] [—               —      █│
│        6 [🏴    jp-tyo-05.this-is-a-deliberately ][🏁   ]=>{     vless/tcp/none     }=>[name] [—               —      █│
│        7 [🏴    us-nyc-04.synthetic-node.example ][🏁   ]=>{      ss/tcp/none       }=>[name] [—               —      █│
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
 Server: 203.0.113.77:443  [xray]  rows 1-7 of 7
 ⚙ Actions Log  ////////////////////////////////////////////////////////////////////////////////////////////////////////
○ Disconnected
🖥 vless 203.0.113.77:443 [xray]
⏱ TCP:       -  RP:       -  SPD:        -
📊  ⬆    0.0 B  ⬇    0.0 B  💾        -
📋  Core: [info] Whitelist loaded

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 Disconnected        [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit
============================================================

[15] line(get_line) — ok (301 ms)
Line 3 (session: live-resize): │   #           Address                             Feat    Protocol Info              Test ↑  Outbound        Country█│

[16] line(get_line) — ok (301 ms)
Line 30 (session: live-resize):  Server: 203.0.113.77:443  [xray]  rows 1-7 of 7

[17] line(get_line) — ok (301 ms)
Line 39 (session: live-resize):  Disconnected        [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit

[18] shot(screenshot) — ok (444 ms)
✓ Screenshot saved: /home/user/oss/xray-tui/docs/guides/tui/artifacts/resize-back-120x40.png
120x40 cells, font 14pt, 1722 cells carry colour

[19] close(close_session) — ok (100 ms)
✓ Closed session: live-resize

------------------------------------------------------------
steps: 19 · errored: 0 · session closed

=== structured ===
ok: True | action: executed | session_alive: False
rescue_files: []
```
