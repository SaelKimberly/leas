Scenario document: routing-rules-audit — The Settings Routing Rules pane at 120x40 and 80x24 — header controls, rule list columns, the add-rule form, and what narrow width clips

Scenario executed — session 'routing-rules-audit' (launched)
============================================================
[ 1] launch(launch_tui) — ok (1138 ms)
✓ Launched TUI application (session: routing-rules-audit)
Command: env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/routing-rules-audit target/debug/leas
Dimensions: 120x40
Mode: buffer

[ 2] expect(expect_text) — ok (301 ms)
✓ Found expected text: '1: \[Profiles\]'

[ 3] assert_text(assert_contains) — ok (301 ms)
✓ Assertion passed: Found '2: [Details]' in output

[ 4] send(send_keys) — ok (654 ms)
✓ Sent keys to session routing-rules-audit

[ 5] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Sections'

[ 6] send(send_keys) — ok (651 ms)
✓ Sent keys to session routing-rules-audit

[ 7] send(send_keys) — ok (652 ms)
✓ Sent keys to session routing-rules-audit

[ 8] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session routing-rules-audit

[ 9] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Routing Rules'

[10] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session routing-rules-audit

[11] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'dataset:'

[12] capture(capture_screen) — ok (301 ms)
Screen output (session: routing-rules-audit, mode: buffer):
============================================================
┌ 1: [Profiles]  Sniffer  Logs ────────────────────────────────────────────────────────────────────────────────────────┐
│ Vie┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐    │
│    │ ┌ Search ────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │Press / to filter settings                                                                              │ │    │
│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Sections · 2/2 ─────────────┐ ┌ Routing Rules ─────────────────────────────────────────────────────────┐ │    │
│    │ │  ▾ Routing                  │ │ dataset: loyalsoldier   country: ru   ruleset: default                 │ │    │
│    │ │›    Routing Rules           │ │ [D] dataset  [C] country  [M] mode   shipped table — switch to custom t│ │    │
│    │ │                             │ │     1  0  geosite:win-spy                 block                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     2  0  geosite:category-ads            block                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     3  0  geosite:google-play             proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     4  0  geosite:github                  proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     5  0  geosite:twitch-ads              proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     6  0  geosite:youtube                 proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│ Ser│ │                             │ │     7  0  geosite:telegram                proxy                        │ │    │
└────│ │                             │ │                                                                        │ │────┘
┌ 2: │ │                             │ │     8  0  geosite:private                 direct                       │ │────┐
│Serv│ │                             │ │                                                                        │ │    │
│  no│ │                             │ │     9  0  geosite:torrent                 direct                       │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │    10  0  geosite:category-ru             direct                       │ │    │
│    │ └─────────────────────────────┘ └────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Help ──────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │Keys     [/] filter this pane   [Tab] focus   [Esc] back                                                │ │    │
│    │ │Legend   · saved   * unsaved   › selected                                                               │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
└────│ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │────┘
  inf└───── [↑/↓] Nav  [a] Add  [e] Edit  [d] Delete  [D]ataset  [C]ountry  [M]ode  [Ctrl+W] Sections  [Esc] Back ┘r/.ca
 Settings > Routing Disconnected
============================================================

[13] region(get_screen_region) — ok (301 ms)
Screen region (session: routing-rules-audit, rows 5-12, cols 2-116):
============================================================
   │ ┌ Sections · 2/2 ─────────────┐ ┌ Routing Rules ─────────────────────────────────────────────────────────┐ │  
   │ │  ▾ Routing                  │ │ dataset: loyalsoldier   country: ru   ruleset: default                 │ │  
   │ │›    Routing Rules           │ │ [D] dataset  [C] country  [M] mode   shipped table — switch to custom t│ │  
   │ │                             │ │     1  0  geosite:win-spy                 block                        │ │  
   │ │                             │ │                                                                        │ │  
   │ │                             │ │     2  0  geosite:category-ads            block                        │ │  
   │ │                             │ │                                                                        │ │  
   │ │                             │ │     3  0  geosite:google-play             proxy                        │ │  
============================================================

[14] send(send_keys) — ok (751 ms)
✓ Sent keys to session routing-rules-audit

[15] capture(capture_screen) — ok (301 ms)
Screen output (session: routing-rules-audit, mode: buffer):
============================================================
┌ 1: [Profiles]  Sniffer  Logs ────────────────────────────────────────────────────────────────────────────────────────┐
│ Vie┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐    │
│    │ ┌ Search ────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │Press / to filter settings                                                                              │ │    │
│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Sections · 2/2 ─────────────┐ ┌ Routing Rules ─────────────────────────────────────────────────────────┐ │    │
│    │ │  ▾ Routing                  │ │ dataset: loyalsoldier   country: ru   ruleset: default                 │ │    │
│    │ │›    Routing Rules           │ │ [D] dataset  [C] country  [M] mode   shipped table — switch to custom t│ │    │
│    │ │                             │ │     1  0  geosite:win-spy                 block                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     2  0  geosite:category-ads            block                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     3  0  geosite:google-play             proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     4  0  geosite:github                  proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     5  0  geosite:twitch-ads              proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     6  0  geosite:youtube                 proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│ Ser│ │                             │ │     7  0  geosite:telegram                proxy                        │ │    │
└────│ │                             │ │                                                                        │ │────┘
┌ 2: │ │                             │ │     8  0  geosite:private                 direct                       │ │────┐
│Serv│ │                             │ │                                                                        │ │    │
│  no│ │                             │ │     9  0  geosite:torrent                 direct                       │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │    10  0  geosite:category-ru             direct                       │ │    │
│    │ └─────────────────────────────┘ └────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Help ──────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │Keys     [/] filter this pane   [Tab] focus   [Esc] back                                                │ │    │
│    │ │Legend   · saved   * unsaved   › selected                                                               │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
│    │ │                                                                                                        │ │    │
└────│ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │────┘
  inf└───── [↑/↓] Nav  [a] Add  [e] Edit  [d] Delete  [D]ataset  [C]ountry  [M]ode  [Ctrl+W] Sections  [Esc] Back ┘
 Settings > Routing Disconnected
============================================================

[16] assert_text(assert_contains) — ok (301 ms)
✓ Assertion passed: Found 'geosite:win-spy' in output

[17] send(send_keys) — ok (751 ms)
✓ Sent keys to session routing-rules-audit

[18] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'custom'

[19] capture(capture_screen) — ok (301 ms)
Screen output (session: routing-rules-audit, mode: buffer):
============================================================
┌ 1: [Profiles]  Sniffer  Logs ────────────────────────────────────────────────────────────────────────────────────────┐
│ Vie┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐    │
│    │ ┌ Search ────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │Press / to filter settings                                                                              │ │    │
│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Sections · 2/2 ─────────────┐ ┌ Routing Rules ─────────────────────────────────────────────────────────┐ │    │
│    │ │  ▾ Routing                  │ │ dataset: loyalsoldier   country: ru   ruleset: custom                  │ │    │
│    │ │›    Routing Rules           │ │ [D] dataset  [C] country  [M] mode   [a/e/d] rule  [Ctrl+↑↓] reorder   │ │    │
│    │ │                             │ │     1  0  geosite:win-spy                 block                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     2  0  geosite:category-ads            block                        │ │    │
│    │ │                             │ │                                                                        │ │    │
│    │ │                             │ │     3  0  geosite:google-play             proxy                        │ │    │
│    │ │                             │ │                                                                        │ │    │
[…581ln elided…]
      "elapsed_ms": 301,
      "output": "Screen output (session: routing-rules-audit, mode: buffer):\n============================================================\n┌ 1: [Profiles]  Sniffer  Logs ────────────────────────────────────────────────────────────────────────────────────────┐\n│ Vie┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐    │\n│    │ ┌ Search ────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │\n│    │ │Press / to filter settings                                                                              │ │    │\n│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │\n│    │ ┌ Sections · 2/2 ─────────────┐ ┌ Routing Rules ─────────────────────────────────────────────────────────┐ │    │\n│    │ │  ▾ Routing                  │ │ dataset: loyalsoldier   country: ru   ruleset: custom                  │ │    │\n│    │ │›    Routing Rules           │ │ [D] dataset  [C] country  [M] mode   [a/e/d] rule  [Ctrl+↑↓] reorder   │ │    │\n│    │ │                             │ │     1  0  geosite:win-spy                 block                        │ │    │\n│    │ │                             │ │                                                                        │ │    │\n│    │ │                             │ │     2  0  geosite:category-ads            block                        │ │    │\n│    │ │                             │ │                                                                        │ │    │\n│    │ │                             │ │     3  0  geosite:google-play             proxy                        │ │    │\n│    │ │                             │ │                                                                        │ │    │\n│    │ │                             │ │     4  0  geosite:github                  proxy                        │ │    │\n│    │ │                             │ │                                                                        │ │    │\n│    │ │                             │ │     5  0  geosite:twitch-ads              proxy                        │ │    │\n│    │ │                             │ │                                                                        │ │    │\n│    │ │                             │ │     6  0  geosite:youtube                 proxy                        │ │    │\n│    │ │                             │ │                                                                        │ │    │\n│ Ser│ │                             │ │     7  0  geosite:telegram                proxy                        │ │    │\n└────│ │                             │ │                                                                        │ │────┘\n┌ 2: │ │                             │ │     8  0  geosite:private                 direct                       │ │────┐\n│Serv│ │                             │ │                                                                        │ │    │\n│  no│ │                             │ │     9  0  geosite:torrent                 direct                       │ │    │\n│    │ │                             │ │                                                                        │ │    │\n│    │ │                             │ │    10  0  geosite:category-ru             direct                       │ │    │\n│    │ └─────────────────────────────┘ └────────────────────────────────────────────────────────────────────────┘ │    │\n│    │ ┌ Help ──────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │\n│    │ │Keys     [/] filter this pane   [Tab] focus   [Esc] back                                                │ │    │\n│    │ │Legend   · saved   * unsaved   › selected                                                               │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n└────│ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │────┘\n  inf└───── [↑/↓] Nav  [a] Add  [e] Edit  [d] Delete  [D]ataset  [C]ountry  [M]ode  [Ctrl+W] Sections  [Esc] Back ┘\n Settings > Routing Disconnected\n============================================================"
    },
    {
      "n": 20,
      "step": "send",
      "tool": "send_keys",
      "status": "ok",
      "elapsed_ms": 752,
      "output": "✓ Sent keys to session routing-rules-audit"
    },
    {
      "n": 21,
      "step": "expect",
      "tool": "expect_text",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "✓ Found expected text: 'Domain Matcher'"
    },
    {
      "n": 22,
      "step": "capture",
      "tool": "capture_screen",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "Screen output (session: routing-rules-audit, mode: buffer):\n============================================================\n┌ 1: [Profiles]  Sniffer  Logs ────────────────────────────────────────────────────────────────────────────────────────┐\n│ Vie┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐    │\n│    │ ┌ Search ────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │\n│    │ │Press / to filter settings                                                                              │ │    │\n│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │\n│    │ ┌ Sections · 2/2 ─────────────┐ ┌ Routing Rule ──────────────────────────────────────────────────────────┐ │    │\n│    │ │  ▾ Routing                  │ │Type                                                                    │ │    │\n│    │ │›    Routing Rules           │ │> (empty)                                                               │ │    │\n│    │ │                             │ │Domain Matcher                                                          │ │    │\n│    │ │                             │ │> (empty)                                                               │ │    │\n│    │ │                             │ │Domains (comma-sep)                                                     │ │    │\n│    │ │                             │ │> (empty)                                                               │ │    │\n│    │ │                             │ │IPs (comma-sep)                                                         │ │    │\n│    │ │                             │ │> (empty)                                                               │ │    │\n│    │ │                             │ │Inbound Tags (comma-sep)                                                │ │    │\n│    │ │                             │ │> (empty)                                                               │ │    │\n│    │ │                             │ │Ports (comma-sep)                                                       │ │    │\n│    │ │                             │ │> (empty)                                                               │ │    │\n│    │ │                             │ │Source Ports (comma-sep)                                                │ │    │\n│    │ │                             │ │> (empty)                                                               │ │    │\n│ Ser│ │                             │ │Network                                                                 │ │    │\n└────│ │                             │ │> (empty)                                                               │ │────┘\n┌ 2: │ │                             │ │Protocols (comma-sep)                                                   │ │────┐\n│Serv│ │                             │ │> (empty)                                                               │ │    │\n│  no│ │                             │ │Domain Strategy                                                         │ │    │\n│    │ │                             │ │> (empty)                                                               │ │    │\n│    │ │                             │ │Outbound Tag                                                            │ │    │\n│    │ └─────────────────────────────┘ └────────────────────────────────────────────────────────────────────────┘ │    │\n│    │ ┌ Help ──────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │\n│    │ │Keys     [/] filter this pane   [Tab] focus   [Esc] back                                                │ │    │\n│    │ │Legend   · saved   * unsaved   › selected                                                               │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n│    │ │                                                                                                        │ │    │\n└────│ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │────┘\n  inf└─────────────────────────────────────────────────────────────── [Enter] Save  [Ctrl+W] Sections  [Esc] Back ┘\n Settings > Routing Disconnected\n============================================================"
    },
    {
      "n": 23,
      "step": "key",
      "tool": "send_special_keys",
      "status": "ok",
      "elapsed_ms": 652,
      "output": "✓ Sent 1 special key(s) to session routing-rules-audit"
    },
    {
      "n": 24,
      "step": "expect",
      "tool": "expect_text",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "✓ Found expected text: 'dataset:'"
    },
    {
      "n": 25,
      "step": "resize",
      "tool": "resize",
      "status": "ok",
      "elapsed_ms": 1103,
      "output": "✓ Resized session routing-rules-audit to 80x24"
    },
    {
      "n": 26,
      "step": "expect",
      "tool": "expect_text",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "✓ Found expected text: 'dataset:'"
    },
    {
      "n": 27,
      "step": "capture",
      "tool": "capture_screen",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "Screen output (session: routing-rules-audit, mode: buffer):\n============================================================\n┌ 1: [Profiles]  Sniffer  Logs ────────────────────────────────────────────────┐\n│ ┌ Settings ────────────────────────────────────────────────────────────────┐ │\n│ │ ┌ Search ──────────────────────────────────────────────────────────────┐ │ │\n│ │ │Press / to filter settings                                            │ │ │\n│ │ └──────────────────────────────────────────────────────────────────────┘ │ │\n└─│ ┌ Sections · 2/2 ───────┐ ┌ Routing Rules ─────────────────────────────┐ │─┘\n┌ │ │  ▾ Routing            │ │ dataset: loyalsoldier   country: ru   rules│ │─┐\n│S│ │›    Routing Rules     │ │ [D] dataset  [C] country  [M] mode   [a/e/d│ │ │\n│ │ │                       │ │     1  0  geosite:win-spy                 block\n│L│ │                       │ │                                            │ │ │\n│ │ │                       │ │     2  0  geosite:category-ads            block\n│ │ └───────────────────────┘ └────────────────────────────────────────────┘ │ │\n│D│ ┌ Help ────────────────────────────────────────────────────────────────┐ │ │\n│p│ │Keys     [/] filter this pane   [Tab] focus   [Esc] back              │ │ │\n│u│ │Legend   · saved   * unsaved   › selected                             │ │ │\n│f│ │                                                                      │ │ │\n│o│ │                                                                      │ │ │\n│ │ │                                                                      │ │ │\n│a│ │                                                                      │ │ │\n│a│ │                                                                      │ │ │\n│r│ │                                                                      │ │ │\n└─│ └──────────────────────────────────────────────────────────────────────┘ │─┘\n  └─────────────… [←] Collapse [→] Fields [/] Filter [Enter] Open [Esc] Close┘\n Settings > Routing Disconnected\n============================================================"
    },
    {
      "n": 28,
      "step": "line",
      "tool": "get_line",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "Line 5 (session: routing-rules-audit): └─│ ┌ Sections · 2/2 ───────┐ ┌ Routing Rules ─────────────────────────────┐ │─┘"
    },
    {
      "n": 29,
      "step": "line",
      "tool": "get_line",
      "status": "ok",
      "elapsed_ms": 300,
      "output": "Line 6 (session: routing-rules-audit): ┌ │ │  ▾ Routing            │ │ dataset: loyalsoldier   country: ru   rules│ │─┐"
    },
    {
      "n": 30,
      "step": "key",
      "tool": "send_special_keys",
      "status": "ok",
      "elapsed_ms": 652,
      "output": "✓ Sent 1 special key(s) to session routing-rules-audit"
    },
    {
      "n": 31,
      "step": "expect",
      "tool": "expect_text",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "✓ Found expected text: '1: \\[Profiles\\]'"
    },
    {
      "n": 32,
      "step": "close",
      "tool": "close_session",
      "status": "ok",
      "elapsed_ms": 100,
      "output": "✓ Closed session: routing-rules-audit"
    }
  ],
  "session_alive": false,
  "rescue_files": [],
  "choice": null
}
```

[Showing lines 1-172 and 754-866 of 866; 581 middle lines (39.9KB) elided. Read artifact://24 for full output]
---

## Appendix: run 1 (failed first attempt, verbatim step 15)

The first script expected `a` to open the routing form while the pane was in
`ruleset: default` (read-only). Step 15 is the evidence the key is a silent
no-op there; steps 1–14 match the saved run above.

```
[15] expect(expect_text) — error (5517 ms)
ToolError: Pattern 'Domain Matcher' not found after 5s.
Current screen (40 lines):
┌ 1: [Profiles]  Sniffer  Logs ───... (unchanged routing list,
    header "dataset: loyalsoldier   country: ru   ruleset: default",
    rows 1..10 geosite:* with block/proxy/direct, no form)
------------------------------------------------------------
steps: 15 · errored: 1 · session closed
```
