Scenario document: routing-sources-verify — Post-implementation verification of the Routing Rules rework and the new Sources pane-1 tab (header controls, clamped rows, read-only notice, tab entry)

Scenario executed — session 'routing-sources-verify' (launched)
============================================================
[ 1] launch(launch_tui) — ok (1147 ms)
✓ Launched TUI application (session: routing-sources-verify)
Command: env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/routing-rules-audit target/debug/leas
Dimensions: 120x40
Mode: buffer

[ 2] expect(expect_text) — ok (301 ms)
✓ Found expected text: '1: \[Profiles\]'

[ 3] send(send_keys) — ok (655 ms)
✓ Sent keys to session routing-sources-verify

[ 4] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Sections'

[ 5] send(send_keys) — ok (651 ms)
✓ Sent keys to session routing-sources-verify

[ 6] send(send_keys) — ok (652 ms)
✓ Sent keys to session routing-sources-verify

[ 7] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session routing-sources-verify

[ 8] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'Routing Rules'

[ 9] key(send_special_keys) — ok (651 ms)
✓ Sent 1 special key(s) to session routing-sources-verify

[10] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'D ‹loyalsoldier›'

[11] capture(capture_screen) — ok (301 ms)
Screen output (session: routing-sources-verify, mode: buffer):
============================================================
┌ 1: [Profiles]  Sniffer  Sources  Logs ───────────────────────────────────────────────────────────────────────────────┐
│ ┌ Settings ────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ┌ Search ──────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│ │ │Press / to filter settings                                                                                    │ │ │
│ │ └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│ │ ┌ Sections · 2/2 ───────────────┐ ┌ Routing Rules ─────────────────────────────────────────────────────────────┐ │ │
│ │ │  ▾ Routing · 3                │ │D ‹loyalsoldier› · C ‹ru› · M ‹default›  22 rules · 0 off                   │ │ │
│ │ │›    Routing Rules             │ │ [D] dataset  [C] country  [M] mode   shipped table — [M] to edit           │ │ │
│ │ │                               │ │  1 block     geosite:win-spy  —                                            │ │ │
│ │ │                               │ │  2 block     geosite:category-ads  —                                       │ │ │
│ │ │                               │ │  3 proxy     geosite:google-play  —                                        │ │ │
│ │ │                               │ │  4 proxy     geosite:github  —                                             │ │ │
│ │ │                               │ │  5 proxy     geosite:twitch-ads  —                                         │ │ │
│ │ │                               │ │  6 proxy     geosite:youtube  —                                            │ │ │
│ │ │                               │ │  7 proxy     geosite:telegram  —                                           │ │ │
│ │ │                               │ │  8 direct    geosite:private  —                                            │ │ │
│ │ │                               │ │  9 direct    geosite:torrent  —                                            │ │ │
│ │ │                               │ │ 10 direct    geosite:category-ru  —                                        │ │ │
│ │ │                               │ │ 11 direct    geosite:whitelist  —                                          │ │ │
│ │ │                               │ │ 12 direct    geosite:microsoft  —                                          │ │ │
│ │ │                               │ │ 13 direct    geosite:apple  —                                              │ │ │
└─│ │                               │ │ 14 direct    geosite:epicgames  —                                          │ │─┘
┌ │ │                               │ │ 15 direct    geosite:riot  —                                               │ │─┐
│S│ │                               │ │ 16 direct    geosite:escapefromtarkov  —                                   │ │ │
│ │ │                               │ │ 17 direct    geosite:steam  —                                              │ │ │
│ │ │                               │ │ 18 direct    geosite:twitch  —                                             │ │ │
│ │ │                               │ │ 19 direct    geosite:pinterest  —                                          │ │ │
│ │ └───────────────────────────────┘ └────────────────────────────────────────────────────────────────────────────┘ │ │
│ │ ┌ Help ────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│ │ │Keys     [/] filter this pane   [Tab] focus   [Esc] back                                                      │ │ │
│ │ │Legend   · saved   ○ at default   * unsaved   › selected                                                      │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
└─│ └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │─┘
  └────────────────────────────────────────── [↑/↓] Nav  [D]ataset  [C]ountry  [M]ode  [Ctrl+W] Sections  [Esc] Back ┘
 Settings > Routing Disconnected
============================================================

[12] line(get_line) — ok (301 ms)
Line 6 (session: routing-sources-verify): │ │ │  ▾ Routing · 3                │ │D ‹loyalsoldier› · C ‹ru› · M ‹default›  22 rules · 0 off                   │ │ │

[13] line(get_line) — ok (301 ms)
Line 7 (session: routing-sources-verify): │ │ │›    Routing Rules             │ │ [D] dataset  [C] country  [M] mode   shipped table — [M] to edit           │ │ │

[14] line(get_line) — ok (301 ms)
Line 8 (session: routing-sources-verify): │ │ │                               │ │  1 block     geosite:win-spy  —                                            │ │ │

[15] send(send_keys) — ok (751 ms)
✓ Sent keys to session routing-sources-verify

[16] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'default is read-only'

[17] capture(capture_screen) — ok (301 ms)
Screen output (session: routing-sources-verify, mode: buffer):
============================================================
┌ 1: [Profiles]  Sniffer  Sources  Logs ───────────────────────────────────────────────────────────────────────────────┐
│ ┌ Settings ────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ┌ Search ──────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│ │ │Press / to filter settings                                                                                    │ │ │
│ │ └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│ │ ┌ Sections · 2/2 ───────────────┐ ┌ Routing Rules ─────────────────────────────────────────────────────────────┐ │ │
│ │ │  ▾ Routing · 3                │ │D ‹loyalsoldier› · C ‹ru› · M ‹default›  22 rules · 0 off                   │ │ │
│ │ │›    Routing Rules             │ │ [D] dataset  [C] country  [M] mode   shipped table — [M] to edit           │ │ │
│ │ │                               │ │  1 block     geosite:win-spy  —                                            │ │ │
│ │ │                               │ │  2 block     geosite:category-ads  —                                       │ │ │
│ │ │                               │ │  3 proxy     geosite:google-play  —                                        │ │ │
│ │ │                               │ │  4 proxy     geosite:github  —                                             │ │ │
│ │ │                               │ │  5 proxy     geosite:twitch-ads  —                                         │ │ │
│ │ │                               │ │  6 proxy     geosite:youtube  —                                            │ │ │
│ │ │                               │ │  7 proxy     geosite:telegram  —                                           │ │ │
│ │ │                               │ │  8 direct    geosite:private  —                                            │ │ │
│ │ │                               │ │  9 direct    geosite:torrent  —                                            │ │ │
│ │ │                               │ │ 10 direct    geosite:category-ru  —                                        │ │ │
│ │ │                               │ │ 11 direct    geosite:whitelist  —                                          │ │ │
│ │ │                               │ │ 12 direct    geosite:microsoft  —                                          │ │ │
│ │ │                               │ │ 13 direct    geosite:apple  —                                              │ │ │
└─│ │                               │ │ 14 direct    geosite:epicgames  —                                          │ │─┘
┌ │ │                               │ │ 15 direct    geosite:riot  —                                               │ │─┐
│S│ │                               │ │ 16 direct    geosite:escapefromtarkov  —                                   │ │ │
│ │ │                               │ │ 17 direct    geosite:steam  —                                              │ │ │
│ │ │                               │ │ 18 direct    geosite:twitch  —                                             │ │ │
│ │ └───────────────────────────────┘ └────────────────────────────────────────────────────────────────────────────┘ │ │
│ │ ┌ Help ────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│ │ │Keys     [/] filter this pane   [Tab] focus   [Esc] back                                                      │ │ │
│ │ │Legend   · saved   ○ at default   * unsaved   › selected                                                      │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ │                                                                                                              │ │ │
│ │ └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
└─│ default is read-only — [M] switch to custom                                                                      │─┘
  └────────────────────────────────────────── [↑/↓] Nav  [D]ataset  [C]ountry  [M]ode  [Ctrl+W] Sections  [Esc] Back ┘
 Settings > Routing Disconnected
============================================================

[18] send(send_keys) — ok (751 ms)
✓ Sent keys to session routing-sources-verify

[19] expect(expect_text) — ok (301 ms)
✓ Found expected text: 'M ‹custom›'

[20] capture(capture_screen) — ok (301 ms)
Screen output (session: routing-sources-verify, mode: buffer):
============================================================
┌ 1: [Profiles]  Sniffer  Sources  Logs ───────────────────────────────────────────────────────────────────────────────┐
│ ┌ Settings ────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ┌ Search ──────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│ │ │Press / to filter settings                                                                                    │ │ │
│ │ └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│ │ ┌ Sections · 2/2 ───────────────┐ ┌ Routing Rules ─────────────────────────────────────────────────────────────┐ │ │
│ │ │  ▾ Routing · 3                │ │D ‹loyalsoldier› · C ‹ru› · M ‹custom›  22 rules · 0 off                    │ │ │
│ │ │›    Routing Rules             │ │ [D] dataset  [C] country  [M] mode   [a/e/d] rule  [Ctrl+↑↓] reorder       │ │ │
│ │ │                               │ │  1 block     geosite:win-spy  —                                            │ │ │
│ │ │                               │ │  2 block     geosite:category-ads  —                                       │ │ │
│ │ │                               │ │  3 proxy     geosite:google-play  —                                        │ │ │
│ │ │                               │ │  4 proxy     geosite:github  —                                             │ │ │
│ │ │                               │ │  5 proxy     geosite:twitch-ads  —                                         │ │ │
│ │ │                               │ │  6 proxy     geosite:youtube  —                                            │ │ │
│ │ │                               │ │  7 proxy     geosite:telegram  —                                           │ │ │
│ │ │                               │ │  8 direct    geosite:private  —                                            │ │ │
│ │ │                               │ │  9 direct    geosite:torrent  —                                            │ │ │
[…663ln elided…]
    },
    {
      "n": 21,
      "step": "send",
      "tool": "send_keys",
      "status": "ok",
      "elapsed_ms": 752,
      "output": "✓ Sent keys to session routing-sources-verify"
    },
    {
      "n": 22,
      "step": "expect",
      "tool": "expect_text",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "✓ Found expected text: 'Domain Matcher'"
    },
    {
      "n": 23,
      "step": "capture",
      "tool": "capture_screen",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "Screen output (session: routing-sources-verify, mode: buffer):\n============================================================\n┌ 1: [Profiles]  Sniffer  Sources  Logs ───────────────────────────────────────────────────────────────────────────────┐\n│ ┌ Settings ────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │\n│ │ ┌ Search ──────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │\n│ │ │Press / to filter settings                                                                                    │ │ │\n│ │ └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │\n│ │ ┌ Sections · 2/2 ───────────────┐ ┌ Routing Rule ──────────────────────────────────────────────────────────────┐ │ │\n│ │ │  ▾ Routing · 3                │ │›  Type                    —█                                               │ │ │\n│ │ │›    Routing Rules             │ │   Domain Matcher          —                                                │ │ │\n│ │ │                               │ │   Domains (comma-sep)     —                                                │ │ │\n│ │ │                               │ │   IPs (comma-sep)         —                                                │ │ │\n│ │ │                               │ │   Inbound Tags (comma-sep) —                                               │ │ │\n│ │ │                               │ │   Ports (comma-sep)       —                                                │ │ │\n│ │ │                               │ │   Source Ports (comma-sep) —                                               │ │ │\n│ │ │                               │ │   Network                 —                                                │ │ │\n│ │ │                               │ │   Protocols (comma-sep)   —                                                │ │ │\n│ │ │                               │ │   Domain Strategy         —                                                │ │ │\n│ │ │                               │ │   Outbound Tag            —                                                │ │ │\n│ │ │                               │ │   Balancer Tag            —                                                │ │ │\n│ │ │                               │ │   Rule Set (File)         —                                                │ │ │\n│ │ │                               │ │   Rule Set (URL)          —                                                │ │ │\n│ │ │                               │ │                                                                            │ │ │\n└─│ │                               │ │                                                                            │ │─┘\n┌ │ │                               │ │                                                                            │ │─┐\n│S│ │                               │ │                                                                            │ │ │\n│ │ │                               │ │                                                                            │ │ │\n│ │ │                               │ │                                                                            │ │ │\n│ │ └───────────────────────────────┘ └────────────────────────────────────────────────────────────────────────────┘ │ │\n│ │ ┌ Help ────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │\n│ │ │Keys     [/] filter this pane   [Tab] focus   [Esc] back                                                      │ │ │\n│ │ │Legend   · saved   ○ at default   * unsaved   › selected                                                      │ │ │\n│ │ │                                                                                                              │ │ │\n│ │ │                                                                                                              │ │ │\n│ │ │                                                                                                              │ │ │\n│ │ │                                                                                                              │ │ │\n│ │ │                                                                                                              │ │ │\n│ │ │                                                                                                              │ │ │\n│ │ └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │\n└─│ default is read-only — [M] switch to custom                                                                      │─┘\n  └───────────────────────────────────────────────────────────────────── [Enter] Save  [Ctrl+W] Sections  [Esc] Back ┘\n Settings > Routing Disconnected\n============================================================"
    },
    {
      "n": 24,
      "step": "key",
      "tool": "send_special_keys",
      "status": "ok",
      "elapsed_ms": 652,
      "output": "✓ Sent 1 special key(s) to session routing-sources-verify"
    },
    {
      "n": 25,
      "step": "key",
      "tool": "send_special_keys",
      "status": "ok",
      "elapsed_ms": 654,
      "output": "✓ Sent 1 special key(s) to session routing-sources-verify"
    },
    {
      "n": 26,
      "step": "key",
      "tool": "send_special_keys",
      "status": "ok",
      "elapsed_ms": 651,
      "output": "✓ Sent 1 special key(s) to session routing-sources-verify"
    },
    {
      "n": 27,
      "step": "expect",
      "tool": "expect_text",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "✓ Found expected text: '1: \\[Profiles\\]'"
    },
    {
      "n": 28,
      "step": "send",
      "tool": "send_keys",
      "status": "ok",
      "elapsed_ms": 852,
      "output": "✓ Sent keys to session routing-sources-verify"
    },
    {
      "n": 29,
      "step": "expect",
      "tool": "expect_text",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "✓ Found expected text: 'Sources'"
    },
    {
      "n": 30,
      "step": "capture",
      "tool": "capture_screen",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "Screen output (session: routing-sources-verify, mode: buffer):\n============================================================\n┌ 1: Profiles  Sniffer  [Sources]  Logs ───────────────────────────────────────────────────────────────────────────────┐\n│Name                 Enabled Status               Updated    Endpoints URL                                            │\n│Default              ✓       never                —          0                                                        │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n│                                                                                                                      │\n└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘\n┌ 2: [Details]  Metrics  Tasks ────────────────────────────────────────────────────────────────────────────────────────┐\n│Server                        │Link                                                     │DB 0                         │\n│  no server selected          │  no link                                                │proven       0               │\n│                              │                                                         │untested     0               │\n│                              │                                                         │failed       0               │\n│                              │                                                         │other        0               │\n│                              │                                                         │                             │\n│                              │                                                         │alive        0               │\n│                              │                                                         │active       0               │\n│                              │                                                         │reliable     0               │\n│                              │                                                         │                             │\n│                              │                                                         │View: Active                 │\n│                              │                                                         │proven       0               │\n│                              │                                                         │untested     0               │\n│                              │                                                         │failed       0               │\n└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘\n  info [tui::ops::settings] Custom ruleset seeded from the shipped default\n Disconnected          [a] Add  [e] Edit  [d] Delete  [u] Update  [Space] Select  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit\n============================================================"
    },
    {
      "n": 31,
      "step": "resize",
      "tool": "resize",
      "status": "ok",
      "elapsed_ms": 1102,
      "output": "✓ Resized session routing-sources-verify to 80x24"
    },
    {
      "n": 32,
      "step": "expect",
      "tool": "expect_text",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "✓ Found expected text: 'Sources'"
    },
    {
      "n": 33,
      "step": "capture",
      "tool": "capture_screen",
      "status": "ok",
      "elapsed_ms": 301,
      "output": "Screen output (session: routing-sources-verify, mode: buffer):\n============================================================\n┌ 1: Profiles  Sniffer  [Sources]  Logs ───────────────────────────────────────┐\n│Name           Enabled Status               Updated                           │\n│Default        ✓       never                —                                 │\n│                                                                              │\n│                                                                              │\n└──────────────────────────────────────────────────────────────────────────────┘\n┌ 2: [Details]  Metrics  Tasks ────────────────────────────────────────────────┐\n│Server                                                                        │\n│  no server selected                                                          │\n│Link                                                                          │\n│  no link                                                                     │\n│                                                                              │\n│DB 0                                                                          │\n│proven       0                                                                │\n│untested     0                                                                │\n│failed       0                                                                │\n│other        0                                                                │\n│                                                                              │\n│alive        0                                                                │\n│active       0                                                                │\n│reliable     0                                                                │\n└──────────────────────────────────────────────────────────────────────────────┘\n  info [tui::ops::settings] Custom ruleset seeded from the shipped default\n Disconnected  … [u] Update [Space] Select [Tab] Pane [?] Help [q/Ctrl+C] Quit\n============================================================"
    },
    {
      "n": 34,
      "step": "key",
      "tool": "send_special_keys",
      "status": "ok",
      "elapsed_ms": 651,
      "output": "✓ Sent 1 special key(s) to session routing-sources-verify"
    },
    {
      "n": 35,
      "step": "close",
      "tool": "close_session",
      "status": "ok",
      "elapsed_ms": 100,
      "output": "✓ Closed session: routing-sources-verify"
    }
  ],
  "session_alive": false,
  "rescue_files": [],
  "choice": null
}
```

[Showing lines 1-168 and 832-958 of 958; 663 middle lines (51.9KB) elided. Read artifact://236 for full output]