# leas Manual

## Overview

leas is a terminal user interface (TUI) for managing proxy connections through
xray-core and sing-box. It provides profile management, subscription updates, speed
testing, settings configuration, and real-time statistics — all from the terminal.

The backend architecture abstracts over the two subprocess backends (xray-core,
sing-box) and the in-process native core. The TUI writes JSON configs and manages
the binary lifetime for the subprocess backends; the native core runs in-process. Only one backend runs
per connection session; switching profiles between backends stops the current core
and starts the other.

---

## Shell — two panes, no top-level tabs

The window is two framed panes plus a status bar:

```
┌ 1: [Profiles]  Logs ────────────────────────────────────┐
│ …table or log viewer…                                    │
├ 2: Details  [Metrics] ──────────────────────────────────┤
│ …actions log / traffic+native+sys metrics…               │
└ status bar ──────────────────────────────────────────────┘
```

- Each pane carries an inline tab bar in its border title: pane index (`1:`/`2:`)
  accent-bold, the active tab bracketed and accent-bold (`[Profiles]`), inactive
  tabs plain. Focused pane draws an accent border, the other a muted one.
- **Pane 1 tabs**: `Profiles` (endpoint table) and `Logs` (live core log viewer).
- **Pane 2 tabs**: `Details` (the Actions Log panel) and `Metrics` (traffic +
  native-core connection ring + core system stats, one scrollable view).
- **Pane keys**: `Tab`/`Shift+Tab` or `1`/`2` move focus; `[`/`]` cycle the focused
  pane's tabs; `Alt+↑`/`Alt+↓` resize pane 2 (pane 2 focused; clamped 3..half the
  terminal, session-only); `F1` toggles pane 2's compact one-line bar.
- Settings is a **popup** (`,`) over both panes, not a tab. `Esc` closes it; an
  unsaved form asks `y/n` before discarding.

Overlays (help `?`, speed-test menu `t`, export `Ctrl+E`, add/edit/import forms,
delete confirmation) render on top of the shell; only the top-most consumes keys.

---

## Screens

### Profiles

The main screen. Shows a table of single-line endpoint rows with the following columns:

| Column       | Width | Content                                     |
| ------------ | ----- | ------------------------------------------- |
| (status)     | 2     | Connection status or test indicator          |
| `ID`         | 8     | Representative link's protocol id as 8 lowercase hex (`{:08x}`); `*` when multi-selected (the marker replaces the id, widths equal) |
| `Flag`       | 5     | Inbound country: `<flag emoji>-<ISO>` (e.g. `🇳🇱-NL`) when the terminal renders flag emoji, bare `<ISO>` when it does not (`LEAS_NO_FLAGS`/`NO_EMOJI` force the fallback); `—` unknown |
| `Address`    | 34    | Host. Multi-variant endpoints carry a bold `+` (collapsed) / `-` (expanded) prefix — the old `▶`/`▾` glyph is gone. A DNS name whose subdomain overflows elides the subdomain's tail, keeping the registrable domain: `jp-tyo-05….synthetic-node.example`. IP literals right-truncate with `…` |
| `Port`       | 6     | Port, right-aligned                          |
| `White`      | 9     | Whitelist membership tokens: `SNI` / `CIDR` / `SNI+CIDR` / `—` (replaces the old flag glyphs; DNS-unresolved lives in the Test cell's `[name]`) |
| `Protocol`   | 24    | `protocol/transport/security` (e.g. `vless/tcp/reality`), center-aligned |
| `Test`       | 7     | Ping delay `[ 12 ]`, colored (green <500ms, yellow ≥500ms, red ≥1000ms); red problem labels `[name]` (DNS unresolved), `[fast]`/`[real]` — shown only when the ACTIVE/preferred link has NO measured delay (a measured result always wins over a stale failure marker; real over fast precedence). The cell describes the endpoint's REPRESENTATIVE link (`EndpointRow::representative_link_index`, the argmin of the ordering key) — the same link the `ID` column names, so the two cells cannot disagree. Labels survive restarts; the Speed Test `error_ttl_hours` setting clears them. The header's `↑` arrow is the fixed sort (`PageSort::Test`, ascending): sorting is deliberately not user-changeable, to avoid database contention |
| `Out`        | 5     | Exit country flag, same `<flag>-<ISO>` idiom as `Flag`; `—` unknown |
| `Exit`       | 14    | Exit IP of the active link's persisted real ping (`—` none); survives reruns |

Every label carries the header role; there are no decorative separator cells.
Delay/Speed/Traffic/Outbound details live in the expanded panel (below).

**Expandable endpoints**: Endpoints with multiple protocol variants show a bold `+`
before the host (collapsed) or `-` (expanded). Press `→` to expand: a rounded panel appears
under the row with an `IPs:` line (resolved inbound addresses; `[?]` with an
`(x resolve)` hint while the DNS name is unresolved) and a per-protocol
sub-table: active marker, hex profile id, Last Seen, Last Used, Protocol Type,
config type (transport/security), delay, speed, traffic, outbound address,
outbound country. The panel shows at most 8 sub-rows; longer variant lists
scroll — the window follows the selected sub-row and the separator shows the
visible range (`6-13/23`). `←` collapses.
Expanding lands on the **first sub-row**; `↑`/`↓` then walk the variants.
`↑` at the first sub-row returns to the full endpoint row; `↓` at the last
sub-row moves to the next profile; `↓` from the full row of an expanded
endpoint re-enters the sub-table. `Enter` on a sub-row activates that variant
(manual override).

**Enrichment**: inbound country, whitelist features, and outbound info are
computed in the background. Press `x` to force a DNS resolution of the
selected endpoint. DNS results are cached (TTL configurable in Settings → DNS)
and persist across launches, so group updates and restarts do not re-resolve.

**Speed tests**: on a collapsed endpoint row with more than one protocol, the
speed-test menu pings **all protocols of the endpoint** (endpoint-scoped
batch); on a panel sub-row it pings the **exact protocol**.

**Search:** Press `/` to focus search field, type to filter profiles by
address/port. `Esc` clears filter and exits search mode.

**Delete confirmation overlay** — centered dialog asking `y/n` when `d` is pressed.
`y` confirms, `n`/`q`/`Esc` cancels.

---

### Settings (popup)

Opened with `,` from anywhere in the shell: a centered modal (width
`clamp(term-4, 50, 110)`, height `clamp(term-2, 20, 40)`) over both panes. Not a
tab — the shell stays rendered behind it. `Esc` closes; a form with unsaved edits
asks `Discard unsaved settings? (y/N)` first.

Left side: a menu of 14 sections. Press `Enter` on a section to open its
configuration form on the right. A separator line visually groups the first 5 "active" sections
from the remaining "deferred" sections.

**Menu items (in order):**

1. Core Settings — binary paths, log level, default core type
2. GUI Settings — language, theme, refresh interval
3. Inbound Settings — ports, listen address, sniffing
4. Routing Rules — add/edit/delete/reorder rules
5. DNS Settings — servers, hosts, query strategy, cache
6. Protocol Core — per-protocol core override (Auto/Xray/SingBox)
7. System Proxy — enable/disable HTTP_PROXY, ports, bypass
8. TUN Mode — enabled, interface name, MTU
9. Mux — multiplexing settings
10. Statistics — enable/disable stats collection
11. Speed Test — ping URL, exit-IP provider, timeouts, batch concurrency, per-profile task queue limit, DNS-failure deferral, error-label TTL
12. Logging — log level, log-to-file path, log retention
13. Subscriptions — group list, add/edit/delete/update (`g` from Profiles jumps here)
14. Updates — check and install backend updates

**Form navigation within a section:**
- `Tab` / `Shift+Tab` — move focus between fields
- `Enter` — save the form
- `Esc` — back to the menu; asks before discarding unsaved edits
- `Tab` on the section tree — closes the popup

**Routing Rules** (section 4) has a two-level UI:
- Routing list: `↑↓` navigate, `Enter` edit, `a` add, `d` delete, `r` reorder
- Routing rule form: same Tab/S-Tab/Enter/Esc navigation

**Updates form** — shows current version and latest available version for each
backend. `C` triggers a version check, `D` triggers download for all available
updates. `Esc` returns to menu.

---

### Logs (pane 1 tab)

Live log output from the connected core process, rendered frameless inside pane 1
(the pane supplies the frame). When no core is running, shows:

```
┌ Logs ───────────────────────────────────────────────────┐
│No logs                                                  │
└──────────────────────────────────────────────────────────┘
```

After connecting to a profile, the core's stdout (xray-core) and stderr (sing-box)
log lines appear in real time. Log levels are color-coded:

- **error/fatal/panic** — red bold (`Theme::ERROR`)
- **warning/warn** — yellow (`Theme::WARNING`)
- **info** — default terminal color
- **debug/trace** — gray (`Theme::HINT`)

The buffer holds the most recent 1000 log lines. Scrolling is bottom-anchored
(0 = newest line visible at bottom of viewport).

---

### Metrics (pane 2 tab)

One scrollable view merging the former Statistics and Native Activity screens —
the pane frame supplies the border; sections are flat labelled rows:

```
session
  edge-a.example:443 [xray]
  today ↑1.0KB ↓2.1KB · total ↑9.8KB ↓19.5KB
native
  4 open · 12 closed · 1 failed
  [7] example.com:443 [vless/tcp] [tls] ↑12KB ↓34KB 120ms
core
  mem 42MB / 64MB · routines 38 · uptime 1h12m
  api http://127.0.0.1:62789
```

- **session** — the CONNECTED profile's traffic (today/total, up/down from the
  link's persisted `profile_stats` plus the session delta); `not connected —
  select a profile and press Ctrl+Enter` when nothing is connected.
- **native** — per-connection trace of the in-process native core: one line per
  connection with byte totals and lifetime; failures render in the error colour.
  With more rows than fit, a `rows N-M of T` line caps the window and `↑↓` scroll.
- **core** — memory/routines/uptime from the backend's gRPC/V2Ray API and the API
  endpoint (the native core reports an in-process event feed).

`Alt+↑`/`Alt+↓` (pane 2 focused) resize the pane; `F1` collapses it to the
one-line compact bar.

### Subscriptions (Settings)

Group management lives in the Settings popup → Subscriptions. Press `g` on pane 1
(Profiles tab) to jump straight there; `Esc` returns to the settings menu.

Lists subscription groups with columns: Name, URL (truncated), Enabled,
Status, Last Updated.

**Actions:**

| Key             | Action                            |
| --------------- | --------------------------------- |
| `a`             | Add new group                     |
| `e`             | Edit selected group               |
| `d`             | Delete selected group (y/n confirm)|
| `u`             | Update all groups' subscriptions  |
| `Esc`           | Return to settings menu           |

**Group form** — fields: `name`, `subscription_url`, `user_agent`,
`update_interval`, `core_type`. `Tab`/`Shift+Tab` navigates, `Enter` saves,
`Esc` cancels.

---

### Add/Edit Server Forms

Opened with `a` (add) or `e` (edit) from the Profiles tab.

**Protocol picker** (add only) — scrollable list of all supported protocols:

- Xray-core native: VMess, VLESS, Shadowsocks, Shadowsocks-2022, SOCKS, HTTP,
  Trojan, WireGuard, Hysteria v2, Dokodemo-door, Freedom, Blackhole, DNS,
  Loopback, Custom
- Sing-box only: TUIC, Hysteria v1, Naïve, AnyTLS, ShadowTLS, Tor, SSH,
  Tailscale, ShadowsocksR, Redirect

`↑↓` to navigate, `Enter` to select, `Esc` to cancel.

**Parameter form** — after selecting a protocol (or when editing), displays
fields specific to that protocol. Field types: text, number, boolean (toggle
on any key press), and select (cycle with `←`/`→` or any key press).

- `Tab` / `Shift+Tab` or `↑↓` — move focus
- `Enter` — save and return to profile list
- `Ctrl+S` — save (alternative)
- `Esc` — cancel
- `Backspace` — delete character before cursor
- `Space` — type space
- `-` in number fields — negative sign

---

### Import URL Screen

Opened with `Ctrl+V` from the Profiles tab. A bordered input field with title:

```
Import URL — Ctrl+V paste, Enter parse, Esc cancel
```

- Type or paste the share URL (vmess://, ss://, trojan://, etc.)
- `Enter` — parse and add profile
- `Esc` — cancel
- Shows error message in red if parsing fails

### Batch Import Screen

Triggered by pasting multiple share URLs into the Import URL screen and pressing Enter.
Shows a scrollable list of import results with success/failure per URL.

**Keyboard shortcuts:**
- `↑/↓` — scroll results list
- `Enter` — save all successful imports and return to profile list
- `Esc` — cancel all and return to profile list

---

### Speed Test Menu

Opened with `t` from the Profiles tab. Overlay menu centered on screen:

```
┌─ Speed Test ─────────────────────────────────────────┐
│  Fast Ping (Selected)                                  │
│  Real Ping (Selected)                                 │
│  Speed Test (Selected)                                │
│  UDP Test (Selected)                                  │
│  ─────                                                │
│  Fast Ping (All Profiles)                               │
│  Fast + Real Ping (All Profiles)                        │
│  Fast + Real Ping (Successful)                          │
│  Fast + Real Ping (New)                                 │
│  Fast + Real Ping (Successful + New)                    │
│  Fast + Real Ping (Failed)                              │
│  Sort by Test                                         │
│  Remove Bad Servers                                   │
│  ─────                                                │
│  Stop Testing                                         │
│  ─────                                                │
│  Clear All Stats                                      │
└───────────────────────────────────────────────────────┘
```

- `↑↓` — navigate (skips separator lines)
- `Enter` — run selected test
- `Esc` — close menu
- `?` — open help overlay
- `s` — stop running tests (works when progress shown in status bar)

Progress is shown in the status bar during batch tests (`Testing: {completed}/{total}` or `Testing...`).
### Export Menu

Open with `Ctrl+E` from Profiles. First choose scope, then destination:

- `Only Alive` — links with current real/fast success (canonical rank tiers 0/1)
- `Only Resolved` — dialable endpoints; DNS endpoints emit one line per stored IP
- `Only Active` — exact current Active view
- `All Valid` — all non-purged links, including aged/stale Purgatory rows
- `Clipboard` — copies raw subscription text through `arboard`
- `File` — writes raw subscription text through `tokio::fs`

`↑↓` navigates, `Enter` selects, `Esc` closes. File paths are editable; existing destinations require `y` confirmation. Output has four metadata comment lines followed by one share URL per line. `Количество` counts matching stored links before Resolved IP expansion or serializer skips; Actions reports emitted and skipped counts separately.
Output header:

```text
# profile-title: leas export • <Scope>
# profile-update-interval: 1
# Date/Time: YYYY-MM-DD / HH:MM (Moscow)
# Количество: <matching-links>

<one share URL per line>
```

File export writes directly to the confirmed destination. A write failure can leave a partial destination; the UI reports the error and does not claim success.

**Batch behavior (Fast Ping / Real Ping / Fast+Real on All Profiles):** the
"All Profiles" entry points test the whole DATABASE — every (protocol,
endpoint) link it holds, not the rows the tab currently shows — so a filtered
or paged view does not narrow a run (only links imported after the run starts
can be missed). The batch runs on a per-profile (protocol, endpoint) task queue — one live test
per profile, further tests queued FIFO up to `task_queue_limit` (default 3,
`0` disables queueing). Profiles whose queue is full are skipped with a
warning. Profiles whose DNS failed recently are deferred and retried after
`dns_failure_defer_secs` (default 5s). Both settings live in Settings → Speed
Test and apply immediately.

**Error labels:** failed tests mark the profile (`[fast]`/`[real]`/`[name]`
in the Test column). The label reflects the endpoint's ACTIVE (preferred)
link, and only when it has NO measured delay — a link that carries both a
successful measurement and a later failure marker still shows its delay (the
expanded panel keeps per-link markers). One exception: a profile the native
engine cannot test (a protocol kind or config it has no implementation for)
is marked `[real]` with the reason, and that marker outranks a stored delay —
it says something about the profile, not about a failed attempt. Such rows
are never removed by **Remove Bad Servers** (they are fine, just untestable
here). A second exception, same precedence: a link carrying a **purge verdict**
shows the verdict instead of its delay (`[mitm]`, `[cert]`, `[expired]`,
`[notls]`, `[cfg]`, `[http]`, `[origin]` — see **Purgatory** below). Markers
persist across restarts;
`error_ttl_hours` (empty = never) clears them automatically on profile reload
and at batch finish. The Test cell describes the endpoint's REPRESENTATIVE link — the argmin of the
ordering key, not `active_link()` (lowest-delay measured, error-blind) — so the
single-row view shows the row's tier band.

---

### Help Overlay

Opened with `?` from any main screen. Rounded-border centered modal listing
keyboard shortcuts grouped by current context (Profiles, Settings, Statistics,
Logs, or Native Activity). `Esc` or `?` closes.


### Actions Log (pane 2 `Details` tab)

A live state information panel showing current system state, connection info,
test results, and recent log lines. Supports two views toggled with `F1`:

**Compact bar** (1 line):

```
⠋ VMess/my-server 1.2.3.4:443 | TCP:45ms RP:120ms SPD:15Mbps | ⬆1.2GB ⬇3.4GB | Info Xray 1.8.0 started
```

Connection indicators:
- `⠋` yellow — connecting
- `●` green — connected
- `⏹` red — error
- `⏏` yellow — disconnected (profile selected but not connected)
- `○` gray — no profile

Segments (compact): server info, test results (only when available), traffic,
last core log snippet.

**Full panel** (8 rows; the pane-2 default height):

```
 ● Connected [xray]
 🖥 VLESS  us.example.com:443
 ⏱ TCP:45ms  RP:120ms  SPD:15Mbps
 📊 ⬆1.2GB  ⬇3.4GB    💾 64.2MB
 📋 Core: [Info] Xray 1.8.0 started
 📋 TUI:  [Info] Connected [xray] (core)
```

Rows:
1. Connection status (icon + state + backend type)
2. Server info (protocol, remarks, address, port)
3. Test results (TCP ping, real ping, speed — `-` for unavailable)
4. Traffic (upload/download from stats API) and memory usage
5. Last core log line (from core process stderr/log channel)
6. Last TUI log line (from `tracing` events, with target tag)

**Behavior:**
- `F1` toggles between compact and full at any time
- Pane 2's height follows the active tab (Details 8 rows, Metrics 14) plus any
  `Alt+↑`/`Alt+↓` adjustment; the compact bar is 1 row.

Tracing integration (backend logging):
- TUI internals emit `tracing` events via `tracing-subscriber` with a
  custom `TuiLogLayer` that forwards events to the core event channel
- Events carry a `target` field (`core`, `tui`, `speedtest`, `subscription`)
- Viewable in the Actions Log pane, the Logs tab, and the configured log file
  (`logging.log_to_file` / `logging.log_file_path`)
- **Stderr mirror is opt-in via `LEAS_STDERR_LOG`** — set it to anything
  other than empty/`0`/`false` to add a stderr `tracing` layer. `RUST_LOG`
  alone does NOT enable it; it only supplies that layer's directives once the
  mirror is on (default `leas=info`). Only usable with stderr redirected —
  unguarded stderr writes corrupt the alternate-screen TUI, so terminal
  debugging is `LEAS_STDERR_LOG=1 leas 2>stderr.log`. The Actions Log,
  Logs tab and log file capture everything regardless
- Key operations (connect, disconnect, speed test, subscription updates)
  emit tracing events for real-time visibility

---

## Status Bar

Bottom line of the terminal. Left side shows connection state and mode context;
right side shows contextual key hints.

**Connection states (left side):**

| State                      | Display                                 |
| -------------------------- | --------------------------------------- |
| Disconnected               | ` Disconnected` (red)                   |
| Connecting                  | ` ⠋ Connecting...` (yellow spinner)     |
| Connected (xray)           | ` Connected [xray]` (green)             |
| Connected (sing-box)       | ` Connected [sing-box]` (green)         |
| Error                      | ` Error: <message>` (red bold)          |
| Testing (individual)       | ` Testing...` (yellow)                  |
| Testing (batch)            | ` Testing: 3/7 profiles...` (yellow)    |

**Mode prefix** is shown before the connection state:

- No prefix for List mode
- ` Settings`, ` Settings > Core`, etc. when in Settings
- ` Add Server`, ` Edit Server` when adding/editing
- ` Speed Test` when speed test menu is open
- ` Help` when help overlay is open

**Update indicator** — `[Update: xray]` or `[Update: xray, sing-box]` (yellow)
appended when updates are available for installed backends.
**Contextual hints (right side):**


| Context                 | Hints                                    |
| ----------------------- | ---------------------------------------- |
| Pane 1 · Profiles (disconnected) | `[a] Add  [Ctrl+V] Import  [,] Settings  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 1 · Profiles (connecting)   | `[,] Settings  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit`  |
| Pane 1 · Profiles (connected)    | `[Ctrl+D] Disconnect  [,] Settings  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 1 · Profiles (filtered-empty) | `No match for "<q>"  [Esc] Clear  [q/Ctrl+C] Quit` |
| Pane 1 · Logs          | `[↑↓] Scroll  [c] Clear  [t] Targets  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 2 · Details       | `[↑↓] Scroll  [F1] Compact  [1] Pane 1  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 2 · Metrics       | `[↑↓] Scroll  [Alt+↑↓] Resize  [1] Pane 1  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Settings popup (tree)  | `[↑↓] Navigate  [←→] Collapse  [Enter] Open  [Ctrl+W] Focus Form  [Tab] Close  [Esc] Close` |
| Settings popup (form)  | `[Tab/Shift+Tab] Focus  [Enter] Save  [Ctrl+W] Focus Tree  [Esc] Back` |
| Confirm modal          | `[y] Confirm  [n/Esc] Cancel`             |
| Speed test menu        | `[↑↓] Navigate  [Enter] Select  [Esc] Close` |
| Help overlay           | `[Esc] Close help`                        |

## Keyboard Shortcuts — Full Reference

### Profiles Tab (List mode)

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `↑` / `↓`        | Navigate profile list               |
| `PgUp` / `PgDn`  | Page up/down in profile list        |
| `Home` / `End`   | Jump to first/last profile          |
| `Enter`          | Set as active server                |
|| `Ctrl+Enter`     | Connect to selected server          |
|| `Ctrl+G`         | Connect fallback (for terminals without Ctrl+Enter) |
|| `Space`          | Toggle multi-select                 |
|| `Ctrl+A`         | Select all / deselect all           |
|| `a`              | Add new server                      |
| `e`              | Edit selected server                |
| `d`              | Delete selected server(s)           |
| `c`              | Clone selected server               |
| `g`              | Open Settings popup at Subscriptions |
| `t`              | Open speed test menu                |
| `x`              | Resolve DNS of selected endpoint    |
| `p`              | Cycle view: Active → Purgatory → All |
| `/`              | Focus search/filter input           |
| `Ctrl+V`         | Import share URL                    |
 | `Ctrl+Shift+S`   | Copy selected server's share URL    |
| `Ctrl+↑`         | Move selected profile up            |
| `Ctrl+↓`         | Move selected profile down          |
| `Tab` / `Shift+Tab` | Switch pane focus (or `1`/`2`)   |
| `?`              | Toggle help overlay                 |
| `q` / `Ctrl+C`   | Quit application                    |
| `F1`             | Toggle pane 2 compact/full view     |
| `,`              | Open Settings popup                |
 | `Ctrl+D`   | Disconnect from active server       |

### Settings Popup

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `↑` / `↓`        | Navigate settings menu              |
| `Enter`          | Open selected section               |
| `Tab` / `Shift+Tab` | Close the popup                  |
| `Esc`            | Close settings / back to menu (asks before discarding unsaved edits) |
| `?`              | Toggle help overlay                 |
| `q` / `Ctrl+C`   | Quit application                    |

### Settings Forms

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `Tab` / `Shift+Tab` | Move focus between fields        |
| `Enter`          | Save and return to menu             |
| `Esc`            | Cancel and return to menu           |
| `Ctrl+C`         | Quit application                    |

### Routing List

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `↑` / `↓`        | Navigate rules                      |
| `Enter`          | Edit selected rule                  |
| `a`              | Add new rule                        |
| `d`              | Delete selected rule                |
| `r`              | Reorder rules                       |

### Updates Form

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `C`              | Check for updates                   |
| `D`              | Download and install updates        |
| `Esc`            | Return to settings menu             |

### Logs Tab

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `↑` / `↓`        | Scroll logs                         |
| `PgUp` / `PgDn`  | Page up/down (20 lines)            |
| `Home`           | Jump to oldest log entry            |
| `End`            | Jump to newest log entry            |
| `Tab` / `Shift+Tab` | Cycle tabs                       |
| `?`              | Toggle help overlay                 |
| `q` / `Ctrl+C`   | Quit application                    |

### Statistics Tab

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `Tab` / `Shift+Tab` | Cycle tabs                       |
| `?`              | Toggle help overlay                 |
| `q` / `Ctrl+C`   | Quit application                    |

### Native Activity Tab

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `↑` / `↓`        | Scroll connections                  |
| `PgUp` / `PgDn`  | Page up/down                        |
| `Home`           | Jump to oldest connection           |
| `End`            | Jump to newest connection           |
| `Tab` / `Shift+Tab` | Cycle tabs                       |
| `?`              | Toggle help overlay                 |
| `q` / `Ctrl+C`   | Quit application                    |

### Anywhere (Global)

| Key               | Action                              |
| ----------------- | ----------------------------------- |
| `q` / `Ctrl+C`   | Quit application                    |
| `?`              | Help overlay (main screens only)    |

---

## Common Workflows

### Adding a server manually

1. From Profiles tab, press `a`
2. Scroll through the protocol picker with `↑↓`
3. Press `Enter` on your protocol (e.g. VMess)
4. Fill in form fields: `Tab` to move focus, type values
5. Press `Enter` to save; profile appears in the list

### Importing a subscription URL

1. From Profiles tab, press `Ctrl+V`
2. Type or paste the subscription URL
3. Press `Enter` to parse and import
4. Profiles are added with automatic dedup based on content hash
5. If parsing fails, an error message appears in red below the input

### Running a speed test

1. Select a profile with `↑↓`
2. Press `t` to open the speed test menu
3. Navigate with `↑↓` (skips the separator line)
4. Press `Enter` on the test type:
   - **Fast Ping** — auto-selects TCP or UDP/QUIC adapter based on protocol.
     On a collapsed endpoint row with >1 protocols this runs an
     **endpoint-scoped batch** (all protocols of the endpoint); on an expanded
     panel sub-row it pings the **exact protocol**
   - **Real Ping** — measures response time through the proxy (same scoping)
   - **Speed Test** — downloads a test payload to measure throughput
   - **UDP Test** — tests UDP forwarding
   - **Fast Ping (All Profiles)** — batch fast pings every link in the database
   - **Fast + Real Ping (All Profiles)** — the same fast phase, then a real ping per reachable link (links the fast phase proved unreachable are skipped, and rows the native engine cannot serve are marked `[real]` instead of probed)
   - **Fast + Real Ping (Successful / New / Successful + New / Failed)** — the same run narrowed to a scope of the feed: endpoints that achieved a real success; endpoints nothing has answered for yet (untested); those two together; or those whose links all failed (including a DNS name that never resolved). The scope reads the endpoint's stored test tier, so it is a filter on the plan, not a different pipeline. A scoped run freezes its endpoint list before the first probe, so an endpoint leaving the scope mid-run is still tested.
   - **Sort by Test** — re-sorts the table by test priority (real successes by delay, then the failure bands)
   - **Remove Bad Servers** — removes profiles with failed tests
5. Results populate the expanded panel's per-protocol sub-table; real-ping
   exit IPs fill the single-line Outbound/Country columns — shown only once the
   endpoint's address is resolved, since an exit IP is evidence a tunnel worked.
   The Test cell reports the endpoint's representative protocol, so a row shows
   a delay or the marker for its worst state, never a failed protocol's stale
   delay. The free ip-api tier allows ~45 exit-IP lookups/minute, so a
   feed-wide run fills only the earliest results; when it refuses, the other
   family-agnostic providers are asked automatically (the exit IP is the same
   either way), which raises but does not remove the ceiling — and the
   provider set is fixed (Settings → Speed Test → IP Provider picks which one
   is asked first), so a keyed provider is not available.

   Batch runs (All Visible) go through the per-profile task queue: a profile
   already being tested queues further tests up to `task_queue_limit` (queue
   full = skipped with a warning), and profiles whose DNS failed recently are
   retried after `dns_failure_defer_secs`. Failed tests leave `[name]`/
   `[fast]`/`[real]` markers that persist until `error_ttl_hours` sweeps them.

### Connecting/Disconnecting

**Connect:**
1. Select a profile with `↑↓`
2. Press `Ctrl+Enter`
3. Status bar shows spinner and `Connecting...`
4. On success: status bar shows `Connected [xray]` (or `[sing-box]`)
5. Statistics tab becomes active with traffic data

**Disconnect:**
 1. Press `Ctrl+D`
2. Status bar returns to `Disconnected`

### Subscription group management

1. From the Profiles tab, press `g` to jump to Settings → Subscriptions
2. **Add:** press `a`, fill fields (name, URL, user_agent, update_interval, core_type), `Enter` saves
3. **Edit:** select a group, press `e`, modify fields, `Enter` saves
4. **Update:** press `u` to fetch the latest subscriptions for every group
5. **Delete:** select a group, press `d`, confirm with `y`, cancel with `n`/`Esc`
6. Press `Esc` twice to return to the profile list, or `Ctrl+C` to quit the app

Group filtering on the Profiles tab is done with `p` (cycle Active → Purgatory →
All views) and `/` (search); the per-group filter keys were removed.

---

## Visual Theme

Color tokens used throughout the TUI.

### Tab Bar

| Token             | Style                                |
| ----------------- | ------------------------------------ |
| `TAB_SELECTED`    | White text on Cyan background, Bold  |
| `TAB_DESELECTED`  | White text on DarkGray background    |

### Profile Table

| Token               | Style                            |
| ------------------- | -------------------------------- |
| `TABLE_HEADER`      | White on DarkGray, Bold           |
| `TABLE_ROW_SELECTED`| White on `rgb(50,60,90)`, Bold    |
| `TABLE_ROW_ALT`     | White on `rgb(25,25,35)`          |
| `TABLE_ROW_NORMAL`  | White (no background)             |

### Containers / Borders

| Token                | Style                          |
| -------------------- | ------------------------------ |
| `CONTAINER_BORDER`   | Cyan foreground                |
| `CONTAINER_TITLE`    | Cyan foreground, Bold          |

### Status Bar

| Token                | Style                          |
| -------------------- | ------------------------------ |
| `STATUS_BAR_BG`      | Background `rgb(20,30,60)`     |
| `STATUS_BAR_MODE`    | Cyan foreground, Bold          |

### Feedback / Progress

| Token                | Style                          |
| -------------------- | ------------------------------ |
| `PROGRESS_BAR`       | White on DarkGray              |
| `PROGRESS_FILL`      | Cyan on Cyan                   |
| `SPINNER`            | Yellow foreground, Bold        |

### Semantic Colors

| Token       | Style            | Used For                     |
| ----------- | ---------------- | ---------------------------- |
| `ERROR`     | Red, Bold        | Connection errors            |
| `WARNING`   | Yellow           | Testing state, batch progress|
| `SUCCESS`   | Green            | Connected status             |
| `HINT`      | Gray             | Footer hints, placeholder text|

### Core Type Colors

| Core       | Color  |
| ---------- | ------ |
| xray-core  | Blue   |
| sing-box   | Green  |
| Auto       | White  |

---

## Automated Testing with tui-test

The `tui-test` MCP tools drive leas programmatically for automated testing.
All tools operate on a session identified by `session_id` (default `"default"`).

### Tool Reference

#### Session lifecycle

| Tool                      | Purpose                                      |
| ------------------------- | -------------------------------------------- |
| `launch_tui`              | Start `target/release/leas` in buffer mode|
| `close_session`           | Kill subprocess and clean up                 |
| `get_session_info`        | PID, uptime, command, mode                   |
| `list_sessions`           | All active sessions                          |

Launch the TUI:

```
launch_tui(
    command: "target/release/leas",
    mode: "buffer",
    dimensions: "120x36",
    session_id: "smoke-test"
)
```

#### Waiting and synchronizing

Always wait for the screen to stabilize after any action.

| Tool                       | When to use                                  |
| -------------------------- | -------------------------------------------- |
| `wait_for_stable`          | After every key press or state change        |
| `expect_text(pattern)`     | Block until text appears (async operations)  |
| `wait_for_change(ref)`     | Poll until screen differs from a snapshot    |

```
# After launch, wait for the UI to render
wait_for_stable(session_id: "smoke-test")

# Wait for an async subscription download
expect_text(pattern: "Groups", timeout: 15)
```

#### Reading screen state

| Tool                     | When to use                                  |
| ------------------------ | -------------------------------------------- |
| `capture_screen`         | Full terminal text for debugging             |
| `assert_contains(text)`  | Pass/fail assertion for substring            |
| `get_line(row)`          | Single row content (pixel-perfect layout)    |
| `get_char(row, col)`     | Single character at position                 |
| `get_screen_region(...)`  | Rectangular region of the buffer             |
| `assert_at_position(text, row, col)` | Assert text at exact position |

```
# Verify the Profiles tab header
assert_at_position(text: " Profiles ", row: 0, col: 1)

# Verify status bar shows disconnected
assert_contains(text: "Disconnected")

# Check speed test menu rendering
let third_line = get_line(row: 5)
# Expect "  Speed Test (Selected)" or "► Speed Test (Selected)"
```

#### Sending input

| Tool                   | When to use                                  |
| ---------------------- | -------------------------------------------- |
| `send_keys(text)`      | Type text; `\r` = Enter, `\t` = Tab, `\x1b` = Esc |
| `send_special_keys(keys)` | Arrow keys, function keys, Home/End, Page Up/Down |
| `send_ctrl(key)`       | Ctrl+letter (e.g. `"c"` Ctrl+C, `"v"` Ctrl+V) |

Rules:
- Use `send_special_keys(["down"])`, NOT `send_keys("\x1b[B")` for arrows
- Use `\r` for Enter (raw-mode TUI apps require `\r` not `\n`)
- Use `inter_key_delay: 0.02` for reliable character-by-character typing of long strings
- Always call `wait_for_stable` after sending keys

#### Example: Full smoke test

```
# Start
launch_tui(
    command: "target/release/leas",
    mode: "buffer",
    dimensions: "120x36",
    session_id: "smoke"
)

# Wait for initial render
wait_for_stable(session_id: "smoke")

# Verify initial state
assert_contains(text: "Profiles")
assert_contains(text: "Disconnected")

# Cycle through all 4 tabs
send_special_keys(session_id: "smoke", keys: ["tab"])
wait_for_stable(session_id: "smoke")
assert_contains(text: "Settings")

send_special_keys(session_id: "smoke", keys: ["tab"])
wait_for_stable(session_id: "smoke")
assert_contains(text: "Logs")

send_special_keys(session_id: "smoke", keys: ["tab"])
wait_for_stable(session_id: "smoke")
assert_contains(text: "Statistics")

send_special_keys(session_id: "smoke", keys: ["tab"])
wait_for_stable(session_id: "smoke")
assert_contains(text: "Profiles")

# Open help
send_keys(session_id: "smoke", keys: "?")
wait_for_stable(session_id: "smoke")
assert_contains(text: "Keyboard Shortcuts")

# Close help
send_keys(session_id: "smoke", keys: "\x1b")
wait_for_stable(session_id: "smoke")

# Quit
send_ctrl(session_id: "smoke", key: "q")
wait_for_stable(session_id: "smoke")

# Cleanup
close_session(session_id: "smoke")
```

#### Example: Subscription import

```
launch_tui(
    command: "target/release/leas",
    mode: "buffer",
    dimensions: "120x36",
    session_id: "sub-test"
)
wait_for_stable(session_id: "sub-test")

# Open Subscriptions (Settings -> Subscriptions)
send_keys(session_id: "sub-test", keys: "g")
wait_for_stable(session_id: "sub-test")
assert_contains(text: "Subscriptions")

# Add group: press 'a'
send_keys(session_id: "sub-test", keys: "a")
wait_for_stable(session_id: "sub-test")
assert_contains(text: "Group")

# Type group name
send_keys(session_id: "sub-test", keys: "My Group", inter_key_delay: 0.02)
# Tab to URL field
send_special_keys(session_id: "sub-test", keys: ["tab"])
# Type URL
send_keys(session_id: "sub-test", keys: "https://example.com/sub", inter_key_delay: 0.02)
# Save
send_keys(session_id: "sub-test", keys: "\r")
wait_for_stable(session_id: "sub-test")

# Select group and update
send_special_keys(session_id: "sub-test", keys: ["down"])
send_keys(session_id: "sub-test", keys: "u")
expect_text(session_id: "sub-test", pattern: "Profiles", timeout: 15)

# Back to settings menu (Esc), then quit the app
send_keys(session_id: "sub-test", keys: "\x1b")
wait_for_stable(session_id: "sub-test")

close_session(session_id: "sub-test")
```

#### Example: Speed test (with connected core)

```
launch_tui(
    command: "target/release/leas",
    mode: "buffer",
    dimensions: "120x36",
    session_id: "speed-test"
)
wait_for_stable(session_id: "speed-test")

# Connect (assumes a profile exists and is selected)
send_ctrl(session_id: "speed-test", key: "\r")
expect_text(session_id: "speed-test", pattern: "Connected", timeout: 15)

# Open speed test menu
send_keys(session_id: "speed-test", keys: "t")
wait_for_stable(session_id: "speed-test")
assert_contains(text: "Speed Test")
# Select first test (Fast Ping) and run
send_keys(session_id: "speed-test", keys: "\r")
wait_for_stable(session_id: "speed-test")

close_session(session_id: "speed-test")
```

### Important notes

- Always wait for the screen to stabilize (`wait_for_stable`) after every action
- Prefer `send_special_keys` over raw `\x1b` sequences for arrow/function keys —
  raw escape sequences are unreliable in buffer mode
- Use `inter_key_delay: 0.02` for reliable character-by-character typing of
  long strings (URLs, names)
- Always call `close_session` at the end to clean up the subprocess
- Use 10s+ timeout for slow operations (subscription fetch, speed test) via
  `expect_text` or `wait_for_stable(timeout: 10)`
- `send_keys` uses `\r` for Enter (not `\n`)
- For delete confirmation dialogs: `y`/`n` are plain key presses, use
  `send_keys("y")` or `send_keys("n")`
- Check `get_session_info` for quick debugging: PID, uptime, dimensions

## Purgatory (view `p`)

`p` cycles **Active → Purgatory → All**.

- **Active** is the effective-profiles list: it shows profiles confirmed live
  and recent (newest live link within `purgatory.ttl_days`, default 7), and it
  does not load purged links at all — a profile whose every link is purged is
  simply absent.
- **Purgatory** is everything else: links whose newest live link aged past the
  TTL, plus every profile whose links all carry a purge verdict — including one
  confirmed by its subscription *today*. This is where a purged link can be
  re-proved by hand.
- **All** shows every profile and every link.

**Purge verdicts.** A real (Real Ping) probe that returns permanent evidence
retires its link: a REALITY server answering with a real certificate
(`[mitm]`), a certificate the configured name cannot match (`[cert]`) or that
has expired (`[expired]`), a port answering cleartext (`[notls]`), a config
that can never dial (`[cfg]`), the proxy's own handshake answering 4xx/3xx
(`[http]`), or a CDN origin error 530/521/522/526 (`[origin]`). Timeouts, TLS
alerts, framing failures, rate limits and the client-side `not testable by the
native engine` marker are deliberately **not** verdicts.

Run **Real Test** on a purged row in Purgatory and a success clears the verdict,
returning the link to Active. The verdict outlives the error-marker TTL
(`error_ttl_hours` never clears it) and the sweep deletes the profile only after
`purgatory.retention_days` (default 30) with no upstream confirmation.
