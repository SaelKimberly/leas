# leas manual

How to drive the leas terminal interface: the shell, every screen, every key, and
the workflows that string them together. It does not cover the crate layout
([architecture](../architecture/architecture.md)), the database schema
([database](../reference/database.md)), share-URL parsing
([protocols](../reference/protocols.md)), or the native core's internals
([native core](../reference/native-core.md)). Screen keys are verified against
`crates/leas/src/ui/` and the input handler in `crates/leas/src/ui/mod.rs`.

## What runs behind the interface

leas manages proxy connections through xray-core, sing-box, or the in-process
native core. The TUI writes JSON configs and owns the binary lifetime for the
subprocess backends; the native core runs in-process. Only one backend runs per
connection session, so switching profiles across backends stops one core and
starts the other.

## Shell

The window is two framed panes, a shell-level log row, and a status bar.

```
┌ 1: [Profiles]  Sniffer  Logs ───────────────────────────┐
│ …table, per-host traffic, or log viewer…                 │
├ 2: Details  Metrics  [Tasks] ────────────────────────────┤
│ …server facts + DB aggregates / metrics / job queue…      │
└ live log tail ───────────────────────────────────────────┘
└ status bar ──────────────────────────────────────────────┘
```

| Part | Tabs / behaviour |
| --- | --- |
| Pane 1 | `Profiles` (endpoint table), `Sniffer` (per-host traffic for the native session), `Logs` (core log viewer) |
| Pane 2 | `Details` (selected server's static facts plus DB aggregates), `Metrics` (connection status, traffic, native connection ring, core stats), `Tasks` (job queue) |
| Log row | Newest log line, between pane 2's bottom border and the status bar. It is outside pane 2's frame, so the pane stays a complete rectangle; it is dropped when pane 2 collapses to one row |
| Status bar | Connection state and mode on the left, contextual keys on the right (`## Status bar`) |

- Each pane carries an inline tab bar in its border title: pane index (`1:`/`2:`)
  and the active tab are accent-bold (`[Profiles]`), inactive tabs plain. The
  focused pane draws an accent border, the other a muted one.
- Pane 2's default height is 16 rows on every tab, so switching tabs never
  resizes. `Alt+↑`/`Alt+↓` resizes it in steps of two rows, clamped to
  `3..term_height/2` and to leave pane 1 at least 6 rows; the height is
  session-only.
- Terminals under 20 rows always collapse pane 2 to the one-line compact bar.
- Settings is a popup (`,`), not a tab. Overlays (help `?`, speed-test menu `t`,
  export `Ctrl+E`, add/edit/import forms, delete confirmation) render on top of
  the shell, and only the top-most consumes keys.

## Screens

### Profiles

The endpoint table. One row per endpoint; multi-protocol endpoints expand into a
per-link panel.

| Column | Width | Content |
| --- | --- | --- |
| (status) | 2 | Connection status or test indicator; also carries the expand chevron in its gap cell |
| `Flag` | 5 | Inbound country as `<flag emoji> <ISO>` (e.g. `🇳🇱 NL`) when the terminal renders flag emoji, bare `<ISO>` when it does not (`LEAS_NO_FLAGS`/`NO_EMOJI` force the fallback); `—` unknown |
| `Address` | 30 | Host, full width. A DNS name whose subdomain overflows elides the subdomain's tail, keeping the registrable domain (`jp-tyo-05….synthetic-node.example`); IP literals right-truncate with `…` |
| `Port` | 6 | Port, right-aligned. Green when it is a conventional mimic port for the representative link's transport: `tcp`/`ws`/`httpupgrade` → any web port (`80`, `443`, `8080`, `8443`, `8880`, `2052`/`2053`, `2082`/`2083`, `2086`/`2087`, `2095`/`2096`); `grpc`/`http`/`xhttp`/`quic`/`kcp` → the TLS set (`443`, `8443`, `2053`, `2083`, `2087`, `2096`). Display hint only; it never affects ordering or testing |
| `White` | 9 | Whitelist membership tokens: `SNI` / `CIDR` / `SNI+CIDR` / `—`. A DNS-unresolved endpoint is reported in the `Real` cell as `[name]` |
| `│` | 1 | Separator between `White` and `Protocol` |
| `Protocol` | 10 | Protocol kind (e.g. `vless`, `vmess`), right-aligned |
| `Config` | 14 | Transport/security pair (e.g. `tcp/reality`), left-aligned; `~` marks a substituted ClientHello |
| `│` | 1 | Separator between `Config` and `Fast` |
| `Fast` | 6 | The transport measurement (e.g. ` 12`), coloured green below 500 ms, yellow at 500 ms or more, red at 1000 ms or more. Independent of `Real`: a row whose transport answered but whose config did not shows a number here beside `Real`'s failure marker. A row with no transport measurement shows blanks. A `[fast]` marker in `Real` suppresses the number, because the marker means the transport did not come up |
| `Auth` | 4 | The config's acceptance flag from the probe's protocol phase: `✓` accepted, `✗` positive rejection evidence (EOF during the VLESS response-header peel, an auth error, a framing error), `·` the family has no server ack (Trojan, classic-AEAD SS) or the engine cannot serve the row, `?` an ack was possible but not observed in time. Blank means never observed, which is not the same fact as `?`. Never changes the row's place in the order |
| `Real` | 7 | The real probe's delay (e.g. ` 12`), coloured as `Fast`. Red problem labels: `[name]` (DNS unresolved), `[n-a]` (the native engine cannot serve this row, so no probe ran), `[fast]`/`[real]`. A marker appears only when the active/preferred link has no measured delay; a measurement always wins over a stale marker, and real beats fast. `[name]` is suppressed when the row carries a transport measurement, because that probe dialled the name successfully and the measurement is the fresher fact |
| `Stab` | 7 | The representative link's stability ring as `successes/attempts` (e.g. `14/16`; `—` no samples). Coloured by success rate: green at 80% or more, yellow at 50% or more, red below; dashed when there are no samples |
| `Streak` | 6 | Consecutive successful real probes at the newest end of the representative link's ring. Shown only for endpoints that are currently `Alive`; blank otherwise and whenever the link carries a real/name error |
| `Speed` | 7 | The representative link's peak download rate in MiB/s, one decimal (e.g. `12.3`), from `Speed Test (Successful)`; blank when never measured. Neutral colour: a speed number says nothing about the link's health |
| `│` | 1 | Separator between `Speed` and `Out` |
| `Out` | 5 | Exit country flag, same idiom as `Flag`; `—` unknown |
| `Exit` | 14 | Exit IP of the active link's persisted real ping (`—` none); survives reruns |

The three `│` cells are the only decorative separators; every other cell
carries the header role. There is no sort arrow: page order is always the
ordering law ([ordering law](../reference/ordering-law.md)), where the `Alive` band (0)
leads `Active` (1), which leads `Purgatory` (2).

**Expandable endpoints.** An endpoint with more than one protocol variant shows
`▸` (collapsed) or `▾` (expanded) in the status column's gap cell. `→` expands:
a rounded panel opens under the row with an `IPs:` line (resolved inbound
addresses; `[?]` and an `(x resolve)` hint while the DNS name is unresolved)
plus a per-protocol sub-table.

- The sub-table's labels sit on the separator line under the IPs row: `ID`,
  `Last Seen`, `Last Used`, `Protocol`, `Config`, `Delay`, `Speed`, `Traffic`,
  `Outbound`, `Exit`, `Stab`.
- The panel border widens past the endpoint grid to fit them. On a narrow pane
  the trailing columns drop whole (never half-drawn) and the border follows the
  last shown column.
- At most 8 sub-rows are visible. Longer lists scroll: the window follows the
  selected sub-row and the separator shows the visible range (`6-13/23`).
- `→` lands on the first sub-row; `↑`/`↓` walk the variants. `↑` at the first
  sub-row returns to the endpoint row; `↓` at the last moves to the next
  profile; `↓` from the full row of an expanded endpoint re-enters the
  sub-table. `Enter` on a sub-row pins that protocol as the endpoint's default
  (a manual override). `←` collapses.

**Enrichment.** Inbound country, whitelist features, and outbound info are
computed in the background. `x` forces a DNS resolution of the selected
endpoint. DNS results are cached (TTL in Settings → Routing → DNS) and persist
across launches, so group updates and restarts do not re-resolve.

**Speed tests.** On a collapsed endpoint row with more than one protocol the
speed-test menu pings all protocols of the endpoint (endpoint-scoped batch); on
a panel sub-row it pings the exact protocol.

**Search.** `/` focuses the search field; typing filters by address and port.
`Esc` clears the filter and leaves search mode.

**Views.** `p` cycles `Active → Purgatory → All` (`### Purgatory`).

### Details (pane 2)

The selected server's static fact sheet plus the database's status. The selected
server is the pane-1 cursor row (`filtered_profiles().nth(selected_index)`), the
same law the footer and `Metrics` use, so a search filter cannot make the
surfaces disagree.

**Layout.** Three columns at 3:6:3, separated by single vertical rules:
`Server` (left), `Link` (middle), `DB` (right). Below 100 columns the facts
stack above the aggregate block.

```
Server         │ Link                          │ DB 74,012
  Address h:443│   Leas URL leas://1a2b/3c4d    │   proven    41,900
  Country NL   │   Protocol vless              │   untested  28,932
  Resolved IPs │   Transport tcp               │   failed     2,996
  Whitelist —  │   Security reality            │   other       184
               │   Last Seen …                 │
               │   Real Delay 120ms            │ alive       3,180
               │   …                           │ active      1,402
               │   Exit IP 1.2.3.4             │ reliable   12,004
               │   Last Error [real]           │
               │   Error Text …                │ View: Active / <query>
```

- **Server** holds the inbound identity: `Address` (`host:port`), `Country`,
  `Resolved IPs`, `Whitelist`.
- **Link** holds everything the representative link can explain: its `Leas URL`
  (`leas://<endpoint hex>/<protocol hex>`, the identity the Real Test log lines
  use), protocol config names (kind, transport, security, SNI, fingerprint; names
  only, no credentials or keys), timestamps, measurements, auth, speed,
  stability, traffic, exit IP and country, and the stored `Last Error` plus
  `Error Text` when one exists. That error text explains the grid's
  `[real]`/`[fast]`/`[name]` label.

**The `DB` column is two blocks, not one list.** The four partition counts
(`proven`, `untested`, `failed`, `other`) are pairwise disjoint and sum to the
total. `alive`, `active`, and `reliable` are orthogonal filters over the same
rows and overlap any partition member, so they are drawn as a separate block.

| Bucket | Meaning |
| --- | --- |
| `proven` | The endpoint has at least one live unpurged link with a real success |
| `untested` | Not proven, and never measured |
| `failed` | Not proven, and carrying a failure marker |
| `other` | Not proven and in no other bucket (measured, but the ring holds no success) |
| `alive` | The newest real probe succeeded and the endpoint is inside the TTL window (band 0). The global scope computes this live; the view scope uses the swept band, so it describes the set the table shows |
| `active` | Inside the TTL window but not alive (band 1); never overlaps `alive` |
| `reliable` | The representative link's success rate is 75% or more (at least 4 samples) |

**Sources.** `Server` reads the loaded row's persisted addresses, which is the
grid's own law; `endpoint_info` is a display cache that lags, so a missing entry
renders `—` and the panel never triggers a background fill. `Link` reads the
representative link, the same link the grid's `Real`/`Stab` cells describe.

### Metrics (pane 2)

One scrollable view: connection status, the connected session's traffic, the
native core's connection ring, and core system stats. It merges the former
Statistics and Native Activity screens; the pane frame supplies the border and
the sections are flat labelled rows.

```
status
  ○ Disconnected
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

- **status**: the connection indicator (`● Connected [xray]`, `⠋ Connecting...`,
  `⏹ Error: ...`, `○ Disconnected`).
- **session**: the connected profile's traffic (today and total, up and down from
  the link's persisted `profile_stats` plus the session delta). Shows
  `not connected — select a profile and press Ctrl+Enter` when nothing is
  connected.
- **native**: one line per connection of the in-process native core, with byte
  totals and lifetime; failures render in the error colour. With more rows than
  fit, a `rows N-M of T` line caps the window and `↑`/`↓` scroll.
- **core**: memory, routines, and uptime from the backend's gRPC/V2Ray API, plus
  the API endpoint. The native core reports an in-process event feed.

### Tasks (pane 2)

The job queue: the running task's progress bar on top, queued tasks below,
earliest first. The running task is the bar's label, not a list row, so its
progress is never drawn twice.

```
Real Test (Successful) 1,240/3,000 ~12m ━━━●──────────
  ► Fill Exit IPs (Successful)
    Compact Duplicate Endpoints
```

The bar is a `LineGauge` with a manual thumb at the fill boundary, themed from
the same tokens as the settings download bar. When nothing runs, the label names
the scheduler state: `paused — N queued, press r to resume`,
`no tasks — pick one from the Speed Test menu`, or `queued: …`.

**Keys are tab-scoped** (see the reference tables) so `d`, `s`, `r` do not collide
with the Profiles tab's delete or the global stop-test.

**Scheduling.** The Speed Test menu is the entry point: picking an item enqueues
it rather than starting it. A duplicate identity (`(kind, scope)` for batched
tasks, `(kind, test type, endpoint)` for the Selected variants) is ignored, so a
task can never be queued or re-armed while it runs. One job at a time is
structural: the scheduler is the only path into the spawn functions.

### Sniffer (pane 1)

Per-host traffic for the in-process native core, fed by a 1 s snapshot of the
session's accounting. With a subprocess core (xray-core or sing-box) or no
connection, the tab reads:

```
No native session — per-host traffic requires the native core
```

Top to bottom:

1. **Rates**: `↓ x/s  ↑ y/s` for the last second.
2. **Summary**: `hosts N · failed N · dropped N datagrams (bytes)`. Dropped
   counts undelivered UDP payloads (malformed, blocked, queue-full,
   unresolvable destination, carrier refusal); failed counts refused or failed
   TCP legs.
3. **Two mirrored sparklines**: down grows downward from the top line, up grows
   upward from the bottom line, over the last 60 s. Both share one scale, so the
   directions are comparable and a non-zero sample is never invisible.
4. **Host table**: `host · ↓ · ↑ · conns · failed`, sorted by total bytes
   descending. A host is the destination as the client sent it (domain or IP
   literal, no port); a proxied domain keeps its domain because the remote proxy
   resolves it.

Bytes only: TCP has no packet boundary, so a packet count would mean different
things per row. Totals are session-only and in memory; disconnecting freezes the
table and connecting again clears it.

### Logs (pane 1)

Live log output from the connected core, rendered frameless inside pane 1 (the
pane supplies the frame). With no output yet:

```
┌ Logs ───────────────────────────────────────────────────┐
│ No logs yet. Run a profile or wait for core output.       │
└──────────────────────────────────────────────────────────┘
```

The core's stdout (xray-core) and stderr (sing-box) arrive in real time; leas's
own `tracing` events land in the same buffer. A filter bar above the log area
shows the active target filter (`[T] Filter (all)` or `(N active)`) and the key
hints for the current mode.

| Level | Colour |
| --- | --- |
| error / fatal / panic | red bold (`Theme::ERROR`) |
| warning / warn | yellow (`Theme::WARNING`) |
| info | default terminal colour |
| debug / trace | gray (`Theme::HINT`) |

- The in-memory buffer holds the most recent 10,000 lines; older rows load from
  the database on demand as you scroll up.
- Scrolling is bottom-anchored: `log_scroll` counts rows up from the newest
  line, and the viewport is filled by a line budget, so a wrapped message
  consumes several rows and the window walks backward from the anchor until the
  pane's lines are spent. `PageUp`/`PageDown` page by the real pane height, not
  the terminal's.
- A single entry occupies at most 3 lines. The third line is truncated to fit and
  ends with `...`, so one long core line cannot push every other row out of view.
- `T` opens the target picker (`↑`/`↓` or `j`/`k` move, `Enter` applies, `t`/`q`/`Esc` closes).
- `y` copies the selected range when a selection anchor is set, else the cursor
  line; `Y` copies every filtered line. Selection is made with
  `Shift+↑`/`Shift+↓` and cleared with `Esc`.
- `c` clears the view (confirm), `Delete` purges the logs database (confirm), and
  `d` dumps the last 20 database-monitor lines plus a `mem:` line (process RSS
  and the size of every session-lifetime cache) into the log.

### Settings (popup)

`,` opens a centered modal (width `clamp(term-4, 50, 110)`, height
`clamp(term-2, 20, 40)`) over both panes. The shell keeps rendering behind it.
`Esc` closes; leaving a dirty form asks `Discard unsaved settings? (y/N)` first.
The popup carries its key hints in its bottom border; the app status bar shows
only the mode.

```
┌ Settings * ─────────────────────────────────────────────┐
│ ┌ Search ─────────────────────────────────────────────┐ │   filter / edit bar
│ │Press / to filter settings                          │ │
│ └─────────────────────────────────────────────────────┘ │
│ ┌ Sections · 2/20 ─────────┐ ┌ Values · 1/2 ──────────┐ │   section list / fields
│ │  ▾ Core                  │ │›* Servers (JSON)   x█  │ │
│ │›    Core Settings        │ │ · DNS Cache TTL    —   │ │
│ └──────────────────────────┘ └────────────────────────┘ │
│ ┌ Help · DNS ─────────────────────────────────────────┐ │   field help
│ │Type     Text                                        │ │
│ └─────────────────────────────────────────────────────┘ │
│ Saved DNS                                                │   status (errors/notice)
└────────────────── [Enter] Open  [Esc] Close ────────────┘
```

The right pane is never empty: the popup opens with the first section's settings
already showing, and moving the selection loads that section immediately. `Enter`
moves the cursor into the fields.

**Bands, top to bottom.**

1. **Filter / edit bar.** Idle it reads `Search` with `Press / to filter settings`;
   while filtering the title is `Filter` and the body is the query behind a `█`
   cursor; with a field focused it names what you are editing (`Edit Servers (JSON) · Text`).
   Its border is accented while active.
2. **Sections** (left, 30%) and **Values** (right). The titles count position:
   `Sections · n/N` counts display rows (group headers included), `Values · i/n`
   counts the open section's field rows. A group header carries `▾` when expanded
   and `▸` when collapsed; `←`/`→` toggles the group that owns the selection, and
   a collapsed group's header carries the highlight.
3. **Help** names the field under the cursor: `Field`, `Type`, `Accepts`,
   `Current`, plus the marker legend. It yields rows first on a short terminal so
   the lists keep their viewport.
4. **Status** appears only when it has something to say: the first validation
   error, a filter that matched nothing, or the last save.

**Value rows** are `›` (focused) + a provenance marker + the label + the value:
`·` when the value matches what the section was loaded with, `*` for an edit not
yet saved. Bools render `✓`/`✗`, an empty text field renders `—`, selects render
`< option >`, and a focused row ends with a `█` cursor.

**Selectors** (Log Level, the per-protocol core, **Theme**) advance on `Space` or
`Enter` and wrap past the last option; `←`/`→` step one option. Because `Enter`
belongs to the selector on those fields, `Ctrl+S` saves the section (`Enter`
still saves every other field type). Theme lists every builtin opaline slug, is
bound to the theme the app actually loads, and applies on save.

**Section tree (15 leaves in 5 groups):**

| Group | Leaves |
| --- | --- |
| Core | Core Settings, Protocol Core |
| Connection | Inbound, System Proxy, TUN, Mux |
| Routing | Routing Rules, Probe Hosts, DNS |
| GUI | GUI Settings |
| Advanced | Statistics, Updates, Speed Test, Logging, Subscriptions |

**Filter.** `/` starts a case-insensitive substring filter over the section list
(a leaf name or its group name). It never filters the Values pane. `Enter`
applies and leaves the query in place; `Esc` cancels and clears it; `Ctrl+U`
clears it while typing. A query that matches nothing says so in the status band.
A filtered list ignores collapsed groups, so a search reveals its own matches,
and a filter that moves the selection moves the Values pane with it. `/` is
claimed only where it cannot be text: the sections list, or the routing and
subscription list panes.

#### Routing Rules (Settings → Routing)

Two levels:

- **Routing list**: `↑`/`↓` navigate, `a` adds, `e` edits, `d` deletes (no
  confirmation), `Ctrl+↑`/`Ctrl+↓` move the selected rule one place and persist
  the whole order immediately.
- **Routing rule form**: `Tab`/`Shift+Tab` and `↑`/`↓` move between fields,
  `Enter` saves, `Esc` returns to the list.

#### Subscriptions (Settings → Advanced)

`g` on the Profiles tab jumps straight here. The list shows Name, URL
(truncated), Enabled, Status, and Last Updated.

| Key | Action |
| --- | --- |
| `a` | Add a group |
| `e` | Edit the selected group |
| `d` | Delete the selected group (`y` confirms) |
| `u` | Update every group's subscription |
| `Space` | Toggle the selected group's enabled mask |
| `Esc` | Return to the section list |

**Group form** fields: `name`, `subscription_url`, `user_agent`,
`update_interval`, `core_type`. `Tab`/`Shift+Tab` moves, `Enter` saves, `Esc`
cancels. `Ctrl+V` pastes the clipboard into the focused text field (crossterm's
Windows backend has no bracketed paste, so `Ctrl+V` is the only paste door there).

#### Updates (Settings → Advanced)

Shows the current and latest version of each backend. `C` checks, `D` downloads
every available update, `Esc` returns to the section list.

### Add and edit server

`a` adds (protocol picker first), `e` edits the selected endpoint, `c` clones it.

**Protocol picker** (add only), a scrollable list in two blocks:

| Backend | Protocols |
| --- | --- |
| Xray-core | VMess, VLESS, Shadowsocks, Shadowsocks-2022, SOCKS, HTTP, Trojan, WireGuard, Hysteria v2, Dokodemo-door, Freedom, Blackhole, DNS, Loopback, Custom |
| Sing-box only | TUIC, Hysteria v1, Naïve, AnyTLS, ShadowTLS, Tor, SSH, Tailscale, ShadowsocksR, Redirect |

**Parameter form.** Fields are text, number, boolean, or select. `Tab`/`Shift+Tab`
or `↑`/`↓` move, `Enter` saves and returns to the list, `Ctrl+S` also saves,
`Esc` cancels. In a field: typing appends, `Backspace` erases (on a boolean it
toggles, because there is no tail to erase), `Space` advances a select or
toggles a boolean, `←`/`→` step a select or toggle a boolean, and `-` is accepted
in number fields.

### Import and batch import

`Ctrl+V` on the Profiles tab reads the clipboard and sorts the payload:

- no share URL found: the import screen opens with
  `No valid share URLs found`;
- exactly one URL: the import screen opens with it filled in;
- more than one URL: the batch import screen opens directly.

The import screen is a bordered field titled
`Import URL — Ctrl+V paste, Enter parse, Esc cancel`; typing edits the URL,
`Enter` parses and adds the profile, `Esc` cancels, and a parse failure shows a
red error line.

The batch screen lists one result per URL with success or failure. `↑`/`↓`
scroll, `Enter` saves every successful import and returns to the list, `Esc`
cancels the whole batch.

### Speed test menu

`t` from the Profiles tab. Items, in menu order (separators between groups):

| Item | Scope |
| --- | --- |
| `Fast Test (Selected)` | Transport measurement only, with a TCP or UDP/QUIC adapter chosen from the protocol. Endpoint-scoped batch on a collapsed multi-protocol row, exact protocol on a sub-row |
| `Real Test (Selected)` | One probe through the proxy, producing the transport span (`Fast`) and the probe's own span (`Real`) |
| `Speed Test (Selected)` | Download a payload through the link |
| `UDP Test (Selected)` | UDP forwarding check |
| `Fast Test (All Profiles)` | Every (protocol, endpoint) link in the database, not the filtered view |
| `Real Test (All Profiles)` | One probe per link over the whole database |
| `Real Test (Successful)` | Endpoints that have achieved a real success |
| `Real Test (New)` | Endpoints nothing has answered for yet |
| `Real Test (Successful + New)` | Both of the above |
| `Real Test (Failed)` | Endpoints whose links all failed, including a DNS name that never resolved |
| `Speed Test (Successful)` | Downloads the configured file through each Successful-band link's own native tunnel and stores the peak one-second-windowed rate in `Speed` (MiB/s) |
| `Fill Exit IPs (Successful)` | Fetches the exit IP and country for Successful-band links on its own rate limiter |
| `Remove Bad Servers` | Immediate removal of failed profiles |
| `Retry Failed DNS Lookups` | Re-resolves every DNS-name endpoint whose address set is empty, bypassing the TTL; Purgatory included |
| `Compact Duplicate Endpoints` | Merges provably identical endpoints |
| `Stop Testing` | Cancels the running task and pauses the queue |
| `Clear All Stats` | Immediate, confirmed |

Behaviour:

- `↑`/`↓` navigate and skip separators; `Enter` enqueues (or runs an immediate
  one-shot); `Esc` closes; `?` opens help.
- `Stop Testing` is enabled exactly while the scheduler is busy. `Remove Bad
  Servers` and `Clear All Stats` are immediate with a `y/n` confirmation and are
  disabled while anything runs or queues.
- The "All Profiles" entry points test the whole database, so a filtered or paged
  view does not narrow a run. Only links imported after the run starts can be
  missed.
- A scoped run freezes its endpoint list before the first probe, so an endpoint
  leaving the scope mid-run is still tested.
- **One probe, two measurements.** The Real Test is one probe per link producing
  the transport span (time to establish the endpoint's transport, the `Fast`
  column) and the real span (the probe's own request time, the `Real` column).
  They do not overlap, and the transport span survives a failure: a row whose
  server answered but whose config did not shows `12` in `Fast` and `[real]` in
  `Real`. A row with a transport failure has neither measurement.
- **Links of one endpoint are probed one at a time.** The walk order is
  `PageSort::Test` and an endpoint's links are contiguous in it. At the group
  entry the first protocol is probed and the siblings wait for the verdict: on
  success the group is dropped (no probe, marker, delay, or exit IP for any of
  its links); on failure the siblings are probed too, each writing its own
  marker. There is no second barrier and no cancel-on-winner.
- **Speed Test (Successful)** needs no connected core and no local SOCKS hop. It
  tests only links that are currently passing (no marker and a measured real
  delay), runs the download under its own maximum duration, and retries only
  after a failed attempt. A failed download is counted in the batch summary and
  never marks or purges a link: an unreachable target says nothing about the
  config, and a slow link is not a dead one.
- **Fill Exit IPs (Successful)** has its own rate limiter because the free
  IP-API tiers publish roughly 45 requests/minute. It writes the exit IP and
  country and never the real delay; the two are independently aged facts. Its
  own progress bar in Details is labelled `Look` and counts
  `N ok, N failed, N retryable`.
- **Retry Failed DNS Lookups** re-resolves every DNS-name endpoint whose address
  set is empty, including Purgatory rows; the log reports how many lookups were
  dispatched.
- **Compact Duplicate Endpoints** merges endpoints with the same port, a shared
  protocol config, and an overlapping resolved-address set. The DNS host survives
  an IP-literal duplicate; two DNS hosts keep the older row. The survivor keeps
  its own purge verdicts; the absorbed side's addresses, group memberships and
  measured evidence move over; rank keys are recomputed in the same transaction.
  There is no undo. An endpoint with a live connection is skipped.
- Batch runs go through the per-profile task queue: one live test per profile,
  further tests queued FIFO up to `task_queue_limit` (default 3; `0` disables
  queueing). A full queue skips the profile with a warning. Profiles whose DNS
  failed recently are deferred by `dns_failure_defer_secs` (default 5 s). Both
  live in Settings → Advanced → Speed Test. Probe concurrency is
  `real_ping_concurrency`, the one limit, and it bounds the native handshakes.
- **Error labels** in `Real`: the label reflects the active/preferred link, and
  only when that link has no measured delay. Two exceptions outrank a stored
  delay: a protocol or config the native engine cannot test (`[real]` with the
  reason; such rows are never removed by Remove Bad Servers), and a purge verdict
  (`[mitm]`, `[cert]`, `[expired]`, `[notls]`, `[cfg]`, `[http]`, `[origin]`).
  Markers persist across restarts; `error_ttl_hours` (empty means never) clears
  them on profile reload and at batch finish.

### Export

`Ctrl+E` from the Profiles tab. Choose scope, then destination.

| Scope | Content |
| --- | --- |
| `Only Working` | Links with current real/fast success (canonical rank tiers 0/1); distinct from the `Alive` band |
| `Only Resolved` | Dialable endpoints; DNS endpoints emit one line per stored IP |
| `Only Active` | The exact current Active view |
| `All Valid` | All non-purged links, including aged/stale Purgatory rows |
| `Clipboard` | Copies raw subscription text through `arboard` |
| `File` | Writes raw subscription text through `tokio::fs` |

`↑`/`↓` navigate, `Enter` selects, `Esc` closes. Paths are editable; an existing
destination asks `[Y] Overwrite`. File export writes to the confirmed path and
does not claim success when the write fails (a partial file can remain). Output
has four metadata comment lines followed by one share URL per line:

```text
# profile-title: leas export • <Scope>
# profile-update-interval: 1
# Date/Time: YYYY-MM-DD / HH:MM (Moscow)
# Количество: <matching-links>

<one share URL per line>
```

`Количество` counts matching stored links before Resolved-IP expansion or
serializer skips; the log reports emitted and skipped counts separately.

### Help overlay

`?` opens a rounded modal listing shortcuts for the current context. `Esc` or `?`
closes it.

### Purgatory (view `p`)

`p` cycles **Active → Purgatory → All**.

- **Active** is the effective list: profiles confirmed live and recent (newest
  live link within `purgatory.ttl_days`, default 7). Purged links are not loaded
  at all, so a profile whose every link is purged is absent.
- **Purgatory** is everything else: links whose newest live link aged past the
  TTL, plus every profile whose links all carry a purge verdict, even one
  confirmed by its subscription today. This is where a purged link can be
  re-proved by hand.
- **All** shows every profile and every link.

**Purge verdicts.** A Real Test probe that returns permanent evidence retires its
link: a REALITY server answering with a real certificate (`[mitm]`), a
certificate the configured name cannot match (`[cert]`) or that has expired
(`[expired]`), a port answering cleartext (`[notls]`), a config that can never
dial (`[cfg]`), the proxy's own handshake answering 4xx/3xx (`[http]`), or a CDN
origin error 530/521/522/526 (`[origin]`). Timeouts, TLS alerts, framing
failures, rate limits, and the client-side `not testable by the native engine`
marker are not verdicts.

Run a Real Test on a purged row and a success clears the verdict. The verdict
outlives `error_ttl_hours`; the sweep deletes the profile only after
`purgatory.retention_days` (default 30) with no upstream confirmation. `r` on a
Purgatory row restores it immediately.

## Status bar

The bottom row. Left: mode prefix, then connection state. Right: contextual keys.

| State | Display |
| --- | --- |
| Connecting | `⠋ Connecting...` (spinner, yellow) |
| Stopping | `■ Stopping...` (red) |
| Running task | `<task label>: <done>/<total>`, or `<task label> …` with no total (yellow) |
| Testing | `Testing...` or `Testing: <done>/<total>` (yellow) |
| Maintenance | `Maintenance...`, `Name: n/N`, `Comp: n/N`, or both (yellow) |
| Error | `Error: <message>` (red bold) |
| Disconnected | `Disconnected` (red) |
| Connected | `Connected [xray]` / `Connected [sing-box]` / `Connected [native]` (green) |

Mode prefixes: none in List mode, then `Settings`, `Settings > Core`,
`Settings > Routing`, `Settings > Updates`, `Settings > Subscriptions`,
`Add Server`, `Edit Server`, `Speed Test`, `Export`, `Export File`,
`Batch Import`, `Help`.

Indicators: `⇧Update:xray,sing-box` (yellow bold) when installed backends have
updates, and `⇩<name> <pct>%` while a backend downloads. The Settings popup's
own title reads `Settings *` while a form is dirty.

Hints by context:

| Context | Hints |
| --- | --- |
| Pane 1 · Profiles (no rows loaded) | `[a] Add  [Ctrl+V] Import  [,] Settings  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 1 · Profiles (connecting) | `[,] Settings  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 1 · Profiles (connected) | `[Ctrl+D] Disconnect  [,] Settings  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 1 · Profiles (rows loaded) | `[→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [,] Settings  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 1 · Profiles (filtered-empty) | `No match for "<q>"  [Esc] Clear  [q/Ctrl+C] Quit` |
| Pane 1 · Profiles (filter applied) | `[Esc] Clear filter  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 1 · Sniffer | `[↑↓] Scroll  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 1 · Logs | `[↑↓] Scroll  [c] Clear  [t] Targets  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 2 · Metrics | `[↑↓] Scroll  [Alt+↑↓] Resize  [1] Pane 1  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 2 · Details | `[↑↓] Scroll  [F1] Compact  [1] Pane 1  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Pane 2 · Tasks | `[↑↓] Select  [d] Delete  [s] Stop  [r] Resume  [1] Pane 1  [Tab] Pane  [?] Help  [q/Ctrl+C] Quit` |
| Confirm modal | `[y] Confirm  [n/Esc] Cancel` |
| Speed test menu | `[↑↓] Navigate  [Enter] Select  [Esc] Close` |
| Help overlay | `[Esc] Close help` |
| Export scope/destination | `[↑↓] Navigate  [Enter] Select  [Esc] Close` |
| Export overwrite | `[Y] Overwrite  [N] Cancel` |
| Export path | `[Enter] Write  [Esc] Cancel` |
| Add/edit/import form | `[Tab/Shift+Tab] Focus  [Enter] Save  [Esc] Cancel  [q/Ctrl+C] Quit` |
| Settings popup | none; its hints live in the popup's bottom border |

The Settings popup's own hint sets, drawn in its bottom border and not in the
status bar:

| Popup state | Hints |
| --- | --- |
| Section list | `[↑↓] Navigate  [←] Collapse  [→] Fields  [/] Filter  [Enter] Open  [Esc] Close` |
| Values pane (form, group form) | `[Tab/Shift+Tab] Field  [Space] Advance  [Ctrl+S] Save  [Ctrl+W] Sections  [Esc] Back` |
| Filtering | `[type] Filter  [Enter] Apply  [Ctrl+U] Clear  [Esc] Cancel` |
| Routing list | `[↑/↓] Navigate  [A] Add  [E] Edit  [D] Delete  [Ctrl+W] Sections  [Esc] Back` |
| Routing form | `[Enter] Save  [Ctrl+W] Sections  [Esc] Back` |
| Updates | `[C] Check  [D] Download  [Ctrl+W] Sections  [Esc] Back` |
| Subscription list | `[↑↓] Navigate  [Space] Select  [A] Add  [E] Edit  [D] Delete  [U] Update  [Ctrl+W] Sections  [Esc] Back` |

## Keyboard reference

One table per context. A key appears only in the context whose handler consumes
it. `q` and `Ctrl+C` quit from every main list screen; inside a form they are
typed (use `Esc` to leave, `Ctrl+C` to quit).

### Shell and panes

| Key | Action |
| --- | --- |
| `Tab` / `Shift+Tab` | Move focus between pane 1 and pane 2 |
| `1` / `2` | Focus pane 1 / pane 2 |
| `[` / `]` | Previous / next tab of the focused pane |
| `Alt+↑` / `Alt+↓` | Resize pane 2 by two rows (pane 2 focused; clamped 3..term/2) |
| `F1` | Toggle pane 2 between full and the one-line compact bar |
| `,` | Open the Settings popup (List mode) |
| `?` | Open help; `?` or `Esc` closes it |
| `q` / `Ctrl+C` | Quit (asks first while connected) |
| `Ctrl+D` | Disconnect the running core |
| `Ctrl+V` | Paste into the focused text field, or open the import screen on Profiles |

### Profiles tab

| Key | Action |
| --- | --- |
| `↑` / `↓` | Move the selection; inside an expanded endpoint, walk its variants |
| `PgUp` / `PgDn` | Page by `term_height - 5` rows |
| `Home` / `End` | First / last profile |
| `Ctrl+↑` / `Ctrl+↓` | Move the selected profile up / down |
| `→` | Expand the endpoint, or enter the sub-table |
| `←` | Collapse the endpoint, or leave the sub-table |
| `Enter` | Set the selected endpoint active; on a sub-row, pin that protocol as default |
| `Ctrl+Enter` / `Ctrl+G` | Connect to the selected endpoint |
| `Space` | Toggle multi-select |
| `Ctrl+A` | Select every filtered profile |
| `a` | Add a server |
| `e` | Edit the selected server |
| `d` | Delete the selected server, or every multi-selected server (confirm) |
| `c` | Clone the selected server |
| `g` | Open Settings → Subscriptions |
| `t` | Open the speed-test menu |
| `s` | Stop the running speed test |
| `x` | Force a DNS resolution of the selected endpoint |
| `p` | Cycle the view: Active → Purgatory → All |
| `r` | Restore the selected row from Purgatory |
| `/` | Focus search |
| `Ctrl+V` | Import from the clipboard (batch screen when it holds several URLs) |
| `Ctrl+E` | Open the export menu |
| `Ctrl+Shift+S` | Copy the active link's share URL |

Search mode takes printable characters and `Backspace`; `Esc` clears the query
and leaves search mode.

### Logs tab

| Key | Action |
| --- | --- |
| `↑` / `↓` | Scroll one row |
| `PgUp` / `PgDn` | Page by the pane's visible rows |
| `Home` | Oldest loaded entry; loading continues to the true top |
| `End` | Newest entry |
| `Shift+↑` / `Shift+↓` | Extend the copy selection |
| `y` | Copy the selection, or the cursor line when nothing is selected |
| `Y` | Copy every filtered line |
| `Esc` | Clear the selection, else fall through |
| `T` / `t` | Open the target filter picker |
| `c` | Clear the log view (confirm) |
| `d` | Dump the last 20 database-monitor lines plus a `mem:` line (RSS + cache sizes) into the log |
| `Delete` | Purge the logs database (confirm) |

Target picker: `↑`/`↓` or `k`/`j` move, `Enter` applies, `t`/`T`/`q`/`Esc` closes.

### Sniffer tab

| Key | Action |
| --- | --- |
| `↑` / `↓` | Scroll the host table |
| `PgUp` / `PgDn` | Page by 10 rows |
| `Home` / `End` | First / last host |

### Details tab (pane 2)

| Key | Action |
| --- | --- |
| `↑` / `↓` | Scroll the `Link` column one row |
| `PgUp` / `PgDn` | Scroll five rows |
| `Home` | Top of the column |
| `End` | Bottom of the column (the render clamps) |

### Metrics tab (pane 2)

| Key | Action |
| --- | --- |
| `↑` / `↓` | Scroll the connection ring |
| `PgUp` / `PgDn` | Page the connection ring |
| `Home` / `End` | Oldest / newest connection |

### Tasks tab (pane 2)

| Key | Action |
| --- | --- |
| `↑` / `↓` | Move the cursor over the queued list |
| `d` | Delete the selected queued task (no confirmation; logged) |
| `s` | Cancel the running task and pause the queue |
| `r` | Resume the paused queue |

### Settings: section list

| Key | Action |
| --- | --- |
| `↑` / `↓` | Move the selection; the Values pane follows |
| `←` | Collapse the group that owns the selection |
| `→` | Expand a collapsed group, else focus the Values pane |
| `Enter` | Expand a collapsed group, else load the section and focus its fields |
| `Tab` / `Shift+Tab` | Focus the Values pane |
| `/` | Filter the section list |
| `Ctrl+W` | Toggle focus between the two panes |
| `Esc` | Close Settings |

### Settings: field (Values pane)

| Key | Action |
| --- | --- |
| `↑` / `↓` | Previous / next field |
| `Tab` / `Shift+Tab` | Next / previous field, wrapping |
| `Space` | Advance the focused selector (wraps) or toggle a boolean |
| `Enter` | Advance a selector; toggle a boolean; otherwise save the section |
| `←` / `→` | Step a selector one option; toggle a boolean |
| `Backspace` | Erase a character; on a boolean it toggles |
| `Ctrl+S` | Validate and save the section |
| `Ctrl+V` | Paste into the focused text field; selectors and booleans ignore it |
| `Esc` | Return focus to the section list; asks before discarding a dirty form |

### Settings: popup-wide keys

These apply wherever the popup is open and no text field owns the key:

| Key | Action |
| --- | --- |
| `Ctrl+W` | Toggle focus between the section list and the Values pane |
| `/` | Start a filter (only where it cannot be text: the section list, the routing list, the subscription list) |
| `Ctrl+C` | Quit (asks first while connected) |

## Common workflows

### Add a server manually

1. On Profiles, press `a`.
2. Pick a protocol with `↑`/`↓`, then `Enter`.
3. Fill the fields: `Tab` moves, typing edits.
4. Press `Enter` to save. The profile appears in the list.

### Import one or many share URLs

1. Copy subscription text containing one or more `vmess://`, `ss://`,
   `trojan://` (or other share) URLs.
2. On Profiles, press `Ctrl+V`. One URL opens the import screen; several open the
   batch screen.
3. `Enter` parses (single) or saves every successful result (batch).
4. Imports are deduplicated by content hash. A parse failure shows a red error.

### Run a speed test

1. Select an endpoint with `↑`/`↓` (or a variant inside an expanded row).
2. Press `t`, move with `↑`/`↓`, press `Enter`.
3. Watch the status bar (`<task>: <done>/<total>`) and the `Tasks` tab. `s` stops
   and pauses; `r` in Tasks resumes.

### Connect and disconnect

1. Select a profile and press `Ctrl+Enter` (or `Ctrl+G` where the terminal eats
   `Ctrl+Enter`).
2. The status bar shows the spinner, then `Connected [xray]` (or `[sing-box]`,
   `[native]`); `Metrics` starts reporting traffic.
3. `Ctrl+D` disconnects; the status bar returns to `Disconnected`.

### Manage subscription groups

1. On Profiles, press `g` to open Settings → Subscriptions.
2. `a` adds a group, `e` edits, `d` deletes (`y` confirms), `u` updates all.
3. `Esc` returns to the section list, `Esc` again closes Settings.

### Re-prove a purged link

1. Press `p` until the view reads `Purgatory`.
2. Select the row and run `Real Test (Selected)` from `t`.
3. A success clears the verdict and moves the link back to Active. `r` restores
   the row without testing.

## Theme

Every style is named in `crates/leas/src/ui/theme.rs` and resolved from the
loaded opaline theme: no hex and no `Color::*` literal sits in a render path.
The 28 core tokens and 14 styles opaline guarantees cover most roles; the roles
it does not name are registered on the theme at load time, so a user TOML can
still override them.

| Role | Style source | Used for |
| --- | --- | --- |
| `tab_selected` | `active_selected` | Active pane tab, connected row, status mode |
| `tab_deselected` | `muted` | Inactive tabs |
| `table_header` | `app.table_header` (`text.primary` on `bg.selection`, bold) | Grid header row |
| `table_row_selected` | `selected` | Selected grid row |
| `table_row_normal` | `text.primary` | Grid rows |
| `table_row_alt` | `app.table_row_alt` (`text.primary` on `bg.panel`) | Alternating rows |
| `table_row_connected` | `active_selected` | The connected endpoint's row |
| `panel_row_selected` | `text.primary`, background reset, bold | Selected sub-row inside an expanded panel |
| `test_delay_ok` / `test_delay_warn` / `test_delay_bad` | `success_style` / `warning_style` / `error_style` | `Fast`/`Real` delay thresholds |
| `container_border` | `unfocused_border` | Unfocused pane frames |
| `container_border_focused` | `focused_border` | Focused pane frame |
| `container_title` | `keyword` | Pane titles and group headers |
| `status_bar_bg` | `app.statusbar` (`text.primary` on `bg.selection`) | Status bar fill |
| `status_bar_mode` | `active_selected` | Mode prefix |
| `status_bar_hint` | `app.statusbar_hint` | Right-side key hints |
| `progress_bar` | `app.progress_bar` | Progress bar track |
| `progress_fill` | `app.progress_fill` (`accent.primary` on itself) | Progress bar fill |
| `spinner` | theme spinner | Connecting indicator |
| `error` / `warning` / `success` / `hint` | `error` / `warning` / `success` / derived muted | Semantic text |
| `dialog` | `app.dialog` (`text.primary`, no fill) | Modals and the Settings popup |
| `badge` | `app.badge` (`error` on `bg.elevated`) | Error badges |

The hint role is derived rather than taken from `text.muted`: on a light theme
`text.muted` computes to 2.72:1 on the selection background, and no Latte token
reaches 4.5:1 there. The derivation walks the colour until it clears 4.6:1
against the strip it sits on, and leaves a user TOML able to override the result.
Modals deliberately share the app background, with only the border separating
them; a `bg.elevated` fill earlier made every dialog read as a slab of colour.

`Theme::load` takes a kebab-case slug. An unknown slug is an error, not a silent
fallback: `unknown theme \`<slug>\``.

## Automated testing

Scenarios drive the real binary through the `tui-test` MCP server. A scenario is
a markdown document in `tui/` whose script block is parsed, not
executed: bare step calls with literal arguments only
([the scenario index](tui/INDEX.md) lists the existing scenarios and
[the Details scenario](tui/2026-10-23-scenario-details-panel.md) is a compact example).

### Steps

| Step | Maps to | Notes |
| --- | --- | --- |
| `launch(cmd, mode="buffer", dimensions="120x40", timeout=30)` | `launch_tui` | Pin `env TERM=xterm-256color LC_ALL=C` in the command |
| `send("text", delay=0.3)` | `send_keys` | Literal text; `\n` warns on buffer launches, raw-mode Enter is `\r` |
| `key("down", "enter")` | `send_special_keys` | Special-key vocabulary: arrows, `home`, `end`, `pageup`, `pagedown`, `tab`, `enter`, `escape`, `f1`.. |
| `ctrl("o")` | `send_ctrl` | One Ctrl chord |
| `expect("regex", timeout=5)` | `expect_text` | Regex, validated at lint time: `[` and `(` are metacharacters |
| `assert_text("literal")` | `assert_contains` | Literal substring |
| `assert_at("text", row=1, col=0)` | `assert_at_position` | Exact cell position |
| `line(row=1)` | `get_line` | Rows and columns are 0-indexed screen coordinates |
| `region(0, 4)` | `get_screen_region` | Rectangular read |
| `char`, `cursor`, `capture`, `stable`, `change`, `info`, `sessions` | the matching read/wait tools | `stable` = `wait_for_stable` |
| `style(row, col)` | `get_cell_style` | The only way to read colour; text reads carry none |
| `shot(path=...)`, `gif(frames=[...])` | `screenshot`, `gif` | For anything colour, focus, or motion |
| `resize("80x24")` | `resize` | Delivers SIGWINCH mid-session |
| `close()` | `close_session` | Required teardown |

`run_scenario(script=<document>, session_id=<label>)` lints and then executes;
lint with `dry_run=True` first. `session_id` is not a script argument. A
`choice({...})` epilogue of `expect`/`assert_text`/`assert_at` is allowed only at
the very end.

### Harness rules that bite

- **`assert_text` is a literal match; `expect` is a regular expression.** A
  pattern with literal brackets (`2: [Details]  Metrics`) cannot go through
  `expect`, and `expect` needs its metacharacters escaped.
- **Send one key per call.** A list of keys in a single call over-delivers (a
  six-`down` list moved eight rows), so write `key("down")` once per press.
- **`Esc` goes through `key("escape")`.** A raw `\u001b` byte is swallowed and the
  keypress silently becomes the next `Enter`.
- **Enter is `\r` in `send`.** `\n` is not the raw-mode Enter key.
- **`wait_for_stable` (or `expect`) after every action.** Reads taken immediately
  after a keystroke can show the previous frame.
- **`wait_for_change` wants bare buffer text.** A `capture()` result carries a
  header and a 60-character `=` rule that must be sliced off before reuse.
- **Text reads lose colour and trailing whitespace.** Use `style(row, col)` for
  colour claims and `preserve_format=True` or `char(row, col)` for geometry.
- **Use 10 s or more as the timeout** for subscription downloads and speed
  tests.
- **Close the session.** `close()` at the end (or `keep_alive=False`), and check
  `sessions()` afterwards; a leftover session blocks its id.

### Minimal scenario

```python
launch("env TERM=xterm-256color LC_ALL=C target/debug/leas", mode="buffer", dimensions="120x40", timeout=30)
expect("Profiles", timeout=10)
assert_text("1: [Profiles]")          # literal: expect() would read [Profiles] as a class
key("tab")                            # one key per call
expect("2: [Details]")
send(",")                             # the Settings popup, not a tab
expect("Sections · 2/20")
key("escape")
send("?")
expect("Keyboard Shortcuts")
key("escape")
close()
```
