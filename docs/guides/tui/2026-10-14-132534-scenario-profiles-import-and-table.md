---
name: profiles-import-and-table
description: leas Profiles tab from the empty state through a clipboard batch import (8 share URLs → 7 endpoints) to the populated table and an expanded multi-variant endpoint
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [profiles, import, table, empty-state, expand]
---

# Scenario: profiles-import-and-table

| Field | Value |
|---|---|
| Run at | 2026-10-14 13:25:34 +0500 |
| App under test | leas 0.1.0, debug binary `/home/user/oss/xray-tui/target/debug/leas` (built 2026-10-14 12:57:36, md5 `13e132f2f7abb5e376ce477504709b93`) |
| Launch command | `env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/profiles-core/config /home/user/oss/xray-tui/target/debug/leas` |
| Session / mode / size | `profiles-import-and-table` / buffer / 120x40 |
| Harness | mcp-tui-test 0.3.0 (`/home/user/oss/mcp-tui-test`), Python 3.14.7, pyte 0.8.2 |
| Evidence | [2026-10-14-132534-scenario-profiles-import-and-table-transcript.md](2026-10-14-132534-scenario-profiles-import-and-table-transcript.md) |

## Purpose and scope

Proves the first-run path a new user meets: the empty Profiles tab, the clipboard batch import,
and the resulting table (which merges two links that share `host:port` into one expandable
endpoint). It covers geometry and wording of those four surfaces.

Does not cover: colour/ANSI (buffer-mode reads are text-only — see *Tooling friction*), the network
path of an import, or the Settings/Logs/Statistics tabs.

## Environment and fixtures

Fixture root: `docs/guides/tui/fixtures/`.

```bash
R=/home/user/.cache/leas-tui/profiles-core
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"     # app config; no data.db → empty store
```

The clipboard must hold `docs/guides/tui/fixtures/import-urls.txt` (8 synthetic share URLs; no real
credentials) before the `ctrl("v")` step — `Ctrl+V` is the app's only entry into the import screen and
a tui-test scenario has no clipboard step. Set it with the `set_clipboard` MCP tool, content = that
file, or `xclip -selection clipboard < docs/guides/tui/fixtures/import-urls.txt`.

Launching with an empty store makes the app create `data.db` itself, so the scenario is idempotent:
delete `$R` and it replays from the empty state.

Pinned by the harness: `TERM=xterm-256color`, `LC_ALL=LANG=LANGUAGE=C`. Network is reachable but not
required for these steps (enrichment only adds the unasserted country/flag columns).

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | launch | Profiles tab bar `○   Profiles    Settings    Logs    Statistics    Native Activity    Actions`; empty state ` No profiles — press 'a' to add one` |
| E2 | `line(1)` | row 1 = ` View: Active [P]   /  (press / to search)` (view cycle hint + search placeholder in one row) |
| E3 | `line(30)` | row 30 = ` Server: (none selected)` — the content area's last row (rows 1–30; actions panel 31–38; status bar 39) |
| E4 | `ctrl("v")` | `┌ Batch Import ─…` popup with ` 8 valid, 0 invalid — Enter to import, Esc to cancel` |
| E5 | `line(10)`, `line(12)` | row 10 = the valid/invalid summary; row 12 = first URL, head-truncated with `…` (the `#name` fragment is off the visible 114 columns) |
| E6 | `key("enter")` | table footer ` Server: 203.0.113.77:443  [xray]  rows 1-7 of 7` — 8 links became 7 endpoints |
| E7 | `line(3)` | header row shows `#`, `Address`, `Feat`, `Protocol Info`, `Test ↑`, `Outbound`, `Country` |
| E8 | `line(4)`, `line(10)` | row 4 = the IP endpoint `203.0.113.77:443` with an empty `[    ]` Feat cell and a blank Test cell; row 10 = last endpoint `us-nyc-04.synthetic-node.example` |
| E9 | `down`, `right` | the multi-variant endpoint expands to `▾` plus a rounded panel with `│ IPs: [?]` and `(x resolve)`, separator, then one sub-row per protocol variant (`●  71fc29f5 … tcp/reality`, `○  62eefde5 … ws/tls`) |
| E10 | `line(6)` | the sub-panel's right border sits inside the table's scrollbar column, rendering `╮█│` (panel narrower than its parent row) |

## Scenario script

```python
launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/profiles-core/config /home/user/oss/xray-tui/target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)
expect("No profiles", timeout=20)
line(row=0)
line(row=1)
line(row=2)
line(row=30)
ctrl("v")
expect("Batch Import", timeout=10)
line(row=10)
line(row=12)
key("enter")
expect("rows 1-7 of 7", timeout=20)
line(row=3)
char(row=3, col=4)
char(row=4, col=9)
line(row=4)
line(row=10)
key("down")
key("right")
expect("IPs:", timeout=5)
line(row=5)
line(row=7)
line(row=9)
line(row=11)
line(row=6)
close()
```

## Observed behaviour

| ID | Verdict | Evidence (verbatim excerpt + transcript step) |
|---|---|---|
| E1 | PASS | step 3 `Line 0 (session: profiles-import-and-table):  ○   Profiles    Settings    Logs    Statistics    Native Activity    Actions`; step 5 `Line 2 …:                                            No profiles — press 'a' to add one` |
| E2 | PASS | step 4 `Line 1 …:  View: Active [P]   /  (press / to search)` |
| E3 | PASS | step 6 `Line 30 …:  Server: (none selected)` |
| E4 | PASS | step 8 `✓ Found expected text: 'Batch Import'`; step 9 `Line 10 …:  │ 8 valid, 0 invalid — Enter to import, Esc to cancel                                                                │` |
| E5 | PASS | step 10 `Line 12 …:  │ ✓ vless://11111111-1111-4111-8111-111111111111@nl-ams-01.synthetic-node.example:443?encryption=none&security=rea…  │` |
| E6 | PASS | step 12 `✓ Found expected text: 'rows 1-7 of 7'` |
| E7 | PASS | step 13 `Line 3 …: │   #           Address                             Feat    Protocol Info              Test ↑  Outbound        Country█│` |
| E8 | PASS | step 16 `Line 4 …: │        1 [🏴   203.0.113.77:443                 ][    ]=>{   vless/tcp/reality    }=>       [—               —      █│`; step 17 `Line 10 …: │        7 [🏴   us-nyc-04.synthetic-node.example ][🏁  ]=>{      ss/tcp/none       }=>[name] [—               —      █│` |
| E9 | PASS | step 21 `Line 5 …: │▾       2 [🏴   nl-ams-01.synthetic-node.example ][🏁  ]=>{   vless/tcp/reality    }=>[name] [—               —      █│`; step 22 `Line 7 …: ││ IPs: [?]                                                                                               (x resolve)│█│`; step 23 `Line 9 …: ││●  71fc29f5 2026-10-14 13:26:29 never      vless      tcp/reality    -       -      -         —               —    —█│` |
| E10 | PASS | step 25 `Line 6 …: │╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮█│`; step 24 `Line 11 …: │╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯█│` |

Column witnesses for the polish remarks (not part of the E table): step 14 `Character at (3, 4): '#'`,
step 15 `Character at (4, 9): '1'`.

## Corrections to expectations

None — all ten expectations held on the first clean attempt. The documented run is the **third**
attempt: attempt 2 was a re-run of the same script against the fixture the first attempt had already
populated, and it failed at step 2 (`✓ Found expected text` never matched; the 20 s `expect('No
profiles')` timed out, 21.8 s wall). That is an environment requirement, not a script defect, and it
is why *Environment and fixtures* says the reset is required before every run.

## Visual polish remarks

| # | Where | What | Severity | Recommendation |
|---|---|---|---|---|
| P1 | table row 3 vs rows 4–10, col 4 | the `#` header is left-aligned over a right-aligned numeric column: `#` sits at col 4, the row numbers end at col 9 (`Character at (3, 4): '#'`, `Character at (4, 9): '1'`) | nit | right-align the `#` header in the same 7-cell slot the values use |
| P2 | batch-import rows 12–19 | every entry is the raw share URL, head-truncated at 114 columns (`security=rea…`), so the human label (the `#name` fragment at the end of each URL) is never visible and 8 entries are near-identical | minor | render the parsed name (or at least tail-truncate so `#Amsterdam-REALITY` survives) |
| P3 | expanded panel rows 7–10 | the sub-table has no header row — `●  71fc29f5 2026-10-14 13:26:29 never      vless      tcp/reality    -       -      -         —               —    —` is nine unlabelled cells, and "no value" is written `-` in three columns and `—` in three others | minor | add a header row (`Up / ID / Seen / Used / Proto / Type / Delay / Speed / Traffic / Exit`) and pick one empty-value glyph |
| P4 | rows 6 and 11 | the sub-panel is one cell narrower than its parent row, so its right border lands in the table's scrollbar column: `╭───…───╮█│` and `╰───…───╯█│` | minor | inset the panel by one column, or draw the scrollbar above the panel |

All four are properties of the *rendered* text, so they survive a re-run; the two that depend on the
emoji column (P3's cell contents, P4's border collision) are quoted from cells right of the flag, and
the harness's one-cell collapse of the flag shifts those columns by one on a real terminal (see
*Tooling friction*) — the *defect* (unlabelled cells, colliding border) is unaffected.

## Tooling friction

Harness limits hit while producing this document — none of them is an app finding:

- **pyte `Screen.display` crashes on wide-character stub cells.** `pyte/screens.py:241` does
  `wcwidth(char[0])` on a cell whose `data` is `""` (pyte's own placeholder for the second half of a
  double-width char) and raises `IndexError: string index out of range`. Every read path
  (`capture_screen`, `expect_text`, `wait_for_stable`, `get_line`, `get_screen_region`) goes through
  it, so reads fail at random on screens that draw emoji — which this app does (🏴 🖥 ⏱ 📊 📋). Two runs
  in this walkthrough died that way (`expect` after a tab switch, `wait_for_stable` after opening the
  help overlay) before the runner patched it: `Screen.display` is replaced with pyte's own renderer
  plus a guard that treats an empty cell as one space and still skips the stub of a wide char. The
  patch is in the runner, not in the app or the harness; the harness itself is unmodified.
- **Wide characters collapse to one cell in the witness.** `display()` yields the emoji as a single
  string cell, so every column to its right reads one cell left of a real terminal. Exact-column
  claims in this document are therefore restricted to cells left of the first emoji.
- **Buffer-mode reads are text-only.** `include_ansi` applies to stream mode only, so the palette
  (theme `dracula` here) — contrast, colour-only semantics, colour in the selection highlight — is
  outside what this pass can assert.
- **`Ctrl+V` is the only door into the import screen**, and a scenario's steps are tui-test tools
  only, so no scenario can set the clipboard; the fixture's URL list has to be placed there by the
  caller (documented in *Environment and fixtures*). Without that prerequisite the step opens
  `ImportUrl` with `No valid share URLs found` instead.
- **A fixture that is not reset fails non-obviously** (attempt 2 above): the assertion that fails is
  the first one, 20 s later, with no hint that the cause is a stale `data.db`.
- **No liveness check anywhere in the harness**: after a child exits, reads replay the last frame and
  writes still answer `✓`. Not hit here (every run closed explicitly), but it is why each document's
  cleanup step is `close()`.

## Review of findings

Everything this scenario set out to prove holds: the empty state, the import round-trip
(8 URLs → 7 endpoints), the table's column set, endpoint grouping, and the expanded panel all behave
as documented. The findings are cosmetic, and two of them are structural enough to be worth fixing
before hand-polishing anything else.

**1. The expanded endpoint's sub-table is unreadable without the manual (minor).** Evidence: step 23 —
`││●  71fc29f5 2026-10-14 13:26:29 never      vless      tcp/reality    -       -      -         —               —    —█│`.
Nine cells, no header, and the manual (`docs/guides/tui-manual.md`, "Expandable endpoints") is the
only place that says they are active-marker, hex id, Last Seen, Last Used, Protocol Type, config
type, delay, speed, traffic, outbound address, outbound country. Why it matters: this panel is the
only place per-variant data (last seen/used, per-variant delay) is visible, so the information exists
but is not legible. Recommendation: add a header row, and pick one glyph for "no value" — the same
row writes `-` for delay/speed/traffic and `—` for the two outbound columns.

**2. The import list hides the only human-readable field (minor).** Evidence: step 10 —
`│ ✓ vless://…nl-ams-01.synthetic-node.example:443?encryption=none&security=rea…  │`. The name a
user gave the link (`#Amsterdam-REALITY`) is at the tail of the URL, past the 114-column cut. Why it
matters: a paste of 50 URLs cannot be sanity-checked before `Enter`, which is the whole point of the
review screen. Recommendation: lead each row with the parsed name, then the `host:port`.

**3. The sub-panel's border collides with the scrollbar column (minor).** Evidence: steps 24 and 25 —
`╰───…───╯█│` and `╭───…───╮█│`. Why it matters: the nested panel reads as broken/misaligned at the
right edge, and the collision is at exactly the column a user checks for "is there more below".
Recommendation: inset the panel one cell from the table's right edge.

**4. The `#` header disagrees with its own column (nit).** Evidence: `Character at (3, 4): '#'` against
`Character at (4, 9): '1'`. Why it matters: small, but it is the first column a reader's eye lands on,
and it is trivially fixable. Recommendation: right-align the header cell in the same slot as the
values.

### Verified good

- The empty state explains the way out: ` No profiles — press 'a' to add one` (E1), with the search
  placeholder on row 1 (E2) and ` Server: (none selected)` as the footer (E3).
- Batch import reports counts before acting and truncates with a real ellipsis:
  ` 8 valid, 0 invalid — Enter to import, Esc to cancel` (E4/E5).
- Endpoint identity is `host:port`: the two `nl-ams-01…:443` links (different transports, same
  credentials) became one row with a `▶` indicator (E6/E9), and the header advertises the active sort
  (`Test ↑`) — steps 13, 21.
- The per-variant sub-rows distinguish the active variant by glyph (`●` vs `○`), not colour alone —
  step 23.
- Land-and-scroll arithmetics: expanding inserts 5 rows and pushes the following endpoint down without
  losing the footer or the scrollbar column (steps 21–25).

### Reproduce

```bash
cd /home/user/oss/xray-tui
R=/home/user/.cache/leas-tui/profiles-core
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
xclip -selection clipboard < docs/guides/tui/fixtures/import-urls.txt   # the Ctrl+V prerequisite
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-10-14-132534-scenario-profiles-import-and-table.md profiles-import-and-table
```
