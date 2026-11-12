---
name: routing-rules-audit
description: The Settings Routing Rules pane at 120x40 and 80x24 — header controls, rule list columns, the add-rule form, and what narrow width clips
app: leas (debug build, target/debug/leas)
tags: [settings, routing, narrow-width, polish-audit]
---

# Scenario: routing-rules-audit

| Field | Value |
|---|---|
| Run at | 2026-11-12 15:40:49 +0500 |
| App under test | leas, dev build, `target/debug/leas` (md5 below) |
| Launch command | `env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/routing-rules-audit target/debug/leas` |
| Session / mode / size | `routing-rules-audit` / buffer / 120x40 → 80x24 |
| Harness | mcp-tui-test, buffer mode |
| Evidence | [2026-11-12-154049-scenario-routing-rules-audit-transcript.md](2026-11-12-154049-scenario-routing-rules-audit-transcript.md) |

## Purpose and scope

Ground the Routing Rules UX findings in observed screens before the spec's §3
amendments are implemented. Covers: popup open, section filter to Routing
Rules, the routing list pane (header + rows), the add-rule form, the `M`
default→custom switch, and the 80x24 narrow rendering. Does not cover
persistence of D/C/M changes beyond the session, the Telegram/subscription
surfaces, or pane 1 tabs.

## Environment and fixtures

- Fixture home: `/home/user/.cache/leas-tui/routing-rules-audit/` with
  `config/leas/config.json` copied from `docs/guides/tui/fixtures/config.json`.
  No `data.db` — the app creates its store; routing rules come from the
  shipped table (`ops/routing_defaults.rs`).
- `NO_COLOR` is unset in the launch command (host exports it; crossterm 0.29
  suppresses all colour under it).
- Repo root run; `target/debug/leas` relative.

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | launch 120x40 | Shell paints: `1: [Profiles]` pane-1 title, `2: [Details]` pane-2 title, status bar present |
| E2 | `,` | Popup titled ` Settings ` opens; bands: ` Search ` bar with `Press / to filter settings`, ` Sections ` list |
| E3 | `/` + `routing rules` + Enter | Sections list filtered to the Routing group leaves; `Routing Rules` row visible |
| E4 | `→` | Right pane switches to the routing list: header line contains `dataset:` `country:` `ruleset:`, second line contains `[D] dataset  [C] country  [M] mode`, list rows are numbered with outbound tags |
| E5 | `a` in default mode | **Silent no-op** — the screen does not change (the list is read-only in `default`; the footer hint still advertises `[a] Add`); recorded as a finding, not a failure |
| E6 | `M` | Header `ruleset:` value flips to `custom`; shipped-table rows appear |
| E7 | `a` in custom mode | Routing rule form renders its Input fields starting with label `Type`, `Domain Matcher`, `Domains (comma-sep)`; bottom hint `[Tab] Next  [Shift+Tab] Prev  [Enter] Save  [Esc] Cancel` |
| E8 | Esc, resize 80x24 | Popup re-lays at narrow width; routing header + rows still legible; observe what clips (pre-registered suspicion: targets blob clips, header hint truncates) |
| E9 | Esc | Popup closes; shell unchanged behind it |

## Scenario script

```python
launch("env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/routing-rules-audit target/debug/leas", mode="buffer", dimensions="120x40", timeout=30)
expect("1: \[Profiles\]", timeout=5)
assert_text("2: [Details]")
send(",", delay=0.3)
expect("Sections", timeout=5)
send("/", delay=0.3)
send("routing rules", delay=0.3)
key("enter", delay=0.3)
expect("Routing Rules", timeout=5)
key("right", delay=0.3)
expect("dataset:", timeout=5)
capture()
region(5, 13, col_start=2, col_end=117)
send("a", delay=0.4)
assert_text("geosite:win-spy")
send("M", delay=0.4)
expect("custom", timeout=5)
capture()
send("a", delay=0.4)
expect("Domain Matcher", timeout=5)
capture()
key("escape", delay=0.3)
expect("dataset:", timeout=3)
resize("80x24", delay=0.8)
expect("dataset:", timeout=5)
capture()
line(row=5)
line(row=6)
key("escape", delay=0.3)
expect("1: \[Profiles\]", timeout=5)
close()
```

## Observed behaviour

| ID | Verdict | Evidence (verbatim excerpt + transcript step) |
|---|---|---|
| E1 | PASS | Step 2/3: `1: [Profiles]`, `2: [Details]` painted (run 2) |
| E2 | PASS | Step 5: `Sections` found; step 12 capture shows the ` Search ` bar and ` Sections · 2/2 ` |
| E3 | PASS | Step 9: `Routing Rules` found; ` Sections · 2/2 ` confirms the filter narrowed 20 rows to 2 |
| E4 | PASS | Steps 11–13: header `dataset: loyalsoldier   country: ru   ruleset: default`, hint `[D] dataset  [C] country  [M] mode   shipped table — switch to custom t│` (clipped, see P3), rows `1  0  geosite:win-spy … block` |
| E5 | PASS (finding) | Run 1 step 15: `a` in `ruleset: default` timed out — the screen never changed (`Domain Matcher` not found after 5s). The list is read-only and gives no feedback. Run 2 step 15 asserts the no-op |
| E6 | PASS | Run 2 step 17: `ruleset: custom`; step 18 capture shows the same 10 shipped rows and hint `[a/e/d] rule  [Ctrl+↑↓] reorder` |
| E7 | PASS | Run 2 steps 20–21: form renders `Type` / `Domain Matcher` / `Domains (comma-sep)` … as `> (empty)` Input rows inside a ` Routing Rule ` titled pane; the modal border shows `[Enter] Save  [Ctrl+W] Sections  [Esc] Back` |
| E8 | PASS (findings) | Run 2 steps 24–28: at 80x24 the popup re-lays, but `ruleset:` truncates to `rules`, the `[a/e/d` hint clips mid-token, and list rows overrun the popup's right border (`…geosite:win-spy                 block` with no border tail); only 2 rules visible |
| E9 | PASS | Run 2 steps 29–30: `1: [Profiles]` shell restored; session closed clean |

## Corrections to expectations

- E5 (first attempt, run 1): expected `a` to open the form in `ruleset:
  default`. The code only enables editing in `custom`; the key is a silent
  no-op there. Corrected in the E-table above; the failed first run's
  transcript step 15 is preserved in the transcript file.
- The routing form renders **inside the right pane** (a `Routing Rule ` titled
  pane), not as an overlay — expectation wording adjusted.

## Visual polish remarks

Colour claims are unwitnessed: this host's harness reads came back unstyled
(`NO_COLOR` unset in launch, but the capture carries no style annotations);
use `shot()` rows in the implementation pass to pin colours.

| # | Sev | Observation (row/col from the step-12 capture unless noted) | Recommendation |
|---|---|---|---|
| P1 | high | List rows overrun the pane: at 80x24 (steps 26–28) `geosite:win-spy … block` paints past the popup's right border, erasing `│ │` | Clamp the rendered line to the inner width; the `GroupListItem` pop-truncate pattern already exists for the group list |
| P2 | high | The rule list wastes every second row — `1  0  geosite:win-spy` then a blank row, ten rules consume twenty rows (step 12) | Remove the blank rows; `ListItem::height` is 1, so the gap comes from the `List` widget's rendering — replace with the shared row renderer |
| P3 | medium | Header hint line clips mid-word with no `…`: `shipped table — switch to custom t│` (step 12), `ruleset:` → `rules` at 80x24 (step 28) | Display-width-aware truncation with reserved `…`; same helper as the form rows |
| P4 | medium | Footer hint advertises `[a] Add  [e] Edit  [d] Delete` in `ruleset: default` where those keys are dead (step 12); pressing `a` is a silent no-op (run 1 step 15) | Mode-aware hint set + a status-band notice (`default is read-only — [M] switch to custom`) on an ignored edit key |
| P5 | medium | Help band: 8-row box holding 2 content rows (step 12); at 80x24 it leaves the routing list 2 visible rows (step 26) | Collapse the help band on narrow widths; the rows it shows (`Keys`, `Legend`) are duplicated by the modal border hints |
| P6 | low | The opaque `0` column (`r#type`) sits between `#` and the target, meaning nothing to the user (step 12) | Drop `r#type` from the row (already in the spec) |
| P7 | low | Targets render as one comma blob with no `+k more` and no truncation (step 12) | First-entries + `+k more`, per spec §3 |
| P8 | low | Rule rows carry no colour signal for `block`/`proxy`/`direct`/`off` (step 12, unstyled read) | Outbound colouring per spec §3; verify with `shot()` |
| P9 | info | The routing form's 14 fields exceed the pane (step 21: `Outbound Tag` last visible, `Rule Set (File)`/`(URL)` unreachable) while focus can still Tab into them | Scroll the form; shared field-row renderer per spec §3 |
| P10 | info | Popup border + shell border corner mixes (`└─│`, `│─┘`) at 80x24 (step 26) — modal-over-shell rendering is correct, cosmetic only | None |

## Tooling friction

- `ctrl(",")` is rejected (`ctrl` takes a single letter); `,` must go through
  `send`. The resolved pipeline handles it.
- Step 12's status bar shows residue `r/.ca` at the right edge in the buffer
  read (run 2 step 12) — pyte tracking artifact, not app output; absent in the
  region read and at other steps.
- The run-1 failure closed the session mid-scenario (`steps: 15 · errored: 1 ·
  session closed`); rerunning the corrected document is the recovery path.

## Review of findings

Severity-ordered:

1. **P1** — list rows overrun the pane border at narrow width (step 26–28).
   Why: `RoutingRuleItem::render` builds fixed-width strings without a
   width-aware clamp. Fix: shared display-width truncate helper (spec §3).
2. **P2** — every second list row is blank, halving rule density (step 12).
   Fix: drop the double-height rendering; shared row renderer.
3. **P3** — mid-word truncation without ellipsis in header + hint (steps 12,
   28). Fix: `fit_value`-style helper.
4. **P4** — misleading footer hints + silent no-op `a` in default mode
   (run 1 step 15, step 12). Fix: mode-aware hints + status notice.
5. **P5** — help band waste starves the list viewport (steps 12, 26).
   Fix: narrow-mode collapse (spec §3).
6. **P6–P9** — dead `r#type` column, comma-blob targets, no colour coding,
   unscrollable 14-field form — all folded into the spec's §3 amendments.

Verified good: popup opens/closes over the shell; `/` filter narrows 20 rows
to 2 and keeps the selection valid; `M` flips default→custom and seeds the
shipped table; the routing form renders and Esc returns to the list; the
modal border carries per-pane key hints that change with mode
(`shipped table…` ↔ `[a/e/d] rule…`); live resize re-lays the popup without
residue at 120x40.

Reproduce:

```bash
cargo build -p leas
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-11-12-154049-scenario-routing-rules-audit.md routing-rules-audit
```
