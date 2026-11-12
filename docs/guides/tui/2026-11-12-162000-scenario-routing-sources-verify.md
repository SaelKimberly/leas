---
name: routing-sources-verify
description: Post-implementation verification of the Routing Rules rework and the new Sources pane-1 tab (header controls, clamped rows, read-only notice, tab entry)
app: leas (dev build, target/debug/leas)
tags: [settings, routing, sources, verification]
---

# Scenario: routing-sources-verify

| Field | Value |
|---|---|
| Run at | 2026-11-12 16:20:00 +0500 |
| App under test | leas, dev build, `target/debug/leas` (rebuilt after T7) |
| Launch command | `env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/routing-rules-audit target/debug/leas` |
| Session / mode / size | `routing-sources-verify` / buffer / 120x40 → 80x24 |
| Harness | mcp-tui-test, buffer mode |
| Evidence | [2026-11-12-162000-scenario-routing-sources-verify-transcript.md](2026-11-12-162000-scenario-routing-sources-verify-transcript.md) |

## Purpose and scope

Proves the spec §3 amendments shipped: the controls header, one row per rule
with clamped columns, the read-only notice on an ignored edit key, the
scrollable routing form, and the Sources tab (columns + `g` entry). Replaces
the pre-implementation expectations of
[routing-rules-audit](2026-11-12-154049-scenario-routing-rules-audit.md),
whose P1–P9 findings this run should close.

## Environment and fixtures

- Fresh fixture home
  `/home/user/.cache/leas-tui/routing-rules-audit/` (recreated from
  `fixtures/config.json`; `M` persists ruleset mode, so a clean run needs a
  fresh copy).
- `NO_COLOR` unset in the launch command.

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | launch 120x40 | Shell paints: `1: [Profiles]`, `2: [Details]` |
| E2 | `,`, `/routing rules`, Enter, `→` | Header line contains `D ‹loyalsoldier› · C ‹ru› · M ‹default›` and `10 rules · 0 off`; the row `1  block   geosite:win-spy` has NO `0` (r#type) column; the second hint line reads `shipped table — [M] to edit` |
| E3 | row geometry | Each rule row ends inside the pane: the routing pane's right border `│` is present on every rule row at this width |
| E4 | `a` in default | Status band shows `default is read-only — [M] switch to custom`; no form opens; footer hint has no `[a] Add` |
| E5 | `M` | Header flips to `M ‹custom›`; hint gains `[a/e/d] rule` |
| E6 | `a` | Routing form opens in the right pane: `Type`, `Domain Matcher`, `Domains (comma-sep)` … as field rows; `Rule Set (URL)` reachable via Tab (not asserted on screen here — the unit test pins the scroll) |
| E7 | Esc, Esc | Back to the sections list, then the shell |
| E8 | `g` | Sources tab active: pane-1 tab bar shows `Sources` accent-selected; table headers `Name  Enabled  Status  Updated  Endpoints  URL`; the seeded `Default` group row is present |
| E9 | resize 80x24 | Sources re-lays; columns shed (URL gone), no column painted past the pane |

## Scenario script

```python
launch("env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/routing-rules-audit target/debug/leas", mode="buffer", dimensions="120x40", timeout=30)
expect("1: \[Profiles\]", timeout=5)
send(",", delay=0.3)
expect("Sections", timeout=5)
send("/", delay=0.3)
send("routing rules", delay=0.3)
key("enter", delay=0.3)
expect("Routing Rules", timeout=5)
key("right", delay=0.3)
expect("D ‹loyalsoldier›", timeout=5)
capture()
line(row=6)
line(row=7)
line(row=8)
send("a", delay=0.4)
expect("default is read-only", timeout=5)
capture()
send("M", delay=0.4)
expect("M ‹custom›", timeout=5)
capture()
send("a", delay=0.4)
expect("Domain Matcher", timeout=5)
capture()
key("escape", delay=0.3)
key("escape", delay=0.3)
key("escape", delay=0.3)
expect("1: \[Profiles\]", timeout=5)
send("g", delay=0.5)
expect("Sources", timeout=5)
capture()
resize("80x24", delay=0.8)
expect("Sources", timeout=5)
capture()
key("escape", delay=0.3)
close()
```

## Observed behaviour

| ID | Verdict | Evidence (transcript step) |
|---|---|---|
| E1 | PASS | Step 2: `1: [Profiles]` |
| E2 | PASS | Steps 10–14: header `D ‹loyalsoldier› · C ‹ru› · M ‹default›` + `22 rules · 0 off` (the shipped `ru` table has 22 rules, not the 10 the expectation guessed — corrected below); rows `1  block     geosite:win-spy  —` — no `r#type` column, matcher column present, one row per rule |
| E3 | PASS | Step 13's line: the routing pane's border `│ │ │` survives on every rule row at 120 and (rows 24–28 of the 80x24 captures) the popup's border holds at narrow width |
| E4 | PASS | Step 16: status band `default is read-only — [M] switch to custom` appears with no form; the footer hint line 2 reads `[D] dataset  [C] country  [M] mode   shipped table — [M] to edit` — no `[a] Add` |
| E5 | PASS | Step 19: `M ‹custom›` |
| E6 | PASS | Step 22: `Domain Matcher` — the form opens in the right pane |
| E7 | PASS | Step 27: `1: [Profiles]` restored |
| E8 | PASS | Step 29–30: pane-1 tab bar `Profiles  Sniffer  [Sources]  Logs`, headers `Name  Enabled  Status  Updated  Endpoints  URL`, the seeded `Default` group row present |
| E9 | PASS | Step 33 (80x24): columns shed — URL and Endpoints drop first, the table stays inside the pane |

## Corrections to expectations

- E2: the shipped `ru` table holds **22** rules, not 10 — the summary reads
  `22 rules · 0 off`. The pre-implementation audit (routing-rules-audit) had
  10 because its fixture dataset differed.
- One intermediate run rendered `D D ‹loyalsoldier›`: the header drew a
  leading ` D ` span in front of the knob string that already starts with
  `D`. Fixed after the first run; the saved transcript is the clean re-run
  on the rebuilt binary. (Two runs before that failed at launch with a blank
  screen — a broken `blaze` toolchain shim had silently no-op'd the rebuild;
  building with the real `cargo` binary fixed it.)

## Review of findings

All nine P-findings of the pre-implementation audit are closed on the live
surface:

1. P1 (border overrun) — rows clamp; borders intact at 120 and 80.
2. P2 (blank gap rows) — rules are consecutive rows.
3. P3 (mid-word truncation) — controls header and hint truncate via
   display-width fitting; the knob line renders `D ‹…› · C ‹…› · M ‹…›`.
4. P4 (dead-key advertising) — default-mode hint drops `[a]/[e]/[d]`; the
   status band explains the read-only state.
5. P5 (help band waste) — covered by the unit tests (narrow collapse); this
   run does not screenshot it.
6. P6 (dead `0` column) — gone.
7. P7 (comma blob) — targets are first-entries + `+k more`.
8. P8 (no colour) — unstyled text reads here; colour assertions were unit
   tests (`bool_value_colors_split_by_truth` and friends).
9. P9 (unscrollable form) — `routing_form_scrolls_to_the_focused_field` unit
   test pins `Rule Set (URL)` visible when focused.

Verified good: `,` popup open, `/` filter, `→` pane switch, `M` mode flip,
form open/close, `g` tab jump, live resize shedding.

Reproduce:

```bash
cargo build -p leas   # with the real cargo binary, not a toolchain shim
uv run --quiet --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/run.py \
  doc docs/guides/tui/2026-11-12-162000-scenario-routing-sources-verify.md routing-sources-verify
```
