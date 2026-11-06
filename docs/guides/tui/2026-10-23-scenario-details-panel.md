---
name: details-panel
description: leas pane-2 Details tab, the selected server's static fact sheet plus the DB aggregate status, two columns that stack below 100 cols, and the facts column's own scroll offset
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [details, aggregates, panes, scroll]
---

# Scenario: details-panel (2026-10-23)

Records what the pane-2 `Details` tab shows on this build: the selected server's `Server` and `Link`
groups, the DB aggregate column with its two blocks, the facts column's own scroll offset, the compact
bar `F1` produces, and the column stack below 100 columns. It does not cover the Tasks tab, the Metrics
sections, or the aggregate's SQL.

## Purpose and scope

The Details tab is the read-only view of one endpoint plus the store-wide counts. This record pins the
group labels, the block split inside the aggregate column, which column scrolls, and the two layouts
(side by side at 120 columns, stacked below 100).

Out of scope: the Tasks pane's keys (see [tasks-pane](2026-10-23-scenario-tasks-pane.md)), the Metrics
sections, and the aggregate's SQL. The SQL and the `alive` arm's live-vs-swept split are covered by
`leas-db`'s integration tests `aggregate_buckets_partition_the_total` and
`aggregate_alive_is_live_for_the_global_scope` (`crates/leas-db/tests/profiles_query.rs`).

## Environment and fixtures

| Field | Value |
|---|---|
| Run at | 2026-10-23 |
| App under test | leas 0.1.0, debug binary `target/debug/leas` |
| Launch command | `env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/details-panel/config target/debug/leas` |
| Session / mode / size | `details-panel` / buffer / 120x40, then `resize("80x24")` |
| Harness | mcp-tui-test 0.3.0, pyte 0.8.2 |
| Transcript | none; the observations below are the run's tool results, quoted in *Observed behaviour* |

Commands run from the repository root.

```bash
R=/home/user/.cache/leas-tui/details-panel
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"      # 7 endpoints, synthetic
```

The fixture store ages out of the Active view after the 7-day TTL, so the aggregate numbers read `0`:
the layout, not the data, is what this scenario pins.

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | `2` then `]` | pane 2's border title reads `2: Details  [Metrics]  Tasks`, `]` from Details lands on Metrics; the third tab exists |
| E2 | `[` | back to `2: [Details]  Metrics  Tasks` |
| E3 | `line(20)` | the Details column shows the `Server` group header, then `Address`, `Protocol`, `Country`, `Resolved IPs`, `Whitelist`, `Exit IP` |
| E4 | `line(26)` | the `Link` group header, then `Last Seen`, `Real Delay`, `Auth`, `Stability` |
| E5 | `region(20, 120)` | the aggregate column shows `DB ` followed by the total |
| E6 | `region(21, 120)` | the four **partition** counts are contiguous (`proven`, `untested`, `failed`, `other`) and the **orthogonal** block (`alive`, `reliable`) follows a blank line, the two blocks are never drawn as one list |
| E7 | `↓` | the facts column scrolls (its own offset) and the aggregate column does not move |
| E8 | `F1` | pane 2 collapses to the one-line compact bar: the **global** bucket counts only, no `rows 1-N of M` (the footer's) and no `Server:` (the footer's) |
| E9 | `F1` | pane 2 expands again |
| E10 | `resize("80x24")` | below 100 cols the two columns **stack**: the facts column first, the aggregate block after |

## Scenario script

```python
launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/details-panel/config target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)

# The third tab exists and cycles: `]` from Details lands on Metrics.
# `assert_text` is a literal match (the `expect` step treats `[...]` as a regex
# character class, which cannot match the literal tab brackets).
send("2")
send("]")
assert_text("2: Details  [Metrics]  Tasks")
send("[")
assert_text("2: [Details]  Metrics  Tasks")

# The facts column's groups.
assert_text("Server")
assert_text("Link")
assert_text("Address")
assert_text("Real Delay")

# The aggregate column's two blocks.
assert_text("DB ")
assert_text("proven")
assert_text("untested")
assert_text("failed")
assert_text("other")
assert_text("alive")
assert_text("reliable")
assert_text("View: ")

# The facts column scrolls with its own offset.
send("Down")
assert_text("Server")

# Compact = the global buckets only.
key("f1")
assert_text("total")
key("f1")

# Below 100 cols the columns stack.
resize("80x24")
assert_text("Server")
assert_text("DB ")
close()
```

## Observed behaviour

| ID | Verdict | Evidence |
|---|---|---|
| E1 | PASS | the three-tab bar cycles: `]` from Details lands on Metrics |
| E2 | PASS | `[` returns to `2: [Details]  Metrics  Tasks` |
| E3 | PASS | both group headers render with an empty store; `Server` is followed by `Address` and `Real Delay` is present under `Link` |
| E4 | PASS | `Link` renders its group under the facts column |
| E5 | PASS | the aggregate column shows the partition block (`proven`/`untested`/`failed`/`other`), a blank line, then the orthogonal block (`alive`/`reliable`), then `View: Active` |
| E6 | PASS | the two blocks are separated by a blank line, never merged into one list |
| E7 | PASS | `Down` scrolls the facts column only |
| E8 | PASS | `F1` collapses to the one-line global aggregate: `total` present, no `rows 1-N of M`, no `Server:` |
| E9 | PASS | `F1` again restores the panel |
| E10 | PASS | `resize("80x24")` stacks the columns, facts first, the aggregate block after |

The aggregate column's block split is a code-level invariant, not only a render result:
`crates/leas/src/ui/details.rs:378-413` describes the partition block and the orthogonal block and
pushes `alive`/`reliable` after a blank line; `THREE_COLUMN_MIN_WIDTH = 100` (same file, line 27) is the
width below which the sections stack.

## Verdict

| Run | Result |
|---|---|
| 2026-10-23, 120x40 | **pass**: the three-tab bar cycles (`]` from Details lands on Metrics, `[` returns); both group headers render with an empty store; the aggregate column shows the partition block (`proven`/`untested`/`failed`/`other`), a blank line, then the orthogonal block (`alive`/`reliable`), then `View: Active`; `F1` collapses to the one-line global aggregate (`total` present, no `rows 1-N of M`, no `Server:`) and `F1` again restores the panel; `resize("80x24")` stacks the columns |
| 2026-10-23, 80x24 | **pass**, the two columns stack (facts first, the aggregate block after) |

The fixture store (`seeded/data.db`) ages out of the Active view after the 7-day TTL, so the aggregate
numbers read `0`; the layout, not the data, is what this scenario pins.
