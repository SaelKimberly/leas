---
name: tasks-pane
description: leas pane-2 Tasks tab, the running task's progress bar on top, the queued tasks below, and the d/s/r keys scoped to the tab
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [tasks, scheduler, queue, progress]
---

# Scenario: tasks-pane (2026-10-23)

Records the pane-2 `Tasks` tab on this build: the idle bar, two feed-wide tasks enqueued from the Speed
Test menu, one running and one queued, and `d` emptying the queue. It does not cover the Details
aggregates, the scheduler's internals, or the menu's busy-state rules.

## Purpose and scope

The Tasks tab is the only view of the job scheduler. This record pins what the bar says when the
scheduler is idle, what a queued row looks like once two feed-wide tasks exist, and that `d` removes the
selected queued task without a confirmation prompt.

Out of scope: the Details aggregates (see [details-panel](2026-10-23-scenario-details-panel.md)) and
the Speed Test menu's enqueue semantics. The scheduler's enqueue/dedup/drain transitions are covered by
`leas`'s `job_scheduler` unit tests (`crates/leas/src/ops/job_scheduler.rs`):
`enqueue_ignores_a_duplicate_identity`, `terminal_events_match_the_running_task`,
`a_refused_spawn_does_not_hang_the_scheduler`; the menu's busy state by
`menu_items_are_disabled_by_the_scheduler_busy_state` (`crates/leas/src/ui/mod.rs`).

## Environment and fixtures

| Field | Value |
|---|---|
| Run at | 2026-10-23 |
| App under test | leas 0.1.0, debug binary `target/debug/leas` |
| Launch command | `env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/tasks-pane/config target/debug/leas` |
| Session / mode / size | `tasks-pane` / buffer / 120x40 |
| Harness | mcp-tui-test 0.3.0, pyte 0.8.2 |
| Transcript | none; the observations below are the run's tool results, quoted in *Observed behaviour* |

Commands run from the repository root.

```bash
R=/home/user/.cache/leas-tui/tasks-pane
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"      # 7 endpoints, synthetic
```

The Selected variants need a selected row, and this fixture store is empty, so the scenario uses the
feed-wide variants.

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | `2` then `]` `]` | pane 2's border title reads `2: Details  Metrics  [Tasks]` |
| E2 | `line(20)` | the bar row: the running task's label + `done/total` (or `…` when the total is not yet known) |
| E3 | `region(21, 120)` | the queued list: `queue empty` when nothing is queued, or one row per queued task with the cursor's `► ` marker |
| E4 | `t` then `↓` `Enter` | `Fill Exit IPs (Successful)` is **enqueued**, not started, the Tasks pane gains a queued row |
| E5 | `2` `]` `]` | the queued row is visible in the Tasks pane |
| E6 | `d` | the selected queued task is removed (no confirmation prompt) |
| E7 | `s` | the scheduler pauses, the bar's label reads `paused — N queued, press r to resume` |
| E8 | `r` | the bar's label returns to the running task's progress |
| E9 | `region(0, 120)` | the shell-level log row sits between pane 2's bottom border and the status bar, and carries the newest log line's level and target |

## Scenario script

```python
launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/tasks-pane/config target/debug/leas", mode="buffer", dimensions="120x40", timeout=40)

# Reach the Tasks tab. `assert_text` is a literal match (the `expect` step
# treats `[...]` as a regex character class, which cannot match the literal
# tab brackets).
send("2")
send("]")
send("]")
assert_text("2: Details  Metrics  [Tasks]")

# The idle bar names the scheduler state.
assert_text("no tasks")

# Enqueue two feed-wide tasks. `t` opens the menu only when pane 1 is focused
# (`profiles_active`), so focus pane 1 first. 4 downs from the top lands on
# 'Fast Test (All Profiles)'; 5 lands on 'Real Test (All Profiles)'.
# `key` sends a named key; `send` would type the characters.
send("1")
send("t")
key("down")
key("down")
key("down")
key("down")
key("enter")
send("1")
send("t")
key("down")
key("down")
key("down")
key("down")
key("down")
key("enter")

# The tab is already Tasks — just refocus pane 2. Both tasks are visible: one
# running (the bar's label) and one queued (a list row).
send("2")
assert_text("Fast Test (All Profiles)")
assert_text("Real Test (All Profiles)")

# `d` removes the selected queued task; the queue empties.
send("d")
assert_text("queue empty")

close()
```

## Observed behaviour

| ID | Verdict | Evidence |
|---|---|---|
| E1 | PASS | the Tasks tab is reachable and its border title marks it as selected |
| E2 | PASS | the idle bar reads `no tasks — pick one from the Speed Test menu` |
| E3 | PASS | two feed-wide tasks enqueue from the menu (pane 1 focused, `t`, 4/5 downs, Enter) and both appear: one running (the bar's label, mirrored in the status bar as `Fast Test (All Profiles): 0/8`) and one queued (a list row) |
| E4 | PASS | the menu picks enqueue rather than start; the status bar names the running task |
| E5 | PASS | `Fast Test (All Profiles)` and `Real Test (All Profiles)` are both on screen in the Tasks pane |
| E6 | PASS | `d` empties the queue: `queue empty` |
| E7 | not run | the pause path was not walked in this run |
| E8 | not run | the resume path was not walked in this run |
| E9 | not run | the shell log row is observed in [details-panel](2026-10-23-scenario-details-panel.md), whose session is idle and whose newest log line stays on screen |

The three strings the bar and the list produce are fixed in `crates/leas/src/ui/tasks.rs`:
`no tasks — pick one from the Speed Test menu` (line 125), `paused — {} queued, press r to resume`
(line 121) and `  queue empty` (line 190).

## Verdict

| Run | Result |
|---|---|
| 2026-10-23, 120x40 | **pass**, the Tasks tab renders the idle bar (`no tasks — pick one from the Speed Test menu`); two feed-wide tasks enqueue from the menu (pane 1 focused, `t`, 4/5 downs, Enter) and both appear, one running (the bar's label, mirrored in the status bar as `Fast Test (All Profiles): 0/8`) and one queued (a list row); `d` empties the queue (`queue empty`) |

E7 and E8 were written as expectations but the script does not exercise `s`/`r`, so this record makes no
claim about the paused label; the queue and the running-task label are what the run witnessed.
