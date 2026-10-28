# Design: Details Panel, DB Aggregates, Tasks Pane

- **Date:** 2026-10-22
- **Status:** **implemented 2026-10-23** (grilling interviews 2026-10-22 and 2026-10-23; executed in three slices — see the plan doc). Gate: `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo nextest run --workspace` **2550 passed (1 slow), 11 skipped**.
- **Kind:** spec
- **Owners:** `crates/leas/src/ui/` (Details, Metrics, Tasks pane, log row), `crates/leas/src/state.rs` (aggregate cache, scheduler queue/running/paused), `crates/leas/src/ops/job_scheduler.rs` (the job scheduler), `crates/leas-db/src/profiles_query.rs` (the aggregate read)
- **Extends:** `2026-10-15-pane-tui-and-profiles-columns-design.md` (the pane-2 shell, D3 pane-2 heights, D4 screen homes, the `Details`/`Metrics` tab pair) — see §11 supersession map
- **Reference read:** `thirdparty/xrat` — `crates/xrat-app/src/tui/view/configs/detail.rs:13-190`, `tui/view/shared.rs:13-138`, `tui/view/configs/runtime.rs:133-165`, `tui/data/snapshot.rs:80-94,149-177`, `tui/view/configs/testbar.rs:10-47`, `tui/theme.rs:13-16`

## 1. Problem

Pane 2's `Details` tab is **not** a per-server details panel today — it is the
**Actions Log** (`crates/leas/src/ui/mod.rs:1075-1085`):

```rust
fn render_pane2(frame: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    match state.pane2_tab {
        crate::Pane2Tab::Details => {
            if state.actions_compact {
                actions_log::render_compact(frame, area, state);
            } else {
                actions_log::render_full_inner(frame, area, state);
            }
        }
        crate::Pane2Tab::Metrics => metrics::render(frame, area, state),
    }
}
```

Per-server detail lives in **pane 1** (grid row + expandable per-link sub-table
+ a one-line footer). Pane 2's `Details` shows connection state, the last test
results, traffic, memory, and two snapshot log rows — all **dynamic**.

The user wants pane 2 to answer two different questions with two tabs:

- **Details** — *mostly static* information about the currently selected
  server, plus **aggregated database status** (how many servers exist, how
  many are alive / stable, and so on).
- **Metrics** — the **dynamic** information.

And the progress bar moves **into a new `Tasks` tab** on pane 2, together with
the **job queue** — the 2026-10-23 redesign that replaces the earlier
gauge-over-border decision (§14).

Three facts shape the design:

1. **xrat separates the two.** Its `Detail` card is per-config static fields
   (`detail.rs:51-190`); its DB aggregates live in a **separate** `Runtime`
   card (`runtime.rs:133-165`) — `"{total} total · {enabled} enabled ·
   {deleted} deleted · {failed} failed"`. xrat keeps them apart. This spec
   **merges** them into one Details panel (user directive), and the section
   labels carry the distinction.
2. **xrat's aggregates are in-memory counts over an already-loaded vector**
   (`snapshot.rs:80-94`) — xrat loads the whole feed into RAM. leas pages 200
   rows (`PROFILES_PAGE_SIZE`) and must not.
3. **leas's DB can answer the cheap buckets cheaply.** `SELECT COUNT(*)
   FROM endpoint_rank …` is index-served with no sorter
   (`profiles_query.rs:634-693`; the covering index
   `endpoint_rank_key_v2 (band, rank_bin, rank_stab, rank_weight DESC, …,
   rank_proven)` — `schema/ddl.rs:49-51`). The **per-protocol distribution has
   no cheap path**: `protocols.proto_kind` is unindexed, there is **zero
   `GROUP BY` in the whole crate**, and `database-manual-sql.md §1` requires a
   recorded cause for raw SQL.

## 2. Goal / Non-goals / Acceptance

**Goal.** Pane 2's Details panel is the selected server's static fact sheet
plus the database's own status, computed from stored facts that already have
canonical owners. Dynamic content lives on Metrics. The **Tasks pane** (§14)
is the job queue: it shows the running task's progress bar and the queued
tasks, and it is the only surface that starts or stops work — one job at a
time, structurally.

**Non-goals.**

- No protocol/DB/config behaviour change. No new dependency. No rename of
  persisted fields.
- **No per-protocol distribution.** Dropped deliberately — see D2.
- No change to the ping pipeline, the enrichment pipeline, the write path, or
  the page query's ordering law.
- No change to the Profiles table's columns.

**Acceptance** is in §9.

## 3. Locked decisions

Every row below was decided in the grilling interview (2026-10-22).

| ID | Decision | Why |
|---|---|---|
| D1 | **Metrics absorbs the Actions Log content.** Details is rebuilt from scratch as a static panel. | user directive: dynamic → Metrics |
| D2 | **Bucket counts come from `endpoint_rank` only. NO per-protocol distribution.** | `proto_kind` unindexed; zero `GROUP BY` precedent; raw SQL needs a cause; a feed-wide `GROUP BY` = full scan + temp b-tree, violating the sorter-free doctrine (`ordering-law.md §8.1`) |
| D3 | **Two aggregate groups: global (whole DB) and current view (filtered).** | the view group agrees by construction with the footer's `rows a-b of N`; the global group is the database's own state |
| D4 | **Buckets: `alive`, `proven`, `reliable`, `untested`, `failed`, `other`** — a **partition block** (`proven`/`untested`/`failed`/`other`, sums to the total) and an **orthogonal block** (`alive`/`reliable`, overlaps any subset). No single ambiguous "stable" word. | "stable" is ambiguous between *ever succeeded* and *success rate ≥ X%*; separate lines say both without picking. The block split keeps the partition addable-up (see D28) |
| D5 | **Details = endpoint facts + the representative link's facts.** The per-link table stays in pane 1's expansion. | xrat's config is one protocol; leas's row is an endpoint with N links — one link's facts cannot fill a per-server panel |
| D6 | **One conditional-aggregation statement per scope** (two statements total). | one index walk per scope instead of five; every bucket column is in the covering index |
| D7 | **Global `alive` is computed live** (`rank_newest_seen >= now-ttl`); the **view** group's Active membership uses the swept `band`. | `band` is materialized by a sweep that runs **every 10 minutes** (`main.rs:538-546`) — up to 10 min stale. Live liveness is index-served on `endpoint_rank_band_window (band, rank_newest_seen)` (`ddl.rs:59-60`). The two are labelled differently (D4/D11) |
| D8 | **`reliable` = `rank_stab <= 2`** — the *representative link's* success rate ≥ 75% (warmup excluded). | `rank_stab` is the representative link's rate (`endpoint_rank.rs:540-600`), NOT an endpoint-wide aggregate. Labelled as a link-level fact beside the endpoint-level `proven` |
| D9 | **Two columns: facts left, aggregates right.** Below ~100 cols they stack full-width, aggregates after facts. | pane 2 is full terminal width; at 80 cols each column is ~38 cells |
| D10 | **Two labelled groups inside the facts column: `Server` and `Link`.** | xrat has blank lines; labelled groups make ~18 rows scannable |
| D11 | **The facts column scrolls; the aggregate column is pinned and clipped from the bottom.** The global group is above the view group. | the global numbers are the ones the user asked for first — clipping must not eat them |
| D12 | **New pane-2 defaults: Details 12, Metrics 16.** Superseded by D49 (now a single shared 16-row default). The log row is always present on tall terminals. | 8 rows cannot show two labelled groups; pane 1 keeps ≥ 6 rows |
| D13 | **The log row is a shell-level row OUTSIDE pane 2's frame**, between pane 2's bottom border and the status bar. | keeps pane 2's frame a complete rectangle; the log row owns the row below the border, and pane 2's border is never overwritten (D14 retired) |
| D14 | **RETIRED by the 2026-10-23 redesign.** The gauge-over-border decision is replaced by the Tasks pane (see §14). Pane 2 keeps its full rectangle; nothing overwrites its bottom border. | user redesign: the progress bar moves INTO a Tasks tab |
| D15 | **RETIRED by the 2026-10-23 redesign** (the gauge's label moved into the Tasks pane's bar row — §14.2). | superseded by the Tasks pane |
| D16 | **Compact (`F1`) = one line of the GLOBAL bucket counts only** — no view total (the footer's), no server identity (the footer's). | no duplication with the Profiles footer's bottom line |
| D17 | **In compact mode the log row is dropped** (pane 2 collapses to the 1-row strip, which is now the global aggregate line — D16). | a 1-row borderless pane 2 has no room for the shell log row |
| D18 | **RETIRED by the 2026-10-23 redesign** — `s` is now the scheduler's stop key (§14.4), scoped to the Tasks tab. The manual single-server ping JOINS the queue rather than bypassing it. | superseded by the scheduler |
| D19 | **RETIRED by the 2026-10-23 redesign** — the `Stop Testing` menu item is replaced by the scheduler's `s`/`r` keys in the Tasks pane. | superseded by the scheduler |
| D20 | **RETIRED by the 2026-10-23 redesign** — the pairwise spawn guards are replaced by the scheduler, which is the ONLY entry point for any job (§14.3). 'One job at a time' becomes structural: there is no path that starts a job outside the queue. | superseded by the scheduler |
| D21 | **Aggregates refresh on filter change and on job events. No timer.** | bounded cost; the numbers freeze while idle (see §7) |
| D22 | **One change, one spec, two implementation slices** (lifecycle → UI), one full gate at the end. | user directive |

### 3.1 Decisions added by the spec review (2026-10-22)

| ID | Decision | Why |
|---|---|---|
| D23 | **Details follows the pane-1 cursor** via `filtered_profiles().nth(selected_index)` — the same law the footer (`profiles.rs:1664-1666`) and Metrics (`metrics.rs:37-41`) use. | a search filter must not make three surfaces disagree about which server is "selected" |
| D24 | **The enrichment gap is a render law, not a bug.** Details renders `—` for a missing `endpoint_info` entry and **never triggers a background fill** on selection change. | the grid does the same (`profiles.rs:1154`); enrichment is seeded at page load (`profiles.rs:191`), not per selection |
| D25 | **The `Details` scroll router gets its own offset** — not `native_activity`'s. | `native_activity::SCROLL` is a **global static** that counts rows back from the newest ring entry (`native_activity.rs:28,39-42`); it is ring-specific and shared. Details' offset lives in `AppState` |
| D26 | **Both pane-2 scroll arms exclude `ALT`.** | **live bug**: the Metrics arm (`ui/mod.rs:684-694`) matches `Up/Down/…` with only `!CONTROL`, and returns **before** the resize arm (`ui/mod.rs:758-771`) — so `Alt+↑` scrolls the ring today and never resizes pane 2. Widening the router without the exclusion would spread the bug to Details |
| D27 | **RETIRED by the 2026-10-23 redesign** — the Tasks bar's label is plain text drawn over `LineGauge` (§14.2); `Gauge::label` is no longer used at all | superseded by the Tasks pane |
| D28 | **The bucket predicates are the crate's OWN scope arms, verbatim** (`PlanScope::predicate`, `profiles_query.rs:100-124`): `proven` = `rank_proven = 1`; `untested` = `rank_proven = 0 AND rank_bin = 12`; `failed` = `rank_proven = 0 AND rank_bin IN (13,14,15)`. A sixth line, `other`, is the partition residual `rank_proven = 0 AND rank_bin NOT IN (12,13,14,15)`. | **correction to the spec draft**: the draft's `untested = rank_bin = 12` and `failed = rank_bin BETWEEN 13 AND 15` **double-count** with `proven` — a proven endpoint whose representative is an untested sibling (bin 12) is Successful, not New. The crate's law is "`rank_proven` FIRST, then the bin" and its three arms are pairwise disjoint. Reusing that law verbatim means the panel's buckets and the scope filters the user already selects are **one filter law**, and `alive` / `reliable` are explicitly orthogonal (not partition members) |

### 3.2 Decisions from the scheduler redesign (2026-10-23)

| ID | Decision | Why |
|---|---|---|
| D29 | **A third pane-2 tab: `Tasks`.** Pane 2 becomes `Details \| Metrics \| Tasks`. The Tasks pane holds the progress bar (top) and the queue list (below). | user redesign: the progress bar moves INTO the Tasks pane; the gauge-over-border (D14) is retired |
| D30 | **The progress bar is `ratatui::widgets::LineGauge` with a manual thumb overlay** — `filled_symbol("━")` / `unfilled_symbol("─")`, themed via `ThemeStyles::progress_fill` / `progress_bar` (`theme.rs:100,104,240-246`). The thumb is one overlay cell at `floor(width * done/total)` (the same math LineGauge uses, `ratatui-widgets-0.3.2/src/gauge.rs:447-450`). **`tui-slider` is REJECTED**: it pulls `tui-nuances ^0.1.6` as a SECOND theme engine, its `SliderStyle` is `Color`-based with no theme trait (verified: only `Color` fields; `blocks()`/`dots()` are static presets), and leas's executed 2026-10-14 spec mandates one theme source (opaline). Zero new deps, zero hakari regen, one theme source | |
| D31 | **Schedulable tasks = the 4 metered kinds + the 4 Selected variants.** Batched: `Fast Test (All Profiles)`, `Real Test (All Profiles)`, `Real Test (Successful)`, `Real Test (New)`, `Real Test (Successful + New)`, `Real Test (Failed)`, `Fill Exit IPs (Successful)`, `Retry Failed DNS Lookups`, `Compact Duplicate Endpoints`. Selected: `Fast/Real/Speed/UDP Test (Selected)`. `Remove Bad Servers` and `Clear All Stats` are NOT schedulable (destructive one-shots with no meters — D45) | |
| D32 | **Task identity = `(TaskKind, PlanScope)` for batched tasks, `(TaskKind, TestType, endpoint_id)` for Selected variants.** The endpoint is FROZEN at enqueue time, so two different rows are different tasks (no false dedup) and the same row twice is a duplicate. `PlanScope` is the discriminator (`profiles_query.rs:114-118`) — `Real Test (Successful)` ≠ `Real Test (New)` | |
| D33 | **Dedup covers BOTH the queue and the running task**: at most one instance of any task identity exists in the system. Scheduling a duplicate is ignored (a log line says 'already queued/running') | |
| D34 | **The queue is in-memory, process lifetime.** A restart drops it; a running task dies with the process. Matches today's `Arc<Meters>` model | |
| D35 | **The scheduler is the ONLY entry point for any job.** The four direct ping spawns (`start_tcp_ping`/`start_real_ping`/`start_speed_test`/`start_udp_test`, `ui/mod.rs:591-613`) are retired — their callers enqueue. The four batch/compact spawns (`run_batch`, `start_fill_exit_ips`, `spawn_compact`, `spawn_dns_retry`) are called ONLY by the drain. 'One job at a time' is structural | |
| D36 | **The manual single-server ping JOINS the queue** as a `(kind, TestType, endpoint_id)` task. The existing `testing_profiles` direct path is retired into the scheduler | |
| D37 | **The Speed Test menu stays the scheduling entry point**: picking an item ENQUEUES it and the popup closes. The menu's labels name the task. `Remove Bad Servers` / `Clear All Stats` are disabled while busy (D45) | |
| D38 | **The Tasks pane: the bar row = the RUNNING task; the list below = QUEUED tasks only** (earliest first). The running task is NOT a list row — it is the bar's label, so no duplication. `↑↓` moves a cursor over the queued list (Profiles-table convention); `PgUp`/`PgDn` page; `Home`/`End` jump. The list scrolls to keep the selection visible | |
| D39 | **`d` deletes the selected queued task immediately, no confirmation** (a reversible queue edit; a log line makes it visible). The running task is cancelled with `s`, not deleted | |
| D40 | **`s` = cancel the running task + PAUSE the queue (contents preserved). `r` = resume draining. Both are Tasks-tab-scoped.** The cancelled task is marked 'cancelled' and the queue freezes — a stop is a PAUSE, not a reset | |
| D41 | **One shared stop flag** (today's `speed_test_stop`, `state.rs:167`) — checked at each task kind's own safe boundary: batch at the dispatch boundary (`ping.rs:1378`), fill between links, compact BETWEEN merges (never inside a merge transaction), DNS retry between lookups (it polls every 500 ms). Safe because only one task runs at a time | |
| D42 | **A queued task whose scope is empty when it reaches the head is SKIPPED** with a 'skipped — nothing to do' line. The outcome is run / skipped / cancelled, and the drain handles all three | |
| D43 | **The scheduler OWNS the terminal events** (`BatchEnded`, `CompactFinished`, `MaintenanceDone`). It matches each to the running task's kind; a mismatch is logged as a stray event and does NOT clear meters. On a match it clears the running task, marks it done, and — if not paused — drains the head. The existing per-event meter-clearing moves INTO the scheduler | |
| D44 | **The drain runs on ANY focused tab** (it hooks `poll_core_events`, `ui/mod.rs:246`). The Tasks pane need not be visible. Before starting the next task it checks the previous task's meters are cleared and the stop flag is unset | |
| D45 | **'Busy' predicate for the disabled destructive items = `running.is_some() \|\| !queue.is_empty() \|\| paused`.** `Remove Bad Servers` and `Clear All Stats` are disabled (greyed, via the menu's existing disable mechanism `ui/mod.rs:1529-1533`) while anything is running, queued, or the scheduler is paused | |
| D46 | **The status bar keeps its progress line** and shows the RUNNING task's name + done/total (e.g. `Real Test (Successful): 1,240/3,000`) — the at-a-glance surface when the user is on Details/Metrics; the Tasks pane is the queue surface. Two surfaces, one meter source | |
| D47 | **The Tasks pane's bar row always names the scheduler state**: idle → a muted hint ('no tasks — pick one from the Speed Test menu'); paused → `paused — N queued, press r to resume`; running → the task's label + bar | |
| D48 | **Quitting cancels the running task and DISCARDS the queue**, logging a line per queued task that never ran. The existing interrupted-batch summary (`ui/mod.rs:340-358`) stays | |
| D49 | ~~Per-tab defaults~~ **Superseded 2026-10-28: single shared default of 16 rows for all tabs**, so switching never resizes. The `Alt+↑/↓` clamp (3..`term/2`) and the pane-1 ≥6 floor unchanged | |
| D50 | **D13 stays**: the shell-level log row remains, between pane 2's bottom border and the status bar |

## 4. Current-state inventory (evidence)

| fact | site |
|---|---|
| Pane-2 dispatch: `Details` = Actions Log, `Metrics` = merged view | `ui/mod.rs:1075-1085` |
| Pane-2 heights: `Details` 8 / `Metrics` 14, clamp 3..`term/2` | `state.rs:266-276`; `ui/mod.rs:761-771` |
| Shell layout: pane1 `Min(6)` / pane2 `Length(rows)` / status `Length(1)`; `small = height < 20` forces a 1-row borderless pane 2 | `ui/mod.rs:1311-1375` |
| Actions Log full panel: 6 rows — status / server / tests / traffic / core log / TUI log | `ui/actions_log.rs:148-288` |
| Actions Log compact bar: connection icon, proto, addr, TCP/RP/SPD, traffic, last non-tui log | `ui/actions_log.rs:68-143` |
| Batch bars: two side-by-side bars in rows 3-4, sourced from `maint_progress` / `fill_progress` / `batch_progress` | `ui/actions_log.rs:306-429` |
| Metrics: `session` / `native` (ring) / `core` sections; ring budget = `area.height - lines - 6` | `ui/metrics.rs:41-116` |
| `progress::bar_cells` = `[███>░░] 42%`; `runs()` = the crate's only glyph producer | `ui/widgets/progress.rs:25-48` |
| `s` = stop speed test, guarded by `profiles_active() && !testing_profiles.is_empty()` | `ui/mod.rs:875-878` |
| `Stop Testing` menu item disabled when `testing_profiles.is_empty()` | `ui/mod.rs:1529-1533` |
| Pane-2 scroll arm (Metrics only): `Up/Down/PageUp/PageDown/Home/End`, `!CONTROL`, **no ALT exclusion** | `ui/mod.rs:684-694` |
| `native_activity::SCROLL` — a module-global static, ring-relative | `ui/native_activity.rs:28,39-42` |
| Progress slots: `batch_progress`, `maint_progress`, `fill_progress` | `state.rs:172-182` |
| Compact/DNS-retry pass **no** stop flag into their spawn loops | `ops/compact.rs:267-303`, `ops/compact.rs:399+` |
| Mutual exclusion today: fill blocks on batch+fill; batch blocks on batch; compact blocks on compact | `ops/ping.rs:3115`, `ops/ping.rs:3334`, `ops/compact.rs:268` |
| `speed_test_stop` — one `AtomicBool` shared by batch and fill | `state.rs:167`; `ops/ping.rs:579-581` |
| `endpoint_rank` columns: `band`, `rank_bin`, `rank_stab`, `rank_proven`, `rank_newest_seen`, `rank_weight`, `rank_domain/sub_domain/addr` | `leas-db/src/models_toasty.rs:740-770` |
| `rank_bin`: 0-5 real-ok, 6-11 fast-ok, 12 untested, 13 real-err, 14 fast-err, 15 dns-err, 16 purged | `models_toasty.rs:729-735` |
| `stab_bin`: 0=≥95% … 2=≥75%, 4 = neutral (`len < STAB_WARMUP`=4) | `endpoint_rank.rs:385-410` |
| `rank_proven` is **endpoint-level**; `rank_stab` is the **representative link's** | `endpoint_rank.rs:540-600` |
| Reband sweep: every 10 minutes (`reband_expired`), `reband_all` at startup | `main.rs:538-546`; `state.rs:584` |
| Page query: `SELECT COUNT(*) FROM endpoint_rank k …` + `ORDER BY` on stored keys; covering index, no sorter | `profiles_query.rs:634-651` (`page_ids_direct`), `:673-693` (`profiles_count_with`); `schema/ddl.rs:49-51` |
| `view_predicate`: `Active` = `k.band = 0`, `Purgatory` = `k.band IS NOT 0`, `All` = `1 = 1` | `profiles_query.rs:500-518` |
| `scope.predicate`: Successful `rank_proven=1`, New `proven=0 AND bin=12`, Failed `proven=0 AND bin IN (13,14,15)` | `profiles_query.rs:114-118` |
| Search predicate uses **range seeks** on `rank_domain`/`rank_sub_domain` — not `LIKE` | `profiles_query.rs:440-499` (`base_from_where`) |
| Grid resolution source = the loaded row's persisted addresses; `endpoint_info` is a *display cache* that can lag | `profiles.rs:1154-1159`; `ops/profiles.rs:418-422` |
| `endpoint_info` seeded at page load for rows lacking an entry | `ops/profiles.rs:189-193` |

## 5. The aggregate read

### 5.1 Two statements, not ten

**Global scope** (whole feed, no view filter):

```sql
SELECT
  COUNT(*),
  SUM(CASE WHEN k.rank_newest_seen >= {active_threshold} THEN 1 ELSE 0 END),
  SUM(CASE WHEN k.rank_proven = 1 THEN 1 ELSE 0 END),
  SUM(CASE WHEN k.rank_stab <= 2 THEN 1 ELSE 0 END),
  SUM(CASE WHEN k.rank_proven = 0 AND k.rank_bin = 12 THEN 1 ELSE 0 END),
  SUM(CASE WHEN k.rank_proven = 0 AND k.rank_bin IN (13, 14, 15) THEN 1 ELSE 0 END),
  SUM(CASE WHEN k.rank_proven = 0
            AND k.rank_bin NOT IN (12, 13, 14, 15) THEN 1 ELSE 0 END)
FROM endpoint_rank k
```

The `rank_proven = 0` guard on the three bin arms is **not optional**: it is the
crate's own partition (`PlanScope::predicate`, `profiles_query.rs:100-124`),
whose doc states the rule as *"`rank_proven` FIRST, then the bin"* and whose
three arms are pairwise disjoint. A proven endpoint whose representative is an
untested sibling (bin 12) is **Successful, not New** — dropping the guard
would double-count it in both `proven` and `untested`.

**View scope** (current filter): the same shape with the view predicate, the
group filter, the search predicate and the scope predicate — i.e. the **exact
predicates `profiles_count_with` already emits** (`base_from_where` +
`view_predicate` + `scope.predicate`, `profiles_query.rs:440-518`), so the view
group's total equals the footer's `rows a-b of N` **by construction**, not by
coincidence.

**The one difference between the two statements is the `alive` arm** (D7):

- **Global** — `rank_newest_seen >= {active_threshold}`, computed live against
  the wall clock. Index-served on `endpoint_rank_band_window (band,
  rank_newest_seen)` (`ddl.rs:59-60`).
- **View** — `band = 0`. The view group's membership is the swept `band`
  because the **view itself** is defined by `band` (`view_predicate`,
  `profiles_query.rs:500-518`): the panel's view numbers must describe the same
  set the table is showing, and the table's Active view is `band = 0`. Using
  the live predicate here would make the panel's view group disagree with the
  table's own membership by up to 10 minutes.

The global statement therefore reads one index for `alive` and the covering
index for the rest; the view statement reads the covering index only. Both
stay index-served; neither groups, sorts, or joins.

Both statements are new raw SQL → **they need a recorded cause** in
`docs/reference/database-manual-sql.md` (its §1 rule, §6 checklist: name the
cause, prefer inlined integer literals, keep the statement inside the
transaction that owns the fact, make it idempotent, **make a test actually run
it**, record the measurement). The recorded cause is *"the aggregate panel
cannot be answered by the typed path; the typed path has no aggregate
constructor, and the page query's COUNT does not project bucket columns."*

**Coverage check.** Every projected bucket column — `rank_bin`, `rank_stab`,
`rank_proven` — rides the covering index `endpoint_rank_key_v2`
(`ddl.rs:49-51`); `rank_newest_seen` rides `endpoint_rank_band_window`
(`ddl.rs:59-60`). Neither statement groups, sorts, or joins.

### 5.2 The bucket definitions (and their honest gaps)

| line | predicate | level | meaning |
|---|---|---|---|
| `alive` | `rank_newest_seen >= now - ttl` (global) / `band = 0` (view) | endpoint | seen within the TTL window — **orthogonal**, not a partition member |
| `proven` | `rank_proven = 1` | **endpoint** | ≥ 1 live unpurged link with a real success in the 16-sample window — **partition member** |
| `reliable` | `rank_stab <= 2` | **representative link** | success rate ≥ 75%, ≥ 4 samples — **orthogonal**, not a partition member |
| `untested` | `rank_proven = 0 AND rank_bin = 12` | endpoint | never measured — **partition member** |
| `failed` | `rank_proven = 0 AND rank_bin IN (13,14,15)` | endpoint | real-err / fast-err / dns-err — **partition member** |
| `other` | `rank_proven = 0 AND rank_bin NOT IN (12,13,14,15)` | endpoint | measured-but-not-proven, e.g. fast-only-ok (bin 6-11) — **partition member** |

**The four partition members sum to the total. `alive` and `reliable` do not
join them — they are orthogonal filters that overlap any subset.** The panel
renders them as separate lines, and the partition group is drawn as one block
so the reader can add it up; `alive` and `reliable` sit outside that block.

Verified from the code:

- `rank_proven = 1 AND rank_bin = 12` is **legal** — a proven endpoint whose
  representative is an untested sibling. The crate's own scope law calls that
  endpoint **Successful, not New** (`profiles_query.rs:102-110`). So `proven`
  and `untested` must be `rank_proven`-disjoint, or the same endpoint counts
  twice.
- `rank_stab` is the **representative link's** rate; `rank_proven` is
  **endpoint-level** (`endpoint_rank.rs:540-600`). An endpoint with one 10/10
  link and a 5/10 representative is `proven` but not `reliable` — hence
  `reliable`'s caption says "link".
- `rank_stab = 4` is neutral: `stab_bin` returns `STAB_NEUTRAL` when
  `len < STAB_WARMUP (4)` (`endpoint_rank.rs:385-392`), so a link with fewer
  than 4 samples is in no rate bucket.

Therefore the panel renders **six labelled counts in two blocks**: a
**partition block** (`proven` / `untested` / `failed` / `other`, which sums to
the total) and an **orthogonal block** (`alive` / `reliable`). It never draws
them as one list, because two of them would break the sum.

### 5.3 Refresh

Per D21: on **filter/view/search/group change** and on **job events** (a batch,
fill, compact or DNS-retry run starting or ending). **No timer.** The counts
live in `AppState` as a cached struct with the scope key it was computed for;
a scope change discards it.

The consequence is stated in §7.

## 6. The Details panel

### 6.1 Layout

Pane 2's block is rendered as today (`Block::borders(ALL)`, accent border when
focused — `ui/mod.rs:1361-1374`). Inside it:

```
┌─ 2: Details  Metrics ──────────────────────────────────────┐
│ Server            │ DB  74,012                             │
│   Address host:443│   proven    41,900                    │
│   Protocol vless… │   untested  28,932                    │
│   …               │   failed     2,996                    │
│ Link              │   other       184                    │
│   Real Delay 120ms│                                        │
│   …               │ alive       3,180                    │
│                   │ reliable   12,004                    │
│                   │ View: Active / <query>                │
│                   │   proven     2,900                    │
└───────────────────┴────────────────────────────────────────┘
```

The **partition block** (`proven` / `untested` / `failed` / `other`) sums to
the group's total; `alive` and `reliable` are drawn **outside** it, separated
by a blank line, because they are orthogonal filters (D28).

- **Left column** (`Server` group, then `Link` group): xrat's label/value
  shape — a 13-cell muted label column (`xrat tui/theme.rs:13-16`), value
  styled muted when it is `—` (`xrat tui/view/shared.rs:13-45`). Empty value =
  `—` (the pane-tui spec's single empty-value glyph).
- **Right column**: the **global** group first (D11), then the **view** group,
  labelled with the active filter so the two are never confused.
- **Below ~100 cols** the columns stack: facts first, aggregates after, both
  full width.
- The facts column **scrolls** (`↑↓`/`PgUp`/`PgDn`/`Home`/`End`); the aggregate
  column is **pinned** and clipped from the bottom when short (D11).
- The pane title carries a `rows visible/total` counter for the facts column,
  the way Metrics exposes one for the ring (`metrics.rs:85-91`).

### 6.2 Which facts, and from where

**Server group** — from the selected endpoint and its row:

| field | source |
|---|---|
| Address | `row.endpoint.display_host(&row.resolved_ips)` + `port` |
| Protocol | the representative link's `protocols` entry: `proto_kind/transport/security` |
| Transport | `transport.type` |
| Security | `security.type` (+ `sni`, `fp` when present) |
| Country | `endpoint_info.country` (display cache) — `—` when absent |
| Resolved IPs | `row.resolved_ips` — **the loaded row's persisted addresses**, the same source the grid uses (`profiles.rs:1155-1159`) |
| Whitelist | `endpoint_info.host_features` / `sni_whitelisted` → `SNI` / `CIDR` / `SNI+CIDR` / `—` |
| Exit IP / Country | the **active** link's persisted `latency.ip` first, `endpoint_info.outbound_ip` as fallback — the grid's exact precedence (`profiles.rs:1183-1195`) |

**Link group** — from the **representative** link
(`EndpointRow::representative_link_index`, the same link the grid's Test/Stab
cells describe):

| field | source |
|---|---|
| Last Seen / Last Used | `link.last_seen_at` / `link.last_used_at` |
| Real Delay / Fast Delay | `link.latency.real_delay` / `fast_delay` |
| Auth | `link.latency.auth` (1 ok, 2 failed, 3 n-a, 4 unknown) |
| Speed | `link.speed_bps` |
| Stability | `link.stab_mask`/`stab_len` → `n/16` |
| Error | `link.error.kind` / `error.text` |
| Traffic | `link.traffic.today_up/down`, `total_up/down` |

**Not shown in Details** (they are Metrics' job, D1): connection state, the
last manual run's TCP/RP/SPD, live traffic counters, memory, the native ring,
core system stats. `last_test_tcp/real/speed` are the **last single/manual
run's** results (`ops/events.rs:952-956`), not the link's stored measurement —
a different source with a different lifetime. They stay on Metrics; Details
shows the link's stored `latency.*`.

### 6.3 The enrichment gap (D24)

`state.endpoint_info` is a **display cache** that lags (`ops/profiles.rs:418-422`).
An endpoint with no cached entry renders `—` for country/whitelist/exit, and
Details **does not trigger a fill**. Enrichment is seeded at page load for
rows that lack an entry (`ops/profiles.rs:189-193`) — the same law the grid
follows. Rendering `—` is the correct behaviour; a background fill on
selection change would be a new write trigger in a read path.

## 7. Known consequences of the locked decisions

| # | Consequence | Mitigation / disclosure |
|---|---|---|
| 1 | **`alive` and `reliable` are orthogonal, not partition members** (D28). Only `proven`/`untested`/`failed`/`other` sum to the total. | two blocks in the panel: the partition block, then a blank line, then the orthogonal block. The partition block is addable-up; the other two are not, and are not drawn as if they were |
| 2 | **Global `alive` (live) and view `alive` (swept) are computed differently** and can disagree by up to 10 minutes. | D7: the global line is captioned "alive (live)", the view group is captioned with the filter. The sweep runs every 10 min (`main.rs:538-546`) |
| 3 | **No refresh timer** (D21): the global counts freeze while idle, and `alive` drifts against the wall clock. | counts refresh on the next filter change or job event; documented in the manual |
| 4 | **Per-protocol distribution is absent** (D2). | stated in the manual's Details section |
| 5 | **Compact shows the global buckets only** (D16) — no view counts, no server identity. | the footer's bottom line owns the view total and the server identity |
| 6 | **In compact mode the log row is dropped** (D17) — pane 2 is the 1-row aggregate strip. | no room for the shell log row |
| 7 | **The shell loses one row** to the log row on tall terminals (D13). | pane 1 keeps ≥ 6 rows; pane-2 clamp becomes `min(default, term - 8)` |
| 8 | **The queue is in-memory** (D34): a restart drops it, and a running task dies with the process. | matches today's `Arc<Meters>` model; quitting logs the tasks that never ran (D48) |
| 9 | **Compact's cancel is destructive mid-merge.** A cancel is checked **between merges**, so a partially-merged batch leaves duplicate endpoints unmerged — the next Compact run finishes the job. | cancel points are placed between merges, never inside a transaction (`ops/compact.rs:332-360` — the loop already treats a failed merge as ordinary) |
| 10 | **A queued task can be stale at run time** (D42): its scope was valid at enqueue, empty at the head. | the head's scope is re-evaluated; an empty scope is skipped with a log line, and the queue advances |
| 11 | **A duplicate schedule is silently ignored** (D33): the user gets a log line, not an error. | the log line says 'already queued/running' |
| 12 | **The Tasks tab's bar duplicates the status bar's progress** (D46) — two surfaces, one meter source. | both read the same meters, so they cannot disagree |

## 8. The log row and the (retired) gauge

### 8.1 The gauge — RETIRED by the 2026-10-23 redesign

The gauge-over-border decision (D14/D15) is **retired**. Pane 2 keeps its full
rectangle; the progress bar moves into the Tasks pane (§14). The
`progress::runs()` glyph owner (`ui/widgets/progress.rs:25-34`) stays — the
Tasks pane's bar uses it.

### 8.2 The log row (D13, D50)

A shell-level row between pane 2's bottom border and the status bar, full
width. It shows the newest log line from `state.log_cache` with its target
tag — the live tail the expanded panel only ever showed as two frozen
snapshot rows (`actions_log.rs:225-247`).

It is **outside** pane 2's frame, so pane 2's rectangle stays complete. On
terminals under 20 rows, pane 2 collapses to the compact strip and the log row
is dropped (no room).

### 8.3 Cancellation — RETIRED by the 2026-10-23 redesign

The pairwise guards (D18/D19/D20) are **retired** in favour of the scheduler,
which is the only entry point for any job (§14.3). Cancellation is now the
scheduler's one shared stop flag (§14.4).

## 9. Acceptance criteria

| # | Criterion | Proved by |
|---|---|---|
| A1 | Pane-2 `Details` renders **two columns** (facts left, aggregates right) at ≥ 100 cols and **stacks** below | unit test on `TestBackend` cells: aggregate column's x-offset at 120 cols; stacked order at 80 cols |
| A2 | The facts column shows the `Server` and `Link` group headers and the representative link's stored `latency.*` | unit test |
| A3 | Details follows the cursor through `filtered_profiles().nth(selected_index)` — with an active search filter, three surfaces (grid, footer, Details) name the same server | unit test with a filtered list |
| A4 | A missing `endpoint_info` entry renders `—` and triggers **no** enrichment write | unit test: `endpoint_info` empty → `—` rendered, `state.endpoint_info` still empty after the render |
| A5 | The aggregate statement returns the six buckets for the global scope and for a filtered scope, and **the four partition buckets sum to the group's total** | `leas-db` integration test that runs the new statement (a raw-SQL site must have a test that actually runs it — `database-manual-sql.md §6`): `proven + untested + failed + other == COUNT(*)` |
| A6 | The view group's total **equals** the page query's total for the same filter | `leas-db` integration test comparing the aggregate statement's `COUNT(*)` with `profiles_count_with`'s |
| A7 | `alive` (global) is computed from `rank_newest_seen` against the TTL, not from `band` | `leas-db` integration test: a row whose `band = 0` but whose `rank_newest_seen` is older than the TTL is **not** counted alive |
| A8 | **RETIRED** — the gauge-over-border is replaced by the Tasks pane (§14). Pane 2's bottom border is always `─` and is never overwritten | unit test: pane 2's bottom border row is `─` with and without a running task |
| A9 | The log row is a **separate shell row below pane 2's frame** and carries the target tag | unit test: the row below pane 2's bottom border contains the newest log line |
| A10 | Compact renders one line of the **global** bucket counts, with no server identity and no view total | unit test |
| A10b | The aggregate column draws the **partition block and the orthogonal block separately** — the four partition lines are contiguous, and `alive`/`reliable` follow a blank line, so the reader cannot add them to the total | unit test on the rendered lines: the index of the `alive` line is not adjacent to the `other` line |
| A11 | The Tasks tab renders the bar row + the queue list; the running task is the bar's label and is **not** a list row | unit test on `TestBackend`: with one running + two queued, the list has exactly two rows |
| A12 | `s` cancels the running task and **pauses** the queue; `r` resumes; the queue contents survive the pause | unit test: queue len unchanged after `s`, and the head starts after `r` |
| A13 | A duplicate task identity (queued or running) is **ignored** — at most one instance exists | unit test: enqueue the same `(kind, scope)` twice → queue len 1; enqueue it while running → ignored |
| A14 | **No `Alt+↑`/`Alt+↓` scroll** in any pane-2 tab — the keys only resize | unit test: `Alt+Up` with pane 2 focused → `pane2_height` changed, scroll offset unchanged (this also **fixes the live Metrics bug**, D26) |
| A15 | Details' scroll offset is independent of the native ring's | unit test: scrolling Details leaves `native_activity`'s offset untouched |
| A16 | The aggregate refreshes on a filter change and on a job event, and **not** on a timer | unit test: no refresh after N idle frames; refresh after a filter change |
| A17 | A stale-scope task is **skipped** at the head, with a 'skipped — nothing to do' line, and the queue advances | unit test: queue a `Real Test (New)` with an empty scope → skipped, next task starts |
| A18 | The scheduler is the **only** entry point: the four direct ping spawns and the four batch/compact spawns are unreachable from the UI | unit test: the UI's test keys enqueue a task rather than starting one |
| A19 | `Remove Bad Servers` and `Clear All Stats` are **disabled** while `running \|\| queued \|\| paused` | unit test: menu items greyed when busy, selectable when idle |
| A20 | Quitting cancels the running task and **discards** the queue, logging each queued task that never ran | unit test: queue of 3 + a running task → quit → 3 log lines |
| A21 | The status bar shows the running task's name + done/total | unit test |
| A22 | Full gate green: `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace`, plus the `tui-test` scenarios | the gate |

## 10. Tests

- **`leas-db` integration** (`crates/leas-db/tests/integration.rs`): the new
  aggregate statement — each bucket's value against a hand-built fixture,
  including the **proven endpoint carrying an untested representative** (bin
  12), which must land in `proven` and **not** in `untested` (the crate's own
  partition, D28); the **partition sum** invariant (`proven + untested +
  failed + other == COUNT(*)`); the view scope's total matching
  `profiles_count_with`; the live-`alive` case (A7). The raw-SQL checklist
  demands a test that **runs the statement**.
- **Unit** (`crates/leas/src/ui/`): the two-column/stacked layout on
  `TestBackend`; the group headers; the `—` for a missing `endpoint_info` (A4);
  the log row's position and tag (A9); the compact line's content and omissions
  (A10); Details' scroll offset independence (A15); the ALT-exclusion (A14);
  the cursor law under a search filter (A3); the Tasks pane's bar row + queue
  list composition (A11); the `LineGauge` bar's fill/thumb math.
- **Scheduler** (`crates/leas/src/ops/scheduler.rs`): enqueue + dedup (A13);
  the drain on a terminal event and the mismatch path (A18); the pause/resume
  flag (A12); the stale-scope skip (A17); the stop flag reaching each task
  kind's safe boundary (batch at the dispatch boundary, compact BETWEEN
  merges, DNS retry between lookups); the quit path discarding the queue (A20);
  the busy predicate gating the destructive one-shots (A19).
- **`tui-test` scenarios**: a new `scenario-details-panel` (selection change
  rewrites the facts column; the aggregate column does not change on selection
  change); a new `scenario-tasks-pane` (enqueue → the bar shows the running
  task, the list shows the queue; `d` removes a row; `s` pauses; `r` resumes);
  updated `scenario-pane-shell` and `pane2-resize` (the three tabs, the new
  defaults, the log row, the compact content); updated `scenario-tiny-80x14`
  (the compact aggregate line, no log row).

**Not** tested, deliberately: the aggregate's absolute numbers against a
production feed (a fixture pins the buckets; a live number is a measurement,
not a test), and the bar's exact glyph shapes (the glyph owner is
`progress::runs()`, already unit-tested).

## 11. Relation to `2026-10-15-pane-tui-and-profiles-columns-design.md` (supersession map)

That spec is **executed** (its plan: "executed P1–P6", `2393/2393` tests) but
its INDEX row still reads "proposed — awaiting user review". This spec does
**not** rewrite it; it supersedes these parts of it:

| 2026-10-15 item | Disposition |
|---|---|
| D3 — pane-2 heights (per-tab default + resize + counter; Details 8 / Metrics 14) | **superseded** by D12 (Details 12 / Metrics 16) and by the new shell reserve (the log row) |
| D4 — screen homes (Actions Log → pane 2 `Details`; Statistics + Native Activity → pane 2 `Metrics`) | **superseded** by D1 — Metrics absorbs the Actions Log's content, and Details is rebuilt as the static panel. The Actions Log is dissolved; `ui/actions_log.rs` is deleted |
| §6 — pane-2 content, the `F1` compact bar | **superseded** by D16/D17 (compact = the global aggregate line), and by §14 (the `Tasks` tab is the third pane-2 tab) |
| §6 — the shell's 3-row split | **amended** by D13 (a 4th shell row: the log row) |
| D2 — keymap scope (app-level `Tab`/`1`/`2`/`[`/`]`, pane-scoped scroll) | **amended** by D26 (the pane-2 scroll arms gain the `ALT` exclusion) and by §14.4 (`s`/`r`/`d` become Tasks-tab-scoped, not app-level) |
| D1 — the overlay stack | **unchanged** |
| D5 — the Settings popup | **unchanged** |
| D6 — the tab-bar style (`1:`/`2:` + `[Name]`) | **unchanged** |
| D7 — the pane frames (accent when focused) | **unchanged** — and the 2026-10-23 redesign keeps it that way: pane 2's bottom border is never overwritten (D14 is retired) |
| D8-D14 — the Profiles columns | **unchanged** — out of scope here |

The Actions Log's disappearance is a **retirement**, not a migration: its
content moves to Metrics (D1), the log tail becomes the shell log row (D13),
and its bars move into the Tasks pane (§14). `ui/actions_log.rs` is deleted and
its tests move with it. Nothing keeps a second owner of the connection-state
row, the test-result row, or the traffic row.

## 12. Implementation slices

One spec, one plan, three slices, one full gate at the end (D22, extended by
the 2026-10-23 redesign).

**Slice 1 — the scheduler (no UI).**

1. The scheduler owner: the queue (`Vec<TaskSpec>`), the running task, the
   paused flag (D34, D40).
2. Retire the four direct ping spawns and route them through the scheduler
   (D35, D36); retire the four batch/compact spawns behind the drain.
3. The stop flag at each task kind's safe boundary (D41); the terminal-event
   ownership and the drain (D43, D44); the stale-scope skip (D42).
4. The ALT-exclusion fix in the pane-2 scroll router (D26) — a defect fix that
   belongs here because slice 3 widens that router.

**Slice 2 — the panel (reads slice 1's scheduler).**

5. The aggregate read in `leas-db` (2 statements), the cached counts in
   `AppState`, the refresh triggers (D6, D21).
6. The Details panel: two columns, the two groups, the scroll offset (D9-D11,
   D23, D24, D25).
7. Metrics: absorb the Actions Log content, drop the duplicated rows (D1).
8. Delete `ui/actions_log.rs` and move its tests.

**Slice 3 — the Tasks pane.**

9. The third pane-2 tab, its height, the tab bar (D29, D49).
10. The `LineGauge` bar with the manual thumb, themed from opaline (D30, D47).
11. The queue list, its cursor and scroll, `d`/`s`/`r` (D38, D39, D40).
12. The menu's enqueue semantics + the busy predicate for the destructive
    one-shots (D37, D45).
13. The status bar's task name + done/total (D46); the quit path (D48).
14. The manual rewrite; the `database-manual-sql.md` cause entry; the INDEX
    rows.

## 13. Docs to sync at implementation time

- `docs/guides/tui-manual.md` — the Actions Log section (pane 2 `Details`) is
  replaced by the Details panel's; the Metrics section; the **new Tasks pane**
  section (the bar, the queue, `d`/`s`/`r`); `F1`; the keybinding tables (`s`
  becomes the scheduler's stop, `r` resumes, `d` deletes a queued task — all
  Tasks-tab-scoped); the pane-2 heights; the log row.
- `docs/reference/database-manual-sql.md` — the recorded cause + the inventory
  row for the two new statements.
- `docs/reference/database.md` — the query map gains the aggregate read.
- `docs/aegis/INDEX.md` — this spec's row; and the stale "proposed" status on
  the 2026-10-15 spec's row (its plan is executed).
- `docs/aegis/plans/2026-10-22-details-metrics-tasks.md` — the plan this spec
  produces.

## 14. The Tasks pane and the scheduler

This section is the **2026-10-23 redesign**. It retires D14/D15 (the
gauge-over-border), D18/D19/D20 (the pairwise guards and the `Stop Testing`
rename) and replaces them with a Tasks pane and a scheduler. The Details
panel (§6), the aggregate read (§5) and the log row (§8.2) are unchanged.

### 14.1 The tab

Pane 2 becomes `Details | Metrics | Tasks` (D29). The tab bar's third label
fits at ≥60 cols; below that it drops by the same width-priority law the
Profiles table uses. The `Alt+↑/↓` clamp (3..`term/2`) and the pane-1 ≥6 floor
are unchanged; pane-2's default height is a single shared 16 rows for every
tab (D49, superseded 2026-10-28).

### 14.2 The progress bar

A `ratatui::widgets::LineGauge` at the top of the Tasks pane's inner area
(D30), themed through the existing tokens — `ThemeStyles::progress_fill` for
the filled run, `ThemeStyles::progress_bar` for the track
(`theme.rs:240-246`, registered at `theme.rs:100,104`). Symbols:
`filled_symbol("━")`, `unfilled_symbol("─")`. The **thumb** is one overlay
cell drawn at `floor(width * done/total)` — the same math `LineGauge` uses
internally (`ratatui-widgets-0.3.2/src/gauge.rs:447-450`), so the thumb and
the bar cannot disagree. The bar's label is `<Task name> <done>/<total> <ETA>`,
and the ETA comes from the rate sampler where one exists (batch, compact).

`tui-slider` was considered and **rejected** (D30): it depends on
`tui-nuances ^0.1.6` (a second theme engine, against the executed 2026-10-14
single-theme spec), its `SliderStyle` is `Color`-based with no theme trait, and
leas would still need an adapter that reads opaline tokens into its fields at
every render site. Zero new deps, zero hakari regen.

### 14.3 The scheduler

The scheduler is the **only** entry point for any job (D35). It owns:

- the **queue**: an ordered `Vec<TaskSpec>` in `AppState`, earliest first;
- the **running task**: `Option<RunningTask>` (the spec + its meters);
- the **paused** flag (D40).

A `TaskSpec` is a value (D34): `(kind, scope)` for batched tasks, `(kind,
TestType, endpoint_id)` for Selected variants (D32). The endpoint is frozen at
enqueue time.

The four direct ping spawns (`ui/mod.rs:591-613`) and the four batch/compact
spawns are called **only** by the scheduler. The existing per-event
meter-clearing moves into the scheduler (D43).

### 14.4 Keys (Tasks-tab-scoped)

| key | action | decision |
|---|---|---|
| `↑↓` / `PgUp` / `PgDn` / `Home` / `End` | move the cursor over the queued list | D38 |
| `d` | delete the selected queued task (no confirmation) | D39 |
| `s` | cancel the running task + PAUSE the queue | D40 |
| `r` | resume draining the paused queue | D40 |

`d` is Tasks-tab-scoped, so it does not collide with the Profiles tab's `d`
(delete profile). `s`/`r` are Tasks-tab-scoped, so they do not collide with the
global `s` (stop speed test — which the scheduler replaces) or `Ctrl+Shift+S`
(copy share URL).

### 14.5 Drain, dedup and cancel

- **Enqueue** (D33, D37): the menu's items enqueue. A duplicate identity
  (queued or running) is ignored with a log line. The popup closes.
- **Drain** (D43, D44): on a terminal event the scheduler matches it to the
  running task's kind, clears the meters, marks the outcome, and — if not
  paused — starts the head. A mismatch is a logged stray event and does not
  clear meters. The drain runs on any focused tab (it hooks
  `poll_core_events`, `ui/mod.rs:246`).
- **Stale scope** (D42): a head whose scope is now empty is **skipped** with a
  'skipped — nothing to do' line. Outcomes are run / skipped / cancelled.
- **Cancel** (D41): one shared stop flag (`state.rs:167`), checked at each
  task kind's safe boundary — batch at the dispatch boundary
  (`ping.rs:1378`), fill between links, compact **between merges** (never
  inside a merge transaction), DNS retry between lookups. A cancel PAUSES the
  queue (contents preserved, D40).
- **Quit** (D48): cancels the running task and discards the queue, logging a
  line per queued task that never ran; the existing interrupted-batch summary
  (`ui/mod.rs:340-358`) stays.

### 14.6 The destructive one-shots

`Remove Bad Servers` and `Clear All Stats` are **not schedulable** (no meters,
destructive). They stay immediate with their existing `y/n` confirmation, but
are **disabled while busy** (D45): `running.is_some() || !queue.is_empty() ||
paused`. The menu's existing disable mechanism (`ui/mod.rs:1529-1533`) is
extended to those two items.

### 14.7 Pane states

The bar row always names the scheduler state (D47): idle → a muted hint;
paused → `paused — N queued, press r to resume`; running → the task's label +
bar. The status bar keeps its progress line with the running task's name and
done/total (D46) — the at-a-glance surface when the user is on Details or
Metrics.
