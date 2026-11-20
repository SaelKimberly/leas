# Failure truth and run integrity — implementation plan

Status: **approved and executing 2026-11-20.** Repair track for the
executed spec `specs/2026-11-19-probe-truth-and-ingest-boundary-design.md` (S1,
T2) plus the hardening items the two 2026-11-20 studies found.

Authority reports:
`docs/research/2026-11-20-failure-pair-review.md` (pair),
`docs/research/2026-11-20-log-review-real-test.md` (log),
`docs/research/2026-11-19-real-test-funnel.md` (funnel, context only).

Baseline evidence (this plan's own check, 2026-11-20 07:34 UTC, live copy of
`data.db` + `-wal`):

| Check | Result |
| --- | --- |
| `profile_stats` rows / rows with `error_stage` | 124 392 / **0** |
| newest `updated_at` | 07:34:13 — the app wrote rows *after* the schema-22 migration |
| `EXPLAIN QUERY PLAN` on the purge sweep | `SCAN endpoints` + `SEARCH p USING index_profile_stats_by_endpoint_id`; 0.36 s cold on the same file |

The zero is not a stale copy and not a pre-migration artifact: the running
build writes `error`, `error_kind`, `error_text` and never the pair.

Why two green tests missed it (the executed T2 claimed a "persistence/clear
test"):

| Test | What it proves | Why it stayed green |
| --- | --- | --- |
| `events.rs:1453 the_failure_pair_is_persisted_and_a_success_clears_it` | `apply_test_result` fills `ErrorInfo.stage/cause` on the in-memory struct | never reaches SQLite |
| `leas-db/tests/integration.rs:2146 apply_link_patches_isolates_column_groups` | the group-scoped statement executes per group | seeds `ErrorInfo { stage: None, cause: None }` — the pair is never set |

So the writer defect (a missing column list) and the test gap (a shape with a
NULL pair) are the same omission seen from two sides.

## Goal

Make the typed failure pair reachable and correct, and remove the two
measurement-integrity defects that made the 2026-11-19/20 run's numbers
unreadable: a DNS gate that records queue starvation as a resolver verdict, and
a relay idle cap below the carried protocols' heartbeat interval. Acceptance:
a probe writes a non-NULL `(stage, cause)` that agrees with `purge_reason`; a
feed-wide DNS retry produces no false `[name]` from queue wait; a 45 s silent
but live connection survives; `just quality-gate code` green.

## Architecture (owners)

| Concern | Owner |
| --- | --- |
| Link write SQL (24 columns) | `leas-db` `database.rs` (`LINK_UPSERT_PREFIX`, `link_values_sql`, `link_patch_conflict_sql`) |
| Pair mapping + probe classes | `leas` `ops/ping_native.rs` (`failure_pair`, `from_engine`, `is_transport_failure`) |
| DNS resolve gate | `leas` `ops/enrich.rs` (`RESOLVE_SEM`, `DNS_LOOKUP_TIMEOUT`, waiter fan-out) |
| Marker clear / rank refresh | `leas-db` `database.rs` (`clear_name_markers`), `leas` `ops/events.rs` |
| Relay idle deadline | `leas-native` `error.rs` (`timeouts`), `inbound/outbound.rs` (`relay`, `copy_half`) |
| Log persistence | `leas` `main.rs` (`LogVisitor`, `TuiLogLayer`) |
| Subscription fetch text | `leas` `ops/stream_import.rs` |

## Tech stack

Rust 2024 workspace; toasty 0.11 + in-tree turso driver; `cargo nextest`;
`just quality-gate code` as the exit gate.

## Baseline / authority refs

`AGENTS.md` (probe truth: never prose as evidence; log layer is a security
boundary) · `docs/reference/database.md` §schema cursor, `profile_stats`
columns · `docs/reference/ordering-law.md` bins 12/13/14 and the `[name]` rule ·
spec `2026-11-19-probe-truth…` S1 (pair), S4 (name ⇒ not tested) · ADR 0012
(migrations), 0018 (deprecation grounds) · plan
`2026-11-19-probe-truth-and-ingest-boundary.md` T2 (its "persistence/clear
test" is struct-level; that is the gap this plan closes).

## Compatibility boundary

- No schema change: the pair columns exist (schema 22); this plan only starts
  writing them and correcting their values. No cursor bump.
- Export/readback already round-trips the pair (`export.rs`, `profiles_query.rs`).
- A new `RELAY_IDLE` constant carries the relay deadline; the old `TUNNEL_READ`
  had no other consumer and is deleted (`CONNECT` is its own 15 s constant). No
  public API change.
- Log persistence gains a bounded, non-secret allowlist; `db.params` remains
  unpersistable by construction (spec §10 non-goal 10).

## Requirement Ready Check

Approved source: the two reports (each finding carries a verdict and a
recommended fix) plus the executed spec's S1. Acceptance evidence per task is
listed below; the final gate is `just quality-gate code` plus one live probe
re-query.

Decisions: all three were answered by the reviewer on 2026-11-20 and are
recorded below; no task stays blocked. D1 and D2 become documentation notes
(S1/S2); D3 turned out to need **no code at all** — see the correction in the
table.

## Change Necessity

| Task | Why no-change is insufficient | Minimum boundary |
| --- | --- | --- |
| A1 | Spec S1 is unreadable in every report; the pair is computed then dropped | two column names, two values, two conflict sets |
| A2 | Rows whose transport failure is boxed under `TlsError::Io` would store `Transport/Alert` — a wrong cause on the first run that finally has data | one mapping arm + tests |
| B1 | Queue starvation is recorded as a DNS verdict, deferring 93.6 % of a feed batch | one deadline split + one outcome branch |
| B2 | The clear path is the only writer without retry; 62 lock failures in 10 s | one wrapper call |
| B3 | 85.7 % of connections are reaped at 30 s, incl. a Discord reconnect loop | one constant + one call site |
| B4 | The sweep holds a pool connection for 143 s during a batch | keyset paging of one read |
| C1 | 1 132 dial failures per run carry no cause in the export | one allowlist in the visitor |
| C2 | Fetch failures name the URL but not the stage | one source-chain helper |

## Ripple Signal Triage

- **A1** is a persistence contract change: consumers are the page projection,
  export/readback, `[dest]` (`ui/profiles.rs:606`), and the rank builder.
  Canonical owner is the shared writer; no second writer exists (verified: only
  `database.rs:876` and `:1428`). Verification must read back through the typed
  projection, not just SQL.
- **A2** feeds class → rank/purge/UI. `purge_reason` is evidence-derived, and
  unwrapping a boxed `NativeError` ADDS evidence to the rows that carry one:
  their verdict moves from none to `transport_rejected`, the same verdict the
  5 689 already-unwrapped ws rows hold. `transport_failed` and the sample gate
  do not move. Rows whose wrapped error is plain text stay `Tls`. The reachable
  subset is measured after the change, not assumed from the 5 199 prose rows.
- **B1** owns the scheduler's DNS deferral contract (`DnsDeferred`); its
  consumer is the batch gate and the retry job. A queue timeout must stop being
  a `mark_dns_failure` input.
- **B3** touches a native constant used by the CONNECT budget; the split is
  required so connect deadlines do not grow.
- **C1** touches the log store's security boundary; the allowlist must be
  explicit and commented.

## Plan Pressure Test

Owner fit: each change lands in the file that already owns the behaviour; no new
owner. Higher-level path: A1+A2 finish S1 end to end; B1 makes the DNS gate
honest rather than faster (throughput tuning is deliberately out of scope until
measured). Verification: DB seam for A1, class table for A2, scheduler
predicate for B1, paused-time test for B3. Executable: yes, in the order below.

## TDD Route

`mode: auto` (no project TDD override found) → **decision: strict for A1, A2,
B1, B3** (persistence, classification contract, scheduler contract, connection
lifetime — each has a plausible consumer-visible regression); **light for B2,
B4, C1, C2** (single owner, obvious focused check); **skipped for S1** (docs
only). Authority: `AGENTS.md` test rules + the reports' evidence. Strict tasks
state a failing-first test before the change; light tasks state one focused
check.

## Decisions (answered 2026-11-20)

| # | Question | Answer |
| --- | --- | --- |
| D1 | `error_kind='name'` has no writer; four readers branch on it (`ui/details.rs:381`, `ui/profiles.rs:575`, `endpoint_rank.rs:237`, `clear_name_markers`) | **Retire it, deferred.** Never write it (already true); mark it legacy in `docs/reference/database.md`; drop it from the CHECK on the next rebuild, triggered by any other schema change — not a bump of its own. `clear_name_markers` stays for legacy rows. Rationale: the funnel report §4.8 documents stale-marker harm, and persisting transient DNS failures would recreate it. |
| D2 | `latency_auth`: 95.4 % `Unknown`, 0 `Failed`, 86 `Ok` — cannot support a four-state display | **Document, no code.** `docs/reference/database.md` gains the measured caveat: `Unknown` dominates because the ack is read inside the tunnel's first read, which a failed target handshake never reaches; `Failed` was 0 in the 2026-11-20 snapshot. No UI change; the column stays as data. |
| D3 | 16 imports/18 h hit the 64 MiB `import.max_feed_bytes` ceiling | **No code — this is a correction.** The compiled default is **256 MiB** (`leas-config/src/app_config.rs:84`, raised 2026-11-16; ADR 17), and `serde` keeps a stored value: this machine's `~/.config/leas/config.json` carries an explicit `67108864`. The fix is to raise or delete that stored value; the research report was corrected accordingly. No default change, no per-source cap. |

## Tasks

### A1 — Bind the pair in the link writer (strict)

Files: `crates/leas-db/src/database.rs`.

Change:

1. `LINK_UPSERT_PREFIX`: insert `error_stage, error_cause` after `error_text`.
2. `link_values_sql`: the error group emits five values
   (`1, kind, text, stage, cause` or `NULL ×5`), using two new helpers
   `failure_stage_str`/`failure_cause_str` next to `error_kind_str` (`:893`)
   with the snake_case storage spellings the model and `export.rs:405` already
   parse: `dial|transport|protocol|target`,
   `timeout|refused|no_route|nxdomain|alert|status|framing|config|io`.
3. `link_patch_conflict_sql`: add `error_stage = excluded.error_stage` and
   `error_cause = excluded.error_cause` to the **RESULT** group only.
4. `LINK_SOURCE_CONFLICT_SQL` unchanged (an import refresh must not wipe a
   measurement's pair).
5. Comment on `ErrorInfo`'s struct test in `events.rs:1453` pointing at the SQL
   seam test below — that comment is why the gap survived.

Test (failing first): `link_upsert_persists_the_failure_pair` in
`crates/leas-db/src/database.rs` tests (in-memory DB): upsert endpoint +
protocol + link with `(Dial, Timeout)`; read through the page projection
(`profiles_query`) and assert the pair decodes; repeat through the patch writer
with `(Target, Timeout)` and assert the update; write a success and assert both
NULL. A wrong spelling must fail the typed decode, not pass silently.

Also extend `apply_link_patches_isolates_column_groups`
(`leas-db/tests/integration.rs:2146`): seed `stage: Some(Dial), cause:
Some(Timeout)` instead of `None/None`, and assert a stale RESULT patch that
carries a different pair overwrites both columns while a TRAFFIC-only patch
leaves them intact. That is the invariant the new conflict entries add.

Verify: `cargo nextest run -p leas-db`; then `cargo nextest run -p leas
the_failure_pair_is_persisted`.

### A2 — Stop flattening the wrapped transport failure to text (strict)

Files: `crates/leas-native/src/security/mod.rs` (`map_tls_err`, `:251`) plus the
one bridge found in Step 0.

**Step 0 (spike, before any edit).** `NativeError::Tls` is `Tls(String)`
(`error.rs:17`), so the typed error is gone before the classifier sees it — a
`from_engine` downcast is impossible. Locate the single site where the
`transport error: ws: HTTP error: …` text becomes the `io::Error` the TLS
handshake reads: a transport `poll_read`/`poll_write` or a seam adapter that
either boxes the typed error (`io::Error::other(native)`) or formats it
(`…to_string()`). Record the site and the observed type in the task log; the
test must go through that real bridge, not a hand-built error. Then one of:

- **bridge keeps the type** → implement the `map_tls_err` unwrap below;
- **bridge formats to text** → change it to `io::Error::other(native)` in the
  same commit, then unwrap.

Change: in `map_tls_err`, for `TlsError::Io(io)` call
`io.downcast::<NativeError>()` (`std::io::Error::downcast` returns
`Result<NativeError, io::Error>`); `Ok` → return the inner, `Err(io)` → keep
today's string. No classifier change: `ProbeFailure::from_engine` and
`evidence()` then read the transport/protocol stage for free, and
`is_transport_failure` stays on the outer error. The target leg (`probe.rs:617`)
is deliberately untouched — its failures prove nothing about the config, and
`target_leg_tls_failure_carries_no_evidence` must stay green.

Ripple: the rows whose inner is a boxed `NativeError::TransportRejected` gain
`HttpRejected` evidence, so they earn `transport_rejected` purge verdicts (the
same verdict the 5 689 already-unwrapped ws rows hold) and the pair reads
`(Transport, Status)`. `transport_failed` and the sample gate do not move
(`Transport*` is false on both sides). The reachable subset is measured after
the change, not assumed from the 5 199 prose rows.

Test (failing first): five rows, each built through the Step-0 bridge, each
asserting **class + pair + transport_failed** together:

| # | constructed failure | expected |
| --- | --- | --- |
| 1 | ws 409 (`TransportRejected{status:409}`) boxed into the TLS stream's io error | `Transport`, `(Transport, Status)`, `transport_failed=false` |
| 2 | typed `NativeError::Transport("… early eof")` boxed | `Transport`, `(Transport, Framing)`, `false` |
| 3 | typed `NativeError::Protocol{…}` boxed | `Protocol`, `(Protocol, Framing)`, `false` |
| 4 | text-only `io::Error::new(UnexpectedEof, "x")` (no typed inner) | `Tls`, `(Transport, Alert)`, `false` — the kind rule `target_leg_error` uses must not hijack this |
| 5 | a genuine TLS alert | `Tls`, `(Transport, Alert)`, `false` |

Row 4 is the trap: a typed inner wins over the `UnexpectedEof` kind; a
text-only EOF stays a TLS-stage failure.

Verify: `cargo nextest run -p leas-native security` and `-p leas failure_pair`.

### B1 — DNS: separate queue wait from the resolver answer (strict)

Files: `crates/leas/src/ops/enrich.rs`.

Change:

1. Split the deadline: `DNS_QUEUE_WAIT` (new, 8 s) around
   `RESOLVE_SEM.acquire_owned()`, `DNS_LOOKUP_TIMEOUT` (8 s) around
   `lookup_ip`. Report time stays a function of constants (≤ 16 s). The
   tradeoff: a link deferred at t0 re-enters at t0 + 15 s and probes by name if
   the answer arrives later — the same outcome a failed lookup produces today,
   but without recording a resolver verdict that never happened.
2. New outcome `Busy` (permit never acquired). The current code returns
   `(Vec::new(), Some(now))` for **both** the lookup timeout (line 536) and the
   general failure (line 553); `Busy` must return **`(Vec::new(), None)`** —
   no `resolved_at` stamp — because the `Some(now)` is what arms the 300 s
   `dns_cache_ttl_secs` (`state.rs:908`) and pins the endpoint against re-ask.
   `Busy` also releases the host's waiters **without** `mark_dns_failure` and
   without an answer event; emit at most one `warn!` per 60 s (`AtomicU64`
   stamp) with the host count, never one per host.
3. Keep a real lookup timeout as today.
4. Testable seam: a small `fn failure_is_ours(outcome: DnsOutcome) -> bool`
   returning true only for a resolver answer that failed; the settle path reads
   it. Test that `Busy` and "no records" never mark, that `Busy` yields
   `(ips, None)` (no `resolved_at`), and that `EAI_NONAME`/`EAI_FAIL` and
   lookup timeouts still do.

Verify: `cargo nextest run -p leas enrich`; live: one feed-wide retry shows
`queued past deadline: N` and no 12 000-timeout cliff.

### B2 — Retry the marker clear (light)

Files: `crates/leas-db/src/database.rs` (`clear_name_markers`, `:2054`).

Change: wrap the chunk loop in `crate::retry_on_busy(…, 5)` exactly as
`refresh_endpoint_ranks` (`endpoint_rank.rs:894`) does.

Verify: focused test that a name-kind row clears and a real-kind row does not
(the existing behaviour), plus `cargo nextest run -p leas-db database`.

### B3 — Split the relay idle deadline (strict)

Files: `crates/leas-native/src/error.rs`, `crates/leas-native/src/inbound/outbound.rs`.

Change: add `RELAY_IDLE = 60 s`; `relay`/`copy_half` read it; delete
`TUNNEL_READ` (it had no consumer — the CONNECT budget is the separate `CONNECT`
constant) and update the doc comments at `outbound.rs:297`, `:847`.

Test (failing first): a 45 s fully-silent gap keeps the tunnel alive; 65 s
closes it. Keep `relay_idle_deadline_is_shared_between_directions` green.

Verify: `cargo nextest run -p leas-native relay`.

### B4 — Page the purge sweep (light)

Files: `crates/leas-db/src/database.rs` (never-observed scan, `:1739`).

Change: keyset-paginate the candidate scan (`WHERE e.id > ?last ORDER BY e.id
LIMIT 10000`), accumulating ids; the re-check transaction is unchanged.
Comment: the plan-time measurement (0.36 s cold) shows the scan is not the
cost — this task exists so a contended read holds a pool connection for
milliseconds, not 143 s.

Verify: a 25 000-endpoint fixture (three pages) yields the same candidate set
as the single statement; measure the cold check on the copy.

### C1 — Persist a non-secret diagnostic allowlist (light)

Files: `crates/leas/src/main.rs` (`LogVisitor`, `split`).

Change: render `error`, `target`, `tag`, `kind`, `endpoint_id` into the
persisted message (bounded, e.g. 256 chars total); everything else stays
session-only, `db.params` first. Comment each name's safety (connection or
identity label, never a config value) and cite the spec's non-goal.

Verify: unit test — a visitor that records `error=boom` and
`db.params=<config>` persists the first and not the second.

### C2 — Name the fetch failure's stage (light)

Files: `crates/leas/src/ops/stream_import.rs` (`:706`).

Change: `fn source_chain(e: &dyn Error, depth: usize) -> String`; log
`HTTP fetch failed: {e} (cause: {chain})` and carry the same text in
`ended_early`.

Verify: unit test with a two-level synthetic error; assert both messages appear
and the depth cap holds.

### S1 — Document the two legacy columns (docs-only)

Files: `docs/reference/database.md` (§`profile_stats`).

Change: two sentences, from the decisions above —

- `error_kind = 'name'`: legacy read-only; no writer exists; it leaves the
  CHECK only when the table is rebuilt for another reason (D1).
- `latency_auth`: `Unknown` (4) dominates because the ack is observed inside
  the tunnel's first read, which a failed target handshake never reaches;
  2026-11-20 snapshot: 56 685 `Unknown`, 2 382 `n/a`, 86 `Ok`, 0 `Failed`
  of 59 396 real failures (D2).

Verify: none (documentation); fold into the A1 commit's docs paragraph.

## Execution evidence (2026-11-20)

| Task | Landed | Test |
| --- | --- | --- |
| setup | `import.max_feed_bytes` deleted from `~/.config/leas/config.json` (inherits the 256 MiB default) | — |
| A1 | `LINK_UPSERT_PREFIX` + `link_values_sql` + the RESULT conflict set carry the pair; `failure_stage_str` / `failure_cause_str` | `leas-db` `link_upsert_persists_the_failure_pair`; `apply_link_patches_isolates_column_groups` now seeds `(Dial, Timeout)` |
| A2 | Step 0 found the bridge in `EarlyDataDial` (`ws.rs:162/190/207`, `io::Error::other(e.to_string())`); all three keep the typed error; `map_tls_err` downcasts `TlsError::Io` | `security` unwrap + text-only rows; `ws` rejected-upgrade row |
| B1 | `DNS_QUEUE_WAIT` 5 s (queue + lookup = 13 s, inside the 15 s floor), `Permit::{Acquired,Closed,Starved}`, starved → release, no mark, no stamp; report budget read by the batch and the floor | `the_queue_budget_reports_starvation_not_an_answer` |
| B2 | `clear_name_markers` behind `retry_on_busy(…, 5)` | group-isolation + existing clear tests |
| B3 | `RELAY_IDLE` 60 s (deletes `TUNNEL_READ`, which had no consumer; `CONNECT` is its own 15 s constant) | shared-deadline + 45 s/70 s rows |
| B4 | keyset-paged sweep (10 000/page) with a no-progress guard | `the_sweep_pages_to_the_same_candidate_set` |
| C1 | persisted allowlist `error, target, tag, kind, endpoint_id`, 256-byte cap | allowlist test (params still session-only) |
| C2 | `describe_error` (three sources) in the fetch failure | synthetic two-level error |
| S1 | `docs/reference/database.md` records the `name`-kind and auth-ack caveats | docs |
| review F1 | `settle_starved` counts a starved lookup as REPORTED (the retry meter) while still writing no verdict — without it a feed-wide retry holds the maintenance job for its 30-minute bound | `a_starved_lookup_completes_the_meter_without_a_verdict` |
| review F2 | Compact's merge copies the pair with the error text (`merge.rs::overwrite_link_fields`) | merge fixture now seeds `(Transport, Status)` and asserts it moves |
| review F3 | The starvation test now drives the settle seam, not only `acquire_permit` | see F1's test |
| review F4 | `TUNNEL_READ` had no consumer after the split; deleted (CONNECT is its own 15 s constant) | docs updated (AGENTS, architecture, plan) |

## Deliberately not planned

- **Coalescing `NamesResolved`** into one debounced writer (log report F3,
  recommendation 2): B2 removes the hard failure. If `database is locked`
  warnings persist after it, that is its own slice with its own measurement.
- **DNS permit count / chunked dispatch fan-out:** B1 makes queue starvation
  harmless; throughput is unmeasured and tuning without a number is noise.
- **Value CHECKs on `error_stage`/`error_cause`:** a table rebuild for a
  constraint the typed writer cannot violate; fold into the next rebuild (D1
  makes that rebuild necessary anyway).
- **A `name`-kind schema rebuild and a feed-budget code change:** D1 is
  deferred to the next rebuild; D3 is an operator setting (256 MiB default,
  stored 64 MiB), not code.
- **The ENOSPC incident** (2026-11-19 11:43) is environmental; the client
  behaviour it produced is already correct (keep rows, say so).

## Verification

Per task above, then:

```sh
cargo nextest run -p leas-db -p leas -p leas-native
just quality-gate code
```

Live seam (the user-visible proof): with the app running, probe one link from
the menu, then

```sh
~/.turso/tursodb ~/.config/leas/data.db \
  "SELECT error_stage, error_cause, purge_reason FROM profile_stats WHERE error=1 ORDER BY updated_at DESC LIMIT 5;"
```

A1 passes when the pair is non-NULL and agrees with `purge_reason` on the rows
that carry one. A2 passes when a ws-status failure reads `transport/status`
rather than `transport/alert` in the same query.

## Risks and retirement

- **A1** adds ~20 bytes per row to the hottest write path (1 606 flushes per
  114-min run). Acceptable; if a hot-path check objects, the strings are already
  `&'static str`.
- **A2** changes the class of every row whose wrapped inner is a boxed
  `NativeError` (the 5 199 prose rows are the ceiling, not the count — Step 0
  decides). Rank and purge read `purge_reason` (evidence-derived) and
  `transport_failed` (unchanged), so the visible effect is the typed columns,
  the gained `transport_rejected` verdicts, and `[dest]`; measure one batch
  before the next full run.
- **B1** changes scheduler inputs; the deferral budget is the risk. Keep the
  ≤ 16 s report bound and re-run the log-review query on the next retry.
- **B3** trades memory for connection lifetime only (no buffer change); the
  paused-time test pins both sides of the threshold.
- **Retirement**: A1 completes S1 (no owner removed). D1 **is retired**: no
  writer exists, S1 marks the kind legacy, and the CHECK drops it at the next
  table rebuild for another reason — not a bump of its own.

## Execution handoff

Route: **inline** (tasks are ordered, share the DB seam, and B1/B3 need live or
paused-time checks that coordinate better in one session). A1+A2 (+S1's docs
paragraph) are the first commit-sized slice; B1+B2 the second; B3 the third;
B4/C1/C2 independent. Subagents would need the same baseline and would race on
`database.rs`.

User confirmation required: **no** — the three decisions are answered and
recorded. The one operational follow-up is outside the repo: raise or delete
the stored `import.max_feed_bytes` (64 MiB) in `~/.config/leas/config.json`;
the compiled default is 256 MiB.
