# Log review: the 2026-11-19/20 real-test run

Evidence study from the persisted log store (not the database). Window:
**2026-11-19 13:00:04 → 2026-11-20 06:46:56** — the run that started with
`Real Test (All Profiles)` and continued through the DNS retry cycles and a
second `Real Test (Failed)` planning pass. 60 263 entries: 38 829 `warn`,
21 393 `info`, 41 `error`.

This complements [`2026-11-19-real-test-funnel.md`](2026-11-19-real-test-funnel.md),
which reads the same run from a DB snapshot (funnel, per-bucket verdicts,
recommendations by evidence per unit work), and
[`2026-11-20-failure-pair-review.md`](2026-11-20-failure-pair-review.md),
which reads the DB's typed failure columns (all NULL — the writer defect).
This document reads what the
application itself *said* while it ran, and what only the timeline shows:
queue starvation, a relay idle cap below the carried protocols' heartbeat
intervals, write contention, and what the log layer deliberately drops.

Method and limits are in [§8](#8-method-and-limits). The `CHECK constraint
failed: transport_type / proto_kind` rows that dominate the full export are
**excluded**: already fixed, and they do not appear in this window at all.

## 1. Headline

| Fact | Value | Source |
| --- | ---: | --- |
| Batch `Real Test (All Profiles)` links planned | 109 524 | `batch: planned`, 13:49:22 |
| Wall time for that batch | **6 868 668 ms (1 h 54 m)** | `batch summary`, 15:43:47 |
| Links deferred by the DNS gate at plan time | **102 507 (93.6 %)** | same summary |
| Probes that succeeded | **15** | same summary |
| Probes that failed | 109 279 (timeout 65 682, dial 23 943, tls 13 655, transport 4 659, protocol 1 100, reality 225, io 14, config 1) | same summary |
| Write-behind flushes | 1 606 | same summary |
| DNS lookups that timed out | **36 645** (12 522 distinct hosts) | `tui::ops::enrich` |
| DNS timeouts in the first 6-second cliff (13:49:26–31) | 12 093 | `tui::ops::enrich` |
| User connections accepted through the tunnel | 10 217 | `leas_native::inbound` |
| … closed by our own 30 s relay idle cap | **8 760 (85.7 %)** | `relay read timed out` |
| SQL statements ≥ 1 s | 626 (p50 2.0 s, p90 4.8 s, p99 14.0 s, max **143.7 s**) | `toasty::query` |
| SQL statements that failed at ~5 s (busy-timeout ceiling) | 183 (101 INSERT, 82 UPDATE) | `query failed` |
| `database is locked` write failures | 67 (62 marker clears, 5 write-behind) | `leas_db`, `tui::ops::events` |
| Subscription updates that completed | 288 | `tui::ops::subscriptions` |

The run's headline is not "15 of 109 524 links work" — the funnel document
already establishes that as a statement about the feeds. It is that **93.6 %
of the batch never reached its first probe on schedule**, because the DNS gate
deferred them, and the mechanism is in [§2](#2-f1--the-dns-gate-starves-itself-936-deferred).

One boundary matters for reading that: the deferral explains *when* links were
probed, not *why they failed*. The five later small batches show links still
probing normally (1 264 links → ok 15 / failed 1 238; 14 links → ok 5 /
failed 9) and the big batch did probe everything it deferred. So the outcome
classes — `timeout` 65 682, `dial` 23 943, `tls` 13 655 — are transport
verdicts from probes that ran, not a DNS artifact. F1 is a timeline and
load defect; the low success rate is the funnel document's subject.

## 2. F1 — The DNS gate starves itself (93.6 % deferred)

### What the log shows

- Batch starts 29 s after process start (`startup` 13:48:53, `planned` 13:49:22),
  so every host is cold.
- 13:49:26–31: **12 093 DNS timeouts in six seconds**, each one exactly
  `DNS lookup of <host> timed out`. Not spread over the run — a single cliff.
- `batch summary` 15:43:47: `deferred=102507`, `untestable=168`.
- The retry loop repeats the same shape five times on Nov 20: dispatch
  ~9 200 endpoints, log `complete` ~10 s later, with **4 195 timeouts landing
  in one second at t+8 s** (04:17:08, 04:24:40, 04:25:20, 06:07:54, 06:37:21).
- Host-set overlap between the 13:49 burst and the 04:17 retry: **4 169 of
  4 214** hosts are the same names. The retry re-times-out what the first pass
  already failed.

### Mechanism

`crates/leas/src/ops/enrich.rs`:

- `DNS_LOOKUP_TIMEOUT` = 8 s (`:51`), `RESOLVE_SEM` = 64 permits (`:310`).
- The deadline wraps the semaphore **acquisition and** the lookup (`:497`):
  a lookup that never gets a permit still burns its full 8 s and is reported
  as a DNS failure. `Ok(None)` (semaphore closed) and `Err(timeout)` are the
  only outcomes; a queued-and-starved lookup is indistinguishable from a
  resolver timeout.
- The timeout path falls through to `scheduler.mark_dns_failure` (`:588`),
  which is the same signal a real `EAI_NONAME` produces.
- `ScheduleOutcome::DnsDeferred` (`crates/leas/src/ops/ping.rs:2235`) is the
  counter behind `deferred=`.

Arithmetic that fits the log exactly: with 64 permits and an 8 s budget, a
lookup that hangs occupies its permit for the whole deadline and serves one
request per 8 s — so a resolver that is failing, or slow on dead names,
delivers at most ~512 answers per 8 s window however many are queued. A
feed-wide pass enqueues 12 000+ hosts in the same tick; the leading 64 hold
their permits for the full deadline (the cliff cannot distinguish a hang from a
slow answer), and every host behind them expires while still queued. That is
why the timeouts land in one-second clumps and why the retry set (dominated by
names that already failed) never drains — the leading lookups own the permits
for their whole deadline.

The consequence is not just a slow batch: every timed-out host marks its
endpoints' DNS state failed and defers their links 15 s — that is where
`deferred=102507` comes from. The persisted `[name]` marker is then written by
probes that ran without an address (bucket 02 in the funnel document,
12 913 links), and 13 590 group releases / 64 568 transport-unreachable
retirements follow from probes run against a 30 s wall clock while their names
were still unanswered.

### Recommendation

1. **Deadline the resolver call, not the permit wait.** Acquire the permit
   outside the timed section (or with a separate, progress-reporting budget);
   only `lookup_ip` gets the 8 s. A queued lookup must report "waiting", never
   `mark_dns_failure`.
2. **Never write the `[name]` marker from a queue timeout.** The marker is a
   resolver verdict; today it also records scheduler congestion. Distinguish
   the outcome at the `match` and keep the marker for
   `EAI_NONAME`/`EAI_FAIL` only — this also fixes the stale-marker problem the
   funnel document §4.8 describes, whose current clear path
   (`NamesResolved` → `clear_name_markers`) is itself now the write-lock
   storm in §3.
3. **Chunk the retry job.** 9 188 dispatches in one tick guarantees the same
   starvation. Dispatch in windows of ~`permits × 8 s worth` and let the
   progress meter mean "answered", not "expired".
4. **Sequence the batch after the first enrichment pass** (or make the DNS
   gate wait on it): the batch planned 109 524 links 29 s after process start,
   while the cold-host resolve pass was still running — that overlap is the
   direct cause of every deferral in this window.

## 3. F2 — The relay's 30 s idle cap dominates connection churn

### What the log shows

- 10 217 connections accepted; 8 760 (85.7 %) closed with
  `error=I/O error: relay read timed out`.
- Durations cluster just past the cap: 5 444 closed at 30.0–30.7 s, 2 088 at
  30.7–32 s, 1 228 later (busy writer).
- Top hosts killed: `alive.github.com` (3 254), `mtalk.google.com` (1 868),
  `gateway.discord.gg` (652 — against 661 accepted, i.e. a reconnect loop),
  `chat.deepseek.com` (605), `grok.com` (537), `music.youtube.com` (475).

### Mechanism

`crates/leas-native/src/error.rs:242` sets `TUNNEL_READ` = 30 s; the relay
(`crates/leas-native/src/inbound/outbound.rs:386`) fails the tunnel once
**neither** direction has moved a byte for that window. The rule itself is
sound and the shared stamp is re-armed by either direction (`Idle` is one
deadline, not one per half), so this is only the *completely silent* case —
an idle browser tab being reaped is expected and correct.

What makes the number worth a change is the host mix: the connections being
reaped are protocol surfaces whose silence is normal but whose liveness
matters. A Discord gateway heartbeat is 41.25 s, so a healthy gateway session
crosses nothing for longer than 30 s; `gateway.discord.gg` shows 652 idle
reaps against 661 accepts, i.e. a reconnect loop that never stays up longer
than one heartbeat interval. `alive.github.com` long-polls, and SSE surfaces
(`chat.deepseek.com`, `grok.com`) heartbeat less often than 30 s by design.
`up=`/`down=` on the closed lines confirm bytes did move before the idle
window.

### Recommendation

Treat this as an enhancement with a measured threshold, not a defect: raise
the relay idle cap to ≥ 60 s (one Discord heartbeat plus margin). The constant
is the relay's own (`RELAY_IDLE`); the CONNECT budget is a separate constant
and is unaffected. The reconnect churn is the metric to re-check: 661 accepts
for 652 reaps on one host.

## 4. F3 — Write contention loses probe results

### What the log shows

- 626 statements ≥ 1 s: p50 2.0 s, p90 4.8 s, p99 14.0 s, max 143.7 s.
  Worst shapes: the purge sweep `SELECT e.id FROM endpoints … NOT EXISTS …
  last_seen_at >=` (max **143.7 s**, 23 occurrences), the page-read
  `SELECT ps.endpoint_id … LEFT JOIN protocols` (max 23.6 s),
  `UPDATE endpoint_rank SET band` (max 18.9 s),
  `INSERT OR REPLACE INTO endpoint_rank` (max 10.5 s),
  `INSERT INTO profile_stats` (max 10.4 s).
- **183 statements failed** after the 5 s `busy_timeout` — 101 INSERT,
  82 UPDATE. Their error text is not in the store (see F4), only the SQL.
- 67 `database is locked` failures: **62** are `clear name markers …` in a
  10-second burst at 06:40:17–26, 5 are write-behind flushes (06:06–06:16).
- The second big plan (`Real Test (Failed)`, 109 497 links) took **17.4 s**
  against 4.2 s for the first — same code, contended store.

### Mechanism

- `clear_name_markers` (`crates/leas-db/src/database.rs:2054`) is the only
  write path in that area **without `retry_on_busy`**; its sibling
  `refresh_endpoint_ranks` retries 5× (`endpoint_rank.rs:894`). It chunks 500
  ids per statement, and `events.rs` spawns one such task per `NamesResolved`
  event — so a mass resolution fans out dozens of concurrent UPDATEs against
  the same rows the batch flushes are writing.
- The purge sweep is documented as a plain read because it once held a write
  lock for 3 s (`database.rs:1718-1723`). Its 143.7 s is **not** the scan:
  `EXPLAIN QUERY PLAN` on a copy of this run's store reports
  `SCAN endpoints AS e USING COVERING INDEX sqlite_autoindex_endpoints_1` +
  `SEARCH p USING INDEX index_profile_stats_by_endpoint_id (endpoint_id=?)`,
  and that statement completes in **0.36 s** on the copy (66 191 endpoints,
  124 391 links — the same file, uncontended). So the 143.7 s is queue/lock
  wait, not a missing index; the code comment's "indexed NOT EXISTS" is
  accurate.

### Recommendation

1. Wrap `clear_name_markers` in the same `retry_on_busy` loop the rank
   refresh uses; it is one line and the failure is a lock, not a defect.
2. Coalesce `NamesResolved` into a single debounced writer (one task, one
   transaction per tick) instead of one task per event. The event already
   carries an id list.
3. **Chunk the purge sweep.** 143 s inside a batch holds a pool connection
   for 143 s while every other query waits. Keyset-page the scan
   (`… WHERE e.id > ?last ORDER BY e.id LIMIT 10000`) so each statement is
   short and the connection is released between chunks; the re-check
   transaction is unchanged. (The engine offers no per-statement deadline in
   this driver, so a timeout is not an option.)
4. Some of the 183 failures are measurement writes (`profile_stats`,
   `endpoint_rank`, `endpoints.resolved_at`): a caller that saw the error has
   no record of the observation. Whether the write-behind retried each one is
   not visible in the store — only the aggregate `staged-left=0`. When F4 is
   fixed, the error text will show which failures are retriable locks and
   which are permanent.

## 5. F4 — The persisted log drops every structured field, by design

### What the log shows

- All 1 132 `socks5 inbound: outbound dial failed` lines are **bare**. The
  emitter supplies `tag`, `target` and `error`
  (`crates/leas-native/src/inbound/mod.rs:436-440`); the store has none of
  them.
- All 183 `query failed` lines carry the SQL but **not the error**, even
  though toasty passes `error` as a field
  (`toasty-core-0.11.0/src/driver/log.rs:146`).
- Consequence: the two highest-volume failure classes in the run cannot be
  diagnosed from the artifact a user can export.

### Mechanism — deliberate, and it is a security boundary

`crates/leas/src/main.rs`: `LogVisitor::split` (`:74-98`) keeps `detail` —
every field except `message`, `duration_ms` and `db.statement` — out of
`LogMessage` and sends it session-only (`:186-200`). The reason is documented
at `:32-52`: enabling toasty's statement params would put
`protocols.config` (UUIDs, passwords) on the `toasty::query` event, so params
must never enter `LogMessage`; the same rule is a non-goal of the DB query
monitoring spec. `LogMessage` (`crates/leas-core/src/log_heed.rs:32`)
therefore has exactly `level`, `target`, `message`, `timestamp_nanos`. The
`error=`, `up=`, `down=` text that DOES appear in the store is hand-formatted
into the message string by the emitting call site (the relay's single `info!`
format string), which is why those lines read well and the dial failures do
not.

So this is not a bug to fix by "persist the fields": that would regress a
security decision. It is a **diagnosis gap** the maintainers have already hit
once — the comment at `:53-58` records the 2026-10-01 run leaving 12
deferral warnings in heed that named no row.

### Recommendation

Extend the existing special case (`duration_ms`, `db.statement` are already
persisted by name) with a small **non-secret allowlist** — `error`, `target`,
`tag`, `kind`, `endpoint_id` — rendered into `message` at split time, and
keep everything else, `db.params` above all, session-only. A code comment
should state why each name is safe (they are connection/identity labels, never
config values). Cheap, no schema change, and it makes the export
self-explaining for the two biggest failure classes.

## 6. F5 — Subscription imports: cause-less fetch errors, silent truncation

### What the log shows

- 288 updates completed; 41 errors. The 24 fetch errors all share one shape:
  `HTTP fetch failed: error sending request for url (…)` — reqwest's top-level
  `Display`, with **no source chain** (no DNS / TLS / timeout cause).
- 16 updates hit the byte budget:
  `Feed exceeded the 64 MiB byte budget … stopping with partial results`.
  The stored rows are kept and the message is honest, but those 16 imports were
  incomplete by size.
- Validation is doing its job and is legible: 48 summaries name the rules
  (`parse error`, `shadowsocks method none on a cleartext wire`,
  `vless flow xtls-rprx-vision requires TLS/REALITY`, `invalid hostname`).

### Recommendation

- Log `{e:#}`/`{e:?}` at `crates/leas/src/ops/stream_import.rs:706` so the
  text names the stage. Cheap, and it is the same fix as F4 at the call site.
- **The 64 MiB is this machine's stored override, not the default.** The
  compiled default is 256 MiB (`leas-config/src/app_config.rs:84`), raised on
  2026-11-16 for exactly this reason (ADR 17 in
  `docs/architecture/decisions.md`), and `serde` keeps a stored value. So no
  code change is due: raise the `import.max_feed_bytes` value in
  `~/.config/leas/config.json` (or delete it to inherit 256 MiB). Treat
  truncation as an operator setting until the stored value is updated; the
  import already says which ceiling it hit.

## 7. F6 — Operator-visible signals worth keeping, and one gap

Present and useful, no action: `startup:` (settings echo), `batch planned /
summary` (the only reason this analysis is possible), `DNS retry: dispatched /
complete`, `Subscription updated / DB upsert succeeded`, `public-suffix list
changed … re-import the feed` (fired twice, correctly).

Gap: **`DNS retry: complete` is not evidence of a retry.** It fires ~10 s
after dispatch (04:17:00.579 → 04:17:10.480), i.e. the moment the last queued
lookup expires, because the meter counts reports, not answers
(`bump_resolve_progress`). The same line printed five times while the same
~4 200 hosts failed every cycle, and it was the single line that made the retry
look healthy. After F1 the counter is honest; until then, count `resolved_ok`
only and name the line `DNS retry: dispatched … reported`.

Also: two `startup:` lines in the window (the 13:48 launch and a 05:27 restart
mid-run) and their `Disconnected / Connected [native]` pairs — the run spans a
restart, so per-batch wall times are not directly comparable.

## 8. Method and limits

```sh
cargo run -p leas-core --example dump_logs -- ~/.config/leas/logs.lmdb /tmp/leas-logs.txt
awk '$0 >= "2026-11-19 13:00"' /tmp/leas-logs.txt > /tmp/leas-logs-win.txt   # 60 263 lines
```

- The store is the persisted copy: `TuiLogLayer` drops DEBUG/TRACE before
  storage (`crates/leas/src/main.rs:150-156`). Every per-host success line
  (`Resolved <host>`) is DEBUG and therefore **absent** — the timeout counts
  here are absolute, not a rate over attempts. Do not divide them by
  "lookups attempted"; the store cannot say.
- Counts are line counts over an 18-hour window with two process starts (the
  13:48 launch and a 05:27 restart mid-run) and five DNS-retry cycles. The two
  large batches are distinct jobs
  (`Real Test (All Profiles)` 13:49, `Real Test (Failed)` 06:40).
- The 06:40 batch has no summary in the export (it ends 06:46:56); only its
  `planned 109 497 link(s) … in 17400 ms` line is used.
- Statement latencies are toasty's own `slow query` timing (1 s threshold),
  not an independent measurement.
- The database was opened only as a **copy**, read-only, for the purge-sweep
  plan and timing in §4 (`EXPLAIN QUERY PLAN` + the same statement, on
  `data.db` + `-wal` copied out of `~/.config/leas`). Every other database
  claim comes from the log text or the funnel document's snapshot.

Excluded on purpose: `CHECK constraint failed: transport_type / proto_kind`
(already fixed), and the `turso_core::io::unix` empty-message errors with
`no storage space` (Nov 19 11:43, before the window — a full disk, not this
run).
