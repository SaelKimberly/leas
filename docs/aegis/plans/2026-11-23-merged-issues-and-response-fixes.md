# Plan: merge the 2026-11-23 issues review with the real-test response analysis

**Status**: draft — decisions grilled 2026-11-23, ready to execute
**Sources**: `issues-research` branch, `docs/issues/` (28 findings, review loop
iteration 11) and `docs/research/2026-11-20-real-test-response-analysis.md`
(8 findings, measured run).
**Aegis visibility**: one P0 is a wire-correctness defect (`012`), three are
security/contract gaps (`025`, `026`, `020`), and two sources disagree about
the same function — a durable plan is what keeps the merge honest and keeps a
later reader from "fixing" a stale item.

This plan is written on `native-core-stub` at `ba63601`. The `issues-research`
branch has 12 doc commits this branch lacks, and lacks 4 commits here (the
2026-11-20 DNS redesign and the response analysis — 26 crate files differ), so
every disposition below is re-checked against `ba63601`, not against the
branch's base (`c9ea7b13`).

## 1. Goal and acceptance

Goal: one ordered workstream that closes every *valid* finding from both
sources, retires the findings that are already fixed, and proves each fix at
the seam it changes.

Acceptance (user-visible, not just green tests):

1. A `?ed=N` WS link's first bytes reach the carrier **once**, in the
   `Sec-WebSocket-Protocol` header, and a rejected upgrade is classified
   `transport/status` — never `TLS error`.
2. A non-VLESS peer on a VLESS port is classified `protocol/framing`, not
   `transport/alert`.
3. TLS: `Finished` MAC comparison is constant-time, and a ServerHello
   key-share group that was not offered (or disagrees with the HRR's
   `selected_group`) is **rejected**.
4. A stalled relay write ends the tunnel; the accept layer enforces one
   configurable cap (default 1024) across all three listeners; a burst does not
   open one handshake per CONNECT; a row's `mux` cap reaches the pool.
5. DNS: a wedged resolver costs 10 s at most (`attempts = 1`); the
   resolved-answer TTL is time-since-answer; a starved host is deferred, never
   dialed. The 8 s lookup budget stays (no tail raise).
6. DB: no orphan link can be staged; a merged endpoint pair does not read the
   whole protocol table; write contention no longer drops result chunks.
7. `last_seen_at` moves on exactly two kinds of event — the source lists the
   link, or the client proves it alive (probe success / active use) — and a
   seam test proves a failure-only write never moves it.
8. The user's next real-test DB snapshot shows the early-data bucket split
   (`status` not `alert`); the agent never launches that batch. The pinned-core
   WS `?ed=` oracle row is green.

Non-goals: re-keying the `error_kind` taxonomy (`F7` — documented, not
changed), raising the probe budget (the replay proved 0/680 rescued), and any
purge/approval change beyond the two-source `last_seen_at` rule in T11.

## 2. Finding inventory and disposition

Severity is the reviewer's; disposition is this plan's.

| Source | ID | Title (short) | Sev | Disposition at `ba63601` |
| --- | --- | --- | --- | --- |
| issues | 012 | WS early data duplicates the prefix | **high** | **P0.** Verified in code (`ws.rs:180-231`): capture returns `Pending`, replay loop sends `early`, then `poll_write(data)` sends the same bytes again. |
| analysis | F1 | early-data path loses the error type | high | **P0, same task as 012** — same function, same test harness. |
| analysis | F2 | `0x48` header filed as TLS alert | med | **P0** (small, isolates a bucket). |
| issues | 025 | Finished MAC compared with `!=` | low | **P1** (security). Verified at `handshake/mod.rs:602`. |
| issues | 026 | ServerHello key-share group never checked | low | **P1** (security). Verified: `hrr_group` is stored (`:1077`) and never compared. |
| issues | 001 | no admission control, accept loop ×3 | med | **P1** |
| issues | 002 | relay write has no deadline | med | **P1** (pairs with 001) |
| issues | 003 | UDP association eager 192 KiB | low | **P1** (same owner as 001) |
| issues | 004 | row mux cap never reaches the pool | med | **P1** |
| issues | 006 | pool-wide build gate; fallback not registered | med | **P1** |
| issues | 005 | mux key rebuilt twice per dial | low | **P2** (fold into 004's task) |
| analysis | F4 | write contention drops result chunks | high | **P1**, merged with 018/020 in the DB lane |
| issues | 018 | merge rescans the protocol table per pair | med | **P1** |
| issues | 019 | feed search scans rank table per keystroke | med | **P2** |
| issues | 020 | no FK → orphan links | med | **P1** (latent: 0 orphans in the 2026-11-20 snapshot) |
| issues | 021 | DNS-retry failure reports `CompactFinished` | med | **P1** (queue wedge for the session) |
| issues | 013 | wedged resolver costs 15 s under an 8 s deadline | med | **P1.** Still true: hickory's TCP/TLS connect bound is a fixed 5 s outside `ResolverOpts`, `attempts` makes 3 sends. |
| issues | 014 | cold list download livelocks DNS | med | **Closed — superseded by `2026-11-20-dns-resolvers-design` D2** (the resolver no longer downloads inside a lookup; the source refresh is a job). Keep only its "source fetch must not block lookups" invariant as a test. |
| issues | 015 | resolved cache restamps its own TTL on hit | med | **P1.** Verified: `engine.rs:610-645` puts the hit back, `resolve.rs:78-84` re-stamps. |
| issues | 022 | DNS failure sweeps the whole deferral map | low | **P1** (same owner as F5's deferral work) |
| issues | 027 | UDP association `seen` list unbounded | med | **P1** |
| issues | 028 | UDP association pins the first DNS answer | med | **P1** |
| analysis | F5 | DNS starvation / 8 s budget / pool rotation | high | **P1**, merged with 013/022/027/028 |
| issues | 017 | unrepresentable condition token widens a rule | med | **P1** (routing correctness: matches MORE traffic) |
| issues | 016 | UDP flow re-routed per datagram | low | **P2** |
| issues | 010 | xhttp dispatches by TLS presence, not its table | med | **P2** |
| issues | 011 | xhttp h1 upload dial bypasses the chain | low | **P2** |
| issues | 007 | datagram recv copies owned `Bytes` | low | **P2** |
| issues | 008 | handshake buffers keep a credential unwiped | low | **P2** |
| issues | 009 | hysteria2 slots sized from peer `frag_count` | low | **P2** |
| issues | 023 | Sniffer scroll clamps to host | low | **P3** |
| issues | 024 | Sniffer rebuilds all rows per frame | low | **P3** |
| analysis | F3 | import restamps `last_seen_at` | design | **P1 enforcement task (T11).** User rule (grilled): stamp only when the source claims the link alive or the client proves it alive; failures never stamp. Three writers to reconcile: import (`state.rs:642`), probe success (`LinkGroups::SEEN`), and **connect initiation** (`connect.rs:85` `update_last_used`, which stamps before a tunnel exists). |
| analysis | F6 | 64 MiB feed budget truncates | med | **P2** (config/UX) |
| analysis | F7 | `error_kind='fast'` covers stage-1 | med | **P2** (documentation/reader rule) |
| analysis | F8 | fast-path marker has no pair | low | **P2** |

Contradictions worth recording:

- **F1 vs 012.** Not a contradiction: 012 corrupts the tunnel *after* a
  successful upgrade; the 4650 stale-class rows are upgrades the server
  rejected before any frame. Both are real; the same function is the owner.
  012's fix (report the capture consumed, delete the replay) makes F1's fix
  simpler: one write path, one place where an upgrade failure becomes an
  `io::Error`.
- **014's premise is dead.** Any plan that budgets the list download against
  the lookup deadline would undo D2.
- **020 is latent, not active.** 0 orphan rows in the measured DB; the guard is
  still a guard.

## 3. Requirement ready check

| Item | State |
| --- | --- |
| Approved source | issues branch docs (theory + reproduced 012) and the measured run report |
| Scope | the 28 issue docs + the 8 analysis findings, deduped above |
| Scenarios | one per task's seam test; live proof = the user's next real test (never started by the agent) + the replay sample |
| Acceptance | §1 items 1-7 |
| Open decisions | D1 (`last_seen_at` semantics), D2 (`error_kind` rule) — both "no behaviour change without the user's call"; they block only F3/F7 tasks |

## 4. TDD route

`TDD Route` — mode `auto`; decision **strict** for T1, T2, T3, T4, T6, T8
(wire, security, liveness, persistence, routing); **light** for T5, T7, T9,
T10 (perf/UX, each with one focused measurement or unit check); **skipped** for
the documentation-only dispositions (F3, F7). Authority: this plan; the repo's
"a test earns its place" rule.

Every strict task starts from the failing seam test named in the task, not from
the fix.

## 5. Tasks

### T1 — Early data: one copy on the wire, one class in the DB (P0)

Files: `crates/leas-native/src/transport/ws.rs`,
`crates/leas-native/src/security/mod.rs` (test only).

Semantics verified before planning: `AsyncWriteExt::write_all` retries
`poll_write` with the same remaining slice while the write reports `Pending`, so
the completion path's `poll_write(data)` re-offers the captured prefix — and the
replay loop re-sends `early` besides. Even if a caller supplied only the
remainder, the replay loop alone would duplicate it. The fix is the same either
way.

Change: the capture branch returns `Poll::Ready(Ok(take))` (bytes consumed
*into the header*) and the stream never touches them again — delete the `early`
replay loop, `early_pos`, and the `.max()` arithmetic. Keep the failed-upgrade
error typed: box the `NativeError`, do not format it. Return `Pending` in
`poll_read` only after registering a waker (or make the no-upgrade read an
explicit `Unsupported` — 012 records it as latent, so choose the waker).

Tests (both assertions, per 012):
- header decodes to the whole first buffer; frames are **empty**;
- a 400 upgrade under `?ed=` classifies `TransportRejected{status}` through
  `map_tls_err`, and `profile_stats` stores `(transport, status)`.

Add the missing oracle row first: a `vless` ws link with `?ed=2560` against the
pinned xray-core server in `crates/leas-oracles/tests/vless.rs` (the plugin path
disables early data, so this row is the only end-to-end cover). The row must
fetch the probe target through the tunnel — a corrupted first flight fails it.

Acceptance: `cargo nextest run -p leas-native transport::ws`,
`cargo nextest run -p leas-native early_data`, and the new
`cargo nextest run -p leas-oracles vless::ws_early_data`; the 2026-11-20 replay
sample's 27 ed rows stop producing `TLS error: I/O error:` lines. Snapshot
baseline to beat: ed ws links show `framing` 8 times against 778 for non-ed ws
links — after T1 the ed rows should begin to reach the protocol stage instead of
dying at the upgrade.

### T2 — VLESS response-header class (P0)

Files: `crates/leas-native/src/protocol/vless/stream.rs`,
`crates/leas-native/src/error.rs` (if a typed variant is needed).

Change: the non-VLESS version byte raises a typed protocol/framing failure
instead of `io::Error::new(InvalidData, …)`, so a target-TLS read cannot turn
it into `Tls(String)`. Do not merge it with the truncated-EOF case (that one is
already correct). Test: one unit that drives the peel with `b"H"` and asserts
the class, plus the stored pair through the existing writer test.

### T3 — TLS conformance: constant-time Finished, offered/HRR group (P1)

Files: `crates/leas-tls/src/handshake/mod.rs`, `tls12.rs`.

Change: compare MACs with the crate's constant-time helper; record the offered
key-share groups in the ClientHello state; **reject** (not merely record) a
ServerHello group that was not offered and a group that disagrees with
`hrr_group` (user decision 2026-11-23: strict). Tests: `#[rstest]` over
(offered, hrr, returned) triples, each asserting accept/reject; the constant-time
helper is already tested where it lives, so the MAC task adds only the call-site
change.

### T4 — Inbound liveness: admission, write deadline, UDP buffers (P1)

Files: `crates/leas-native/src/inbound/{mod,http,mixed,outbound}.rs`.

Change: one accept helper with a semaphore shared by the three listeners (not
copied), sized from a new config field defaulting to **1024** concurrent
tunnels and surfaced on the status bar when it rejects; `copy_half`'s
`write_all` under the same idle deadline as the read (one `select!` on write vs
deadline, re-armed by `Idle`); allocate an association's buffers on first
datagram. Note the config surface is a new `[inbound]` key, so plan the settings
form row with it. Tests: a stalled-reader duplex proves
the write half ends; a 3-listener test proves one cap; an allocation-count test
for the association.

### T5 — Mux pool: cap, gate, key (P1)

Files: `crates/leas-native/src/mux_pool.rs`, `context.rs`,
`crates/leas/src/ops/native_connect.rs`.

Change: carry `MuxPolicy::cap` from the row's `mux`/`muxConcurrency` into the
key and the stream limit; make the build gate per-key; register the 1 s
fallback carrier; build the key once per dial (no `Debug` formatting twice, no
clone into the map). Tests: two rows with `mux=4` and `mux=32` dial different
carrier counts; a >1 s burst produces one carrier; the key is built once
(allocation count).

### T6 — DB: orphan guard, merge cost, write contention (P1)

Files: `crates/leas-db/src/{write_behind,database,merge}.rs`,
`crates/leas/src/ops/{compact,profiles,ping}.rs`.

Change: the delete path removes a link's staged patch or writes the link only
if its endpoint survives (refresh the staged set under the same transaction);
merge loads the protocol table once per batch, not per pair (018); the feed
search's footer count runs over the same materialized keys as the page instead
of a second rank-table scan (019); result chunks retry past the first busy
timeout, and background `resolved_at` updates are folded into the same batch. Tests: a staged patch whose endpoint is deleted leaves no
row; a 2-pair merge reads the protocol table once (statement counter); a
replayed 5 s busy failure still lands its chunk.

### T7 — App ops: queue terminal event, deferral sweep, feed budget, markers (P1/P2)

Files: `crates/leas/src/ops/{compact,job_scheduler,scheduler,enrich}.rs`,
`crates/leas/src/ops/stream_import.rs`, `crates/leas/src/ops/ping.rs`.

Change: a DNS-retry failure emits `MaintenanceDone` (or the scheduler maps the
failure to the task kind) so the queue cannot wedge; a DNS failure marks the
host in a side set swept once per dispatch, not the whole map; the feed budget
message names a key the Settings form exposes (F6); the fast path computes
`(dial, …)` and carries it on the event (F8). Tests: a failing DNS retry lets
the next task run; a 1000-failure burst does O(F) scans; the fast marker round
trips its pair.

### T8 — DNS: deadline tail, TTL, starvation, UDP pin (P1)

Files: `crates/leas-dns/src/lib.rs`, `crates/leas/src/ops/{enrich,dns}.rs`,
`crates/leas-route/src/{resolve,engine}.rs`,
`crates/leas-native/src/inbound/mod.rs`.

Change (user decision: `attempts = 1`, keep 8 s): set
`POOL_OPTS.attempts = 1`, halving a wedged resolver's cost from 15 s to 10 s
and letting the other pool members carry failover — do **not** raise
`DNS_LOOKUP_TIMEOUT`; size `RESOLVE_SEM` from `real_ping_concurrency`; a starved
host is deferred, never dialed (F5); cache hits read without `put`
(`get_fresh` is already the right read); the UDP association's resolution
carries a TTL and a family retry (028) and its `seen` set is bounded (027).
Tests: a wedged TLS name server cannot exceed the caller's budget; a hit at
`ttl-1s` expires at `ttl`; a starved host is not probed; a 65th host evicts.

### T9 — Routing correctness and datagram cost (P1/P2)

Files: `crates/leas-route/src/{route_compile,geodata}.rs`,
`crates/leas-native/src/inbound/mod.rs`.

Change: a condition field whose every token is unrepresentable is a **compile
error / disabled rule**, never a dropped field (017); a UDP flow caches its
decision per 5-tuple for a bounded window instead of re-routing each datagram
(016). Tests: a rule with one unrepresentable token does not match a host the
full rule rejects; a 100-datagram flow routes once.

### T10 — Transport and datagram hygiene (P2)

Files: `crates/leas-native/src/transport/xhttp.rs`,
`protocol/hysteria2/udp.rs`, `protocol/vless/packet.rs`,
`protocol/{trojan,first_flight,vless}/…`, `crates/leas/src/ui/sniffer.rs`.

Change: xhttp dispatches from `http_version()` (010) and its plaintext h1 upload
uses the chain (011); datagram receive forwards the owned `Bytes` without a
copy (007); credential buffers are `Zeroizing`/wiped (008); the defragger
validates `frag_count` against a bound before sizing (009); the Sniffer clamps
to pages (023) and builds rows lazily for the painted window (024). Tests:
one per claim, plus the existing hotpath counts for 007.

### T11 — `last_seen_at` has exactly two producers (P1)

Files: `crates/leas-db/src/{database,write_behind}.rs`,
`crates/leas/src/state.rs`, `crates/leas/src/ops/{ping,events}.rs`.

Change (user rule): the stamp moves when the **source claims** the link alive
(feed import, `link_from_parsed_with_id`) and when the **client proves** it
alive (a data-carrying success, the `LinkGroups::SEEN` stamp; active use counts
as proof). A failure, a DNS retry, a traffic flush or a merge must never move it
forward; a merge may only preserve the stored value. Audit every writer and
delete or narrow any other producer.

The third writer is explicit: `connect.rs:85` calls `update_last_used`, which
sets `last_used_at` **and** `last_seen_at` (`database.rs:1603`) at connect
*initiation* — before any tunnel exists, so a failed connect rejuvenates the
row. Split it:

- initiation writes `last_used_at` only (`update_last_used` loses its
  `last_seen_at` assignment, or grows a caller flag);
- the initiation site records the link it is dialing on `AppState` (endpoint id
  is already there as `connected_protocol_id`; the protocol id needs one field),
  and `CoreEvent::Connected` (`events.rs:446`) stamps `last_seen_at` for that
  link — a built tunnel is proof, an attempt is not;
- `Error`/`Disconnected` clear the pending pair without stamping.

Tests: a connect initiation alone leaves `last_seen_at` unchanged and sets
`last_used_at`; `Connected` moves it; a connect error does not; a failing probe
result leaves it unchanged; a successful probe moves it; a merge of two
endpoints preserves the max without advancing; a feed re-import still moves it
(that IS the source claim). Live check, on the user's next batch: one import,
one failed batch, one successful connect — only the last two touch the stamp
for their rows.

## 6. Grilled decisions (2026-11-23)

| # | Decision | Answer | Effect on the plan |
| --- | --- | --- | --- |
| D1 | `last_seen_at` producers | **Two only**: the source claims the link alive, or the client proves it alive (probe success / active use). Failures never stamp. | T11. The import restamp stays — it is the source claim. Connect **initiation** is intent, not proof, so its `last_seen_at` write moves to the successful build. No new stamp column, no schema step. |
| D2 | DNS wedged-resolver cost | **`attempts = 1`**, keep the 8 s lookup budget; no tail raise. | T8. A wedged server costs 10 s, and pool rotation carries failover. |
| D3 | TLS 026 group handling | **Strict**: reject an unoffered group and any HRR `selected_group` disagreement. | T3. |
| D4 | Inbound admission cap | **Configurable, default 1024**, shared by all listeners, visible when it rejects. | T4 (adds an `[inbound]` setting). |
| D5 | Execution scope | **All** findings, P0 through P3. | T1-T11, including the P2/P3 lane in T10. |
| D6 | Proof of landing | **Run the real-core oracles** for the wire/security fixes. | T1 adds a pinned-core `?ed=` row; T3 runs the TLS oracle rows before merge. |

Still open (not behaviour, reader-facing):

- **D7 — `error_kind='fast'` (F7).** The plan documents the rule (kind is
  stage-conditional: `fast` ⇔ `dial`) and does not re-key the column. Promote to
  a task only if a UI/report consumer needs the real-test scope.
- **D8 — probe budget (F5).** Not raised; 0/680 rescued at 15 s.

## 7. Verification

Per task: the named test, plus `cargo nextest run -p <crate>` for its crate.
Whole branch: `just quality-gate code` (fmt + clippy workspace + nextest).
Wire/security tasks (T1, T3) additionally run `cargo nextest run -p leas-oracles`
(`vless` mux/`ws` rows) because the changed bytes cross a real server.
Live proof is a handoff, not an agent step: the user runs `Real Test (All
Profiles)` after T1+T2 (it takes hours; the agent must not launch it). The agent
then exports the log store, runs the response-taxonomy query from the analysis
doc, and reports the delta — expectation: `transport/alert` drops by ~4 650 (ed
rows) and ~685 (`0x48`), and ed rows start producing `protocol`/`framing`
outcomes (baseline: 8 framing among ed ws links vs 778 non-ed).
Allocation work (T5, T10-007/024) runs `just hotpath` where a budget exists and
`just memtrace` for the rest.

## 8. Risks and retirement

| Risk | Mitigation |
| --- | --- |
| Early-data fix changes the first bytes on the wire | T1's two-assertion test + the pinned-core `?ed=` oracle row, both required before merge |
| Admission cap changes throughput under load | default 1024 is above today's observed concurrency (100 probes, 4,429 accepted connections/day); measure the batch before/after |
| `RESOLVE_SEM` resize raises DNS fan-out | the pool is already the measured fast set; observe 429s, do not raise concurrency past `real_ping_concurrency` |
| TLS group check rejects servers a lenient client accepted | strict is the decision; the oracle rows prove the pinned cores still negotiate |
| Merge/search rewrite regresses the page query | keep the existing page tests; 019 changes only the count path |

Retirement: 012's replay loop, `early_pos`, the `.max()` return arithmetic, the
three copies of the accept loop, the per-pair protocol scan, and the
`CompactFinished` mapping for `DnsRetry` are **deleted**, not deprecated. 014's
download-in-lookup path is already gone; add only the invariant test.

## 9. Execution route

Inline on `native-core-stub` (workspace shared with the user's in-flight work;
files overlap across tasks, so subagents would collide). Order: T1 (with its
oracle row), T2, T3, then T4/T5, T6/T7/T11, T8/T9, T10. Commit per task after
its crate suite — and, for T1/T3, the oracle rows — are green.
`User confirmation required: no (decisions D1-D6 answered 2026-11-23). The
real-test run after T1/T2 is the user's to launch; the agent's part is the
export + taxonomy query, and it is a handoff, not a gate.`
