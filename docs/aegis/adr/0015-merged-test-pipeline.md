# ADR 0015 — One probe, two measurements: the test pipeline is merged

Date: 2026-10-21
Status: **accepted — DESIGN APPROVED, IMPLEMENTATION PENDING** (three slices:
schema, probe, worker + TUI)
Amends: ADR 0004 (the real-ping engine), ADR 0008 (the batch-feed walk)
Related: `specs/2026-10-21-merged-test-pipeline-design.md`,
`docs/reference/ordering-law.md`, ADR 0006 (purge evidence), ADR 0012 (the
migration cursor)

## Context

The test pipeline measured a link **twice, in two phases, with two verdicts**,
and the two phases disagreed about what a number meant.

The **fast level** (`leas_core::FastPingManager`) opened a raw TCP / UDP /
QUIC socket to the endpoint's address and measured the transport span. It
proved the server's socket accepts a connection and said nothing about the
config: a wrong UUID, a wrong password and a dead backend all read
"reachable".

The **real level** (`ops::ping_native::real_ping`) built the full native
tunnel and issued one HTTP request to `ping_url` over it, then opened a
**second tunnel** to fetch the exit IP. A successful row therefore cost **two
proxy handshakes**, and the documented throughput (~2.45 results/s at
concurrency 5) was really ~5 handshakes/s.

The phases were sequential in substance: the real half was dispatched from the
fast half's settle, and the fast half's transport verdict was the only thing
that could retire the real half early.

Three facts forced the shape of the answer:

1. **A tunnel is bound to one target.** The request headers carry the
   destination, so one connection cannot carry both a truncated-handshake
   measurement and a full probe measurement for the TCP family.
2. **Not every family has an ack.** Trojan and Shadowsocks have silent
   handshakes; sing-box writes the VLESS response header **lazily** (only
   before the first application-data write). A "the server accepted this
   config" signal therefore exists for some families, not others, and an
   unobserved ack is not a rejection.
3. **The 0-RTT premise does not hold.** `into_0rtt()` is called
   (`leas-native/src/transport/quic.rs:170`), but a fresh `rustls::ClientConfig`
   **and** a fresh `quinn::Endpoint` are built per dial
   (`leas-native/src/protocol/hysteria2/quic.rs:155-166`), so the resumption
   store is always empty and 0-RTT never fires. On a feed-wide run every
   endpoint is probed **once** anyway — there is no ticket to reuse.

## Decision

1. **One probe, one verdict.** A link's test is ONE probe that produces the
   transport span, the Auth flag and (where the native engine can serve the
   row) the real span. A failure's **class** picks the marker, so a row never
   carries two contradicting verdicts. The three outcomes are *measured*,
   *transport-only* (the engine cannot serve the config — today's
   `not testable` marker) and *not measurable* (the transport failed).
2. **The Fast metric is the transport span** — the time for the endpoint's
   IP+port to accept a transport — and it is the **same unit** in the Fast
   Test (endpoint scope) and as stage 1 of the Real Test (link scope). The
   alternative, the protocol-handshake span, has **no ack** for two of the six
   servable families and no native handshake at all for 21 of 27 kinds, so it
   would *drop* coverage rather than add it.
3. **The Auth flag is a quad-state success flag, not a metric**: `ok` (the
   ack arrived), `failed` (**positive** rejection evidence only), `n-a` (the
   family has no ack, or the engine cannot serve the row) and `unknown` (the
   ack is possible but was not observed in time). An unobserved ack is never
   `failed`: sing-box's lazy ack means a slow target yields no ack at all, and
   recording that as a rejection would persist a false negative
   indistinguishable from a wrong UUID.
4. **The probe's budgets are per-stage and independent**: the transport stage
   gets `tcp_timeout_secs`, the protocol+probe stage gets the full
   `real_ping_timeout_secs`. They are not a split of one total — the transport
   span must never be truncated by the protocol stage's budget, which is the
   whole point of measuring it separately. A row's worst case is therefore
   10 s (was 5 s), and the merged level is **slower** on hanging servers. That
   cost is accepted: the transport span is the measurement that separates
   "alive" from "dead".
5. **The exit IP is a separate background phase** with the provider fallback
   chain and the provider's rate limit. **Mux rows hand the live connection
   over** — the IP fetch opens a second session on the same proxy connection,
   so the row costs one handshake for both destinations. Non-mux rows reopen,
   because a tunnel is bound to one target.
6. **The exit-IP command never rewrites the Real delay.** The Real delay
   belongs to gstatic's `generate_204`; an IP-API measurement is a different
   destination. The Real delay and the exit IP are therefore
   **independently-aged facts in one row**, and the TUI keeps them in separate
   cells.
7. **One concurrency limit**, `speed_test.real_ping_concurrency` (100). The
   merged limit bounds native handshakes — the expensive stage — so the fast
   level's 200 was never a meaningful ceiling for it.
   `speed_test.fast_ping_concurrency` is **retired** (ignored, not an error).
8. **The worker is a scheduler, and the walk's order is `PageSort::Test` —
   unchanged.** The decision-16 order puts the **working servers first**, which
   is what a feed-wide run wants; a result-independent order is *stable*, but
   stable is not the property that matters. The endpoint **grouping** the
   worker needs already exists for free: `PageSort::Test` sorts ENDPOINTS
   (`profiles_query.rs:372-385`) and each endpoint's links come back together
   (`plan_row_links` → `row.links`), so the group is **contiguous** and the
   worker never mutates the queue to find a sibling.

   At **group entry** the worker consults a plain
   **`HashSet<EndpointId>` of the endpoints whose real probe succeeded**:
   **succeeded** → the whole group is **dropped**; **not succeeded** → the
   endpoint's **first** protocol (the one the law ranks best) is dispatched
   immediately and its **siblings are deferred to the back** of the queue,
   where they are **probed** when reached (a sibling's config may work where
   the first did not). When the concurrency limit is **not reached**, a
   deferred sibling may be dispatched immediately — the **bypass** — and its
   result is a **full result of its own** (its own Fast, Auth, Real and exit
   IP), because a sibling's config may route through a different exit.

   **No bloom filter**: the success set is run-local and tiny (the measured
   real-success rate is 0.03%–1.7%, so tens of ids on a 74k-endpoint run), so
   a bloom filter would add a false-positive dimension to a set that can be
   tested exactly, for no measurable saving.

   **No cancel-on-winner path**: a sibling is dispatched either after the
   endpoint's verdict (the deferral) or via the bypass, and in both cases its
   result is recorded in full. A sibling already in flight when the endpoint's
   winner lands **completes and records its full result** — the endpoint's
   success does not suppress it. The only remaining `cancel_queued` consumer
   is the batch **STOP** path.

   The tier may move mid-run (a sibling can become the endpoint's
   representative); that is the law working, and the frozen plan is still the
   run's plan — nothing re-reads the scope mid-run.
9. **An auth rejection earns NO purge verdict.** It is a marker plus the Auth
   flag; the row stays in Active. See ADR 0006's amendment below.

## Why

- **The measurement, not the plumbing.** The fast level's number was already
  the transport span; the merge makes it the *first stage* of one probe rather
  than a separate connection, so the dataset is measured once and the two
  numbers of a row come from the same attempt.
- **The transport span is the diagnostic the old pipeline threw away.** 531 of
  535 real-timeout rows on the 2026-09-21 run had a **sub-second fast
  latency** — the transport was alive and the timeout was spent later, but the
  merged row showed only "timeout". Per-stage budgets plus a separately
  recorded transport span make that visible: `[12ms] ✓ [err]`.
- **One limit, one bar.** Two knobs for one pipeline is a config surface
  without a meaning, and the Fast progress bar reported a phase that no longer
  exists.
- **The exit-IP handover is free where mux exists.** The engine already has
  `MuxClient::open_session`; using it turns two handshakes into one for the
  rows that have mux, which is the largest single throughput win in the
  change.

## Alternatives considered

1. **Keep two phases and two verdicts, share one semaphore.** Rejected: the
   user rejected it and it merges nothing — the two probes still cost two
   handshakes and the dataset is still measured twice.
2. **The Fast number = the protocol-handshake span.** Rejected: no ack for
   Trojan/SS, and 21 of 27 kinds have no native handshake — the column would
   lose coverage.
3. **The fast delay stored at the endpoint level.** Rejected: a new schema
   surface for a value that is per (endpoint, transport class), with the same
   write amplification.
4. **Two rows per endpoint (one fast, one real).** Rejected: doubles the rows
   and the writes, and the error marker's ownership becomes ambiguous.
5. **The exit IP rides the probe's tunnel.** Rejected: a tunnel is bound to
   one target; only a mux session (or a second connection) reaches a second
   destination.
6. **A per-server QUIC session cache to make 0-RTT real.** Rejected for this
   change: 0-RTT cannot fire on a feed-wide run (one probe per endpoint, no
   prior ticket), and the only re-probe — the exit-IP fill — is already
   covered by the live connection, which dominates it (zero extra RTT, no
   ticket, no early-data rejection path). It remains a valid future change.
7. **An auth rejection earns a purge verdict.** Rejected: the signal is only
   positive for hysteria2 (an explicit non-233), and even there a non-233 may
   be the server's **masquerade** page answering a non-hysteria request — a
   hijacked IP, not a wrong credential. For VLESS/VMess, "the connection ended
   before the ack" is indistinguishable from a crash or a middlebox kill. And
   a false positive **deletes a working profile**. `PurgeReason` is also
   CHECK-frozen, so a new variant forces a `profile_stats` rebuild. Revisit
   condition: measure the Auth-flag distribution; if `failed` shows up on rows
   that later succeed, the flag is unsound and must be dropped.
8. **Stream the rows sorted by endpoint, replacing `PageSort::Test`.**
   **REJECTED by the user (2026-10-21).** A result-independent order is
   *stable*, but stable is not the property that matters: `PageSort::Test`
   puts the **working servers first**, which is what a feed-wide run wants.
   It was also **unnecessary** — the walk already sorts ENDPOINTS and each
   endpoint's links come back together, so the endpoint grouping the worker
   needs exists for free. The proposal would have cost a sort and lost the
   ordering property, for nothing.
9. **The siblings dispatched in parallel during the main pass.** Rejected: the
   walk's front would advance 3× slower on a multi-protocol endpoint, so the
   "working servers first" property would hold only for each endpoint's best
   link, not for the walk's front.
10. **The deferred siblings skipped unconditionally.** Rejected: an endpoint
    whose first protocol has a broken config would never have its other
    protocols tried — a working vless row beside a broken trojan row on the
    same host is never measured.
11. **The scope re-checked before each probe.** Rejected: the run would probe
    LESS than it planned; the freeze exists to guarantee that a scoped run
    probes everything it planned.
12. **The bloom filter deciding alone.** Rejected: a false positive would skip
    a **working** endpoint's siblings — their real delay and exit IP would
    never be measured. Superseded by the ruling below: there is no bloom at
    all, so the question does not arise.
13. **A bloom filter over the success set** (user ruling, 2026-10-21: **no
    bloom at all**). Rejected: the set is run-local and tiny — the measured
    real-success rate is 0.03%–1.7%, so tens of ids on a 74k-endpoint run — and
    a membership test is a hash of 8 bytes. A bloom filter would add a
    false-positive dimension to a set that can be tested exactly, for no
    measurable saving. (`fastbloom` was already in the dependency graph via
    `leas-host-features`, so the cost was low; the benefit was zero.)
14. **Dropping the deferred siblings whenever the endpoint's verdict is known.**
    Rejected: an endpoint whose first protocol has a broken config would never
    have its other protocols tried — a working vless row beside a broken
    trojan row on the same host is never measured. The group is dropped only
    when the endpoint **succeeded**; otherwise the siblings are deferred and
    **probed**.
15. **Cancelling the siblings when the endpoint's winner lands.** Rejected: no
    cancel-on-winner path remains — a sibling is dispatched either after the
    endpoint's verdict (the deferral) or via the bypass, and in both cases its
    result is recorded in full. Only the batch **STOP** path cancels.

## Consequences

- **A schema change (18 → 19) with a real migration** — the first one this
  crate has ever run. See ADR 0016.
- The `Latency` enum becomes a struct embed: `latency_real_delay`,
  `latency_fast_delay`, `latency_ip`, `latency_auth`, and the `latency`
  discriminator is **dropped**. The two delays are no longer mutually
  exclusive.
- **The ordering law's band law is unchanged in number and meaning**: "is this
  a real or a fast measurement?" becomes "is `latency_real_delay` non-null?".
  The Auth flag does **not** enter the band law — it is a status, and no band
  has room for a third axis.
- The `error_kind` CHECK and the `PurgeReason` CHECK are untouched — no new
  marker kind, no new verdict.
- The Profiles grid gains two columns (Fast, Auth) and the 118-cell geometry
  is re-derived.
- The menu's `Fast + Real Ping` disappears; `Real Test` is the merged pass.
- `fast_ping_concurrency` leaves the config file, the settings UI and the
  settings form.
- A feed-wide run's throughput on **hanging** servers is lower (10 s worst
  case per row vs 5 s). On **healthy** servers it is better: one handshake
  per mux row instead of two, and one pass instead of two.
- The exit-IP fill is structurally capped by the provider (~45 req/min ⇒
  ~2,700 rows/hour on ip-api's free tier), so a feed-wide IP fill is a
  deliberate, resumable act, not a side effect of a test run.
- **A bypassed sibling can now carry its own failure marker** — today no
  sibling of a succeeded endpoint ever carries one, because the endpoint's
  real verdict is the endpoint's. A bypassed sibling's config may genuinely be
  broken (or genuinely route elsewhere), so its own verdict is recorded.
- **A sibling in flight when the endpoint's winner lands now completes and
  records its full result** — it is no longer cancelled. The endpoint's success
  does not suppress a sibling's measurement, because the sibling's config is a
  different config. Only the batch **STOP** path cancels a task.
- **The measured set of siblings is load-dependent**: the bypass fires only
  when a slot is free, and the queue is full for the whole main pass (the walk
  produces ~23× the links the probes consume), so in practice it fires only at
  the tail. A faster machine measures more siblings.
- **The endpoint's tier can move mid-run** (a bypassed sibling may become the
  representative). The walk's order is a frozen snapshot; the tier is live.
  The two are already different objects — the walk orders endpoints by the
  endpoint key, the tier is the representative link's `rank_bin` — and any
  real probe can already change the representative. The bypass raises the
  rate, not the class.

## Documentation obligation (per slice)

The reference set describes shipped architecture, so each doc is updated by the
slice that changes the code behind it — never by the design:

| slice | docs |
|---|---|
| **S1 (schema)** | `reference/database.md`, `reference/glossary.md`, `reference/database-manual-sql.md` |
| **S2 (probe)** | `reference/native-core.md` (the attempt deadline, the two-tunnel exit-IP fetch) |
| **S3 (worker + TUI)** | `reference/ordering-law.md` (§2's "is it real or fast?" predicate), `guides/tui-manual.md` (the grid columns, the Speed Test menu, the progress text) |

A pending marker in one doc and silence in the others would leave the set
describing two different schemas at once — which is worse than describing
either one alone, because a reader cannot tell which is current.

## Verification (planned, per the spec's three slices)

- S1: a version-18 database opens, migrates, and reads back with the same
  numbers; a version-19 database opens unchanged; a foreign version still
  reports `IncompatibleSchema`.
- S2: a VLESS-mux row's exit IP arrives over the same connection (one
  handshake, countable by the probe's own connection count); a TCP-ok /
  TLS-hang row reports a transport span **and** a real failure, not a total
  timeout.
- S3: the Fast column shows a number beside a real failure; the endpoint's
  other links show the Fast delay and no real delay; a feed-wide run's
  throughput is better than today's two-phase pipeline on the same corpus.

## Boundary

This ADR records an **approved design**, not a shipped implementation. The
implementation lands in three slices under
`specs/2026-10-21-merged-test-pipeline-design.md`; the ADR's status moves to
SHIPPED when S3 lands. This record grants no completion authority.
