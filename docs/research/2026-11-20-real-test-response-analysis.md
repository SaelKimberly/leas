# Real-test response analysis: the 2026-11-20 run

Read of the persisted log store **and** the live DB after the 2026-11-20
`Real Test (All Profiles)` runs, focused on one question: of everything the
batch recorded as a failure, what did the *server* actually answer, and which
answers prove a defect on our side?

Companion documents:
[`2026-11-19-real-test-funnel.md`](2026-11-19-real-test-funnel.md) (the funnel
by DB snapshot), [`2026-11-20-failure-pair-review.md`](2026-11-20-failure-pair-review.md)
(the schema-22 pair before it was written),
[`2026-11-20-log-review-real-test.md`](2026-11-20-log-review-real-test.md)
(the 11-19/20 log timeline). This one is the **response taxonomy**: per-class
outcome, the wire evidence behind it, and a replay of 680 recorded failures.

## 0. Evidence basis and limits

| Evidence | Detail |
| --- | --- |
| Log export | `cargo run -p leas-core --example dump_logs -- ~/.config/leas/logs.lmdb /tmp/logs-all.txt` — 180 088 entries total, **36 711 on 2026-11-20** (17 `error`, 9 559 `info`, 27 135 `warn`) |
| DB snapshot | `data.db` + WAL copied at 13:16 UTC with the app live; `tursodb --readonly` cross-checks on the live file |
| Replay | `cargo run --release -p leas-native --example probe_replay` over a 680-row stratified sample of today's failures, 15 s budget, concurrency 50 |
| Wire probes | raw TCP/HTTP and TLS+WS requests against the same endpoints, reproducing the stored statuses |
| Code | read at `3dbd2690` (working tree) |

Limits that qualify every number below:

- **`last_seen_at` is not a probe time.** A feed import at 13:04:43 stored
  132 029 links and stamped `last_seen_at = now` on every one
  (`state.rs:642`, `link_from_parsed_with_id`). The purge/band clock therefore
  shows "seen today" for links whose *error* is days old. Probe authorship can
  only be reconstructed from `updated_at` + the log timeline.
- **Two binaries ran during the day.** The failure-pair writer fix
  (`9dcb4e7c`) and the TLS-I/O unwrap landed mid-day, so rows written by the
  earlier processes carry `error_stage IS NULL` (20 479) or the coarse `alert`
  cause (the pre-fix text wrap). A pair-less row written *today* can also come
  from the fast path (§3 F8), which is current code. The early-data
  misclassification in §3 F1 is current code and reproduces today (§3 F1's
  replay).
- The probe's dial succeeded or failed on **this workstation's** path. A
  censored path can make a live server look dead; the replay below is the
  control for that (it reproduces the same failures, so the classification is
  at least honest about what we saw).
- The batch's own counters (`deferred`, `retired-unreachable`) are counters,
  not identities: `deferred` means "started late under the DNS gate", not
  "skipped" — the batch probed them anyway (11 + 147 411 = the whole 147 622-link plan, §1).

## 1. Run reconstruction

Six app sessions today (all with `real-timeout=5s retries=2
concurrency=100 dedup-endpoints=true error-ttl=None`):

| UTC | Event |
| --- | --- |
| 05:27 | startup (native session) |
| 09:26 / 09:46 / 10:14 / 12:48 / 13:02 | restart |
| 04:17–04:19 | batch: 1 264 links, ok 15, failed 1 238 |
| 09:49–09:58 | batch: 12 531 links, ok **1**, failed 12 475, wall 554 s |
| 10:06–10:13 | batch: 54 691 planned, **interrupted at quit**, 6 244 failed / 6 252 settled |
| **10:16–12:45** | **batch: 147 622 links, ok 11, failed 147 411, wall 8 961 920 ms (2 h 29 m)** |
| 12:45:50 | batch: 4 links, 4 failed (`protocol`) |
| 13:03–13:16 | no new test — DNS retries, resolver test, one 132 029-link import |

The day's DB state is that 10:16 batch plus whatever the feeds re-stamped.
`profile_stats` holds 162 654 rows, **162 630 with an error marker and 24
clean**; 102 702 protocol rows, 80 514 endpoints.

Batch 10:16 histogram: `timeout=85 559, dial=34 172, tls=17 825, transport=7 959,
protocol=1 183, reality=361, config=331, io=21` — 147 411 failures, 11 successes.

Throughput: 16.5 probes/s at concurrency 100 ⇒ the batch is **timeout-bound**,
not CPU- or DB-bound: 100 in flight / 5 s deadline is exactly the observed rate.

## 2. What the servers answered

Buckets computed from `profile_stats.error_text` (the typed pair is used where
present), whole DB, snapshot 13:16 UTC.

| # | Response | Rows | Stage/cause pair | Owner |
| --- | --- | ---: | --- | --- |
| A | No answer at all: transport-stage deadline (5 s) | 53 631 | dial/timeout | server / path |
| B | Tunnel up, target did not answer in 5 s | 33 805 | target/timeout | server |
| C | Server host does not resolve | 18 484 | dial/io | feed data |
| D | Server refused the TCP connection | 13 564 | dial/io | server |
| E | HTTP status from the server's edge (all transports) | 19 337 | transport/status; the 5 115 NULL-pair rows are pre-fix writes (e.g. `httpupgrade … got 409`: 399 `status` / 394 NULL) | server |
| F | TLS alert (`2 40`, `2 80`, `2 112`) | 9 673 | transport/alert | server / block |
| G | Certificate does not cover the configured SNI | 2 471 | transport/alert | config/feed |
| H | REALITY answered with a **real** certificate | 2 439 | transport/config | server |
| I | Reply is not a VLESS response header (`0x48` = `H` of `HTTP/`) | 685 | transport/**alert** ← wrong | server (config) |
| J | Client refused the config | 726 | protocol\|transport/config | ours |
| K | Engine has no implementation | 265 | config | ours (capability) |
| L | Connection reset / early EOF / tunnel closed | 1 700+ | transport/alert | server / path |
| M | Other dial failures (unreachable, EHOSTUNREACH…) | 2 357 | dial/io | path |
| Z | Remainder (WebSocket protocol errors, gRPC framing, SSH banner, cleartext…) | ~3 500 | mixed | mixed |

HTTP statuses (E), by code, from the same snapshot:

| Status | Rows | Reading |
| --- | ---: | --- |
| 409 Conflict | 5 205 | Cloudflare edge answers `409` + body `error` for a `Host` the edge refuses (verified with a raw request: `Server: cloudflare`, `CF-RAY`) |
| 500 Internal Server Error | 4 541 | origin error page behind a CDN |
| 403 Forbidden | 3 955 | CDN/WAF denies the path |
| 530 | 1 612 | Cloudflare origin DNS failure |
| 503 | 1 095 | origin unavailable |
| 404 | 740 | path absent on that origin |
| 421 Misdirected Request | 584 | CDN edge wrong route |
| 400 | 351 | request rejected |
| 412 | 343 | WAF challenge |
| 200 / 301 / 302 / 308 | 449 | the "WS endpoint" is a normal web page (redirect / success on a plain GET) |
| 429 / 521 / 522 / 523 / 525 / 526 | 194 | rate limit / origin down |

The `200`/`301`+ group matters: our upgrade request reached an **ordinary HTTP
server**, so the stored config is not a WS endpoint at all. Nothing on our side
makes that dial.

Purge verdicts written from those answers (whole DB): `transport_rejected`
9 139, `reality_fallback` 3 767, `certificate_mismatch` 2 525,
`origin_unreachable` 1 339, `config_invalid` 902, `certificate_expired` 163,
`not_tls` 140; 144 679 rows carry no verdict. Whether a row is purged depends
on the **class**, which is why the misclassifications in §3 are not cosmetic:
the same 409 is purged for one half of the population and not the other.

## 3. Defects on our side, with the evidence

### F1 — The WS early-data path loses the error type: every HTTP rejection becomes a TLS alert

The 409 itself is the server's answer (§4 lists it as not ours); this finding is
only about **which class we store** for it.

**Symptom.** The same wire answer is classified two ways:

| Config | Text | Pair |
| --- | --- | --- |
| WS, plain | `transport error: ws: HTTP error: 409 Conflict` | `transport/status` |
| WS, `?ed=` + `max_early_data` | `TLS error: I/O error: transport error: ws: HTTP error: 409 Conflict` | `transport/alert` |

**Measured correlation (whole DB).**

Whole HTTP-status population (`HTTP error:`, `expected 101`, `download GET`):

| `max_early_data` in config | pair `status` | pair `alert` | no pair |
| --- | ---: | ---: | ---: |
| absent | 10 784 | **0** | 4 312 |
| present | **0** | 3 438 | 803 |

Every early-data row with a pair falls in `alert`; no non-early-data row does.
(The no-pair rows come from the paths in F8 or from the pre-fix binary.)

**Controlled experiment.** 36 early-data links that recorded `409`/`500` were
replayed twice — once as stored, once with `max_early_data` and `?ed=` stripped:

```
ORIGINAL (early data on):   27 x "TLS error: I/O error: transport error: ws: HTTP error: N Conflict"
                            6  x "TLS error: I/O error: transport error: ws: HTTP error: N Internal Server Error"
EARLY DATA OFF:             27 x "transport error: ws: HTTP error: N Conflict"
                            6  x "transport error: ws: HTTP error: N Internal Server Error"
```

Same status, same hosts, different class. The server rejection is genuine; the
**type is lost on the deferred-upgrade path**, so `map_tls_err`'s
`io::Error::downcast::<NativeError>()` (`security/mod.rs:262-278`) fails and
falls back to `NativeError::Tls(io.to_string())`.

**Scope (snapshot):** 18 843 links carry early data; **4 650 rows** are
`TLS error: I/O error: transport error: …` under an early-data config.

**Consequences.** The stored pair says "TLS alert" for an HTTP WAF rejection,
so the purge policy, the `[tls]` class counter and any report that groups by
cause are wrong for ~3 % of the whole DB (and 24.7 % of the early-data
population). The purge verdict shows the split exactly:

| 409 Conflict | purge `transport_rejected` | no purge verdict |
| --- | ---: | ---: |
| WS, plain | 3 539 | 0 |
| WS, `?ed=` | **0** | **1 666** |

The same server answer is purged for one half of the population and never
purged for the other, purely because of how the error crossed the early-data
wrapper.

**Owner and fix.** `crates/leas-native/src/transport/ws.rs` `EarlyDataDial`
boxes the upgrade failure into `io::Error` on both the read (`~:163`) and write
(`~:207`) paths; the deferred-upgrade future is also polled from the protocol
write path. Wherever the `NativeError` becomes a string, keep the concrete type
(`io::Error::new(kind, Box::new(err))`) so the downcast in `map_tls_err`
succeeds. Also audit `transport/mux.rs:1031` and `:1064`, which call
`io::Error::new(e.kind(), e.to_string())` unconditionally: any mux-carried
failure loses its type there by construction.
Guard: one unit test that drives a rejected early-data upgrade and asserts
`map_tls_err` returns `TransportRejected { status }`, plus an `#[rstest]` case
for `Io(boxed(TransportRejected))`.

### F2 — "Not a VLESS response header" is filed as a TLS alert

`protocol/vless/stream.rs:112-122` raises a plain
`io::Error::new(InvalidData, "vless response version 0x48: not a VLESS response
header")`. When the target TLS handshake is already reading that stream, the
record layer wraps it as `TlsError::Io`, the downcast fails, and the row is
stored `(transport, alert)`.

| Text | Rows | Pair |
| --- | ---: | --- |
| `vless response version 0x48` (TLS-wrapped) | 685 | `transport/alert` (606) or none (79) |
| `vless response header truncated (EOF)` | 1 070 | `protocol/framing` — correct |

The two are the *same server condition class* (a peer that is not a VLESS
server) and land in different buckets. The `0x48` byte is literally `H` of an
`HTTP/1.1` response: the port speaks HTTP, the config says VLESS. That is a
config/feed defect, and it is currently costed as a TLS alert.

Fix: raise a typed error in the peel (e.g. `NativeError::Protocol { kind:
Vless, detail }`) instead of a bare `io::Error`, or teach `map_tls_err` to
recognise the two peel errors and keep `protocol/framing`.

### F3 — The feed import resets the staleness clock for every re-seen link

`state.rs:642` builds each imported link with `last_seen_at: now`; the shared
writer's `LinkGroups::SEEN` uses `MAX(excluded, stored)`. One import at
13:04:43 therefore stamped `last_seen_at` and `updated_at` on **132 029 rows**,
87 291 of them existing rows, and it also carries 3 098 ingestion errors.

Observed effect: after that import the DB reads "everything was seen in the
last 15 minutes" while the probes that produced the errors ran much earlier.
Purge/band decisions (`purge_expired`, the Active/Purgatory split) and any
"freshness" reading of `last_seen_at` are then driven by the fetch schedule,
not by test evidence. This is likely the intended "a re-seen link is alive"
rule (feed presence = approval), but it has two costs that are not obviously
intended:

1. A dead link that stays in a feed can never age out.
2. Reporting cannot separate "probed today" from "re-imported today", which is
   exactly the confusion §0 has to disclaim.

Decide explicitly: either keep the rule and add a `probed_at`-style stamp for
reporting, or stop stamping `last_seen_at` on import and let only a probe
result/`PlanSource::Purgatory` move it.

### F4 — Write contention still loses probe results

| Metric | Today |
| --- | ---: |
| Statements ≥ 1 s (`toasty::query`) | 1 202 (p50 2.08 s, p90 6.15 s, p99 23.6 s, max **143.7 s**) |
| Statements failing at the 5 s busy ceiling | **375** — 226 `INSERT` (link patches, `LINK_STATEMENT_ROWS = 400` rows per statement, `database.rs:723`), 149 `UPDATE` |
| `database is locked` | 271 lines: 65 `clear name markers`, 16 `write-behind flush failed`, the rest failed statements |
| Write-behind flushes (big batch) | 1 859, `staged-left=0` |

The failure text is `transaction serialization failure: database is locked`, at
5 001–5 719 ms. Each failed `INSERT` statement carries up to **400** staged link
results, so the 226 failures can drop tens of thousands of row-writes
(`retry_on_busy` already retried each one before giving up); `staged-left=0`
does not cover it because the chunk was counted as flushed. The import writer, the probe writer and the DNS `UPDATE
endpoints` writer all contend on the same file at the busy ceiling.

Existing mitigation is `retry_on_busy` on the patch path
(`database.rs:1452,5`); the failing statements show it is not enough at this
contention. Options, in order of cost: batch the DNS `resolved_at` updates into
the same chunked statement as the link patches; raise the retry count on the
result writer only; serialise background DNS/`enrich` writes behind one writer
task.

### F5 — The DNS pool starves the batch it is meant to feed

| Signal | Today |
| --- | ---: |
| Lookups that hit the 8 s budget (`DNS lookup of X timed out`) | 24 498 |
| Distinct hosts | 9 436 |
| Hosts **starved on the 64-permit semaphore** (`DNS_QUEUE_WAIT`, 5 s) | **46 006** |
| `Server Failure` (`SERVFAIL`) | 174 |
| DoH `429 Too Many Requests` ("these aren't the droids…") | 7 |
| DoH `405 Method Not Allowed` | 7 |

`RESOLVE_SEM` is 64 (`enrich.rs:334`), the pool is the 10 fastest "ok"
resolvers (`ops/dns.rs:29`), and each upstream attempt gets **500 ms**
(`POOL_OPTS`, `leas-dns/src/lib.rs:41-46`) with a 2-attempt hickory policy.
46 006 hosts × 5 s of queue time is a large share of the batch's wall clock
that never touches a socket. Starved hosts are deliberately not marked as
resolver failures — correct — but they also are not scheduled for a retry in
the same batch, so they simply come back as dial timeouts.

Recommended, in order: make `RESOLVE_SEM` track `real_ping_concurrency` (the
original bound this replaced) instead of the fixed 64; raise the per-attempt
timeout for encrypted transports (a DNSCrypt cert fetch + query inside 500 ms
is optimistic on this path); and report a starved host to the batch as
"defer, do not dial", so the probe does not spend 5 s to discover what the
queue already knew.

### F6 — Feed byte budget truncates the largest feed seven times a day

7 truncated imports `64 MiB byte budget — raise import.max_feed_bytes` today,
between 92 831 and 92 849 links stored, each logged at `error` (21 log lines
because the failure is reported twice and retried). The user's `config.json` carries
`import.max_feed_links = 200000` but not `max_feed_bytes`, so the shipped
64 MiB default binds first and the largest feed is permanently partial. Either
raise the default (a 92 k-link feed is normal in this ecosystem) or make the
two knobs visible together in Settings; the message currently names a key the
UI does not expose.

Not a correctness defect — stored rows are kept — but it is a daily `error`
that trains the reader to ignore `error`, and every truncated feed leaves the
DB missing whatever came after byte 64 MiB.

### F7 — `error_kind='fast'` covers every stage-1 real-test failure

`error_kind` is `dial`-stage-conditional in practice:

| kind | stage | rows |
| --- | --- | ---: |
| fast | dial | 80 396 |
| real | target | 29 244 |
| real | transport | 28 721 |
| real | protocol | 1 654 |

A consumer that selects `error_kind='real'` to answer "what did the real test
find" misses 57 % of today's failures. That is a modelling choice (D12: the
transport span is the Fast metric), not a bug, but every report and the funnel
doc have to know it. If the real test owns the marker it writes, consider
storing the *test* in the kind and the *stage* in the pair, or documenting the
rule where readers look.

### F8 — The fast probe path stores a marker without its pair

`failure_pair()` returns a pair for **every** `ProbeClass`
(`ping_native.rs:83-135`), and the real-probe paths pass it: the batch at
`ping.rs:2963`, the single **Real Test** computed in the match arm at
`ping.rs:435` and forwarded by its result event (`ping.rs:466-481`). The
single-profile **Fast Test** does not: its
`CoreEvent::SpeedTestResult` is built with `failure: None`
(`ping.rs:233-246`), so `apply_test_result` writes `error_kind='fast'` with
`error_text` and both `stage`/`cause` NULL.

Observed: of 22 639 pair-less rows, **8 416 were created today** — and every
one of them was created **before 12:48 UTC**, i.e. by a binary that may predate
the pair fix. So today's snapshot cannot separate "old binary" from "fast path"
empirically: `real` (4 438) and `fast` (3 975) pair-less rows are both in that
pre-fix window. What is certain is the code fact — the fast emitter passes
`failure: None` today, so the gap survives the writer fix on the fast path.
The batch's result *event* also carries `failure: None` (`ping.rs:3144`); it is
masked because the batch stages its own write, but a row that is on the loaded
page when the event lands can be rewritten without the pair.

A future run on the post-fix binary separates the two: pair-less rows created
after the fix are the fast path (or the batch event overwrite); everything
before is history.

Fix: compute the pair in the fast path too — a TCP handshake's failure is
`(dial, timeout|io|refused)`, which is a class, not a config verdict — and
carry it in the event. `probe_class` already exists for the fast outcome.

## 4. What is NOT ours — do not chase these

- **A/B (87 436 rows).** At 15 s instead of 5 s, **0 of 680** replayed failures
  became a success; 133/150 transport timeouts still timed out at the
  engine's own 10 s dial cap, 85/150 protocol-stage hangs still hung. The 5 s
  budget is not what kills these links. Raising it would only cost wall time:
  throughput is `concurrency / timeout`, so 5 s→10 s doubles a 2.5 h batch.
- **C/D (32 048).** NXDOMAIN and refused sockets. The camo domains
  (`speedtest.net`, `ucdavis.edu`, `cloudflare.com` as *endpoint* hosts) are
  feed-generated garbage, not resolution failures; the hosts that timed out in
  `enrich` also show `timeout on probe transport`, so the resolver is not
  inventing the failure.
- **E (19 337).** Replay reproduces the statuses deterministically — 78/80
  `403`, 66/80 `409`, 51/60 `500`, 57/60 `alert 2 40`, 29/40 `0x48` and 30/60
  `header truncated` came back with the same signature; the remainder failed
  *earlier* in the replay (dial/DNS), never with a different answer — and a
  raw `GET` with the same `Host`/path gets the same code with a Cloudflare
  `CF-RAY`. These are the edges refusing a host/path they do not serve.
- **F/G/H (14 583).** TLS alerts and certificate-name mismatches are the
  operator's chain/SNI, and REALITY answering with a real certificate is the
  fallback the protocol is designed to detect (2 439 rows carry that text now;
  3 767 rows carry the `reality_fallback` verdict across the DB).
- **I (685).** "Not a VLESS server" is a config defect; only its *class* is
  ours (F2).

The one number that should worry a reader is not a class but the ratio: 24
clean rows out of 162 654. The feed ecosystem is mostly dead servers, and this
run is a dump of that, not a measurement of our engine. The engine-level
control that says it works is the same replay set: non-early-data WS, REALITY,
xhttp and shadowsocks rows in this DB do complete (24 clean rows across
`ss`, `vless/reality`, `vless/xhttp`, `vless/ws`, `vless/http`).

## 5. Native-session findings (same day, different owner)

| Signal | Value |
| --- | ---: |
| Connections accepted through the tunnel | 4 429 |
| Closed by the relay idle cap (`relay read timed out`) | **3 792** |
| …at 30.0–31.6 s (pre-13:02 binary, old 30 s cap) | 3 140 |
| …after the 60 s binary (`RELAY_IDLE`, `error.rs:253`), 60.2–183.6 s | 51 |
| SOCKS5 inbounds whose outbound dial failed | 533 |
| Target-side `timeout on tls handshake (limit 10s)` | the dominant detail line |

The 30 s cluster is the old binary; the current 60 s cap is visible only after
13:06 and there are too few samples to judge it. Long-poll clients
(`alive.github.com`, `mtalk.google.com:5228`, `gateway.discord.gg`) still get
reaped when they go quiet, which is the documented cost of a shared idle
stamp; no new evidence here to re-open 60 s.

## 6. Recommendations, ranked

| # | Priority | Change | Evidence |
| --- | --- | --- | --- |
| 1 | **P0** | Preserve `NativeError` through the WS early-data upgrade (and audit the mux `io::Error::new(kind, to_string)` bridges) so an HTTP rejection stays `transport/status` | F1: 4 650 rows, 100 % correlation, controlled on/off replay |
| 2 | **P0** | Type the VLESS "not a VLESS response header" failure (`protocol/framing`), not a bare `io::Error` | F2: 685 rows, splits one condition across two buckets |
| 3 | **P1** | Size `RESOLVE_SEM` from the configured probe concurrency, raise the encrypted-resolver attempt timeout above 500 ms, and defer starved hosts without a probe dial | F5: 46 006 starved, 24 498 lookup timeouts, 9 436 hosts |
| 4 | **P1** | Stop the import from moving `last_seen_at` (or add a separate probe stamp) | F3: 132 029 rows re-stamped in one import |
| 5 | **P1** | Close the write-contention gap: fold the DNS `endpoints.resolved_at` updates into the chunked writer and retry the result chunk more than once | F4: 375 failed statements, 226 lost `INSERT` chunks |
| 6 | **P1** | Give the Fast Test a `(dial, …)` pair and carry it on `CoreEvent::SpeedTestResult` | F8: emitter passes `failure: None` in current code; 8 416 pair-less rows created today are all pre-12:48, so re-check after the fix |
| 7 | **P2** | Raise/expose `import.max_feed_bytes` next to `max_feed_links` | F6: 7 truncations/day |
| 8 | **P2** | Document or change the `error_kind='fast'` rule for stage-1 real-test failures | F7: 80 396 fast/dial rows |
| 9 | **P3** | Re-measure `RELAY_IDLE` after a full day on the 60 s binary | §5: too few post-fix samples |

## 7. Reproduction

```text
# logs (all entries; filter by date prefix)
cargo run -p leas-core --example dump_logs -- ~/.config/leas/logs.lmdb /tmp/logs-all.txt

# one bucket's response taxonomy
~/.turso/tursodb -m list -q ~/.config/leas/data.db \
  "select coalesce(error_stage,'-'), coalesce(error_cause,'-'), count(*) \
   from profile_stats where error_text like '%409 Conflict%' group by 1,2"

# replay a sample at a longer budget (needs a JSONL: delay/host/port/config/err/grp)
cargo run --release -p leas-native --example probe_replay -- /tmp/replay.jsonl 50 15
```

`probe_replay` expects the pre-rename `endpoints.host`; today's schema stores
`domain` + `endpoint_ip.ip_key` (family byte + address bytes), so the sample
generator decodes `hex(ip_key)` (`4`+4 bytes → IPv4, `6`+16 → IPv6). Worth
fixing the example's SQL doc block while the schema is fresh in mind.
