# Log and failure audit — 2026-11-23 00:00 → 2026-11-24 12:52 (+05)

Read of the persisted log store and a live DB snapshot from the user's
installation, for the stated task: export yesterday→now, analyse logs **and**
the error messages stored in the database, and inventory protocol
implementation gaps against the cloned reference implementations.

Companion documents:
[`2026-11-20-real-test-response-analysis.md`](2026-11-20-real-test-response-analysis.md)
(the same taxonomy three days earlier, and the 680-row 15 s replay),
[`2026-11-20-log-review-real-test.md`](2026-11-20-log-review-real-test.md)
(relay reaps, DNS starvation), [`2026-11-20-failure-pair-review.md`](2026-11-20-failure-pair-review.md)
(the schema-22 pair), [`2026-11-23-live-memory-audit.md`](2026-11-23-live-memory-audit.md)
(the batch memory bound).

## 0. Evidence basis and limits

| Evidence | Detail |
| --- | --- |
| Log export | exported through `HeedLogStorage::read_all_older_than` — the same read as `cargo run -p leas-core --example dump_logs` and the Logs tab's copy — with the store's `u64` ns keys kept for filtering: 30 390 stored entries at the analysis read (30 580 at the 12:59 dump), **14 336 inside the window** (12 205 `info`, 2 059 `warn`, 72 `error`) |
| DB snapshot | `data.db` + `-wal` + `-shm` copied while the release app was live (PID 417 608), read read-only; cross-checked with the pinned `tursodb` CLI |
| Window | local TZ +05; `2026-11-23 00:00` = `1795374000`, DB snapshot `2026-11-24 12:52` |
| Window log file | `/home/user/leas-logs-2026-11-23_24.txt` — `dump_logs` text (UTC timestamps), 14 794 lines at the 12:59 read |
| DB size | 81 351 endpoints, 104 750 protocols, 165 206 `profile_stats` rows, 94 692 `endpoint_groups` links, 10 groups |
| Code read | working tree at `94123265` (`docs(ss): correct shadowsocks E2E counts`) |
| References | consulted: `thirdparty/Xray-core` @ v26.11.9, `thirdparty/sing-box` @ v1.15.0-alpha.13, `thirdparty/mihomo` @ v1.19.33 (all three match `crates/leas-oracles/src/pins.rs`), `thirdparty/shoes` @ ee44a39 (REALITY auth). `ferrox`/`unbihex` were not needed for these findings and are not cited. |

Limits that qualify every number:

- **The analysis read stopped at 12:38 local; the shipped file was written at
  12:59.** Every count below is the 14 336-entry read; the file has 458 more
  lines (12:38–12:59 local), which do not change any class or ratio.

- **The persisted log is already lossy.** `TuiLogLayer` drops DEBUG/TRACE and
  the structured fields (including `db.params`); the bounded channel's overflow
  drops are reported on stderr, not in the store. Every count here is a lower
  bound, and no richer sidecar exists (`log_to_file` is off in this config).
- **`last_seen_at` / `updated_at` are not probe times.** The feed import stamps
  both on every re-seen link (`LinkGroups::SEEN`, monotone `MAX`). `146 673`
  rows carry a window `last_seen_at`, but the log's batch counters are the only
  honest probe volume: **190 559 failed + 149 ok probes** across the ten
  batches in the window.
- **Four startup records in the window** (11-23 14:28, 17:21, 18:48, 11-24
  12:01); the logs before 14:28 belong to a session that began earlier. The DB
  therefore mixes rows written by more than one build. Current
  source emits the typed texts (`transport error: ws: HTTP error: …`,
  `protocol vless error: …`) and 157 702 failure rows carry a pair, so those
  two 2026-11-20 defects are closed in code; the DB still contains their older
  vocabulary, and a row's writer cannot be dated without a `probed_at`.
- **Stale text survives re-import.** 5 463 window-updated error rows have
  `error_stage IS NULL`; their text is older than the pair writer and the
  import restamped them. With no `probed_at` column they cannot be separated
  from a current writer gap. Against that: 157 702 rows carry a non-NULL pair,
  versus 0 across 124 341 failure rows on 2026-11-20.
- Two statements were recorded at **806 s / 812 s** (see §6). That is not
  consistent with the 5 s busy ceiling and cannot be attributed from available
  evidence: `/var/log/syslog` is not readable for this user, the session
  crashed/rebooted at 18:45, and no in-app heartbeat exists. It stays an
  unresolved anomaly, not a root cause.
- The probe path was this workstation's network. A censoring path can make a
  live server look dead; the 2026-11-20 replay at 15 s (0/680 rescued) is the
  control that the 5 s budget is not what kills these links.

## 1. What ran

Ten Real Test batches, one 146 k-link feed-wide run, `real_ping_concurrency=100`,
`real_ping_timeout_secs=5`, `real-retries=2`, page size 200, mux enabled:

| queued | links | ok | failed | plan | wall | dominant failure classes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 11-23 12:02 | 3 000 | 23 | 2 928 | 74 ms | 228 s | timeout 1 988, tls 407, reality 208 |
| 12:24 | 265 | 1 | 261 | 23 ms | 31 s | timeout 234 |
| 12:44 | 67 | 8 | 31 | 12 ms | 28 s | timeout 27 |
| 14:28 | **146 531** | **40** | 146 257 | 5.5 s | 2 h 29 m | timeout 84 536, dial 35 431, tls 12 150, transport 11 349, protocol 1 998 |
| 17:04 | 427 | 21 | 329 | **34.5 s** | 138 s | timeout 275 |
| 17:28 | 426 | 19 | 314 | 26 ms | 56 s | timeout 245 |
| 17:34 | 19 356 | 0 | 19 305 | **739 s** | 776 s | transport 7 885, timeout 6 669, reality 1 468, tls 1 277, dial 1 123 |
| 18:03 | 2 | 0 | 2 | 12 ms | 2 s | protocol 2 |
| 11-24 12:02 | 1 222 | 36 | 1 122 | **87 s** | 137 s | timeout 922, protocol 129 |
| 11-24 12:04 | 20 033 | 1 | 20 010 | **772 s** | 792 s | transport 7 809, timeout 7 321, tls 1 317, dial 1 336, reality 1 288 |

Aggregate success rate: **149 / 190 708 = 0.08 %**. The 146 k run retired
88 499 links as transport-unreachable; 60 % of a feed can be retired in one
run if the path is hostile, so that counter is a verdict about this network as
much as about the servers.

## 2. Log volume

14 336 lines. The loud targets are not errors, they are per-connection traffic
and the import pipeline:

| target | lines | what it is |
| --- | ---: | --- |
| `leas_native::inbound` | 11 006 | accepted/closed/relay reaps |
| `tui::ops::subscriptions` | 2 072 | fetch, validate, upsert |
| `toasty::query` | 869 | 455 slow + 414 failed statements |
| `tui::ops::enrich` | 257 | DNS |
| `tui::ops::job_scheduler` / `ping` / `events` | 26 / 24 / 21 | batch lifecycle |
| `leas_db` | 9 | write-behind flush failures |
| `tui::state` | 8 | PSL roll, whitelist |
| `leas_native::transport::kcp` | 2 | UDP send/recv died |

Errors (72) are all subscription failures, and each network failure
is logged **twice** (the source-level `HTTP fetch failed: …` plus the pipeline
`Subscription update failed: …`): ~36 failure events across 13 distinct
source+cause identities, 72 lines. That is log
noise with a real cost — the same event is read as two.

## 3. Database outcomes

Of 146 673 rows seen in the window, **146 531 carry `error=1`** and 142 are
clean. Only **216 links have a `latency_real_delay`** and 54 of those are clean;
64 963 have a fast latency. In other words: the DB records the feed, not a
working network.

Lifetime `purge_reason` (all 165 206 rows):

| reason | rows |
| --- | ---: |
| `transport_rejected` | 11 637 |
| `reality_fallback` | 4 167 |
| `certificate_mismatch` | 2 643 |
| `origin_unreachable` | 1 945 |
| `config_invalid` | 1 195 |
| `certificate_expired` | 165 |
| `not_tls` | 148 |
| `credential_rejected` | 1 |

`endpoint_rank.band`: **20** Active, **70 457** Purgatory, **10 874** expired
(`band=2`). The 20 live endpoints are the entire "working feed" at snapshot time.

Window error count by shape (top):

| shape | error rows |
| --- | ---: |
| `vless/ws/tls` | 38 843 |
| `vless/tcp/reality` | 35 651 |
| `vless/ws/none` | 21 106 |
| `vless/tcp/none` | 12 189 |
| `vless/grpc/reality` | 6 485 |
| `vless/grpc/tls` | 4 686 |
| `vless/x_http/tls` | 4 637 |
| `vless/tcp/tls` | 3 782 |
| `vless/grpc/none` | 3 360 |
| `vless/x_http/reality` | 2 904 |
| `vless/x_http/none` | 2 639 |
| `vless/http_upgrade/none` | 2 341 |
| `vmess/ws/none` | 1 877 |
| `shadowsocks/tcp/none` | 1 401 |
| `vmess/ws/tls` | 1 253 |
| `trojan/*` (5 shapes) | 2 511 |
| `hysteria2/quic/tls` | 118 |
| `shadowsocks2022/tcp/none` | 100 |
| `tuic` + `wire_guard` + `hysteria1` | 12 |

## 4. Failure taxonomy

`error_stage` / `error_cause`, window:

| pair | rows | reading |
| --- | ---: | --- |
| `dial/timeout` | 47 448 | endpoint socket never accepted in 5 s |
| `dial/io` | 33 940 | refused, reset, NXDOMAIN-class |
| `target/timeout` | 26 733 | tunnel up, destination handshake stalled |
| `transport/status` | 16 122 | HTTP status from ws/xhttp/httpupgrade |
| `transport/alert` | 12 663 | TLS alert from the proxy endpoint |
| `(NULL, NULL)` | 5 463 | pre-fix text, re-stamped (§0) |
| `protocol/framing` | 1 227 | VLESS header junk, gRPC/mux framing |
| `transport/framing` | 1 173 | malformed WS/HTTP response |
| `transport/config` | 1 038 | locally refused shapes (non-ASCII URI, bad flow) |
| `protocol/config` | 719 | protocol-level config defects (REALITY missing pbk, etc.) |

Top stored texts (window):

| text | rows |
| --- | ---: |
| `timeout on probe transport (limit 5s)` | 47 594 |
| `timeout on probe attempt (limit 5s)` | 27 157 |
| `TLS error: handshake error: alert: 2 40` | 8 653 |
| `transport error: ws: HTTP error: 409 Conflict` | 4 318 |
| `transport error: ws: HTTP error: 500 …` | 3 924 |
| `transport error: ws: HTTP error: 403 Forbidden` | 3 269 |
| `TLS error: CertNotValidForName(…)` | 2 081 |
| `REALITY error: … received real certificate` | 1 550 |
| `transport error: ws: HTTP error: 530 …` | 1 398 |
| `TLS error: Connection reset by peer` | 967 |
| `invalid … ws request: … invalid uri character` | 890 (881 ws, 7 httpupgrade, 2 xhttp) |
| `transport error: ws: HTTP error: 404 …` | 940 |
| `transport error: httpupgrade: expected 101, got 409` | 778 |
| `transport error: ws: HTTP error: 503 …` | 721 |
| `protocol vless error: vless response version 0x48` | 664 |
| `tunnel closed: … vless response header truncated (EOF)` | 502 |
| `transport error: ws: … invalid HTTP version` | 597 |
| `transport error: xhttp download GET: expected 200, got 421` | **501** |

The 0x48 byte is `H` of an HTTP status line: the peer speaks HTTP, the row
says VLESS. The whole `protocol vless error:` family is now typed
`protocol/framing` (700 of 701 rows; the 664 `0x48` rows are inside it), so
the 2026-11-20 mislabel is gone.

## 5. Confirmed client defects

### D1 — xhttp over h2 sends no `:authority` (501 × 421, [INFERENCE] high confidence)

`crates/leas-native/src/transport/xhttp.rs:296-319`: `build_request` sets
`.uri(url_path)` (origin-form) and a `Host` header. That is correct for h1; for
h2 the `h2` crate builds the pseudo-headers from the **URI only**
(`h2-0.4.12/src/frame/headers.rs:559-590` `Pseudo::request`), so the request
carries `Host` but **no `:authority`**. Xray sets `requestURL.Host` and lets
Go's h2 transport derive `:authority` from it
(`thirdparty/Xray-core/transport/internet/splithttp/dialer.go`, the
`requestURL.Host = transportConfiguration.Host` block).

Cross-oracle: mihomo does the same as Xray — it builds
`url.URL{Scheme: "https", Host: cfg.Host}`, passes `u.String()` to
`http.NewRequest`, and sets `req.Host` too
(`thirdparty/mihomo/transport/xhttp/client.go:110-127`); sing-box ships no
xhttp in the pinned clone. So both references that implement xhttp put the
config host in the URL **authority**, which is what Go's h2 transport reads.

Empirical support: **all 501** `421 Misdirected Request` rows are
`vless/x_http/tls`; the h1 xhttp rows (`x_http/none`, `http_version = "1.1"`)
have zero 421s. 421 is the status CDNs use when the connection's routing name
and the request's authority disagree. Confidence is high but not a controlled
A/B: the fix is to use an absolute URI
(`https://{host}{path}`) for the h2 arm — keeping origin-form for h1, and h3
already rewrites at `xhttp.rs:536-560` — and to align or drop the duplicated
`Host` header, then assert `:authority == cfg.host` in the fake-h2 harness.

### D2 — WS/xhttp URI construction rejects representable paths (890 rows)

`transport/ws.rs:26-35` builds `ws://{cfg.host}{cfg.path}` and requires the
whole string to be a valid `http::Uri`. Xray instead builds its URI from the
**endpoint** (`protocol://dest:port` + normalized path) and puts the config
`host` in the `Host` header (`websocket/dialer.go`); sing-box does the same
(`v2raywebsocket/client.go:43-61`: `requestURL.Host = serverAddr`, overridden
only by an explicit `Host`). Consequences:

- **798** rows fail on a non-ASCII **host** (`RFDJCK.سیسی.wOrLd`,
  `EveRLaSTinG-…`). Go rejects non-ASCII in `Host` too
  (`net/http.ValidHostHeader`), so Xray cannot dial these either — this is a
  feed defect, not a client gap, and belongs in the ingest gate (D3).
- **90** rows fail on a non-ASCII or space **path** (`/?ed=2560&Telegram🇨🇳+…`,
  `/?ed=Telegram@mtmvpn---…=?ed=2560`). Go's `url.Parse` percent-encodes the
  path and Xray dials it. Here the client loses a dialable row.

Fix: percent-encode path bytes before `.uri(…)` (Go `EscapedPath` semantics —
non-ASCII as UTF-8 `%XX`, space as `%20`), and keep the `Host` header as the
raw config value only when it is ASCII.

### D3 — the ingest gate does not cover URI syntax

`proto_spec::is_undialable_shape` covers VLESS flow-without-TLS and
non-native SS methods only. In the window, **2 010 links** carry a
host/path no HTTP request line can represent:

| defect | ws | httpupgrade | xhttp |
| --- | ---: | ---: | ---: |
| non-ASCII host | 998 | 9 | 1 |
| non-ASCII path | 805 | 8 | 138 |
| space in path | 20 | 7 | 21 |
| control byte | 1 | – | – |
| markup punctuation in host | 2 | – | – |

Two rows carry markup in the host — `</code>speedtunnel<code><br/><br/>` and
`` `rb24`.`ir` ``. The host validator accepts punctuation (`<`, `>`, `/`,
backtick), so a feed that pasted escaped HTML or Markdown becomes a stored
"host". That is the same validator gap, not a Telegram extractor bug: the
markup is in the message text.

**IDNA is a feasible but low-yield option here.** The project already
normalizes endpoint names (`utils/host_port.rs:52-77`: `idna::domain_to_ascii`
then `DnsName::try_from_str`). Running the same pair over the 311 unique
non-ASCII `transport.host` values: **288 convert and pass `DnsName`**, 19 fail
IDNA, 4 more fail the DNS-name check (none rescued by trimming the trailing
dot). But the sampled endpoints are unrelated decoys (`visa.com`,
`speedtest.net`), so conversion changes only the camouflage Host; the cheap
correct gate is still rejection, and any normalization must be limited to
non-ASCII hosts (the helper's defaults lowercase ASCII and accept `<`/backtick,
so an ASCII charset gate stays separate).

These are retested on every cycle with a deterministic config error (890 of
them land in `transport/config`; the rest time out after the failed build), and
each retest pays a probe slot. Reject non-ASCII/control/markup host bytes at
ingestion (`config_invalid`), and do not reject a non-ASCII path once D2
encodes it. `/`-leading-normalization and a `Host:port` sanity check belong in
the same validator.

### D4 — capability verdicts are sticky across engine upgrades

`profile_stats.error_text` persists the plan-time verdict
(`not testable by the native engine: …`). In the window:

| verdict | rows | current code |
| --- | ---: | --- |
| `shadowsocks 2022 multi-user PSK list is not implemented` | 27 | **supported**: `capability.rs:454-470` serves AES-256-GCM lists through EIH; a test pins that a valid list is not a malformed key |
| `vless account encryption is not implemented` | 5 | stale: the configs carry no `encryption` field; the string exists only as a test fixture (`ops/ping.rs:5465`) |
| `legacy vmess payload security is not implemented` | 13 | current (enc `none`/CFB) |
| `vless flow is not implemented` | 8 | current (`xtls-rprx-origin`, `dir…-udp443`, double-suffix `vision-udp443-udp443`) |
| `transport is not implemented` | 3 | current (VLESS `quic`) |
| `no native implementation for this protocol kind` | 13 | current (TUIC 5, WireGuard 6, Hysteria1 1, HTTP 1) |

A support upgrade does not invalidate old verdicts, so the 27 SS-2022 rows and
the 5 VLESS rows are never re-probed and keep reporting a false gap. Add an
`app_meta.capability_version` marker (bump when `NATIVE_KINDS` /
`support_reason` change) and clear only the `not testable` verdicts on mismatch
— the same marker-gated one-time step as `invalid_shapes_purged`.

## 6. Database contention and the planning stall

The window's DB evidence, from `toasty::query`:

| signal | value |
| --- | ---: |
| statements ≥ 1 s | 455 (p50 2.24 s, p95 8.66 s, max **960 s**) |
| statements failing at ~5 s | **414** (p50 5 002 ms, p95 5 235 ms) — 269 `UPDATE`, 145 `INSERT`; these are per-attempt `toasty::query` lines, not final losses (final losses are the 21 below) |
| `database is locked` lines | 444 (414 statements + 21 `tui::ops::events` + 9 `leas_db`) |
| retry-exhausted operations | 21 (`tui::ops::events`): 11 × `clear name markers`, 6 × `refresh ranks`, 4 × `update_endpoint_resolution`; separately **9** `write-behind flush failed` lines (`leas_db`) between 16:27 and 18:18 |
| plan latency outliers | 34.5 s (427 links), 87 s (1 222), **739 s** (19 356), **772 s** (20 033) against 12–74 ms for the same page size on quiet batches |

The failure p50s are exactly the 5 s `busy_timeout`, so the normal mode is
"writer waited the ceiling, gave up, `retry_on_busy` re-entered". The
write-behind flush re-stages the failed window and every later one
(`write_behind.rs:362-378`), so the 9 flush failures are delays, not loss; the
21 exhausted operations are real dropped work (DNS markers/rank refreshes, one
`update_endpoint_resolution` chunk).

Two statements — `UPDATE endpoint_rank SET band = 2 …` (812 s) and an
`INSERT INTO profile_stats` (806 s), 18:35–18:36 — are **not** explainable by
the 5 s ceiling. On the copied DB that reband statement executes in **2.96 s**
cold (81 k rows), and the 5 s busy ceiling cannot account for 13 minutes unless one
`exec` re-entered the busy wait dozens of times — which the current
instrumentation cannot see. Candidate explanations, none proven:

1. a long write transaction elsewhere (the import that ended at 18:36:32 had
   stored 42 886 links) plus WAL's single-writer rule;
2. a process-wide stall (the 18:22:54→18:35:40 gap is one of the few longer
   gaps, but the ~9–10 min refresh cadence also produces gaps of that scale;
   the machine rebooted at 18:45 and `/var/log/syslog` is unreadable from this
   account);
3. measurement inflation from a suspended process (wall clock vs monotonic is
   not differentiated in the current `QueryLog`).

**Do not flip MVCC.** The 2026-09-24 rollout is CLOSED with WAL 1.2–4.8× faster
at 32 writers and no in-place WAL→MVCC conversion
(`docs/aegis/plans/2026-09-24-turso-mvcc-production-rollout.md`). The
actionable fixes are at the write boundaries:

- **Instrument before changing**: log `pool_wait_ms` separately from
  `exec_ms`, and add a 5 s heartbeat line while a statement is in flight; that
  separates (1)/(2)/(3) in one run.
- **Batch the enrichment writes.** `UPDATE endpoints SET resolved_at = ?` is
  one statement per endpoint (logged individually at 12:06), and 65 k endpoints
  × several statements is the import's write volume. Fold the resolved-at and
  `endpoint_ip` writes into the existing chunked link transaction
  (`link-values` batch) — this is the still-open 2026-11-20 F4 recommendation.
- **Move the bulk reband off the hot path**: `UPDATE endpoint_rank SET band=2`
  measured 2.96 s cold; run it at session start / after batch end, and chunk
  with yields, not inside a 42 k-link import.
- **Bound a writer's total wait**: `retry_on_busy` at 5–8 attempts with a 5 s
  per-attempt ceiling can spend 25–40 s per operation before giving up; cap the
  total budget per operation and fail the *operation* (not the process) so the
  UI's plan query is not queued behind it.

The plan-time blowup is the user-visible symptom: a page query that is 12 ms
on a quiet DB took 772 s while enrichment/import writes were in flight, i.e.
the TUI's "Real Test" appeared frozen for 13 minutes before the first probe.

## 7. Subscription pipeline

Window: 113 validation events, **96 465 rejected links** and 1 399 insecure
warnings; **58** imports ended incomplete, storing **213 820** links before the
failure; 43 source-ended warnings. Rejection breakdown:
`other (parse) 87 339`, `host validation 9 126`, `missing fields 0`.

What can be done with "other: 87 339"? Nothing: the log deliberately withholds
the reason (`parse error (details withheld: the message can carry the URL)`).
The single highest-value observability change is a **reason histogram** beside
the count (error enum + the first N bytes of the offending scheme/field, no
URL), which is also the only way to find parser coverage gaps from the feed.

Source failures: 37 `error sending request`, 24 `SOCKS error: host unreachable`
(fetches routed through the live tunnel with no direct fallback), 5 timeouts,
5 `error decoding response body`. The decode failures are the expensive ones —
they interrupt a body mid-stream (103 067 links stored, 42 886, 16 241, 5 834)
and the log line for that case omits the source name/URL, so the operator
cannot tell which feed needs a longer/retry budget. Recommendations:

- Give the decode failure a source identity and the byte count read.
- Retry a failed tunneled fetch **directly once** before marking the source
  failed (fetches are control traffic; the tunnel is the thing being tested).
- De-duplicate the two error lines into one event with `source` + `attempt`.
- Keep the per-source backoff; today every source retries on its fixed
  interval regardless of repeated connection failures.

## 8. Relay idle cap reaps live long-poll sessions

`timeouts::RELAY_IDLE = 60 s`. In the window, **2 985 connections closed with
`relay read timed out`** — the largest single close class — and **2 930 of them
had carried traffic** (947.8 MB total, median 5.6 KiB down):

| destination | reaps |
| --- | ---: |
| `mtalk.google.com:5228` | 964 |
| `chat.deepseek.com:443` | 440 |
| `web.telegram.org:443` | 276 |
| `alive.github.com:443` | 196 |
| `music.youtube.com:443` | 116 |
| `discord.com:443` | 47 |

The 60 s cap was raised from 30 s because 30 s reaped Discord's 41.25 s
heartbeat. The data says 60 s still reaps Google's push channel and Telegram
web long-polls. AGENTS is explicit that raising it is not a memory trade (no
buffer changes). Either raise to 90–120 s, or exempt destinations whose
protocol is long-poll by shape (Telegram `zws*-*.web.telegram.org`,
`mtalk.google.com:5228`) — the second is more code than the first.

## 9. DNS

234 lookup timeouts, 15 `SERVFAIL`, 6 `receiver was canceled`, and one
`7 484 DNS host(s) waited past the queue budget` event. Resolver pool:
275 `ok`, 92 `error` (timed out / no connections available). Much improved
from 2026-11-20's 24 498 timeouts / 46 006 starved hosts, but the queue-budget
event still means a batch planned against unresolved hosts. The 2026-11-20
recommendation (defer instead of dialing a starved host) is still the right
one; today's number is evidence the queue is much smaller.

## 10. Protocol implementation audit against the references

### 10.1 What was checked and matches (do not "fix" these)

| Claim | Reference | Our code |
| --- | --- | --- |
| WS features | ALPN `http/1.1` forced for ws/httpupgrade (`tls/tls.go:115-140`, `websocket/dialer.go`); sing-box `v2raywebsocket/client.go` builds URI from the server address | `context.rs::alpn_vec` returns `http/1.1` for ws/httpupgrade |
| TLS default ALPN | Xray defaults `NextProtos = ["h2","http/1.1"]` when unset (`tls/config.go:426`) | engine keeps the profile ALPN when `alpn` is None (Chrome spec carries h2+http/1.1) |
| VLESS response version | `DecodeResponseHeader` rejects any non-zero version (`vless/encoding/encoding.go:159-165`) | `vless/stream.rs:127` matches; typed `protocol/framing` |
| vision-udp443 | Xray truncates the flow to `xtls-rprx-vision` on the wire (`vless/outbound/outbound.go:248-251`) | `vless/header.rs:41-54` encodes the 16-byte flow; test pinned |
| REALITY AAD | AEAD AAD is the hello with SessionId zeroed, nonce = random[20:], auth key = HKDF(`ECDH(client, pbk)`, random[0:20], "REALITY") (`reality/reality.go:160-200`) | `reality/mod.rs:8-23`, `reality/auth.rs`; hybrid key-share handled (`graft_hybrid_key_share`) |
| REALITY fallback verdict | a real cert = invalid connection (`reality.go:296-303`) | `TlsError::RealityFallback` → `reality_fallback` purge |
| SS-2022 multi-user | xray `ParseKey` list form | `ss/eih.rs`, `capability.rs:454-470`; only ChaCha refuses a list |

### 10.2 Unexplained classes that need a controlled A/B

1. **`alert: 2 40` (8 653).** Fatal `handshake_failure` from the endpoint.
   Rate is not uniform across fingerprints:

   | `security.fp` | rows | alert-40 | rate |
   | --- | ---: | ---: | ---: |
   | `random` | 2 523 | 332 | **13.2 %** |
   | `(none)` | 73 170 | 5 473 | 7.5 % |
   | `chrome` | 41 185 | 2 303 | 5.6 % |
   | `firefox` | 14 088 | 301 | 2.1 % |
   | `edge` | 3 174 | 2 | 0.1 % |

   Either the server cohorts differ by fingerprint field, or the randomized
   hello is malformed enough for some TLS frontends. A/B one endpoint with
   `fp=random` vs `fp=chrome` (same host/path) and count alerts; a controlled
   hello capture is the only honest test.
2. **`REALITY: received real certificate` (1 550).** Matches Xray's verdict,
   but these rows are then purged as `reality_fallback`; if the SNI is a
   shared CDN, the server may be a healthy non-REALITY fallback and the row is
   simply wrong. Validate against Xray on a sample before trusting the purge.
3. **Hysteria2: 0 successes in 234 lifetime rows** (117/118 in the window are
   5 s transport timeouts). Either UDP egress is blocked on this path, the
   server set is dead, or the QUIC/handshake client is wrong. A local
   sing-box hysteria2 server + the existing e2e harness distinguishes these;
   no such row has ever passed, so the oracle should be checked before the
   feed.
4. **`CertNotValidForName` (2 081).** Sampled rows are genuine mismatches
   (`potato.dbintro.space` presenting `*.yccdn.cloud.yandex.net`); this is a
   feed/SNI defect, not a verifier bug.
5. **WS/xhttp HTTP statuses (409: 4 318; 500: 3 924; 403: 3 269; 530: 1 398;
   404: 940; 503: 721; 421 on ws: 80).** The statuses are the server's answer,
   but no oracle client was dialed on the same rows, so a request-shape defect
   (header set, path normalization, authority) cannot be excluded. Run Xray and
   mihomo on a stratified sample and compare status distributions; until then
   these are open, not proved server-side.

### 10.3 Protocol coverage inventory

| family | state | window rows |
| --- | --- | ---: |
| VLESS | native; all shipped transports; flows vision + vision-udp443 | 139 160 |
| VMess | native AEAD; legacy `enc=none/CFB` refused by design | 3 312 |
| Trojan (+ Trojan-Go SS layer) | native | 2 512 |
| Shadowsocks / SS-2022 | native, incl. EIH multi-user (AES) | 1 506 |
| Hysteria2 | native, 0/234 lifetime successes (§10.2) | 118 |
| AnyTLS, SOCKS5 client | native | 0 / 51 |
| TUIC | **no native implementation** | 5 |
| WireGuard | **no native implementation** | 6 |
| Hysteria1 | **no native implementation** | 1 |
| HTTP proxy kind | **no native implementation** (server kind only) | 1 |
| VLESS over QUIC transport | **not implemented** | 3 |
| mKCP | native; 2 rows died with `udp recv/send failed` | 53 |
| xhttp / HTTPUpgrade / gRPC / HTTP | native | 10 241 / 2 520 / 14 582 / 194 |

Also inventory of "not testable" verdicts, corrected for stale text (§D4):
the real gaps are VMess legacy security, legacy XTLS flows, VLESS-over-QUIC,
TUIC/WireGuard/Hysteria1.

## 11. Gap inventory, ranked

| id | severity | finding | evidence | fix | verification |
| --- | --- | --- | --- | --- | --- |
| G1 | high | xhttp h2 has no `:authority` | 501 × 421, all h2 xhttp; h1 zero | absolute URI for h2 | fake-h2 server asserts `:authority == host`; re-run xhttp rows |
| G2 | high | plan query starves behind writers (772 s) | batch table; 455 slow statements | batch enrichment writes, move reband, cap total retry | plan ms on the same batch with import running |
| G3 | medium | WS rejects representable non-ASCII/space paths | 890 URI errors; 90 path-only | percent-encode path | unit test with a non-ASCII path → wire path is %XX |
| G4 | medium | ingest gate misses URI syntax | 2 010 links with invalid host/path | `is_undialable_shape` extension | stored rows get `config_invalid`; no probe attempts |
| G5 | medium | capability verdicts never invalidate | 27 SS-2022 + 5 VLESS stale | `capability_version` marker | reopen DB after bump → those rows re-planned |
| G6 | medium | 60 s relay idle reaps long-polls | 2 985 reaps, 2 930 with traffic, 947 MB | raise to 90–120 s or exempt hosts | replay mtalk/telegram idle sessions |
| G7 | medium | subscription decode failures lack source identity; no direct fallback | 5 decode failures with 168k stored; 24 SOCKS failures | log source+bytes; retry direct once | induce a tunnel drop mid-fetch |
| G8 | low | duplicate error lines per fetch failure | 72 lines / 13 identities | one event with source+attempt | log count |
| G9 | low | 800 s statements unexplained | 806 s / 812 s vs 5 s ceiling | pool-wait vs exec split + heartbeat | one batch run with the split |
| G10 | low | hysteria2 0/234 | §10.2 | local sing-box oracle lab | one hysteria2 row passes |
| G11 | low | `fp=random` alert-40 rate 2.4× chrome | §10.2 | hello A/B | same endpoint, both fps |
| G12 | low | `error_kind=fast` still covers every transport-stage real failure | 90 290 fast vs 74 754 real lifetime | document or split kind/stage | read one batch through the DB |

## 12. What not to do (already disproved)

- **Do not enable MVCC** — closed rollout, WAL faster at 32 writers, no
  in-place conversion (§6).
- **Do not raise the 5 s probe budget** — 0/680 failures were rescued at 15 s
  (2026-11-20 §4); throughput scales as `concurrency/timeout`.
- **Do not treat `409/403/500/530` WS statuses as proved client bugs** — no
  oracle A/B was run; a server/CDN answer to the feed's decoy Host is the
  plausible reading, and these stay an open A/B item. Only the authority/URI
  issues have code-level evidence.
- **Do not "fix" `CertNotValidForName`** — the sampled chains genuinely do not
  contain the configured name.

## 13. Reproduction

```sh
# logs (the TUI's own export read); dump_logs prints UTC, while the report
# window is +05, so the window starts at 2026-11-22 19:00 UTC
cargo run -p leas-core --example dump_logs -- ~/.config/leas/logs.lmdb /tmp/logs-all.txt
awk '/^2026-11-22 19:/,0' /tmp/logs-all.txt > ~/leas-logs-2026-11-23_24.txt

# DB snapshot (read-only analysis while the app runs)
cp ~/.config/leas/data.db* /tmp/leas-export/
~/.turso/tursodb /tmp/leas-export/data.db \
  "select error_stage,error_cause,count(*) from profile_stats where error=1 group by 1,2 order by 3 desc;"

# the bulk-write cost measured in §6 (on a copy)
cp /tmp/leas-export/data.db /tmp/bench.db
time ~/.turso/tursodb /tmp/bench.db \
  "update endpoint_rank set band=2 where band<2 and rank_newest_seen < 1794835317;"
```
