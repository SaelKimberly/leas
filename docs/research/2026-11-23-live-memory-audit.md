# Live memory audit — a feed-wide Real Test, 2026-11-23

Measured on the user's installation (`/home/user/oss/xray-tui`, `6dacf7af`+dirty),
Linux 6.8, 20 cores. Profile under investigation:
`leas://8ed4e9d90ee901e6/b885a84bac448bce` — VLESS + TLS + xhttp (`mode=auto`,
SNI `plaindune.com`, fingerprint `chrome`), endpoint `plaindune.com:8443`.

Database: 81 170 endpoints, 104 409 protocols, 164 782 `profile_stats` rows;
10 subscription groups with 10–60 min refresh intervals; `logs.lmdb` 47 MiB.
Client config: `real_ping_concurrency=100`, `tcp_timeout_secs=5s`,
`real_ping_timeout_secs=5s`, mux enabled (`smux`).

Instrument: `leas-memtrace` (`mem-trace` feature → `System` allocator + the
workspace tracer), `scripts/trace_app.py` for the app, `mem-audit/pty_run.py`
for the live process. Allocation counts are allocator-independent; live/peak
bytes are the tracer's view and are **not** RSS (see §2 for both).

## 1. The 570–650 MB is a batch, not the client's idle state

Idle, with the real 81 k-endpoint database and no batch: **94 MiB RSS**
(48 MiB anonymous heap + 43.5 MiB executable pages; the 49 MiB
`GeoLite2-City.mmdb` and the 124 MiB `data.db` are not resident). With the real
`logs.lmdb` staged the settled figure is the same within sampling noise
(~95 MiB); LMDB maps 1 GiB but only 34.8 MiB of it is resident.

The live process the complaint came from was in a different state: **1 155 MiB
RSS, 1 293 MiB peak**, 85 threads (20 runtime workers + the 64 blocking cap),
198 sockets, and 100 sockets in `SYN-SENT` to a rotating set of `:443`
servers — a **Real Test (All Profiles) still running** over the feed. The
batch had been running for 1 h 39 m; RSS was flat over a minute of sampling,
so it is live batch state plus retained allocator pages, not a slow leak.

The two labs below reproduce that state without the network: a copy of the
real database with every endpoint pointed at `127.0.0.1:1`, then
`t` → `Real Test (All Profiles)` (menu index 6). The tracer's interval writer
(`LEAS_MEM_TRACE_INTERVAL_SECS=5`) gives a per-5 s curve.

## 2. What the trace found

Full-feed Real Test, pre-fix, at 210 s (tick 42 of `target/mem-trace/fastlab`):

| module | live B | live # | top stack |
|---|---:|---:|---|
| `leas_native::transport::quic` | **541 667 066** | 13 670 | `ops::ping_native;probe;transport;transport::quic` |
| `leas::ops::ping` | **212 928 911** | 308 975 | `ui;ops::ping` (the batch) |
| `<untraced>` | 206 404 972 | 375 510 | tokio/runtime/quinn internals |
| everything else | ~18 MB | | |

Two rows are 77 % of the live heap, and both grow linearly with the number of
processed links.

### 2.1 QUIC dials allocate a 188 KiB receive buffer each, and retain it

`quinn::Endpoint::client` allocates `max_udp_payload_size` (1 472) ×
`max_receive_segments` (Linux GRO = 4) × `BATCH_SIZE` (32) = **188 416 B** of
receive buffer per endpoint (`quinn-0.11.12/src/endpoint.rs:754`). Every
xhttp-h3 dial and every non-obfuscated hysteria2 dial built a **fresh
endpoint**; a failed handshake was retained until quinn's 300 s idle timeout
because the h3 driver task holds the endpoint and connection and only observes
`poll_close`.

Standalone measurement (`target/mem-trace/h3lab`: 560 h3 links, 70 s): peak
live in `client_endpoint` **202 MiB**, total allocated there 398 MiB over
2 132 endpoints, RSS peak **251 MiB**.

### 2.2 The batch spawned one chain per planned link

`dispatch_fast_link` acquired the concurrency permit only for a fast-only
batch; a real-phase batch spawned `run_task_chain` for every link immediately,
and each chain then waited on the real-probe semaphore. On a feed-wide plan
that is one live `ProfileStats` (plus future state) per link — the 213 MiB
`ops::ping` row — and the deferred-sibling backlog grows with it.

### 2.3 The per-batch protocol memo was unbounded

`BatchShared::protocols` keeps parsed configs per `ProtocolId` for the whole
run. Feed identity ignores host/port, not the uuid, so a feed-wide run is
nearly one unique config per link: at 215 s the memo held **175 MiB** of
parsed configs (12 KB average, `ProtocolConfig` plus its strings), and it kept
growing for the run's life.

### 2.4 Smaller items

- A completed `tokio` task's allocation lives until its `JoinHandle` is
  dropped; `BatchShared::tasks` held one per link until the final join.
- The QUIC TLS config (the whole webpki root store, ~40 KiB) was rebuilt on
  every dial.
- A successful fast probe loads the protocol config for the capability gate;
  the parsed config then stayed in the memo even if the link never reached a
  real probe.
- Obduscated hysteria2 receive allocated a `Vec` per datagram.
- A subscription import has no allocator boundary: the write-behind staging and
  parse buffers are freed, but mimalloc's pages stay committed while the app
  idles (the prior audit's burst case).

## 3. Changes and measurements

| # | Change | Evidence |
|---|---|---|
| Q1 | One shared `quinn::Endpoint` per address family (`transport::quic::client_endpoint`); per-dial bind kept under `test`/`e2e-support`, where each case has its own runtime | h3 lab: `client_endpoint` peak **202 MiB → 5.2 MiB**; `transport::quic` live 2.3 MiB; RSS peak **251 → 192 MiB** |
| Q2 | Close the connection on an h3 open/transport failure (xhttp) and on an auth failure (hysteria2) so the driver task resolves instead of waiting out the 300 s idle timeout | live `transport::quic` at the QUIC phase **541.7 MB → 3.1 MB (−99.4 %)** |
| Q3 | Cache the QUIC `rustls::ClientConfig` per (trust mode, ALPN) | 411 calls in the h3 lab left **15 live allocations** instead of one root store per dial |
| Q4 | Take the one probe permit **before** spawning a chain, for both batch kinds; the real half reuses the permit instead of acquiring a second | `ops::ping` live at 150 s **123.2 MB → 20.1 MB**; new test `real_phase_dispatch_stops_at_the_probe_bound` |
| Q5 | `SiblingGate`: verdicts and held siblings share one lock, so a group that settles before its page published the siblings still releases them (required by Q4's throttle) | all 105 `ops::ping` tests pass, incl. `sibling_dedup_retires_links_waiting_behind_a_success` |
| Q6 | Cap the parsed-protocol memo at 1 024 entries | `ops::ping` live at 150 s **37.8 MB → 20.1 MB** (and bounded instead of linear: 158 MB at 190 s → 20 MB) |
| Q7 | Prune finished chain handles every 256 settles | `<untraced>` at 150 s **125.4 MB → 59.5 MB**; `ops::ping` fell to 7.8 MB by 215 s instead of growing |
| Q8 | `job_boundary("import")` at the end of a streaming import | returns the import burst's freed pages while idle |
| Q9 | Thread-local receive scratch in the hysteria2 obfuscated socket | one fewer allocation per received datagram |

Full-feed Real Test, same workload (`target/mem-trace/fastlab5` vs `fastlab`):

| metric | pre-fix @150 s | post-fix @150 s | post-fix @215 s |
|---|---:|---:|---:|
| total live heap | 305.1 MB | **115.3 MB** | **109.1 MB** |
| `leas::ops::ping` | 123.2 MB | 29.0 MB | **7.8 MB** |
| `<untraced>` | 63.1 MB | 59.5 MB | 72.7 MB |
| `leas_native::transport::quic` | 3.7 MB (before its phase) | 3.1 MB | **3.1 MB** |
| allocations so far | 25.5 M | 25.6 M | 34.7 M |

At the same 210–215 s the pre-fix run held **979 MB live / 213 MB in
`ops::ping` / 541.7 MB in `transport::quic`**; the post-fix run holds 109 MB,
7.8 MB and 3.1 MB. Peak live across the whole run fell from 979 MB (still
rising when the driver killed it) to a **142 MB plateau**. RSS peak (traced
`System` build, which includes the 71.5 MB binary image and tracer overhead)
fell from 523 MiB to 458 MiB; the pre-fix run never reached its own exit, the
post-fix one still did not read the scripted `q` within the drain (SIGTERM),
so its exit artifact is the 215 s interval tick, not a shutdown snapshot.

The QUIC figure is compared at the phase that actually dials QUIC; earlier
ticks do not reach those links yet. The h3-only lab isolates Q1–Q3: peak live
in `client_endpoint` 202 MiB → 5.2 MiB and RSS peak 251 → 192 MiB.

## 4. What remains

- `<untraced>` is now the largest row (59–73 MB). It is runtime/quinn/rustls
  internals, not workspace state: tokio task bookkeeping, blocking-pool
  stacks, the shared UDP endpoint. Reducing it needs runtime-level pooling
  (mux/QUIC endpoint reuse across connections), not a workspace allocation fix.
- The executable image is 43.5 MiB resident (71.5 MB binary). Prior audits
  found no dominant symbol; unchanged.
- `logs.lmdb` maps 1 GiB and is 34.8 MiB resident; the map size is LMDB's, not
  an allocation.
- mimalloc retention after a burst is the same class the prior audit measured;
  Q8 covers the import burst. A forced idle collect was already measured as
  inside run-to-run noise.
- Obfuscated hysteria2 (`salamander`) still binds an endpoint per dial: it
  reports `max_receive_segments() = 1`, so its buffer is 47 KiB, not 188 KiB.
  Pooling by obfs password is possible but was not measured as a hot path here.

## 5. Reproduction

```sh
# idle baseline, real DB
TRIM=200000 SOAK=1 DELAY=30 TRACE_DIR=target/mem-trace/plain \
  python3 scripts/trace_app.py

# feed-wide Real Test, traced (127.0.0.1 lab DB)
cargo build --release -p leas --features mem-trace
TRIM=200000 DELAY=125 INTERVAL=5 INTERVAL_MAX=30 HOME_SRC=/tmp/leas-lab \
  KEYS='t:1,DOWN:1,DOWN:1,DOWN:1,DOWN:1,DOWN:1,ENTER:60' \
  TRACE_DIR=target/mem-trace/fastlab5 python3 scripts/trace_app.py

# h3-only QUIC lab (560 links)
#   same, with HOME_SRC=/tmp/leas-h3, DELAY=70, ROWS=symbol, INTERVAL=10
```

The lab database is a copy of the real one with
`update endpoints set domain='127.0.0.1', port=1; delete from endpoint_ip;`
so every dial fails locally and the batch is deterministic. The `KEYS`
sequence opens `t` and walks five rows down to `Real Test (All Profiles)` (the
separator at index 4 is skipped).

The tracer replaces the process allocator (`System`), so its RSS is not the
shipped mimalloc build's RSS; allocation counts and *relative* live bytes are
the comparable quantities.
## 6. Verification

```sh
cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings   # clean
cargo nextest run -p leas -p leas-native                                                     # 1 391 passed, 2 skipped
cargo build --release -p leas                                                                # shipped (mimalloc) build
TRIM=3000 DELAY=12 python3 scripts/trace_app.py                                              # 13.5 s PTY boot, status 0
```

The new `real_phase_dispatch_stops_at_the_probe_bound` test fails on the old
dispatch (it planned all 6 links while one probe held the only permit) and
passes on the throttled one. The sibling-gate change is exercised by the
existing `sibling_dedup_retires_links_waiting_behind_a_success` and the merged
pipeline tests, all green.
