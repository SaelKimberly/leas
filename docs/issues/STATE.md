# Issues Review — Loop State

```yaml
loop:
  iteration: 7
  status: running
  noop_streak: 0
coverage:
  - domain: native-inbound
    status: in-progress
    last_touched_iteration: 1
    issues: [001, 002, 003]
  - domain: mux-pool
    status: in-progress
    last_touched_iteration: 2
    issues: [004, 005, 006]
  - domain: native-protocol
    status: in-progress
    last_touched_iteration: 3
    issues: [007, 008, 009]
  - domain: native-transport
    status: in-progress
    last_touched_iteration: 4
    issues: [010, 011, 012]
  - domain: dns
    status: in-progress
    last_touched_iteration: 5
    issues: [013, 014]
  - domain: routing-engine
    status: in-progress
    last_touched_iteration: 6
    issues: [015, 016, 017]
  - domain: db-layer
    status: in-progress
    last_touched_iteration: 7
    issues: [018, 019, 020]
  - domain: app-ops
    status: unexplored
    issues: []
  - domain: ui-render
    status: unexplored
    issues: []
  - domain: tls-security
    status: unexplored
    issues: []
blocked: []
```

## Iteration Log

### Iteration 1 — native-inbound
- Pre-existing dirty worktree (user's in-flight DNS-resolvers work) left untouched;
  only `docs/issues/` files written.
- Prior-work check: `docs/issues/` did not exist, no duplicates possible.
- Read: `crates/leas-native/src/inbound/{mod,socks5,http,mixed,outbound}.rs`,
  `crates/leas-native/src/error.rs` (`timeouts`).
- Findings: 001 (no admission control at the accept layer, triplicated accept loop),
  002 (relay write has no deadline), 003 (eager 192 KiB per UDP association).
- Reviewer round 1: `needs-fix` (4 findings: overstated semaphore absence in 001;
  002's fix sketch dropped the shared-deadline re-arm; 003 misstated the pool API
  and the association's lifetime authorities). All four fixed; no second round
  needed — the fixes are wording/ref corrections, no claim changed shape.
- Next: pick `mux-pool` (oldest unexplored) in iteration 2.

### Iteration 2 — mux-pool
- Pre-existing dirty worktree (user's in-flight DNS-resolvers work) left
  untouched; only `docs/issues/` files written.
- Prior-work check: `rg mux_pool|MuxKey|MuxPolicy|build_gate` over `docs/issues/`
  hit only a passing mention in 002 — no duplicate.
- Read: `crates/leas-native/src/mux_pool.rs` (whole), `protocol/mod.rs` `MuxTunnel`,
  `transport/mux.rs` `open_session`, `context.rs` (`mux_explicit`),
  `leas-proto/proto_spec/vless.rs` (`VlessMux`), `ops/native_connect.rs`
  (`mux_policy`), `inbound/mod.rs` UDP call site.
- Findings: 004 (row mux cap never reaches the pool), 005 (key rebuilt twice per
  dial by `Debug` formatting, then cloned), 006 (pool-wide build gate, unregistered
  fallback carrier).
- Dead ends recorded so they are not re-run: `open_session`'s "mark the carrier
  dead on any error" is safe for MUX.Cool (its only errors are tunnel-closed and
  id-exhausted); the `_lease` in `run_proxy_leg` is dropped with the association,
  not earlier; lock order is uniformly `entries → last_used`, so `sweep`'s
  teardown under the map lock is not a deadlock.
- Reviewer round 1: `needs-fix` (3 findings, all refs/claims: 004's wire citation
  pointed at the match close instead of `wire: effective_wire` at `:223`; 005
  overstated how long the plaintext key copy lives — the hit-path clone is
  dropped by the occupied entry; 006's "only build path that skips `register`"
  ignored the deliberate `Spill` skip). All three fixed; verdict after fixes was
  not re-run (wording/ref corrections only, no claim changed shape).
- Next: pick `native-protocol` in iteration 3.

### Iteration 3 — native-protocol
- Pre-existing dirty worktree (user's in-flight DNS-resolvers work) left
  untouched; only `docs/issues/` files written.
- Prior-work check: `rg protocol/|first_flight|HeaderFirst|vision|trojan/|ss/|vmess/`
  over `docs/issues/` hit only STATE's own reading list — no duplicate.
- Scope note: `crates/leas-native/src/protocol/` is 22 886 lines; reviewed
  `mod.rs`, `first_flight.rs`, `vless/{header,packet}`, `trojan/mod.rs`,
  `hysteria2/udp.rs`, `ss/{mod,method}`, `vmess/header.rs` on the hot/datagram
  and credential paths. `vision.rs` (2074), `stream2022.rs` (1486),
  `ss/udp.rs` (2386), `vmess/stream.rs` (1350) not read line by line.
- Findings: 007 (datagram receive copies payloads that already live in a
  `Bytes` — hysteria2 + VLESS packetaddr), 008 (credential-bearing handshake
  buffers are plain `Vec`s, never wiped, while `auth_key` is `Zeroizing`),
  009 (hysteria2 defragger allocates `frag_count` slots from an unvalidated
  peer byte).
- Dead ends recorded: `vless/header.rs` is allocation-correct
  (`encode_request_into` + `HEADER_RESERVE`); `HeaderFirst`'s
  Pending-must-not-shrink rule is kept and tested; trojan/vmess datagram write
  paths reuse scratch; `Trojan auth_key`/`uuid_bytes` recomputation per dial is
  microsecond-scale and not filed.
- Reviewer round 1: `needs-fix` (5 findings: STATE's coverage left
  native-protocol's `issues` empty; 007 attributed the VLESS packetaddr copy to
  the `Vec` seam when it is local to the frame arm; 008's wipe site ran after
  `pending.clear()` and its `Drop` would break `into_inner` (E0509), with an
  after-drop test that is a use-after-free; 007 said seven `to_bytes` call sites
  (eight) and named `PacketWriter` among the readers; 008 called vmess's
  `auth_id` HMAC-bound when it is an AES-128-ECB timestamp block). All five
  fixed; second round not run — ref/causality corrections only.
- Next: pick the next unexplored domain — `native-transport`.

### Iteration 4 — native-transport
- Pre-existing dirty worktree (user's in-flight DNS-resolvers work, 35 paths)
  left untouched; only `docs/issues/` written. Start HEAD `668b3b4` (iter 3).
- Prior-work check: `rg` over `docs/issues/` for
  `transport/(tcp|quic|ws|grpc|xhttp|httpupgrade)` — only 005/006 touch
  `transport/mux.rs` internals; no existing issue on transport framing, and
  `XHTTP_POOL` was uncovered.
- Read: `transport/mod.rs`, `tcp.rs`, `quic.rs`, `httpupgrade.rs`,
  `v2rayhttp.rs`, `http/conn.rs`, `http/body.rs`, `ws.rs` (whole), `grpc.rs`
  (whole), `xhttp.rs` (`:30-300`, `:360-530`, `:660-860`, `:900-1215`,
  `:1215-1340` + the `http_version` table), `kcp/mod.rs`, `kcp/stream.rs`,
  `kcp/wire.rs::parse_datagram`/`parse_ack`, `kcp/session.rs::input`.
- Filed:
  - 010 (medium) — `xhttp::connect` branches on `ctx.is_tls()`, never on
    `http_version()`; a TLS row with `alpn=http/1.1` is dispatched to the h2
    client over an h1-negotiated session. Not a one-liner: the h1 arms' upload
    dial is a raw `tcp::connect(ctx, None)`.
  - 011 (low) — the same h1 arms' second dial ignores a chain base: a
    non-first-hop upload half exits the chain, while the h2 pool refuses exactly
    that shape (`register`'s `direct_hop` guard, and `chain.rs` refuses to
    consult the pool when `base.is_some()`).
  - 012 (high, **reproducer run**) — WS early data captures the first `N` bytes
    into `Sec-WebSocket-Protocol` and then writes the caller's buffer twice
    more; the carrier received `HEADERPAYLOADHEADERPAYLOAD` for a 13-byte write.
    Challenge test appended to `ws.rs`, run, reverted; `git status` shows no
    `crates/leas-native` path.
- Dead ends recorded (not filed): hyper's `initial_stream_window_size` is
  `&mut self -> &mut Self`, so `let _ =` there is NOT a dropped config (checked
  hyper 1.8/1.11/1.12 source); grpc's `MAX_FRAME_LEN` 16 MiB is a documented
  bound and its `poll_flush` returning `Ready` is deliberate; kcp
  `parse_ack` caps `count` at 255 and `KcpSession::input` is bounded by
  `rcv_wnd`; `v2rayhttp`/`XhttpStream` write-through `kick`/`poll_flushing`
  cannot report `Ok(0)`; xhttp `drain_incoming`/`drain_h3` are per-tunnel tasks,
  not per-request leaks.
- Reviewer round 1: `needs-fix`, 6 findings, all fixed:
  1. 012's fix sketch was wrong — it kept the `early` replay, so the prefix
     would still be written after already being in the header. Corrected to the
     reference's shape (`dialer.go:203-205` returns `len(ed), nil`, quoted in
     `docs/aegis/specs/2026-09-23-ws-path-canonicalization-design.md` §Residual):
     the capture branch returns `Ready(Ok(take))`, replay and `.max()` deleted.
     The reproducer now also decodes `Sec-WebSocket-Protocol` so a fix that
     leaves the prefix in a frame cannot pass on the frame assertion alone.
  2. 012 said "twice"; the prefix leaves three times (header + two frames) —
     fixed in body, title and INDEX row.
  3. 012 → 008 cross-ref misattributed the retry to 008; repointed to plain
     `AsyncWrite` + `flush_pending` (`first_flight.rs:85-105`) in both files.
  4. 010's ingestion-refusal fallback contradicts ADR 0018 D-F and
     `is_undialable_shape`'s own non-goal; replaced with a dial-time
     `capability::support_reason` refusal.
  5. 010's Related 006 misstated 006; reworded to the xhttp pool's own
     register-before-GET shape.
  6. 011's guard named a `base` that `xhttp::connect` never receives; corrected
     to `ctx.direct_hop` (set from `base.is_none()` at `chain.rs:205`).
- Second reviewer round not run: each fix is backed by the source the first
  round cited, and the two claim-shaped changes were re-derived from it.
- Next: pick the next unexplored domain — `dns`.

### Iteration 5 — dns
- Pre-existing dirty worktree (user's in-flight DNS-resolvers work, 35 paths)
  left untouched; only `docs/issues/` written. Start HEAD `0cde89f` (iter 4).
- Prior-work check: `rg 'leas-dns|dns_cache|mark_dns_failure|DNS_QUEUE_WAIT|
  resolve\.rs'` over `docs/issues/` — no hits.
- Read (all at HEAD): `crates/leas-dns/src/lib.rs` (whole), `dnscrypt.rs`
  (whole), `crates/leas-route/src/{dns_adapter,resolve}.rs`,
  `crates/leas/src/ops/enrich.rs` (the resolve task, permit layer, TTL gate,
  waiter registry). Dependency source read: hickory-resolver 0.26.3
  (`config.rs`, `connection_provider.rs`, `name_server_pool.rs`, `resolver.rs`).
- Filed:
  - 013 (medium, **measured**) — `ResolverOpts::timeout = 500 ms` bounds
    requests, not connection establishment: hickory-net's `CONNECT_TIMEOUT` is a
    hardcoded 5 s (`xfer/mod.rs:473`, applied at `tls.rs:223`), and `attempts=2`
    means 3 sends, so a wedged resolver costs 15.0 s. Measured: a silent-accept
    DoT endpoint took 15.006 s at 500 ms and at 2000 ms alike, and 20 real hosts
    over the real published list resolved 20/20 under both 500 ms and 5 s, worst
    10.22 s (= 2 × 5 s). The caller's 8 s `DNS_LOOKUP_TIMEOUT` is therefore the
    only real bound — it books the host as a failure, and it is below the tail of
    a working lookup.
  - 014 (medium, **reproducer run**) — the cold list download runs inside the
    lookup deadline, its own budget is 10 s (longer than the caller's 8 s), a
    caller cancellation never reaches the `downloaded.or(cached)` gate in front of
    the `system_conf` fallback, and a cancelled download caches nothing: a slow
    list host makes DNS resolve nothing, forever. Test passed (two cancelled
    attempts, no cache; control with a longer deadline caches). The test models
    the mechanism, not the 8 s/10 s ratio — recorded as such in the issue.
- Disproved first theory (recorded so it is not retried): "500 ms is too tight,
  so lookups fail on a slow path". Raising it 10× changed nothing on this host —
  20/20 either way, identical worst latency. The constant is not a fail-fast
  knob.
- Dead ends recorded (not filed): `lookup_ip`'s `Ok(empty)` after the
  `allow_ipv6` filter (every in-tree caller passes `true`, so it is unreachable
  today — noted, not filed); the DNSCrypt nonce (8 ns bytes + 4 random bytes per
  ephemeral session key) is unique per key; `write_dnscrypt_cache`'s temp+rename
  leaves no partial cache; `LOOKUP_WAITERS` cannot race because
  `spawn_dns_resolve_host` takes `&mut AppState`.
- Runbooks: both reproducers ran in a detached worktree (`git worktree add
  --detach /tmp/iter5 HEAD`, `CARGO_TARGET_DIR` shared, removed and pruned
  afterwards) because `crates/leas-dns` is dirty in this tree. One accident: the
  first append went to the DIRTY file; removed with a marker-delimited truncation
  and the tree verified against the pre-iteration path list.
- Reviewer round 1 (`ReviewIter5`, 3m20s): **needs-fix**, 6 findings, all fixed:
  1. 013's mechanism was wrong: `ResolverOpts::timeout` DOES bound a request
     (hickory-net `tls.rs:107` `DnsMultiplexer::with_timeout`,
     `dns_multiplexer.rs:236`); what escapes it is connection establishment,
     bounded by the hardcoded `CONNECT_TIMEOUT = 5 s` (`xfer/mod.rs:473`,
     `tls.rs:223`), and `attempts=2` makes 3 sends = 15.006 s, exactly the
     measurement. The issue, its title, its INDEX row and the cross-reference
     were rewritten around that; also renamed the file
     (`013-wedged-resolver-costs-15s-under-an-8s-deadline.md`).
  2. 013's fix sketch proposed a timeout around `NameServer::send`, which is
     `pub(crate)` — not implementable here, and the per-request bound it would
     add already exists. Replaced with the real levers (`attempts`, an outer
     per-lookup bound, or a connection provider like `dnscrypt.rs`'s).
  3. 014 said 10 s was "twice the caller's"; it is 1.25×, and the ratio is not
     load-bearing (only that the download outlives the caller).
  4. 014 said the fallback fires "only on `Err`"; the gate is
     `downloaded.or(cached)` (`lib.rs:311`), which also covers a download that
     parses to zero stamps. The real gap is that a CANCELLATION never reaches the
     gate at all — now stated as such, and the fix bullet was rewritten around it.
  5. 014's "mirrored 16× smaller" was false: the fixture is a 2 s response
     against a 500 ms deadline and never exercises the 10 s client budget. The
     issue now states exactly what the test models (the mechanism) and what it
     does not (the ratio).
  6. The STATE log carried 013's wrong mechanism as fact — corrected here.
- Second reviewer round not run: each fix re-derives from the source the reviewer
  cited, and those citations were verified directly in the vendored crates
  (`CONNECT_TIMEOUT` at hickory-net `src/xfer/mod.rs:473`, applied at
  `src/tls.rs:223`; `RetrySendStream` decrementing at
  `src/xfer/retry_dns_handle.rs:60,98-101`).
- Next: pick the next unexplored domain — `routing-engine`.

### Iteration 6 — routing-engine
- Pre-existing dirty worktree unchanged (35 paths, the user's in-flight
  DNS-resolvers work); HEAD `ad6fdee6`. 015's reproducer ran in a detached
  worktree (`/tmp/iter6`, removed after); 016 and 017 are code-proven from the
  sources and needed no run.
- Read (all at HEAD): `crates/leas-route/src/{lib,engine,matchers,resolve,sniff,geo,dns_adapter}.rs`
  (engine and matchers in full through the compiled-cond and
  `matches_domain`/`CidrSet` paths), `crates/leas/src/route_compile.rs`,
  `crates/leas/src/ops/geodata.rs` around the build,
  `crates/leas-native/src/inbound/mod.rs` (`handle_connect`, `forward_client`,
  `forward_direct`, the proxy leg).
- Filed:
  - 015 (medium, **reproducer run**) — `decide_async` puts the answer back into
    `ResolvedCache` on the *hit* path (`engine.rs:643` runs for `cached = Some`
    too), and `put` re-stamps (`resolve.rs:79-82`), so the 300 s TTL slides:
    a host under traffic never expires. Contradicts `get_fresh`'s documented
    `peek` rationale and `new`'s "ttl_secs past their store time". Also pays two
    `Vec<IpAddr>` copies, a second lock, and a `Resolved` event per hit —
    latent only because no production caller installs an event sink.
  - 016 (low, **code-proven shape, cost unmeasured**) — `forward_client`
    re-routes every UDP datagram: sniff copy → rule scan → engine cache →
    probe lock, then a *second* DNS cache (`self.dns_cache`) for the same host
    in `forward_direct`/`run_proxy_leg`. No per-flow memo, while every reference
    implementation routes per flow.
  - 017 (medium, **code-proven**, shape pinned by an existing test) —
    `match_items` deletes a field whose every token is unrepresentable, and the
    fields are AND-ed, so `A AND unrepresentable` becomes `A`:
    `protocols: [bittorrent]` + a domain matches all protocols, `network: "icmp"`
    vanishes entirely, `ips: ["oops"]` + ports matches every host on the port. A
    field that keeps at least one token instead *narrows* (fail-closed), which is
    the boundary the advisory and the reviewer both flagged and the issue now
    states explicitly. Only a `tracing::warn!` at build; the row stays active and
    the default is PROXY. Same refusal principle the repo applies to geo codes
    (`incompatibility`) and undialable configs (ADR 0018 D-C/D-F).
- Dead ends (recorded so they are not re-tried): `needs_resolve()` is a public
  O(rules×items) walk with **no production caller** (tests only) — dead-ish API,
  not worth an issue; `CompiledDomainItem`'s `positive || any(!negated)` reads
  like an OR-of-negations bug but is exactly OR semantics for a reversed token;
  `suffix_hit`'s dot walk, merged-CIDR `contains`, the `SCAN_MAX` split, and
  `GeoCompiler::preload`/`take_site` are all deliberate and already
  allocation-aware; `compile_domain_item`'s per-token work is build-time only.
- Reviewer round 1 (`ReviewIter6`, 5m31s): **needs-fix**, 8 findings, all fixed.
  It confirmed the three mechanisms and the 015 reproducer, then corrected
  citations and one false claim:
  1. 016 asserted an engine rebuild can re-route a live flow. False: the engine
     is `Arc<Engine>` pinned in `Socks5InboundConfig` per session
     (`inbound/mod.rs:100`, `ops/native_connect.rs:49`); a rebuild swaps the
     `EngineCell` slot, a profile switch ends the association. The real
     per-datagram variance is the stateless `probe` (Initial vs 1-RTT) and a
     re-resolved domain; the Fix sketch's invalidation premise went with it.
  2. `:1166` is a comment — `cached_domain` is `:1145` (fixed in the issue and
     its INDEX row).
  3. The proxy leg resolves once per leg (`:1417`), per datagram only for a
     different destination (`:1522-1525`) — the per-datagram second lookup is
     `forward_direct` only.
  4. 016's cross-reference to 001 was wrong (001 is the TCP accept loop); 003
     owns the same `UdpRelay`.
  5. 017's "losing one [token] turns `A AND B` into `A`" over-generalized: each
     field is OR-valued internally and 2+ recognised protocols lower to
     `Cond::Any`, so a partially recognised field *narrows*. Only a field whose
     last surviving item is dropped widens. Rewritten, and confirmed
     independently by the advisory.
  6. `geodata.rs:452-457` is the `incompatibility` warn; the row warnings are
     `:461-466`.
  7. 015's `IfNonMatch` anchor is `geodata.rs:481` (479 is the PROXY tag).
  8. STATE said "no worktree run was needed and none was started" while 015
     recorded one — provenance contradiction, fixed.
- Second reviewer round not run: every fix is a citation correction or a claim
  deletion, each re-verified directly against HEAD (`:1145`, `:1417`,
  `:1522-1525`, `:461-466`, `:481`, `Socks5InboundConfig`), not re-derived.
- 015's reproducer: detached worktree `/tmp/iter6`,
  `test resolve::hit_path_restamp_slides_the_ttl ... ok` (control assertion
  expires), removed afterwards. 017 stays **code-proven only**: a run would need
  a cold `crates/leas` binary-target build, and its shape is already pinned by
  `unparseable_ip_entry_warns_not_errors` (`route_compile.rs:642`).
- Next: `db-layer` (next unexplored).

### Iteration 7 — db-layer
- Pre-existing dirty worktree unchanged (35 paths, the user's in-flight DNS
  work, incl. `crates/leas-db/*`); HEAD `936d42f2`. Because `leas-db` is in the
  dirty set, every line reference below is to **HEAD**, read in a detached
  worktree (`/tmp/iter7`, removed after) — never the working tree.
- Read at HEAD: `write_behind.rs` (whole driver + `LinkSpec`), `retry.rs`,
  `database.rs` (open/wipe, `conn`, `drain_dirty_ranks`, `apply_link_patches_tx`,
  `link_values_sql`, page loaders, delete/purge cascades,
  `purge_invalid_shapes_once`), `merge.rs`, `profiles_query.rs` (SQL builders,
  `page_ids_direct`, aggregates), `endpoint_rank.rs` (refresh, write,
  `protocol_weights`, `backfill_all`), `endpoint_ip.rs`, `export.rs`,
  `driver/mod.rs`, `schema/{mod,steps,ddl}.rs`, `docs/research/2026-11-16-turso-0.9-delta.md`.
- Filed:
  - 018 (medium, **theory** — both halves measured in-repo) —
    `merge_in` loads the WHOLE protocol table (`protocol_weights` =
    `Protocol::all()`, ~0.47 s at 6,111 protocols per the crate's own page-load
    measurement) to answer for the two endpoints' link protocol ids it has
    already loaded, and `delete_absorbed` runs the whole-table orphan anti-join
    (23 + 29 ms at 74k protocols, 31 ms inside the transaction). One pair per
    transaction, driven by the compact loop ⇒ 171 merges pay 171 of each. The
    repo's own study already recommends the batch half (delta doc §6 item 3) and
    the crate's `endpoint_rank::refresh` already documents avoiding the other
    ("a separate load would re-scan the whole protocols table on every flush
    window"). Fix: restrict both to the pair's ids.
  - 019 (medium, **theory** — plan and timings measured on the turso shell) —
    the D6 search predicate claims "an index seek, not a full scan". It is a
    scan: `rank_domain` is the 5th column of `endpoint_rank_key_v2` (no index
    leads with it; the tab opens on `Active`, binding `band < 2`, a range on the
    leading column), and the `CAST(e.port AS TEXT) LIKE '%…%'` arm is
    unindexable by construction and OR-ed with the range arms. Measured at 50k
    rows: no-search page 0.5 µs, all three arms 40 ms, `COUNT(*)` with the same
    WHERE 15 ms — the count runs on every keystroke and the page degrades to the
    same scan whenever fewer than 200 rows match. Adding `rank_domain` /
    `rank_sub_domain` indexes AND dropping the port arm gives `MULTI-INDEX OR` +
    a sorter at **53 µs**; with the port arm left in, the plan does not move.
    Caveat stated in the issue: the probe ran on the 0.6.1 shell, the app pins
    `=0.9.0-pre.5`; the two structural facts are planner-independent, and the
    repo's own gate for the shape is `arm_plan_sweep`, whose 13 statements omit
    the search page.
  - 020 (medium, **theory** — schema-proven, exposure from four delete paths) —
    the schema declares NO foreign keys (`docs/reference/database.md`: "none:
    toasty emits no SQL `REFERENCES`"; no `REFERENCES` in `crates/leas-db`; the
    db-rewamp spec §9.5 already measured `PRAGMA foreign_key_list` empty), while
    `driver/mod.rs:450` applies `foreign_keys=ON` and `discard_where`'s doc
    justifies itself with a "live-FK error … re-stage it, retrying forever" that
    cannot happen. The real consequence of a missed sweep is a silent orphan
    `profile_stats` row. Only the compact merge sweeps (`compact.rs:213-214`);
    `delete_profile` (`profiles.rs:938`), "remove failed servers"
    (`ping.rs:612`, which deletes exactly the endpoints whose patches the probe
    just staged, `events.rs:875`) and the 10-minute retention purge
    (`main.rs:596-630`) do not.
- Rejected during the iteration (recorded so they are not re-tried):
  - "`SCHEMA_VERSION` can be bumped without a `steps` entry and wipe every user
    database" — plausible (`steps_after(22)` returns `None`, and `migrate` maps
    that to `IncompatibleSchema` → file deleted), but **already guarded**:
    `schema_migrate.rs:747-760` opens a v20 fixture and asserts the cursor
    reaches `SCHEMA_VERSION`, so a stale step list reds the suite. Not filed.
  - `is_busy_error`'s `to_string().contains(..)` allocation; `drain()`'s
    `Vec`-of-keys + `Vec`-of-rows passes; `discard_where`'s one-shot sweep
    (kept, with 020's caveat); `purge_invalid_shapes_once` materialising every
    config once per database; `apply_link_patches_tx`'s 32-bucket presence-vector
    loop (bounded, and the bucketing is what makes one `ON CONFLICT` per group
    set possible). All deliberate or trivial.
- Dead ends: `profiles_walk_page` has no production caller (documented); the
  `Coalesced` doc comment says "coalesce returns the row alongside the patch"
  while `Coalesced` holds only key+patch and restage reconstructs from the patch
  — doc drift, not worth a file; `sql_lit`'s "values come from our own rows"
  comment is stale (domains come from share links) but `sql_lit` doubles quotes,
  so there is no injection.
- Plan-sweep caveat for the next db-layer pass: the `arm_plan_sweep` statement
  list (`tests/turso09_lab.rs:684-780`) should gain the search page before 019's
  fix is adopted, so the plan change is pinned by the lab rather than by the CLI.
- Reviewer round 1 (`ReviewIter7`, 5m12s): **needs-fix**, 9 findings, all
  addressed. It confirmed every core mechanism (both 018 halves, the 019 plan
  facts incl. `arm_plan_sweep`'s statement list, the 020 schema premise — and it
  found an additional, stronger citation for it: the db-rewamp spec's §9.5
  `PRAGMA foreign_key_list` empty measurement).
  1. **020 understated exposure** (P2, the only substantive finding): it said
     the guard existed in "one of the two delete paths". There are FOUR and only
     compact guards — `delete_profile` (`profiles.rs:938`), "remove failed
     servers" (`ping.rs:612`, which deletes exactly the endpoints whose failure
     patches the probe just staged via `events.rs:875`), and the retention
     purge. Severity raised low → **medium** with the impact bounded explicitly
     (orphans are invisible to the page; they cost a metrics count and a
     permanently-live protocol row), fix option 3 re-scoped from "both paths" to
     all three call sites and downgraded to window-narrowing only.
  2. `page_ids_direct` cited at `:974-1010` (that range is `Projection`) — it is
     `:762-799`; fixed in header, body and INDEX. (I had fixed this before the
     review ran; the reviewer read the pre-fix copy.)
  3. Pragma test cited at `turso09_lab.rs:1315` — the test is at `:1286`, the
     assertion `:1308`.
  4. `discard_where`'s doc cited at `:249-256` — it is `:271-275` (already
     fixed pre-review).
  5. 018's 0.47 s measurement cited at `:1247-1251` — it is `:1226-1229`.
  6. 018's `delete_endpoints` quote cited at `:1929-1936` — it is `:1918-1921`.
  7. 020's cascade range `1864-1892` stopped before the `endpoint_ip`/`endpoints`
     /rank deletes it listed — now `:1877-1900` with per-step lines.
  8. 019 called `All` the tab's default view; `PurgatoryView` derives
     `#[default] Active` (`models_toasty.rs:1019-1023`, `state.rs:831`). The
     structural claim survives (`Active` binds `band < 2`, a RANGE on the
     leading column) and the paragraph now says so.
  9. 019's "two full scans per keystroke" overreached the measurement: the count
     always scans, the page only when fewer than 200 rows match. Hypothesis and
     title corrected.
  Minor, also fixed: STATE labelled 018/019 "code-proven"/"reproducer run" while
  the issue headers say `theory` — both now say theory.
- Second reviewer round not run: six of the nine findings were citation lags
  already fixed before the review returned, and the remaining three (020's
  delete-path inventory, 019's default view, 019's double-scan wording) were
  each re-verified directly against HEAD (`profiles.rs:938`, `ping.rs:612`,
  `events.rs:875`, `models_toasty.rs:1019`, `state.rs:831`).
- Carried in this iteration's commit: 017's Location line and INDEX row still
  cited `geodata.rs:452-471` (a range that also spans the `incompatibility`
  skip) after iteration 6's body fix; both now cite the warn site `:461-466`,
  matching the body.
- Next: `app-ops` (next unexplored).
