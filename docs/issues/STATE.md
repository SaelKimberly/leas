# Issues Review — Loop State

```yaml
loop:
  iteration: 11
  status: running
  noop_streak: 0
coverage:
  - domain: native-inbound
    status: in-progress
    last_touched_iteration: 11
    issues: [001, 002, 003, 027, 028]
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
    status: in-progress
    last_touched_iteration: 8
    issues: [021, 022]
  - domain: ui-render
    status: in-progress
    last_touched_iteration: 9
    issues: [023, 024]
  - domain: tls-security
    status: in-progress
    last_touched_iteration: 10
    issues: [025, 026]
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

### Iteration 8 — app-ops
- Pre-existing dirty worktree (the user's DNS-resolvers work, 35 paths) left
  untouched; `crates/leas/src/ops/*` is in that set, so every read, grep and
  challenge ran in a detached worktree at HEAD (`81ac1a58` → `/tmp/iter8`,
  removed before the commit).
- Prior-work check: `ops/*` appeared only as incidental citations in 001, 004,
  013, 014, 020 — no issue is about an app-ops flow. No duplicates.
- Read: `job_scheduler.rs` (whole), `scheduler.rs` (whole), the
  `CompactFinished`/`MaintenanceDone`/`BatchEnded` handlers in `events.rs`
  (`:700-790`, `:1039-1082`), `poll_core_events`'s drain budget (`:412-444`),
  `speed_test.rs` (batch start + terminal emits), `compact.rs` (both maintenance
  spawns, the merge driver), `enrich.rs` (resolve lifecycle, `should_resolve`,
  the waiter fan-out, the whitelist/countries passes), `purge.rs`, the tick loop
  in `ui/mod.rs:280-345`.
- Filed:
  - 021 (medium, **theory** — code-proven) — `spawn_dns_retry` reports a scan
    failure as `CoreEvent::CompactFinished` (`compact.rs:428-437`), whose only
    accepted `TaskKind` is `Compact`; `handle_terminal` therefore treats it as a
    stray (spec D43) and restores `running_task`, which nothing clears before
    quit. Result: the queue never drains again, every later task sits in
    `task_queue`, `is_busy()` keeps the destructive one-shots disabled, and
    `stop`/`resume` do not touch `running_task`, so only a restart recovers.
    The scheduler-level mismatch is *pinned* as intended
    (`terminal_events_match_the_running_task`); nothing tests producers against
    the taxonomy, which is the seam the bug slips through.
  - 022 (low, **theory**, shape proven + cost measured on a lock-free
    stand-in) — `mark_dns_failure` calls `sweep_dns_failures`, i.e.
    `dns_failures.retain(..)` over the WHOLE map, on every failure; the map
    cannot shrink inside the 15 s floor (`MIN_DNS_DEFER_SECS`), so a burst of F
    failures pays F²/2 entry visits plus a write lock of every DashMap shard per
    sweep, blocking the dispatch path's `is_dns_unresolved` reads. The repo's
    own 2026-11-19/20 record (12,093 hosts in six seconds) is the burst shape.
    Measured stand-in (`rustc -O`, plain `HashMap`, outside the repo): 0.85 ms
    at F=1,000, 8.17 ms at 4,000, **72.60 ms at 12,093** — visit counts
    500,500 / 8,002,000 / 73,126,371, i.e. ≈1 ns per visit — a lower bound. The
    sweep is pure hygiene (`is_dns_unresolved` already drops an expired entry it
    reads), so a counter or a length bound removes the quadratic term.
- Rejected / dead ends during the iteration (recorded so they are not re-tried):
  - `TaskScheduler::reset` clears `states` but not `tasks`, so a live id would
    stay registered across a batch boundary. **No reachable trigger**: every
    probe entry point goes through the job scheduler (`start_tcp_ping` /
    `start_real_ping` / `start_speed_test` / `start_udp_test` have no caller
    outside `job_scheduler::dispatch`), which is one-job-at-a-time, and both
    `reset` callers guard on `batch_progress`/`fill_progress`. Recorded, not
    filed.
  - `stop()`'s doc says "cancel the running task", but `Compact` and `DnsRetry`
    never read `speed_test_stop` (only the probe batches and the fill clone it),
    so those two run to completion with the queue paused. Deliberate-looking,
    not filed.
  - `spawn_whitelist_pass` clones every endpoint's `EndpointInfo` and emits one
    `EndpointInfoUpdated` per endpoint (11k) — the channel is 65,536 slots
    (`state.rs:783`) and the drain budget 256/tick (`events.rs:405`), so the
    burst is designed for. `mark_rows_dirty` is a `|=` on a `RefCell<u8>`.
  - `db_monitor`'s per-statement mutex is documented as deliberate with a
    profile caveat. `spawn_outbound_enrich`'s linear endpoint lookup is O(n) per
    real-ping result — a few ms per batch, not worth a file.
- Reviewer round 1 (`ReviewIter8`, 5m15s): **needs-fix**, 9 findings, all
  applied. It verified 021's chain end to end (`compact.rs:431-434` →
  `events.rs:727-730` → `job_scheduler.rs:335-336` → `:357-365` → `drain`
  `:170`) and 022's mechanism (including dashmap 6.2.1's `_retain` taking each
  shard's write lock), so no claim changed shape; every finding was a citation
  or a precision defect.
  1. **021's Related referenced a phantom 023** and described 022 as a second
     slot-handback failure — 022 never touches `running_task`. Deleted the
     phantom, 022 now described as the scan cost.
  2. 021's counter-test comment was inverted: with `running_task = DnsRetry`,
     `CompactFinished` is refused, so the sketched assertion **fails today**.
     Replaced with the two halves a seam test needs — the pairing table (passes
     today) and the producer half (untested).
  3. "Nothing tests producers against the taxonomy" was too broad: the retry's
     **success** exit is pinned by `retry_targets_only_unresolved_dns_hosts`
     (`compact.rs:708-762`, waiting on the `"DNS retry: complete"` log line only
     the `MaintenanceDone` handler writes). Now scoped to the failure exit.
  4. "Nothing else clears `running_task` except the quit path" was false —
     `drain`'s refused-spawn path (`:198`) also clears it, unreachable behind
     `drain`'s early return. Text now says so.
  5. 021's `→ 019` bullet called a slow scan "this issue's trigger"; the trigger
     is any `load_all_rows` error, and 019's scan only widens the window.
  6. 022's `retain` sub-citation landed on closing braces: the function is
     `:425-433` and the `retain` `:431-432`, not `:423-435`/`:433-434`.
  7. The measured F=4,000 visit count contradicted F²/2. Re-ran the probe
     (`rustc -O`, outside the repo) and replaced the block with exact counts
     (500,500 / 8,002,000 / 73,126,371) and the fresh times (0.85 / 8.17 /
     72.60 ms); the first run's 14.10 ms at F=4,000 was a warm-up outlier.
  8. "The map cannot shrink during a burst" overreached — `retain` does drop
     pre-window entries. Now stated as F·(K + F/2) over a pre-existing
     population K, with the reason nothing inserted in a window can expire in
     it.
  9. The INDEX `021 → 013, 022 → 013` bullet attributed a fix 013 did not make
     and claimed 021 reads the stamp. Split: only `022 → 013` remains, phrased
     as 013 documenting the starved-vs-answer split.
- Second reviewer round not run: all nine findings were citation/precision
  fixes re-derived from the sources the first round itself cited
  (`compact.rs:708-762`, `:431-434`, `job_scheduler.rs:198`, `:431-432`), plus a
  re-run of the probe whose numbers the finding disputed.
- Deferred lead (not filed — third-party advisory, verified partially): the
  retry's completion counter can also fall short *without* a lost bump.
  `spawn_dns_retry` sizes `name.total` from DB rows
  (`is_dns() && resolved_ips.is_empty()`, `compact.rs:439-458`) and
  `enrich.rs:382-398` (`settle_starved`) says in its own doc that "a silent
  starvation would hold the maintenance job (and the task queue) for its
  30-minute bound" — i.e. the repo already knows the class. The residual gap is
  `spawn_dns_resolve_host`'s `should_resolve == false` early return
  (`enrich.rs:481-497`): it calls `end_dns_lookup` and returns **without**
  `bump_resolve_progress()`, so a target whose SESSION entry disagrees with its
  DB row (the exact split `enrich.rs:486-495` documents for the batch path) is
  never retried and the counter never reaches `total` — 1,800 × 500 ms in the
  job slot. Needs: prove a session entry can carry `resolved_ips` non-empty with
  `resolved_at_secs: None` (the only shape `should_resolve` rejects under
  `force`), then file with the fix at the counter (settle against what was
  actually dispatched) rather than at the loop bound.
- Advisory review (external, two turns later): 021's symptom paragraph was
  sharpened from it — the `CompactFinished` handler clears `maint_progress`
  (`events.rs:721`) before forwarding, so the stuck state is `running_task`
  alone, the status bar renders `" <label> …"` from `running_task_meters`'s
  `(0,0)` fallback (`ui/status_bar.rs:27-48`, `:78-84`), and the resolve meter
  installed at `enrich.rs:425` is never cleared (`set_resolve_progress(None)`
  lives only in the `MaintenanceDone` arm, `events.rs:753`). Its other two
  points were stale (nothing in 021 claimed the one-shots stay enabled; the
  phantom 023 and the `→ 019` bullet were already fixed in reviewer round 1),
  and its proposed `021 → 020` link was rejected: 020 is orphan rows on delete
  paths, with no causal relation to a read error in the retry's scan.
- Next: `ui-render` (next unexplored).

### Iteration 9 — ui-render
- Dirty worktree unchanged (the user's 35 paths, including
  `crates/leas/src/ui/**`); all reads/greps at HEAD in a detached worktree
  (`/tmp/iter9`), removed before the commit.
- Prior work: `docs/issues/` had **no** issue about a `crates/leas/src/ui/`
  file — `ui/` appeared only as incidental citations (status bar, tasks pane,
  settings) inside app-ops issues. Domain was `unexplored` in INDEX.
- Scope: the pane-1 `Sniffer` tab (`ui/sniffer.rs`, 386 lines) — the only
  per-host view of a live native session, and its producer
  (`crates/leas-native/src/telemetry.rs`).
- Filed:
  - 023 (low, **theory**) — `scroll_offset` clamps the offset to `len - 1`
    (`sniffer.rs:41-44`) and `handle_key` repeats the bound (`:271`), so `End`
    parks the window on the last host: `ratatui`'s `visible_rows` starts at
    `state.offset.min(last_row)` and never backs up unless a *selected* row is
    past the end (`ratatui-widgets-0.3.2/src/table.rs:998-1031`), and this
    table sets no selection — one host painted, the rest of the pane blank.
    The `TableState`-selection alternative was checked and does **not** fix it
    (at `offset = len-1` the selected last row is already visible).
  - 024 (low, **theory**, cost measured outside the repo) — `render_table`
    maps every host into a `Row` (5 `String`s + a `Row` each,
    `sniffer.rs:202-215`) while `render_rows` paints `visible_rows` only
    (`table.rs:846-884`); widths come from the constraints, not the cells
    (`:1041-1068`), so the slice preserves the paint **once the widget's offset
    is reset to 0** — it re-applies `state.offset` to whatever rows it gets
    (`:998`, `:865`), reviewed and corrected in round 1. Host list cap 1000
    (`telemetry.rs:196-198`); probe (`rustc -O`, **six** Strings per host — one
    above the repo's five, so an upper bound): 58 µs / 1,200 Strings at 200
    hosts, **180 µs / 6,000 Strings at 1,000**. Draws
    fire per input and per core event (`ui/mod.rs:374`), and the core publishes
    a sample every second (`native_connect.rs:138-141`), so the tab re-pays it
    at ≥1 Hz while connected. Probe kept at `/tmp/probe23` (outside the repo).
- Checked and **not** filed (recorded so the next pass does not re-derive):
  - `telemetry.rs:527-534` — `with_host` scans all 1000 rows for the LRU victim
    on a *new* host at cap, under the mutex every datagram's accounting takes
    (`udp_sent`/`udp_received` are per datagram, `inbound/mod.rs:1000`,
    `:1208`). Real, but ~1 µs and only on first sight of a host; the per-second
    `snapshot()` merge (`telemetry.rs:575-633`, O(hosts × open legs)) is 1 Hz.
    Below the bar for an issue.
  - the display-row cache (`profiles.rs:1271-1306`) is keyed on
    `endpoints_gen` + expanded flags + multi-select — checked every writer of
    `state.endpoints` (`ops/profiles.rs:189` bumps at `:196`;
    `:226` — the load-error arm — clears WITHOUT a bump; `:1365`/`:1769` are
    test-only). No stale rows result, for a different reason than the gen: the
    key also requires `!cache.rows.is_empty()` and
    `cache.expanded.len() == rows.len()` (`ui/profiles.rs:1276`, `:1285`), so
    a cleared page can never match.
  - `textfit::truncate` guards `width == 0` (`textfit.rs:30-38`); the routing
    list indexes are guarded (`settings.rs:1946`, `:1972`); the log cache is a
    `VecDeque` with a `pop_front` beside every `push_back` (`logs.rs:613`,
    `events.rs:560`, `:598`) and the pane's scroll is saturating
    (`logs.rs:208`).
- Reviewer (`ReviewIter9`, 5m55s): **needs-fix**, 8 findings, all citation or
  reasoning defects — no mechanism changed. Dispositions:
  1. 024's slice recipe kept the widget offset — fixed: the `TableState` must be
     built without `with_offset`, since `render_rows` re-applies
     `state.offset` to whatever rows it receives (`table.rs:998`, `:865-866`).
  2. "empty slice" was wrong — `len - 1` yields exactly one host
     (`len-1..len`); corrected in 023, 024 and the INDEX bullet.
  3. 023's clamp must record the **data-row** height, not `area.height` (the
     header is split off first, `table.rs:775-777`) — one row short otherwise.
  4. the header renders at `table.rs:777` (`render_footer` is `:781`) — cite
     fixed in 023.
  5. `PageUp` does recover the view (`sniffer.rs:265`) — "no key but Home/Up"
     corrected.
  6. STATE's "behaviour-preserving" now carries the offset-reset caveat.
  7. the probe builds six `String`s per host, not five — described as an upper
     bound in both the issue and STATE (its timings were not re-run).
  8. `reload_profiles`'s error arm clears `endpoints` WITHOUT bumping
     `endpoints_gen`; the no-stale-rows conclusion stands on the other two key
     terms (`ui/profiles.rs:1276`, `:1285`) and STATE now says so.
- Second reviewer round not run: all eight were re-derived from the files the
  first round cited (the ratatui widget source for 1-4, `sniffer.rs` for 5,
  `ops/profiles.rs:226` + `ui/profiles.rs:1276/1285` for 8).
- Next: `tls-security` (last unexplored).

### Iteration 10 — tls-security
- Selected: the last `unexplored` domain. Scope: `crates/leas-tls` (verify
  tiers, record layer, REALITY/ECH, hello/extension parsing) with the
  `crates/leas-native/transport/tls*` seams.
- Dirty worktree untouched (35 user paths, unchanged since iteration 9);
  all reads at HEAD in a detached `/tmp/iter10`.
- Prior-work check: `rg 'tls-security|leas-tls|tls13' docs/issues/` → only the
  coverage row and the "Next:" line; no issue had ever cited a `leas-tls` file.
- Filed (both `theory`, both read-proven from HEAD):
  - **025** `025-finished-mac-compared-out-of-constant-time.md` (low): the
    server `Finished` MAC is compared with slice `!=` in both drivers
    (`handshake/mod.rs:602`, `handshake/tls12.rs:531`) and the SPKI pin digest
    at `verify/mod.rs:147`, while the crate's own standard is `subtle::ct_eq`
    (`reality/verify.rs:77-78` + `Cargo.toml:22-24`, `dnscrypt.rs:230`) and the
    ECH confirmation is hand-written branchless (`handshake/mod.rs:434-443`).
    Hardening, NOT an exploitable oracle: round 1 killed the prefix-oracle
    narrative (the record is AEAD-opened before the compare and the tag is
    derived from the same secret, so the submitter already knows it). Filed at
    low for the convention gap only; no reproducer and no test proposed, by the
    review's own rule against source-text tests.
  - **026** `026-servers-key-share-group-is-never-checked-against-the-hello.md`
    (low): two RFC 8446 §4.2.8 rules are unenforced on the `ServerHello` path —
    the client MUST compare the server's group with the `HelloRetryRequest`'s
    `selected_group` (verbatim MUST + `illegal_parameter` abort in the RFC;
    `hrr.selected_group` is consumed only by `retry.rebuild`, `:247-262`,
    nothing compares it afterwards) and the `server_share` "MUST be in the same
    group as the KeyShareEntry value offered" (the suite at `:394` and the
    sigalg at `:557` are both re-derived from the hello actually sent; the
    group is not, `:1079-1112`; `offered_share` `:825-837` has no caller outside
    the retry rebuild, `:269`/`:275`). The retried case is a working downgrade:
    `ClientHello2` carries only the hybrid entry (`retry_extensions`,
    `:843-885`), whose body includes the client's X25519 public half
    (`spec/mod.rs:165-168`), so a hostile server can answer `0x001D` and
    complete classically — `:494-508` takes the `_` arm, `:643` records
    `negotiated_hybrid = false`, and no PRODUCTION path surfaces that flag (the
    e2e oracle asserts it, `leas-oracles/src/e2e/mod.rs:328`, `:429-444`).
    Explicitly scoped: selecting the classical share when it WAS offered is
    legal and is not the bug.
- Checked and **not** filed:
  - read-side per-key record limit: RFC 8446 §5.5 is a SHOULD on the sender
    ("SHOULD do a key update prior to reaching these limits"), and a failed
    decrypt kills the stream here, so there is no receiver obligation to
    enforce; `should_update` (write-only, `record/stream.rs:63`, `:421-427`,
    call `:945`) seals the KeyUpdate at `seq == limit`, inside the 2^24.5
    margin. Not a defect.
  - the flight reassembly is bounded (`MAX_FLIGHT_BUFFER` = `4 + 0xFF_FFFF`,
    `handshake/mod.rs:176`, enforced at `flight.rs:148-152` and `tls12.rs:131`) and the RFC 8879 decompressor is capped at
    1 MiB (`flight.rs:358-378`); the ECH parser uses `get(..)`/`checked` shapes
    (`ech.rs:75-140`) and the REALITY DER walker bounds every `pos + len`
    (`read_tlv`, `reality/verify.rs:353-390`); no panic path found on peer input.
  - ECH inner hellos are padded to 32-byte units (`seal_inner` →
    `pad_inner`, `ech.rs:192-233`) and a rejected ECH is a hard error, never a
    plain-SNI fallback (`handshake/mod.rs:434-457`); a malformed `ech=` value
    is refused by name at capability checking and never dialed
    (`capability.rs:173-174` → `security_reason`, which `ops/ping.rs:361` and
    `ops/connect.rs:174` turn into the marker text — NOT a `config_invalid`
    purge verdict; corrected in round 1).
  - the `insecure` flag defaults to false where it is read
    (`security/mod.rs:96`, `opts.insecure.unwrap_or(false)`); `verifier_for`
    only forwards it (`fingerprint.rs:160-172`), and `WebPkiVerifier` itself
    starts `insecure: false` (`verify/mod.rs:78`). The probe builds
    `webpki_roots()` with no insecure fallback (`probe.rs:625`).
  - `make_handshake_record`/`make_app_data_record` silently clamp a >64 KiB
    length with `unwrap_or(u16::MAX)` (`record/mod.rs:195-222`) — real smell,
    but `make_app_data_record` has no production caller and the handshake
    builder only frames hand-sized messages; recorded here instead of an issue.
  - `spider::run` issues bounded browser-shaped GETs to the peer that failed
    REALITY auth (`reality/spider.rs:53-100`), which is xray's documented
    `!Verified` behaviour, not a defect.
- Reviewer (`ReviewIter10`, 7m9s): **needs-fix**, 7 findings — 2 substantive,
  5 citation/mechanism drift. Dispositions:
  1. **Accepted, and it reshaped 025.** The prefix-oracle narrative was
     unreachable: the `Finished` record is AEAD-opened under the handshake
     traffic key before the compare, and `finished_key` is expanded from that
     same secret, so whoever submits a candidate tag already knows it. 025 is
     now filed explicitly as hardening (convention gap), with a "no oracle is
     reachable today" paragraph and the old Lucky13 parallel removed.
  2. **Accepted, and it reshaped 026.** The quoted "server MUST select a group
     from `key_share`" is not RFC text. Re-read §4.2.8: the real rules are
     "`server_share` … MUST be in the same group as the KeyShareEntry value
     offered by the client" (server MUST) and, after an HRR, "the client MUST
     verify that the selected NamedGroup in the ServerHello is the same as that
     in the HelloRetryRequest … abort with an `illegal_parameter` alert" (an
     explicit CLIENT MUST, and a stronger finding: `hrr.selected_group` is
     consumed only by `retry.rebuild`). 026 now leads with the verbatim client
     MUST and the retried-downgrade case; the "compliant client rejects"
     overstatement is gone.
  3. Coverage row `issues: []` → `[025, 026]` (fixed; the only row that
     disagreed with its own iteration block).
  4. "malformed `ech=` is `config_invalid` at ingestion" was wrong: the
     capability gate refuses it by name (`capability.rs:173-174`) and the
     consumers turn that into marker text (`ops/ping.rs:361`,
     `ops/connect.rs:174`), not a purge verdict. Corrected.
  5. `reality/verify.rs:10` → `:11` for the `subtle` import, and the snippet
     header is `:76-78` (comment 76-77, `ct_eq` 78). Fixed in 025.
  6. "`verifier_for` defaults `insecure` to false" mis-attributed the default:
     it is `opts.insecure.unwrap_or(false)` at `security/mod.rs:96`; the helper
     only forwards it. Corrected.
  7. "nobody surfaces `negotiated_hybrid`" was absolute: the e2e oracle reads it
     (`leas-oracles/src/e2e/mod.rs:328`, `:429-444`). Narrowed to "no production
     path surfaces it".
- Second reviewer round not run: each fix was re-derived from the files the
  first round cited (RFC 8446 §4.2.8 text, `handshake/mod.rs` helper lines,
  `capability.rs`, `security/mod.rs`, the oracle). 025's *mechanism* changed
  (exploit → hardening), which is the one place a second round would have been
  justified; the new text only drops claims, it adds none.
- Reviewer round 2 (`ReviewIter10b`, 5m42s): **needs-fix**, 4 findings — all in
  the two fix sketches plus one absolute in a title. Round-1 items 1-7 verified
  gone against HEAD. Dispositions (all applied):
  1. 025's title claimed "every other secret-keyed tag uses `ct_eq`", which its
     own body contradicts (the ECH check is a branchless fold, constant-time but
     not `ct_eq`). Title and INDEX row now say "every other secret-keyed tag
     comparison is constant-time".
  2. 025's `tags_equal` sketch was a private `fn` used from two modules — it
     cannot compile as written. Now `pub(crate)` in `crypto/mod.rs` (the
     AEAD/KDF home both modules already read) with the reachability reason
     stated.
  3. 026 said §4.2.8 defines "exactly two server obligations"; the paragraph
     also carries `supported_groups`, `psk_ke` and "exactly one entry" rules.
     Reworded to "several … two of them are the ones this engine does not
     enforce", with the rest declared out of scope.
  4. 026's sketch called `ensure_offered_share` unconditionally in the
     version-generic block that also dispatches TLS 1.2 (`sh.suite12` is read
     two lines up), so it would reject every legitimate 1.2 reply. The recorded
     group is now `Option<u16>` and both checks are guarded on `Some`.
- Third round not run: the four fixes are the reviewer's own wording (title,
  visibility, enumeration, guard) applied at the exact lines it named; no claim
  changed shape. State of the slate: 025 hardening / 026 two §4.2.8 group
  rules, both `low` + `theory`.
- Next: commit, then convergence check — no `unexplored` domain remains
  (10 of 10 in-progress), so the next iteration is the first that must pick by
  "oldest in-progress".

### Iteration 11 — native-inbound
- Domain choice (policy): no `unexplored` domain remains; picked the oldest
  in-progress, `native-inbound` (last touched iteration 1).
- Prior-work check (`rg` over `docs/issues/`): 001/002/003 cover the accept
  layer, the relay write deadline and the association's eager buffers; 016
  already cites `resolve_domain`/`cached_domain` as *cost* and 015 covers the
  engine-side TTL re-store. No issue covered the `seen` list or the answer's
  lifetime, so two new files; the DNS duplication stayed in 016 rather than
  being re-filed.
- Read (HEAD in `/tmp/iter11`): `inbound/mod.rs` (relay loop :623-700, proxy
  queue :760-1395, direct leg :1110-1230, association cache :1573-1618),
  `inbound/mixed.rs`, `inbound/socks5.rs` (greeting/credentials/request),
  `inbound/http.rs` (head parser :434-560), plus the engine side
  (`leas-route/src/engine.rs:520-655`, `resolve.rs`), the production wiring
  (`ops/geodata.rs:481-494`) and the app's TTL policy (`state.rs:909`).
- Filed:
  - **027** `027-udp-association-seen-hosts-vec-is-unbounded.md` (medium,
    theory, measured): `seen: SmallVec<[CompactString; 4]>`
    (`inbound/mod.rs:884`) grows by one entry per distinct destination and
    `note_conn` (`:931-938`) linearly scans it on every routed datagram
    (`:1099`/`:1104`); the sibling `DnsCache` was capped at 64 for the same
    reason. Probe (standalone `rustc -O`, i7-12700): 1k entries 0.56 µs/miss,
    10k 2.3 µs, 50k 53 µs (97 µs to the last entry) — linear, and the list is
    the association's whole history.
  - **028** `028-udp-association-pins-the-first-dns-answer.md` (medium, theory):
    `resolve_domain` (`:1601-1618`) caches one address for the association's
    life (no TTL; the engine's `ResolvedCache` uses 300 s, `engine.rs:467`),
    keeps `addrs.into_iter().next()` only (`:1609`) so a v6-first answer is
    dead forever on a host where `[::]:0` failed to bind (`:1250-1284`), and
    negative-caches nothing — each datagram to an unresolvable name spawns a
    task and a fresh `getaddrinfo` (`:1168-1180`).
- Checked and **not** filed: `read_greeting` is stack-buffered but
  `read_credentials` allocates two `Vec`s + two `String`s per connection
  (`socks5.rs:238-252`) — under 1 KiB, per connection, no amplification;
  the SOCKS5/HTTP auth compares are `!=` but the listener is local-only (025's
  precedent: no reachable oracle); the mixed inbound's shutdown select clones
  the watch receiver at accept time, so a later shutdown still fires
  (`mixed.rs:72-118`); `read_head`'s post-extend cap check can overshoot
  `MAX_HEAD_BYTES` by at most one `BufReader` buffer (`http.rs:459-505`) —
  bounded, no memory claim; the proxy queue's byte counter is returned on both
  `try_send` failure arms and dropped with an aborted leg (`:1345-1395`).
- Reviewer round 1 (`ReviewIter11`, 2m16s): **needs-fix**, 2 findings — both
  arithmetic/cross-reference, all citations verified against `/tmp/iter11`.
  Dispositions (all applied):
  1. 027's "25-50 % of a core" contradicted its own table (53 µs × 2,000/s
     = 11 %, the 97 µs last-entry column 19 %) and mis-sized the entry: a
     `CompactString` is 24 B, so 100k hosts is ≈2.4 MB of slots plus heap
     (≈5 MB worst case), not 7 MB. Sentence now states 11 %/19 % and the
     corrected memory figures; medium severity rests on unbounded growth, not
     on the percentage.
  2. The 027 → 016 bullet claimed a decision memo "shrinks the datagram count"
     the `seen` scan pays on. `note_conn` runs after the decision
     (`:1096-1106`), so the memo does not skip it; the two fixes are
     independent and only the cap bounds the scan. Fixed in 027, 016 and INDEX.
- Reviewer round 2 (`ReviewIter11b`, 3m23s): **needs-fix**, 1 finding — the
  inline limit is 24 bytes, not 23 (`compact_str` 0.10's `repr::MAX_SIZE` =
  `size_of::<String>()`, and the workspace convention note says ≤24 B); the
  three mentions in 027 corrected. Both round-1 findings verified applied, and
  the reviewer independently re-checked the arithmetic (10.6 %/19.4 %), the
  2.4 MB slot figure and every cross-reference against HEAD e752ea5f.
- Second round applied and closed; no third round (one P3 boundary).
- Post-commit correction (docs only): 028's resolver framing narrowed after a
  re-read of the crate's own dials — `server_socket`
  (`leas-native/src/context.rs:156-180`, the `lookup_host` choice is documented
  at :156-158) and `dial_direct` (`inbound/outbound.rs:139-145`) also resolve
  through `tokio::net::lookup_host` and also take the first address, so neither
  is an inbound deviation. 028 now states the invariant that *is* local: those
  dials re-resolve on the next attempt, the association's cache never does.
  No severity change; the lifetime claims are untouched.
