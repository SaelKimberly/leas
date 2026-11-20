# Issues Review — Loop State

```yaml
loop:
  iteration: 4
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
    status: unexplored
    issues: []
  - domain: routing-engine
    status: unexplored
    issues: []
  - domain: db-layer
    status: unexplored
    issues: []
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
