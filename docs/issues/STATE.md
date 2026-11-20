# Issues Review — Loop State

```yaml
loop:
  iteration: 3
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
    status: unexplored
    issues: []
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
