# Issues Review — Loop State

```yaml
loop:
  iteration: 2
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
    status: unexplored
    issues: []
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
