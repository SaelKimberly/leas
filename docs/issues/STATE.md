# Issues Review — Loop State

```yaml
loop:
  iteration: 1
  status: running
  noop_streak: 0
coverage:
  - domain: native-inbound
    status: in-progress
    last_touched_iteration: 1
    issues: [001, 002, 003]
  - domain: mux-pool
    status: unexplored
    issues: []
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
