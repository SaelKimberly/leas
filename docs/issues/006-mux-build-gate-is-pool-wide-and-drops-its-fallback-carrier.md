# 006 — The build gate is pool-wide, and the carrier it builds after its 1 s deadline is thrown away unregistered

- **Location:** `crates/leas-native/src/mux_pool.rs:276-279` (`build_gate`),
  `crates/leas-native/src/mux_pool.rs:365-410` (`acquire`, the gate + fallback),
  and `crates/leas-native/src/mux_pool.rs:512-518` (`register`)
- **Severity:** medium
- **Status:** theory
- **Domain:** mux-pool

## Hypothesis

The cold-burst coalescer gives up after one second and then builds a carrier it
never registers, so a burst whose first carrier takes longer than 1 s to build
produces exactly the N-handshakes-for-N-CONNECTs it exists to prevent — while
the gate itself is one mutex for the whole pool, so it also serialises builds
for unrelated keys.

## Evidence

```rust
// mux_pool.rs:377-388
let Ok(_gate) = tokio::time::timeout(
    std::time::Duration::from_secs(1),
    self.inner.build_gate.lock(),
).await else {
    let tunnel = build_tunnel(params, policy).await?;
    let carrier = Arc::new(Carrier::new(tunnel));
    carrier.live.fetch_add(1, Ordering::AcqRel);
    carrier.touch();
    return Ok(carrier);          // NOTE: no self.register(&key, …)
};
```

- There are four `build_tunnel` call sites and only one skips `register` by
  accident: `fresh_carrier` registers (`:348`), the `Choice::Build` arm
  registers (`:394`), the `Choice::Spill` arm deliberately does not (`:400`,
  a spill is unpooled by definition), and the timeout fallback (`:383`) does
  not either — so its carrier is reachable only by its own session, no later
  dial can find it, and `sweep` never sees it.
- The deadline is 1 s while the build it waits on has a 15 s budget
  (`crate::error::timeouts::CONNECT`, `crates/leas-native/src/error.rs:259`;
  applied at `mux_pool.rs:603`). Any cold build between 1 s and 15 s — a
  REALITY/sbox handshake on a high-RTT path, or a tarpitted dial — makes every
  concurrent waiter take the fallback arm, and then the winner registers one
  carrier with `cap` free slots that the waiters never look at again.
- The gate is `build_gate: tokio::sync::Mutex<()>` inside `PoolInner`
  (`mux_pool.rs:278`) — one lock for every `MuxKey`. `Choice::Spill` also enters
  the same arm (`:365`): a spill, which by definition builds OUTSIDE the pool,
  still queues behind another key's build for up to 1 s.
- A pool can hold more than one key at a time: `resolved_ip` is part of the key
  (`mux_pool.rs:219`), so a DNS re-resolution mid-burst gives the new key's
  dials a wait behind the old key's build, and then a fallback carrier they
  cannot share.

## Impact

For a 12-connection burst (the comment's own example, `mux_pool.rs:368`) on a
link whose handshake takes 1.2 s:

| Outcome | Carriers dialled | Carriers reusable |
|---|---|---|
| Gate holds (fast build, < 1 s) | 1 | 1 (8 more stream slots) |
| Gate times out (slow build, > 1 s) | 12 | 1 |

The burst still pays 12 handshakes — the pre-pool cost — and 11 of them are
permanently useless: their sessions run on carriers no later dial can ever
reach, and each is closed when its session ends. Nothing logs the fallback, so
the only signal is extra dials per burst on a slow path.

For `Choice::Spill` the 1 s wait buys nothing at all: the spill build is
unpooled by definition, so the gate delays it without coalescing anything.

## Fix sketch

Two independent one-liners, in order of value:

1. **Register the fallback**: call `self.register(&key, &carrier, policy)` before
   returning; `register` already refuses to exceed `policy.carriers`
   (`mux_pool.rs:514`), so the burst converges on the same steady state as the
   gate path and the extra carriers become the intended `Spill`, not garbage.
   Registering after the fact cannot break the cap: the map insert is the same
   lock the `choose` reservation uses.
2. **Do not gate a spill**: split the `Choice::Spill` arm out of the
   `Choice::Build | Choice::Spill` match at `mux_pool.rs:365` and build directly.
   A spill is never shared, so there is nothing to coalesce.

If the coalescing is to be exact rather than best-effort, the deeper fix is a
per-key in-flight build (`Mutex<HashMap<MuxKey, watch::Receiver<…>>>`): waiters
await the one build and re-`choose`, and the 1 s deadline disappears. Do not do
this before (1) — one registered fallback already removes the waste that the
deadline creates.

## Related

- [004](004-row-mux-cap-never-reaches-the-pool.md) — how many carriers the burst
  ends up wanting; the gate decides how many dials it actually pays.
- [001](001-inbound-accept-layer-has-no-admission-control.md) — without an
  admission cap, a burst is unbounded, which is what makes a 1 s gate deadline
  a recurring rather than one-off loss.
