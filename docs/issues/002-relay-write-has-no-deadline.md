# 002 — The relay's write has no deadline: a stalled reader pins the tunnel forever

- **Location:** `crates/leas-native/src/inbound/outbound.rs:359-402` (`copy_half`)
- **Severity:** medium
- **Status:** theory
- **Domain:** native-inbound

## Hypothesis

`RELAY_IDLE` (`crates/leas-native/src/error.rs:253`, 60 s) wraps only the read
half of each direction. The matching `write_all` sits outside every timer, so a
peer that stops reading keeps its direction blocked indefinitely — and the
shared idle stamp (`Idle::touch`, `outbound.rs:317`) is slid forward by the
*other* direction as long as it keeps moving bytes. The result is a tunnel that
is alive by the idle rule, half dead in practice, holding both sockets, both
relay buffers and a proxy sub-stream, with no timeout to end it.

## Evidence

```rust
// outbound.rs:369-402
let sleep = tokio::time::sleep_until(idle.deadline());
tokio::pin!(sleep);
loop {
    let deadline = idle.deadline();
    sleep.as_mut().reset(deadline);
    let n = tokio::select! {
        res = r.read(buf.as_mut_slice()) => res?,          // cancel-safe: only the read is timed
        () = sleep.as_mut() => { ... return Err(TimedOut) }
    };
    if n == 0 { break; }
    idle.touch();                                          // outbound.rs:395
    w.write_all(&buf.as_mut_slice()[..n]).await?;           // outbound.rs:397 — no timer, no select
    buf.filled(n);
}
```

- `Idle::deadline()` (`outbound.rs:323`) is `last activity + RELAY_IDLE`, and
  `touch()` is called by BOTH directions. So while one direction blocks in
  `write_all`, the opposite direction's reads keep pushing the deadline out.
- `try_join!` (`outbound.rs:347`) only tears the other direction down when a
  direction *returns* `Err`. A direction blocked in `write_all` never returns,
  so nothing fires.
- The read half of the stalled direction is also not polled while it is inside
  `write_all`, so that direction's own timer is not armed at all during the
  stall.
- The shape is already exercised — and only asserted for byte integrity, not
  for termination: `relay_does_not_lose_bytes_under_write_backpressure`
  (`outbound.rs:786-847`) deliberately blocks the forward `write_all` on a slow
  reader while reverse traffic "keeps completing". That is exactly the state in
  which the timer cannot fire.
- Reachable in normal use: a client that stops reading (paused download, full
  receive buffer, an app that abandoned the socket without closing) while its
  uplink continues (uploads, heartbeats, request pipelining). The direction to
  the client is blocked, the direction to the proxy is live, so the tunnel
  never reaps.

## Why it matters

The idle cap is the only reaper for a client-side half-close-less hang. Today a
"dead but busy one way" tunnel is indistinguishable from a healthy download
from the relay's point of view, and it keeps a mux carrier slot alive — the
scarcest resource on the proxy side (`crates/leas-native/src/mux_pool.rs`, live
slots reserved per entry).

## Fix sketch (the trap to avoid)

`timeout(RELAY_IDLE, w.write_all(..))` is WRONG: `write_all` is not
cancel-safe, so the timeout drops it after a partial write and the next chunk
would resume at the wrong offset — losing or duplicating bytes, which is the
exact invariant the comment at `outbound.rs:396` protects ("bytes that were
read are always written").

Correct shape: track a write offset and select on a single `poll_write`
(`AsyncWriteExt::write`, cancel-safe because it reports what it wrote):

```rust
let mut off = 0;
while off < n {
    // Re-arm from the shared stamp on every iteration, exactly like the read
    // arm (`outbound.rs:373-384`): a live reverse direction must be able to
    // slide this deadline, or a window-limited download dies mid-transfer.
    let deadline = idle.deadline();
    sleep.as_mut().reset(deadline);
    tokio::select! {
        res = w.write(&buf.as_mut_slice()[off..n]) => { let k = res?; if k == 0 { return Err(WriteZero); } off += k; idle.touch(); }
        () = sleep.as_mut() => {
            if idle.deadline() > deadline { continue; }   // peer direction moved bytes
            return Err(TimedOut);
        }
    }
}
```

The `sleep` is the same shared future, so a live reverse direction still slides
the deadline; only a direction that makes no write progress for the whole idle
window dies. A progress-based `touch()` per successful `write` also covers the
case the current `touch()`-before-write misses: a write that takes longer than
`RELAY_IDLE` is currently invisible.

## Not verified

No reproducer was run: the stall needs either the real 60 s window or a paused
clock over real sockets. The claim rests on code structure above (the write is
outside every timer, and `touch` is shared) plus the existing backpressure
test's scenario.

## Related

- [001](001-inbound-accept-layer-has-no-admission-control.md) — nothing caps how
  many such stuck tunnels can exist.
- [003](003-udp-association-eager-buffers.md) — the UDP relay has the same
  "no deadline around the send" question for `send_to`, bounded there only by
  the socket's own behaviour.
