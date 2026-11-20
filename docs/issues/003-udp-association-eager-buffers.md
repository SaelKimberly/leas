# 003 — A UDP association allocates 192 KiB before its first datagram and outlives its connection

- **Location:** `crates/leas-native/src/inbound/mod.rs:664-666` (buffers),
  `crates/leas-native/src/inbound/mod.rs:593` (`run_udp_associate`) and
  `crates/leas-native/src/inbound/mod.rs:634` (`run_udp_relay`)
- **Severity:** low
- **Status:** theory
- **Domain:** native-inbound

## Hypothesis

Each SOCKS5 UDP ASSOCIATE eagerly allocates three 64 KiB heap buffers, spawns a
detached task that outlives the connection handler, and only the
never-pinned case is time-bounded (60 s). A client that opens associations and
then uses one datagram each keeps 192 KiB + two sockets per association for the
life of the association, with no cap on how many exist (see 001).

## Evidence

```rust
// inbound/mod.rs:664-666, before the select loop, unconditionally
let mut client_buf = vec![0u8; 64 * 1024];
let mut out4_buf  = vec![0u8; 64 * 1024];
let mut out6_buf  = vec![0u8; 64 * 1024];
```

- `out4_buf`/`out6_buf` are read only from the arms guarded by
  `relay.out_v4.is_some()` / `relay.out_v6.is_some()`
  (`inbound/mod.rs:713-724`), and those sockets are created lazily on the first
  *direct* datagram (`ensure_direct_sockets`, `inbound/mod.rs:1250`). A
  proxy-only or DNS-only association pays 128 KiB for buffers no arm can use.
- The association task is spawned by `run_udp_associate`
  (`inbound/mod.rs:613`) and is **not** owned by the connection task's shutdown
  `select!` — it re-arms its own `shutdown_signal`
  (`inbound/mod.rs:676`). `UDP_PIN_DEADLINE` (`inbound/mod.rs:573`, 60 s) stops
  the clock only while `relay.source.is_none()`; one datagram disables it, and
  from then on the controlling TCP connection and the session shutdown signal
  (`inbound/mod.rs:676-679`) are the only lifetime authorities.
- The TCP relay already owns a `BufferPool` for exactly these two sizes
  (`outbound.rs:207-291`: `RELAY_SMALL` 16 KiB, `RELAY_LARGE` 64 KiB,
  `take`/`put` at `outbound.rs:223`/`235`). It is private to `inbound::outbound`
  and, being a cache, retains at most `POOL_CAP` 64 buffers per class — a miss
  still allocates (`outbound.rs:229`), so it bounds retained buffers, not
  concurrent ones. The UDP path ignores it entirely.
- `reply_buf` (`inbound/mod.rs:999-1007`) shows the awareness of high-water
  pinning: it shrinks once it exceeds 16 KiB. The three fixed buffers are the
  same concern, unfixed.

## Impact

100 idle-but-pinned associations = 18.75 MiB of zeroed heap that traffic never
touches, on a client whose steady-state budget is measured in tens of MiB
(see the memory-reduction work). The two bound sockets cost the association for
its whole life regardless; the buffers are pure waste until a family is used.

## Fix sketch

- Store the upstream buffers as `Option<Vec<u8>>` and fill them in the same
  place `ensure_direct_sockets` binds each socket — allocation follows the
  socket, and a proxy-only association pays nothing.
- Take the 64 KiB client buffer from the existing `BufferPool::take`/`put`
  (`RELAY_LARGE`; only its visibility needs widening — the methods already
  accept 64 KiB) and return it on association end, so a closed association
  costs nothing retained.
- Keep the 64 KiB datagram ceiling; the buffer size is correct, only its
  eagerness is not.

## Related

- [001](001-inbound-accept-layer-has-no-admission-control.md) — the missing
  admission cap is what turns a per-association constant into an unbounded
  total.
- [002](002-relay-write-has-no-deadline.md) — same validate-the-lifetime
  question, on the TCP side.
