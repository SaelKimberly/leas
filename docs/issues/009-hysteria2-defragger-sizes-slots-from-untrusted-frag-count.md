# 009 — hysteria2's defragmenter sizes its slot vector from a peer-controlled `frag_count`

- **Location:** `crates/leas-native/src/protocol/hysteria2/udp.rs:158-200`
  (`Defragger::feed`), the allocation at `:168`, and the parse that feeds it
  at `:226`
- **Severity:** low
- **Status:** theory
- **Domain:** native-protocol

## Hypothesis

`UDPMessage.frag_count` is a `u8` straight off the wire (`udp.rs:114`, no
validation beyond the address-length and payload-length guards at `:118-123`).
When a fragment arrives with a new `packet_id`, the defragger allocates one
slot per claimed fragment *before* any of them arrive:

```rust
self.frags = (0..m.frag_count as usize).map(|_| None).collect();
```

`Option<UdpMessage>` is ~56 bytes (`u32`, `u16`, two `u8`, a `String`, a `Vec`),
so a single attacker-chosen byte turns an ~11-byte datagram into a ~14 KiB
allocation. Rotating `packet_id` — the field that resets the array — re-arms it
on every datagram. The array is also rebuilt rather than reused when only
`frag_count` changed.

Separately, `accept_datagram` parses the whole message (allocating the `addr`
`String` and the payload `Vec`) before the session filter drops it at `:227`,
so a co-tenant session's datagrams on the same connection still pay for a full
parse.

## Evidence

- `udp.rs:110-131` — `frag_count` is read from `buf[7]` (`:114`) and stored
  unvalidated; only `addr_len` is bounded (`:121`, `addr_len > MAX_MESSAGE_LEN`
  where `MAX_MESSAGE_LEN = 2048`, `:43`).
- `udp.rs:158-168` — the new-message branch allocates
  `(0..m.frag_count as usize)` slots. `frag_count` is `u8`, so the ceiling is
  255 slots.
- `udp.rs:165` — the gate is
  `m.packet_id != self.pkt_id || m.frag_count as usize != self.frags.len()`, so
  changing `packet_id` alone re-enters the allocating branch.
- `udp.rs:221-229` — `accept_datagram` runs `UdpMessage::parse(bytes)?` before
  the `msg.session_id != session_id` test, so the parse (and both of its
  allocations, `:124-125`) happens for datagrams that are then dropped.
- The sibling bounds this one ignores. The client's own sender derives the
  count from the payload and the QUIC datagram budget —
  `frag_count = msg.data.len().div_ceil(budget - header)` (`:521`), budget from
  `conn.max_datagram_size()` (`:338`, defaulting to
  `DEFAULT_DATAGRAM_BUDGET = 1200`, `:50`) — and refuses a payload above
  `MAX_UDP_SIZE = 4096` (`:310-317`, `:47`). A conforming peer therefore sends
  at most ~4 fragments for the largest legal datagram; 255 is not a value any
  sender on this wire produces.
- Not a leak: the state is bounded (one array, at most the last message's
  fragments) and a new `packet_id` discards it. The cost is allocation churn
  and retained bytes an untrusted peer controls.

## Impact

A peer that keeps sending a single unfilled fragment with a fresh `packet_id`
forces ~14 KiB of allocation per inbound datagram — an allocation-amplifier of
roughly three orders of magnitude on a connection the client dials itself.
On a hostile or misconfigured server the client's allocator sees the churn; the
`leas` process installs mimalloc and runs `release_freed_heap()` only at job
boundaries, so it is retained rather than returned promptly.

## Fix sketch

1. Bound the slot count to what a conforming sender can emit: at most
   `MAX_UDP_SIZE.div_ceil(budget - header)` fragments, i.e. ~4 at the 1200-byte
   default budget. Reject a larger `frag_count` as malformed (the same `None`
   every other bad message gets) — check the pinned upstream hysteria for its
   own cap before fixing the constant, so the client does not refuse a real
   peer with a smaller negotiated datagram size.
2. Reuse the slot array: `self.frags.clear(); self.frags.resize(n, None);`
   keeps the allocation across `packet_id` changes, so the steady state stops
   allocating even for legitimate fragmentation.
3. Move the session filter ahead of the parse: check `session_id` on the raw
   bytes (`buf[0..4]`) in `accept_datagram` and skip `UdpMessage::parse` for a
   foreign session.

Test that pins it: feed `feed()` a fragment with `frag_count = 255` and assert
it is refused (or that the array is reused — `frags.capacity()` unchanged
across two `packet_id`s). Both are cheap, deterministic, and fail on the
current code.

## Related

- [007](007-datagram-recv-copies-what-bytes-already-owns.md) — same receive
  function: that issue is the fast-path copy, this one is what a peer can make
  the defragmenter allocate.
- [003](003-udp-association-eager-buffers.md) — the inbound side of the same
  question: memory a UDP association holds before any datagram arrives.
- [001](001-inbound-accept-layer-has-no-admission-control.md) — no admission cap
  on the accept layer means the per-datagram cost here has no outer bound on
  how many peers can run it at once.
