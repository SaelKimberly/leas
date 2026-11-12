# First-flight coalescing — implementation plan

Date: 2026-11-12
Spec: `specs/2026-11-12-first-flight-coalescing-design.md` (draft, D1–D3 open)
Domain: **protocol / transport first bytes** — `crates/leas-native/src/protocol/`
Execution route: **inline** (one new module, five call sites, one new test file's worth
of cases).
`User confirmation required: no`.

Aegis Visibility: this changes what every VLESS, Trojan and VMess connect puts on the
wire before the application speaks, and it changes a rule about when a header may be
held back. The plan pins the ordering contract, the server-first escape and the deadlock
boundary; none of those is safe to improvise.

## 1. Goal

The protocol request header leaves in the same carrier write as the first payload
instead of its own write. Vision additionally coalesces header + camouflage frame +
first padded frame into one write.

Acceptance: the wrapper's tests prove order, exactly-once, the server-first release and
the close-without-write case; every protocol connect is covered; the e2e rows against
real cores still pass.

## 2. Architecture / tech stack

New `protocol/first_flight.rs` (`pub(crate) mod`), holding
`HeaderFirst<S: AsyncRead + AsyncWrite + Unpin>`:

```rust
struct HeaderFirst<S> {
    inner: S,
    pending: Vec<u8>,        // header, later header + first payload bytes
    pending_pos: usize,
    released: bool,          // a first payload has been accepted
    wait: Option<Pin<Box<Sleep>>>, // armed by the first read
}
```

Rules:

1. `poll_write`, before release: copy up to `FIRST_PAYLOAD_MAX` (16 KiB) of the caller's
   buffer into `pending`, mark released, then flush `pending` as far as the inner writer
   takes it, and return the number of caller bytes copied. Copied bytes are ours; the
   caller may forget them.
2. `poll_write` after release: flush any remaining `pending` first; once empty, write
   the caller's buffer straight through.
3. `poll_read`: the first read flushes `pending` (returning `Pending` if the carrier
   does not take it, with the inner write's waker registered) before it may hand up
   read data. That is the server-first escape — no timer, no extra future.
4. `poll_flush` flushes `pending` first. `poll_shutdown` flushes `pending`, then shuts
   the inner writer down, so a connect that never writes still sends its header. A
   stream dropped without `shutdown` loses a buffered header; no caller does that.
5. Once `pending` is empty it is cleared and its capacity released; nothing else is
   retained.

## 3. Baseline and authority refs

Header-as-its-own-write sites: VLESS plain `protocol/vless/mod.rs:126`, vision header
`:191` + camouflage `:204`, UDP `:317`, mlkem `:105`; Trojan `protocol/trojan/mod.rs:92`;
VMess `protocol/vmess/mod.rs:88,104`. ZeroNet's wrapper and its 100 ms rule:
`thirdparty/ZeroNet/crates/zero-protocol/src/first_flight.rs:1-40`.

Ordering constraints that must not change: `VlessClientStream::with_ack_slot` peels the
response header on the READ side and must sit above the wrapper; `VisionStream` frames
the WRITE side and must sit above it too (`protocol/vless/mod.rs:219-221`).

## 4. Compatibility boundary

- Same bytes, same order, fewer writes. A carrier reader cannot tell.
- `connect` may now return before anything is sent. Two consequences are accepted and
  stated: the per-write 10 s `timeouts::PROTOCOL` guard no longer applies at connect
  (the relay's 30 s idle bound is the new outer bound), and a tunnel closed before its
  first write sends its header during shutdown.
- UDP connect paths are **out of scope**: their first write is a datagram frame with a
  different lifetime, and coalescing there buys one packet on a path that is not the
  fingerprint surface this plan targets.
- No public API: the wrapper and module are `pub(crate)`.

## 5. Change Necessity

The header and the first payload are written by two different layers; no configuration
can merge them. Without the wrapper the option is per-protocol duplication of timer and
partial-write logic, which is how the four copies drift.

## 6. TDD Route

Mode `auto`, decision **strict** for the wrapper: its contracts (order, exactly-once,
timer release, no lost bytes under partial writes) are exactly what a bug would violate
silently. RED fires as compile failure for the first test, then each contract test is
written before its branch. Wiring at the five sites is **light** (byte-identical output).

## 7. Tasks

### F1 — wrapper and tests

Files: `crates/leas-native/src/protocol/first_flight.rs` (new),
`crates/leas-native/src/protocol/mod.rs` (`pub(crate) mod first_flight;`).

Tests (duplex carrier):
1. header + first payload arrive as ONE write (the peer sees
   `header || payload` and a single `write` call is observable through a recording
   wrapper);
2. a second write does not repeat the header;
3. the read-first case flushes the header on the read, before the greeting is handed up;
4. `shutdown` without any write emits the header, and a carrier that returns `Pending`
   on the first write does not shrink the reported count;
5. a partial inner write still delivers the whole header, in order, with no caller byte
   lost (write a header larger than the inner buffer slack).

`FIRST_PAYLOAD_MAX = 16 * 1024`; bytes past it stay with the caller (rule 1).

### F2 — VLESS wiring

File: `crates/leas-native/src/protocol/vless/mod.rs`.

- `connect_plain`: replace the header `write_all` + returned stream with
  `VlessClientStream::with_ack_slot(Box::new(HeaderFirst::new(stream, request)), ack)`.
- `connect_vision_over`: build one `preamble = header || camouflage_frame` and use
  `HeaderFirst` under the peel; delete both `write_all`s.
- `connect_encrypted` (mlkem): same as plain.
- UDP paths unchanged.

### F3 — Trojan and VMess wiring

Files: `crates/leas-native/src/protocol/trojan/mod.rs`,
`crates/leas-native/src/protocol/vmess/mod.rs`.

- Trojan `connect`: return `HeaderFirst::new(stream, request)`; delete the write.
- VMess: both the legacy and AEAD arms wrap before constructing the client stream;
  delete both writes.
- While there: `encode_request`/`encode_request_legacy` currently call
  `encode_addr_port_last`/`encode_addr`, each allocating a second `Vec` per connect.
  Both already have an `write_addr*` sibling; point them at it (same defect the
  allocation gate found in VLESS, `specs/2026-11-12-allocation-count-gate-design.md` §4a).

### F4 — verification

`cargo nextest run -p leas-native first_flight`, `... protocol::vless`, `...
protocol::trojan`, `... protocol::vmess`; then the workspace gate and `just hotpath`.
Real-core proof: `cargo nextest run -p leas-oracles` (skipped without cores; recorded).

## 8. Risks

- **Deadlock if the read flush is wrong.** The escape is tested: a peer that never
  writes and an app that only reads must still get the header, and the reverse (app
  writes first) must never wait.
- **Either ordering mistake leaks a byte or repeats the header.** The exactly-once and
  partial-write tests are the guard; both are byte-level, not behavioural.
- **`connect` returning early** can surprise a caller that measured "bytes sent at
  connect". No production caller does; the plan records it because a test might.

## 9. Retirement

Five standalone header writes are deleted, not kept behind a flag. `HeaderFirst` is the
only owner of "header waits for payload".

## Execution note (2026-11-12)

Executed inline. Reviewer findings applied before the commit:

- **Relay:** promotion moved after the write that consumed the read (promoting earlier
  would swap the buffer and discard bytes), and the buffer is now owned by `relay()`
  and passed into `copy_half`, so a test observes promotion through the real loop
  (`copy_half_promotes_on_a_bulk_read_and_not_on_a_short_one`) instead of only through
  `RelayBuf` directly. The ceiling test asserts the pointer does not move, because a
  fresh 64 KiB `Vec` per chunk would keep `capacity()` identical.
- **Path MTU:** the MSS is applied to an **unconnected** `TcpSocket` before `connect`
  (previously applied post-connect, where the kernel ignores it for MSS advertisement);
  the stall evidence is gated on `ctx.is_tls() && !is_quic_link(ctx)`, because a
  plaintext row runs no handshake and a QUIC link has no TCP socket.
- **First flight:** the read path flushes the header instead of arming a 100 ms timer
  (the timer was unobservable and its only effect was a buffered write turning into
  `Pending`); a `Pending` inner write has its own test; the e2e PQ assertion in
  `leas-oracles` peels the new wrapper, and that is why `first_flight` is `pub` with an
  `e2e-support`-only `inner()`.
