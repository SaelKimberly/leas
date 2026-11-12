# Relay buffer escalation — implementation plan

Date: 2026-11-12
Spec: `specs/2026-11-12-relay-buffer-escalation-design.md` (draft, D1–D3 open)
Domain: **inbound relay** — `crates/leas-native/src/inbound/outbound.rs`
Execution route: **inline** (one file, one task set).
`User confirmation required: no`.

Aegis Visibility: the change alters per-connection memory and bulk throughput of the
only relay leas has; the plan pins the promotion rule and the memory ceiling so a later
"make it bigger" edit is a reviewed decision, not a drive-by.

## 1. Goal

A relay direction starts at 16 KiB and promotes to 64 KiB after it proves it is bulk
by filling the small buffer completely. Idle and interactive tunnels keep 32 KiB total.

Acceptance: the promotion is a unit-testable state transition; the workspace gate is
clean; `just hotpath` is unaffected; a manual A/B on `leas-oracles`' relay bench is
recorded in the plan's execution note.

## 2. Architecture / tech stack

`copy_half` currently allocates `vec![0u8; RELAY_BUF]` per direction
(`crates/leas-native/src/inbound/outbound.rs:235`). The change swaps that for a small
`RelayBuf` type owning the buffer and its promotion state, so the rule is one place
and one test. No new dependency, no new module unless the type earns one.

## 3. Baseline and authority refs

- `RELAY_BUF = 16 * 1024` (`outbound.rs:168`); one buffer per direction, allocated once
  per `copy_half` call (`:235`); the loop's idle stamping and "bytes read are always
  written" contract (`:241-266`) must not change.
- ZeroNet's measured numbers behind 64 KiB and against 128 KiB:
  `thirdparty/ZeroNet/crates/zero-runtime/src/relay.rs:18-33,290-304`.
- Spec non-goals: pool, upstream `split` removal, UDP buffers.

## 4. Compatibility boundary

No public API, config, schema, or wire change. Peak per bulk tunnel: 32 KiB → 128 KiB
(two directions); idle unchanged at 32 KiB. That is the opposite direction from
`2026-11-10-memory-reduction-design.md`'s idle-floor work and does not touch it: those
numbers are ping-batch memory.

## 5. Change Necessity

A single constant bump to 64 KiB would make every interactive tunnel pay 128 KiB —
exactly what the memory spec spent effort removing. The escalation rule is the change;
docs or config cannot express it.

## 6. TDD Route

Mode `auto`, decision **light**: one struct with a state transition and no behavior
visible outside the relay. Authority: the project's default auto decision. The test
asserts the transition (small buffer grows on a full read, not otherwise), which is
neither a tautology nor wiring.

## 7. Tasks

### R1 — `RelayBuf` and the promotion rule

File: `crates/leas-native/src/inbound/outbound.rs`.

```rust
struct RelayBuf { buf: Vec<u8> }
impl RelayBuf {
    fn new() -> Self;                  // RELAY_SMALL
    fn filled(&mut self, read: usize); // promote when read == buf.len()
    fn as_mut_slice(&mut self) -> &mut [u8];
}
```

Constants: `RELAY_SMALL = 16 * 1024`, `RELAY_LARGE = 64 * 1024` (replacing `RELAY_BUF`).
`copy_half` reads into `buf.as_mut_slice()` and calls `filled(n)` after each non-zero
read. No demotion, no pool.

Test (in the module's `#[cfg(test)]`): `RelayBuf::new().as_mut_slice().len() ==
RELAY_SMALL`; `filled(RELAY_SMALL)` → `RELAY_LARGE`; `filled(100)` from new →
`RELAY_SMALL`; a promoted buffer stays large after a short read.

### R2 — verification and record

`cargo nextest run -p leas-native inbound` (relay tests), the workspace gate, and
`just hotpath` (the relay is not a gate row, but the crate must stay green). Manual
A/B note: the `leas-oracles` `relay` bench, single stream, is the number to compare;
it needs cores, so it is recorded as a manual step, not a CI gate.

## 8. Risks

- A false promotion costs one 64 KiB allocation on an interactive tunnel. Bounded and
  one-way; the regression test pins the trigger so it cannot become "always large".
- No demotion: a tunnel that goes quiet after a bulk phase keeps 64 KiB until it
  closes. Same as ZeroNet; the idle timeout (300 s) bounds the residency.

## 9. Retirement

`RELAY_BUF` is deleted, not kept as an alias. No pool is added, so nothing else retires.

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
