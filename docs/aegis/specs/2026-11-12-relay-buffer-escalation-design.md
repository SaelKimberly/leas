# Relay buffer escalation — Design Spec Brief

Date: 2026-11-12
Status: **implemented 2026-11-12** — plan `plans/2026-11-12-relay-buffer-escalation.md`.
Origin: `thirdparty/ZeroNet` @ `29e7a95` audit, `docs/research/2026-11-12-zeronet-zray-analysis.md` §7.
Owner gap: no spec owns `copy_half`'s buffer size. `2026-11-10-memory-reduction-design.md`
owns the allocator and the idle floor, not the per-direction relay buffer.

---

## 1. Why this exists

Before this plan, every proxied TCP tunnel was a pair of `copy_half` futures, each
with a fixed 16 KiB buffer allocated once per direction (`RELAY_BUF`, one `vec!` per
call). 16 KiB is right for interactive traffic and wrong for bulk: at 64 KiB per chunk
a gigabit flow is a few thousand read/write rounds a second instead of tens of
thousands. ZeroNet reached 64 KiB the same way and rejected 128 KiB with
measurements: no throughput gain, and every busy connection cost 256 KiB
(`zero-runtime/src/relay.rs:20-33`).

The escalation rule matters more than the size: **a direction is promoted only
after it has proven it is bulk** by filling the small buffer completely. An idle or
interactive tunnel keeps costing 32 KiB total; a download moves to 64 KiB chunks
after its first full read.

## 2. Scope

`crates/leas-native/src/inbound/outbound.rs` only: `copy_half` gains a promotion
step, `RELAY_BUF` becomes `SMALL`/`LARGE`.

**Out of scope**, each with its reason:

- **A buffer pool.** ZeroNet pools two sizes (256 × 16 KiB + 32 × 64 KiB). leas
  allocates one `vec!` per direction per tunnel; with mimalloc that is two fast-path
  allocations and two frees per connection. A pool only pays if the allocation
  shows up in a profile — measure before adding the `Mutex<Vec<Box<[u8]>>>` and its
  poisoning surface. Decision D2.
- **Removing `tokio::io::split` on the upstream.** It locks an `Arc<Mutex<..>>` per
  poll of the proxy-direction write `outbound.rs:209-211`. ZeroNet wrote a custom
  `CopyBidirectional` to avoid exactly this (`relay.rs:402-410`), but leas' upstream
  is a `BoxStream` with no owned split, so this needs a trait change. Separate
  spec; do not bundle.
- **UDP.** `run_udp_relay` uses its own 64 KiB buffers (`inbound/mod.rs:649-651`);
  datagram sizes are bounded by MTU and this brief does not touch them.

## 3. The shape

```rust
const RELAY_SMALL: usize = 16 * 1024;
const RELAY_LARGE: usize = 64 * 1024;
```

In `copy_half`:

1. start with `vec![0u8; RELAY_SMALL]`;
2. after a read returns `n == RELAY_SMALL` (the buffer filled), replace it with
   `vec![0u8; RELAY_LARGE]` and read into that from then on;
3. never demote — a direction that once filled a small buffer is a bulk direction
   for the rest of the connection;
4. no change to the idle stamping, the `select!` shape, the `shutdown` on EOF, or
   the "bytes read are always written" rule (`outbound.rs:230-267`).

One read that exactly fills the buffer is not proof by itself, but the cost of a
false promotion is one 64 KiB allocation on a connection that was probably bulk
anyway. The alternative (two consecutive full reads) adds state for no measured
benefit; if the A/B shows churn, tighten it later.

## 4. Compatibility boundary

- No schema, config, or wire change. No `SCHEMA_VERSION` bump.
- Peak memory per bulk tunnel goes 32 KiB → 128 KiB (two directions), idle stays
  32 KiB. This is the trade ZeroNet measured as a net win; it is the opposite
  direction from `2026-11-10-memory-reduction-design.md`, which lowered the *idle*
  floor and the batch peak. That spec's numbers are unaffected: they are ping-batch
  memory, not relay buffers.
- No allocator interaction: the new buffer goes through mimalloc like the old one.

## 5. Verification

1. A unit test with a `tokio::io::duplex` pair that reads a 64 KiB burst in one go
   and asserts the large buffer is used (observable via a counter or a `cfg(test)`
   accessor), plus a 100-byte burst that never promotes.
2. `leas-oracles` `relay`/`throughput` benches before/after on a real core, single
   stream and 8 streams, recorded in the plan. The gate is the direction's MB/s at
   one stream, since that is where 64 KiB is expected to move the number.
3. Workspace gate: `cargo clippy --workspace --exclude leas-oracles --all-targets
   --all-features -- -D warnings` and `cargo nextest run`.

## 6. Decisions (settled at implementation)

- **D1 — promotion trigger.** One full small read, applied **after** the write that
  consumed it: promoting between read and write would replace the buffer and discard
  the bytes just read.
- **D2 — pool.** None. ZeroNet's pool saves two allocator calls per tunnel; nothing
  measured that. The gate in `2026-11-12-allocation-count-gate-design.md` names the
  relay as a future row if it ever shows up.
- **D3 — 64 KiB.** 128 KiB is refused on ZeroNet's measurement (no throughput,
  double the per-busy-connection cost), and our links are not faster than theirs.
