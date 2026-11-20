# 004 — A row's mux cap (`mux=N`, `muxConcurrency=N`, `mux=-1`) is parsed, stored, exported, and then ignored by the pool

- **Location:** `crates/leas-native/src/mux_pool.rs:52` (`policy.cap`),
  `crates/leas-native/src/mux_pool.rs:459` (`live() < policy.cap`),
  `crates/leas-native/src/context.rs:73-76` (`mux_explicit`), and
  `crates/leas/src/ops/native_connect.rs:184-192` (the only writer of `cap`)
- **Severity:** medium
- **Status:** theory
- **Domain:** mux-pool

## Hypothesis

The row's mux *magnitude* never reaches the pool. `mux=4`, `muxConcurrency=32`
and `mux=-1` all produce the same 8-streams-per-carrier behaviour, because the
row's cap is collapsed to a boolean before the dial and `MuxPolicy::cap` is
filled from the profile only.

## Evidence

- The cap exists and is preserved through parse and export:
  `VlessMux::Limited(u32)` / `Unlimited` / `Named { wire, cap }`
  (`crates/leas-proto/src/proto_spec/vless.rs:109-127`), parsed from
  `mux=`/`muxConcurrency=` (`vless.rs:488-535`) and written back
  (`VlessMux::as_value`, `identity_token` at `vless.rs:192,219`).
- At dial it becomes one bit. `NativeConnectParams::new` stores
  `mux_explicit: cfg.mux.as_ref().map(VlessMux::is_active)`
  (`crates/leas-native/src/context.rs:73-76`) — `Option<bool>`, so `Limited(4)`
  and `Unlimited` are indistinguishable from `Limited(8)`.
- `MuxPolicy::cap` (`mux_pool.rs:52`) is the only stream cap the pool reads
  (`choose`, `mux_pool.rs:459`), and its only writer is the profile:
  `crates/leas/src/ops/native_connect.rs:187-191` reads
  `MuxConfig::max_streams` / `concurrency`, defaulting to the policy's 8.
- So the shipped behaviour is: `mux=4` → 8 streams on one carrier;
  `mux=-1` (unlimited, an *active* request per `VlessMux::is_active`) → 8;
  `muxtype=h2mux&muxConcurrency=32` → 8.
- `AGENTS.md` states the opposite: "`VlessMux::Named` carries the wire, cap from
  `mux`/`muxConcurrency`". `MuxKey::of` does include the wire
  (`mux_pool.rs:223`) and excludes the cap, matching the code — the docs claim
  about the cap is what the code does not honour.

## Impact

Two directions, both silent:

- **Over-subscription.** A row that asks for 4 concurrent streams gets 8 on one
  carrier. Whatever the server's per-connection budget is, it is exceeded by
  the client's own declared limit, and the resulting stream errors surface as
  link failures (the retry path at `mux_pool.rs:317-330` marks the whole
  carrier dead on the first failure, so one over-cap rejection can churn a
  carrier that other sessions still use).
- **Under-use.** `mux=-1` means "no cap" to the row's author and "8" to the
  pool, so a row that could carry 64 streams dials 8 carriers instead.

The exported `muxConcurrency` value also promises behaviour the dial does not
provide, so a bug report against an export/import round-trip would be
unfalsifiable from the row alone.

## Fix sketch

- Carry the cap, not the bit: replace `mux_explicit: Option<bool>` with the
  resolved request (`Option<VlessMux>`, or `Option<MuxRequest { off: bool, cap:
  Option<usize> }>`), keeping `is_active` as the off/on decision.
- Add one predicate beside `effective_mux` —
  `effective_cap(params, policy) -> usize` — that returns the row's cap when it
  is above zero and below `Unlimited`, the policy cap otherwise, and clamps to
  `>= 1` (the profile path already clamps, `native_connect.rs:191`).
- Feed that into `choose` (`mux_pool.rs:459`) instead of `policy.cap`;
  `MuxPolicy::cap` stays the default for rows that say nothing.
- Leave `MuxKey` alone: the cap is policy, not carrier identity
  (`mux_pool.rs:170-184`), and there is a test pinning that
  (`key_ignores_remarks_and_cap_but_not_identity`).

## Related

- [006](006-mux-build-gate-is-pool-wide-and-drops-its-fallback-carrier.md) — the
  cap decides how many carriers are dialled; the build gate decides how many
  dials coalesce. Both are read at the same `choose`.
