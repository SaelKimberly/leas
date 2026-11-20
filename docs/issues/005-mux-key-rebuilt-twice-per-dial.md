# 005 — Every dial builds the carrier key twice, by `Debug`-formatting the protocol config, then clones it into the map

- **Location:** `crates/leas-native/src/mux_pool.rs:186-232` (`MuxKey::of`),
  `crates/leas-native/src/mux_pool.rs:309` + `:362` (double build per
  `open_session`), `:429` + `:362` (same for `open_udp`), and
  `crates/leas-native/src/mux_pool.rs:456`, `:514` (`entry(key.clone())`)
- **Severity:** low
- **Status:** theory
- **Domain:** mux-pool

## Hypothesis

A warm pool hit — the case mux exists to make cheap — still performs ~14–16
heap allocations and two full `Debug` renderings of the transport and security
config, because the lookup key is rebuilt per dial and cloned on every
`HashMap` entry.

## Evidence

`MuxKey::of` (`mux_pool.rs:186-232`) builds the key with `format!`:

```rust
// mux_pool.rs:191-197 (VLESS arm)
format!(
    "{}|enc:{:?}",
    cfg.uuid,
    cfg.encryption.as_ref().map(ToString::to_string)
),                    // 1-2 allocs
format!("{:?}", cfg.transport), // 1 alloc, renders the whole transport config
format!("{:?}", cfg.security),  // 1 alloc, renders the whole security config
cfg.flow.as_ref().map(ToString::to_string), // 0-1 alloc
```

plus `params.server.host.clone()` (`mux_pool.rs:217`).

- It runs **twice per dial**: `open_session` builds it at `:309` and then calls
  `self.acquire(params, policy)` (`:310`), which builds it again at `:362`.
  `open_udp` does the same (`:429` then `:362`).
- The map path clones it: `entries.entry(key.clone())` at `:456` (`choose`) and
  `:514` (`register`) — a second copy of every `String` field, including the
  credential, per dial.
- On the sweep it is more: `choose` runs `sweep(&mut entries, policy.idle)`
  before the lookup (`mux_pool.rs:455`), so a dial also walks every carrier of
  every key.

Warm-hit total for one VLESS CONNECT: 2× (`MuxKey::of`) + 1× (`clone` into
`entry`) ≈ 14–16 allocations and two `Debug` passes over a nested config that
can contain maps (`TransportConfig::headers`, `crates/leas-proto/src/proto_spec/
common.rs:251-310`).

The repo already treats this class as a defect: `crates/leas-hotpath` asserts
exact allocation counts for the dial-adjacent hot paths, and the Profiles
render path has a "nothing per frame" rule. A per-CONNECT pool key sits in the
same budget.

## Impact

- Per-connection allocator traffic on the path that is supposed to be the
  cheap one; `Debug` cost scales with transport complexity (an xhttp/ws row
  renders headers, paths and nested security options).
- The credential is stored as a `String` map key and is never zeroized on drop;
  on the hit path the per-dial clone is dropped when the occupied entry returns,
  so the pool holds one copy for its lifetime, not two. The repo's convention is
  `zeroize` on owned key buffers; a `String` map key is outside it.
- Nothing here is a correctness bug — the key is correct and the test
  `key_ignores_remarks_and_cap_but_not_identity` pins the policy/identity split.
  It is the cost of computing it that is wrong.

## Fix sketch

- Build once: `open_session`/`open_udp` pass `&key` into `acquire`, which stops
  calling `MuxKey::of` (`mux_pool.rs:362`). That removes the second build of the pair, halving the cost before any identity change.
- Avoid the clone on the hit path: `if let Some(carriers) = entries.get_mut(key)
  { ... }` before the insert, so a steady-state dial never copies the key; let
  the vacant branch clone (`entries.insert(key.clone(), …)`), which only runs
  when a new profile key appears.
- Optional, bigger: replace the `String` fields with a borrowed view over
  `params.protocol` plus a 64-bit digest, and keep the owned copy only in the
  map. Do this only if `just hotpath` shows the key in the profile — the first
  two steps are the same win with no identity change.

## Related

- [004](004-row-mux-cap-never-reaches-the-pool.md) — the same `choose` call site
  reads `policy.cap`; a cap fix must not re-introduce a per-dial key build.
- [001](001-inbound-accept-layer-has-no-admission-control.md) — the accept layer
  decides how many of these keys are built per second; the two costs compound.
