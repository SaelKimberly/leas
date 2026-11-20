# 016 — A UDP flow is fully re-routed per datagram, through two DNS caches and a payload copy

- **Location**: `crates/leas-native/src/inbound/mod.rs:1035-1058`
  (`forward_client`: sniff copy → `ConnMeta` → `decide_async`), `:1145`
  (`cached_domain(&self.dns_cache, …)` in `forward_direct`), `:1417`/`:1522-1525`
  (`run_proxy_leg`'s once-per-leg resolve); engine side
  `crates/leas-route/src/engine.rs:584-650`
- **Severity**: low (architectural)
- **Status**: theory (code-proven; cost unmeasured)

## Hypothesis

Every SOCKS5 UDP datagram re-enters the whole routing pipeline. Nothing is
memoized per flow: the `(target, network, inbound, source)` tuple that
determines the decision is stable for the life of a QUIC flow, yet each of its
datagrams pays

1. `bytes::Bytes::copy_from_slice(payload)` when any rule sniffs
   (`mod.rs:1044-1046`) — up to `MAX_SNIFF_LEN`, and for QUIC the whole datagram
   by design;
2. the full rule scan (`engine.rules.iter().find`, `engine.rs:585`) plus the
   `IfNonMatch` resolution pass;
3. an engine `ResolvedCache` lock + two `Vec<IpAddr>` copies (see **015**), and
   then, for a direct-routed flow, a *second, different* per-datagram DNS cache
   lookup in `forward_direct` (`:1145`) for the same host — the engine's answer
   lands in `ConnMeta`, which is dropped when `forward_client` returns (the proxy
   leg resolves once per leg, `:1417`, and per datagram only when the destination
   differs from the session target, `:1522-1525`);
4. a `parking_lot` lock on `probe_tracker` (`engine.rs:633-638`), whose only
   input that varies per datagram is the same host.

Meanwhile the per-association state that could key a memo already exists
(`forward_client` is a method on the association struct, with `self.source`,
`self.config`, and `self.dns_cache` in hand).

## Evidence

`mod.rs:1041-1058` — the whole pipeline, once per datagram:

```rust
let owned_payload = self
    .config
    .engine
    .needs_sniff()
    .then(|| bytes::Bytes::copy_from_slice(payload));
let mut meta = ConnMeta {
    target: target_to_net(&target),
    …
    payload_prefix: owned_payload.clone(),
    …
};
let decision = decide_async(&self.config.engine, &mut meta).await;
```

`mod.rs:1145` — the second lookup, after routing:

```rust
if let Some(addr) = cached_domain(&self.dns_cache, &domain, dest.port) {
```

That cache is a `parking_lot` mutex around a `Vec` scanned linearly per
datagram (`cached_domain`, `:1592-1598`: `lock().iter().find(...)`), and on a
miss `resolve_domain` answers through `tokio::net::lookup_host`
(`:1601-1609`) — the **system** resolver, not the hickory resolver the routing
pass used. So one domain datagram consults two different caches and, on a miss,
two different name-resolution stacks for the same name.

The exact cost is **unmeasured** — no bench drives `forward_client`, and the
engine's own `benches/decide.rs` measures only the pure `decide`. Treat the
numbers as unknown and the shape as the finding: a per-packet pipeline where
every mature implementation routes per flow (xray's UDP dispatcher keys its
outbound per destination; sing-box's `udpnat` holds a per-flow session) and
consults the router once.

## Why it matters

A QUIC video stream or a game session is 10²-10³ datagrams/second per flow, and
a SOCKS5 UDP association multiplexes dozens of flows. Per datagram that is one
heap copy of the payload plus several locks and a full rule scan; it also keeps
the engine cache "hot" in the pathological sense described in **015**, and two
datagrams of one flow can take different decisions — the stateless probe sniffs
a QUIC `Initial` but not the 1-RTT packets after it, and a re-resolved domain
flips an `IpCidr` rule — which is how a single QUIC connection ends up split
across outbounds. The engine handle itself is pinned in
`Socks5InboundConfig` (`inbound/mod.rs:100`, captured per session at
`ops/native_connect.rs:49`), so a rule-set rebuild does not re-route a live
flow; a profile switch ends the association instead (`inbound/mod.rs:676-679`).

## Fix sketch

Memoize the **decision**, not the pipeline: keep a small bounded map on the
association keyed by `(destination, network)` with the same lifetime as the
association's `dns_cache`. On a hit, skip the sniff copy and `decide_async`
entirely and go straight to the outbound — a memo cannot go stale against the
engine, because the engine handle is pinned in `Socks5InboundConfig` for the
association's whole life. Sniffing then happens once per flow, which is also
the point where a stateful `QuicSniffer` (`leas_route::sniff::QuicSniffer`)
becomes usable — today the stateless `probe` sees one datagram and cannot
reassemble a split ClientHello.

Do not put this cache inside `leas-route`: the engine is immutable and shared;
the association is the thing with a lifetime.

## Related

- **015** — the engine's `ResolvedCache` re-writes its entry on every hit, so the
  per-datagram cost described here also slides a TTL that was meant to expire.
- **003** (native-inbound) — the same `UdpRelay`/association object: 003 is what
  it allocates before any traffic, this is what it redoes per datagram.
- **027** (native-inbound) — the linear scan of `seen` inside the per-datagram
  pipeline described here. Independent fixes: the memo removes the re-route,
  not the scan (`note_conn` runs after the decision), so only 027's cap bounds
  it.
- **028** (native-inbound) — the `resolve_domain` call this issue counts as
  cost, read as correctness: its answer never expires and keeps one address.
