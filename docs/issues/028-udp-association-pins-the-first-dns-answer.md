# 028 — A UDP association pins the first DNS answer for its whole life: no TTL, no family fallback, no negative cache

- **Location**: `crates/leas-native/src/inbound/mod.rs:1573-1618` (`DnsCache`,
  `cached_domain`, `resolve_domain`), `:1145`/`:1168-1180` (the direct leg's
  cache-hit and spawn-on-miss), `:1609` (first address only), `:1250-1284`
  (`ensure_direct_sockets` / `socket_for`), `:1417` (the proxy leg's one
  resolve)
- **Severity**: medium (a stale or unreachable answer serves every later
  datagram; a failing name is re-resolved per datagram, unbounded)
- **Status**: theory

## Hypothesis

Three separate properties of one cache add up to "the association's first DNS
answer is its only answer":

1. **No TTL.** `resolve_domain` stores `(domain, port, addr)` and the entry is
   evicted only by the 64-entry cap
   (`DNS_CACHE_MAX`, `:1581`; evict-oldest `:1611-1615`). The type doc says so
   plainly — "caching the answer for the association's lifetime"
   (`:1600`). Every other resolver in the process has a TTL: the engine's
   `ResolvedCache` is built with 300 s (`leas-route/src/engine.rs:467`) and the
   app's own stamp policy is `dns_cache_ttl_secs`, default 300
   (`leas/src/state.rs:909`, used at `ops/enrich.rs:486`). A busy association
   outlives any DNS TTL by definition — it lives until its control connection
   closes, not for 60 s (the 60 s `UDP_PIN_DEADLINE` only reaps an association
   *before* its first datagram, `:691-697`).

2. **First address only.** `let addr = addrs.into_iter().next()?` (`:1609`)
   keeps whichever address `getaddrinfo` returned first and discards the rest.
   `ensure_direct_sockets` binds both families independently and remembers a
   failed bind (`:1250-1276`), and `socket_for` returns `None` for a family with
   no socket (`:1280-1284`). So on a dual-stack host with IPv6 disabled — the
   `[::]:0` bind fails, `out_v6` stays `None` — a name whose first answer is
   `AAAA` sends **every** datagram to `self.drop_datagram` (`:1145-1150` on a
   cache hit, `:1190-1198` in the spawned miss path), for the association's life, while the host's `A` record sits
   discarded in the same `addrs` iterator. `cached_domain` also keys on
   `(domain, port)`, so no later failure ever invalidates the pick.

3. **No negative cache.** A lookup that times out or returns NXDOMAIN returns
   `None` without recording anything (`:1605-1608`, two `?`s after the
   `timeouts::DIAL` guard — 10 s, `error.rs:238`). `forward_direct`'s miss path
   spawns one task per datagram (`:1168-1180`), each of which calls
   `resolve_domain` again. An association sending N datagrams/s at an
   unresolvable destination therefore drives N concurrent `getaddrinfo` calls
   and N spawned tasks, each parked up to 10 s — with no attempt counter, no
   backoff, and no cap on in-flight lookups per association.

The engine already resolved the same name for the same datagram when the
`IfNonMatch` pass ran (`leas-route/src/engine.rs:608-643`, resolver installed
from `leas-dns` at `ops/geodata.rs:481-494`): that answer goes into `ConnMeta`
and is dropped, because `forward_direct` consults `self.dns_cache` and the
system resolver instead (`:1145`, `:1605`). So the two resolvers can disagree,
and the leg's answer is the one that sticks forever.

## Evidence

The whole resolution policy, `:1592-1618`:

```rust
fn cached_domain(cache: &DnsCache, domain: &str, port: u16) -> Option<SocketAddr> {
    cache.lock().iter()
        .find(|(d, p, _)| *p == port && &**d == domain)
        .map(|(_, _, addr)| *addr)
}

async fn resolve_domain(cache: &DnsCache, domain: &str, port: u16) -> Option<SocketAddr> {
    if let Some(cached) = cached_domain(cache, domain, port) {
        return Some(cached);
    }
    let addrs = tokio::time::timeout(timeouts::DIAL, tokio::net::lookup_host((domain, port)))
        .await
        .ok()?
        .ok()?;
    let addr = addrs.into_iter().next()?;      // ← one of possibly several
    {
        let mut entries = cache.lock();
        if entries.len() >= DNS_CACHE_MAX {
            entries.remove(0);
        }
        entries.push((Box::from(domain), port, addr));
    }
    Some(addr)
}
```

The drop path a pinned dead address lands in, `:1145-1150`:

```rust
if let Some(addr) = cached_domain(&self.dns_cache, &domain, dest.port) {
    let Some(socket) = self.socket_for(addr) else {
        tracing::debug!(%addr, "socks5 inbound: no upstream socket for family");
        self.drop_datagram(Some(host), payload.len());
        return;
    };
```

Nothing in the file records a resolution failure: `resolve_domain` returns the
same `None`, so the next datagram re-enters the same miss path.

Code-proven, not run: reaching this path in a test needs a SOCKS5 UDP
association with a domain destination and a `Direct` decision, plus a resolver
stub — the crate's existing inbound tests drive a real listener
(`inbound/tests.rs`), and no runtime claim here depends on timing.

## Why it matters

A `Direct`-routed UDP domain destination is the one place in the client where a
destination name is resolved *by the client* and then contacted directly, so
its address is exactly what DNS is for. Pinning the first answer:

- breaks rotation for the life of the association (a CDN node decommissioned
  mid-session is contacted until the client disconnects);
- makes a v6-first answer permanently dead on an IPv4-only host, instead of
  costing one family's first datagram;
- turns an unresolvable name into an unbounded fan-out of blocking lookups
  rather than one failure and a drop.

The privacy half (the leg uses the OS resolver while the profile may be
configured for dnscrypt/DoH through `leas-dns`) is filed as cost/shape in
**016**; here it is the input to a cache that never revisits it.

## Fix sketch

Reuse the mechanism the process already has instead of a second one:

1. Give the association cache the same input the engine's: resolve through the
   pinned `DnsSink` (`Socks5InboundConfig` already holds the
   `Arc<Engine>`, whose resolver is installed in production,
   `ops/geodata.rs:481-494`), or at minimum through the same
   `leas_dns::DnsResolver` the app is configured with.
2. Store the address list plus a `stored_at` and honour
   `dns_cache_ttl_secs` — `ResolvedCache`'s shape (`leas-route/src/resolve.rs:27-83`)
   is the existing precedent, not a new one.
3. On send failure for a cached address, invalidate the entry and retry once
   with the next address, so a family the host cannot reach costs one datagram.
4. Negative-cache the failure for a short window (the association's own
   `proxy_retry_at`/`RETRY_BACKOFF` pattern at `:1276` is the local precedent),
   and cap in-flight resolve tasks per association.

The minimal version that fixes the correctness bug without the resolver
plumbing: keep the system resolver, but cache `Vec<SocketAddr>` + `stored_at`,
try addresses in order, and drop the entry on the first send error.

## Related

- **016** (routing-engine) — the same `resolve_domain` read from the cost side:
  016 counts the second lookup per datagram, this issue is what the second
  lookup's answer is worth.
- **015** (routing-engine) — the engine-side cousin: a cache hit re-stores its
  own TTL so it never expires; here there is no TTL to re-store at all.
- **013** (dns) — the same "resolver deadline inside a caller budget" shape; 013
  counts the seconds, this issue counts the concurrent lookups those seconds
  hold.
- **027** (native-inbound) — the other per-association accumulator: `dns_cache`
  is capped but never expires, `seen` expires with the association but is never
  capped.
- **003** (native-inbound) — the association object these fields live on.
