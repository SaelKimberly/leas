# 015 — A cache hit re-stores the answer it just read, so the TTL never runs out for a host in use

- **Location**: `crates/leas-route/src/engine.rs:610-645` (`decide_async`'s
  cache-then-`put` block), `crates/leas-route/src/resolve.rs:59-83`
  (`get_fresh` / `put`)
- **Severity**: medium
- **Status**: theory (reproducer run)

## Hypothesis

`decide_async` reads the resolver cache first, and then `put`s the *same*
answer back with a *fresh* stamp — on the hit path as well as the miss path.
`ResolvedCache::put` re-stamps an existing entry (`get_mut` … `*stored = now`,
`resolve.rs:79-82`), so every routed connection to a host refreshes that host's
entry. The 300 s TTL is therefore not "300 s after the answer arrived" but "300 s
after the host was last used": a host with steady traffic — a CDN origin, a
browser's parallel fetches, and *every datagram of a live UDP flow*
(`NativeInbound::forward_client` calls `decide_async` per datagram,
`crates/leas-native/src/inbound/mod.rs:1058`) — is pinned to its first answer
indefinitely, and a rotated or failed-over record is never picked up.

The intent is documented as the opposite in two places: `get_fresh` uses `peek`
"no recency bump: a freshness check must not keep entries alive past their TTL
intent" (`resolve.rs:62-66`), and `new` describes entries living "`ttl_secs`
past their store time". The hit path defeats both.

## Evidence

`engine.rs:610-645`:

```rust
let now = jiff::Timestamp::now();
let cached = engine
    .resolve_cache
    .as_ref()
    .and_then(|c| c.lock().get_fresh(&host, now).map(<[IpAddr]>::to_vec));
let outcome = match cached {
    Some(ips) => Ok(ips),                      // ← hit
    None => resolver.lookup_ip(&host).await,   // ← miss
};
…
if let Ok(ips) = outcome && !ips.is_empty()
    && let Some(cache) = &engine.resolve_cache
{
    cache.lock().put(host, ips, now);          // ← runs on BOTH paths
}
```

`resolve.rs:78-83`:

```rust
pub fn put(&mut self, host: String, ips: Vec<IpAddr>, now: jiff::Timestamp) {
    if let Some((slot, stored)) = self.entries.get_mut(host.as_str()) {
        *slot = ips;
        *stored = now;   // ← the hit path's own `now`, i.e. a TTL slide
    } else {
        self.entries.push(host, (ips, now));
    }
}
```

Three costs ride the same block on a hit, all avoidable:

1. `.map(<[IpAddr]>::to_vec)` — one allocation + copy out of the cache,
   then `meta.resolved_host_ips.clone_from(ips)` copies the same addresses a
   second time into the connection metadata.
2. A second lock acquisition (`cache.lock().put`) and an LRU recency bump for
   an entry that was just found.
3. `emit_resolved` runs on the hit too (`engine.rs:628-631`), so a
   `RouteEvent::Resolved` — `ips.to_vec()` plus an `Arc<str>` host — is sent per
   *datagram* into an unbounded channel once a sink is installed. No sink is
   installed in production today (`set_event_sink` has no caller outside this
   crate), so this is latent, not live.

## Why it matters

A routing policy that resolves `IfNonMatch` (the production rule set does:
`ops/geodata.rs:481`) and a DNS answer that changes behind a hot name — CDN
rotation, a blue/green failover, a poisoned record — leaves the engine dialing
the old address for as long as traffic keeps arriving. The per-hit cost is
small but it is on the per-datagram path, where it is paid thousands of times a
second for one flow.

## Fix sketch

Make the hit path read-only:

- `get_fresh` → copy into `meta.resolved_host_ips` under the lock (or return an
  `Arc<[IpAddr]>` so the copy is a refcount bump) and skip `put` when the answer
  came from the cache;
- `put` only in the `None` arm of the `match`, which is the only path that has a
  new answer to stamp;
- emit `Resolved` only for a fresh lookup. If the event stream is meant to
  report cache hits too, that needs a bounded channel and a per-flow gate, not
  an unbounded send per datagram.

## Reproducer

The mechanism is the `ResolvedCache` API, so it needs no engine and no I/O.
Append to `crates/leas-route/src/resolve.rs`'s test module (temp worktree at
HEAD, removed after the run):

```rust
#[test]
fn hit_path_restamp_slides_the_ttl() {
    let t0 = jiff::Timestamp::now();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let mut cache = ResolvedCache::new(300);
    cache.put("h".into(), vec![ip], t0);

    // `decide_async`'s hit path: read at t0+290 s, then `put` back with the
    // same `now`.
    let later = t0 + std::time::Duration::from_secs(290);
    let read = cache.get_fresh("h", later).map(<[IpAddr]>::to_vec).unwrap();
    cache.put("h".into(), read, later);

    // Peek-only semantics would say stale at t0+300 s; the hit path says fresh.
    let after = t0 + std::time::Duration::from_secs(301);
    assert!(cache.get_fresh("h", after).is_some(), "the hit re-stamped it");
    // Peek-only reading of the same timeline says it should be stale.
    let mut control = ResolvedCache::new(300);
    control.put("h".into(), vec![ip], t0);
    assert!(control.get_fresh("h", after).is_none(), "control expires");
}
```

Recorded run: appended to `crates/leas-route/src/resolve.rs` in a detached
worktree at HEAD (`git worktree add --detach /tmp/iter6 HEAD`), run with the
shared target dir:

```text
test resolve::hit_path_restamp_slides_the_ttl ... ok
test result: ok. 1 passed; 0 failed
```

It passes today, and that is the defect: without the hit path's re-`put` the
same timeline expires (the `control` assertion). The worktree was removed
afterwards; the main tree was never touched.

## Related

- **016** — this block sits on the per-datagram UDP path; a per-flow decision
  memo would drop the re-`put` along with the rest of the pipeline. It would not
  fix the staleness, which is this issue's own claim.
- **013** — the lookup a miss falls into can take 15 s (hickory's
  `CONNECT_TIMEOUT` × attempts); a hit path that never expires keeps that
  exposure alive for a new host instead of amortizing it.
