# 014 — A slow resolver list host makes DNS resolve nothing, forever

- **Location**: `crates/leas-dns/src/lib.rs:36-42` (`HTTP_CLIENT`, 10 s),
  `:289-306` (the download inside `get_dns_servers_from`), `:311-321` (the
  `downloaded.or(cached)` gate in front of the system fallback), `:348`
  (`get_or_try_init(|| self.init())`); `crates/leas/src/ops/enrich.rs:51`,
  `:609` (the 8 s deadline around it)
- **Severity**: medium
- **Status**: theory (reproducer run)
- **Domain**: dns

## Hypothesis

`DnsResolver` is constructed with no I/O (`state.rs:913-921`, "Cheap
constructors — no I/O until first lookup"), so the first `lookup_ip` runs
`init()` — which, on a cold cache, downloads the resolver list — **inside** the
lookup's 8 s deadline (`enrich.rs:609`). Three facts make that a livelock rather
than a slow start:

1. the download's own budget is 10 s (`lib.rs:39`), longer than the caller's 8 s;
2. the `system_conf` fallback is gated on `downloaded.or(cached)` (`lib.rs:311`),
   and a caller deadline is not an `Err` — the future is simply dropped, so the
   gate is never reached. (The gate DOES cover the other empty cases: a download
   that errors, and one that succeeds but parses to zero stamps, `:293-294`.)
3. the cache is written after the body is complete (`:289-306`), so a cancelled
   download caches nothing and the `OnceCell` stays empty.

The result: on a network where the list host answers in more than 8 s (or is
reachable only through a proxy/hole that stalls), every lookup burns 8 s,
cancels, and starts the next attempt from zero. Nothing is ever cached, the
fallback never runs, and no host resolves — `enrich.rs:691` books each of them
as a DNS failure on the way out.

## Evidence

Reproducer run (temporary test appended to `crates/leas-dns/src/lib.rs` in a
detached worktree at HEAD, so the in-flight `crates/leas-dns` work is untouched).
It models the mechanism — a caller deadline shorter than the server's response
delay — not the production 8 s/10 s ratio: the fixture delays 2 s against a
500 ms deadline, and `HTTP_CLIENT`'s own 10 s budget is never exercised because
the caller's cancellation lands first. That is the point: the caller cancels, and
what it leaves behind is nothing.

```rust
#[tokio::test]
async fn challenge_slow_download_never_caches() -> anyhow::Result<()> {
    let url = slow_serve(Duration::from_secs(2)).await;   // answers after 2 s
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join(DNSCRYPT_RESOLVERS_CACHE);
    for attempt in 1..=2 {
        let outcome = tokio::time::timeout(
            Duration::from_millis(500),
            get_dns_servers_from(dir.path(), &url),
        ).await;
        assert!(outcome.is_err(), "attempt {attempt}: the deadline must fire");
        assert!(!cache.exists(), "a cancelled download cached nothing");
    }
    // Control: a deadline longer than the delay completes and caches, so the
    // two failures above are the budget, not the fixture.
    let ok = tokio::time::timeout(Duration::from_secs(3),
        get_dns_servers_from(dir.path(), &url)).await?;
    assert_eq!(ok?.hickory.name_servers().len(), 1);
    assert!(cache.exists(), "control must cache");
    Ok(())
}
```

```
PASS [   3.024s] (1/1) leas-dns challenge_tests::challenge_slow_download_never_caches
```

Both failing attempts hit the deadline and left no cache file; the control with a
deadline above the delay resolved and wrote it. That is the whole failure: the
budget, not the fixture, decides whether the cache ever lands.

## Why it matters for this app

The list host is `raw.githubusercontent.com` (`lib.rs:19-20`) — a name that is
slow or blocked on exactly the networks the client targets (`ru`/`cn`/`ir`
rulesets ship in the box). The failure is not "DNS is slow on first run": it is
"DNS never works, and every host in the feed is logged as a DNS failure", because
each attempt restarts the download and none of them can outlive the caller.

## Fix sketch

Any one of:

- give the download a budget SHORTER than the caller's (e.g. 4 s). Its own
  timeout then arrives as an `Err` and reaches the existing `system_conf`
  fallback; today the only clock that can fire is the caller's, and that one
  leaves the gate untouched;
- move the refresh out of the lookup: `init()` synchronously builds the pool
  from the cache or the system config and spawns the refresh, so a slow list
  never blocks a resolution;
- warm the cache at startup, off the lookup path.

## Note — the pending redesign already takes the third route

The user's in-flight DNS work (`docs/aegis/specs/2026-11-20-dns-resolvers-design.md`,
uncommitted) replaces the lazy list with an explicit source fetch:
`fetch_source` is called from `crates/leas/src/ops/dns.rs` (a user action), not
from a lookup. Filed against HEAD because HEAD is what shipped; if that redesign
lands as specified, this issue is closed by it.

## Related

- 013 — the read side of the same asymmetry: an inner budget (500 ms) that does
  not bound anything, under a caller deadline (8 s) that bounds too much.
