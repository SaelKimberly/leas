# 013 — A wedged resolver costs up to 15 s per lookup, and the caller's 8 s deadline books the host as failed

- **Location**: `crates/leas-dns/src/lib.rs:25-30` (`DEFAULT_RESOLVER_OPTS`),
  `crates/leas/src/ops/enrich.rs:51` (`DNS_LOOKUP_TIMEOUT`), `:609` (the deadline),
  `:334-335` (`RESOLVE_SEM`)
- **Severity**: medium
- **Status**: theory (measured)
- **Domain**: dns

## Hypothesis

`DEFAULT_RESOLVER_OPTS` (`lib.rs:25-30`) sets `ResolverOpts::timeout = 500 ms`
and leaves `attempts` at hickory's default of 2. Neither number bounds what this
pool actually spends on a resolver that is up but wedged, because the two phases
of a lookup are bounded by different things:

| phase | bound | configurable? |
|---|---|---|
| request / read | `cx.options.timeout` — `DnsMultiplexer::with_timeout` for TCP/TLS (hickory-net `tls.rs:107`), `request_timeout` for DoH/DoQ/H3, `with_timeout` for UDP (`connection_provider.rs:85`) | yes, this is the 500 ms |
| connect + handshake | `CONNECT_TIMEOUT`, a FIXED 5 s (hickory-net `xfer/mod.rs:473`, applied at `tls.rs:223`) | **no** — `ResolverOpts` has no field for it |
| whole lookup | `attempts = 2` → `RetrySendStream` makes **3** sends (hickory-net `xfer/retry_dns_handle.rs:60,98-101`) | via `attempts` |

So a resolver whose TCP connect succeeds but whose handshake stalls costs
5 s × 3 = **15 s**, and the 500 ms never enters that arithmetic. The only real
bound on it is the caller's `tokio::time::timeout(DNS_LOOKUP_TIMEOUT /* 8 s */, ..)`
(`enrich.rs:609`) — and that timeout ends in a DNS VERDICT (`enrich.rs:632-657`
sets `resolved_ok = false`, `:691` calls `mark_dns_failure`), not in congestion
accounting, and it also stamps `resolved_at`, which the TTL gate then trusts for
`dns_cache_ttl_secs`.

Second, independent half: the same 8 s is below the tail of a lookup that WORKS.
Measured against the real published resolver list, the worst of 20 real hosts
took 10.2 s; the app would have cut it.

## Evidence

Measured (temporary tests in `crates/leas-dns/src/lib.rs`, run in a detached
worktree at HEAD so the in-flight `crates/leas-dns` work stays untouched):

1. A `Tls` name server that accepts the TCP connection and never answers the
   handshake — a resolver that is up but wedged:

   ```
   500ms opts -> 15.006135916s; 2000ms opts -> 15.005661572s
   ```

   15.006 s under both budgets, to the millisecond — which is 3 × the fixed
   `CONNECT_TIMEOUT` of 5 s, i.e. the handshake bound times `attempts + 1`.
   Changing `options.timeout` cannot move it.

2. The real published resolver list (`get_dns_servers` on the live URL, 898
   stamps), 20 real hosts, `allow_ipv6 = true`, the production builder:

   ```
   500ms: 20 ok / 0 fail, worst 10.219806394s
     5s: 20 ok / 0 fail, worst 10.221027615s
   ```

   20/20 both ways and an identical worst case, so the 500 ms is NOT a fail-fast
   knob: it bounds requests, which are a small part of a cold lookup, and the
   run loses nothing either way. The 10.2 s worst is 2 × 5 s — the same fixed
   connect bound, hit twice.

The measurement therefore retires the obvious first theory ("500 ms is too tight,
so slow-path lookups fail") — and that theory's fix (raise it) is not the lever.
It also refutes the opposite reading of the same constant, which is the one the
field invites: `options.timeout` is NOT an end-to-end deadline for a lookup.
`name_server_pool.rs:313` arms it as a pool deadline and then awaits the in-flight
exchanges without checking it, so item (2) resolved 20 hosts while each lookup was
allowed to run to 10.2 s under a 500 ms setting. Only the caller's timer is
end-to-end.

## Why it matters

`RESOLVE_SEM` is 64 permits shared by every in-flight lookup (`enrich.rs:334-335`),
and `Permit::Starved` already exists because contention was once booked as
resolver failure. A wedged resolver costs one permit its whole 8 s (the pool
cannot cut it earlier — the fixed 5 s × 3 is longer than the caller allows), so a
handful of bad name servers in the rotation saturate the gate; the hosts behind
them are then `mark_dns_failure`d and the batch defers them. The recorded instance
of the end state is `docs/research/2026-11-20-log-review-real-test.md`.

## Fix sketch

- `attempts`: with a 5 s fixed connect bound per send, `attempts = 2` is what
  makes a single wedged server cost 15 s. `attempts = 1` halves it, and failover
  across the other ~38 name servers is the pool's job anyway. This IS an
  `ResolverOpts` field.
- The wedge bound itself is not reachable from `ResolverOpts`; a hard ceiling
  needs to be OUTSIDE hickory — either a per-lookup wrapper tighter than the
  caller's deadline (so one wedged server cannot eat the whole 8 s), or a
  connection provider of our own, as `dnscrypt.rs` already does for DNSCrypt.
- `DNS_LOOKUP_TIMEOUT` (8 s) sits below the measured tail of a working lookup
  (10.2 s), so raising it (or letting the batch's deferral budget account for the
  tail) is the other half.

`NameServer::send` is `pub(crate)` in hickory-resolver, so "wrap the send" is not
implementable here; the per-request timeouts it would have added are already
applied (`DnsMultiplexer::with_timeout`).

## Reproducer

Both harnesses are quoted in the Evidence block: a silent-accept
`ConnectionConfig::tls` endpoint for (1), and `get_dns_servers` + the production
builder over 20 real hosts for (2). Both are network tests and stay out of the
suite.

## Related

- 014 — the same `init()` path runs a 10 s list download inside the 8 s deadline.
 013 is the read side of the same asymmetry (a caller deadline doing the bounding
  that the inner budgets do not), 014 the fetch side.
