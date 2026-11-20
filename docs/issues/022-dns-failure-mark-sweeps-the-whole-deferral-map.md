# 022 — Every DNS failure rescans the whole deferral map, so a failure burst pays O(F²) scans under the shard locks the dispatch path also needs

- **Location**: `crates/leas/src/ops/scheduler.rs:337-343` (`mark_dns_failure`),
  `:425-433` (`sweep_dns_failures`, the `retain` at `:431-432`),
  `crates/leas/src/ops/enrich.rs:684-693` (the per-waiter call site)
- **Severity**: low
- **Status**: theory (shape proven; cost measured on a lock-free stand-in)

## Hypothesis

`mark_dns_failure` does two things: insert the endpoint's timestamp, then
`sweep_dns_failures` — which is `dns_failures.retain(|_, ts| now - ts < defer)`,
a scan of **every** entry in the map. So the Nth failure of a burst costs N entry visits, and a burst of F failures
costs about F²/2 scans when nothing in the map has expired.

The map only shrinks for entries **older than** the window: `retain` drops
those, but nothing a burst inserts can expire inside that burst, because
`dns_defer_secs` is floored at `MIN_DNS_DEFER_SECS = 15` (`state.rs:763-777`,
and the floor exists precisely so the window outlasts a resolution). So for a
burst of F failures over a pre-existing population K the sweep cost is
F·(K + F/2) — quadratic in F — and the only entries it ever removes are ones a
previous window left behind.

The call site is the lookup settle path, not a per-link probe: one call per
endpoint waiting on a failed host (`enrich.rs:687-693`), so a single DNS outage
over a shared CDN host marks every endpoint on it. The repo's own record of the
2026-11-19/20 run is the shape that hits this: **12,093 hosts recorded as DNS
failures in six seconds** (`AGENTS.md`, DNS-resolution bullet).

The cost is not only the scan. `DashMap::retain` takes each shard's write lock
in turn, and the dispatch path reads the same map per link
(`is_dns_unresolved`, `:387-404`, called from `schedule`) and per deferral
accounting (`dns_state_stamp`, `:415-421`). Each of the 12,093 sweeps
write-locks every shard, so a schedule that wants a read lock queues behind a
full-map scan.

The sweep is pure hygiene: `is_dns_unresolved` already removes an expired entry
it looks at (`:401-402`), and `clear_dns_failure` removes on success, so
correctness never depends on the bulk pass.

## Evidence

```rust
// scheduler.rs:337-343
pub fn mark_dns_failure(&self, endpoint: EndpointId) {
    let now = Timestamp::now();
    self.dns_failures.insert(endpoint, now);
    self.sweep_dns_failures(now);          // full-map scan, every call
}
```

Measured shape, run outside the repo (`rustc -O retain_probe.rs`, a plain
`HashMap` with the same insert-then-retain-per-insert loop — no shard locks, no
`Timestamp` conversion, so this is a **lower bound**):

```text
F=  1000  visits=    500500    0.85 ms
F=  4000  visits=   8002000    8.17 ms
F= 12093  visits=  73126371   72.60 ms
```

The visit count is F·(F+1)/2 and the wall time tracks it at ≈1 ns per visit, so
the quadratic term is in the scans, not in the clock granularity. 72 ms of
scanning at the recorded burst size, before the lock cost, whose entire output
is "nothing inserted in this window expired". It is bounded — by the number of
DNS failures inside one window, not by table size — but it is work the probe
task pays while it should be dispatching probes.

## Fix options

1. **Amortize.** Sweep every Nth mark (an `AtomicUsize` counter) or only when
   `dns_failures.len()` crosses a bound (e.g. 4,096). One line, keeps the map
   bounded, removes the quadratic term.
2. **Drop the bulk sweep.** Keep the lazy removal in `is_dns_unresolved` and
   the removal in `clear_dns_failure`; the map is then bounded by the number of
   endpoints that ever failed DNS, which is a page of the feed, not a leak.
3. **Store the failures in a structure whose expiry is ordered** (a
   `BTreeMap<Timestamp, …>` front-swept in O(expired) instead of O(all)) — only
   worth it if 1 or 2 shows up in a profile.

Option 1 is the smallest complete change; option 2 is defensible if the
"bounded by failures ever seen" argument holds for the session.

## Related

- **013:** the same failure bookkeeping from the caller's side — a starved
  lookup must not stamp a failure at all. The two together define what the map
  is for; neither needs a scan per insert.
- **021:** both make a DNS-retry run hold the single job slot for longer than it
  should.
