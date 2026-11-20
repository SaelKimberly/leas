# 027 — A UDP association's "hosts already counted" list is unbounded, and every datagram scans it linearly

- **Location**: `crates/leas-native/src/inbound/mod.rs:884` (the field),
  `:931-938` (`note_conn`), callers `:1099` (direct arm) and `:1104` (proxy arm)
- **Severity**: medium (unbounded memory growth + O(hosts) work on the datagram
  hot path; constant factor measured)
- **Status**: theory

## Hypothesis

`UdpRelay::seen` exists to dedupe one Sniffer counter — it remembers which hosts
this association already reported to `Telemetry::udp_conn`, so the per-host
`conns` column counts a host once. It is a `SmallVec` with no cap:

```rust
/// Hosts this association already counted in `conns` (inline, no hashing).
seen: SmallVec<[CompactString; 4]>,
```

and every routed datagram walks it from the front before falling through to the
push:

```rust
fn note_conn(&mut self, host: &str, outbound: &str) {
    if self.seen.iter().any(|seen| seen == host) {
        return;
    }
    self.seen.push(CompactString::new(host));
    …
}
```

Nothing bounds the distinct destination count of an association. A SOCKS5 UDP
association is exactly the shape that names many hosts: a torrent client's DHT
and swarm traffic, a QUIC game session's matchmaking, a DNS-over-UDP relay. Each
new host costs one `CompactString` (heap for names past 24 bytes) and makes
every later datagram pay one more string compare, so the association's per-packet
cost grows with its own history — O(N²) over N distinct hosts.

The sibling structure in the same object was capped for this exact reason. The
association's `DnsCache` carries `const DNS_CACHE_MAX: usize = 64` and an
evict-oldest insert (`:1581`, `:1611-1615`), and its type doc records why: "the
cap bounds an association that keeps naming new hosts (the map grew without
limit)" (`:1574-1577`). `seen` — same lifetime, same per-datagram use, same
peer-driven key space — is the one that kept growing.

## Evidence

Both routing arms call it once per datagram (`:1096-1106`):

```rust
match &outbound.kind {
    OutboundKind::Block => self.drop_datagram(Some(&host), payload.len()),
    OutboundKind::Direct => {
        self.note_conn(&host, &outbound.tag);
        self.forward_direct(dest, payload, owned_payload.as_ref(), &host)…
    }
    OutboundKind::Proxy(proxy) => {
        self.note_conn(&host, &outbound.tag);
        self.forward_proxy(&tag, proxy, dest, owned_payload.as_ref(), &host);
    }
}
```

Measured constant factor of the scan alone, `rustc -O`, i7-12700, a
`Vec<String>` of host-shaped names scanned with `.iter().any(|s| s == needle)`
(the same comparison `note_conn` performs, without the `CompactString` inline
path, so this is the string-compare term only):

| entries | miss (full scan) | hit at the last entry |
|---|---|---|
| 1,000 | 0.56 µs | 2.0 µs |
| 10,000 | 2.3 µs | 20 µs |
| 50,000 | 53 µs | 97 µs |

The scan is the floor: `CompactString`'s inline compare for names ≤24 bytes is
cheaper than `String`'s pointer chase, so a real 50k-host list would scan
somewhat faster — but the growth is linear in the list, and the list is the
association's whole history. At 2,000 datagrams/s and 50k hosts, 53 µs a scan
is 11 % of a core spent deciding whether to increment a counter, and the
last-entry column (97 µs) is 19 %; the honest reading is "low double digits at
a rate a torrent association reaches", not a wall. Memory: a `CompactString`
is 24 bytes, so 100k distinct hosts is ≈2.4 MB of slots plus a heap block for
each name past 24 bytes — ≈5 MB if every name is long — held until the control
connection ends.

The association's lifetime is not short: the 60 s `UDP_PIN_DEADLINE` only
expires an association that never received a datagram (`:691-697`), and after
that the association lives until the controlling TCP connection closes or the
native session is shut down (`:676-689`).

## Fix sketch

Cap it, exactly as `DNS_CACHE_MAX` caps the sibling, and stop counting new hosts
past the cap — `conns` is a Sniffer hint, not an accounting identity, so a
truncated set loses nothing a user acts on:

```rust
const SEEN_HOSTS_MAX: usize = 256;

fn note_conn(&mut self, host: &str, outbound: &str) {
    if self.seen.len() >= SEEN_HOSTS_MAX {
        return;                       // counter capped; keep reporting bytes
    }
    if self.seen.iter().any(|seen| seen == host) {
        return;
    }
    …
}
```

256 entries keeps the scan at ~0.1 µs and the memory under 8 KiB. If the column
must stay exact for large associations, the replacement is a per-association
`hashbrown` set with the same cap — but the cap is the thing that makes it safe,
not the lookup structure.

## Related

- **003** (native-inbound) — the same `UdpRelay` object: 003 is what an
  association allocates before its first datagram, this is what it accumulates
  while running.
- **028** (native-inbound) — the other per-association accumulator with a
  lifetime problem: `dns_cache` is capped but never expires, this one expires
  with the association but is never capped.
- **016** (routing-engine) — the per-datagram pipeline this scan sits on top of.
  The two fixes are independent: 016 removes the re-route, this one the scan
  that survives it — a decision memo does not skip `note_conn`, which runs
  after the decision (`:1096-1106`), so the cap is the only mitigation here.
- **024** (ui-render) — same antipattern at the drawing layer (a per-frame build
  bounded only by the dataset); both are fixed by bounding the structure, not by
  making the loop cheaper.
