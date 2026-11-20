# leas — Issue Index

Curated findings from the review loop. One entry per root cause; related issues
are cross-linked rather than duplicated. Status values: `hypothesis` (not yet
proved), `theory` (proved from code paths / references), `declined`, `blocked`.

Loop state: [STATE.md](STATE.md).

## Open

| ID | Title | Severity | Status | Domain | Location |
|---|---|---|---|---|---|
| [001](001-inbound-accept-layer-has-no-admission-control.md) | Accept layer has no admission control; accept loop written three times | medium | theory | native-inbound | `inbound/mod.rs:200`, `inbound/http.rs:169`, `inbound/mixed.rs:72` |
| [002](002-relay-write-has-no-deadline.md) | Relay write has no deadline; a stalled reader pins the tunnel forever | medium | theory | native-inbound | `inbound/outbound.rs:359-402` |
| [003](003-udp-association-eager-buffers.md) | UDP association eagerly allocates 192 KiB and outlives its connection | low | theory | native-inbound | `inbound/mod.rs:664-666`, `inbound/mod.rs:593` |
| [004](004-row-mux-cap-never-reaches-the-pool.md) | A row's mux cap is parsed, stored, exported — then ignored by the pool | medium | theory | mux-pool | `mux_pool.rs:52`, `context.rs:73-76`, `native_connect.rs:184-192` |
| [005](005-mux-key-rebuilt-twice-per-dial.md) | Carrier key built twice per dial by `Debug`-formatting, then cloned into the map | low | theory | mux-pool | `mux_pool.rs:186-232`, `:309`+`:362`, `:456` |
| [006](006-mux-build-gate-is-pool-wide-and-drops-its-fallback-carrier.md) | Build gate is pool-wide; its 1 s fallback carrier is never registered | medium | theory | mux-pool | `mux_pool.rs:365-410`, `:278` |
| [007](007-datagram-recv-copies-what-bytes-already-owns.md) | Datagram receive copies payloads that already live in a `Bytes` (hysteria2, VLESS packetaddr) | low | theory | native-protocol | `hysteria2/udp.rs:124-125`, `vless/packet.rs:156`, `protocol/mod.rs:422-426` |
| [008](008-handshake-buffers-hold-a-credential-and-are-never-wiped.md) | Handshake buffers carry a replayable credential in plain `Vec`s that are never wiped | low | theory | native-protocol | `trojan/mod.rs:78-99,114`, `first_flight.rs:41,104`, `vless/mod.rs:113` |
| [009](009-hysteria2-defragger-sizes-slots-from-untrusted-frag-count.md) | hysteria2 defragger sizes its slot vector from a peer-controlled `frag_count` | low | theory | native-protocol | `hysteria2/udp.rs:158-168`, `:226-229` |
| [010](010-xhttp-dispatch-ignores-http-version.md) | xhttp dispatches h1/h2 by TLS presence, not by its own `http_version()` table | medium | theory | native-transport | `xhttp.rs:902-925`, `:119-160` |
| [011](011-xhttp-h1-upload-dial-bypasses-the-chain.md) | The plaintext xhttp h1 arm dials its upload connection straight to the server, bypassing a chain | low | theory | native-transport | `xhttp.rs:992`, `:1070` |
| [012](012-ws-early-data-duplicates-the-captured-prefix.md) | WS early data writes the captured prefix into two frames on top of the header — the tunnel's first bytes are corrupted | high | theory | native-transport | `ws.rs:183-193`, `:213-229` |
| [013](013-wedged-resolver-costs-15s-under-an-8s-deadline.md) | A wedged resolver costs up to 15 s per lookup; the caller's 8 s deadline then books the host as failed | medium | theory | dns | `leas-dns/src/lib.rs:25-30`, `enrich.rs:51`, `:609` |
| [014](014-cold-resolver-list-download-livelocks-dns.md) | A slow resolver list host makes DNS resolve nothing, forever — the list download runs inside the lookup's own deadline | medium | theory | dns | `leas-dns/src/lib.rs:36-42`, `:289-306`, `:311`, `:348` |
| [015](015-resolved-cache-refreshes-its-own-ttl-on-every-hit.md) | A cache hit re-stores the answer it just read, so the resolver TTL never runs out for a host in use | medium | theory | routing-engine | `engine.rs:610-645`, `resolve.rs:59-83` |
| [016](016-udp-flow-is-rerouted-per-datagram.md) | A UDP flow is fully re-routed per datagram, through two DNS caches and a payload copy | low | theory | routing-engine | `inbound/mod.rs:1035-1058`, `:1145`, `:1417` |
| [017](017-dropped-condition-token-widens-the-rule.md) | When every token of a condition field is unrepresentable the field vanishes, so the rule silently matches MORE traffic | medium | theory | routing-engine | `route_compile.rs:164-256`, `geodata.rs:461-466` |
| [018](018-merge-does-whole-table-work-per-merged-pair.md) | A merge reads the whole protocol table and rescans it for orphans, once per merged pair | medium | theory | db-layer | `merge.rs:174`, `:486`, `endpoint_rank.rs:1088`, `database.rs:2215` |
| [019](019-feed-search-scans-the-rank-table-twice-per-keystroke.md) | The feed search scans the whole rank table — the footer count on every keystroke, the page too when fewer than 200 rows match | medium | theory | db-layer | `profiles_query.rs:513-548`, `:762-799`, `ddl.rs:49-51` |
| [020](020-no-foreign-key-so-deleted-endpoints-leave-orphan-links.md) | No foreign key exists, so a link staged while its endpoint is deleted lands as a permanent orphan row | medium | theory | db-layer | `write_behind.rs:271-289`, `compact.rs:209-217`, `profiles.rs:938-946`, `ping.rs:612-625`, `main.rs:594-630` |
| [021](021-dns-retry-failure-reports-the-compact-terminal-event.md) | A DNS-retry scan failure reports `CompactFinished`, which cannot end a `DnsRetry` task, so the job queue wedges for the session | medium | theory | app-ops | `compact.rs:428-437`, `job_scheduler.rs:335-336`, `:348-362` |
| [022](022-dns-failure-mark-sweeps-the-whole-deferral-map.md) | Every DNS failure rescans the whole deferral map, so a burst pays O(F²) scans under the shard locks the dispatch path needs | low | theory | app-ops | `scheduler.rs:337-343`, `:425-433`, `enrich.rs:684-693` |

## Cross-references

- **001 → 002:** the missing admission cap is the only thing that would bound
  how many write-stalled tunnels coexist; 002 is why one of them never ends.
- **001 → 003:** 003's per-association cost is a constant; 001 is what makes the
  total unbounded.
- **002 ↔ 003:** both are "what ends this?" gaps in the inbound's resource
  lifetimes — one on the TCP relay's write, one on the UDP association's owner.
- **004 → 006:** both decide how many carriers a burst dials — the cap says how
  many are wanted, the gate decides how many dials are paid for nothing.
- **005 ↔ 004:** same `choose` site; a cap fix must not re-introduce a per-dial
  key build.
- **001 → 006:** unbounded admission is what turns the gate's 1 s deadline from a
  one-off into a recurring loss of handshakes.
- **007 ↔ 009:** same hysteria2 receive function — 007 is the copy the fast path
  pays, 009 is what a peer can make the defragmenter allocate.
- **007 → 003:** two halves of the UDP datagram cost — 003 is what an association
  holds before traffic, 007 is what it pays per datagram.
- **008 → 005:** one convention gap, two layers: the mux key's `String` and the
  handshake `Vec` both keep a credential that the rest of the crate zeroizes.
- **010 ↔ 011:** the same three arms read differently in each issue — 010 is
  which arm is chosen, 011 is what the chosen arm does with a chain. Fixing 010
  without 011's guard makes the leak reachable under TLS as well.
- **012 ↔ 008:** both sit in `HeaderFirst`'s wrapper, different mechanisms —
  008 is the buffer that keeps a credential unwiped, 012 is a `poll_write` that
  reports `Pending` after consuming bytes, so the retry re-sends them. 012's
  cause is `AsyncWrite` semantics, not the buffer.
- **012 → 007:** same "bytes we already own are copied again" class; 007 is on a
  protocol's receive side, 012 on a transport's send side.
- **010 → 004:** a plan input (there the row's mux cap, here the ALPN-derived
  HTTP version) is computed, documented, then not consulted at the point that
  dials.
- **013 ↔ 014:** one asymmetry seen from two sides of `init()` — 013 is the read
  side (a caller deadline of 8 s doing the bounding that no inner budget does:
  the connect/handshake bound is a hardcoded 5 s × 3 sends, and 8 s also cuts
  lookups that work), 014 is the fetch side (a 10 s download inside that same
  8 s, cancelled instead of timed out, so its own fallback never runs). A fix for
  one that assumes the other's budget is derived from the caller will re-break
  it.
- **015 ↔ 016:** the same per-datagram pipeline. 016 is the shape (every
  datagram re-routes the flow); 015 is the one bug inside it that a per-flow memo
  would also mask — a hit path that re-writes the cache entry it just read, which
  is both a wasted two-copy store per datagram and a TTL that never expires for
  a host in use. Fix 016 and 015's cost disappears but its staleness stays; fix
  015 and 016's cost stays but stops compounding.
- **013 → 015:** 013 is what a cache *miss* can cost (up to 15 s under an 8 s
  caller deadline); 015 is why a host that already has a cached answer never
  takes that hit again — nor ever picks up a rotated answer.
- **017 → 014:** the same refusal principle from two directions. 014 is a
  silent degradation on the network side (the only bound is the caller's timer);
  017 is one on the policy side (an unrepresentable token is healed by deletion,
  widening the rule). Both are cases where the project's documented pattern is a
  named refusal — `incompatibility` disables a geo row, ADR 0018 refuses an
  undialable config — and neither refuses.
- **018 ↔ 019:** one failure class, two paths: a query priced by a table instead
  of by the rows it needs. 018 pays it per merged pair inside a write
  transaction (a whole-table protocol read plus a whole-table anti-join); 019
  pays it per keystroke on the read path (two full scans of `endpoint_rank`).
  Both are fixable by scoping to the ids already in hand, and neither needs a
  schema change — 019 needs two indexes.
- **020 → 018:** 018's merge path carries the only working instance of
  `discard_where`, and 020 is why it matters: with no foreign key, a missed
  sweep writes an orphan link instead of failing loudly. Three other delete
  paths — delete a profile, "remove failed servers", the retention purge — have
  no sweep at all, and the middle one deletes exactly the endpoints whose
  patches were just staged.
- **021 → 022:** one flow, two ends. 022 is the failure bookkeeping a DNS-retry
  run consumes (`mark_dns_failure` per failed host); 021 is how that run reports
  it is finished. Different modules, same command — and both are wrong in the
  "costs more than it should" direction, 021 permanently (the queue never
  drains) and 022 quadratically.
- **022 → 013:** 013 documents the split between a starved permit and a real
  resolver answer — the rule that a queue wait must not leave a DNS-failure
  stamp. 022 is the cost of the stamp that *is* legitimate: it is written once
  per failed host, and each write currently rescans the whole deferral map.

## Domain coverage

| Domain | Status | Last iteration |
|---|---|---|
| native-inbound | in-progress | 1 |
| mux-pool | in-progress | 2 |
| native-protocol | in-progress | 3 |
| native-transport | in-progress | 4 |
| dns | in-progress | 5 |
| routing-engine | in-progress | 6 |
| db-layer | in-progress | 7 |
| app-ops | in-progress | 8 |
| ui-render | unexplored | — |
| tls-security | unexplored | — |
