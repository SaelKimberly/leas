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

## Domain coverage

| Domain | Status | Last iteration |
|---|---|---|
| native-inbound | in-progress | 1 |
| mux-pool | in-progress | 2 |
| native-protocol | in-progress | 3 |
| native-transport | unexplored | — |
| dns | unexplored | — |
| routing-engine | unexplored | — |
| db-layer | unexplored | — |
| app-ops | unexplored | — |
| ui-render | unexplored | — |
| tls-security | unexplored | — |
