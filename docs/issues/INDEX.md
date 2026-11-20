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

## Cross-references

- **001 → 002:** the missing admission cap is the only thing that would bound
  how many write-stalled tunnels coexist; 002 is why one of them never ends.
- **001 → 003:** 003's per-association cost is a constant; 001 is what makes the
  total unbounded.
- **002 ↔ 003:** both are "what ends this?" gaps in the inbound's resource
  lifetimes — one on the TCP relay's write, one on the UDP association's owner.

## Domain coverage

| Domain | Status | Last iteration |
|---|---|---|
| native-inbound | in-progress | 1 |
| mux-pool | unexplored | — |
| native-protocol | unexplored | — |
| native-transport | unexplored | — |
| dns | unexplored | — |
| routing-engine | unexplored | — |
| db-layer | unexplored | — |
| app-ops | unexplored | — |
| ui-render | unexplored | — |
| tls-security | unexplored | — |
