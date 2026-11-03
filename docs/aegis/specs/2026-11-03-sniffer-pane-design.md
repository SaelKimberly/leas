# Design: Sniffer Pane — Per-Host Traffic for the Native Session

- **Date:** 2026-11-03
- **Status:** **implemented 2026-11-03** (grilling interview 2026-11-03; plan `plans/2026-11-03-sniffer-pane.md`, execution notes there). Gate: `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo nextest run --workspace` **2613 passed (1 slow), 11 skipped**.
- **Kind:** spec
- **Owners:** `crates/leas-native/src/telemetry.rs` (host table, open-leg registry, snapshot), `crates/leas-native/src/inbound/mod.rs` + `inbound/http.rs` (failure traces, UDP accounting), `crates/leas/src/types.rs` (`Pane1Tab`, snapshot state), `crates/leas/src/state.rs` (sniffer state), `crates/leas/src/ops/events.rs` (`CoreEvent::SnifferSample`), `crates/leas/src/ui/sniffer.rs` (new pane), `crates/leas/src/ui/mod.rs` (tab bar, routing)
- **Extends:** `2026-10-15-pane-tui-and-profiles-columns-design.md` (pane-1 tab bar, shell keys)
- **Reference read:** `thirdparty/sniffnet/src/gui/pages/overview_page.rs` (host cards, top-30, rate card), `thirdparty/sniffnet/src/gui/types/favorite.rs` (per-host totals + bars), `thirdparty/sniffnet/src/networking/types/data_representation.rs` (unit selector — deliberately not adopted, D6)

## 1. Problem

The native in-process core already observes every proxied destination, its byte totals, and its outcome, but the TUI only exposes them as a flat, capped connection ring on the Metrics tab (`NativeActivityLog`, 2000 rows, `crates/leas/src/types.rs:55`). There is no answer to "which hosts did this session carry traffic to, and how much", no live rate view, and no failure visibility for connections that never reached the relay.

The user wants a pane-1 `Sniffer` tab modelled on sniffnet's Overview: per-host statistics, live incoming/outgoing rates, and failure counts — adapted to what an application-level proxy can actually observe.

## 2. Evidence (current code)

| fact | site |
|---|---|
| trace open carries `dest: host:port`, kind, protocol, transport, security | `telemetry.rs:75` |
| trace close carries `up_bytes`, `down_bytes`, `duration_ms`, `error` | `telemetry.rs:90` |
| exactly one `telemetry.opened` call site — relayed TCP legs only | `inbound/mod.rs:448` |
| block/reject/hijack/dial-fail/unknown-tag/auth paths return before it | `inbound/mod.rs:318-440`, `inbound/http.rs` |
| UDP associations emit no trace; `TraceKind::UdpAssoc` exists unused | `telemetry.rs:53` |
| per-leg byte atomics exist and are exact mid-transfer | `telemetry.rs:247,283` |
| shared counters drained every 3 s into `CoreEvent::StatsUpdate` | `native_connect.rs:19,130` |
| telemetry event queue is 16 deep; drops are counted, logged as one line | `native_connect.rs:22`, `telemetry.rs:283-321` |
| `CoreEvent` queue is 65 536 deep | `state.rs:697` |
| pane-1 tabs are `Profiles`, `Logs` only | `types.rs:183` |
| `smallvec` is a workspace dependency; `compact_str` is already in `Cargo.lock` transitively | root `Cargo.toml:79` |

## 3. Decisions

### D1 — Scope: native core only, three leg classes

The pane counts what the in-process listener handled: relayed TCP legs (proxy **and** direct outbounds), **pre-relay failures** (auth, malformed request, Block, Reject, HijackDns, unknown tag, dial failure), and **UDP associations**. Subprocess cores (xray/sing-box) expose no per-host data; the pane renders an explicit empty state there rather than approximate numbers.

### D2 — Identity: the destination string as sent, no port

One row per host string. A domain stays the domain the client requested (the remote proxy resolves it); an IP literal stays an IP literal; the same host reached both ways is two rows. No local DNS lookup is added for identity — it would leak queries, add resolver latency to the hot path, and mis-attribute CDN answers.

### D3 — "Dropped" means undelivered traffic

One bucket over two event classes, split in the summary line:

- UDP datagrams dropped at any branch (`malformed`, `fragmented`, `Reject`, `HijackDns`, proxy byte cap, queue full, proxy leg gone, unresolvable destination, carrier refusal, direct send error) — counted with payload bytes.
- TCP legs that failed or were refused — counted as events; bytes exist only when the leg relayed first.

Host attribution uses the request destination. A failure that never yielded a destination lands in a `(unknown)` row and never contributes bytes.

### D4 — Live bytes come from an open-leg registry

`Telemetry` keeps `conn_id → OpenLeg { host, up, down }`, where `up`/`down` are the same atomics the relay already increments. Snapshot value per host = folded closed-leg totals + the sum of still-open legs. A leg is either open or folded, never both, so no double count.

### D5 — Lifetime and cap

Session-only, in memory. Cleared when a new native session starts (same site as `reset_native_activity`, `ops/events.rs:435`); **not** cleared on disconnect, so the table freezes until the next connect. Host table capped at **1000** rows, evicting the least recently active; an evicted host reappears if it sends again.

### D6 — Units: bytes only

No unit selector. TCP has no packet boundary, so a uniform packet count does not exist; the pane never displays a unit it cannot compute for every row.

### D7 — Rate view: two mirrored sparklines

60 one-second samples. **Down** renders above, **up** below, mirrored. The two series share one vertical scale (max of both maxima) so their sizes are comparable; a non-zero sample always occupies at least one cell. Numeric rates sit in the header.

### D8 — No gauge

The summary is textual: current rates, session totals, host count, failures, dropped bytes/datagrams. The sparklines carry the visual weight.

### D9 — Table: fixed columns, fixed order

`host · ↓ bytes · ↑ bytes · conns · failed`, sorted by `up + down` descending. No sort keys, no row selection.

### D10 — Sampler ownership: the native session pushes

The session task samples its own `Telemetry` every second and sends `CoreEvent::SnifferSample(SnifferSnapshot)`. It already owns the telemetry handle and a ticker; the TUI keeps no native-only handle in `AppState`, and samples arrive even when the UI is busy.

### D11 — `conns` semantics

TCP legs opened, plus UDP associations that exchanged at least one datagram with the host (counted once per association, deduped by a small per-association set).

### D12 — Failure reasons are an enum

`TraceFailReason { Auth, Malformed, Blocked, Rejected, HijackDns, NoOutbound, Dial }`, `#[non_exhaustive]`, rendered through `as_str()`. Free-form strings are not worth the per-event allocation and cannot be aggregated stably.

### D13 — Allocation policy

Per the user directive, avoid avoidable allocations:

| surface | representation | why |
|---|---|---|
| host keys (host table, open legs, snapshot rows) | `CompactString` | inline ≤ 24 bytes — the overwhelmingly common hostname or IPv4 literal never allocates; clones of heap hosts are refcount bumps |
| `SnifferSnapshot.hosts` | `SmallVec<[HostStat; 16]>` | typical sessions have < 16 hosts; the common snapshot costs no heap allocation |
| per-association UDP host set | `SmallVec<[CompactString; 4]>` linear scan | associations touch a handful of hosts; no hashing, no heap until the fifth host |
| UDP lookup | `get_mut(&str)` on `HashMap<CompactString, …>` | borrow lookup, allocation only on first sight of a host |
| sparkline history | fixed `[Sample; 60]` + write cursor | no ring allocation, no growth |
| snapshot sort | in-place `sort_unstable_by` on the `SmallVec` | no scratch buffer |
| failures | `TraceFailReason` + `CompactString` host | no format allocation on the emit path |

`compact_str` and `smallvec` are added as explicit dependencies (`smallvec` already workspace-declared; `compact_str` is already in the lock). Host, open-leg, and pending maps use `rapidhash::RapidHashMap` (the fast hasher the workspace already pins) so the per-datagram lookup pays a cheap hash. No allocation is introduced on the TCP relay hot path — the registry insert happens once per leg. Promoting `compact_str` to a direct dependency changes `Cargo.lock` inputs, so `leas-hakari` is regenerated (`cargo hakari`) in the same change.

## 4. Native data model — `telemetry.rs`

```rust
struct HostRow {
    host: CompactString, // also the map key
    up: u64,
    down: u64,
    conns: u64,
    failed: u64,
    last: Instant,       // LRU eviction key
}
type HostTable = HashMap<CompactString, HostRow>; // cap 1000, LRU by `last`

struct OpenLeg {
    host: CompactString,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

pub struct HostStat {
    pub host: CompactString,
    pub up: u64,
    pub down: u64,
    pub conns: u64,
    pub failed: u64,
}

pub struct SnifferSnapshot {
    pub hosts: SmallVec<[HostStat; 16]>, // sorted by up+down desc
    pub dropped_bytes: u64,
    pub dropped_datagrams: u64,
    pub failed: u64,
}
```

- `Telemetry` gains `hosts: Arc<parking_lot::Mutex<HostTable>>` and `open: Arc<parking_lot::Mutex<HashMap<u64, OpenLeg>>>`; both are `Arc` so the cloned `Telemetry` handles share them.
- `opened()` derives the host key from `dest` (strip `:port`, unbracket IPv6) and records it as `pending[conn_id]`; it cannot register the leg yet because the atomics do not exist at emit time.
- `guard(conn_id, up, down)` moves `pending[conn_id]` into `open` with those atomics (`(unknown)` if the pending row is missing). `TraceGuard::emit()` folds `up`/`down` into the host row, increments `conns`, and removes the open leg before emitting `Closed`.
- UDP never enters `open` (its bytes are live in the host table by construction). Four methods keep the association off the registry: `udp_sent(host, bytes)`, `udp_received(host, bytes)`, `udp_dropped(host: Option<&str>, bytes)`, `udp_conn(host)` — each one map lookup, no allocation unless the host is new.
- `snapshot()` walks the table and the open map once, merges open bytes, sorts, and returns.
- `NativeActivityLog`, `TraceOpened`, `TraceClosed`, and the 3 s traffic poller are unchanged.

## 5. Failure tracing

New variant in the existing enum (same channel, same consumer):

```rust
pub enum TraceEvent {
    Opened(TraceOpened),
    Closed(TraceClosed),
    Failed(TraceFailed),
}

pub struct TraceFailed {
    pub kind: TraceKind,
    pub host: CompactString, // "(unknown)" when no destination was parsed
    pub reason: TraceFailReason,
}
```

Emitted through one helper, `TraceCtx::failed(kind, host, reason)`, from every pre-relay exit in `handle_connect`, the HTTP CONNECT handler, and the UDP forwarding branches. `TraceEvent::Failed` increments `HostRow.failed` and the snapshot's `failed` total; it never touches byte totals.

## 6. UDP accounting

Per datagram, at the branches that already exist:

| direction / branch | accounting |
|---|---|
| client datagram forwarded (direct or queued to proxy) | `host.up += payload.len()` |
| reply delivered to the client | `host.down += payload.len()` |
| any drop branch (D3 list) | `dropped_bytes += payload.len()`, `dropped_datagrams += 1`, and `host` when the destination parsed |
| association joins a host | `conns += 1` once per (association, host) — deduped by the association's `SmallVec<[CompactString; 4]>`, no lock |

Reply attribution uses the reply's source address (proxy carriers report it; otherwise the association's resolved session address, matching `run_proxy_leg`). Downlink for a host the table has not seen creates the row. One mutex acquisition + `&str` lookup per datagram; allocation only on first sight of a host. Documented as a `shortcut:` comment — revisit with sharding only if profiling shows contention.

## 7. Snapshot delivery — `ops/native_connect.rs`

- `run_native_session` adds a 1 s `interval` arm beside the existing 3 s ticker: `try_send_or_warn(tx, CoreEvent::SnifferSample(telemetry.snapshot()), "sniffer_sample")`.
- `CoreEvent` gains `SnifferSample(SnifferSnapshot)` (binary crate, not published).
- A full channel skips one sample; snapshots are cumulative, so totals self-heal and only one sparkline bar is lost.
- Sampling runs regardless of the visible tab; cost is one pass over ≤1000 hosts + open legs per second.

## 8. TUI

- `Pane1Tab::{Profiles, Sniffer, Logs}`; `next`/`prev`/`ALL` updated; existing `[`/`]` keys and `Tab` focus work unchanged.
- `types.rs`: `SnifferState { latest: Option<SnifferSnapshot>, samples: [Sample; 60], head: usize, filled: usize, prev: HashMap<CompactString, (u64, u64)> }`; `record()` computes per-host rate deltas and the total sample.
- `state.rs`: `pub sniffer: SnifferState`; reset alongside `native_activity` on a new native session; `reset_scroll`-style module offset in `ui/sniffer.rs`.
- `ops/events.rs`: `CoreEvent::SnifferSample` → `state.sniffer.record(sample)`.
- `ui/sniffer.rs`: header line (`↓ rate ↑ rate · totals · hosts · failed · dropped`); two mirrored sparklines drawn with one small custom half-block renderer (top grows downward, bottom grows upward, shared scale, 1-cell floor); table with the D9 columns; `Up/Down/PageUp/PageDown/Home/End` scrolling; empty state when nothing is connected or the core is not native.
- `ui/mod.rs`: `render_pane1` arm, `p1_tabs` entry, key routing for the tab.

## 9. Lifecycle and failure modes

- Not connected / external core: one hint line, no table.
- Disconnect: frozen table, no further samples.
- New native session: totals, samples, and rates reset.
- Evicted host: row disappears; recreated on next activity.
- Capture anomalies (a `Closed` with no `Opened`): the fold creates a row from the close's host when the open row is missing, mirroring `NativeActivityLog`'s ghost-row rule.

## 10. Non-goals

No persistence, no schema change, no per-host history, no port dimension, no unit selector, no per-host rate column, no DNS resolution for attribution, no coverage of subprocess cores, no Services/Programs cards (no local port→process map).

## 11. Acceptance

| id | observable |
|---|---|
| A1 | With a native session connected, proxying a TCP request to `example.com:443` shows one `example.com` row whose ↓/↑ grow while the transfer runs. |
| A2 | A blocked destination produces a `failed += 1` (and a `(unknown)` row only when no destination parsed); no byte total changes. |
| A3 | A UDP association carrying DNS/QUIC shows the destination host with accumulated up/down bytes and exactly one connection increment per association. |
| A4 | A dropped datagram (proxy queue cap or unresolvable destination) increments `dropped_datagrams`/`dropped_bytes` and no host byte total. |
| A5 | The two sparklines move within ~1 s of traffic starting and share one scale; a small non-zero uplink still renders. |
| A6 | Rows sort by total descending on every sample. |
| A7 | Disconnect freezes the table; the next native connect clears it. |
| A8 | With an xray/sing-box session, the tab shows the empty-state hint. |
| A9 | The pane is allocation-free per snapshot for ≤16 hosts (verified by a counting-allocator test in `leas-native`). |
| A10 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo nextest run --workspace` green. |

## 12. Testing

`leas-native` (unit): open-leg fold with no double count; snapshot sums live bytes mid-leg; failure emission per pre-relay branch; UDP up/down/drop counters; unknown-destination row; 1000-row LRU eviction; association `conns` dedupe; `SmallVec`/`CompactString` snapshot allocation count.

`leas` (unit): tab cycle; `record()` rate math and the 60-sample ring; sort order; reset/freeze lifecycle; empty state; `CoreEvent::SnifferSample` handling.

Smoke (manual, before completion): run the app against a native profile, drive a TCP download and a UDP DNS lookup through the mixed port, observe rows, rates, failures, and the frozen post-disconnect table.

## 13. Artifacts and doc gate

| artifact | when |
|---|---|
| this spec + one `docs/aegis/INDEX.md` row | now |
| telemetry contract subsection in `docs/reference/native-core.md` (new trace variant, snapshot API, accounting rules) | with implementation |
| `Sniffer` tab + keys in `docs/guides/tui-manual.md` | with implementation |
| one bullet under “Native core & TLS” in `docs/architecture/decisions.md` | at closeout, if the accounting semantics survive implementation (prove-then-record) |

No ADR now: no schema cursor, owner, dependency direction, or compatibility boundary moves. If a future backend must adopt the same snapshot contract, that becomes the ADR's trigger.

Doc Necessity Gate: durable surface = public API of the publishable `leas-native` crate (`TraceEvent::Failed`, `TraceFailReason`, `Telemetry::snapshot`, `SnifferSnapshot`, `HostStat`) plus cross-crate data semantics, so a spec is required; `native-core.md` is the reference owner of the contract and is updated in the same change.

## 14. Risks

- **Per-datagram lock** on the shared host table: bounded by one uncontended `parking_lot` mutex per association task; revisit with sharding only on measured contention.
- **`CompactString`/`SmallVec` in a published API**: both are already in the dependency graph; the exposure is recorded here rather than discovered later.
- **UDP `conns` is an approximation** (per-association, not per-flow); documented in the pane's column semantics.
- **Blocked/refused legs now appear twice** in the UI: once as a log line and once as a Sniffer failure count. Accepted — they answer different questions.
