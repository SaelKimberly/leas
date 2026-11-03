# Plan: Sniffer Pane — Per-Host Traffic for the Native Session

- **Date:** 2026-11-03
- **Spec:** [`specs/2026-11-03-sniffer-pane-design.md`](../specs/2026-11-03-sniffer-pane-design.md) (approved 2026-11-03)
- **Status:** draft — awaiting user review
- **TDD Route:** `auto` → **strict** for T2–T4 and T6 (behaviour, cross-crate contract, producer/consumer, accounting invariants); **light** for T1 (dependency wiring), T5 (event plumbing), T7 (rendering + smoke), T8 (docs). Authority: spec §11 acceptance + this plan.

## Goal

Add a `Sniffer` tab to pane 1 that lists the native session's per-host traffic (`host · ↓ · ↑ · conns · failed`), two mirrored 60 s rate sparklines, and a summary line with failures and dropped datagrams — session-only, in memory, honest about what an application-level proxy observes.

## Architecture

`leas-native`'s `Telemetry` gains a host table and an open-leg registry; relayed TCP legs register their existing byte atomics and fold into the table on close, while UDP datagrams increment the table directly. A 1 s sampler in the session task pushes `CoreEvent::SnifferSample` to the TUI, which keeps the sample ring, computes per-host rates against the previous snapshot, and renders the pane. No persistence, no schema change, no external-core coverage.

## Tech Stack

Rust 2024 workspace; `ratatui` pane rendering; `tokio` timers in the native session; `compact_str` for host keys; `smallvec` for snapshots and per-association sets; `parking_lot` mutexes (already a dependency).

## Baseline / Authority Refs

- Spec `2026-11-03-sniffer-pane-design.md` — D1–D13, A1–A10.
- `docs/reference/native-core.md` — native-core module map (telemetry feeds, inbound routing).
- `crates/leas-native/src/telemetry.rs` — current trace/traffic sink contract.
- `crates/leas-native/src/inbound/mod.rs:318-520` — route decision, failure exits, `traced_relay`.
- `crates/leas-native/src/inbound/http.rs:250-320` — HTTP CONNECT refusal exits.
- `crates/leas/src/types.rs:183` — `Pane1Tab`; `crates/leas/src/ui/native_activity.rs` — ring scroll convention to mirror.
- `docs/guides/tui-manual.md` — tab/keys documentation owner.

## Compatibility Boundary

All additions are additive: new `TraceEvent` variant, new `SnifferSnapshot`/`HostStat`/`TraceFailReason` types, new `CoreEvent` variant (binary crate only), new `Pane1Tab` variant before `Logs`. `TraceOpened`, `TraceClosed`, `NativeActivityLog`, the 3 s traffic poller, and the DB are untouched. `TraceEvent` and `CoreEvent` are not marked `#[non_exhaustive]` today; adding arms is a workspace-internal compile change only.

## Change Necessity

No configuration or documentation-only route exists: the data does not exist yet (failures and UDP are untraced), and the pane needs a live read path (open-leg registry). Code is required in three owners: `telemetry.rs` (accounting), `inbound/` (emit points), `ui/` (presentation).

## Ripple Signal Triage

Shared/cross-module contract: `TraceEvent` is a producer (`inbound/`) / consumer (`ops/events.rs`) pair, and `Telemetry` is public in a publishable crate. Canonical owner stays `Telemetry`; no second aggregator is created. Expanded verification: unit tests in the producing crate plus a TUI consumer test for the new event arm; the spec is the contract artifact and `native-core.md` is synced in T8.

## Plan Pressure Test

Owner fit good (`Telemetry` already owns per-leg counters; the TUI owns view state). No `ui/sniffer.rs` split needed beyond one module. Verification is exact (unit + acceptance smoke). Tasks are executable in order; T6/T7 depend on T5's event type, so the route is **inline**.

---

## Task 1: Dependency surface

**Files:**
- Modify: `Cargo.toml` (`[workspace.dependencies]`)
- Modify: `crates/leas-native/Cargo.toml`
- Modify: `crates/leas/Cargo.toml`
- Regenerate: `crates/leas-hakari/src/lib.rs` (via `cargo hakari`)

**Interfaces:**
- Produces: `compact_str` and `smallvec` usable in both crates.

- [ ] **Step 1: Add the workspace dependency**

In root `Cargo.toml`, under the existing `smallvec` line:

```toml
smallvec = { version = "1.16.4", default-features = false, features = ["const_new"] }
compact_str = "0.10.0"
```

- [ ] **Step 2: Add the crate dependencies**

`crates/leas-native/Cargo.toml` (after `parking_lot`):

```toml
# inline host keys / allocation-free snapshots (spec D13)
compact_str.workspace = true
smallvec.workspace = true
```

`crates/leas/Cargo.toml`, same two lines in its `[dependencies]`.

- [ ] **Step 3: Regenerate the workspace hack**

Run: `cargo hakari`
Expected: `leas-hakari` updated (no hand edits).

- [ ] **Step 4: Compile**

Run: `cargo check --workspace`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/leas-native/Cargo.toml crates/leas/Cargo.toml crates/leas-hakari/src/lib.rs Cargo.lock
git commit -m "build: add compact_str and smallvec to the native and TUI crates"
```

---

## Task 2: Host table, open-leg registry, snapshot (strict)

**Files:**
- Modify: `crates/leas-native/src/telemetry.rs`
- Test: `crates/leas-native/src/telemetry.rs` (`mod tests`)

**Interfaces:**
- Consumes: existing `Telemetry { up, down, dropped_logs, dropped_traces }`, `Telemetry::opened`, `Telemetry::guard`, `TraceGuard::emit`.
- Produces (used by T3–T7):

```rust
pub const UNKNOWN_HOST: &str = "(unknown)";

#[derive(Debug, Clone)]
pub struct HostStat {
    pub host: CompactString,
    pub up: u64,
    pub down: u64,
    pub conns: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SnifferSnapshot {
    pub hosts: SmallVec<[HostStat; 16]>,
    pub dropped_bytes: u64,
    pub dropped_datagrams: u64,
    pub failed: u64,
}

impl Telemetry {
    pub fn snapshot(&self) -> SnifferSnapshot;
    pub fn udp_sent(&self, host: &str, bytes: u64);
    pub fn udp_received(&self, host: &str, bytes: u64);
    pub fn udp_dropped(&self, host: Option<&str>, bytes: u64);
    pub fn udp_conn(&self, host: &str);
}
```

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `telemetry.rs`:

```rust
#[test]
fn snapshot_sums_open_legs_and_does_not_double_count_after_close() {
    let (telemetry, _events) = Telemetry::new(16);
    let id = telemetry.opened(TraceKind::Tcp, "example.com:443", "vless", "tcp", TraceSecurity::Tls);
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let mut guard = telemetry.guard(id, Arc::clone(&up), Arc::clone(&down));

    up.fetch_add(100, Ordering::Relaxed);
    down.fetch_add(250, Ordering::Relaxed);
    let live = telemetry.snapshot();
    assert_eq!(live.hosts.len(), 1);
    assert_eq!((live.hosts[0].host.as_str(), live.hosts[0].up, live.hosts[0].down), ("example.com", 100, 250));

    guard.finish(None);
    let closed = telemetry.snapshot();
    assert_eq!((closed.hosts[0].up, closed.hosts[0].down), (100, 250), "fold must not double count");
    assert_eq!(closed.hosts[0].conns, 1);
}

#[test]
fn one_row_per_host_across_ports_and_kinds() {
    let (telemetry, _events) = Telemetry::new(16);
    for dest in ["example.com:443", "example.com:8443", "[2001:db8::1]:53"] {
        let id = telemetry.opened(TraceKind::Tcp, dest, "vless", "tcp", TraceSecurity::Plain);
        telemetry.guard(id, Arc::new(AtomicU64::new(10)), Arc::new(AtomicU64::new(1))).finish(None);
    }
    let snap = telemetry.snapshot();
    assert_eq!(snap.hosts.len(), 2, "ports merge, families do not");
    assert!(snap.hosts.iter().any(|h| h.host == "2001:db8::1"));
}

#[test]
fn snapshot_sorts_by_total_desc_and_keeps_the_inline_buffer() {
    let (telemetry, _events) = Telemetry::new(16);
    for (dest, bytes) in [("a.example:1", 1_u64), ("b.example:1", 5)] {
        telemetry.udp_sent(dest, bytes);
    }
    let snap = telemetry.snapshot();
    assert_eq!(snap.hosts[0].host, "b.example");
    assert!(!snap.hosts.spilled(), "<=16 hosts must stay inline");
}

#[test]
fn udp_bytes_and_drops_land_in_the_table() {
    let (telemetry, _events) = Telemetry::new(16);
    telemetry.udp_sent("dns.example", 40);
    telemetry.udp_received("dns.example", 120);
    telemetry.udp_dropped(Some("dns.example"), 40);
    telemetry.udp_dropped(None, 7);
    let snap = telemetry.snapshot();
    let row = snap.hosts.iter().find(|h| h.host == "dns.example").expect("row");
    assert_eq!((row.up, row.down), (40, 120));
    assert_eq!((snap.dropped_datagrams, snap.dropped_bytes), (2, 47));
}

#[test]
fn the_host_table_evicts_the_least_recently_active_past_the_cap() {
    let (telemetry, _events) = Telemetry::new(16);
    for i in 0..1001 {
        telemetry.udp_sent(&format!("h{i}.example"), 1);
    }
    let snap = telemetry.snapshot();
    assert_eq!(snap.hosts.len(), 1000);
    assert!(snap.hosts.iter().all(|h| h.host != "h0.example"));
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo nextest run -p leas-native telemetry::tests::snapshot`
Expected: compile error — `snapshot`, `udp_sent`, `udp_received`, `udp_dropped` do not exist.

- [ ] **Step 3: Implement**

In `telemetry.rs`:

```rust
use compact_str::CompactString;
use smallvec::SmallVec;

const HOST_TABLE_CAP: usize = 1000;

struct HostRow {
    host: CompactString,
    up: u64,
    down: u64,
    conns: u64,
    failed: u64,
    last_seq: u64,
}

struct OpenLeg {
    host: CompactString,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

pub struct Telemetry {
    // existing fields…
    hosts: Arc<parking_lot::Mutex<HashMap<CompactString, HostRow>>>,
    open: Arc<parking_lot::Mutex<HashMap<u64, OpenLeg>>>,
    pending: Arc<parking_lot::Mutex<HashMap<u64, CompactString>>>,
    seq: Arc<AtomicU64>,
}
```

- `fn host_of(dest: &str) -> &str` — bracketed `[v6]:port` → inside the brackets; otherwise `rsplit_once(':')`; no colon → the whole string.
- `Telemetry::new` initializes the four new fields.
- `opened()` records `pending[conn_id] = host_of(dest)` before emitting.
- `guard()` takes `pending.remove(&conn_id)` and inserts `OpenLeg` into `open`; missing → `UNKNOWN_HOST`.
- `TraceGuard::emit()` folds into `hosts` (insert-or-update `up/down`, `conns += 1`, `last_seq` bump), removes `open[conn_id]`, then emits `Closed`.
- `fn row_mut(&self, host: &str) -> parking_lot::MutexGuard<'_, HashMap<…>>`-based helper: lookup by `&str`; on miss insert; when `len >= HOST_TABLE_CAP` evict the minimum `last_seq`.
- `udp_sent` / `udp_received` / `udp_conn` increment `up` / `down` / `conns`; `udp_dropped` adds to the global counters and, when `Some(host)`, to that row's `dropped`… **correction:** drops are global-only in the snapshot (`dropped_bytes`/`dropped_datagrams`); the host row does not carry a dropped column. Attribute only the global counters; keep the row untouched unless bytes moved.
- `snapshot()`: clone rows; for each `OpenLeg`, add `up/down.load(Relaxed)` into the matching host (creating a row fragment if absent); sort `sort_unstable_by(|a, b| (b.up + b.down).cmp(&(a.up + a.down)));` collect into `SmallVec`.

- [ ] **Step 4: Run them to verify they pass**

Run: `cargo nextest run -p leas-native telemetry::`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add crates/leas-native/src/telemetry.rs
git commit -m "feat(native): host table, open-leg registry, and sniffer snapshot"
```

---

## Task 3: Failure traces (strict)

**Files:**
- Modify: `crates/leas-native/src/telemetry.rs` (`TraceFailed`, `TraceFailReason`, `Telemetry::failed`)
- Modify: `crates/leas-native/src/inbound/mod.rs` (`handle_connect` exits, `TraceCtx::failed`)
- Modify: `crates/leas-native/src/inbound/http.rs` (refusal exits)
- Test: `crates/leas-native/src/inbound/tests.rs`, `crates/leas-native/src/inbound/http.rs` (`mod tests`)

**Interfaces:**
- Consumes: `Telemetry`, `TraceKind`, `UNKNOWN_HOST`.
- Produces:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TraceFailReason { Auth, Malformed, Blocked, Rejected, HijackDns, NoOutbound, Dial }

impl TraceFailReason { pub const fn as_str(self) -> &'static str; }

#[derive(Debug, Clone)]
pub struct TraceFailed { pub kind: TraceKind, pub host: CompactString, pub reason: TraceFailReason }

pub enum TraceEvent { Opened(TraceOpened), Closed(TraceClosed), Failed(TraceFailed) }

impl TraceCtx { pub fn failed(&self, host: &str, reason: TraceFailReason); }
```

- [ ] **Step 1: Failing tests**

`inbound/tests.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_connect_emits_a_failure_trace_and_no_traffic() {
    use crate::telemetry::{NativeEvent, Telemetry, TraceEvent, TraceFailReason};
    let (telemetry, mut events) = Telemetry::new(64);
    let mut config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("block")),
        vec![Outbound { tag: "block".into(), kind: OutboundKind::Block }],
    );
    config.trace = Some(TraceCtx {
        telemetry: telemetry.clone(),
        kind: TraceKind::Tcp,
        protocol: "vless".into(),
        transport: "tcp".into(),
        security: TraceSecurity::Plain,
    });
    let (addr, handle) = spawn_inbound(config).await;

    let target = TargetAddr::new(Host::Domain("blocked.example".into()), 443);
    let ClientResult::Connected { code, .. } = client_connect(addr, None, &target).await else {
        panic!("expected a reply");
    };
    assert_eq!(code, 0x02, "ConnectionNotAllowed");

    let failed = loop {
        match events.recv().await.expect("event") {
            NativeEvent::Trace(TraceEvent::Failed(f)) => break f,
            NativeEvent::Trace(_) | NativeEvent::Log { .. } | NativeEvent::Traffic { .. } => {}
        }
    };
    assert_eq!(failed.reason, TraceFailReason::Blocked);
    assert_eq!(failed.host, "blocked.example");
    let snap = telemetry.snapshot();
    assert_eq!(snap.failed, 1);
    assert_eq!(snap.hosts.iter().map(|h| h.up + h.down).sum::<u64>(), 0);
    handle.abort();
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo nextest run -p leas-native a_blocked_connect_emits_a_failure_trace`
Expected: compile error — no `TraceEvent::Failed`.

- [ ] **Step 3: Implement**

- Add the enum/struct/variant, `TraceFailReason::as_str` (`"auth"`, `"malformed"`, `"blocked"`, `"rejected"`, `"hijack-dns"`, `"no-outbound"`, `"dial"`), and `Telemetry::failed(kind, host, reason)` which increments `HostRow.failed` (creating the row) and the snapshot's global `failed`, then emits `TraceEvent::Failed`.
- `TraceCtx::failed(host, reason)` calls `self.telemetry.failed(self.kind, host, reason)`.
- Emit at every exit before `traced_relay`: auth/negotiation failure in `handle_conn`, malformed request, unknown outbound tag (`NoOutbound`), `Block` (`Blocked`), `Reject` (`Rejected`), `HijackDns`, dial error (`Dial`). Host = request target's host, `UNKNOWN_HOST` when the request never parsed.
- Mirror the same exits in `http.rs` (`write_refusal` sites) with the HTTP trace kind.

- [ ] **Step 4: Run to verify pass**

Run: `cargo nextest run -p leas-native inbound`
Expected: pass (existing trace tests unaffected).

- [ ] **Step 5: Commit**

```bash
git add crates/leas-native/src/telemetry.rs crates/leas-native/src/inbound/
git commit -m "feat(native): trace pre-relay connection failures"
```

---

## Task 4: UDP accounting (strict)

**Files:**
- Modify: `crates/leas-native/src/inbound/mod.rs` (`UdpRelay`, `forward_client`, `forward_direct`, `forward_proxy`, `run_proxy_leg` reply loop)
- Test: `crates/leas-native/src/inbound/tests.rs`

**Interfaces:**
- Consumes: `Telemetry::udp_sent/udp_received/udp_dropped/udp_conn`.
- Produces: no new public type; `UdpRelay` owns `seen: SmallVec<[CompactString; 4]>`.

- [ ] **Step 1: Failing test**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_datagrams_are_accounted_per_host_and_one_conn_per_association() {
    use crate::telemetry::{Telemetry, TraceKind, TraceSecurity};
    let echo_a = spawn_udp_echo().await;
    let echo_b = spawn_udp_echo().await;
    let (telemetry, _events) = Telemetry::new(64);
    let mut config = Socks5InboundConfig::new(
        "127.0.0.1:0".parse().expect("listen addr"),
        engine(Vec::new(), route_default("direct")),
        vec![Outbound { tag: "direct".into(), kind: OutboundKind::Direct }],
    );
    config.trace = Some(TraceCtx {
        telemetry: telemetry.clone(),
        kind: TraceKind::Tcp,
        protocol: "vless".into(),
        transport: "tcp".into(),
        security: TraceSecurity::Plain,
    });
    let (addr, handle) = spawn_inbound(config).await;
    let (stream, reply) = udp_associate(addr).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client udp");

    for (echo, payload) in [(echo_a, b"to-a".as_slice()), (echo_b, b"to-b".as_slice())] {
        let target = TargetAddr::new(Host::new("127.0.0.1"), echo.port());
        client.send_to(&udp_datagram(&target, 0, payload), reply).await.expect("send");
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await.expect("echo reply timed out").expect("recv reply");
        assert!(socks5::parse_udp_request(&buf[..n]).is_ok());
    }

    let snap = telemetry.snapshot();
    let row = snap.hosts.iter().find(|h| h.host == "127.0.0.1").expect("row");
    assert_eq!(row.conns, 1, "one association, two ports: one conn");
    assert_eq!(row.up, 8, "both client payloads counted");
    assert!(row.down > 0, "reply bytes counted");
    drop(stream);
    handle.abort();
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo nextest run -p leas-native udp_datagrams_are_accounted`
Expected: `conns == 0` (no accounting yet) — assertion fails.

- [ ] **Step 3: Implement**

- `UdpRelay` gains `seen: SmallVec<[CompactString; 4]>`; helper `fn note_host(&mut self, host: &str)` calls `telemetry.udp_conn(host)` once per new host.
- `forward_client`: after routing, `udp_sent(&host, payload.len())`; every drop branch calls `udp_dropped(Some(&host), payload.len())` (malformed/fragmented/reject/hijack have no host → `udp_dropped(None, datagram.len())` only where a payload was parsed; otherwise count the datagram with 0 bytes).
- `forward_proxy`: byte cap and queue-full branches call `udp_dropped(Some(&host), payload.len())`.
- `forward_direct`: send errors call `udp_dropped(Some(&host), payload.len())`; successful sends already counted by `forward_client`.
- Reply loop (`run_proxy_leg`) and direct receive loop: `udp_received(&host, payload.len())` using the frame's source address host (fallback to the association's `session_addr`).
- Add the `shortcut:` comment from spec §6 above the per-datagram mutex use.

- [ ] **Step 4: Run to verify pass**

Run: `cargo nextest run -p leas-native inbound`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add crates/leas-native/src/inbound/mod.rs crates/leas-native/src/inbound/tests.rs
git commit -m "feat(native): per-datagram UDP accounting and drop counters"
```

---

## Task 5: Snapshot delivery (light)

**Files:**
- Modify: `crates/leas/src/types.rs` (`CoreEvent::SnifferSample`)
- Modify: `crates/leas/src/ops/native_connect.rs` (1 s sampler arm)
- Modify: `crates/leas/src/ops/events.rs` (exhaustive stub arm)
- Test: `crates/leas/src/ops/events.rs` (`mod tests`)

**Interfaces:**
- Consumes: `Telemetry::snapshot()`.
- Produces: `CoreEvent::SnifferSample(leas_native::telemetry::SnifferSnapshot)`.

- [ ] **Step 1: Add the event and the sampler**

```rust
// types.rs, CoreEvent
SnifferSample(leas_native::telemetry::SnifferSnapshot),
```

```rust
// native_connect.rs, inside run_native_session
const SNIFFER_INTERVAL_SECS: u64 = 1;
let mut sniffer_ticker = tokio::time::interval(std::time::Duration::from_secs(SNIFFER_INTERVAL_SECS));
sniffer_ticker.tick().await;
// select! arm:
_ = sniffer_ticker.tick() => {
    try_send_or_warn(tx, CoreEvent::SnifferSample(telemetry.snapshot()), "sniffer_sample");
}
```

```rust
// ops/events.rs, poll_core_events — keeps the match exhaustive until T6
CoreEvent::SnifferSample(_) => {}
```

- [ ] **Step 2: Compile and run the crate's tests**

Run: `cargo nextest run -p leas ops::`
Expected: pass. The stub arm is replaced by `state.sniffer.record(snapshot)` in T6.

- [ ] **Step 3: Commit**

```bash
git add crates/leas/src/types.rs crates/leas/src/ops/native_connect.rs crates/leas/src/ops/events.rs
git commit -m "feat: push a 1 s sniffer snapshot from the native session"
```

---

## Task 6: TUI state, rates, event handling (strict)

**Files:**
- Modify: `crates/leas/src/types.rs` (`Pane1Tab::Sniffer`, `SnifferState`, re-exports)
- Modify: `crates/leas/src/state.rs` (`sniffer` field, reset)
- Modify: `crates/leas/src/ops/events.rs` (`CoreEvent::SnifferSample` arm)
- Test: `crates/leas/src/types.rs` (`mod tests`), `crates/leas/src/ops/events.rs`

**Interfaces:**
- Produces:

```rust
pub const RATE_SAMPLES: usize = 60;

#[derive(Debug, Clone, Copy, Default)]
pub struct RateSample { pub down: u64, pub up: u64 }

#[derive(Debug, Default)]
pub struct SnifferState {
    pub latest: Option<leas_native::telemetry::SnifferSnapshot>,
    pub samples: [RateSample; RATE_SAMPLES],
    pub head: usize,
    pub filled: usize,
    prev: std::collections::HashMap<compact_str::CompactString, (u64, u64)>,
    prev_total: (u64, u64),
}

impl SnifferState {
    pub fn record(&mut self, snapshot: SnifferSnapshot);
    pub fn reset(&mut self);
    pub fn rates(&self) -> RateSample;        // last sample's per-second totals
    pub fn host_rate(&self, host: &str) -> (u64, u64); // 0,0 if unseen
    pub fn samples_iter(&self) -> impl Iterator<Item = &RateSample>; // oldest → newest
}
```

- [ ] **Step 1: Failing tests**

In `types.rs` `mod tests`:

```rust
#[test]
fn rates_are_the_delta_between_consecutive_snapshots() {
    let mut state = SnifferState::default();
    state.record(snapshot_with(&[("a.example", 100, 10)]));
    state.record(snapshot_with(&[("a.example", 180, 30)]));
    assert_eq!(state.rates(), RateSample { down: 80, up: 20 });
    assert_eq!(state.host_rate("a.example"), (80, 20));
    assert_eq!(state.host_rate("missing"), (0, 0));
}

#[test]
fn the_sample_ring_keeps_sixty_and_evicts_the_oldest() {
    let mut state = SnifferState::default();
    for i in 0..RATE_SAMPLES + 5 {
        state.record(snapshot_with(&[("a.example", u64::from(i as u32) * 10, 0)]));
    }
    assert_eq!(state.filled, RATE_SAMPLES);
    assert_eq!(state.samples_iter().count(), RATE_SAMPLES);
}

#[test]
fn reset_clears_totals_and_history() {
    let mut state = SnifferState::default();
    state.record(snapshot_with(&[("a.example", 10, 0)]));
    state.reset();
    assert!(state.latest.is_none() && state.filled == 0 && state.rates() == RateSample::default());
}
```

(`snapshot_with` is a test helper building `SnifferSnapshot` from `(host, up, down)` triples.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo nextest run -p leas types::tests::rates_are_the_delta`
Expected: compile error — no `SnifferState`.

- [ ] **Step 3: Implement**

- `records` builds `prev`/`prev_total` deltas (saturating), pushes `RateSample` into the ring at `head` (`head = (head + 1) % RATE_SAMPLES`, `filled = (filled + 1).min(RATE_SAMPLES)`), replaces `latest`.
- `samples_iter` yields from oldest to newest (skip unused slots when `filled < RATE_SAMPLES`).
- `Pane1Tab::{Profiles, Sniffer, Logs}`; `ALL`, `next`, `prev` updated (order: Profiles → Sniffer → Logs).
- `AppState` gains `pub sniffer: SnifferState`; `reset_native_activity()` also calls `self.sniffer.reset()` (spec D5 reset site).
- `poll_core_events`: `CoreEvent::SnifferSample(snapshot) => { state.sniffer.record(snapshot); }`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo nextest run -p leas types::tests:: ops::events::`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add crates/leas/src/types.rs crates/leas/src/state.rs crates/leas/src/ops/events.rs
git commit -m "feat(tui): sniffer state, rate deltas, and sample ring"
```

---

## Task 7: Pane rendering and tab plumbing (light + smoke)

**Files:**
- Create: `crates/leas/src/ui/sniffer.rs`
- Modify: `crates/leas/src/ui/mod.rs` (`pub mod sniffer;`, `render_pane1`, `p1_tabs`, key routing)
- Test: `crates/leas/src/ui/sniffer.rs` (`mod tests`) + manual smoke

**Interfaces:**
- Consumes: `AppState.sniffer`, `SnifferState::samples_iter`, `rates`, `latest`.
- Produces: `pub fn render(frame: &mut Frame, area: Rect, state: &AppState)`, `pub fn handle_key(state: &mut AppState, key: &KeyEvent)`, module-local `SCROLL` + `reset_scroll()` (mirror `ui/native_activity.rs`).

- [ ] **Step 1: Render**

Layout: 2 header lines (rates + summary), 2 sparkline rows, remainder table.

- Header line 1: `↓ {format_bytes(down_rate)}/s  ↑ {format_bytes(up_rate)}/s`.
- Header line 2: `hosts {n} · failed {f} · dropped {datagrams} ({format_bytes(bytes)})`.
- Sparklines: custom half-block renderer over `samples_iter()`; top row set draws down bars downward, bottom row set draws up bars upward; shared max = `max(all down, all up).max(1)`; a non-zero value gets at least 1 cell.
- Table: header `host  ↓  ↑  conns  failed`, rows from the snapshot (already sorted), right-aligned byte columns via `format_bytes`, scroll window from the module `SCROLL` offset.
- Empty state when `state.connected_core != Some(CoreType::Native)` or `latest.is_none()`: `No native session — per-host traffic requires the native core`.
- Keys: `Up/Down/PageUp/PageDown/Home/End` adjust `SCROLL`.

- [ ] **Step 2: Wire the tab**

- `ui/mod.rs`: `Pane1Tab::Sniffer => sniffer::render(frame, area, state)` in `render_pane1`; `("Sniffer", matches!(state.pane1_tab, Pane1Tab::Sniffer))` in `p1_tabs` between `Profiles` and `Logs`; key routing arm for the tab (before the Logs arm).
- `ui/mod.rs`: reset the pane scroll when a new session starts, next to the existing `native_activity::reset_scroll()` call.

- [ ] **Step 3: Unit test the renderer's scale law**

```rust
#[test]
fn the_shared_scale_uses_the_larger_series_and_floors_non_zero() {
    let samples = [RateSample { down: 1_000, up: 1 }, RateSample { down: 0, up: 0 }];
    assert_eq!(bars_for(1, shared_max(&samples)), 1, "a tiny non-zero uplink still draws");
    assert_eq!(bars_for(1_000, shared_max(&samples)), super::SPARK_ROWS);
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo nextest run -p leas sniffer`
Expected: pass.

- [ ] **Step 5: Smoke**

Run `cargo run`, connect a native profile, drive traffic through the mixed port (`curl -x socks5h://127.0.0.1:<port> https://example.com` and a DNS query through UDP ASSOCIATE), then check: rows grow, sparklines move, blocked host increments `failed`, disconnect freezes, reconnect clears. Record the observed output in the workflow chat (A1–A8).

- [ ] **Step 6: Commit**

```bash
git add crates/leas/src/ui/sniffer.rs crates/leas/src/ui/mod.rs
git commit -m "feat(tui): Sniffer pane with mirrored rate sparklines"
```

---

## Task 8: Docs and closeout (light)

**Files:**
- Modify: `docs/reference/native-core.md` (telemetry contract)
- Modify: `docs/guides/tui-manual.md` (tab, columns, keys)
- Modify: `docs/architecture/decisions.md` (one bullet under “Native core & TLS”)
- Modify: `docs/aegis/specs/2026-11-03-sniffer-pane-design.md` (status → implemented)
- Modify: `docs/aegis/INDEX.md` (spec status)

- [ ] **Step 1: Telemetry contract**

Add a subsection under the native-core telemetry material: trace events (`Opened`/`Closed`/`Failed`), `TraceFailReason` values, `Telemetry::snapshot` fields, host identity (no port, no local DNS), UDP accounting/drop rules, 1000-host LRU, 1 s `CoreEvent::SnifferSample`.

- [ ] **Step 2: TUI manual**

Document `Sniffer` in the pane-1 tab list, the columns, sort order, sparkline scale rule, scroll keys, empty state.

- [ ] **Step 3: Decision bullet**

Under “Native core & TLS” in `decisions.md`, one bullet: per-host accounting exists only for the in-process core; identity is the destination as sent; live bytes come from the open-leg registry; the snapshot is additive public API.

- [ ] **Step 4: Full gate**

Run:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
```
Expected: all green (record the Summary line).

- [ ] **Step 5: Commit**

```bash
git add docs/
git commit -m "docs: sniffer pane and native telemetry contract"
```

---

## Verification

| check | command |
|---|---|
| native accounting | `cargo nextest run -p leas-native telemetry::` |
| inbound traces + UDP | `cargo nextest run -p leas-native inbound` |
| TUI state math | `cargo nextest run -p leas types::tests:: ops::events:: sniffer` |
| lint (authoritative) | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| suite | `cargo nextest run --workspace` |
| user-visible seam | the T7 smoke (A1–A8) |

## Risks

- **Per-datagram lock**: one `parking_lot` mutex + `&str` lookup per datagram; revisit only on measured contention (spec §14).
- **`TraceEvent` growth**: consumers must handle the new arm in `ops/events.rs` and `Telemetry`'s own fold; `#[non_exhaustive]` is deliberately not added (workspace-internal match).
- **UDP `conns`**: per-association approximation, documented in `tui-manual.md`.
- **`CompactString`/`SmallVec` in public API**: recorded in the spec; no downgrade path is planned, and both crates are already in the graph.

## Retirement

No old path is retired. `NativeActivityLog` and the `Metrics` tab keep the per-connection view; the Sniffer is additive. If a future backend adopts `SnifferSnapshot`, that triggers an ADR and the snapshot type moves behind a backend-neutral trait.

## Execution notes (2026-11-03)

- `SnifferState` keeps only the session total delta and the 60-sample ring — no per-host rate map. D9 fixes the table to totals, so a per-host rate had no consumer; the plan's `host_rate` API was dropped rather than shipped dead.
- `CoreEvent::SnifferSample` carries `Box<SnifferSnapshot>`: with the inline `SmallVec<[HostStat; 16]>` the variant tripped `clippy::large_enum_variant`. One heap allocation per second, on the once-a-second path only.
- The T7 "live smoke" is a `TestBackend` render test (`ui::sniffer::tests::the_pane_shows_the_empty_state_then_host_rows`): a live native session needs a real server and the user's database, neither of which an agent run may touch. A1–A8 are still covered at the unit/integration level; the pane's layout was asserted on a 100×20 backend.
- Direct UDP accounting lives in `UdpRelay::sent`/`drop_datagram`; proxy accounting in `forward_proxy` plus `run_proxy_leg` (reply bytes attributed by the reply's source IP).
- RapidHashMap (rapidhash fast hasher) backs the host/open/pending maps, per the user directive during execution.
