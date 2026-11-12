# Path-MTU descent for proxy dials — Design Spec Brief

Date: 2026-11-12
Status: **implemented 2026-11-12** — plan `plans/2026-11-12-path-mtu-descent.md`.
Origin: `thirdparty/ZeroNet` @ `29e7a95` audit, `docs/research/2026-11-12-zeronet-zray-analysis.md` §3, §7.
Owner gap: `sockopt.rs` owns "which options a dial may request"; nothing owns a
*socket-size policy across dials*.

---

## 1. Why this exists

Many Iranian paths carry less than 1500 bytes — PPPoE at 1492, mobile GTP tunnels
near 1400 — and drop the ICMP "fragmentation needed" replies path-MTU discovery
depends on. The result is a black hole: the SYN and the small ClientHello pass, the
server's full-size certificate flight never arrives, and the handshake times out.
ZeroNet's project exists for exactly these networks and documents the same failure
(`zero-core/src/path_mss.rs:1-30`).

The remedy is one `setsockopt` before connect: lower the MSS *we advertise*, so the
server never sends a segment we cannot take. Cost: 40 bytes of header per packet —
under 3% — and no probe traffic, no allocation.

leas could not do this before the plan: `SockOpts` covered `TCP_USER_TIMEOUT`,
keepalive, `SO_REUSEPORT`, `IPV6_V6ONLY`, `TCP_NODELAY` and `TOS`, and its module doc
lists `SO_MARK`, `SO_BINDTODEVICE`, `TCP_CONGESTION` and `TCP_FASTOPEN_CONNECT` as
needing an ADR because `socket2` has no safe API for them
(`crates/leas-native/src/sockopt.rs:1-14`).

**That constraint does not apply here.** `socket2` 0.6.5, with the `all` feature leas
already enables, exposes `Socket::set_tcp_mss` and `Socket::set_tcp_quickack`
(`socket2-0.6.5/src/sys/unix.rs:1651-1674`, `:1813-1845`), both safe, both
`#[cfg(feature = "all")]` and non-Windows. No ADR, no `forbid(unsafe_code)` exception,
no new crate.

## 2. Scope

- `crates/leas-native/src/sockopt.rs`: two new `SockOpts` fields, `tcp_maxseg` and
  `tcp_quickack`, applied through the existing `apply_to_stream`.
- A new `crates/leas-native/src/path_mss.rs`: the two-step policy and its counters.
- `crates/leas-native/src/transport/tcp.rs:24-28`: the proxy-server dial reads the
  policy value; the two call sites that classify an attempt outcome feed
  `note_stall`/`note_success`.

**Out of scope:** the direct (non-proxied) outbound dial (`inbound/outbound.rs:150`).
Domestic paths are exactly the ones that should keep the kernel default; shrinking
their MSS would cost throughput for nothing.

## 3. The shape

```rust
pub const SAFE_MSS: u16 = 1360;   // 1400-byte path minus IPv4 + TCP headers
pub const FLOOR_MSS: u16 = 1220;  // 1280-byte IPv6 minimum minus 60 bytes
pub const STALLS_TO_DESCEND: u32 = 3;
```

- `current() -> u16` — what new proxy dials advertise.
- `note_stall()` — called when a proxy dial reached the server but the handshake
  produced no reply within `timeouts::SECURITY`/`PROTOCOL`. Three in a row with no
  useful connection between them descend to `FLOOR_MSS`.
- `note_success()` — any completed handshake resets the stall run.
- The policy only goes down within a run (D2 covers getting back up).

`tcp_quickack` is in scope because it is the same one-line change and the same
latency problem: with a bulk download the ACK delay interacts badly with a shrunken
MSS. It is applied on the proxy dial only (D3).

## 4. Compatibility boundary

- Default behaviour change, visible in throughput: a 1360 MSS is ~3% header overhead
  on a 1500-byte path that would have worked. That is the buy-in; D1 lets it be
  turned off.
- Setting MSS before connect is what makes it take effect on the SYN; applied after
  connect it only affects our own segments, which is not the failing direction.
- No schema or config change if D1 keeps this internal. If D1 exposes it, it is a new
  `#[serde(default)]` key and cannot fail an old `config.json` load.
- Windows: both options are Unix-only; `apply_to_stream` ignores them, as it already
  does for `TCP_USER_TIMEOUT` (`sockopt.rs:61-105`).

## 5. Verification

1. Unit: `apply_to_stream` with `tcp_maxseg: Some(1360)` and `Some(1220)` then a
   `tcp_mss()` read-back equal to the request on Linux; `Some(1220)` on a live socket
   is the honest test, since the kernel may clamp.
2. Policy unit: three `note_stall()` calls descend, an interleaved `note_success()`
   prevents the descent, and `current()` never exceeds `SAFE_MSS`.
3. e2e: an `leas-oracles` row that sets an interface MTU of 1400 on a veth pair and
   completes a TLS handshake through it. This is the row that proves the black hole is
   actually fixed rather than the option merely accepted by the kernel.
4. Workspace gate as usual.

## 6. Decisions (settled at implementation)

- **D1 — always-on, internal.** `transport/tcp.rs` requests
  `Some(path_mss::current())` on every proxy dial; no config key. The direct outbound
  is untouched.
- **D2 — how the policy re-arms.** Decided: option (a), never within a process. The
  implementation is `path_mss.rs` with two atomics and no ascent. ZeroNet resets only on a network change, which
  needs a netmonitor leas does not have (no `network_changed` surface anywhere in the
  crates). Options: (a) never re-arm within a process — conservative and simple, one
  restarted TUI is one re-arm; (b) re-arm after 10 minutes with no stall and at least
  one success; (c) re-arm after N successes. **Proposed: (a)** for the first slice,
  because a wrong descent costs ~1% header overhead while a wrong ascent costs a
  dead handshake class, and (a) cannot oscillate. Revisit with evidence.
- **D3 — `TCP_QUICKACK`.** Applied once at dial (proxy dial only, no config). The
  kernel resets it after internal protocol events, so it is not tracked; if the
  oracles' relay bench shows nothing, removing the one line is the follow-up.
