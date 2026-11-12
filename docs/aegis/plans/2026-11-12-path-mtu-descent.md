# Path-MTU descent for proxy dials — implementation plan

Date: 2026-11-12
Spec: `specs/2026-11-12-path-mtu-descent-design.md` (draft, D2 open)
Domain: **dial / socket policy** — `crates/leas-native/src/{path_mss.rs,sockopt.rs,transport/tcp.rs,chain.rs}`
Execution route: **inline** (one crate, ordered tasks).
`User confirmation required: no` — the spec's D1 (always-on) and D3 (quickack) are
implemented as proposed; D2 is decided here as the conservative option.

Aegis Visibility: a process-global policy that changes every proxy dial's advertised
MSS, plus two new socket options. The plan exists because a wrong re-arm rule silently
makes connections slower, and because the stall signal has to be owned by exactly one
place.

## 1. Goal

New proxy dials advertise an MSS that fits a 1400-byte path, descending to the IPv6
minimum only after three consecutive handshake stalls with no success between them.

Acceptance: policy unit tests (descend, reset, floor), a Linux read-back test that the
option reaches a real socket, and no change to the direct outbound dial.

## 2. Architecture / tech stack

- `path_mss.rs` (new, `pub(crate)`-friendly module): `SAFE_MSS`, `FLOOR_MSS`,
  `STALLS_TO_DESCEND`, two atomics, `current()`, `note_stall()`, `note_success()`,
  `reset_for_tests()`.
- `sockopt.rs`: two new `SockOpts` fields, applied through the existing non-fatal
  `apply` (`socket2` 0.6.5 has safe `set_tcp_mss`/`set_tcp_quickack` under its `all`
  feature, which leas already enables — no unsafe, no ADR).
- `transport/tcp.rs`: the dial requests `Some(path_mss::current())`.
- `chain.rs`: the one owner of the stall signal — after a dial succeeded, a
  `NativeError::Timeout` from the security/transport stage is a stall; any successful
  handshake is a success. Three call sites: `connect_chain`, `connect_chain_udp`,
  `finish_chain` (the probe's continuation).

## 3. Baseline and authority refs

- `SockOpts` today: `tcp_user_timeout_ms`, `tcp_keepalive`, `v6only`, `reuse_port`,
  `nodelay`, `tos` (`crates/leas-native/src/sockopt.rs:26-45`); `apply` is non-fatal
  per option (`:66-105`); dial builds the options at
  `crates/leas-native/src/transport/tcp.rs:24-28`.
- Timeout classes: `NativeError::Timeout { step, limit }` (`error.rs`); the security
  handshake is bounded by `timeouts::SECURITY` (`security/mod.rs:95,175,216`), the
  transport upgrade by `timeouts::TRANSPORT`.
- ZeroNet's policy and its stated rationale: `thirdparty/ZeroNet/crates/zero-core/src/path_mss.rs`.
- leas has no network-change monitor (no `network_changed` surface anywhere in
  `crates/`), so the spec's D2 option (a) — never re-arm within a process — applies.

## 4. Compatibility boundary

- Default dial now advertises 1360 instead of the kernel default: ~3% header overhead
  on a 1500-byte path, in exchange for surviving a 1400-byte path whose ICMP is
  blackholed. No config key (D1).
- Windows: both options are Unix-only; `apply` ignores them, as it already does for
  `TCP_USER_TIMEOUT`.
- The direct outbound dial (`inbound/outbound.rs:150`) is untouched.
- No schema, wire, or public API change (`path_mss` is crate-internal).

## 5. Change Necessity

No existing knob expresses "lower our advertised MSS before connect"; `SockOpts`
carries per-dial options but nothing computes a value. Config/docs cannot fix a
handshake that never completes.

## 6. TDD Route

Mode `auto`, decision **strict** for the policy module (it is a state machine whose
whole value is the transition boundary), **light** for the sockopt field and the
wiring. RED: the policy tests are written against `current()`/`note_*` before the
module exists (compile failure is the first red); the read-back test asserts a value
the kernel reports, which fails if the option is not applied.

## 7. Tasks

### M1 — policy module and tests

File: `crates/leas-native/src/path_mss.rs` (+ `pub(crate) mod path_mss;` in `lib.rs`).

Tests: starts at `SAFE_MSS`; three `note_stall()` descend to `FLOOR_MSS`; a
`note_success()` between stalls prevents the descent; the value never goes above
`SAFE_MSS` or below `FLOOR_MSS`; after descending it stays down. Tests reset the
statics first (a test-only `reset()`), because the policy is process-global and
nextest runs tests in one process.

### M2 — socket options

File: `crates/leas-native/src/sockopt.rs`.

`tcp_maxseg: Option<u16>` and `tcp_quickack: Option<bool>`; `is_empty` accounts for
both; `apply` calls `set_tcp_mss(u32::from(mss))` and `set_tcp_quickack(v)` under
`#[cfg(unix)]` / `#[cfg(any(target_os = "linux", target_os = "android"))]`.

Test: on a real unconnected TCP socket, apply `tcp_maxseg: Some(1360)` and read
`socket.tcp_mss()` back. If the kernel clamps on this host, the test asserts the
observed clamp with the reason in a comment rather than a value that only passes on
one kernel.

### M3 — dial wiring and stall signal

Files: `crates/leas-native/src/transport/tcp.rs`, `crates/leas-native/src/chain.rs`.

- Dial: `SockOpts { nodelay: Some(true), tcp_maxseg: Some(crate::path_mss::current()),
  .. }` (quickack applies to the same dial).
- `chain.rs`: one small helper `fn note_handshake<T>(r: Result<T, NativeError>) -> Result<T, NativeError>`
  that calls `note_success()` on `Ok`, `note_stall()` on `Timeout`, and passes other
  errors through untouched. Used at the three sites named in §2.

Test: a `chain.rs` unit test would need a network; instead the classifier is tested in
`path_mss` as `fn note_outcome(&Result<(), NativeError>)` so the classification is
provable without a socket (a `Timeout` descends, a `Dial`/`Tls` non-timeout does not,
an `Ok` resets).

### M4 — verification

`cargo nextest run -p leas-native path_mss` and `sockopt`, then the workspace gate.
The veth/1400-MTU e2e row the spec asks for needs `ip` privileges and a peer; it is
recorded as a manual step in the execution note with the exact commands, not added to
the default suite.

## 8. Risks

- **A wrong descent** costs ~1% more header overhead on a healthy path, permanently
  for the process. Accepted: the alternative is a dead handshake class.
- **A wrong ascent** would oscillate; option (a) cannot.
- `TCP_QUICKACK` is not sticky in Linux (it reverts to normal ACK behaviour), so its
  effect is per-instant. Applied once at dial; if the bench shows nothing, D3 says
  drop it — recorded, not silently kept.

## 9. Retirement

None. Additive module plus two option fields; no old path is deleted.

## Execution note (2026-11-12)

Executed inline. Reviewer findings applied before the commit:

- **Relay:** promotion moved after the write that consumed the read (promoting earlier
  would swap the buffer and discard bytes), and the buffer is now owned by `relay()`
  and passed into `copy_half`, so a test observes promotion through the real loop
  (`copy_half_promotes_on_a_bulk_read_and_not_on_a_short_one`) instead of only through
  `RelayBuf` directly. The ceiling test asserts the pointer does not move, because a
  fresh 64 KiB `Vec` per chunk would keep `capacity()` identical.
- **Path MTU:** the MSS is applied to an **unconnected** `TcpSocket` before `connect`
  (previously applied post-connect, where the kernel ignores it for MSS advertisement);
  the stall evidence is gated on `ctx.is_tls() && !is_quic_link(ctx)`, because a
  plaintext row runs no handshake and a QUIC link has no TCP socket.
- **First flight:** the read path flushes the header instead of arming a 100 ms timer
  (the timer was unobservable and its only effect was a buffered write turning into
  `Pending`); a `Pending` inner write has its own test; the e2e PQ assertion in
  `leas-oracles` peels the new wrapper, and that is why `first_flight` is `pub` with an
  `e2e-support`-only `inner()`.
