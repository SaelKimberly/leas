# WireGuard in `leas-native` — implementation plan (T1–T9)

Date: 2026-11-26
Spec: [`../specs/2026-11-26-wireguard-native-design.md`](../specs/2026-11-26-wireguard-native-design.md) (draft, grilled)
Status: **executed 2026-11-26 (T1–T9).**

Landed: `keys`, `kdf`, `core/{transport,handshake,device}`, `stack/{net,flow,link,dns}`, `pool`; `leas-dns` `PlainResolver` arm with the alive-window policy; `dial` branch + chain refusal; capability flip (`SUPPORT_REVISION` 4, `non_native_kinds_unsupported` 17) with a value-bearing `wireguard_reason`; ADR 0019; native-core/decisions/AGENTS docs; hakari regenerated. Evidence so far: `leas-native` + `leas-dns` 991/991, `leas-dns` 23/23, clippy `-D warnings` clean on the three touched crates. T9 landed in `leas-oracles` (every e2e row lives there). The first cut used a `boringtun` dev-dependency peer; once the pinned **sing-box** and **xray-core** oracles passed, it was removed. `tests/wireguard.rs` now drives the native stack against sing-box's `wireguard` endpoint (userspace netstack, route action overriding the peer destination onto a loopback echo) for TCP/UDP, 128 KiB and chunked transfers, 20 % loss, half-close, keepalives and a silent-tunnel retransmit; `tests/wireguard_oracle.rs` proves one request each through the sing-box endpoint and xray's `wireguard` inbound. Rows that found real defects: the interface needs a default route per family (a `/32` address routes nothing), `padded_len` must not subtract header/tag from the MTU, and a connected UDP socket's ICMP `ECONNREFUSED` (a core that is not listening yet) must not tear the device down.

## Goal

A WireGuard profile dials natively: SOCKS5 TCP and UDP ASSOCIATE carry traffic through a user-space IP stack fed by a sans-I/O WireGuard codec; target DNS resolves through the tunnel via `leas-dns`; `capability` admits the kind; `probe.rs` Real Test exercises it end to end.

## Architecture

```text
protocol/wireguard/
  keys.rs   base64/hex keys, clamp/precompute, zeroize
  kdf.rs    KDF1/2/3 = RFC 2104 HMAC-BLAKE2s
  core/     handshake.rs (msgs, MACs, cookie), transport.rs (seal/open, replay, reserved),
            device.rs (Tunnel: now -> Vec<Event>, timers, session rotation, staged queue)
  stack/    net.rs (smoltcp Device + Interface driver), flow.rs (TcpFlow/UdpFlow), dns.rs
  pool.rs   WgPool: one device per profile identity
```

Owner split: `core/` never sees a socket, a runtime or a clock (`now: u64` in, `Event`s out). `stack/` is the only async surface. `leas-dns` gains an address-routing arm with caller-supplied sockets (§3.7 of the spec).

## Tech stack

Rust 2024, tokio, `smoltcp = "0.14.0"` (`medium-ip`, v4+v6, tcp+udp, `iface-max-addr-count-2`), existing `chacha20poly1305 0.11`, `blake2 0.11`, `hmac 0.13`, `x25519-dalek` (workspace), `base64` (workspace), `hickory-resolver 0.26` via `leas-dns`. `#![forbid(unsafe_code)]` stays.

## Baseline / authority refs

`thirdparty/wireguard-go` (`device/{kdf_test,noise_test,cookie_test}.go` = vectors; `noise-protocol.go`, `cookie.go`, `timers.go`, `constants.go`), `thirdparty/ferrox` (`ferrox-core/src/wireguard/*`, reserved-byte rule), `thirdparty/ZeroNet` (`wg_stack.rs` driver shape, `vendor/netstack-smoltcp/PATCHES.md` lifecycle list), `thirdparty/shoes` (smoltcp recovery warning).

## Compatibility boundary

No schema change, no identity change (`WireguardConfig` fields are already identity-covered), no new `ProtocolKind`. `capability::SUPPORT_REVISION` 3 → 4 clears stale `[n-a]` markers once. `protocol::connect`'s WireGuard arm stays as an unreachable guard. WireGuard may only be the single link of a chain. `leas-dns`'s public `lookup_ip` keeps working unchanged for the app.

## TDD route

`TDD Route: auto` → **strict** for T1–T3 (new protocol/crypto core: vectors and byte layouts are the contract) and **light** for T4–T9 (wiring/stack, verified by the e2e rows and the gate). Authority: this plan, per the spec's acceptance bar A.

## Tasks

**T1 — keys + KDF (strict).** `keys.rs`: base64/hex decode of 32-byte keys, zero-key rejection, `public_key`, static-static precompute, `Zeroizing` wrappers. `kdf.rs`: KDF1/2/3 over HMAC-BLAKE2s. RED: the three `kdf_test.go` vectors (KDF2/KDF3 = t0/t1/t2) as an `#[rstest]` table; GREEN: implement. Files: `protocol/wireguard/{keys,kdf}.rs`, `Cargo.toml` (`base64`, `x25519-dalek`). Verify: `cargo nextest run -p leas-native wireguard`.

**T2 — messages + MACs (strict).** `core/transport.rs`/`core/handshake.rs`: the four message layouts as fixed-size arrays, `mac1`/`mac2`/cookie derivation, reserved stamp-after-MAC rule. RED: layout sizes (148/92/64/16+n+16), `mac1` verify-after-zeroing with `reserved=[1,2,3]`, cookie reply round-trip, replay window (in-order, out-of-order, duplicate, ceiling). GREEN: implement. Verify: same command.

**T3 — handshake + device state machine (strict).** `core/device.rs`: `Tunnel::{new,initiate,send,receive,poll}` with `now: u64`, `Event::{Datagram,KeypairEstablished,Expired}`, timer constants from `constants.go`, staged queue, session rotation, TAI64N. RED: two in-memory tunnels complete a handshake and agree on transport keys; a lost response retransmits at 5 s; give-up at 90 s; rekey at 120 s; sends refused at 180 s; a keepalive is an empty record. GREEN: implement.

**T4 — netstack (light).** `stack/net.rs`: smoltcp `Device` (`Medium::Ip`, MTU from config), `Interface`, `SocketSet`, one driver task woken by socket/flow/timer; `stack/flow.rs`: `TcpFlow` (`AsyncRead`+`AsyncWrite`, bounded rings, shutdown-on-FIN-queued, abort-on-drop) and `UdpFlow`; limits (live-socket cap = `max_connections`, 120 s handshake linger, retransmitted-SYN dedupe). Verify: unit rows for flow backpressure + a loopback round-trip through a stub device.

**T5 — pool + dispatch (light).** `pool.rs` (`WgPool` keyed by profile identity, 5 min idle teardown), `inbound::outbound::dial` branch, chain restriction, `protocol::connect` guard test. Verify: dispatch tests, chain-refusal test.

**T6 — `leas-dns` plain arm (light).** `HybridConn::Plain`, public provider constructor taking `Arc<dyn PlainDnsSockets>`, `install_plain_servers`, alive window, `DnsScope` sibling of `lookup_ip`. Verify: `cargo nextest run -p leas-dns` + one loopback UDP resolver test.

**T7 — tunnel DNS wiring (light).** `stack/dns.rs` implements `PlainDnsSockets` over netstack flows; `protocol/wireguard` installs plain servers from `WireguardConfig::dns` under the §3.7 policy. Verify: unit row that the policy selects tunnel/local from config, and the fallback fires only when nothing is alive.

**T8 — capability + docs (light).** Remove the WireGuard refusal, bump `SUPPORT_REVISION` 3 → 4, `non_native_kinds_unsupported` 18 → 17, `WireGuardConfig` doc note, `native-core.md` rows, ADR 0019, `AGENTS.md` bullet, `cargo hakari`.

**T9 — e2e oracle (light).** `leas-oracles`: sing-box `wireguard` endpoint as the server + local TCP/UDP echo; rows: TCP echo, UDP echo, tunnel DNS, induced loss, reserved bytes, wrong key. Verify: `cargo nextest run -p leas-oracles wireguard`.

## Review round 1 (2026-11-26, independent reviewer)

Verdict was **reject** on five blockers, all fixed and regression-tested:

| Finding | Fix |
| --- | --- |
| Probe never reached `outbound::dial` — a Real Test TCP-dialled the UDP port | `chain::dial_transport` branches WireGuard to `pool::open`; `finish_chain` passes the already-target stream through; probe keeps its transport/protocol spans |
| Recv dequeued then dropped a chunk on a full flow channel (silent corruption) | dequeue only while `channel.capacity() > 0` |
| Partial `send_slice` ignored; pending chunk overwritten | `write_pending` drains what the socket took; pending chunks append; shutdown deferred until data is in the socket (a `close()` on `SynSent` aborted the flow) |
| TCP sockets never freed; FIN/RST never reached the flow | reclaim on `Closed`/`TimeWait`/`CloseWait` (after draining), 12 s connect timeout, socket+channel+flow removed together so the flow sees EOF |
| `Event::Failed` ignored — a dead tunnel hung every flow | `Dead` when the give-up had no session; `WgLink` returns an error, the driver exits, channels close |

Majors fixed: replay behind-window rejection + capped clear loop; new-handshake-on-silence (15 s); `persistent_keepalive` implemented; UDP destinations resolve through the tunnel resolver; padding capped at the MTU (reference `send.go`); TAI64N base + monotone nanos; pool identity includes `dns`; UDP bind failure is an error; UDP multi-link placement guarded; link outbox (no cancellable flush); zero deadline yields; exact `REJECT_AFTER_MESSAGES`.

## Review round 2 (2026-11-26, same reviewer)

Verdict **approve-with-fixes**; the core was declared correct, and the driver had three P1s:

| Finding | Fix |
| --- | --- |
| P1 idle-tunnel starvation: `poll`-produced keepalive/retransmit datagrams sat in the outbox because it was drained only at loop top | flush right after the poll event block, before the deadline |
| P1 backpressure: a flow that drained its channel freed capacity with no command, so the driver parked with bytes still in the socket | `read_wake: Arc<Notify>`, signalled by `TcpFlow::poll_read`/`UdpFlow::recv_from` and awaited in the driver's `select!` |
| P1 dead device never evicted — every later connection failed with "stack is closed" | evict a cached device whose command channel is closed |
| P2 `poll_shutdown` dropped the FIN on a full channel | park on the same `Notify` as `poll_write`; the test now asserts the FIN is queued, not lost |
| P2 reclaiming `CloseWait` aborted a connection that could still write | `CloseWait` closes the flow's channel (EOF) after draining; only `Closed`/`TimeWait` are reclaimed |
| P2 UDP recv dequeued then dropped on a full channel | mirror the TCP capacity guard |
| P3 `dns_identity` folded `None`/`Some(false)` | keep all three states |
| P3 UDP session target resolved on the host even with a tunnel resolver | tunnel-only when a resolver exists (`leas-dns` applies the permitted fallback) |

New rows: `an_idle_tunnel_sends_keepalives` (server datagram counter grows while idle) and `a_chunked_transfer_arrives_in_order` (4 KiB writes ⇒ many `TcpWrite`s, so append-vs-replace is observable).

## Review round 3 (2026-11-26, same reviewer)

Verdict **reject**; two of my round-2 edits had silently not applied, which the review proved:

| Finding | Fix |
| --- | --- |
| Blocker: `poll_shutdown` still dropped the FIN on a full channel (the round-2 edit never landed; the test certified the bug) | the parking implementation is in place and the test is inverted (`shutdown_waits_for_room_instead_of_dropping_the_fin`) |
| Blocker: `CloseWait` closed the read channel that was also the write-liveness gate, so the writable tail was dropped | write/shutdown/retry gates now use `flows` (removed only at reclaim); `tcp_channels` removal is the read EOF |
| Blocker: the link flush was still at loop entry, not after `poll` (same silent no-op) | flush sits right after the poll event block, before the deadline — proven red without it by `a_handshake_retransmit_leaves_a_silent_tunnel` (peer-side datagram count) |
| Major: split `UdpReader` never signalled `read_wake` (the production association path) | `UdpReader` carries the wake and notifies after each datagram |
| Major: association session target still host-resolved for `WireGuard` | eager resolve only for the pooled path; a carrier resolver means tunnel-only, no `.or(host_answer)` fallback |
| Minor: pool eviction could remove a device another caller just installed | check + remove under one lock, on the locked entry |
| Minor: `Drop` close commands could be lost; UDP sockets were never reclaimed; `UdpOpen` had no cap | driver treats a closed flow channel as an implicit close (TCP orphan linger, UDP retire at once), `UdpOpen` honours `max_sockets` |
| Minor: `pending_tcp_writes` unbounded | `MAX_PENDING_WRITE` (256 KiB) + a deferred-command queue; the bounded channel is what parks `poll_write` |
| Nit: padding near the MTU | `next_multiple_of(16).min(mtu)` for content ≤ mtu, matching `calculatePaddingSize`; near-MTU rows added |

## Review round 4 (2026-11-26, same reviewer)

Verdict **reject**; fixed:

| Finding | Fix |
| --- | --- |
| Blocker: `UdpClose` removed an already-retired socket — smoltcp `remove` panics and kills the whole device | the map removal is the gate (`udp_channels.remove(..).is_some()` plus the token check); red-proven by `a_repeated_udp_close_never_frees_a_live_socket` (without the guard: `handle does not refer to a valid socket`, driver channel closed) |
| Major: one capped socket froze every write on the device (deferred-queue head + `cmds.recv` gate) | replaced by **per-flow credit**: the driver returns bytes as it writes and notifies that flow; `poll_write` parks on its own credit, never on another flow's progress |
| Major: `poll_shutdown` parked on a per-flow notify the driver never fires | the stack now carries a shared `space` signal fired after every popped command; `poll_write`/`poll_shutdown` park on it for a full channel |
| Major: a dead socket with pending bytes could never be reclaimed (`finished` required an empty pending buffer) | `finished` no longer requires it; reclaim returns the credit and notifies |
| Minor: late commands could hit a reused `SocketHandle` | every TCP/UDP command carries the open `token`; mismatches are ignored |
| Nit: `padded_len` above the MTU / replay distance in counters | unreachable branch documented; replay uses the reference's block distance (127 blocks), with boundary rows |

New rows: UDP association round trip through a **split** reader (40 datagrams, exercises `read_wake` + capacity), remote-FIN tail (EOF on reads, writes still accepted), driver UdpClose retire race. UDP socket metadata raised to 64 so a burst is buffered, not dropped.

## Review round 5 (2026-11-26, final reviewer)

Verdict **approve-with-fixes**; the core was declared sound, four P2s fixed:

| Finding | Fix |
| --- | --- |
| mac2 covered the stamped reserved bytes (WARP + cookie would be dropped) | `set_mac2` before `set_reserved`; row `mac2_is_computed_before_the_reserved_stamp`, red-proven with the old order |
| replay window compared block distance, not the reference's 8128 counters | `last - counter > 8128` per `replay.go:52`; boundary rows at 8128 (examined) / 8129 (refused) |
| a reclaimed socket or an exited driver left the writer parked on credit | per-flow `dead` flag: reclaim and every `run` exit mark it (`fail_device`), a non-live write returns its credit, `poll_write`/`poll_shutdown` return `BrokenPipe`; row `a_driver_exit_fails_every_open_flow` |
| the DNS fallback was unbounded and the association used the unscoped lookup | `PlainEntry.fallback_used` gates it to one `tracing::warn!` per installed resolver; the association resolves with `lookup_ip_scoped`; `pool.rs` no longer warns per lookup |

## Verification

Per task as above; final `just quality-gate code`. Real-core evidence is T9. `just hotpath` unaffected (no hot-path row added).

## Risks

See spec §7. The loss row (T9) decides plain 0.14 vs the cfal fork (needs its own ADR). `reserved` is unit-proven, not WARP-live. The DNS fallback is a bounded leak by user decision.

## Retirement

`protocol/wireguard/mod.rs`'s placeholder comment goes with T5; the `not_impl("wireguard")` arm stays as a guard, its comment changed to say so (no dead path: a test pins it).
