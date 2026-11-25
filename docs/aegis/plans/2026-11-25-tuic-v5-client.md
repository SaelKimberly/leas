# TUIC v5 client — implementation plan

Date: 2026-11-25
Spec: [`../specs/2026-11-25-tuic-v5-client-design.md`](../specs/2026-11-25-tuic-v5-client-design.md)
Status: **ready to execute**

## Goal

Serve `ProtocolKind::Tuic` in the in-process core: TCP CONNECT, UDP `native` (QUIC DATAGRAM), UDP `quic` (one uni stream per packet), exporter auth, heartbeat, opportunistic 0-RTT with transparent first-write retry. Prove it against the pinned sing-box and mihomo servers.

## Architecture

`leas-native` is the only code owner. TUIC is a `ConnectShape::Quic` link: the QUIC dial replaces dial + transport + security. A pure `wire.rs` owns every byte; `quic.rs` owns quinn/TLS/auth/driver; `stream.rs` owns the bidi CONNECT stream; `udp.rs` owns associations.

```
context/server -> quic::dial -> auth task -> stream::TuicConnect (TCP)
                                      \----> udp::UdpConn (UDP)
wire.rs: auth, CONNECT, PACKET, DISSOCIATE, HEARTBEAT, address, fragment/defrag
```

## Tech stack

Rust 2024, tokio, quinn 0.11.12 (quinn-proto 0.11.19), rustls 0.23 ring, `bytes`, `uuid`. No new dependency. Sibling pattern: `protocol/hysteria2/{mod,quic,udp}.rs`.

## Baseline / authority refs

- Spec §2 (wire), §3 (design), D1–D8.
- `thirdparty/mihomo/transport/tuic/v5/{protocol,packet,frag}.go` — on-disk v5 wire codec.
- `thirdparty/sing-box/protocol/tuic/{inbound,outbound}.go`; sing-quic v0.7.2 client at `7e0a5869a5f4`.
- `thirdparty/ferrox/crates/ferrox-core/src/tuic.rs` — independent codec.
- `crates/leas-native/src/protocol/hysteria2/{quic,udp}.rs` — house QUIC/stream/UDP shape.
- `crates/leas-native/src/transport/quic.rs` — shared endpoint/TLS/0-RTT helper.
- `crates/leas-native/src/capability.rs`, `protocol/mod.rs`, `chain.rs`, `error.rs`.
- `crates/leas-oracles/src/e2e/{case,config,harness}.rs`, `tests/hysteria2.rs` — e2e shape.

## Compatibility boundary

- No schema, working-directory, or dependency change.
- `SUPPORT_REVISION` 2 → 3 clears persisted “not testable” verdicts once.
- Rows native cannot honour (bad UUID, unknown congestion/UDP mode, REALITY/absent TLS, overlong ALPN) are refused by `capability` and fall back to sing-box; they are never silently dialed differently.
- TUIC v4/v6, `udp_over_stream`, server role, and connection pooling stay out.
- No `leas-proto` parsing change.

## TDD Route

- Mode: `auto`. Decision: `strict` for T1/T3/T4 behavior (new wire contract, producer/consumer, regression-sensitive); `light` for T2/T5 wiring (focused type/compile + existing suite) and T6/T7 (docs/oracle config).
- Authority: auto strict signals — new wire protocol, new public protocol arm, state transitions, error classes.
- Test posture: golden bytes and boundary tables first; then minimal implementation; wiring verified by compile + capability tests + e2e.
- Verification: `cargo nextest run -p leas-native <filter>` per task, then workspace gate; `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings`; `cargo fmt --check`; `cargo nextest run -p leas-oracles tuic`.

## Tasks

### T1 — `wire.rs`: sans-I/O codec + golden tests

Files: `crates/leas-native/src/protocol/tuic/wire.rs`, `mod.rs`.

- Constants: version 5, commands, max domain 255, auth 50, connect header max 261, packet header 10, continuation marker `0xff`.
- Address: encode into caller buffer / decode borrowed; IPv4/IPv6/domain; reject empty, >255, unknown ATYP, truncated.
- Auth: stack `[u8; 50]`.
- CONNECT: stack header `[u8; 261]`; port BE.
- PACKET: encode first/continuation fragments; parse prefix into borrowed packet; exact-length parser; validate `frag_total != 0`, `frag_id < total`, `payload_len`, marker.
- `Fragmenter`: plan by `max_datagram_size`; first cap `max - 10 - addr_len`, continuation `max - 11`; total ≤255.
- `Defragger`: key `(session, packet)`, 64 live, 10 s TTL caller-supplied `now`, out-of-order, duplicate/mismatched total drop, one-pass sweep.
- `DISSOCIATE`/`HEARTBEAT` stack arrays.
- Tests: exact golden bytes from mihomo/sing-quic; every truncation; trailing bytes; fragment boundaries; defrag expiry. RED before implementation.

### T2 — `quic.rs`: dial, TLS, auth, phase, driver

Files: `crates/leas-native/src/transport/quic.rs`, `crates/leas-native/src/protocol/tuic/quic.rs`.

- Add `quic_tls_config_alpns(ctx, &[Vec<u8>])`; existing `quic_tls_config` delegates with one element; cache key includes the list.
- TUIC dial owns `Connecting` + `into_0rtt()` and keeps `ZeroRttAccepted` (do not reuse `transport::quic::connect`).
- Build TUIC `TransportConfig`: 300 s idle, no keep-alive, datagrams, large incoming uni credit, congestion factory (`cubic`/`new_reno`/`bbr`).
- Handshake task: await acceptance (bounded by `timeouts::DIAL`), export 32-byte token (`label = uuid raw bytes`, `context = password`), write auth on one uni stream, publish `Phase::{Accepted,Rejected,Failed}`.
- Heartbeat task: `05 04` DATAGRAM every 10 s, stops on connection close/shutdown.
- UDP driver: `accept_uni` + `read_datagram` + control channel; parse PACKET replies; forward complete packets; ignore HEARTBEAT/unknown command; close on unknown version/malformed PACKET.
- Tests: phase slot wake, congestion mapping (pure), ALPN list/split, no handshake in unit tests.

### T3 — `stream.rs`: CONNECT + 0-RTT retry

Files: `crates/leas-native/src/protocol/tuic/stream.rs`.

- `TuicConnect` AsyncRead/AsyncWrite over one bidi stream, holds connection + phase slot.
- Header staged in stack buffer. First write composes `header || payload` in one exact `Vec`; only that write may be early.
- Later writes/reads return `Pending` until phase resolves.
- `Accepted`: continue; drop replay buffer.
- `Rejected`: open a fresh bidi stream on the same connection, write the replay buffer once, continue.
- `Failed`: io error. Drop resets send; no graceful finish required.
- Server-first read flushes the header first.
- Tests: a pure phase state-machine test with a duplex/mock stream where possible; e2e covers the QUIC path.

### T4 — `udp.rs`: native and quic lanes

Files: `crates/leas-native/src/protocol/tuic/udp.rs`.

- `UdpConn`/`UdpReader`/`UdpWriter`; reusable send `Vec`; `session` u16, `packet` wrapping.
- `native`: one DATAGRAM when the frame fits `max_datagram_size()`; otherwise fragments; `UnsupportedByPeer` → quic lane; `TooLarge` → one conservative re-split then error.
- `quic`: one uni stream per frame, `write_all`, `finish`.
- Driver channel: bounded 64, `try_send`, drop on pressure; defrag complete packets.
- Drop/`split`: dissociate via control, driver exits; `PacketTunnel` halves share the session lifetime without keeping the driver alive.
- Tests: send lane selection with a fake datagram sink where practical; parser/defrag already in T1; e2e covers real QUIC.

### T5 — dispatch, chain, capability, probe verdict

Files: `protocol/mod.rs`, `protocol/tuic/mod.rs`, `chain.rs`, `capability.rs`.

- `connect_quic` Tuic arm; `connect_chain_udp_inner` Tuic arm; `PacketTunnel`/Reader/Writer variants and split.
- `NATIVE_KINDS` + `kind_supported` + `SUPPORT_REVISION` 3.
- `tuic_reason`: UUID parses; TLS present and not REALITY; ALPN tokens ≤255; congestion ∈ {cubic,new_reno,bbr}; UDP mode ∈ {native,quic}; `security_reason` includes Tuic for ECH validation.
- `initial_auth_ack` stays `NotApplicable` (default covers it; add an explicit test).
- Update capability tests: `Tuic` leaves `non_native` (18 rows), positive config passes, each refusal names its reason.
- Verify dispatch compiles and existing native tests pass.

### T6 — Documentation truth

Files: `docs/reference/native-core.md`, `docs/reference/protocols.md`, `docs/aegis/INDEX.md`, plan/spec status.

- Native-core table: TUIC native/e2e yes; QUIC transport note.
- Protocols §9: native column, cubic default correction, UDP lanes.
- Index status moves to implemented after e2e green.

### T7 — Oracle: sing-box + mihomo TUIC inbound

Files: `crates/leas-oracles/src/e2e/{case,config}.rs`, `crates/leas-oracles/src/oracle_adapters/config_builder/{singbox,mihomo}.rs`, `crates/leas-oracles/tests/tuic.rs`.

- Add `CaseSpec::tuic(udp_mode)` and `ProtocolKind::Tuic`, `client_params_tuic`, `tuic_inbound` (sing-box JSON + mihomo `listeners:` YAML), server users `{uuid: password}`, ALPN `h3`, harness cert/key.
- Rows: TCP plain (domain/IPv4/IPv6 targets), UDP native, UDP quic, oversized datagram, idle heartbeat, wrong password (close, no cred verdict), 0-RTT sing-box true/false.
- If mihomo cannot express a row, that row runs sing-box only with a recorded reason; the other rows must run both.

### T8 — Verification and closeout

- `cargo nextest run -p leas-native` (all native tests).
- `cargo nextest run -p leas-oracles tuic` (real cores; `LEAS_CORE_BIN_DIR` as the existing harness requires).
- `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings`.
- `cargo fmt --check`.
- `just quality-gate code` if the environment can run it.
- Report per-row evidence; do not claim a row that did not run.

## Change Necessity

- User-visible need: TUIC rows cannot dial natively; they always spawn sing-box.
- No-change option: leave the placeholder and keep subprocess fallback. Rejected by the request.
- Minimum boundary: one protocol module tree + dispatch/capability/chain arms + oracle rows. No schema or dependency change.

## Ripple signal triage

- Canonical owner: `protocol/tuic/` for wire/dial; `capability.rs` for admission; `chain.rs` for the UDP datagram variant.
- Downstream: `PacketTunnel` consumers (inbound UDP relay, probe), `probe` auth verdict, oracle config.
- Contract risk: 0-RTT rejection fallback, UDP lane switching, close-code non-evidence.
- Verification: golden bytes + real-core e2e + capability refusals.

## Risks

1. 0-RTT rejection semantics are quinn-specific; the stream wrapper must be tested through a real resumed handshake, not only unit code.
2. mihomo's TUIC inbound may not expose 0-RTT; that row is sing-box-only with reason.
3. BBR numerical behaviour differs from quic-go; no benchmark claim.
4. Per-dial connection cost remains; pool deferred by D2.

## Execution route

Inline. Shared files (`protocol/mod.rs`, `chain.rs`, `capability.rs`) and one workspace mean subagents would serialize on the same owner. Coordinator is the only Git mutation owner. `User confirmation required: no`.
