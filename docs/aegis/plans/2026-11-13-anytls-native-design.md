# AnyTLS native client — Design Spec Brief + Plan

Date: 2026-11-13
Status: **implemented 2026-11-13**
Owner gap: `crates/leas-native` serves AnyTLS only through the sing-box
subprocess; the native module is a 2-line placeholder and the capability gate
refuses the kind.

## 1. Why this exists

AnyTLS is a TLS-carried, **session-multiplexed** proxy: one TLS connection
carries many logical streams (`cmdSYN`/`cmdPSH`/`cmdFIN`), each stream relays one
TCP destination after a SOCKS5 address; UDP rides sing-box's uot v2
(`sp.v2.udp-over-tcp.arpa`). The wire is specified in
`thirdparty/anytls-go/docs/protocol.md`; the reference client is
`thirdparty/anytls-go/proxy/session`, and `thirdparty/mihomo/transport/anytls`
is a second, vendored implementation (padding + pool + uot confirmed there).

Xray-core has no AnyTLS (verified: `thirdparty/Xray-core/proxy/` has no anytls
arm, `Xray-core v26.11.9`), so the e2e oracles are sing-box and mihomo.

## 2. Scope

In scope (client side only):

1. Authenticated TLS session: `sha256(password) | u16 padding0 len | padding0`.
2. Session framing: `cmd:u8 | stream_id:u32 BE | len:u16 BE | data`, commands 0–10.
3. Padding scheme: default `stop=8` table, server `cmdUpdatePaddingScheme`
   replaces it **for the client object** (later sessions), packet counter per
   `write` of the TLS plaintext, `c` check-marks.
4. Session reuse pool (spec MUST): newest idle session first, idle reaper
   (30 s check / 60 s timeout), one session per link identity.
5. TCP relay: SYN → PSH(SOCKS5 address) → data frames → FIN.
6. UDP relay: uot v2 over a stream to `sp.v2.udp-over-tcp.arpa`, per-packet
   addresses (`isConnect=false` framing) so a SOCKS UDP association keeps its
   per-destination semantics.
7. v2 control handling: `cmdServerSettings`, `cmdSYNACK` (data ⇒ stream error),
   `cmdHeartRequest` → `cmdHeartResponse`, `cmdAlert` ⇒ session close.
8. Capability gate: AnyTLS becomes native-served (password required, no
   transport, TLS mandatory), `initial_auth_ack` = `Unknown` (server settings /
   alert are the only observations).
9. E2E rows against the sing-box and mihomo reference servers (TCP + UDP).

Out of scope: server side, `idleSession*` / `minIdleSession` config fields
(Clash rows already drop them for every backend — pre-existing gap), the
3-second missing-SYNACK session watchdog (mihomo's heuristic; a slow v2 server
would kill healthy sessions), and proxy-chain pooling (only the first link
pools; an AnyTLS link behind another proxy opens a one-stream session).

## 3. Baseline and authority refs

- Wire: `thirdparty/anytls-go/docs/protocol.md`; frame constants
  `thirdparty/mihomo/transport/anytls/session/frame.go`.
- Padding/write semantics: `anytls-go/proxy/session/session.go:418-493`
  (`writeConn`), `proxy/padding/padding.go` (md5 of the raw scheme).
- Pool: `anytls-go/proxy/session/client.go:68-206`.
- uot v2: `$GOPATH/pkg/mod/github.com/sagernet/sing@v0.8.13/common/uot`
  (`protocol.go` family bytes 0x00/0x01/0x02; `conn.go` framing).
- Layer contract: `docs/architecture/architecture.md`, `docs/reference/native-core.md`,
  `docs/reference/protocols.md` (matrix row 14: native `no` → `yes`).
- Implicit TLS: `AnyTlsConfig` stores only explicit TLS overrides
  (`proto_spec/anytls.rs` clash collapse) and `ProtoSpec` had no `security()`
  accessor — both are defects this change fixes at their owner.

## 4. Compatibility boundary

- No DB/schema change: `AnyTlsConfig`'s serialized shape is unchanged.
- `ProtoSpec::security()` for AnyTLS starts returning the stored (possibly
  empty) security — the native dial needs it; subprocess builders already read
  the field directly.
- `LinkContext::is_tls()` starts answering `true` for AnyTLS; `security::wrap`
  treats an empty typed security as **default TLS** for this kind only.
- Public API: `PacketTunnel`/`PacketReader`/`PacketWriter` gain an `AnyTls`
  variant (additive, crate-internal consumers only).
- Capability: `NATIVE_KINDS` gains `AnyTls`; Auto may now resolve AnyTLS rows
  onto native. A mis-implemented wire is the user-visible risk — the e2e rows
  are the gate.

## 5. Change Necessity

The native engine's whole purpose is in-process dialing; AnyTLS is one of the
kinds `SINGBOX_ONLY_KINDS` still forces onto a subprocess. Docs/config cannot
add a wire codec; the code is the only carrier.

## 6. TDD Route

Mode `auto`, decision **strict for the wire codec** (frame codec, padding
engine, uot framing — byte-exact tests with recorded/reference vectors), light
for the pool (behavioral test: reuse newest, idle reaper closes old sessions).
Real-core e2e rows are the acceptance gate.

## 7. Tasks

- **A1** proto: `AnyTlsConfig::security()` accessor (native needs explicit TLS
  knobs).
- **A2** native wiring: `is_tls` + mandatory-TLS default in `security::wrap`.
- **A3** `protocol/anytls/frame.rs` + `padding.rs` (+ byte tests).
- **A4** `protocol/anytls/session.rs`: reader/writer tasks, stream type,
  control commands.
- **A5** `protocol/anytls/client.rs`: identity-keyed pool, dial closure over
  `chain::secured_upgraded`, idle reaper.
- **A6** `protocol/anytls/udp.rs`: uot v2 `PacketConn`.
- **A7** dispatch: `protocol::{connect,connect_udp}`, `chain` first-link pool,
  `PacketTunnel` variants, capability + auth-ack.
- **A8** oracles: `CaseSpec::anytls`, sing-box/mihomo server configs, e2e tests
  (TCP, UDP, multi-stream pool).
- **A9** docs: `docs/reference/protocols.md` matrix + native notes, AGENTS.md
  structure line.

## 8. Execution note

Landed: `protocol/anytls/{frame,padding,session,client,udp,mod}.rs`;
`AnyTlsConfig::security()`; mandatory-TLS default for the kind in
`security::wrap`; `is_tls` arm; `PacketTunnel`/`PacketReader`/`PacketWriter`
variants; capability arm (+ password/REALITY refusals); first-link pooling in
`chain::connect_chain`; oracle builders and `tests/anytls.rs`.

Three deviations, all deliberate: (1) no missing-`cmdSYNACK` watchdog — the
reference closes the whole session after 3 s without one, which a slow v2
server would trip; (2) `idleSession*`/`minIdleSession` are not config fields —
Clash rows already dropped them for every backend, and the client uses the
reference defaults; (3) only the first chain link pools.

Bug found and fixed during e2e: uot's REQUEST destination is read with sing's
default SOCKS5 serializer, NOT the uot family set the per-datagram addresses
use — the first UDP run sent 3 datagrams and received 0 on both cores.

Verification: anytls unit tests 13/13; `leas-native` + `leas-proto` 1228/1228;
workspace nextest 2708/2708 (3 slow, 11 skipped); workspace clippy
`-D warnings` clean; `cargo fmt --check` clean; `leas-oracles` anytls e2e
green on all four rows (TCP and uot UDP against sing-box and mihomo).

## 8. Verification

`cargo nextest run -p leas-native anytls`, then
`cargo nextest run -p leas-oracles anytls` (real cores), then the workspace
gate: `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings`
and `cargo fmt --check`.
