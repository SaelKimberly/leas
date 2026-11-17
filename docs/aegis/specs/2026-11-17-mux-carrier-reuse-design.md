# MUX carrier reuse — Design Spec

Date: 2026-11-17
Status: **approved 2026-11-17; S0–S3 implemented and executed.** Oracle mux matrix: 17 rows
pass on the pinned cores (mux.cool, vision+mux, smux/yamux, h2mux×sing-box, pooled XUDP and
sbox UDP); two mihomo h2mux rows are `#[ignore]`d with the interop-gap evidence recorded in
§12.1.
Origin: this session's live diagnosis (one TLS/gRPC tunnel per SOCKS leg; 1.8–5 s dial,
~30 % failure under a 12-connection burst) and the user decision set of 2026-11-17
(approach "C-hybrid", MUX **on** by default, sing-box wire interop, 8 streams / 8 carriers,
own modules rather than third-party crates).
Owners touched: `leas-native` (`transport/mux.rs`, new `transport/sbox/`, new
`mux_pool.rs`, `protocol/{vless,ss}/mux.rs`, `inbound/outbound.rs`, `context.rs`,
`chain.rs`, `capability.rs`), `leas-proto`, `leas-config`, `leas` (settings), `leas-oracles`.
Reference pins: `thirdparty/sing-mux` `caf09fe` (2026-09-28), `thirdparty/smux`
(SagerNet fork) `f373f1e` = `v1.5.50-sing-box-mod.1`, `thirdparty/yamux` `17017e9` =
`v0.1.2` — the versions `thirdparty/sing-box` @ `824dbcf` actually pins in its `go.mod`
(`sing-mux v0.3.10-0.20260929204512-caf09fe32475`, `sagernet/smux v1.5.50-sing-box-mod.1`,
`hashicorp/yamux v0.1.2`). `thirdparty/**` is gitignored; these pins are recorded here only.

---

## 1. Why this exists

Every local SOCKS/HTTP CONNECT dials its **own** proxy carrier. For a mux row the tunnel
is then used for exactly one session (`protocol/ss/mux.rs:25-30` says so verbatim;
`mux_session.rs:1-16` defers the pool). Consequences measured on the live profile
(2026-11-17, apt run + scripted probe):

- one TCP + TLS/REALITY + gRPC/h2 + VLESS handshake per request: **1.8–5.0 s** per CONNECT dial;
- 4/12 standards-compliant CONNECTs failed outright in a small burst; apt's 122-parallel run
  produced 24 `socks5 inbound: outbound dial failed` and bursts of
  `grpc response: stream closed because of a broken pipe` on independent legs at the same ms;
- Settings → Mux persists `MuxConfig` that **no connect path reads** (`ops/settings.rs` is the
  only consumer); a row's `mux=N` is parsed and its magnitude then discarded;
- `connect_chain` has no aggregate deadline (10 s × DIAL/SECURITY/TRANSPORT/PROTOCOL), so a
  hung carrier stalls the **CONNECT reply** (not the greeting — that is answered before routing)
  beyond a client's 10 s read timeout.

So the defect is not "MUX missing" but "reuse missing"; enabling mux today adds framing and
buys nothing.

## 2. Scope

In scope:

1. A **carrier pool** for the protocol-mux layer, keyed per profile, with per-carrier stream
   cap, per-profile carrier cap, idle close, eviction, and pool-owned keepalive.
2. An **aggregate connect budget** for building a carrier (and for evicting a bad one).
3. **Own sbox wire implementation** (`smux`, `yamux`, `h2mux`, request/padding handshake) as
   in-tree modules — no new dependencies — wire-compatible with the pinned references.
4. A **per-profile mux wire field** (`muxcool` default; `h2mux`/`smux`/`yamux`), because a
   VLESS link does not encode which server implementation answers it.
5. Making the Mux settings live (cap, padding, wire default) or deleting the dead fields.
6. Transport-level reuse for XHTTP (`xmux`-style) as the "transport is already multiplexed"
   arm of the same policy.
7. The session-id allocator fix that pooling makes mandatory.
8. **UDP through the same carriers**: mux.cool XUDP associations and sbox UDP streams are
   sessions on the pooled carrier, not a separate transport. Pooling must not change either
   wire (existing `xudp_tls`/`xudp_reality` rows stay green).

Out of scope:

- server-side mux (leas is a client);
- QUIC-family protocols and VLESS-over-QUIC transport (existing `quic_guard` refusal stays);
  QUIC's own multiplexing is not a mux carrier and no UDP-over-QUIC path is pooled;
- multi-stream gRPC (one h2 stream per carrier; VLESS target rides the mux stream);
- changing `reply_for`'s SOCKS reply-code mapping (tracked as a separate defect);
- VMess/Trojan mux (no wire in this tree, and prior art disables mux for Trojan);
- padding for MUX.Cool (the protocol has none).

## 3. Decisions (locked)

- **D1 — one reuse layer, chosen by transport.** Protocol mux when the carrier is a single
  logical stream; transport-level stream reuse when the transport already multiplexes
  (XHTTP). Matrix in §5.
- **D2 — MUX on by default** (user decision). Per-profile off must restore today's
  per-leg behaviour exactly. This contradicts every surveyed client (v2rayN, v2rayNG, xrat,
  ferrox ship off; Xray docs: mux is for handshake latency, not throughput) and is accepted
  with the 8/8 caps and the per-profile switch as mitigation.
- **D3 — 8 streams per carrier, 8 carriers per profile** (defaults; configurable).
- **D4 — sing-box wire interop** in addition to MUX.Cool, implemented in-tree.
- **D5 — per-profile wire**, default `muxcool` from `MuxConfig.wire_default`; `muxtype=` rows
  are no longer `Invalid` but select their own wire. Precedence: **row `muxtype` > the
  profile's `wire_default` > `muxcool`.** `wire_default` only seeds a row that has no
  `muxtype`; a stored per-row wire is never overridden by a later config change. Wrong wire ⇒
  named failure, never silent fallback.
- **D6 — gRPC stays mux-over-one-stream.** Multi-stream h2 is rejected as nonstandard.
- **D7 — own modules, no crates.** `smux 0.2`/`yamux 0.14` (crates.io) were considered and
  dropped: sing-box uses the **SagerNet smux fork**, so the reference is `thirdparty/smux`.
- **D8 — default-on applies only to families that have a wire**: VLESS (mux.cool/sbox) now;
  SS-plugin rows keep their own `mux=` plugin option (prior art disables mux for SS);
  everything else is unchanged. A VLESS row carrying a `flow` (Vision) is **never** pulled
  onto mux by the default — Xray rejects TCP mux under XRV, so such a row muxes only when it
  spells `mux` itself (prior art disables mux for flow too). An `xhttp` transport row is
  excluded from default-on for the same class of reason: prior art forces mux off for XHTTP
  (v2rayN resets it, v2rayNG disables it), because XHTTP multiplexes at the transport layer
  (§5, S3).
- **D9 — Vision pairs with MUX.Cool only.** `connect_mux` already dispatches a Vision flow to
  `connect_mux_vision` (`vless/mod.rs:366-380`, addon + camouflage + vision codec), and
  `leas-oracles` proves the row against sing-box (`tests/vless.rs:261`). Xray rejects TCP mux
  under an XRV flow **by design** (`inbound.go:178-189`: command=Mux under XRV is the XUDP
  path, so a TCP `New` frame fails); sing-box (via sing-vmess) and mihomo both accept it —
  mihomo applies `vision.NewConn` and then `case vless.CommandMux:
  vmess.HandleMuxConnection` (`listener/sing_vless/service.go:114-142`). The current
  `capability.rs:296-310` refusal is stale relative to the shipped codec; it becomes "Vision
  + mux requires wire `muxcool` and names the sing-box/mihomo-only caveat", never a silent
  refusal, and sbox wires never pair with Vision. Vision also requires TLS/REALITY over
  **TCP** (the shipped `connect_mux_vision` refuses anything else), so a Vision row over
  WS/gRPC/XHTTP stays a named refusal. This also fixes the §8.5 mapping: `muxcool` is not
  equivalent to "Xray" — it is the only wire Vision can ride.

## 4. Current state (evidence)

| Fact | Site |
| --- | --- |
| One tunnel per dial, one session per tunnel | `inbound/outbound.rs:100-108`, `mux_session.rs:1-16`, `protocol/ss/mux.rs:25-30` |
| Mux predicate is row-only, derived once | `context.rs:63-66`, `86-95` |
| `VlessMux::Limited(n)` magnitude never used | `leas-proto/src/proto_spec/vless.rs:117-139` |
| `MuxConfig` dead (only settings UI reads it) | `leas-config/src/app_config.rs:196-234`, `leas/src/ops/settings.rs:525-535`, `676-690` |
| Session ids `AtomicU16`, wrap overwrites a live entry | `transport/mux.rs:566-590` |
| No stream cap / semaphore; `CHUNK_SIZE` 8 KiB; writer queue 32; session queue 8 | `transport/mux.rs:93`, `466`, `471` |
| One writer error kills the whole carrier; demux HoL | `transport/mux.rs:660-700`, `771-786` |
| No aggregate deadline | `chain.rs:155-195`; `error.rs` `timeouts::{DIAL,SECURITY,TRANSPORT,PROTOCOL}` = 10 s |
| Wire = MUX.Cool only; `muxtype` refused | `capability.rs:272-310`; `transport/mux.rs:80-105` |
| Vision×mux: codec ships it, gate refuses it | `vless/mod.rs:366-380`, `connect_mux_vision:425`, oracles `vless.rs:261`; `capability.rs:296-310` |

## 5. Reuse layers

| Transport | Reuse layer | Why |
| --- | --- | --- |
| raw TCP, WS, HTTPUpgrade | protocol mux (MUX.Cool / sbox) | carrier is a single logical stream |
| gRPC, HTTP | protocol mux inside the carrier | one h2 stream per carrier (D6); VLESS target rides mux |
| XHTTP | transport-level pool (`xmux`-style) | XHTTP already multiplexes requests; nesting mux is redundant |
| KCP | protocol mux | carrier is a byte stream |
| QUIC-family protocols, VLESS-QUIC | none | out of scope (existing refusal) |

Policy resolution for one dial:

1. transport has transport-level reuse (XHTTP) → `xhttp_pool` path; mux framing off.
2. family has a protocol-mux wire (VLESS, SS-plugin opt) **and** effective mux is on → pool.
3. otherwise → today's per-leg dial (unchanged).

Effective mux = row `VlessMux` if present (`Limited(0)`/`Invalid` = off; `Limited(n>0)`/`Unlimited`
= on) else `MuxConfig.enabled` (default on only for VLESS, D8), then the capability gate
(Vision rows: MUX.Cool only, §8.5; sbox padding vs wire, §8).

## 6. Pool contract

- **Key** (`MuxKey`) — the wire-visible carrier identity, built field-by-field, **never**
  `hash(ProtocolConfig)`:
  - protocol kind and credentials (`uuid`/`password`);
  - endpoint: host, port, resolved IP;
  - transport kind and its params (ws/httpupgrade path+host+headers, grpc service/authority,
    xhttp path/mode, kcp seed/mask, …);
  - security kind and its params (TLS: SNI/ALPN/fingerprint/insecure; REALITY: public key,
    short id, server name, fingerprint);
  - flow; wire; padding.

  Excluded from the key: `remarks`, the row's `mux` cap and enabled flag (D8/§5 policy), the
  inbound tag, and the row id — two rows with identical carrier identity share a carrier and
  their sessions stay isolated. Caps and idle policy are applied per acquire from the
  requesting row/profile, not baked into the key. The target is not part of the key
  (MUX.Cool carries it per frame; sbox carries it per stream).
- **Structure**: `MuxPool` per profile (or a global map keyed by `MuxKey`), holding
  `Vec<Arc<Carrier>>`; `Carrier { tunnel, live_streams, opened_at, last_used, dead }`.
  `MuxTunnel` is not `Clone` (`protocol/mod.rs:488-496`), so carriers are `Arc`.
- **Acquire**: pick the carrier with the fewest live streams that is alive and
  `live_streams < cap`; if none, dial a new carrier while `carriers.len() < max_carriers`;
  otherwise dial a temporary carrier outside the pool for that one stream (bulk overflow,
  mirrors Xray's `MaxConnection` spill).
- **Release**: on session drop/EOF; decrement; if the carrier has zero streams and has been
  idle for 16 s, close and remove it. Keepalive is owned by the pool, not by the session
  (today the pool cannot exist because `MuxClient` is held by the session —
  `mux_session.rs:7-17`).
- **Eviction**: `dead` flag, writer error, demux exit, or idle expiry → remove; the next
  acquire re-dials. Never hand a session to a carrier observed dead after allocation
  (double-check, same pattern as `transport/mux.rs:566-600`).
- **Budget**: one deadline for `dial → security → transport → protocol` (default 15 s for a
  single-hop profile; a chain gets `links × 15 s`, still one ceiling per carrier), applied in
  `connect_chain`/pool build. It replaces four independent 10 s steps, so it is neither the
  sum nor a per-step cap; it is one value, configurable, and a slow-but-successful handshake
  must still fit it. A pool eviction + redial uses the same ceiling; the SOCKS reply is
  written within it.
- **UDP sessions** ride the same pool: an XUDP association is a mux.cool session (our
  existing `open_udp_session` allocates a session id and carries an 8-byte GlobalID; the
  server keys the NAT mapping by GlobalID), and an sbox UDP association is one sbox stream
  (`[2B flags][addr]` request with flags UDP=1, then `[2B BE len][datagram]` per datagram —
  a stream-local frame, unrelated to mux.cool's `[2B meta_len]…` frames). Both are acquired,
  released and capped exactly like TCP sessions; a carrier with UDP sessions is not idle.
  Pooling changes no UDP wire byte.
- **Shutdown**: profile switch/`shutdown` drops the pool; in-flight sessions abort with the
  carrier (same visibility as today's `TraceGuard` close rows).
- **Ids**: `next_id` is a plain `fetch_add(1)`; the only wrap handling is rejecting id 0
  (`transport/mux.rs:566-590`). A reused id is therefore not impossible: after the counter
  wraps, an id equal to a **still-live** session (a long download plus churn on the same
  carrier) is inserted and overwrites that session's entry. Reachable, not routine — the
  16 s idle close only fires at zero live streams, so a carrier with one long-lived stream is
  never idle and can accumulate > 65 536 opens. Fix: skip-live allocation (scan past occupied
  ids), not a wrap error. Ids stay 16-bit on the wire.
- **Isolation**: a writer error still kills the carrier, but each session sees EOF/error
  rather than a shared panic; HoL is bounded by the 8-stream cap.

## 7. Wire — MUX.Cool (existing)

Unchanged: VLESS command `0x03`, `v1.mux.cool`/9527, frame
`[2B meta_len][2B sid][1B status][1B opt][target?][2B data_len][payload]`, statuses
New/Keep/End/KeepAlive, options Data/Error, 8 KiB chunks. Pool work only changes carrier
lifetime and id allocation (which becomes per-carrier still — the pool does not change the
wire).

## 8. Wire — sbox (new, in-tree)

Reference: `thirdparty/sing-mux@caf09fe` (`protocol.go`, `protocol_conn.go`, `padding.go`,
`h2mux.go`, `session.go`, `client.go`).

### 8.1 Handshake (part of the stream, not an option)

```
[1B Version][1B Protocol]
Version ∈ {0,1}; Protocol 0=smux 1=yamux 2=h2mux
if Version == 1:  [1B PaddingFlag]
                 if PaddingFlag: [2B PadLen BE][PadLen bytes]   # PadLen = 256 + rand(0..512)
```

- **Version0 carries no padding byte at all**: the layout is exactly the two leading bytes, so
  a Version0 client cannot request padding; padding exists only in Version1 (the Go
  `ReadRequest`/`EncodeRequest` agree — there is no flag to renegotiate afterwards).
- These bytes are **prepended to the first payload write** (`protocol_conn.go:33-45`,
  `EncodeRequest`): one write, header first. Our implementation must do the same (the
  `HeaderFirst` discipline).
- A padding-enabled sing-box inbound (`multiplex.padding=true`) rejects Version0 and
  Version1-without-padding at `ReadRequest`; a version outside `0..=1` is rejected there too.
- Protocol bytes then hand over to smux/yamux/h2mux.

### 8.2 Per-stream framing

Before payload: `[2B flags BE][addr]` — **no leading version byte** (the reference's
`streamRequestLen` still counts one, but `EncodeStreamRequest` does not write it; that is a
harmless over-allocation, not wire content). `flags: UDP=0x1, Addr=0x2`; address is the
sing-box socksaddr: ATYP + addr + BE port, which is the family set we already encode with
`addr::write_addr_port_last`. First read: `[1B status][varbin message if status=error]`.
The carrier's proxy request destination is `sp.mux.sing-box.arpa:444`, not the flow target.

**UDP stream layout** (same section, per association): the stream's request is
`[2B flags][addr]` with `flags = UDP(0x1)`; the first response byte pair is the
`[1B status]` above; each datagram is then `[2B BE length][payload]` in both directions.
The length prefix belongs to the **sbox stream**, not to a mux frame — an sbox carrier
carries TCP and UDP streams side by side and the two framings never nest.

### 8.3 Session parameters (must match)

| Protocol | Parameter |
| --- | --- |
| smux | `KeepAliveDisabled = true`; SagerNet fork semantics (not xtaci upstream) |
| yamux | `StreamCloseTimeout = StreamOpenTimeout = 5 s`; logging discarded |
| h2mux | HTTP/2 client conn; per stream `CONNECT https://localhost`, expects `200`; server idle 30 s and `MaxReadFrameSize = buf.BufferSize` (sing-box constant — read it from the reference, do not hard-code a guess) |

### 8.4 Module layout

`crates/leas-native/src/transport/sbox/{mod,protocol,padding,smux,yamux,h2mux}.rs`.
No new dependencies: `h2`/`bytes`/`tokio` already drive the gRPC transport; smux/yamux state
machines are hand-written (`#![forbid(unsafe_code)]` stays). Buffers are fixed-size and
reused; no per-frame allocation; 8 KiB writes align with the existing chunk discipline.

### 8.5 Interop rule (D5/D9)

| Wire | Server | Notes |
| --- | --- | --- |
| `muxcool` | Xray/v2ray, sing-box (sing-vmess), mihomo | plain rows; **Vision + mux also uses this wire and is sing-box/mihomo-only** (Xray rejects TCP mux under XRV) |
| `h2mux` / `smux` / `yamux` | sing-box, mihomo | never paired with Vision; padding optional per profile (`multiplex.padding` / `mux-option.padding`) |

Because the link cannot say which server answers, the wire is per-profile. Failure is named at
the carrier stage (`mux wire mismatch` / `server refused padding`) and never downgraded to a
per-leg dial.

## 9. Config and proto changes

- `VlessConfig` gains `mux_wire: MuxWire` (`MuxCool` default; `H2Mux`, `Smux`, `Yamux`),
  parsed from `muxtype=` (today `VlessMux::Invalid{key,value}`); `mux=` stays the cap. Export
  writes the spelling back. JSON config blob only — **no schema cursor bump** (not DDL).
- `MuxConfig`: `enabled`, `max_streams` (8), `max_carriers` (8), `idle_secs` (16),
  `padding`, `wire_default` become live; `enabled` defaults to **true** for new configs and
  `protocol = "smux"` is corrected to `wire_default = "muxcool"` (the dead value is the one
  that would have misled). `fragment_*` stays as-is.
- Settings UI: the Mux section either drives these fields or is removed; no dead knobs.
- `capability.rs`: `muxtype` is no longer refused for VLESS; padding+wire combinations are
  validated; the Vision refusal becomes the D9 pairing rule (Vision + mux requires
  `muxcool`, named as sing-box/mihomo-only), matching the codec that already ships
  (`connect_mux_vision`).

**Compatibility boundary.** Rows that spell `muxtype=smux|yamux|h2mux` are dialable after S2
instead of refused by name — a behaviour change for exactly those rows, and the reason D5
fails loudly on a mismatch. Rows with no mux key gain mux by default (D2/D8). Existing
`VlessMux` semantics, exports, and the JSON config blob are otherwise unchanged; no schema
cursor bump.

## 10. Failure and recovery

| Event | Behaviour |
| --- | --- |
| carrier build fails | evict attempt, surface the error on the CONNECT reply inside the budget |
| carrier dies mid-session | session EOF/error; next acquire redials; no zombie carriers |
| wire mismatch / padding rejected | named error, no fallback, no per-leg retry (that would hide config) |
| pool exhaustion at 8 carriers | spill dial for the one stream, not queued behind it |
| profile switch | pool dropped; sessions abort exactly like today's per-leg teardown |
| idle carrier | closed after 16 s with no live streams |

## 11. Detectability and performance claims (status)

- **Measured (local):** per-leg handshake cost and failure rate (§1); apt's error classes.
- **Measured prior art:** Xray 16 s idle ticker + `CloseIfNoSessionAndIdle`, `MaxConnection`
  1024, `concurrency 0..128 → 128` in v26.11.9 (`handler.go:122-140`, contradicting the
  docs' "0 = 8"); sing-box pool with least-streams selection and `min_streams = 8` default.
- **Inference, to be measured after S1:** fewer carriers ⇒ fewer handshake bursts. No DPI
  measurement is claimed. MUX.Cool adds no padding; sbox padding is available only with the
  sbox wire and must match the server.
- **Risk (D2):** default-on can reduce bulk throughput (head-of-line). Acceptance A6 bounds it
  and the per-profile switch is the escape hatch.

## 12. Testing and acceptance

- **A1 (reuse):** 20 sequential short-lived CONNECTs to one profile open **1** carrier, not
  20; counted from trace `Opened` rows and a carrier counter. p95 warm-CONNECT reply < cold.
- **A2 (budget):** a blackholed carrier yields a SOCKS reply inside the aggregate budget,
  before a 10 s client timeout; no greeting is affected (greeting is answered pre-routing).
- **A3 (ids):** an allocator test drives > 65 536 opens with one long-lived session held
  across the wrap: no open ever returns an id that is live, and id 0 is never handed out.
  This is the exact claim — "a wrap past 0 is rejected" is not enough.
- **A4 (caps):** 9th concurrent stream opens a second carrier; at 8 carriers the 65th stream
  spills outside the pool; no request queues behind a full carrier.
- **A5 (wire vectors):** byte-exact golden vectors for the sbox handshake — Version0 = exactly
  2 bytes (no padding flag), Version1 padding off = 3 bytes, Version1 padding on = 3 +
  2 + N bytes with `N ∈ 256..=767` — plus all three protocol bytes, the per-stream request
  (`2B flags + addr`, no version byte) and response (`1B status` + error form), and unchanged
  MUX.Cool frames.
- **A6 (throughput):** `just bench`/hotpath unaffected; a bulk download through 1 carrier vs
  per-leg is recorded (ratio, environment) — no gate, documented.
- **A7 (e2e):** `leas-oracles` rows against pinned xray (mux.cool) and sing-box (h2mux, smux,
  yamux; one row with `multiplex.padding=true` proving the reject-unpadded path and the padded
  success path). The existing `mux_vision_singbox` row stays green, and a Vision row with an
  sbox wire is refused by name.
- **A8 (regression):** per-profile off reproduces today's per-leg behaviour; Vision + mux is
  dialable on `muxcool` (D9) and refused by name on sbox wires; SS-plugin rows keep their own
  `mux=` semantics.
- **A9 (config):** every `MuxConfig` field has a reader or is deleted; `muxtype=` round-trips
  through parse → config → export.

### 12.1 Oracle matrix: what each core really serves

Server-side capability, read from the pinned sources, and the client wire status. `✓ row` =
a row the harness can run after S0b/S2; `server` = the core accepts it but leas has no client
wire (declared out of scope, §2); `✗` = the server has no such wire.

| Protocol | Core | mux.cool | sbox (h2mux/smux/yamux) | padding | leas wire | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| VLESS | Xray | ✓ row | ✗ | n/a | mux.cool | existing `mux_tls`/`mux_reality`/`xudp_*` rows; Xray ships no sbox server |
| VLESS | sing-box | ✓ row | ✓ rows | ✓ | mux.cool + sbox | sing-vmess `service.go:364` (CommandMux); `common/mux/router.go`; `option/multiplex.go`; existing `mux_vision_singbox` |
| VLESS | mihomo | ✓ row | smux/yamux ✓ rows; **h2mux: client interop gap** | ✓ | mux.cool + sbox (h2mux pending) | `listener/sing_vless/service.go:141-142`; `listener/sing/sing.go:78-90`; `listener/inbound/mux.go` (`mux-option.padding`). h2mux evidence: mihomo's `metacubex/sing-mux v0.3.12` ends 3/4 streams right after the 200 headers, while sing-box's identical server code passes and mihomo's smux/yamux pass — the two rows are `#[ignore]`d with that reason, not deleted |
| VMess | sing-box / mihomo | server | server | ✓ | none | sing-vmess `service.go:364`; `sing_vmess` + `MuxOption` |
| Trojan | mihomo | ✗ | server | via smux | none | `listener/trojan/server.go:306,354`: `CommandMux` is **smux** (`smux.Server`), not mux.cool |
| Shadowsocks | sing-box / mihomo | ✗ | server | ✓ | plugin-only | `sing_shadowsocks` + `MuxOption`; our SS mux is the SIP003 plugin's own smux |

Mihomo's real inbound set (`listener/inbound/`) is broader than the harness wires: VLESS,
VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, Snell, Mieru, SOCKS/HTTP/mixed,
ShadowTLS/Restls/JLS wrappers, Sudoku, ShadowQUIC, KCPTun/MKCP, TrustTunnel. Only the first
four are mux-relevant and only VLESS+SS are client wires here; the rest are recorded so the
matrix is not mistaken for "mihomo only does Shadowsocks".

**Harness gap (evidence):** `config.rs:401` marks mihomo VLESS unsupported and `:159`
(`set_flow`) marks mihomo **flow** unsupported — so even a VLESS listener builder is not
enough for the Vision row; `sing_vless/service.go` implements XRV and accepts CommandMux, so
both gates must be lifted (`flow` emitted into the `users[].flow` field for mihomo, as for
sing-box). `:206` VMess and `:948` Trojan are likewise unwired; they stay so until a client
mux wire exists. S0b adds the **VLESS** builder
(`listeners: [{type: vless, users, certificate, private-key, flow?, mux-option: {padding}}]`,
REALITY via `reality-config` in a follow-up row) and lifts the flow gate.

### 12.2 Handshake count — the hard acceptance

The user requirement: a multiplexed workload must show **exactly one** handshake per carrier.

**Primary instrument — the real inbound, black-box.** `inbound::outbound::dial` is
`pub(crate)` and `leas-oracles` depends on `leas-native`, not on `leas`, so the e2e cannot
call the pool directly. It does not need to: `Socks5Inbound` is already `pub` (`bind`,
`serve`, `Socks5InboundConfig` with an `OutboundKind::Proxy`), so S0b drives the **actual
user-visible path** — `MUX_SESSION_COUNT = 4` SOCKS CONNECTs through a local `Socks5Inbound`
whose proxy outbound dials the core through a counting TCP proxy. Every session echoes
within the 16 s idle window, then assert:

- `accepted == 1` — one carrier handshake for four SOCKS CONNECTs (the user requirement), and
- `sessions_ok == MUX_SESSION_COUNT` — the reused carrier was usable.

A `pub` carrier counter behind the existing `e2e-support` feature is optional white-box
diagnostic (the `HeaderFirst::inner` precedent), not required by the gate; the counting proxy
is the observable, and it sits between the inbound's outbound and the core, so no new API is
needed.

This is the signal the defect is about, and it avoids two traps: a black-box accept counter
is not 1 when the pool legitimately idle-closes and redials, and REALITY inbounds delay the
first app-data exchange ~5 s in their post-handshake detector (`MUX_PROBE_TIMEOUT` already
covers it) — an extra relay hop per row adds timing variance the pass/fail does not need.

**Secondary, black-box (diagnostic, not the gate):** a `CountingProxy` (transparent TCP
forwarder, `Arc<AtomicUsize>` accepts) may wrap non-REALITY rows; the invariant asserted is
`accepted == carriers_opened`, not `accepted == 1`. It is skipped on REALITY rows.

**Positive redial test (proves the 2-accept case is legitimate, not a flake):** kill the
carrier mid-test → the next SOCKS CONNECT opens a second carrier: `accepted == 2`, sessions
still succeed.

**Negative control (the test must be able to fail):** the per-leg path (mux off, and the
pre-pool codec that `probe_mux` exercises today) reports `accepted == MUX_SESSION_COUNT` — the
red proof S0b records before S1.

- **A10** is the gate for S1 (muxcool rows) and S2 (sbox rows): one carrier opened, N
  sessions OK; accept count equals the carrier count where the proxy is used. Rows: Xray ×
  muxcool; sing-box × {muxcool, h2mux, smux, yamux}; mihomo × {muxcool, h2mux, smux, yamux}
  — 9 rows. Wrong-wire control: a sbox wire against Xray fails by name and opens **one**
  carrier attempt, never a silent per-leg fallback.

- **A11 (padding rows):** on sing-box and mihomo — padded client + `padding=true` server ✓;
  padded client + `padding=false` server recorded (behaviour of the reference, not assumed);
  unpadded client + `padding=true` server = named failure. Xray has no padding cell.
- **A12 (UDP through one carrier):** XUDP (existing `xudp_tls`/`xudp_reality`) and sbox UDP
  streams run through the counting proxy: N datagrams/associations → 1 accept, all echoes
  returned. Framing vectors stay A5. **Gate: S2** — S1's pool serves TCP only; the UDP arm
  needs `MuxTunnel::open_udp_session` plus pool access in the inbound's UDP relay.
- **A13 (mihomo VLESS rows):** muxcool (TLS), the three sbox wires, `mux-option.padding`, and
  a Vision+mux row (mihomo accepts it, D9; the `set_flow` gate is lifted in S0b).
  REALITY-via-mihomo is a follow-up row.


## 13. Slices

| Slice | Content | Gate |
| --- | --- | --- |
| **S0** | Aggregate connect budget; skip-live session-id allocation (wrap-safe) | A2, A3; no behaviour change otherwise |
| **S0b** | Oracle mux harness: pool-backed session opener for e2e (same acquisition path as `inbound::dial`, carrier-open counter) + optional `CountingProxy` diagnostic; mihomo VLESS listener builder (`listeners: vless`, inline cert/key, `mux-option`) and the `set_flow` gate lifted for mihomo; per-leg negative control recorded (`carriers_opened == sessions`) | harness self-test: pool opener reports one carrier for the in-process reuse proof and `sessions` carriers on the per-leg path — the red proof A10 can fail; mihomo Vision server config accepted |
| **S1** | Pool over MUX.Cool (VLESS + SS-plugin), **TCP only**; live config; per-profile wire field (`muxcool`); default-on policy | A1, A4, A8, A9; A10 on muxcool × {xray, sing-box, mihomo} |
| **S2** | sbox handshake + padding + stream framing; **h2mux** first, then smux, then yamux; capability gating; **UDP pool arm** (`MuxTunnel::open_udp_session` + `run_udp_relay` uses the pool) | A5, A7, A10 on sbox × {sing-box, mihomo}, A11, A12, A13 |
| **S3** | XHTTP `xmux`-style transport pool (the "transport is already multiplexed" arm) | A1 analogue on XHTTP; no mux nesting |

Each slice compiles and passes the workspace suite alone; S0 is a prerequisite for S1/S2.
S2 is the largest and may split into S2a (handshake + padding + h2mux) and S2b (smux, yamux)
at planning time without changing this spec's contracts.

## 14. ADR signals

- New owners: `transport/sbox/`, `mux_pool.rs`; retirement of the dead `MuxConfig.protocol`
  picker and of `muxtype` refusal.
- Contract change: effective mux gains a profile default (on) and a per-profile wire; failure
  is named, never downgraded.
- Dependency posture: **no new crates**; Go references pinned, wire compatibility proven by
  vectors + e2e.
- Record as an ADR when S1 lands (pool + policy), amending it for sbox in S2.

## 15. Open questions

None blocking. Assumed unless the reviewer objects: `muxcool` is the default wire (VLESS
server majority + our existing codec); gRPC is mux-over-one-stream (D6); padding default off
(prior art; the setting is exposed).

## 16. References

- `thirdparty/sing-mux@caf09fe`: `protocol.go`, `protocol_conn.go`, `padding.go`, `h2mux.go`,
  `session.go`, `client.go`.
- `thirdparty/smux@f373f1e` (SagerNet fork), `thirdparty/yamux@17017e9`.
- `thirdparty/sing-box@824dbcf`: `option/multiplex.go`, `common/mux/client.go`,
  `common/mux/router.go`, `protocol/vless/inbound.go`, `go.mod` (pins `sing-vmess`, which
  serves `CommandMux`).
- `thirdparty/mihomo@3f27ef3`: `listener/sing_vless/{server,service}.go` (Vision + CommandMux
  + sing-mux service), `listener/sing/sing.go` (`MuxOption`), `listener/trojan/server.go`
  (`CommandMux` = smux), `listener/inbound/mux.go`, `listener/config/vless.go`
  (`certificate`/`private-key`/`mux-option`).
- Harness: `crates/leas-oracles/src/e2e/{harness,mod,config,case}.rs`; existing mux rows
  `tests/vless.rs:143-156,261`.
- `thirdparty/Xray-core@v26.11.9`: `common/mux/*`, `app/proxyman/outbound/handler.go:118-170`,
  `infra/conf/xray.go:110-132`.
- Clients: v2rayN (`ServiceLib/Services/CoreConfig/V2ray/V2rayOutboundService.cs:231-251`,
  `SingboxOutboundService.cs:406-421`), v2rayNG (`CoreOutboundBuilder.kt:47-80`), xrat
  (`docs/src/05-reference/config-file.md:319-345`), ferrox (`proxy.rs:15107-15190`,
  `crates/ferrox-app/src/xmux.rs`), matryoshka (no mux).
- Docs: `xtls.github.io/en/config/outbound.html` (MuxObject), `xtls.github.io/…/muxcool.html`,
  `sing-box.sagernet.org/configuration/shared/multiplex/`.
