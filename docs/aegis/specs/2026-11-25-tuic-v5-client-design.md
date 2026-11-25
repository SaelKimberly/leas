# TUIC v5 client — native design

Date: 2026-11-25
Status: **approved 2026-11-25 — implementation in progress**; plan [`../plans/2026-11-25-tuic-v5-client.md`](../plans/2026-11-25-tuic-v5-client.md).
Origin: user request “implement TUIC in `leas-native`; sans-I/O where possible; grill the details.”
Evidence: `sing-quic` v0.6.0-beta.13 (`tuic/{protocol,client,service,packet,service_packet}.go`), the pinned sing-box v1.15.0-alpha.13 (`protocol/tuic`, `go.mod` → sing-quic v0.7.2 commit `7e0a5869a5f4`), `thirdparty/mihomo` v1.19.33 (`transport/tuic/v5/{protocol,packet,frag}.go` — the on-disk wire codec — plus `adapter/outbound/tuic.go`, `listener/inbound/tuic.go`), and `thirdparty/ferrox/crates/ferrox-core/src/tuic.rs`. The pinned sing-quic client source at `7e0a5869a5f4` agrees with the cached v0.6.0-beta.13, and mihomo's independent v5 codec, on every frame below. `thirdparty/tuic` HEAD is the v6 rewrite; its `tuic-tests` bytes are not used as the v5 authority.

---

## 1. Why this exists

`protocol/tuic/mod.rs` is a two-line placeholder. `capability` refuses every `ProtocolKind::Tuic` row, so the TUI resolves TUIC links to the sing-box subprocess even in a native-only session. TUIC is the largest remaining dialable-by-subprocess gap after Hysteria2: a stored row that can never dial natively.

This spec defines the **client only**. `leas-native` has no server role. The wire is TUIC v5; v4 (token-only) and v6 (different transport) are out of scope, and the current `tuic://uuid:password@` parser cannot express either.

## 2. Wire contract

All integers are big-endian. Every frame starts with `version = 0x05` then a command byte:

| Command | Value | Carrier |
| --- | --- | --- |
| `AUTHENTICATE` | `0x00` | one client-initiated unidirectional QUIC stream |
| `CONNECT` | `0x01` | one bidirectional QUIC stream |
| `PACKET` | `0x02` | QUIC DATAGRAM (native) or one unidirectional stream (quic) |
| `DISSOCIATE` | `0x03` | unidirectional stream |
| `HEARTBEAT` | `0x04` | QUIC DATAGRAM |

### 2.1 Transport and TLS

- QUIC v1, TLS 1.3 only. Every frame above is application data inside QUIC.
- ALPN: the row's explicit list, default `h3`. `TuicConfig.security.alpn` is a single comma-separated string; `LinkContext::alpn_tokens()` already owns `split(',') → trim → drop-empty`. Empty after that means `["h3"]`.
- Certificate verification: the existing `transport::quic::quic_tls_config` rules (`insecure` skips the chain walk; otherwise webpki roots / the e2e test CA), SNI from `LinkContext::server_name()`.
- QUIC DATAGRAM must be enabled locally and advertised. `max_datagram_size()` is quinn's **application payload** limit, so a TUIC frame is passed whole; do **not** copy quic-go's `-3` accounting from `sing-quic` (`udpMTU = 1200 - 3` is that stack's frame overhead, not ours).

### 2.2 Authentication

The client opens one unidirectional stream and writes exactly 50 bytes, then closes the stream:

```text
05 00 | uuid[16] | token[32]
```

`token = TLS exporter(label = the 16 raw UUID bytes, context = the password UTF-8 bytes, length = 32)`.
Sing-quic: `ExportKeyingMaterial(string(uuid[:]), []byte(password), 32)`.

There is **no auth response frame**. The server verifies on its first uni stream; a bad UUID/token, a duplicate auth, a wrong version, or its auth timeout (sing-box default 3 s) closes the QUIC connection. Sing-box closes with application code 0; mihomo uses its own codes (`0xfffffff1` `AuthenticationFailed`, `0xfffffff2` `AuthenticationTimeout`, `protocol.go`), so a close code is **not** portable credential evidence and D4 stays `NotApplicable`. Acceptance is only observable indirectly: CONNECT/PACKET data starts flowing. A CONNECT or PACKET received before auth completes is buffered server-side until `authDone`.

Both independent implementations compute the same token: sing-quic `ExportKeyingMaterial(string(uuid[:]), []byte(password), 32)` and mihomo v5 `GenToken` (`utils.StringFromImmutableBytes(uuid[:])`, `ImmutableBytesFromString(password)`, 32). Ferrox's doc states the same “raw 16-byte UUID with the password as context”; `ferrox-core` does not compute the token itself.

### 2.3 CONNECT

```text
05 01 | ATYP | address | port[2]
```

| ATYP | Address |
| --- | --- |
| `0x00` | `len[1]` (1..=255) + domain bytes |
| `0x01` | IPv4, 4 bytes |
| `0x02` | IPv6, 16 bytes |

No response frame. Bytes after the header are the target stream, and the server's bytes are returned raw on the same stream. A CONNECT stream may carry payload bytes in the same write as its header.

### 2.4 PACKET

```text
05 02 | session[2] | packet[2] | frag_total[1] | frag_id[1] | payload_len[2] | address | port[2] | payload
```

- `session` is chosen by the client per association; `packet` increments per association and wraps at `u16`.
- `frag_total` is 1..=255; `frag_id < frag_total`; `frag_total = 0` is malformed.
- `payload_len` counts the payload only.
- The first fragment (`frag_id = 0`) carries the full address+port. Continuation fragments carry the single byte `0xff` in place of the address, and no port.
- `native` mode: each fragment is one QUIC DATAGRAM.
- `quic` mode: each PACKET frame is one unidirectional stream, closed after the write.
- The server mirrors the mode of the **first** packet it receives for an association (`service_packet.go`: `udpStream` becomes the association's reply mode). The client must therefore read replies from both lanes; the codec is identical.

### 2.5 DISSOCIATE and HEARTBEAT

```text
05 03 | session[2]      # one unidirectional stream; drop the association
05 04                    # one QUIC DATAGRAM; both directions; ignored
```

Heartbeat interval: 10 s (sing-quic default and mihomo default). Sing-quic closes the connection if a heartbeat send fails; it ignores received heartbeats. Unknown datagram commands: sing-quic closes. This client ignores an unknown command for forward compatibility and closes only on a malformed PACKET or unknown version; that is a deliberate, recorded deviation.

### 2.6 Address codec

The same address encoding serves CONNECT, the first PACKET fragment, and UDP destinations. Reject an empty domain, a domain longer than 255 bytes, a truncated address, an unknown ATYP, and trailing bytes. `0xff` is legal only as the continuation marker.

## 3. Design

### 3.1 Module map

```text
crates/leas-native/src/protocol/tuic/
  mod.rs      public connect / connect_udp, constants, docs
  wire.rs     sans-I/O: constants, address codec, auth/CONNECT/PACKET/
              DISSOCIATE/HEARTBEAT encoders, PACKET parser, fragment planner,
              defragmenter. No quinn, no tokio, no async.
  quic.rs     QUIC dial, TLS/ALPN, congestion factory, auth task, handshake
              phase, UDP connection driver.
  stream.rs   TuicConnectStream: AsyncRead/AsyncWrite over one bidi stream,
              0-RTT staging + transparent retry.
  udp.rs      UdpConn/UdpReader/UdpWriter, native/quic send lanes, session
              lifecycle.
```

`wire.rs` is the whole sans-I/O boundary selected in grilling. It depends on `std`, `bytes` (a data type, not an I/O runtime), and `leas_proto` address types. QUIC streams, datagrams, exporter, and errors stay in `quic.rs`.

### 3.2 Dial and auth

1. Build `rustls::ClientConfig` with the explicit ALPN list (extend `quic_tls_config` to accept `&[Vec<u8>]`, cache keyed by the list; existing call sites pass one element).
2. Build a TUIC `TransportConfig`: idle timeout 300 s, **no** quinn keep-alive (the TUIC HEARTBEAT owns liveness), datagrams enabled, large incoming uni-stream credit, congestion factory from §3.3.
3. `endpoint.connect_with(...)`, then `into_0rtt()`. **Do not call `transport::quic::connect` unchanged**: it discards the `ZeroRttAccepted` future (`crates/leas-native/src/transport/quic.rs:246`), and quinn 0.11 has no `Connection::connected()` equivalent. TUIC's dial must own `Connecting`, call `into_0rtt()`, and keep the returned `ZeroRttAccepted`; that future is the only handshake-completion handle the auth exporter can wait on.
4. One handshake task owns the `ZeroRttAccepted` future (or runs immediately when no ticket resumed). On handshake completion it exports the 32-byte token, writes the 50-byte auth frame into a stack `[u8; 50]` on a fresh uni stream, closes it, and publishes the phase (`Accepted` / `Rejected` / `Failed`) to the stream wrapper. Auth always follows the handshake because the exporter key does not exist earlier; CONNECT/PACKET may precede it.
5. On auth write failure, close the connection and fail the tunnel.

### 3.3 Congestion control

Map the config string case-sensitively:

| Value | quinn factory |
| --- | --- |
| absent | `CubicConfig` (sing-box default) |
| `cubic` | `CubicConfig` |
| `new_reno` | `NewRenoConfig` |
| `bbr` | `BbrConfig` |
| anything else, including `bbr3` | refused by `capability`; row falls back to sing-box |

`bbr3` is accepted by neither sing-box nor the TUIC v5 references; the parser's current free string is a latent undialable row.

### 3.4 TCP CONNECT stream

`connect()` returns before the handshake when a ticket resumed; otherwise the QUIC handshake already completed.

- The CONNECT header is built at connect time into a stack `[u8; MAX_CONNECT_HEADER]` (2 + 1 + 1 + 255 + 2 = 261 bytes). No heap allocation.
- The first write composes `header || payload` into one `Vec` with exact capacity, writes it to the stream, and keeps that `Vec` as the replay buffer. This is the only staging allocation; the wire encoder never allocates.
- Subsequent writes wait for the handshake phase:
  - `Accepted`: write normally, then drop the replay buffer.
  - `Rejected`: open a fresh bidirectional stream on the **same** connection after the handshake, write the replay buffer once, then continue with the caller's current write. No application byte is duplicated to the server: QUIC discarded the rejected 0-RTT data. The connection and auth are unchanged.
  - `Failed`: return the stored error.
- Reads wait for the phase, then read the stream. If no write happened before the first read, the header is sent as the replay buffer (server-first behaviour).
- Drop resets the send side; a graceful finish is not required for a proxy tunnel.

Only the **first** write can be early data. Every later `poll_write` polls the phase and returns `Pending` until it resolves, so a second write never joins the rejected-0-RTT stream and no unbounded buffering exists. This is the grilling decision “buffer the first write and transparently retry”. The staging copy is unavoidable: the caller's buffer cannot be retained after `poll_write` returns `Ready`. One exact-size `Vec` per CONNECT is the floor.

### 3.5 UDP association

`connect_udp()` awaits the handshake (no early UDP: a native DATAGRAM sent in 0-RTT can be dropped when early data is rejected, and replaying arbitrary UDP is unsafe), starts auth, allocates a `u16` session id on the connection, and returns `UdpConn`.

- `send(dest, payload)`: `None` uses the session target (`ctx.target`); `Some` uses the per-packet destination. Build one PACKET frame in a reusable `Vec`.
  - `native`: read `max_datagram_size()` per send. If the frame fits, one DATAGRAM. Else fragment at `max - 10 - addr_len` (first) and `max - 11` (continuations), capped at 255 fragments. `send_datagram` takes `Bytes`, so one copy per datagram is unavoidable at the quinn API.
  - Peer does not advertise DATAGRAM, or `send_datagram` returns `UnsupportedByPeer`: switch the association to the quic lane and send the frame on a uni stream. `TooLarge`: re-split once at a conservative 1200-byte frame cap and retry; a second failure is an error.
  - `quic`: one uni stream per frame, `write_all` from the reusable buffer, then `finish`.
- Replies: the connection driver (spawned only for a UDP association) selects on `accept_uni()` and `read_datagram()`:
  - DATAGRAM: parse the full `05 02 ...` frame, feed the defragmenter, forward complete packets.
  - Uni stream: read to the frame boundary, same parser, same defragmenter.
  - HEARTBEAT: ignore. Unknown command: ignore. Unknown version or malformed PACKET: close the connection.
  - Complete packets go to a bounded channel (64) with `try_send`; UDP drops under pressure, as sing-quic does.
- Defragmentation: key `(session, packet)`, 64 live assemblies, 10 s TTL, first-fragment address retained, one buffer grown in fragment order. Out-of-order fragments are appended; the assembled payload is handed through as `Bytes`.
- Drop: send `DISSOCIATE` through the driver's control channel (best effort), then drop the connection when the driver exits. No server-side socket lingers until the UDP timeout.
- `split()`: reader owns the receive channel + defragmenter; writer owns the send buffer/state; both hold an `Arc<Session>` whose last drop signals the driver. The driver holds no `Arc<Session>` (else it would never see the drop), only the connection, the control receiver, and the data sender.

### 3.6 Heartbeat

One task per live connection sends `05 04` as a DATAGRAM every 10 s and exits with the connection. No config field; the references hardcode 10 s. This is the only liveness mechanism; quinn keep-alive stays disabled for TUIC to avoid a second 10 s probe. If the peer does not support DATAGRAM, the heartbeat send fails; the tunnel errors rather than running silently dead (sing-quic behaves the same).

### 3.7 Capability, dispatch, probe

| Site | Change |
| --- | --- |
| `capability::NATIVE_KINDS` | add `ProtocolKind::Tuic` |
| `capability::SUPPORT_REVISION` | 2 → 3 (clears persisted “not testable” verdicts once) |
| `capability::kind_supported` | add `Tuic` |
| `capability::support_reason` | `Tuic` arm: config variant must match; UUID must parse; TLS must be present and not REALITY; ALPN tokens non-empty and ≤255 bytes; congestion and UDP mode from §3.3/§3.5; else `None` |
| `protocol::connect_quic` | `Tuic(cfg) => tuic::connect(ctx, cfg)` |
| `protocol::initial_auth_ack` | `Tuic` stays `NotApplicable` — there is no server ack; a close is never credential evidence |
| `chain::connect_chain_udp_inner` | `Tuic(cfg) => PacketTunnel::Tuic(tuic::connect_udp(ctx, cfg))`, under `quic_guard` |
| `PacketTunnel` / `PacketReader` / `PacketWriter` | add `Tuic` variants and `split` arms |

`is_quic_link` already includes `Tuic`. No schema, config, or dependency change. No `leas-proto` change is required for the first release; the invalid-value refusal lives in the native capability gate, exactly as other native-only refusals do.

### 3.8 Error mapping

- `Dial` for endpoint/UDP bind and `connect_with` construction failures.
- `Timeout { step: "tuic handshake" }` for the existing `timeouts::DIAL` bound; `"tuic auth"` for a bounded auth stream write.
- `Protocol { kind: Tuic, .. }` for malformed server frames, unknown version, and auth-stream failure.
- `NativeError::AuthRejected` is **never** produced by TUIC. The protocol has no rejection frame.

## 4. Decisions (grilling, 2026-11-25)

| # | Decision |
| --- | --- |
| D1 | v5 client only; TCP CONNECT + UDP `native` + UDP `quic`; v4/v6 out of scope. |
| D2 | One QUIC connection per dialed tunnel; no cross-session pool. Deferred, not refused. |
| D3 | Absent congestion → cubic (sing-box parity); `cubic`/`new_reno`/`bbr` accepted; unknown values (including `bbr3`) refused by capability. |
| D4 | `AuthAck::NotApplicable`; no credential verdict from a TUIC close. |
| D5 | Sans-I/O boundary is `wire.rs`; the async driver owns quinn/TLS. No full event/action state machine. |
| D6 | Opportunistic 0-RTT from the rustls session store; auth after the handshake. |
| D7 | On 0-RTT rejection, stage the first write (including the CONNECT header) and transparently retry it on a fresh stream on the same connection. One exact-size staging allocation; no duplicate payload reaches the server because QUIC discards rejected early data. |
| D8 | Interop evidence runs against both pinned sing-box and mihomo TUIC inbound servers. |

## 5. Out of scope

- TUIC v4 token auth and v6.
- `udp_over_stream` (sing-box's UoT add-on; not a TUIC v5 wire mode). `udp_relay_mode` covers both TUIC lanes.
- Server role, QUIC connection pooling, 0-RTT for UDP, and a general `TransportConfig::Quic`.
- Changing `leas-proto` parsing/validation of `congestion_control`/`udp_relay_mode`; the native gate refuses unsupported values and falls back.

## 6. Verification

### 6.1 Unit (no runtime)

- Auth frame: fixed UUID/token → exactly `05 00 || uuid || token`, 50 bytes; stack buffer, no allocation.
- CONNECT header: IPv4, IPv6, domain; port big-endian; max 261-byte domain; empty/256-byte domain refused; trailing-byte parser refusal.
- PACKET: golden frames for first and continuation fragments; `frag_total = 0`/`frag_id ≥ total` refused; `payload_len` mismatch refused; `0xff` required on continuations; unknown ATYP refused; every truncation returns an error, never panics.
- Fragment planner: max boundary exactness, 1..=255 total, oversized payload refused.
- Defragmenter: out-of-order completion, duplicate fragment, mismatched total, 64-slot cap, 10 s expiry, one-pass sweep.
- `DISSOCIATE`/`HEARTBEAT` bytes.
- Capability: valid TUIC config passes; `bbr3`/unknown congestion, unknown UDP mode, invalid UUID, REALITY/absent TLS refuse with the documented reason; `NATIVE_KINDS` count and `non_native` list updated.

### 6.2 E2E (`leas-oracles`, real cores)

Add a TUIC inbound to the sing-box config builder and a `listeners: [{type: tuic, ...}]` entry to the mihomo builder. Server TLS cert/key from the existing harness CA; `users: {uuid: password}`; ALPN `h3`.

| Case | Assertion |
| --- | --- |
| TCP echo (domain / IPv4 / IPv6 target) | payload round-trips against both servers |
| UDP echo, `udp_relay_mode=native` | datagrams round-trip, per-packet destination honoured |
| UDP echo, `udp_relay_mode=quic` | same, one uni stream per packet |
| UDP payload > path DATAGRAM size | fragments reassemble; no truncation |
| Wrong password | connection closes; probe records `NotApplicable`, never `[cred]` |
| Idle 15 s, then echo | heartbeat keeps the tunnel alive |
| 0-RTT, sing-box server `zero_rtt_handshake: true` | first dial full, second resumes and succeeds (CONNECT may ride early data) |
| 0-RTT rejected (server default false) | transparent retry succeeds; exactly one target stream is observed |

The 0-RTT rows run only against sing-box (mihomo's inbound config surface does not expose early data in the read tree). If the harness cannot prove the early lane, the row is marked `#[ignore]` with the upstream reason rather than weakening the codec tests.

### 6.3 Docs after implementation

- `docs/reference/native-core.md`: TUIC native `yes`, e2e `yes`, QUIC transport note.
- `docs/reference/protocols.md` §9: native column and the `cubic` default correction.
- `docs/reference/clash.md` if the TUIC row's defaults change.
- `docs/aegis/INDEX.md` status update.

## 7. Risks and limits

1. **0-RTT replay.** Early CONNECT payload is replayable by an on-path attacker, as in sing-box/ferrox. The transparent retry prevents *our* duplication, not a network replay. Accepted by D6/D7; 0-RTT only fires after a ticket exists.
2. **Server must enable 0-RTT.** sing-box defaults it off. The retry path makes this a one-stream cost, not a failure.
3. **BBR is quinn's BBR, not quic-go's.** Congestion behaviour will differ numerically from the subprocess; the wire is unaffected. No benchmark claim is made.
4. **Per-dial handshakes.** A TUIC session that opens many target streams still pays one QUIC handshake per `connect()`. Correct but more expensive than sing-box's per-outbound connection; the pool remains the known follow-up.
5. **No TUIC v4/v6.** Rows in those shapes are not expressible by the current parser; if a future feed carries them, that is a separate parser/protocol change.
